// TODO: Do client init.
// TODO: Do server-client loop.
// TODO: Handle timeouts and exits.
// TODO: Test in C.
// TODO: Wrap in python API.
// Add better error checking.

// STRING CONVENTION : All strings should include their length.
// All strings should be null-terminated.

// The IPC works off of a synchronous turn based model, backed by a shared memory buffer.
// The buffer is large enough to store an entire message. If this is not the case,
// the server and client can request for this to be changed. To accomplish this, a new
// shared memory object is created.
//
// To connect to a server, a client makes a request by modifying a shared memory buffer
// `JoinArea`. The server responds by assigning a client ID. While this is happening, the
// client has locked the buffer.
//
// Synchronization Primitives:
// - The server has 1 semaphore to handle signals from clients (join, turn change).
// - Each client has 1 semaphore to handle signals from the server (turn change).
// - Client share 1 semaphore (mutex) to handle joining the server, to prevent concurrent
//   writes to the join shared memory area.

#include "ipcack.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef _WIN32
#define IPCACK_WINDOWS
#include <Windows.h>
#else
#define IPCACK_POSIX
#include <fcntl.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

#ifndef static_assert
#define static_assert(ignore, args)
#endif

static_assert((IPCACK_ERR_H_COUNT) < UINT8_MAX, "Error codes must fit in 1 byte.");
static_assert(IPCACK_ERR_L_COUNT < UINT8_MAX, "Error code details must fit in 1 byte.");

static inline IPCAckError error(IPCAckErrorHigh err_high, IPCAckErrorLow err_low) {
    return (err_high << 8) | err_low;
}

#define error(high, low) error(IPCACK_ERR_H_##high, IPCACK_ERR_L_##low)

// Platform specific config.
#ifdef IPCACK_WINDOWS
typedef HANDLE ShmemFD;
typedef HANDLE Semaphore;
#elif defined(IPCACK_POSIX)
typedef int ShmemFD;
typedef sem_t *Semaphore;
#endif

// Compiler specific config.
#if defined(_MSC_VER_)
#define thread_local __declspec(thread)
#elif defined(_GNUC_) || defined(__clang__)
#define thread_local __thread
#else
// TODO: uncomment
// #error "Only MSVC, Clang, and GCC are supported."

// These should be defined if porting to a new compiler.
#define thread_local
#endif

/// Common prefix to all system-wide named objects.
#define IPCACK_PREFIX_LEN ((sizeof ipcack_prefix) - 1)
static const char ipcack_prefix[] = "/_ipcack_";

/// 5 character or 30-bit base64 connection ID assigned per client.
#define IPCACK_FIXED_ID_LEN 5
#define IPCACK_FIXED_ID_BITS (IPCACK_FIXED_ID_LEN * 6)
static_assert(IPCACK_FIXED_ID_BITS < 32,
              "ID must fit into a 32 bit integer. This may change later.");
/// 5 character or 28-bit base64 connection ID assigned per client buffer.
#define IPCACK_DYNAMIC_ID_LEN IPCACK_FIXED_ID_LEN
#define IPCACK_DYNAMIC_ID_BITS (IPCACK_FIXED_ID_LEN * 6)

/// 8 character object specifier.
#define IPCACK_OBJECT_TYPE_LEN 8
#define DEFINE_IPCACK_OBJECT_TYPE_PREFIX(var, value)                                     \
    static const char ipcack_prefix_##var[] = value;                                     \
    static_assert((sizeof ipcack_prefix_##var - 1) == IPCACK_OBJECT_TYPE_LEN,            \
                  "Prefix length.")

/// Shared memory: Waiting area for clients wanting to join server.
DEFINE_IPCACK_OBJECT_TYPE_PREFIX(join_area, "joinarea");
/// Mutex (using semaphore): For clients wanting to join server.
DEFINE_IPCACK_OBJECT_TYPE_PREFIX(join_lock, "joinlock");

/// Shared memory: buffer for client-server messages.
DEFINE_IPCACK_OBJECT_TYPE_PREFIX(shmem, "sharemem");
/// Semaphore: event for server wake up.
DEFINE_IPCACK_OBJECT_TYPE_PREFIX(server_sem, "servesem");
/// Semaphore: event for client wake up.
DEFINE_IPCACK_OBJECT_TYPE_PREFIX(client_sem, "clientse");

#define IPCACK_MIN_SHMEM_NAME                                                            \
    (IPCACK_PREFIX_LEN + IPCACK_FIXED_ID_LEN + IPCACK_DYNAMIC_ID_LEN +                   \
     IPCACK_OBJECT_TYPE_LEN)

#define IPCACK_MAX_SHMEM_NAME (IPCACK_MIN_SHMEM_NAME + IPCACK_MAX_NAME)
static_assert(IPCACK_MAX_SHMEM_NAME < 250,
              "Shared memory object name must be less than 250");

#define IPCACK_MUTEX_ID_JOIN 0x0
#define IPCACK_MUTEX_ID_

typedef struct String {
    /// Length in bytes, NOT characters or code points.
    uint16_t len;
    /// Pointer to <len> count raw UTF-8 bytes, where bytes[len] = 0x0.
    char *bytes;
} String;

typedef struct ShmemBuffer {
    ShmemFD fd;
    char *buf;
    size_t size;
} ShmemBuffer;

static IPCAckError validate_shmem_name_external(const char *name) {
    size_t len = strnlen(name, IPCACK_MAX_NAME + 1);
    if (len > IPCACK_MAX_NAME) { // Name must be short enough.
        return error(ARGS, STRING_TOO_LONG);
    }
    if (len < 2) { // Name must be long enough.
        return error(ARGS, STRING_TOO_SHORT);
    }
    if (strchr(name, '/') != NULL) { // Name must not contain any other /.
        return error(ARGS, STRING_INVALID);
    }

    return IPCACK_OK;
}

static inline void base64_encode(uint32_t value, char buffer[IPCACK_FIXED_ID_LEN]) {
    static const char base64_table[64] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

    for (int i = 0; i < IPCACK_FIXED_ID_LEN; ++i) {
        buffer[i] = base64_table[(value & 0x3F)];
        value >>= 6;
    }
}

static inline size_t cat(char *buf, uint16_t start, uint16_t len, const char *addition) {
    int i = 0;
    for (; i < len; ++i)
        buf[start + i] = addition[i];
    return i;
}

// TODO: Make thread safe.
// TODO: Unused.
// static char string_scratch[IPCACK_MAX_SHMEM_NAME + 1];

thread_local static char shmem_string_scratch[IPCACK_MAX_SHMEM_NAME + 1];
#define SHMEM_SCRATCH_SIZE                                                               \
    ((sizeof shmem_string_scratch) / (sizeof *shmem_string_scratch))

typedef struct BuildNameParams {
    /// UTF-8 string of at most <IPCACK_MAX_NAME> bytes that has already been validated.
    String name;
    const char (*object_type_str)[IPCACK_OBJECT_TYPE_LEN + 1];
    uint32_t fixed_id;
    uint32_t dynamic_id;
    char b64_scratch[IPCACK_FIXED_ID_LEN];
} BuildNameParams;
static IPCAckError build_shmem_name(BuildNameParams *params, String *string, char *buf,
                                    size_t bufsize) {
    size_t total_length_needed = 1 + IPCACK_MIN_SHMEM_NAME + params->name.len;
    if (bufsize < total_length_needed)
        return error(ARGS, STRING_TOO_LONG);

    size_t start = 0;
    start += cat(buf, start, IPCACK_PREFIX_LEN, ipcack_prefix);
    start +=
        cat(buf, start, IPCACK_OBJECT_TYPE_LEN, (const char *)params->object_type_str);
    base64_encode(params->fixed_id, params->b64_scratch);
    start += cat(buf, start, IPCACK_FIXED_ID_LEN, params->b64_scratch);
    base64_encode(params->dynamic_id, params->b64_scratch);
    start += cat(buf, start, IPCACK_DYNAMIC_ID_LEN, params->b64_scratch);
    start += cat(buf, start, params->name.len, params->name.bytes);
    start += cat(buf, start, 1, "\0");

    string->bytes = buf;
    string->len = start;

    return IPCACK_OK;
}

#ifdef IPCACK_WINDOWS

/// TODO: check if this is threadsafe

/// @brief Scratch buffer for converting UTF-8 to `WCHAR` for Windows calls.
/// While only at most `IPCACK_MAX_SHMEM_NAME` `WCHAR`s are needed to convert to UTF-16,
/// extra space is added just in case.
/// + 1 added for null-terminator.
thread_local static WCHAR wide_char_scratch[IPCACK_MAX_SHMEM_NAME * 2 + 1];
#define WIDE_CHAR_SCRATCH_SIZE ((sizeof wide_char_scratch) / (sizeof *wide_char_scratch))

static IPCAckError utf8_to_wide_char_scratch(const char *name, size_t len, WCHAR buf[],
                                             size_t bufsize) {

    int status = MultiByteToWideChar(CP_UTF8, 0, name, len, NULL, 0);
    if ((status <= 0)) {
        // Error occured.
        return error(ARGS, STRING_UTF8_INVALID);
    }
    unsigned int ustatus = status;
    if (ustatus > bufsize) {
        // The string is too long.
        return error(ARGS, STRING_TOO_LONG);
    }

    status = MultiByteToWideChar(CP_UTF8, 0, name, len, buf, bufsize);
    if (status <= 0) {
        return error(ARGS, STRING_UTF8_INVALID);
    }

    buf[status] = '\0';
    return IPCACK_OK;
}
#endif

/// @brief Open a shared memory buffer.
/// @param shmem Buffer to initialize.
/// @param name Null-terminated `String` of length 2-`IPCACK_MAX_SHMEM_NAME`, containing
/// exactly 1 `/` as the first character.
/// @return
static IPCAckError open_shmem(ShmemBuffer *shmem, String name) {
#ifdef IPCACK_WINDOWS
    IPCAckError err = IPCACK_OK;

    if ((err = utf8_to_wide_char_scratch(name.bytes, name.len, wide_char_scratch,
                                         WIDE_CHAR_SCRATCH_SIZE))) {
        return err;
    }
    HANDLE handle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                       (shmem->size >> 32) & 0xFFFFFFFF,
                                       shmem->size & 0xFFFFFFFF, wide_char_scratch);
    if (handle == NULL) {
        return error(SYS, SHM_OPEN);
    }

    void *buf = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, shmem->size);
    if (buf == NULL) {
        CloseHandle(handle);
        return error(SYS, MMAP);
    }

    shmem->fd = handle;
    shmem->buf = buf;
    return err;

#elif defined(IPCACK_POSIX)
    int fd_or_err = shm_open(name->bytes, O_CREAT | O_RDWR, 0644);
    if (fd_or_err == -1) {
        return IPCACK_ERROR_SYSTEM;
    }
    if (ftruncate(fd_or_err, shmem->size) == -1) {
        shm_unlink(shmem->name);
        return IPCACK_ERROR_SYSTEM;
    }

    void *buf = mmap(NULL, shmem->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_or_err, 0);
    if (buf == MAP_FAILED) {
        shm_unlink(shmem->name);
        return IPCACK_ERROR_SYSTEM;
    }

    shmem->fd = fd_or_err;
    shmem->buf = buf;
#endif
    return IPCACK_OK;
}

/// @brief Close an open shared memory buffer. Unmap and close the associated handle.
/// @param shmem Buffer to close.
/// @param name Null-terminated `String` of length 2-`IPCACK_MAX_SHMEM_NAME`, containing
/// exactly 1 `/` as the first character.
/// @return 
static IPCAckError close_shmem(ShmemBuffer *shmem, const char *name) {
#ifdef IPCACK_WINDOWS
    BOOL success = TRUE;
    success = success && UnmapViewOfFile(shmem->buf);
    success = success && CloseHandle(shmem->fd);
    return success ? IPCACK_OK : error(SYS, FREE);
#elif defined(IPCACK_POSIX)
    bool success = true;
    success = success && (munmap(shmem->buf, shmem->size) == 0);
    success = success && (shm_unlink(name) == 0);
    return success ? IPCACK_OK : error(SYS, FREE);
#endif
}

/**
 * Open a named semaphore.
 * <name> must be a null-terminated string of length 2-255 starting with '/' and not
 * containing any other '/' characters.
 */
static IPCAckError open_semaphore(Semaphore *semaphore, String *name,
                                  unsigned int value) {
#ifdef IPCACK_WINDOWS
    IPCAckError err = IPCACK_OK;
    if ((err = utf8_to_wide_char_scratch(name->bytes, name->len, wide_char_scratch,
                                         WIDE_CHAR_SCRATCH_SIZE)) != 0) {
        return err;
    }
    HANDLE sem = CreateSemaphoreW(NULL, value, LONG_MAX, wide_char_scratch);
    if (sem == NULL) {
        return error(SYS, SEM_OPEN);
    }
    *semaphore = sem;
#elif defined(IPCACK_POSIX)
    Semaphore sem = sem_open(name, O_CREAT, 0644, value);
    if (sem == SEM_FAILED) {
        return IPCACK_ERROR_SYSTEM;
    }
    *semaphore = sem;
#endif
    return IPCACK_OK;
}

#define IPCACK_WAIT_SUCCESS 0x0
#define IPCACK_WAIT_TIMEOUT 0x1
#define IPCACK_WAIT_ERROR 0x8

static IPCAckError wait_semaphore(Semaphore sem, uint32_t timeout_ms) {
#ifdef IPCACK_WINDOWS
    DWORD status = WaitForSingleObject(sem, timeout_ms);
    switch (status) {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        return IPCACK_WAIT_SUCCESS;
    case WAIT_TIMEOUT:
        return IPCACK_WAIT_TIMEOUT;
    case WAIT_FAILED:
    default:
        return IPCACK_WAIT_ERROR;
    }
#elif defined(IPCACK_POSIX)
    struct timespec ts;
    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000000;
    int status = sem_timedwait(sem, &ts);
    if (status == 0) {
        return IPCACK_WAIT_SUCCESS;
    }
    switch (errno) {
    case ETIMEDOUT:
        return IPCACK_WAIT_TIMEOUT;
    case EINTR:
    case EINVAL:
    default:
        return IPCACK_WAIT_ERROR;
    }
#endif
}

static IPCAckError post_semaphore(Semaphore sem) {
#ifdef IPCACK_WINDOWS
    BOOL status = ReleaseSemaphore(sem, 1, NULL);
    return (status != 0) ? IPCACK_OK : error(SYS, SEM);
#elif defined(IPCACK_POSIX)
    int status = sem_post(sem);
    return (status == 0) ? IPCACK_OK : IPCACK_ERROR_SYSTEM;
#endif
}

static IPCAckError close_semaphore(Semaphore sem, const char *name) {
#ifdef IPCACK_WINDOWS
    (void)name;
    BOOL status = CloseHandle(sem);
    return (status != 0) ? IPCACK_OK : error(SYS, FREE);
#elif defined(IPCACK_POSIX)
    bool success = true;
    success = success && (sem_close(sem) == 0);
    success = success && (sem_unlink(name) == 0);
    return success ? IPCACK_OK : error(SYS, FREE);
#endif
}

#define DEFINE_ARRAY(Type, TypeName)                                                     \
    typedef struct TypeName {                                                            \
        size_t len;                                                                      \
        size_t capacity;                                                                 \
        Type *slice;                                                                     \
    } TypeName;                                                                          \
                                                                                         \
    IPCAckError TypeName##_new(TypeName *list, size_t initial_size) {                    \
        size_t capacity = initial_size;                                                  \
        Type *slice = malloc(capacity * sizeof(Type));                                   \
        if (!slice) {                                                                    \
            return error(SYS, MALLOC);                                                   \
        }                                                                                \
        *list = (TypeName){.len = 0, .capacity = capacity, .slice = slice};              \
        return IPCACK_OK;                                                                \
    }                                                                                    \
                                                                                         \
    void TypeName##_free(TypeName *list) {                                               \
        if (list) {                                                                      \
            free(list->slice);                                                           \
        }                                                                                \
    }                                                                                    \
                                                                                         \
    IPCAckError TypeName##_append(TypeName *list, Type value) {                          \
        if (list == NULL) {                                                              \
            return error(ARGS, IS_NULL);                                                 \
        }                                                                                \
                                                                                         \
        if (list->len + 1 > list->capacity) {                                            \
            size_t new_capacity = list->capacity * 2;                                    \
            Type *new_slice = realloc(list->slice, new_capacity * sizeof(Type));         \
                                                                                         \
            if (!new_slice) {                                                            \
                return error(SYS, MALLOC);                                               \
            }                                                                            \
                                                                                         \
            list->capacity = new_capacity;                                               \
            list->slice = new_slice;                                                     \
        }                                                                                \
                                                                                         \
        list->slice[list->len] = value;                                                  \
        list->len++;                                                                     \
                                                                                         \
        return IPCACK_OK;                                                                \
    }                                                                                    \
                                                                                         \
    IPCAckError TypeName##_delete(TypeName *list, size_t i) {                            \
        if (list == NULL) {                                                              \
            return error(ARGS, IS_NULL);                                                 \
        }                                                                                \
        if (i >= list->len) {                                                            \
            return error(ARGS, INDEX);                                                   \
        }                                                                                \
                                                                                         \
        list->len--;                                                                     \
        list->slice[i] = list->slice[list->len];                                         \
        return IPCACK_OK;                                                                \
    }

typedef struct ClientConnection {
    uint32_t id;
    uint32_t dynamic_id;
    ShmemBuffer shmem;
    Semaphore client_sem;
} ClientConnection;

DEFINE_ARRAY(ClientConnection, Array_ClientConnection)

typedef struct JoinArea {
    uint32_t fixed_id; // Server writable, client readable.
    uint32_t counter;  // Write locked: Client writable, server readable.
    bool server_alive; // Server writable, client readable.
} JoinArea;

const uint32_t INITIALIZED_CANARY = 0x12345678;

typedef struct Server {
    Array_ClientConnection clients;
    Semaphore server_event_sem;

    ShmemBuffer join_shmem;

    uint32_t join_last_counter;
    uint32_t initialized_canary;
    uint16_t name_len;
    char name[];
} Server;

typedef struct Client {
    ClientConnection connection;
    Semaphore server_event_sem;

    ShmemBuffer join_shmem;

    uint32_t initialized_canary;
    uint16_t name_len;
    char name[];
} Client;

IPCAckError ipcack_server_bind(IPCAckServer *server, char *name) {
    IPCAckError err = IPCACK_OK;
    bool server_alloced = false;
    bool client_array_alloced = false;
    bool open_sem_opened = false;
    bool shmem_opened = false;

    if (server == NULL) {
        err = error(ARGS, IS_NULL);
        goto error_cleanup;
    }

    // Validate given name/address.
    if ((err = validate_shmem_name_external(name)))
        goto error_cleanup;
    size_t name_len = strnlen(name, IPCACK_MAX_SHMEM_NAME);

    // Allocate the server itself.
    Server *ptr = malloc(sizeof(Server) + name_len + 1);
    if (ptr == NULL) {
        err = error(SYS, MALLOC);
        goto error_cleanup;
    }
    server_alloced = true;

    // Initialize internal name storage.
    ptr->name_len = name_len;
    memcpy(ptr->name, name, name_len);
    ptr->name[name_len] = '\0';

    // Initialize client array list.
    if ((err = Array_ClientConnection_new(&ptr->clients, 8)))
        goto error_cleanup;
    client_array_alloced = true;

    // // Create a semaphore for joining (acts as a mutex)
    // String join_sem_name = {0};
    // err = build_shmem_name(
    //     &(BuildNameParams){.dynamic_id = 0,
    //                        .fixed_id = 0,
    //                        .name = (String){.len = ptr->name_len, .bytes = ptr->name},
    //                        .object_type_str = &ipcack_prefix_mutex},
    //     &join_sem_name, ptr->string_buffer, sizeof(ptr->string_buffer));
    // if (err)
    //     goto error_cleanup;
    // err = open_semaphore(&ptr->join_sem, &join_sem_name, 1);
    // if (err)
    //     goto error_cleanup;

    // Create a semaphore for server events
    String server_sem_name = {0};
    err = build_shmem_name(
        &(BuildNameParams){.name = (String){.len = ptr->name_len, .bytes = ptr->name},
                           .object_type_str = &ipcack_prefix_server_sem},
        &server_sem_name, shmem_string_scratch, shmem_string_scratch);
    if (err)
        goto error_cleanup;
    err = open_semaphore(&ptr->server_event_sem, &server_sem_name, 1);
    if (err)
        goto error_cleanup;
    open_sem_opened = true;

    // Open the shared memory buffer.
    String join_shmem_name = {0};
    err = build_shmem_name(
        &(BuildNameParams){.name = (String){.len = ptr->name_len, .bytes = ptr->name},
                           .object_type_str = &ipcack_prefix_join_area},
        &join_shmem_name, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err)
        goto error_cleanup;

    printf("shmem name is '%s'\n", join_shmem_name.bytes);
    ptr->join_shmem = (ShmemBuffer){.size = sizeof(JoinArea)};
    if ((err = open_shmem(&ptr->join_shmem, join_shmem_name)))
        goto error_cleanup;

    shmem_opened = true;

    const uint32_t initial_counter_value = 0x0;
    ((JoinArea *)ptr->join_shmem.buf)->counter = initial_counter_value;
    ptr->join_last_counter = initial_counter_value;

    JoinArea *join_area = (JoinArea *)ptr->join_shmem.buf;
    if (join_area->server_alive == true) {
        err = error(IPC, ALREADY_OPEN);
        goto error_cleanup;
    }

    join_area->server_alive = true;

    ptr->initialized_canary = INITIALIZED_CANARY;
    server->internal = ptr;

    return err;

error_cleanup:
    if (shmem_opened) {
        String join_shmem_name = {0};
        IPCAckError err = build_shmem_name(
            &(BuildNameParams){.name = (String){.len = ptr->name_len, .bytes = ptr->name},
                               .object_type_str = &ipcack_prefix_join_area},
            &join_shmem_name, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
        if (!err)
            close_shmem(&ptr->join_shmem, join_shmem_name.bytes);
    }
    if (open_sem_opened) {
        String server_sem_name = {0};
        IPCAckError err = build_shmem_name(
            &(BuildNameParams){.name = (String){.len = ptr->name_len, .bytes = ptr->name},
                               .object_type_str = &ipcack_prefix_server_sem},
            &server_sem_name, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
        if (!err)
            close_semaphore(ptr->server_event_sem, server_sem_name.bytes);
    }
    if (client_array_alloced)
        Array_ClientConnection_free(&ptr->clients);
    if (server_alloced)
        free(ptr);

    return err;
}

IPCAckError ipcack_server_close(IPCAckServer server) {
    IPCAckError err = IPCACK_OK;

    Server *ptr = server.internal;

    if (ptr == NULL)
        return error(ARGS, IS_NULL);

    if (ptr->initialized_canary != INITIALIZED_CANARY)
        return error(ARGS, NOT_INITIALIZED);

    // Let clients know that the server is not alive.
    ((JoinArea *)ptr->join_shmem.buf)->server_alive = false;

    // This resource cleanup should be done in the same way everywhere it's needed.
    // Close system resources.
    String join_shmem_name = {0};
    err = build_shmem_name(
        &(BuildNameParams){.name = (String){.len = ptr->name_len, .bytes = ptr->name},
                           .object_type_str = &ipcack_prefix_join_area},
        &join_shmem_name, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    close_shmem(&ptr->join_shmem, join_shmem_name.bytes);

    String server_sem_name = {0};
    err = build_shmem_name(
        &(BuildNameParams){.name = (String){.len = ptr->name_len, .bytes = ptr->name},
                           .object_type_str = &ipcack_prefix_server_sem},
        &server_sem_name, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err)
        close_semaphore(ptr->server_event_sem, server_sem_name.bytes);

    // Free all memory related to clients.
    Array_ClientConnection_free(&ptr->clients);

    // Free struct itself.
    if (ptr)
        free(ptr);

    return IPCACK_OK;
}

IPCAckError ipcack_client_connect(IPCAckClient *client, char *name, uint32_t timeout_ms) {
    IPCAckError err = IPCACK_OK;
    bool client_alloced = false;

    if (client == NULL) {
        err = error(ARGS, IS_NULL);
        goto error_cleanup;
    }

    // Validate given name/address.
    if ((err = validate_shmem_name_external(name)))
        goto error_cleanup;
    size_t name_len = strnlen(name, IPCACK_MAX_SHMEM_NAME);

    // Allocate the client itself.
    Client *ptr = malloc(sizeof(Client) + name_len + 1);
    if (ptr == NULL) {
        err = error(SYS, MALLOC);
        goto error_cleanup;
    }
    client_alloced = true;

    // Initialize internal name storage.
    ptr->name_len = name_len;
    memcpy(ptr->name, name, name_len);
    ptr->name[name_len] = '\0';

    // Open the join waiting area shared memory.


    // Open the join waiting area shared memory.



    ptr->initialized_canary = INITIALIZED_CANARY;
    client->internal = ptr;

    return err;

error_cleanup:
    if (client_alloced)
        free(ptr);

    return err;
}

IPCAckError ipcack_client_disconnect(IPCAckClient client) {}