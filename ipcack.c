// TODO: Implement mutex APIs.
// TODO: Do server init.
// TODO: Do client init.
// TODO: Do server-client loop.
// TODO: Handle timeouts and exits.
// TODO: Test in C.
// TODO: Wrap in python API.

/**
 * STRING CONVENTIONAll strings should include their length.
 * All strings should be null-terminated.
 *
 */

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

#ifdef IPCACK_WINDOWS
typedef HANDLE ShmemFD;
typedef HANDLE Semaphore;
#elif defined(IPCACK_POSIX)
typedef int ShmemFD;
typedef sem_t *Semaphore;
#endif

/// Common prefix to all system-wide named objects.
#define IPCACK_PREFIX_LEN ((sizeof ipcack_prefix) - 1)
static const char ipcack_prefix[] = "_ipcack_";

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
static const char ipcack_prefix_shmem[] = "sharemem";
static_assert((sizeof ipcack_prefix_shmem - 1) == IPCACK_OBJECT_TYPE_LEN,
              "Prefix length.");
static const char ipcack_prefix_semaphore[] = "semaphor";
static_assert((sizeof ipcack_prefix_semaphore - 1) == IPCACK_OBJECT_TYPE_LEN,
              "Prefix length.");
static const char ipcack_prefix_mutex[] = "mutexloc";
static_assert((sizeof ipcack_prefix_mutex - 1) == IPCACK_OBJECT_TYPE_LEN,
              "Prefix length.");

#define IPCACK_MIN_SHMEM_NAME                                                            \
    (IPCACK_PREFIX_LEN + IPCACK_FIXED_ID_LEN + IPCACK_DYNAMIC_ID_LEN +                   \
     IPCACK_OBJECT_TYPE_LEN)

#define IPCACK_MAX_SHMEM_NAME (IPCACK_MIN_SHMEM_NAME + IPCACK_MAX_NAME)
static_assert(IPCACK_MAX_SHMEM_NAME < 250,
              "Shared memory object name must be less than 250");

typedef struct String {
    /// Length in bytes, NOT characters or code points.
    uint16_t len;
    /// Pointer to <len> count raw UTF-8 bytes.
    char *bytes;
} String;

typedef struct ShmemBuffer {
    ShmemFD fd;
    char *buf;
    size_t size;
} ShmemBuffer;

static int32_t validate_shmem_name_external(const char *name) {
    size_t len = strnlen(name, IPCACK_MAX_NAME + 1);
    if (len > IPCACK_MAX_NAME) { // Name must be short enough.
        return IPCACK_ERROR_NAME_TOO_LONG;
    }
    if (len < 2) { // Name must be long enough.
        return IPCACK_ERROR_NAME_INVALID;
    }
    if (strchr(name, '/') != NULL) { // Name must not contain any other /.
        return IPCACK_ERROR_NAME_INVALID;
    }

    return IPCACK_ERROR_NO_ERROR;
}

static inline char *base64_encode(uint32_t value) {
    static const char base64_table[64] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
    static char temp_buf[IPCACK_FIXED_ID_LEN];

    for (int i = 0; i < IPCACK_FIXED_ID_LEN; ++i) {
        temp_buf[i] = base64_table[(value & 0x3F)];
        value >>= 6;
    }
    return temp_buf;
}

static inline size_t cat(char *buf, uint16_t start, uint16_t len, const char *addition) {
    int i = 0;
    for (; i < len; ++i)
        buf[start + i] = addition[i];
    return i;
}

// TODO: Make thread safe.
static char string_scratch[IPCACK_MAX_SHMEM_NAME + 1];

typedef struct BuildNameParams {
    /// UTF-8 string of at most <IPCACK_MAX_NAME> bytes that has already been validated.
    String name;
    const char (*object_type_str)[IPCACK_OBJECT_TYPE_LEN + 1];
    uint32_t fixed_id;
    uint32_t dynamic_id;
} BuildNameParams;
static int32_t build_shmem_name(BuildNameParams *params, String *string, char *buf,
                                size_t bufsize) {
    size_t total_length_needed = 1 + IPCACK_MIN_SHMEM_NAME + params->name.len;
    if (bufsize < total_length_needed)
        return IPCACK_ERROR_NAME_TOO_LONG;

    size_t start = 0;
    start += cat(buf, start, IPCACK_PREFIX_LEN, ipcack_prefix);
    start += cat(buf, start, IPCACK_FIXED_ID_LEN, base64_encode(params->fixed_id));
    start += cat(buf, start, IPCACK_DYNAMIC_ID_LEN, base64_encode(params->dynamic_id));
    start += cat(buf, start, IPCACK_DYNAMIC_ID_LEN, base64_encode(params->dynamic_id));
    start += cat(buf, start, params->name.len, params->name.bytes);

    string->bytes = buf;
    string->len = start;

    return IPCACK_ERROR_NO_ERROR;
}

#ifdef IPCACK_WINDOWS
// TODO: Make thread safe.
/**
 * Scratch buffer for converting UTF-8 to WCHAR for Windows system calls.
 * While only at most <IPCACK_MAX_SHMEM_NAME> WCHAR's are needed to convert to UTF-16,
 * extra space is added just in case.
 * + 1 added for null-terminator.
 */
static WCHAR wide_char_scratch[IPCACK_MAX_SHMEM_NAME * 2 + 1];
#define WIDE_CHAR_SCRATCH_SIZE ((sizeof wide_char_scratch) / (sizeof *wide_char_scratch))

static int32_t utf8_to_wide_char_scratch(const char *name, size_t len, WCHAR buf[],
                                         size_t bufsize) {

    int status = MultiByteToWideChar(CP_UTF8, 0, name, len, NULL, 0);
    if ((status <= 0)) {
        // Error occured.
        return IPCACK_ERROR_NAME_INVALID;
    }
    unsigned int ustatus = status;
    if (ustatus > bufsize) {
        // The string is too long.
        return IPCACK_ERROR_NAME_TOO_LONG;
    }

    status = MultiByteToWideChar(CP_UTF8, 0, name, len, buf, bufsize);
    if (status <= 0) {
        return IPCACK_ERROR_NAME_INVALID;
    }

    buf[status] = '\0';
    return IPCACK_ERROR_NO_ERROR;
}
#endif

/**
 * Open a shared memory buffer.
 * <name> must be a null-terminated string of length 2-255 starting with '/' and not
 * containing any other '/' characters.
 * <size> must not exceed the maximum shared memory buffer size.
 */
static int32_t open_shmem(ShmemBuffer *shmem, String name) {
#ifdef IPCACK_WINDOWS
    if (utf8_to_wide_char_scratch(name.bytes, name.len, wide_char_scratch,
                                  WIDE_CHAR_SCRATCH_SIZE) != 0) {
        return IPCACK_ERROR_NAME_INVALID;
    }
    HANDLE handle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                       (shmem->size >> 32) & 0xFFFFFFFF,
                                       shmem->size & 0xFFFFFFFF, wide_char_scratch);
    if (handle == NULL) {
        return IPCACK_ERROR_SYSTEM;
    }

    void *buf = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, shmem->size);
    if (buf == NULL) {
        CloseHandle(handle);
        return IPCACK_ERROR_SYSTEM;
    }

    shmem->fd = handle;
    shmem->buf = buf;

    return IPCACK_ERROR_NO_ERROR;
#elif defined(IPCACK_POSIX)
    int fd_or_err = shm_open(shmem->name, O_CREAT | O_RDWR, 0644);
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

    shmem->fd = fd_or_error;
    shmem->buf = buf;

    return IPCACK_ERROR_NO_ERROR;
#endif
}

/**
 * Close an open shared memory buffer.
 * Will try to both unmap and close the shared memory and file handle on each call.
 */
static int32_t close_shmem(ShmemBuffer *shmem) {
#ifdef IPCACK_WINDOWS
    BOOL success = TRUE;
    success = success && UnmapViewOfFile(shmem->buf);
    success = success && CloseHandle(shmem->fd);
    return success ? IPCACK_ERROR_NO_ERROR : IPCACK_ERROR_SYSTEM;
#elif defined(IPCACK_POSIX)
    bool success = true;
    success = success && (munmap(shmem->buf, shmem->size) == 0);
    success = success && (shm_unlink(shmem->name) == 0);
    return success ? IPCACK_ERROR_NO_ERROR : IPCACK_ERROR_SYSTEM;
#endif
}

/**
 * Open a named semaphore.
 * <name> must be a null-terminated string of length 2-255 starting with '/' and not
 * containing any other '/' characters.
 */
static int32_t open_semaphore(Semaphore *semaphore, String *name) {
#ifdef IPCACK_WINDOWS
    if (utf8_to_wide_char_scratch(name->bytes, name->len, wide_char_scratch,
                                  WIDE_CHAR_SCRATCH_SIZE) != 0) {
        return IPCACK_ERROR_NAME_INVALID;
    }
    HANDLE sem = CreateSemaphoreW(NULL, 0, LONG_MAX, wide_char_scratch);
    if (sem == NULL) {
        return IPCACK_ERROR_SYSTEM;
    }
    *semaphore = sem;
#elif defined(IPCACK_POSIX)
    Semaphore sem = sem_open(name, O_CREAT, 0644, 0);
    if (sem == SEM_FAILED) {
        return IPCACK_ERROR_SYSTEM;
    }
    *semaphore = sem;
#endif
}

#define IPCACK_WAIT_SUCCESS 0x0
#define IPCACK_WAIT_TIMEOUT 0x1
#define IPCACK_WAIT_ERROR 0x8

static int32_t wait_semaphore(Semaphore sem, uint32_t timeout_ms) {
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

static int32_t post_semaphore(Semaphore sem) {
#ifdef IPCACK_WINDOWS
    BOOL status = ReleaseSemaphore(sem, 1, NULL);
    return (status != 0) ? IPCACK_ERROR_NO_ERROR : IPCACK_ERROR_SYSTEM;
#elif defined(IPCACK_POSIX)
    int status = sem_post(sem);
    return (status == 0) ? IPCACK_ERROR_NO_ERROR : IPCACK_ERROR_SYSTEM;
#endif
}

static int32_t close_semaphore(Semaphore sem, const char *name) {
#ifdef IPCACK_WINDOWS
    (void)name;
    BOOL status = CloseHandle(sem);
    return (status != 0) ? IPCACK_ERROR_NO_ERROR : IPCACK_ERROR_SYSTEM;
#elif defined(IPCACK_POSIX)
    bool success = true;
    success = success && (sem_close(sem) == 0);
    success = success && (sem_unlink(name) == 0);
    return success ? IPCACK_ERROR_NO_ERROR : IPCACK_ERROR_SYSTEM;
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
            return IPCACK_ERROR_SYSTEM;                                                  \
        }                                                                                \
        *list = (TypeName){.len = 0, .capacity = capacity, .slice = slice};              \
        return IPCACK_ERROR_NO_ERROR;                                                    \
    }                                                                                    \
                                                                                         \
    void TypeName##_free(TypeName *list) {                                               \
        if (list) {                                                                      \
            free(list->slice);                                                           \
        }                                                                                \
    }                                                                                    \
                                                                                         \
    IPCAckError TypeName##_append(TypeName *list, Type value) {                          \
        if (!list) {                                                                     \
            return IPCACK_ERROR_ARG_INVALID;                                             \
        }                                                                                \
                                                                                         \
        if (list->len + 1 > list->capacity) {                                            \
            size_t new_capacity = list->capacity * 2;                                    \
            Type *new_slice = realloc(list->slice, new_capacity * sizeof(Type));         \
                                                                                         \
            if (!new_slice) {                                                            \
                return IPCACK_ERROR_SYSTEM;                                              \
            }                                                                            \
                                                                                         \
            list->capacity = new_capacity;                                               \
            list->slice = new_slice;                                                     \
        }                                                                                \
                                                                                         \
        list->slice[list->len] = value;                                                  \
        list->len++;                                                                     \
                                                                                         \
        return IPCACK_ERROR_NO_ERROR;                                                    \
    }                                                                                    \
                                                                                         \
    IPCAckError TypeName##_delete(TypeName *list, size_t i) {                            \
        if (!list || i >= list->len) {                                                   \
            return IPCACK_ERROR_ARG_INVALID;                                             \
        }                                                                                \
                                                                                         \
        list->len--;                                                                     \
        list->slice[i] = list->slice[list->len];                                         \
        return IPCACK_ERROR_NO_ERROR;                                                    \
    }

typedef struct ClientConnection {
    uint32_t id;
    uint32_t dynamic_id;
    ShmemBuffer shmem;
} ClientConnection;

DEFINE_ARRAY(ClientConnection, Array_ClientConnection)

typedef struct JoinArea {
    uint32_t fixed_id;
    uint32_t counter;
} JoinArea;

typedef struct Server {
    Array_ClientConnection clients;
    ShmemBuffer join_shmem;

    char string_buffer[IPCACK_MAX_SHMEM_NAME + 1];

    uint16_t name_len;
    char name[];
} Server;

struct _IPCAckServer {
    Server *ptr;
};

IPCAckError ipcack_server_bind(IPCAckServer *server, char *name) {
    IPCAckError err = IPCACK_ERROR_NO_ERROR;
    bool server_alloced = false;
    bool client_array_alloced = false;

    if (!server) {
        err = IPCACK_ERROR_ARG_INVALID;
        goto cleanup;
    }

    // Validate given name/address.
    if ((err = validate_shmem_name_external(name)))
        goto cleanup;
    size_t name_len = strnlen(name, IPCACK_MAX_SHMEM_NAME);

    // Allocate the server itself.
    Server *ptr = malloc(sizeof(Server) + name_len);
    if (ptr == NULL) {
        err = IPCACK_ERROR_SYSTEM;
        goto cleanup;
    }
    server_alloced = true;

    // Initialize internal name storage.
    ptr->name_len = name_len;
    memcpy(ptr->name, name, name_len);

    // Initialize client array list.
    if ((err = Array_ClientConnection_new(&ptr->clients, 8)))
        goto cleanup;
    client_array_alloced = true;

    String join_shmem_name = {0};
    err = build_shmem_name(
        &(BuildNameParams){.dynamic_id = 0,
                           .fixed_id = 0,
                           .name = (String){.len = ptr->name_len, .bytes = ptr->name},
                           .object_type_str = &ipcack_prefix_shmem},
        &join_shmem_name, ptr->string_buffer, sizeof(ptr->string_buffer));
    if (err)
        goto cleanup;

    // Open the shared memory buffer.
    ptr->join_shmem = (ShmemBuffer){.size = sizeof(JoinArea)};
    if ((err = open_shmem(&ptr->join_shmem, join_shmem_name)))
        goto cleanup;

    (server)->internal = ptr;

    return err;

cleanup:
    if (client_array_alloced)
        Array_ClientConnection_free(&ptr->clients);
    if (server_alloced)
        free(ptr);
    return err;
}