/*
TODO:
- add mutex to server init
- refactor to use ordered defer instead of many bools
- client init and join
- server loop
- client close
- client send and receive
- write tests
*/
// TODO: Do client init.
// TODO: Do client disconnect.
// TODO: Handle 2 servers trying to bind at the same time.

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
// - Client share 1 mutex to handle joining the server, to prevent concurrent
//   writes to the join shared memory area.

#include "epicac.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef _WIN32
#define EPC_WINDOWS
#include <Windows.h>
#else
#define EPC_POSIX
#include <fcntl.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#endif

#ifndef static_assert
#define static_assert(ignore, args)
#endif

static_assert((EPC_ERR_H_COUNT) < UINT8_MAX, "Error codes must fit in 1 byte.");
static_assert(EPC_ERR_L_COUNT < UINT8_MAX, "Error code details must fit in 1 byte.");

static inline EPCError error(EPCErrorHigh err_high, EPCErrorLow err_low) {
    // return (err_high << 8) | err_low;
    return (EPCError){err_high, err_low};
}

#define error(high, low) error(EPC_ERR_H_##high, EPC_ERR_L_##low)

// Compiler specific config.
#if defined(_MSC_VER)
#define thread_local __declspec(thread)
#elif defined(__GNUC__) || defined(__clang__)
#define thread_local __thread
#else
#error "Only MSVC, Clang, and GCC are supported."
// These should be defined if porting to a new compiler.
#define thread_local
#endif

// ███████ ████████ ██████  ██ ███    ██  ██████
// ██         ██    ██   ██ ██ ████   ██ ██
// ███████    ██    ██████  ██ ██ ██  ██ ██   ███
//      ██    ██    ██   ██ ██ ██  ██ ██ ██    ██
// ███████    ██    ██   ██ ██ ██   ████  ██████

/// Common prefix to all system-wide named objects.
#define EPC_PREFIX_LEN ((sizeof epc_prefix) - 1)
static const char epc_prefix[] = "/_epc_";

/// 5 character or 30-bit base64 connection ID assigned per client.
#define EPC_FIXED_ID_LEN 5
#define EPC_FIXED_ID_BITS (EPC_FIXED_ID_LEN * 6)
static_assert(EPC_FIXED_ID_BITS < 32,
              "ID must fit into a 32 bit integer. This may change later.");
/// 5 character or 28-bit base64 connection ID assigned per client buffer.
#define EPC_DYNAMIC_ID_LEN EPC_FIXED_ID_LEN
#define EPC_DYNAMIC_ID_BITS (EPC_FIXED_ID_LEN * 6)

/// 8 character object specifier.
#define EPC_OBJECT_TYPE_LEN 8
#define DEFINE_EPC_OBJECT_TYPE_PREFIX(var, value)                                        \
    static const char epc_prefix_##var[EPC_OBJECT_TYPE_LEN + 1] = value;                 \
    static_assert((sizeof epc_prefix_##var - 1) == EPC_OBJECT_TYPE_LEN, "Prefix "        \
                                                                        "length.")

/// Shared memory: Waiting area for clients wanting to join server.
DEFINE_EPC_OBJECT_TYPE_PREFIX(join_shmem, "joinarea");
/// Mutex: For servers wanting to bind an address.
DEFINE_EPC_OBJECT_TYPE_PREFIX(server_addr_lock, "addrlock");

/// Mutex: For clients wanting to join server.
DEFINE_EPC_OBJECT_TYPE_PREFIX(join_lock, "joinlock");
/// Semaphore: For clients wanting to join server.
DEFINE_EPC_OBJECT_TYPE_PREFIX(join_sem, "joinsema");

/// Shared memory: buffer for client-server messages.
DEFINE_EPC_OBJECT_TYPE_PREFIX(shmem, "sharemem");
/// Semaphore: event for server wake up.
DEFINE_EPC_OBJECT_TYPE_PREFIX(server_sem, "servesem");
/// Semaphore: event for client wake up.
DEFINE_EPC_OBJECT_TYPE_PREFIX(client_sem, "clientse");

#define EPC_MIN_SHMEM_NAME                                                               \
    (EPC_PREFIX_LEN + EPC_FIXED_ID_LEN + EPC_DYNAMIC_ID_LEN + EPC_OBJECT_TYPE_LEN)

#define EPC_MAX_SHMEM_NAME (EPC_MIN_SHMEM_NAME + EPC_MAX_NAME)
static_assert(EPC_MAX_SHMEM_NAME < 250,
              "Shared memory object name must be less than 250");

typedef struct String {
    /// Pointer to <len> count raw UTF-8 bytes, where bytes[len] = 0x0.
    char *bytes;
    /// Length in bytes, NOT characters or code points.
    uint16_t len;
} String;

static EPCError validate_shmem_name_external(const char *name) {
    size_t len = strnlen(name, EPC_MAX_NAME + 1);
    if (len > EPC_MAX_NAME) { // Name must be short enough.
        return error(ARGS, STRING_TOO_LONG);
    }
    if (len < 2) { // Name must be long enough.
        return error(ARGS, STRING_TOO_SHORT);
    }
    if ((strchr(name, '/') != NULL) ||
        strchr(name, '\\') != NULL) { // Name must not contain any other / or \.
        return error(ARGS, STRING_INVALID);
    }

    return EPC_OK;
}

static inline void base64_encode(uint32_t value, char buffer[EPC_FIXED_ID_LEN]) {
    static const char base64_table[64] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

    for (int i = 0; i < EPC_FIXED_ID_LEN; ++i) {
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
// static char string_scratch[EPC_MAX_SHMEM_NAME + 1];

static thread_local char shmem_string_scratch[EPC_MAX_SHMEM_NAME + 1];
#define SHMEM_SCRATCH_SIZE                                                               \
    ((sizeof shmem_string_scratch) / (sizeof *shmem_string_scratch))

typedef struct BuildNameParams {
    /// UTF-8 string of at most <EPC_MAX_NAME> bytes that has already been validated.
    String name;
    const char(*object_type_str);
    uint32_t fixed_id;
    uint32_t dynamic_id;
} BuildNameParams;
static EPCError build_internal_obj_name(BuildNameParams *params, String *string,
                                        char *buf, size_t bufsize) {
    size_t total_length_needed = 1 + EPC_MIN_SHMEM_NAME + params->name.len;
    if (bufsize < total_length_needed)
        return error(ARGS, STRING_TOO_LONG);

    char b64_scratch[EPC_FIXED_ID_LEN];

    size_t start = 0;
    start += cat(buf, start, EPC_PREFIX_LEN, epc_prefix);
    start += cat(buf, start, EPC_OBJECT_TYPE_LEN, (const char *)params->object_type_str);
    base64_encode(params->fixed_id, b64_scratch);
    start += cat(buf, start, EPC_FIXED_ID_LEN, b64_scratch);
    base64_encode(params->dynamic_id, b64_scratch);
    start += cat(buf, start, EPC_DYNAMIC_ID_LEN, b64_scratch);
    start += cat(buf, start, params->name.len, params->name.bytes);
    start += cat(buf, start, 1, "\0");

    string->bytes = buf;
    string->len = start;

    return EPC_OK;
}

#ifdef EPC_WINDOWS

/// TODO: check if this is threadsafe

/// @brief Scratch buffer for converting UTF-8 to `WCHAR` for Windows calls.
/// While only at most `EPC_MAX_SHMEM_NAME` `WCHAR`s are needed to convert to UTF-16,
/// extra space is added just in case.
/// + 1 added for null-terminator.
static thread_local WCHAR wide_char_scratch[EPC_MAX_SHMEM_NAME * 2 + 1];
#define WIDE_CHAR_SCRATCH_SIZE ((sizeof wide_char_scratch) / (sizeof *wide_char_scratch))

static EPCError utf8_to_wide_char_scratch(const char *name, size_t len, WCHAR buf[],
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
    return EPC_OK;
}
#endif

// ███████ ██   ██ ███    ███ ███████ ███    ███
// ██      ██   ██ ████  ████ ██      ████  ████
// ███████ ███████ ██ ████ ██ █████   ██ ████ ██
//      ██ ██   ██ ██  ██  ██ ██      ██  ██  ██
// ███████ ██   ██ ██      ██ ███████ ██      ██

#ifdef EPC_WINDOWS
typedef HANDLE ShmemFD;
#elif defined(EPC_POSIX)
typedef int ShmemFD;
#endif

typedef struct ShmemBuffer {
    ShmemFD fd;
    volatile char *buf;
    size_t size;
} ShmemBuffer;

/// @brief Open a shared memory buffer.
/// @param shmem Buffer to initialize.
/// @param name Null-terminated `String` of length 2-`EPC_MAX_SHMEM_NAME`, containing
/// exactly 1 `/` as the first character.
/// @return
static EPCError open_shmem(ShmemBuffer *shmem, String name, bool *already_open) {
    if (shmem->size == 0) {
        return error(ARGS, SIZE_TOO_SMALL);
    }

#ifdef EPC_WINDOWS
    EPCError err = EPC_OK;

    if ((err = utf8_to_wide_char_scratch(name.bytes, name.len, wide_char_scratch,
                                         WIDE_CHAR_SCRATCH_SIZE))
            .high) {
        return err;
    }
    HANDLE handle = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                       (shmem->size >> 32) & 0xFFFFFFFF,
                                       shmem->size & 0xFFFFFFFF, wide_char_scratch);
    if (handle == NULL) {
        return error(SYS, SHM_OPEN);
    }

    if (already_open != NULL) {
        *already_open = GetLastError() == ERROR_ALREADY_EXISTS;
    }

    void *buf = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, shmem->size);
    if (buf == NULL) {
        CloseHandle(handle);
        return error(SYS, MMAP);
    }

    shmem->fd = handle;
    shmem->buf = buf;
    return err;

#elif defined(EPC_POSIX)
    int fd_or_err = 0;
    if (already_open != NULL) {
        // Assume it already exists. Try and open without O_CREAT first.
        *already_open = true;
        fd_or_err = shm_open(name->bytes, O_RDWR, 0644);
        if ((fd_or_err == -1) && (errno == ENOENT)) {
            // If it doesn't exist, set `already_open` and create it.
            fd_or_err = shm_open(name->bytes, O_CREAT | O_RDWR, 0644);
            *already_open = false;
        }
    } else {
        fd_or_err = shm_open(name->bytes, O_CREAT | O_RDWR, 0644);
    }
    if (fd_or_err == -1) {
        return error(SYS, SHM_OPEN);
    }

    if (ftruncate(fd_or_err, shmem->size) == -1) {
        shm_unlink(shmem->name);
        return error(SYS, SHM_OPEN);
    }

    void *buf = mmap(NULL, shmem->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_or_err, 0);
    if (buf == MAP_FAILED) {
        close(fd_or_err);
        return error(SYS, MMAP);
    }

    shmem->fd = fd_or_err;
    shmem->buf = buf;
    return EPC_OK;
#endif
}

/// @brief Close an open shared memory buffer. Unmap and close the associated handle.
/// @param shmem Buffer to close.
/// @param name Null-terminated `String` of length 2-`EPC_MAX_SHMEM_NAME`, containing
/// exactly 1 `/` as the first character.
/// @return
static EPCError close_shmem(ShmemBuffer shmem) {
#ifdef EPC_WINDOWS
    BOOL success = TRUE;
    success = success && UnmapViewOfFile((char *)shmem.buf);
    success = success && CloseHandle(shmem.fd);
    return success ? EPC_OK : error(SYS, FREE);
#elif defined(EPC_POSIX)
    bool success = true;
    success = success && (munmap(shmem.buf, shmem.size) == 0);
    success = success && (close(shmem.fd) == 0);
    return success ? EPC_OK : error(SYS, FREE);
#endif
}

#ifdef EPC_POSIX
static EPCError destroy_shmem(const char *name) {
    return (shm_unlink(name) == 0) ? EPC_OK : error(SYS, FREE);
}
#endif

// ███████ ███████ ███    ███  █████  ██████  ██   ██  ██████  ██████  ███████
// ██      ██      ████  ████ ██   ██ ██   ██ ██   ██ ██    ██ ██   ██ ██
// ███████ █████   ██ ████ ██ ███████ ██████  ███████ ██    ██ ██████  █████
//      ██ ██      ██  ██  ██ ██   ██ ██      ██   ██ ██    ██ ██   ██ ██
// ███████ ███████ ██      ██ ██   ██ ██      ██   ██  ██████  ██   ██ ███████

#ifdef EPC_WINDOWS
typedef HANDLE Semaphore;
#elif defined(EPC_POSIX)
typedef sem_t *Semaphore;
#endif

/**
 * Open a named semaphore.
 * <name> must be a null-terminated string of length 2-255 starting with '/' and not
 * containing any other '/' characters.
 */
static EPCError open_semaphore(Semaphore *semaphore, String name) {
#ifdef EPC_WINDOWS
    EPCError err = EPC_OK;
    if ((err = utf8_to_wide_char_scratch(name.bytes, name.len, wide_char_scratch,
                                         WIDE_CHAR_SCRATCH_SIZE))
            .high) {
        return err;
    }
    HANDLE sem = CreateSemaphoreW(NULL, 0, LONG_MAX, wide_char_scratch);
    if (sem == NULL) {
        return error(SYS, SEM_OPEN);
    }
    *semaphore = sem;
    return EPC_OK;
#elif defined(EPC_POSIX)
    Semaphore sem = sem_open(name, O_CREAT, 0644, 0);
    if (sem == SEM_FAILED) {
        return error(SYS, SEM_OPEN);
    }
    *semaphore = sem;
    return EPC_OK;
#endif
}

static EPCError close_semaphore(Semaphore sem) {
#ifdef EPC_WINDOWS
    BOOL success = CloseHandle(sem);
    return success ? EPC_OK : error(SYS, FREE);
#elif defined(EPC_POSIX)
    bool success = (sem_close(sem) == 0);
    return success ? EPC_OK : error(SYS, FREE);
#endif
}

#ifdef EPC_POSIX
static EPCError destroy_semaphore(const char *name) {
    return (sem_unlink(name) == 0) ? EPC_OK : error(SYS, FREE);
}
#endif

static EPCError wait_semaphore(Semaphore sem, uint32_t timeout_ms) {
#ifdef EPC_WINDOWS
    DWORD status = WaitForSingleObject(sem, timeout_ms);
    switch (status) {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        return EPC_OK;
    case WAIT_TIMEOUT:
        return error(POLL, TIMEOUT);
    case WAIT_FAILED:
    default:
        return error(POLL, SEM);
    }
#elif defined(EPC_POSIX)
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return error(SYS, TIME);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000;
    int status = sem_timedwait(sem, &ts);
    if (status == 0) {
        return EPC_OK;
    }
    switch (errno) {
    case ETIMEDOUT:
        return error(POLL, TIMEOUT);
    case EINTR:
    case EINVAL:
    default:
        return error(POLL, SEM);
    }
#endif
}

static EPCError post_semaphore(Semaphore sem) {
#ifdef EPC_WINDOWS
    BOOL success = ReleaseSemaphore(sem, 1, NULL);
    return success ? EPC_OK : error(SYS, SEM);
#elif defined(EPC_POSIX)
    bool success = (sem_post(sem) == 0);
    return success ? EPC_OK : error(SYS, SEM);
#endif
}

// ███    ███ ██    ██ ████████ ███████ ██   ██
// ████  ████ ██    ██    ██    ██       ██ ██
// ██ ████ ██ ██    ██    ██    █████     ███
// ██  ██  ██ ██    ██    ██    ██       ██ ██
// ██      ██  ██████     ██    ███████ ██   ██

#ifdef EPC_WINDOWS
typedef HANDLE Mutex;
#elif defined(EPC_POSIX)
struct WrappedPosixMutex {
    pthread_mutex_t mutex;
    uint32_t initialized;
};
struct PosixMutexPolyfill {
    WrappedPosixMutex *shared;
    ShmemBuffer shmem;
};
typedef struct PosixMutexPolyfill Mutex;

static void short_nap() {
    struct timespec req, rem;
    ts.tv_sec = 0;
    // Sleep for at least 1000ns = 1us, but because of the scheduler, actually sleep for
    // some unknown amount of time greater than this. This isn't an RTOS!
    ts.tv_nsec = 1000;
    if ((nanosleep(&req, &rem) == -1) && (errno == EINTR))
        nanosleep(rem, NULL);
}

#endif

/**
 * Open a named mutex.
 * <name> must be a null-terminated string of length 2-255 starting with '/' and not
 * containing any other '/' or '\' characters.
 */
static EPCError open_mutex(Mutex *mutex, String name) {
#ifdef EPC_WINDOWS
    EPCError err = EPC_OK;
    if ((err = utf8_to_wide_char_scratch(name.bytes, name.len, wide_char_scratch,
                                         WIDE_CHAR_SCRATCH_SIZE))
            .high) {
        return err;
    }
    HANDLE mut = CreateMutexW(NULL, FALSE, wide_char_scratch);
    if (mut == NULL) {
        return error(SYS, MUTEX_OPEN);
    }
    *mutex = mut;
    return EPC_OK;
#elif defined(EPC_POSIX)
    EPCError err = EPC_OK;

    mutex->shmem.size = sizeof(WrappedPosixMutex);
    bool shmem_exists = false;
    EPCError err = open_shmem(&mutex->shmem, &name, &shmem_exists);
    if (err != EPC_OK)
        return err;
    mutex->shared = (WrappedPosixMutex *)shmem.buf;

    // Allow other thread to initialize first.
    // If this does not happen, assume ownership and initialize it.
    if (shmem_exists && (mutex->shared.initialized != INITIALIZED_CANARY)) {
        short_nap();
    }

    if (mutex->shared.initialized != INITIALIZED_CANARY) {
        pthread_mutexattr_t attr;
        if ((pthread_mutexattr_init(&attr) != 0) ||
            (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0) ||
            (pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) != 0) ||
            (pthread_mutex_init(&mutex->shared->mutex, &attr) != 0)) {
            // Unset on error to allow other threads to try.
            mutex->shared.initialized = 0;
            err = error(SYS, MUTEX_OPEN);
            close_shmem(mutex->shmem);
            // Leak shared memory by not calling unlink. It will be collected by the
            // server, or on restart if the server failed to initialize this.
        }
        mutex->shared.initialized = INITIALIZED_CANARY;
    }

    return err;
#endif
}

static EPCError close_mutex(Mutex mutex) {
#ifdef EPC_WINDOWS
    BOOL success = CloseHandle(mutex);
    return success ? EPC_OK : error(SYS, FREE);
#elif defined(EPC_POSIX)
    return close_shmem(mutex.shmem);
#endif
}

#ifdef EPC_POSIX
static EPCError destroy_mutex(Mutex mutex, const char *name) {
    int mutex_err = pthread_mutex_destroy(&mutex.shared->mutex);
    EPCError err = destroy_shmem(name);
    mutex.shared->initialized = 0;
    if (mutex_err != 0)
        return error(SYS, MUTEX_CLOSE);
    return err;
}
#endif

static EPCError wait_mutex(Mutex mutex, uint32_t timeout_ms) {
#ifdef EPC_WINDOWS
    DWORD status = WaitForSingleObject(mutex, timeout_ms);
    switch (status) {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        return EPC_OK;
    case WAIT_TIMEOUT:
        return error(POLL, TIMEOUT);
    case WAIT_FAILED:
    default:
        return error(POLL, MUTEX);
    }
#elif defined(EPC_POSIX)
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return error(SYS, TIME);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000;
    int status = pthread_mutex_timedlock(&mutex.shared->mutex, &ts);
    if (status == 0) {
        return EPC_OK;
    }
    switch (errno) {
    case EOWNERDEAD: // Analogous to WAIT_ABANDONED in Win32.
        // WARNING: Unchecked error.
        pthread_mutex_consistent(&mutex.shared->mutex);
        return EPC_OK;
    case ETIMEDOUT:
        return error(POLL, TIMEOUT);
    case EINTR:
    case EINVAL:
    default:
        return error(POLL, MUTEX);
    }
#endif
}

static EPCError release_mutex(Mutex mutex) {
#ifdef EPC_WINDOWS
    BOOL success = ReleaseMutex(mutex);
    return success ? EPC_OK : error(SYS, MUTEX);
#elif defined(EPC_POSIX)
    bool success = (pthread_mutex_unlock(&mutex.shared->mutex) == 0);
    return success ? EPC_OK : error(SYS, MUTEX);
#endif
}

// ██    ██ ████████ ██ ██      ███████
// ██    ██    ██    ██ ██      ██
// ██    ██    ██    ██ ██      ███████
// ██    ██    ██    ██ ██           ██
//  ██████     ██    ██ ███████ ███████
// void sleep_ms(uint32_t time_ms) {
// #ifdef EPC_WINDOWS
//     Sleep(time_ms);
// #elif defined(EPC_POSIX)
//     struct timespec req, rem;
//     ts.tv_sec = timeout_ms / 1000;
//     ts.tv_nsec = (timeout_ms % 1000) * 1000000;
//     if ((nanosleep(&req, &rem) == -1) && (errno == EINTR))
//         nanosleep(rem, NULL);
// #endif
// }

// typedef enum PollStage {
//     POLL_STAGE_SPIN = 0,
//     POLL_STAGE_15MS = 1,
//     POLL_STAGE_1S = 2,
// } PollStage;

// typedef struct PollTimeout {
//     uint32_t ms;
//     uint8_t stage;
// } PollTimeout;

#define STRINGIZE_(x) #x
#define STRINGIZE(x) STRINGIZE_(x)

uint64_t monotonic_time_ms() {
#ifdef EPC_WINDOWS
    return GetTickCount64();
#elif defined(EPC_POSIX)
    struct timespec ts = {0};
    // TODO: Verify if this behaviour is desired.
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror(__FILE__ ", line " STRINGIZE(__LINE__)", epicac.monotonic_time_ms.clock_gettime failed");
        return 0;
    }
    return ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
#endif
}

// ████████ ██    ██ ██████  ███████ ███████
//    ██     ██  ██  ██   ██ ██      ██
//    ██      ████   ██████  █████   ███████
//    ██       ██    ██      ██           ██
//    ██       ██    ██      ███████ ███████

#define DEFINE_ARRAY(Type, TypeName)                                                     \
    typedef struct TypeName {                                                            \
        size_t len;                                                                      \
        size_t capacity;                                                                 \
        Type *slice;                                                                     \
    } TypeName;                                                                          \
                                                                                         \
    EPCError TypeName##_new(TypeName *list, size_t initial_size) {                       \
        size_t capacity = initial_size;                                                  \
        Type *slice = malloc(capacity * sizeof(Type));                                   \
        if (!slice) {                                                                    \
            return error(SYS, MALLOC);                                                   \
        }                                                                                \
        *list = (TypeName){.len = 0, .capacity = capacity, .slice = slice};              \
        return EPC_OK;                                                                   \
    }                                                                                    \
                                                                                         \
    void TypeName##_free(TypeName *list) {                                               \
        if (list) {                                                                      \
            free(list->slice);                                                           \
        }                                                                                \
    }                                                                                    \
                                                                                         \
    EPCError TypeName##_append(TypeName *list, Type value) {                             \
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
        return EPC_OK;                                                                   \
    }                                                                                    \
                                                                                         \
    EPCError TypeName##_delete_unordered(TypeName *list, size_t i) {                     \
        if (list == NULL) {                                                              \
            return error(ARGS, IS_NULL);                                                 \
        }                                                                                \
        if (i >= list->len) {                                                            \
            return error(ARGS, INDEX);                                                   \
        }                                                                                \
                                                                                         \
        list->len--;                                                                     \
        list->slice[i] = list->slice[list->len];                                         \
        return EPC_OK;                                                                   \
    }                                                                                    \
                                                                                         \
    EPCError TypeName##_delete_ordered(TypeName *list, size_t i) {                       \
        if (list == NULL) {                                                              \
            return error(ARGS, IS_NULL);                                                 \
        }                                                                                \
        if (i >= list->len) {                                                            \
            return error(ARGS, INDEX);                                                   \
        }                                                                                \
                                                                                         \
        list->len--;                                                                     \
        for (int at = i; i < list->len; at++)                                            \
            list->slice[at] = list->slice[at + 1];                                       \
        return EPC_OK;                                                                   \
    }

typedef struct ClientConnection {
    uint32_t id;
    uint32_t dynamic_id;
    ShmemBuffer shmem;
    Semaphore client_sem;
    uint64_t last_response_time_ms;
} ClientConnection;

DEFINE_ARRAY(ClientConnection, Array_ClientConnection)

typedef struct JoinArea {
    uint32_t fixed_id;     // Server writable, client readable.
    uint32_t initial_size; // Server writable, client readable.
    uint32_t counter;      // Write locked: Client writable, server readable.
    bool server_alive;     // Server writable, client readable.
} JoinArea;

typedef enum SharedTurn {
    TURN_SENDER = 0x00,
    TURN_RECEIVER = 0x01,
    TURN_UPGRADE = 0x40,
    TURN_ERROR = 0x80,
} SharedTurn;

// Header modelled after PNG header. Allows easier viewing in hex editors.
const char EPICAC_HEADER[17] = "\x8F"   // High bit byte.
                               "EPICAC" // Protocol identifier.
                               "000000" // Version identifier.
                               "\r\n"   // Windows line terminator.
                               "\x1A"   // Ctrl+Z (oldschool Windows end-of-file)
                               "\n"     // Unix line terminator.
    ;

typedef struct SharedBufferHeader {
    char magic_string[sizeof EPICAC_HEADER]; // Should be set to EPICAC_HEADER.
    uint8_t turn;          // Whether this buffer should be written to or not.
    uint64_t buffer_size;  // Total capacity of the buffer, ie. maximum message size.
    uint64_t message_size; // Size of most recent message OR new size to upgrade to.
    uint8_t *ptr;          // Pointer to start of message.
} SharedBufferHeader;

typedef struct SharedBuffer {
    SharedBufferHeader client;
    SharedBufferHeader server;
    uint8_t buf[];
} SharedBuffer;

const uint32_t INITIALIZED_CANARY = 0x12345678;

typedef struct Server {
    Array_ClientConnection clients;
    Semaphore server_event_sem;

    Mutex address_mutex;

    uint32_t join_last_counter;
    Mutex join_mutex;
    ShmemBuffer join_shmem;
    Semaphore join_semaphore;

    uint32_t initialized;
    uint16_t name_len;
    char name[];
} Server;

typedef struct Client {
    ClientConnection connection;
    Semaphore server_event_sem;

    uint32_t initialized;
    uint16_t name_len;
    char name[];
} Client;

// ███████ ███████ ██████  ██    ██ ███████ ██████
// ██      ██      ██   ██ ██    ██ ██      ██   ██
// ███████ █████   ██████  ██    ██ █████   ██████
//      ██ ██      ██   ██  ██  ██  ██      ██   ██
// ███████ ███████ ██   ██   ████   ███████ ██   ██

EPCError epc_server_bind(EPCServer *server, char *name, uint32_t timeout_ms) {
    EPCError err = EPC_OK;
    EPCError err_cleanup = EPC_OK;

#undef CLEANUP
#define CLEANUP cleanup_nothing

    if (server == NULL) {
        err = error(ARGS, IS_NULL);
        goto CLEANUP;
    }

    // Validate given name/address.
    if ((err = validate_shmem_name_external(name)).high)
        goto CLEANUP;
    size_t name_len = strnlen(name, EPC_MAX_SHMEM_NAME);

    // Allocate the server itself.
    Server *ptr = malloc(sizeof(Server) + name_len + 1);
    if (ptr == NULL) {
        err = error(SYS, MALLOC);
        goto CLEANUP;
    }

#undef CLEANUP
#define CLEANUP cleanup_server_alloced

    // Initialize internal name storage.
    ptr->name_len = name_len;
    memcpy(ptr->name, name, name_len);
    ptr->name[name_len] = '\0';

    String name_str = {.bytes = ptr->name, .len = ptr->name_len};
    String str = {0};

    // Lock address mutex.
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str,
                           .object_type_str = epc_prefix_server_addr_lock},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_mutex(&ptr->address_mutex, str)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_addr_mutex_opened

    if ((err = wait_mutex(&ptr->address_mutex, timeout_ms)).high) {
        if (err.low == EPC_ERR_L_TIMEOUT)
            err = error(IPC, ALREADY_OPEN);
        goto CLEANUP;
    }

#undef CLEANUP
#define CLEANUP cleanup_addr_mutex_locked

    // Initialize client array list.
    if ((err = Array_ClientConnection_new(&ptr->clients, 8)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_client_array_alloced

    // Create a semaphore for server events
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_server_sem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_semaphore(&ptr->server_event_sem, str)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_open_sem_opened

    // Open the shared memory buffer.
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_shmem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;

    printf("shmem name is '%s'\n", str.bytes);
    ptr->join_shmem = (ShmemBuffer){.size = sizeof(JoinArea)};
    if ((err = open_shmem(&ptr->join_shmem, str, NULL)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_shmem_opened

    volatile JoinArea *join_area = (volatile JoinArea *)ptr->join_shmem.buf;

    if (join_area->server_alive == true) {
        err = error(IPC, ALREADY_OPEN);
        goto CLEANUP;
    }

    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_lock},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_mutex(&ptr->join_mutex, str)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_join_mutex_opened

    // Create a semaphore for joining clients
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_sem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_semaphore(&ptr->join_semaphore, str)).high)
        goto CLEANUP;

    const uint32_t initial_counter_value = 0x0;
    join_area->counter = initial_counter_value;
    ptr->join_last_counter = initial_counter_value;

    join_area->server_alive = true;

    ptr->initialized = INITIALIZED_CANARY;
    server->internal = ptr;

    return err;

    // Error cleanup.
cleanup_join_mutex_opened:
    close_mutex(ptr->join_mutex);
#ifdef EPC_POSIX
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_lock},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err.high) {
        destroy_mutex(&ptr->join_mutex, str.bytes);
    }
#endif
cleanup_shmem_opened:
    close_shmem(ptr->join_shmem);
#ifdef EPC_POSIX
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_shmem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err.high) {
        destroy_shmem(str.bytes);
    }
#endif
cleanup_open_sem_opened:
    close_semaphore(ptr->server_event_sem);
#ifdef EPC_POSIX
    err_cleanup = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_server_sem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup) {
        destroy_semaphore(str.bytes);
    }
#endif
cleanup_client_array_alloced:
    Array_ClientConnection_free(&ptr->clients);
cleanup_addr_mutex_locked:
    release_mutex(ptr->address_mutex);
cleanup_addr_mutex_opened:
    close_mutex(ptr->address_mutex);
cleanup_server_alloced:
    free(ptr);
cleanup_nothing:
    return err;
}

EPCError epc_server_close(EPCServer server) {
    String str = {0};
    EPCError err = EPC_OK;

    Server *ptr = server.internal;

    if (ptr == NULL)
        return error(ARGS, IS_NULL);

    if (ptr->initialized != INITIALIZED_CANARY)
        return error(ARGS, NOT_INITIALIZED);

    // Let clients know that the server is not alive.
    ((volatile JoinArea *)ptr->join_shmem.buf)->server_alive = false;

    // Allow the address to be reused.
    release_mutex(ptr->address_mutex);

    // This resource cleanup should be done in the same way everywhere it's needed.
    // Close system resources.

    close_mutex(ptr->join_mutex);
#ifdef EPC_POSIX
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_lock},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err.high)
        destroy_mutex(&ptr->join_mutex, str.bytes);
#endif
    close_shmem(ptr->join_shmem);
#ifdef EPC_POSIX
    err_cleanup = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_shmem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup) {
        destroy_shmem(str.bytes);
    }
#endif
    close_semaphore(ptr->server_event_sem);
#ifdef EPC_POSIX
    err_cleanup = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_server_sem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup)
        destroy_semaphore(str.bytes);
#endif
    close_mutex(ptr->address_mutex);

    // Free all memory related to clients.
    Array_ClientConnection_free(&ptr->clients);

    // Free struct itself.
    free(ptr);

    return EPC_OK;
}

//  ██████ ██      ██ ███████ ███    ██ ████████
// ██      ██      ██ ██      ████   ██    ██
// ██      ██      ██ █████   ██ ██  ██    ██
// ██      ██      ██ ██      ██  ██ ██    ██
//  ██████ ███████ ██ ███████ ██   ████    ██

EPCError epc_client_connect(EPCClient *client, char *name, uint32_t timeout_ms) {
    EPCError err = EPC_OK;
    EPCError err_cleanup = EPC_OK;

    String str = {0};

#undef CLEANUP
#define CLEANUP cleanup_nothing

    if (client == NULL) {
        err = error(ARGS, IS_NULL);
        goto CLEANUP;
    }

    // Validate given name/address.
    if ((err = validate_shmem_name_external(name)).high)
        goto CLEANUP;
    size_t name_len = strnlen(name, EPC_MAX_SHMEM_NAME);

    // Allocate the client itself.
    Client *ptr = malloc(sizeof(Client) + name_len + 1);
    if (ptr == NULL) {
        err = error(SYS, MALLOC);
        goto CLEANUP;
    }

#undef CLEANUP
#define CLEANUP cleanup_alloc

    // Initialize internal name storage.
    ptr->name_len = name_len;
    memcpy(ptr->name, name, name_len);
    ptr->name[name_len] = '\0';
    String name_str = (String){.len = ptr->name_len, .bytes = ptr->name};

    // Open the join waiting area mutex.
    Mutex join_lock;

    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_lock},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_mutex(&join_lock, str)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_join_lock_opened

    // Lock the join waiting area mutex.
    if ((err = wait_mutex(join_lock, timeout_ms)).high) {
        if (err.low == EPC_ERR_L_TIMEOUT)
            err = error(IPC, ALREADY_OPEN);
        goto CLEANUP;
    }

#undef CLEANUP
#define CLEANUP cleanup_join_lock_locked

    // Open the server event semaphore used to signal a join event to the server.
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_server_sem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_semaphore(&ptr->server_event_sem, str)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_server_sem_opened

    // Open the join waiting area shared memory.
    ShmemBuffer join_shmem = {.size = sizeof(JoinArea)};

    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_shmem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_shmem(&join_shmem, str, NULL)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_join_shmem_opened

    // Open the join semaphore for waiting for server's accepting of the join request.
    Semaphore join_sem = {0};
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_sem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_semaphore(&join_sem, str)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_join_sem_opened

    // Connect to server.
    volatile JoinArea *join_area = (volatile JoinArea *)join_shmem.buf;
    // TODO: this behaviour will result in a failure despite the timeout.
    // ie. the timeout accounts for busy servers, not non-existing servers.
    if (!join_area->server_alive) {
        err = error(IPC, COULD_NOT_CONNECT);
        goto CLEANUP;
    }

    // Request an ID.
    join_area->counter++;

    // Signal the server.
    if ((err = post_semaphore(ptr->server_event_sem)).high)
        goto CLEANUP;

    // Wait for the server to assign an ID.
    if ((err = wait_semaphore(join_sem, timeout_ms)).high)
        goto CLEANUP;

    close_semaphore(join_sem);

    ptr->connection.id = join_area->fixed_id;
    ptr->connection.dynamic_id = 0;
    ptr->connection.last_response_time_ms = monotonic_time_ms();

    ptr->connection.shmem.size = join_area->initial_size;

    // Open given shared memory and semaphore.
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str,
                           .object_type_str = epc_prefix_client_sem,
                           .fixed_id = ptr->connection.id},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_semaphore(&ptr->connection.client_sem, str)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_client_sem_opened

    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str,
                           .object_type_str = epc_prefix_shmem,
                           .fixed_id = ptr->connection.id,
                           .dynamic_id = ptr->connection.dynamic_id},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_shmem(&ptr->connection.shmem, str, NULL)).high)
        goto CLEANUP;

    ptr->initialized = INITIALIZED_CANARY;
    client->internal = ptr;

    // Release the mutex.
    release_mutex(join_lock);
    close_mutex(join_lock);

    return err;

// Error cleanup.
cleanup_client_sem_opened:
    close_semaphore(ptr->connection.client_sem);
#ifdef EPC_POSIX
    err_cleanup = build_internal_obj_name(
        &(BuildNameParams){.name = name_str,
                           .object_type_str = epc_prefix_client_sem,
                           .fixed_id = ptr->connection.id},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup)
        destroy_semaphore(str.bytes);
#endif
cleanup_join_sem_opened:
    close_semaphore(join_sem);
cleanup_join_shmem_opened:
    close_shmem(join_shmem);
cleanup_server_sem_opened:
    close_semaphore(ptr->server_event_sem);
cleanup_join_lock_locked:
    release_mutex(join_lock);
cleanup_join_lock_opened:
    close_mutex(join_lock);
cleanup_alloc:
    free(ptr);
cleanup_nothing:

    return err;
}

EPCError epc_client_disconnect(EPCClient client) {
    Client *ptr = client.internal;

    free(ptr);

    return EPC_OK;
}
