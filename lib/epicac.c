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

static_assert(sizeof(EPCError) == 2, "EPCError contains no padding.");

#define error(high, low) error(EPC_ERR_H_##high, EPC_ERR_L_##low)

static inline bool err_eq(EPCError x, EPCError y) {
    return x.high == y.high && x.low == y.low;
}

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

#define HEX_(x) 0x##x
#define HEX(x) HEX_(x)
#define STRING_(x) #x
#define STRING(x) STRING_(x)

// Version string is 12 hexadecimal characters or 6 bytes (major-minor-patch).
#define EPC_MIN_COMPAT_VERSION 000000000000
#define EPC_VERSION 000000000000
#define EPC_VERSION_STRING STRING(EPC_VERSION)
#define EPC_VERSION_VALUE HEX(EPC_VERSION)
#define EPC_MIN_COMPAT_VERSION_VALUE HEX(EPC_MIN_COMPAT_VERSION)

typedef struct EPCHeader {
    uint8_t first_byte[1];
    uint8_t protocol[7];
    uint64_t version;
    uint8_t win_line_terminator[2];
    uint8_t win_eof[1];
    uint8_t unix_line_terminator[1];
} EPCHeader;

static_assert(sizeof(EPCHeader) == 24, "EPCHeader contains no padding.");

// Header modelled after PNG header. Allows easier viewing in hex editors.
const EPCHeader EPC_HEADER = {.first_byte = '\x8F',          // High bit byte.
                              .protocol = "EPICACv",         // Protocol identifier.
                              .version = EPC_VERSION_VALUE,  // Version identifier.
                              .win_line_terminator = "\r\n", // Windows line terminator.
                              .win_eof = "\x1A", // Ctrl+Z (oldschool Windows end-of-file)
                              .unix_line_terminator = "\n"};

EPCError check_valid_header(EPCHeader *header) {
    bool ok = true;
    ok = ok && !memcmp(header->first_byte, EPC_HEADER.first_byte,
                       sizeof(EPC_HEADER.first_byte));
    ok =
        ok && !memcmp(header->protocol, EPC_HEADER.protocol, sizeof(EPC_HEADER.protocol));
    ok = ok && !memcmp(header->win_line_terminator, EPC_HEADER.win_line_terminator,
                       sizeof(EPC_HEADER.win_line_terminator));
    ok = ok && !memcmp(header->win_eof, EPC_HEADER.win_eof, sizeof(EPC_HEADER.win_eof));
    ok = ok && !memcmp(header->unix_line_terminator, EPC_HEADER.unix_line_terminator,
                       sizeof(EPC_HEADER.unix_line_terminator));

    if (!ok)
        return error(IPC, HEADER_MALFORMED);

    return EPC_OK;
}

EPCError check_compatibility(EPCHeader *header) {
    EPCError err = EPC_OK;

    if ((err = check_valid_header(header)).high)
        return err;

    uint64_t version = header->version;
    if (version < EPC_MIN_COMPAT_VERSION_VALUE)
        return error(IPC, VERSION_INCOMPATIBLE);

    return err;
}

// ███████ ████████ ██████  ██ ███    ██  ██████
// ██         ██    ██   ██ ██ ████   ██ ██
// ███████    ██    ██████  ██ ██ ██  ██ ██   ███
//      ██    ██    ██   ██ ██ ██  ██ ██ ██    ██
// ███████    ██    ██   ██ ██ ██   ████  ██████

/// Common prefix to all system-wide named objects.
#define EPC_PREFIX_LEN ((sizeof epc_prefix) - 1)
static const char epc_prefix[] = "/_epc_";

/// 5 character or 30-bit base64 connection ID assigned per client.
#define EPC_FIXED_ID_LEN 6
#define EPC_FIXED_ID_BITS (EPC_FIXED_ID_LEN * 6)
static_assert(32 < EPC_FIXED_ID_BITS,
              "ID must fit all 32 bit integers. This may change later.");

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

/// Shared memory: buffer for client-server messages.
DEFINE_EPC_OBJECT_TYPE_PREFIX(shmem, "sharemem");
/// Semaphore: event for server wake up.
DEFINE_EPC_OBJECT_TYPE_PREFIX(server_sem, "servesem");
/// Semaphore: event for client wake up.
DEFINE_EPC_OBJECT_TYPE_PREFIX(client_sem, "clientse");

#define EPC_MIN_SHMEM_NAME (EPC_PREFIX_LEN + EPC_FIXED_ID_LEN + EPC_OBJECT_TYPE_LEN)

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

static thread_local char shmem_string_scratch[EPC_MAX_SHMEM_NAME + 1];
#define SHMEM_SCRATCH_SIZE                                                               \
    ((sizeof shmem_string_scratch) / (sizeof *shmem_string_scratch))

typedef struct BuildNameParams {
    /// UTF-8 string of at most <EPC_MAX_NAME> bytes that has already been validated.
    String name;
    const char(*object_type_str);
    uint32_t fixed_id;
    uint32_t rand_id;
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
    base64_encode(params->rand_id, b64_scratch);
    start += cat(buf, start, EPC_FIXED_ID_LEN, b64_scratch);
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

uint64_t get_page_size() {
    static uint64_t page_size = 0;
    if (page_size == 0) {
#ifdef EPC_WINDOWS
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        page_size = sys_info.dwPageSize;
#elif defined(EPC_POSIX)
        page_size = sysconf(_SC_PAGESIZE);
#endif
        assert("Page size fits in 32 bits" && page_size <= UINT32_MAX);
    }
    return page_size;
}

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
static EPCError open_shmem(ShmemBuffer *shmem, String name, size_t size,
                           bool *already_open) {
    if (size == 0) {
        return error(ARGS, SIZE_TOO_SMALL);
    }
    shmem->size = size;

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

    bool shmem_exists = false;
    EPCError err =
        open_shmem(&mutex->shmem, &name, sizeof(WrappedPosixMutex), &shmem_exists);
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
    EPCError TypeName##_at_checked(TypeName *list, Type *item, size_t i) {               \
        if (list == NULL) {                                                              \
            return error(ARGS, IS_NULL);                                                 \
        }                                                                                \
        if (i >= list->len) {                                                            \
            return error(ARGS, INDEX);                                                   \
        }                                                                                \
                                                                                         \
        *item = list->slice[i];                                                          \
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
        for (size_t at = i; i < list->len; at++)                                         \
            list->slice[at] = list->slice[at + 1];                                       \
        return EPC_OK;                                                                   \
    }

typedef struct ClientConnection {
    uint32_t id;
    uint32_t rand_id;
    ShmemBuffer shmem;
    Semaphore client_sem;
    uint64_t last_response_time_ms;
    uint32_t server_buf_size;
    uint32_t client_buf_size;
} ClientConnection;

DEFINE_ARRAY(ClientConnection, Array_ClientConnection)

DEFINE_ARRAY(uint8_t, Array_U8)

typedef struct BitArray {
    uint32_t bit_count;
    uint32_t last_checked_byte;
    Array_U8 array;
} BitArray;

EPCError BitArray_new(BitArray *array, uint32_t initial_size) {
    EPCError err = EPC_OK;

    size_t byte_size = (initial_size + 8 - 1) / 8; // Floor division.
    if ((err = Array_U8_new(&array->array, byte_size)).high)
        return err;

    for (int32_t i; i < array->array.len; i++) {
        array->array.slice[i] = 0x00;
    }

    array->last_checked_byte = 0;

    return err;
}

static inline uint8_t find_first_set_index(uint8_t value) {
    assert("ffs does not support zero" && value != 0);

#if defined(_MSC_VER)
    unsigned long index;
    unsigned long mask = value;
    assert("MSVC builtin cannot fail on non-zero mask" && _BitScanForward(&index, mask));
    assert(0 <= index && index <= 7);
    return index;
#elif defined(__GNUC__) || defined(__clang__)
    int mask = value;
    int index = __builtin_ffs(mask);
    assert("GCC/Clang builtin should be taking non-zero mask" && index > 0);
    return index - 1;
#else
    for (int i = 0; i < 8; ++i)
        if (value & (1 << i))
            return i;
    assert("loop should never terminate, else value was 0" && false);
#endif
}

EPCError BitArray_get_new_bit(BitArray *array, uint32_t *index) {
    EPCError err = EPC_OK;
    uint32_t byte_index = 0;
    uint32_t bit_index = 0;
    uint32_t i;

    // Iterate from the last used byte (avoid rechecking start over and over).
    // When a suitable location is found, set the bit.
    for (i = 0; i < array->array.len; i++) {
        // Check from the last used byte all through the entire array, wrapping around.
        uint32_t byte_index = (i + array->last_checked_byte) % array->array.len;

        if (array->array.slice[byte_index] != 0xFF) {
            bit_index = find_first_set_index(~array->array.slice[byte_index]);
            array->array.slice[byte_index] |= 1 << bit_index;
            break;
        }
    }

    // If this fails, all bits are set, so we expand the array. Next time, check the last
    // byte.
    if (i >= array->array.len) {
        if ((err = Array_U8_append(&array->array, 0x01)).high)
            return err;

        byte_index = array->array.len - 1;
        bit_index = 1;
    }

    // Note down where to start checking on the next call.
    array->last_checked_byte = byte_index;

    *index = byte_index * 8 + bit_index;

    return err;
}

void BitArray_unset_bit_unchecked(BitArray *array, uint32_t index) {
    uint32_t byte_index = index / 8;
    uint32_t bit_index = index % 8;

    assert("cannot free a bit out of range" && byte_index < array->array.len);

    array->array.slice[byte_index] &= ~(1 << bit_index);
}

void BitArray_free(BitArray *array) { Array_U8_free(&array->array); }

typedef struct JoinArea {
    EPCHeader server_header; // Should be set to EPC_HEADER by server.
    EPCHeader client_header; // Should be set to EPC_HEADER by client.
    uint32_t fixed_id;       // Server writable, client readable.
    uint32_t client_size;    // Client writable, server readable.
    uint32_t server_size;    // Server writable, client readable.
    uint64_t shmem_size;     // Server writable, client readable.
    uint8_t client_waiting;
    uint8_t server_ready; // Client sets to false, server sets to true.
    uint8_t client_ready; // Server sets to false, client sets to true.
    uint8_t server_alive; // Server writable, client readable.
    uint8_t abort;        // Writable by both, not locked.
} JoinArea;

typedef enum SharedTurn {
    TURN_SENDER = 0x00,
    TURN_RECEIVER = 0x01,
    TURN_CLOSE = 0x80,
    TURN_ERROR = 0xFF,
} SharedTurn;

typedef struct SharedBufferHeader {
    uint8_t turn;        // Whether this buffer should be written to or not.
    size_t message_size; // Size of most recent message OR new size to upgrade to.
    uint8_t *ptr;        // Pointer to start of message.
    uint32_t canary;
} SharedBufferHeader;

typedef struct SharedBuffer {
    SharedBufferHeader client;
    SharedBufferHeader server;
    uint8_t buf[];
} SharedBuffer;

static const uint32_t INITIALIZED_CANARY = 0x12345678;

// TODO: config for sever and client setup.

typedef struct ServerSettings {
    uint32_t initial_message_size;
} ServerSettings;

ServerSettings SERVER_SETTINGS_DEFAULT = {.initial_message_size = 128};

typedef struct Server {
    Array_ClientConnection clients;
    BitArray client_ids;
    Semaphore server_event_sem;

    Mutex address_mutex;

    Mutex join_mutex;
    ShmemBuffer join_shmem;

    ServerSettings settings;

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

// ██    ██ ████████ ██ ██      ███████
// ██    ██    ██    ██ ██      ██
// ██    ██    ██    ██ ██      ███████
// ██    ██    ██    ██ ██           ██
//  ██████     ██    ██ ███████ ███████

#define STRINGIZE_(x) #x
#define STRINGIZE(x) STRINGIZE_(x)

#define MIN(name, type)                                                                  \
    static type min_##name(type a, type b) { return (a < b) ? a : b; }
MIN(u32, uint32_t)

uint64_t monotonic_time_ms() {
#ifdef EPC_WINDOWS
    return GetTickCount64();
#elif defined(EPC_POSIX)
    struct timespec ts = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror(__FILE__ ", line " STRINGIZE(__LINE__)", epicac.monotonic_time_ms.clock_gettime failed");
        return 0;
    }
    return ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
#endif
}

bool update_timeout(uint64_t *last_time, uint32_t *timeout_ms) {
    uint64_t now = monotonic_time_ms();
    assert("Clock is incosistent" && *last_time <= now);
    uint64_t elapsed = now - *last_time;
    *last_time = now;

    if (*timeout_ms <= elapsed) {
        *timeout_ms = 0;
        return true;
    } else { // elapsed < *timeout_ms
        *timeout_ms -= elapsed;
    }

    return false;
}

void sleep_ms(uint32_t time_ms) {
#ifdef EPC_WINDOWS
    Sleep(time_ms);
#elif defined(EPC_POSIX)
    struct timespec req, rem;
    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000000;
    if ((nanosleep(&req, &rem) == -1) && (errno == EINTR))
        nanosleep(rem, NULL);
#endif
}

typedef enum PollStage {
    POLL_STAGE_SPIN = 0,
    POLL_STAGE_15MS,
    POLL_STAGE_1S,
} PollStage;

typedef struct BackoffTimeout {
    uint8_t stage;
    uint8_t iterations;
} BackoffTimeout;

uint8_t get_next_backoff_stage(uint8_t current_backoff_stage) {
    switch (current_backoff_stage) {
    case POLL_STAGE_SPIN:
        return POLL_STAGE_15MS;
    case POLL_STAGE_15MS:
    case POLL_STAGE_1S:
        return POLL_STAGE_1S;
    default:
        assert("Poll stage is invalid, maybe not initialized." && false);
    }
}

void backoff_timeout(uint32_t timeout_ms, BackoffTimeout *backoff) {
    if (backoff->stage == POLL_STAGE_SPIN) {
        // TODO: Make sure this doesn't get optimized out.
        for (volatile int i = 0; i < 1000; ++i)
            ;
    } else if (backoff->stage == POLL_STAGE_15MS) {
        sleep_ms(min_u32(15, timeout_ms));
    } else {
        assert(backoff->stage == POLL_STAGE_1S);
        sleep_ms(min_u32(1000, timeout_ms));
    }

    // Advance to the next, lower resolution step in the backoff.
    backoff->iterations++;
    if (backoff->iterations > 200) {
        backoff->iterations = 0;
        backoff->stage = get_next_backoff_stage(backoff->stage);
    }
}

typedef enum EPCSide {
    SIDE_SERVER = 0x0,
    SIDE_CLIENT = 0x1,
} EPCSide;

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

    ptr->settings = SERVER_SETTINGS_DEFAULT;

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

    if ((err = BitArray_new(&ptr->client_ids, 8)).high) {
        goto CLEANUP;
    }

#undef CLEANUP
#define CLEANUP cleanup_client_bitarray_alloced

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
    if ((err = open_shmem(&ptr->join_shmem, str, sizeof(JoinArea), NULL)).high)
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

    join_area->server_alive = true;
    *join_area = (JoinArea){.server_alive = true,
                            .client_waiting = false,
                            .client_ready = false,
                            .server_ready = false,
                            .abort = false,
                            .server_header = EPC_HEADER,
                            .fixed_id = 0};

    ptr->initialized = INITIALIZED_CANARY;
    server->internal = ptr;

    return err;

    // Error cleanup.
cleanup_join_mutex_opened:
    close_mutex(ptr->join_mutex);
#ifdef EPC_POSIX
    err_cleanup = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_lock},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup.high) {
        destroy_mutex(&ptr->join_mutex, str.bytes);
    }
#endif
cleanup_shmem_opened:
    close_shmem(ptr->join_shmem);
#ifdef EPC_POSIX
    err_cleanup = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_shmem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup.high) {
        destroy_shmem(str.bytes);
    }
#endif
cleanup_open_sem_opened:
    close_semaphore(ptr->server_event_sem);
#ifdef EPC_POSIX
    err_cleanup = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_server_sem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup.high) {
        destroy_semaphore(str.bytes);
    }
#endif
cleanup_client_bitarray_alloced:
    BitArray_free(&ptr->client_ids);
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

EPCError epc_server_close(EPCServer *server) {
    String str = {0};
    EPCError err = EPC_OK;

    Server *ptr = server->internal;

    // TODO: close all client connections

    if (ptr == NULL)
        return error(ARGS, IS_NULL);

    if (ptr->initialized != INITIALIZED_CANARY)
        return error(ARGS, NOT_INITIALIZED);

    // Let clients know that the server is not alive.
    ((volatile JoinArea *)ptr->join_shmem.buf)->server_alive = false;

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
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_shmem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err.high) {
        destroy_shmem(str.bytes);
    }
#endif
    close_semaphore(ptr->server_event_sem);
#ifdef EPC_POSIX
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_server_sem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err.high)
        destroy_semaphore(str.bytes);
#endif

    // Allow the address to be reused.
    release_mutex(ptr->address_mutex);
    close_mutex(ptr->address_mutex);

    // Free all memory related to clients.
    Array_ClientConnection_free(&ptr->clients);
    BitArray_free(&ptr->client_ids);

    // Free struct itself.
    free(ptr);

    server->internal = NULL;

    return EPC_OK;
}

uint32_t rand32() {
    // TODO: once you have internet access again.
    return 0;
}

EPCError epc_server_accept(EPCServer server, uint32_t timeout_ms,
                           uint32_t requested_size) {
    uint64_t last_time = monotonic_time_ms();

    EPCError err = EPC_OK;
    EPCError err_cleanup = EPC_OK;
    Server *ptr = (Server *)server.internal;

    String name_str = {.len = ptr->name_len, .bytes = ptr->name};
    String str = {0};

    volatile JoinArea *join_area = (volatile JoinArea *)ptr->join_shmem.buf;

    if (!join_area->client_waiting) {
        return EPC_OK;
    }
    join_area->client_waiting = false;

#undef CLEANUP
#define CLEANUP cleanup_client_exists

    // A client wants to join. Check compatibility then set system resources up.
    if ((err = check_compatibility(&join_area->client_header)).high) {
        goto CLEANUP;
    }

    if (join_area->client_size == 0) {
        err = error(IPC, INVALID_MESSAGE_SIZE);
        goto CLEANUP;
    }

    ClientConnection connection = {0};

    if ((err = BitArray_get_new_bit(&ptr->client_ids, &connection.id)).high)
        goto CLEANUP;

    connection.rand_id = rand32();

#undef CLEANUP
#define CLEANUP cleanup_id_alloced

    connection.server_buf_size = requested_size ? requested_size : get_page_size();
    connection.client_buf_size = join_area->client_size;
    connection.last_response_time_ms = monotonic_time_ms();

    size_t shmem_size =
        sizeof(SharedBuffer) + connection.server_buf_size + connection.client_buf_size;

    // Open new shared memory and semaphore.
    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str,
                           .object_type_str = epc_prefix_client_sem,
                           .fixed_id = connection.id},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_semaphore(&connection.client_sem, str)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_client_sem_opened

    err = build_internal_obj_name(
        &(BuildNameParams){
            .name = name_str,
            .object_type_str = epc_prefix_shmem,
            .fixed_id = connection.id,
            .rand_id = connection.rand_id,
        },
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_shmem(&connection.shmem, str, shmem_size, NULL)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_message_shmem_opened

    volatile SharedBuffer *shared = (volatile SharedBuffer *)connection.shmem.buf;

    shared->server = (SharedBufferHeader){.turn = TURN_SENDER,
                                          .message_size = 0,
                                          .ptr = shared->buf,
                                          .canary = INITIALIZED_CANARY};
    shared->client = (SharedBufferHeader){.turn = TURN_SENDER,
                                          .message_size = 0,
                                          .ptr = shared->buf + connection.server_buf_size,
                                          .canary = INITIALIZED_CANARY};

    // Signal client to finish initialization.
    join_area->server_size = connection.server_buf_size;
    join_area->shmem_size = shmem_size;
    join_area->fixed_id = connection.id;
    join_area->client_ready = false;
    join_area->server_ready = true;

    // Wait for client to finish their part of initialization.
    // To exit this loop, 1 of the following must hold:
    // 1. The timeout has been exceeded.
    // 2. The client has aborted the operation.
    // 3. The client has indicated that its finished necessary initialization.
    BackoffTimeout backoff = {0};

    while (true) {
        if (join_area->client_ready) {
            break;
        }
        if (join_area->abort) {
            err = error(IPC, CLIENT);
            goto CLEANUP;
        }
        backoff_timeout(timeout_ms, &backoff);

        if (update_timeout(&last_time, &timeout_ms)) {
            err = error(IPC, TIMEOUT);
            goto CLEANUP;
        }
    }

    if ((err = Array_ClientConnection_append(&ptr->clients, connection)).high)
        goto CLEANUP;

    return err;

cleanup_message_shmem_opened:
    close_shmem(connection.shmem);
#ifdef EPC_POSIX
    err_cleanup =
        build_internal_obj_name(&(BuildNameParams){.name = name_str,
                                                   .object_type_str = epc_prefix_shmem,
                                                   .fixed_id = connection.id,
                                                   .rand_id = connection.rand_id},
                                &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup.high) {
        destroy_shmem(str.bytes);
    }
#endif
cleanup_client_sem_opened:
    close_semaphore(connection.client_sem);
#ifdef EPC_POSIX
    err_cleanup = build_internal_obj_name(
        &(BuildNameParams){.name = name_str,
                           .object_type_str = epc_prefix_client_sem,
                           .fixed_id = connection.id},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup)
        destroy_semaphore(str.bytes);
#endif
cleanup_id_alloced:
    BitArray_unset_bit_unchecked(&ptr->client_ids, connection.id);
cleanup_client_exists:
    join_area->abort = true;

    return err;
}

EPCError epc_server_disconnect_client(Server *ptr, uint32_t index) {
    EPCError err = EPC_OK;
    EPCError err_cleanup = EPC_OK;
    String name_str = {.len = ptr->name_len, .bytes = ptr->name};
    String str = {0};

    ClientConnection connection = {0};
    if ((err = Array_ClientConnection_at_checked(&ptr->clients, &connection, index)).high)
        return err;

    volatile SharedBuffer *shared = (volatile SharedBuffer *)connection.shmem.buf;

    shared->server.turn = TURN_CLOSE;

    close_shmem(connection.shmem);
#ifdef EPC_POSIX
    err_cleanup =
        build_internal_obj_name(&(BuildNameParams){.name = name_str,
                                                   .object_type_str = epc_prefix_shmem,
                                                   .fixed_id = connection.id,
                                                   .rand_id = connection.rand_id},
                                &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (!err_cleanup.high) {
        destroy_shmem(str.bytes);
    }
#endif


}

//  ██████ ██      ██ ███████ ███    ██ ████████
// ██      ██      ██ ██      ████   ██    ██
// ██      ██      ██ █████   ██ ██  ██    ██
// ██      ██      ██ ██      ██  ██ ██    ██
//  ██████ ███████ ██ ███████ ██   ████    ██

EPCError epc_client_connect(EPCClient *client, char *name, uint32_t timeout_ms,
                            uint32_t requested_size) {
    uint64_t last_time = monotonic_time_ms();

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

    if (update_timeout(&last_time, &timeout_ms)) {
        err = error(IPC, TIMEOUT);
        goto CLEANUP;
    }

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
    ShmemBuffer join_shmem;

    err = build_internal_obj_name(
        &(BuildNameParams){.name = name_str, .object_type_str = epc_prefix_join_shmem},
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_shmem(&join_shmem, str, sizeof(JoinArea), NULL)).high)
        goto CLEANUP;

#undef CLEANUP
#define CLEANUP cleanup_join_shmem_opened

    // Connect to server.
    volatile JoinArea *join_area = (volatile JoinArea *)join_shmem.buf;

    BackoffTimeout backoff = {0};
    while (true) {
        if (join_area->server_alive) {
            break;
        }
        backoff_timeout(timeout_ms, &backoff);

        if (update_timeout(&last_time, &timeout_ms)) {
            err = error(IPC, TIMEOUT);
            goto CLEANUP;
        }
    }

    // Check header and version compatibility.
    if ((err = check_compatibility(&join_area->server_header)).high) {
        goto CLEANUP;
    }

    // Request an ID.
    join_area->abort = false;
    join_area->client_header = EPC_HEADER;
    join_area->client_size = requested_size;
    join_area->server_ready = false;
    join_area->client_waiting = true;

#undef CLEANUP
#define CLEANUP cleanup_server_notified

    // Wake up the server.
    if ((err = post_semaphore(ptr->server_event_sem)).high)
        goto CLEANUP;

    // Wait for the server to assign an ID.
    // To exit this loop, 1 of the following must hold:
    // 1. The timeout has been exceeded.
    // 2. The server has aborted the operation.
    // 3. The server has indicated that its finished necessary initialization.
    BackoffTimeout backoff = {0};

    while (true) {
        if (join_area->server_ready) {
            break;
        }
        if (join_area->abort) {
            err = error(IPC, SERVER);
            goto CLEANUP;
        }
        backoff_timeout(timeout_ms, &backoff);

        if (update_timeout(&last_time, &timeout_ms)) {
            err = error(IPC, TIMEOUT);
            goto CLEANUP;
        }
    }

    ptr->connection = (ClientConnection){.client_buf_size = join_area->client_size,
                                         .server_buf_size = join_area->server_size,
                                         .id = join_area->fixed_id,
                                         .last_response_time_ms = monotonic_time_ns()};
    uint64_t shmem_size = join_area->shmem_size;

    if (shmem_size != sizeof(SharedBuffer) + ptr->connection.server_buf_size +
                          ptr->connection.client_buf_size) {
        err = error(IPC, INVALID_MESSAGE_SIZE);
        goto CLEANUP;
    }

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
        &(BuildNameParams){
            .name = name_str,
            .object_type_str = epc_prefix_shmem,
            .fixed_id = ptr->connection.id,
        },
        &str, shmem_string_scratch, SHMEM_SCRATCH_SIZE);
    if (err.high)
        goto CLEANUP;
    if ((err = open_shmem(&ptr->connection.shmem, str, shmem_size, NULL)).high)
        goto CLEANUP;

    // Initialize internal state.
    volatile SharedBuffer *shared = (volatile SharedBuffer *)ptr->connection.shmem.buf;

    // Indicate to server that the client area has been initialized.
    join_area->client_ready = true;

    ptr->initialized = INITIALIZED_CANARY;
    client->internal = ptr;

    // Release the mutex and close it. Also close join shmem.
    release_mutex(join_lock);
    close_mutex(join_lock);
    close_shmem(join_shmem);

    return err;

// Error cleanup.
cleanup_client_sem_opened:
    close_semaphore(ptr->connection.client_sem);
cleanup_server_notified:
    join_area->abort = true;
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

EPCError epc_client_disconnect(EPCClient *client) {
    String str = {0};
    EPCError err = EPC_OK;

    Client *ptr = client->internal;

    if (ptr == NULL)
        return error(ARGS, IS_NULL);

    if (ptr->initialized != INITIALIZED_CANARY)
        return error(ARGS, NOT_INITIALIZED);

    // Signal the server of the disconnect.
    volatile SharedBuffer *shared = (volatile SharedBuffer *)ptr->connection.shmem.buf;
    shared->client.turn = TURN_CLOSE;
    post_semaphore(ptr->server_event_sem);

    // Close the shared memory and server & client semaphores.
    close_shmem(ptr->connection.shmem);
    close_semaphore(ptr->server_event_sem);
    close_semaphore(ptr->connection.client_sem);

    free(ptr);

    client->internal = NULL;

    return EPC_OK;
}