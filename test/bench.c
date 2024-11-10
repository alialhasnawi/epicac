

#ifdef _WIN32
#define EPC_WINDOWS
#include <Windows.h>
#else
#define EPC_POSIX

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "epicac.h"

// ██    ██ ████████ ██ ██      ███████
// ██    ██    ██    ██ ██      ██
// ██    ██    ██    ██ ██      ███████
// ██    ██    ██    ██ ██           ██
//  ██████     ██    ██ ███████ ███████

// Thank you to https://jera.com/techinfo/jtns/jtn002 <3

#define TEST_PERROR(message)                                                             \
    do {                                                                                 \
        fprintf(stderr, "test runner: %s: %s\n", __func__, message);                     \
        exit(2);                                                                         \
    } while (0)

#define TEST_ERROR(...)                                                                  \
    do {                                                                                 \
        fprintf(stderr, "test runner: "__VA_ARGS__);                                     \
        exit(2);                                                                         \
    } while (0)

static inline char *epc_err_to_string(const char *message, EPCError err) {
    const char *high_desc = epc_error_high_description(err);
    const char *low_desc = epc_error_low_description(err);
    char *string =
        malloc(sizeof(char) * (strlen(message) + strlen(high_desc) + strlen(low_desc)) +
               sizeof(":  ()"));
    if (string == NULL) {
        TEST_PERROR("malloc");
    }
    if (sprintf(string, "%s: %s (%s)", message, high_desc, low_desc) < -1) {
        TEST_PERROR("sprintf");
    }
    return string;
}

static inline EPCError error_(EPCErrorHigh err_high, EPCErrorLow err_low) {
    // return (err_high << 8) | err_low;
    return (EPCError){err_high, err_low};
}

#define error(high, low) error_(EPC_ERR_H_##high, EPC_ERR_L_##low)

static inline bool err_eq(EPCError x, EPCError y) {
    return x.high == y.high && x.low == y.low;
}

#define ADDRESS_LENGTH 64

#if RAND_MAX < 100
#error "The rand() implementation on this system is bad"
#endif

static void random_address(char address[ADDRESS_LENGTH + 1]) {
    for (int i = 0; i < ADDRESS_LENGTH; ++i) {
        address[i] = '0' + rand() % (1 + 'Z' - '0');
    }
}

uint64_t monotonic_time_ms() {
#ifdef EPC_WINDOWS
    return GetTickCount64();
#elif defined(EPC_POSIX)
    struct timespec ts = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        TEST_PERROR("clock_gettime");
        return 0;
    }
    return ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
#endif
}

static void sleep_ms(uint32_t time_ms) {
#ifdef EPC_WINDOWS
    Sleep(time_ms);
#elif defined(EPC_POSIX)
    struct timespec req, rem;
    req.tv_sec = time_ms / 1000;
    req.tv_nsec = (time_ms % 1000) * 1000000;
    if ((nanosleep(&req, &rem) == -1) && (errno == EINTR)) {
        nanosleep(&rem, NULL);
    }
#endif
}

static inline const char *repr_str(const char *value) {
    return value == NULL ? "(null)" : value;
}
static inline char *repr_bool(bool value) { return value ? "true" : "false"; }

// ███    ███ ██    ██ ████████ ███████ ██   ██
// ████  ████ ██    ██    ██    ██       ██ ██
// ██ ████ ██ ██    ██    ██    █████     ███
// ██  ██  ██ ██    ██    ██    ██       ██ ██
// ██      ██  ██████     ██    ███████ ██   ██

// NOTE: This is an in-process (*not* inter-process communication) mutex.

#ifdef EPC_WINDOWS
HANDLE global_mutex;
#elif defined(EPC_POSIX)
pthread_mutex_t global_mutex;
#endif

static void init_mutex() {
#ifdef EPC_WINDOWS
    global_mutex = CreateMutexW(NULL, FALSE, NULL);
    if (global_mutex == NULL) {
        TEST_PERROR("CreateMutexW");
    }
#elif defined(EPC_POSIX)
    pthread_mutexattr_t attr;
    if ((pthread_mutexattr_init(&attr) != 0) ||
        (pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) != 0) ||
        (pthread_mutex_init(&global_mutex, &attr) != 0)) {
        TEST_PERROR("pthread_mutex_init");
    }
#endif
}

static void destroy_mutex() {
#ifdef EPC_WINDOWS
    CloseHandle(global_mutex);
#elif defined(EPC_POSIX)
    pthread_mutex_destroy(&global_mutex);
#endif
}

static void lock_mutex() {
#ifdef EPC_WINDOWS
    DWORD status = WaitForSingleObject(global_mutex, INFINITE);
    if (status != WAIT_OBJECT_0) {
        TEST_PERROR("WaitForSingleObject");
    }
#elif defined(EPC_POSIX)
    int status = pthread_mutex_lock(&global_mutex);
    if (status != 0) {
        TEST_PERROR("pthread_mutex_lock");
    }
#endif
}

static void unlock_mutex() {
#ifdef EPC_WINDOWS
    BOOL success = ReleaseMutex(global_mutex);
    if (!success) {
        TEST_PERROR("ReleaseMutex");
    }
#elif defined(EPC_POSIX)
    int status = pthread_mutex_lock(&global_mutex);
    if (status != 0) {
        TEST_PERROR("pthread_mutex_lock");
    }
#endif
}

// ████████ ██   ██ ██████  ███████  █████  ██████
//    ██    ██   ██ ██   ██ ██      ██   ██ ██   ██
//    ██    ███████ ██████  █████   ███████ ██   ██
//    ██    ██   ██ ██   ██ ██      ██   ██ ██   ██
//    ██    ██   ██ ██   ██ ███████ ██   ██ ██████

typedef void (*ThreadFunction)(void *);

#ifdef EPC_WINDOWS
typedef HANDLE Thread;
#elif defined(EPC_POSIX)
typedef pthread_t Thread;
#endif

typedef struct ThreadFunctionArgs {
    ThreadFunction function;
    void *arg;
} ThreadFunctionArgs;

#ifdef EPC_WINDOWS
static DWORD thread_function_wrapper(void *args) {
    ThreadFunctionArgs *args_ = (ThreadFunctionArgs *)args;
    args_->function(args_->arg);
    free(args);
    return 0;
}
#elif defined(EPC_POSIX)
static void *thread_function_wrapper(void *args) {
    ThreadFunctionArgs *args_ = (ThreadFunctionArgs *)args;
    args_->function(args_->arg);
    free(args);
    return NULL;
}
#endif

static void start_thread(Thread *thread, ThreadFunctionArgs args) {
    void *heap_args = malloc(sizeof(ThreadFunctionArgs));
    if (heap_args == NULL) {
        TEST_PERROR("malloc");
    }
    *((ThreadFunctionArgs *)heap_args) = args;

#ifdef EPC_WINDOWS
    *thread = CreateThread(NULL, 0, thread_function_wrapper, heap_args, 0, NULL);
    if (*thread == NULL) {
        TEST_PERROR("CreateThread");
    }
#elif defined(EPC_POSIX)

    int status = pthread_create(thread, NULL, thread_function_wrapper, heap_args);
    if (status != 0) {
        TEST_PERROR("pthread_create");
    }
#endif
}

static void join_thread(const Thread thread) {
#ifdef EPC_WINDOWS
    DWORD status = WaitForSingleObject(thread, INFINITE);
    if (status != WAIT_OBJECT_0) {
        TEST_PERROR("WaitForSingleObject");
    }
#elif defined(EPC_POSIX)
    int status = pthread_join(thread, NULL);
    if (status != 0) {
        TEST_PERROR("pthread_join");
    }
#endif
}

// ████████ ███████ ███████ ████████ ███████
//    ██    ██      ██         ██    ██
//    ██    █████   ███████    ██    ███████
//    ██    ██           ██    ██         ██
//    ██    ███████ ███████    ██    ███████

static uint32_t roundtrip_count = 1000000;
static double max_accepted_rtt_ms = 0.01;

typedef struct SubthreadArgs {
    char *address;
} SubthreadArgs;

#define TEST_CLIENT_OPEN                                                                 \
    SubthreadArgs *args_ = (SubthreadArgs *)args;                                        \
    EPCClient client;                                                                    \
    assert(                                                                              \
        epc_error_ok(epc_client_connect(&client, args_->address, requested_size, 200)));

#define TEST_CLIENT_CLOSE assert(epc_error_ok(epc_client_disconnect(&client)));

#define TEST_SERVER_OPEN_WITH_CLIENT(client_function)                                    \
    char address[ADDRESS_LENGTH + 1] = {0};                                              \
    random_address(address);                                                             \
    Thread client;                                                                       \
    start_thread(&client, (ThreadFunctionArgs){.function = client_function,              \
                                               .arg = &(SubthreadArgs){                  \
                                                   .address = address,                   \
                                               }});                                      \
    EPCServer server;                                                                    \
    assert(epc_error_ok(epc_server_bind(&server, address, 1000)));

#define TEST_SERVER_CLOSE_WITH_CLIENT                                                    \
    assert(epc_error_ok(epc_server_close(&server)));                                     \
    join_thread(client);

const char test_message[] =
    "hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello epicac!hello "
    "epicac!hello epi";

static const uint32_t requested_size = sizeof(test_message);

static void test_client_send_client_thread(void *args) {
    TEST_CLIENT_OPEN

    for (uint32_t i = 0; i < roundtrip_count; ++i) {
        EPCBuffer buffer = {.buf = NULL};
        assert(epc_error_ok(epc_client_try_send(client, &buffer, 1000)));

        assert(buffer.buf != NULL);
        assert(buffer.size == requested_size);

        buffer.buf[0] = 0;
        char *buf_ = (char *)buffer.buf;
        strcat(buf_, test_message);

        assert(epc_error_ok(epc_client_end_send(client, sizeof(test_message))));

        EPCMessage message = {.buf = NULL};
        assert(epc_error_ok(epc_client_try_recv(client, &message, 1000)));
        assert(message.len == sizeof(test_message));
        char *message_ = (char *)message.buf;
        assert(message_ != NULL);
        // assert(!memcmp(message_, test_message, message.len));
        EPCError e = epc_client_end_recv(client);
        assert(epc_error_ok(e));
    }

    TEST_CLIENT_CLOSE
}

static void test_client_send() {
    TEST_SERVER_OPEN_WITH_CLIENT(test_client_send_client_thread)

    EPCClientID client_id;
    EPCMessage message = {.buf = NULL};
    assert(err_eq(
        epc_server_try_recv_or_accept(server, &client_id, &message, requested_size, 1000),
        error(OK, ACCEPTED)));

    for (uint32_t i = 0; i < roundtrip_count; ++i) {
        message = (EPCMessage){.buf = NULL};
        assert(err_eq(epc_server_try_recv_or_accept(server, &client_id, &message,
                                                    requested_size, 1000),
                      error(OK, GOT_MESSAGE)));
        assert(message.len == sizeof(test_message));
        char *message_ = (char *)message.buf;
        assert(message_ != NULL);
        // assert(!memcmp(message_, test_message, message.len));

        assert(epc_error_ok(epc_server_end_recv(server, client_id)));

        EPCBuffer buffer = {.buf = NULL};
        assert(epc_error_ok(epc_server_try_send(server, client_id, &buffer, 1000)));

        assert(buffer.buf != NULL);
        assert(buffer.size == requested_size);

        buffer.buf[0] = 0;
        char *buf_ = (char *)buffer.buf;
        strcat(buf_, test_message);

        assert(
            epc_error_ok(epc_server_end_send(server, client_id, sizeof(test_message))));
    }

    TEST_SERVER_CLOSE_WITH_CLIENT
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    init_mutex();
    srand(time(NULL));
    (void)unlock_mutex;
    (void)lock_mutex;
    (void)sleep_ms;

    fprintf(stderr, "=======================================================\n");

    uint64_t start_time_ms = monotonic_time_ms();
    test_client_send();
    uint64_t total_time_ms = monotonic_time_ms() - start_time_ms;

    double average_rtt_ms = total_time_ms / (double)roundtrip_count;

    fprintf(stderr, "%d messages sent in %.2lfs. Average RTT is %.2lfus\n",
            roundtrip_count, total_time_ms / 1000.0, average_rtt_ms * 1000.0);

    bool passed = true;
    if (average_rtt_ms <= max_accepted_rtt_ms) {
        fprintf(stderr, "Within acceptable range of less than %.2lfus\n",
                max_accepted_rtt_ms * 1000.0);
    } else {
        fprintf(stderr, "Failure: RTT is larger than %.2lfus\n",
                max_accepted_rtt_ms * 1000.0);
        passed = false;
    }

    fprintf(stderr, "=======================================================\n");

    destroy_mutex();

    return !passed;
}