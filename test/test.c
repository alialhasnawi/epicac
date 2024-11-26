

#ifdef _WIN32
#define EPC_WINDOWS
#define _CRT_SECURE_NO_WARNINGS 1
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

#define ASSERT(error_message, test)                                                      \
    do {                                                                                 \
        if (!(test))                                                                     \
            return (TestResult){.failure = true, .message = error_message};              \
    } while (0)

#define EPC_ASSERT_ERR(error_message, epc_error, expected_error)                         \
    do {                                                                                 \
        EPCError e = epc_error;                                                          \
        if (!err_eq(e, expected_error))                                                  \
            return (TestResult){                                                         \
                .failure = true,                                                         \
                .message = epc_err_to_string(                                            \
                    error_message " (expected " #expected_error ")", e)};                \
    } while (0)

#define EPC_ASSERT(error_message, epc_error)                                             \
    do {                                                                                 \
        EPCError e = epc_error;                                                          \
        if (epc_error_not_ok(e))                                                         \
            return (TestResult){.failure = true,                                         \
                                .message = epc_err_to_string(error_message, e)};         \
    } while (0)

#define ASSERT_THREAD(error_message, test)                                               \
    do {                                                                                 \
        if (!(test)) {                                                                   \
            *args_->result = (TestResult){.failure = true, .message = error_message};    \
            return;                                                                      \
        }                                                                                \
    } while (0)

#define EPC_ASSERT_THREAD(error_message, epc_error)                                      \
    do {                                                                                 \
        EPCError e = epc_error;                                                          \
        if (epc_error_not_ok(e)) {                                                       \
            *args_->result = (TestResult){                                               \
                .failure = true, .message = epc_err_to_string(error_message, e)};        \
            return;                                                                      \
        }                                                                                \
    } while (0)

#define EPC_ASSERT_ERR_THREAD(error_message, epc_error, expected_error)                  \
    do {                                                                                 \
        EPCError e = epc_error;                                                          \
        if (!err_eq(e, expected_error)) {                                                \
            *args_->result =                                                             \
                (TestResult){.failure = true,                                            \
                             .message = epc_err_to_string(                               \
                                 error_message " (expected " #expected_error ")", e)};   \
            return;                                                                      \
        }                                                                                \
    } while (0)

static inline char *epc_err_to_string(const char *message, EPCError err) {
    const char *high_desc = epc_error_high_description(err);
    const char *low_desc = epc_error_low_description(err);
    size_t string_buflen = strlen(message) + strlen(high_desc) + strlen(low_desc);
    char *string = malloc(sizeof(char) * string_buflen + sizeof(":  ()"));
    if (string == NULL) {
        TEST_PERROR("malloc");
    }
    if (snprintf(string, string_buflen, "%s: %s (%s)", message, high_desc, low_desc) <
        -1) {
        TEST_PERROR("snprintf");
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

#define RUN_TEST(test)                                                                   \
    do {                                                                                 \
        TestResult result = test();                                                      \
        tests_run++;                                                                     \
        if (result.failure) {                                                            \
            fprintf(stderr, "[%s] %s\n", #test, result.message);                         \
            exit(1);                                                                     \
        } else {                                                                         \
            tests_passed++;                                                              \
            fprintf(stderr, ".");                                                        \
        }                                                                                \
    } while (0)

typedef struct TestResult {
    bool failure;
    char *message;
} TestResult;

int tests_run = 0;
int tests_passed = 0;

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
    pthread_mutexattr_destroy(&global_mutex);
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

static TestResult test_basic_server_start() {
    char address[ADDRESS_LENGTH + 1] = {0};
    random_address(address);

    EPCServer server;
    EPC_ASSERT("epc_server_bind", epc_server_bind(&server, address, 1000));
    EPC_ASSERT("epc_server_close", epc_server_close(&server));

    return (TestResult){0};
}

static TestResult test_unique_server() {
    char address[ADDRESS_LENGTH + 1] = {0};
    random_address(address);

    EPCServer server;
    EPC_ASSERT("epc_server_bind", epc_server_bind(&server, address, 1000));

    EPCServer server2;
    EPC_ASSERT_ERR("second epc_server_bind should fail",
                   epc_server_bind(&server2, address, 1000), error(IPC, ALREADY_OPEN));

    EPC_ASSERT("epc_server_close", epc_server_close(&server));

    return (TestResult){0};
}

static TestResult test_restart_server() {
    char address[ADDRESS_LENGTH + 1] = {0};
    random_address(address);

    EPCServer server;
    EPC_ASSERT("epc_server_bind", epc_server_bind(&server, address, 1000));
    EPC_ASSERT("epc_server_close", epc_server_close(&server));

    EPCServer server2;
    EPC_ASSERT("second epc_server_bind should succeed",
               epc_server_bind(&server2, address, 1000));

    return (TestResult){0};
}

static const uint32_t requested_size = 128;

static TestResult test_client_timeout() {
    char address[ADDRESS_LENGTH + 1] = {0};
    random_address(address);

    EPCServer server;
    EPCClient client;
    EPC_ASSERT("epc_server_bind", epc_server_bind(&server, address, 1000));
    EPC_ASSERT_ERR("epc_client_connect",
                   epc_client_connect(&client, address, requested_size, 200),
                   error(IPC, TIMEOUT));

    EPC_ASSERT("epc_server_close", epc_server_close(&server));
    EPC_ASSERT_ERR("epc_client_disconnect", epc_client_disconnect(&client),
                   error(ARGS, NOT_INITIALIZED));

    return (TestResult){0};
}

typedef struct SubthreadArgs {
    char *address;
    TestResult *result;
} SubthreadArgs;

#define TEST_CLIENT_OPEN                                                                 \
    SubthreadArgs *args_ = (SubthreadArgs *)args;                                        \
    EPCClient client;                                                                    \
    EPC_ASSERT_THREAD("epc_client_connect",                                              \
                      epc_client_connect(&client, args_->address, requested_size, 200));

#define TEST_CLIENT_CLOSE                                                                \
    EPC_ASSERT_THREAD("epc_client_disconnect", epc_client_disconnect(&client));

#define TEST_SERVER_OPEN_WITH_CLIENT(client_function)                                    \
    char address[ADDRESS_LENGTH + 1] = {0};                                              \
    random_address(address);                                                             \
    Thread client;                                                                       \
    TestResult client_result = {0};                                                      \
    SubthreadArgs *client_args = malloc(sizeof(SubthreadArgs));                          \
    *client_args = (SubthreadArgs){.address = address, .result = &client_result};        \
    start_thread(&client,                                                                \
                 (ThreadFunctionArgs){.function = client_function, .arg = client_args}); \
    EPCServer server;                                                                    \
    EPC_ASSERT("epc_server_bind", epc_server_bind(&server, address, 1000));

#define TEST_SERVER_CLOSE_WITH_CLIENT                                                    \
    EPC_ASSERT("epc_server_close", epc_server_close(&server));                           \
    join_thread(client);                                                                 \
    if (client_result.failure)                                                           \
        return client_result;                                                            \
    return (TestResult){0};

static void test_basic_connect_client_thread(void *args) {
    TEST_CLIENT_OPEN
    TEST_CLIENT_CLOSE
}

static TestResult test_basic_connect() {
    TEST_SERVER_OPEN_WITH_CLIENT(test_basic_connect_client_thread)

    EPCClientID client_id;
    EPCMessage message;
    EPC_ASSERT_ERR(
        "epc_server_try_recv_or_accept",
        epc_server_try_recv_or_accept(server, &client_id, &message, requested_size, 1000),
        error(OK, ACCEPTED));

    TEST_SERVER_CLOSE_WITH_CLIENT
}

const char test_message[] = "hello epicac!";

static void test_client_send_client_thread(void *args) {
    TEST_CLIENT_OPEN

    EPCBuffer buffer = {.buf = NULL};
    EPC_ASSERT_THREAD("epc_client_try_send", epc_client_try_send(client, &buffer, 1000));

    ASSERT_THREAD("buffer is set", buffer.buf != NULL);
    ASSERT_THREAD("buffer requested size is respected", buffer.size == requested_size);

    buffer.buf[0] = 0;
    char *buf_ = (char *)buffer.buf;
    strcat(buf_, test_message);

    EPC_ASSERT_THREAD("epc_client_try_send",
                      epc_client_end_send(client, sizeof(test_message)));

    TEST_CLIENT_CLOSE
}

static TestResult test_client_send() {
    TEST_SERVER_OPEN_WITH_CLIENT(test_client_send_client_thread)

    EPCClientID client_id;
    EPCMessage message = {.buf = NULL};
    EPC_ASSERT_ERR(
        "epc_server_try_recv_or_accept (accept)",
        epc_server_try_recv_or_accept(server, &client_id, &message, requested_size, 1000),
        error(OK, ACCEPTED));

    EPC_ASSERT_ERR(
        "epc_server_try_recv_or_accept (recv)",
        epc_server_try_recv_or_accept(server, &client_id, &message, requested_size, 1000),
        error(OK, GOT_MESSAGE));
    ASSERT("message size is correct", message.len == sizeof(test_message));
    char *message_ = (char *)message.buf;
    ASSERT("message not null", message_ != NULL);
    ASSERT("message not corrupted", !strcmp(message_, test_message));

    TEST_SERVER_CLOSE_WITH_CLIENT
}

static void test_server_send_client_thread(void *args) {
    TEST_CLIENT_OPEN

    EPCMessage message = {.buf = NULL};
    EPC_ASSERT_THREAD("epc_client_try_recv", epc_client_try_recv(client, &message, 1000));
    ASSERT_THREAD("message size is correct", message.len == sizeof(test_message));
    char *message_ = (char *)message.buf;
    ASSERT_THREAD("message not null", message_ != NULL);
    ASSERT_THREAD("message not corrupted", !strcmp(message_, test_message));

    TEST_CLIENT_CLOSE
}

static TestResult test_server_send() {
    TEST_SERVER_OPEN_WITH_CLIENT(test_server_send_client_thread)

    EPCClientID client_id;
    EPCMessage message = {.buf = NULL};
    EPC_ASSERT_ERR(
        "epc_server_try_recv_or_accept (accept)",
        epc_server_try_recv_or_accept(server, &client_id, &message, requested_size, 1000),
        error(OK, ACCEPTED));

    EPCBuffer buffer = {.buf = NULL};
    EPC_ASSERT("epc_server_try_send",
               epc_server_try_send(server, client_id, &buffer, 1000));

    ASSERT("buffer is set", buffer.buf != NULL);
    ASSERT("buffer requested size is respected", buffer.size == requested_size);

    buffer.buf[0] = 0;
    char *buf_ = (char *)buffer.buf;
    strcat(buf_, test_message);

    EPC_ASSERT("epc_server_end_send",
               epc_server_end_send(server, client_id, sizeof(test_message)));

    TEST_SERVER_CLOSE_WITH_CLIENT
}

static void all_tests() {
    srand((unsigned int)time(NULL));

    RUN_TEST(test_basic_server_start);
    RUN_TEST(test_unique_server);
    RUN_TEST(test_restart_server);
    RUN_TEST(test_client_timeout);
    RUN_TEST(test_basic_connect);
    RUN_TEST(test_client_send);
    RUN_TEST(test_server_send);

    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    init_mutex();
    (void)unlock_mutex;
    (void)lock_mutex;
    (void)sleep_ms;

    uint64_t start_time = monotonic_time_ms();

    fprintf(stderr, "========================================\n");

    all_tests();

    fprintf(stderr, "%d tests run.\n", tests_run);
    if (tests_run == tests_passed) {
        fprintf(stderr, "All tests passed in %.2fs.\n",
                (float)(monotonic_time_ms() - start_time) / 1000.0f);
    }

    fprintf(stderr, "========================================\n");

    destroy_mutex();

    return tests_run != tests_passed;
}