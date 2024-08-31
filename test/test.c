
#include "epicac.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

#define EPC_ASSERT_FAIL(error_message, epc_error, expected_error)                        \
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

static inline char *epc_err_to_string(char *message, EPCError err) {
    const char *high_desc = epc_error_high_description(err);
    const char *low_desc = epc_error_low_description(err);
    char *string = malloc(sizeof(char) * (strlen(message) + strlen(high_desc) +
                                          strlen(low_desc) + strlen(":  ()")));
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

#define RUN_TEST(test)                                                                   \
    do {                                                                                 \
        TestResult result = test();                                                      \
        tests_run++;                                                                     \
        if (result.failure) {                                                            \
            fprintf(stderr, "[%s] %s\n", #test, result.message);                         \
            exit(1);                                                                     \
        } else {                                                                         \
            tests_passed++;                                                              \
            printf(".");                                                                 \
        }                                                                                \
    } while (0)

typedef struct TestResult {
    bool failure;
    char *message;
} TestResult;

typedef TestResult(TestFunction)(void *);

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
        perror(__FILE__ ", line " STRINGIZE(__LINE__)", epicac.monotonic_time_ms.clock_gettime failed");
        return 0;
    }
    return ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
#endif
}

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
    EPC_ASSERT_FAIL("second epc_server_bind should fail",
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

static TestResult test_client_timeout() {
    char address[ADDRESS_LENGTH + 1] = {0};
    random_address(address);

    EPCServer server;
    EPCClient client;
    EPC_ASSERT("epc_server_bind", epc_server_bind(&server, address, 1000));
    EPC_ASSERT_FAIL("epc_client_connect", epc_client_connect(&client, address, 128, 200),
                    error(IPC, TIMEOUT));

    EPC_ASSERT("epc_server_close", epc_server_close(&server));
    EPC_ASSERT_FAIL("epc_client_disconnect", epc_client_disconnect(&client),
                    error(ARGS, NOT_INITIALIZED));

    return (TestResult){0};
}

static void all_tests() {
    srand(time(NULL));

    RUN_TEST(test_basic_server_start);
    RUN_TEST(test_unique_server);
    RUN_TEST(test_restart_server);
    RUN_TEST(test_client_timeout);

    printf("\n");
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    uint64_t start_time = monotonic_time_ms();

    printf("========================================\n");

    all_tests();

    printf("%d tests run.\n", tests_run);
    if (tests_run == tests_passed) {
        printf("All tests passed in %.1fs.\n",
               (float)(monotonic_time_ms() - start_time) / 1000.0f);
    }

    printf("========================================\n");

    return tests_run != tests_passed;
}