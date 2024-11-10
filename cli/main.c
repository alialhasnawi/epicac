// Read data from stdin and send data to stdout.

#ifdef _WIN32
#define EPC_WINDOWS
#include <Windows.h>
#else
#define EPC_POSIX

#define _POSIX_C_SOURCE 200809L
#define _GNU_SO

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epicac.h"
#include <ctype.h>

static const uint32_t DEFAULT_BUFFER_SIZE = 4096;
static const uint32_t DEFAULT_MESSAGE_SIZE = 4096;

#define PROGRAM_NAME "epicat"
const char *program_name = PROGRAM_NAME;

#define STR_(x) #x
#define STR(x) STR_(x)

char err_str_buffer[1024];

#ifdef EPC_WINDOWS
WCHAR err_str_bufferw[sizeof(err_str_buffer) / sizeof(*err_str_buffer) / 2];
const char *err_to_string(DWORD err) {
    size_t buflen = sizeof(err_str_buffer) / sizeof(char);

    DWORD err_str_len =
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, err, 0, err_str_bufferw,
                       sizeof(err_str_bufferw) / sizeof(*err_str_bufferw), NULL);

    if (err_str_len == 0) {
        if (snprintf(err_str_buffer, buflen, "Error while printing error (%ld)", err) <
            0) {
            return "sprintf: Error while printing error printing error";
        }
        return err_str_buffer;
    }

    // Convert win32 WCHAR error to UTF-8.
    int status = WideCharToMultiByte(CP_UTF8, 0, err_str_bufferw, err_str_len, NULL, 0,
                                     NULL, NULL);

    if ((status <= 0)) {
        return "WideCharToMultiByte: UTF-8 conversion error while trying to print "
               "another error";
    }
    unsigned int ustatus = status;
    if (ustatus > buflen) {
        return "WideCharToMultiByte: Input buffer too small while trying to print "
               "another error";
    }

    status = WideCharToMultiByte(CP_UTF8, 0, err_str_bufferw, err_str_len, err_str_buffer,
                                 buflen, NULL, NULL);
    if (status <= 0) {
        return "WideCharToMultiByte: UTF-8 conversion error while trying to print "
               "another error";
    }
    return err_str_buffer;
}
#else
const char *err_to_string(int err) {
    size_t buflen = sizeof(err_str_buffer) / sizeof(char);
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE
    if (!strerror_r(err, err_str_buffer, buflen)) {
        return err_str_buffer;
    }
#else
    return strerror_r(err, err_str_buffer, buflen);
#endif

    if (snprintf(err_str_buffer, buflen, "Error while printing error (%d)", err) < 0) {
        return "sprintf: Error while printing error printing error";
    }
}
#endif

#define CLIB_ERROR(call, err)                                                            \
    do {                                                                                 \
        fprintf(stderr, PROGRAM_NAME ": %s: %s\n", call, err_to_string(err));            \
        exit(2);                                                                         \
    } while (0)

#define EPICAT_ERROR(...)                                                                \
    do {                                                                                 \
        fprintf(stderr, PROGRAM_NAME ": "__VA_ARGS__);                                   \
        exit(2);                                                                         \
    } while (0)

#define USAGE_ERROR(...)                                                                 \
    do {                                                                                 \
        fprintf(stderr, PROGRAM_NAME ": "__VA_ARGS__);                                   \
        fprintf(stderr, "Try '" PROGRAM_NAME " --help' for more information.\n");        \
        exit(2);                                                                         \
    } while (0);

#define HELP_ERROR(...)                                                                  \
    do {                                                                                 \
        fprintf(stderr, PROGRAM_NAME ": "__VA_ARGS__);                                   \
        fprintf(stderr, help_string);                                                    \
        exit(2);                                                                         \
    } while (0);

#define USAGE_STRING "Usage: " PROGRAM_NAME " [OPTIONS...] ADDRESS\n"

static const char *help_string = USAGE_STRING
    "Send messages from standard input to an epicac peer, and receive to standard "
    "output.\n"
    "Example to open a server on address 'foo_bar': " PROGRAM_NAME " -l foo_bar\n"
    "ADDRESS is a string not containing forwards / or backwards \\ slashes.\n"
    "  -l, --listen            start a server instead of a client\n"
    "  -b, --buffer-size=NUM   use an internal IO buffer of size NUM bytes\n"
    "  -m, --message-size=NUM  use an internal max message size of NUM bytes\n"
    "  -v, --verbose           output extra information\n"
    "  -V, --version           output version info and exit\n"
    "  -h, --help              display this help and exit\n";

static const char *version_string =
    "epicac " STR(EPC_VERSION_MAJOR) "." STR(EPC_VERSION_MINOR) "." STR(
        EPC_VERSION_PATCH) "\n"
                           "Copyright (c) 2024 Ali Al-Hasnawi\n"
                           "Licence: MIT\n"
                           "\n"
                           "Written by Ali Al-Hasnawi, with love <3\n";

typedef enum ArgType {
    ARG_TYPE_STRING,
    ARG_TYPE_UINT32,
    ARG_TYPE_FLAG,
} ArgType;

typedef struct ArgDefinition {
    char *name;
    char char_;
    ArgType type;
    size_t struct_offset;
} ArgDefinition;

#define INTO_ARG(x) offsetof(EpicatArgs, x)

typedef struct EpicatArgs {
    const char *address;
    uint32_t buffer_size;
    uint32_t message_size;
    uint32_t loop_time;
    bool listen;
    bool verbose;
    bool print_version;
    bool print_help;
} EpicatArgs;

static const ArgDefinition ARGS[] = {
    {"address", .type = ARG_TYPE_STRING, INTO_ARG(address)},
    {"--buffer-size", 'b', ARG_TYPE_UINT32, INTO_ARG(buffer_size)},
    {"--message-size", 'm', ARG_TYPE_UINT32, INTO_ARG(message_size)},
    {"--loop-time", 't', ARG_TYPE_UINT32, INTO_ARG(loop_time)},
    {"--listen", 'l', ARG_TYPE_FLAG, INTO_ARG(listen)},
    {"--verbose", 'v', ARG_TYPE_FLAG, INTO_ARG(verbose)},
    {"--version", 'V', ARG_TYPE_FLAG, INTO_ARG(print_version)},
    {"--help", 'h', ARG_TYPE_FLAG, INTO_ARG(print_help)},
};
static const size_t ARGS_LEN = (sizeof ARGS) / (sizeof *ARGS);

static inline const ArgDefinition *get_non_positional_arg(const char *name, char char_) {
    if (name != NULL) {
        for (unsigned int i = 0; i < ARGS_LEN; ++i) {
            const ArgDefinition *arg = &ARGS[i];
            if (arg->name[0] == '-' && !strcmp(&arg->name[2], name))
                return arg;
        }
        return NULL;
    }

    if (char_) {
        for (unsigned int i = 0; i < ARGS_LEN; ++i) {
            const ArgDefinition *arg = &ARGS[i];
            if (arg->name[0] == '-' && arg->char_ == char_)
                return arg;
        }
        return NULL;
    }

    assert(false);
    return NULL;
}

static inline const ArgDefinition *get_next_positional_arg(unsigned int *index) {
    for (unsigned int i = *index; i < ARGS_LEN; i++) {
        const ArgDefinition *arg = &ARGS[i];
        if (arg->name[0] != '-') {
            *index = i + 1;
            return arg;
        }
    }
    return NULL;
}

static inline const char *repr_str(const char *value) {
    return value == NULL ? "(null)" : value;
}
static inline char *repr_bool(bool value) { return value ? "true" : "false"; }

static inline void parse_arg(const ArgDefinition *arg_def, EpicatArgs *args,
                             char *arg_value) {
    char *args_base = (char *)args;
    if (arg_def->type == ARG_TYPE_STRING) {
        *(char **)(args_base + arg_def->struct_offset) = arg_value;
    } else if (arg_def->type == ARG_TYPE_UINT32) {
        char *end = NULL;
        errno = 0;
        int64_t value = strtoll(arg_value, &end, 0);
        if (isspace(arg_value[0]) || *end != '\0') {
            USAGE_ERROR("argument for %s/-%c '%s' is not a valid integer\n",
                        arg_def->name, arg_def->char_, arg_value);
        }
        if (errno == ERANGE || value > UINT32_MAX || value < 0) {
            USAGE_ERROR("argument for %s/-%c '%s' is out of range\n", arg_def->name,
                        arg_def->char_, arg_value);
        }
        *(uint32_t *)(args_base + arg_def->struct_offset) = value;
    } else {
        assert("arg_value passed to parse_arg cannot be for an arg that doesn't need a "
               "value" &&
               false);
    }
}

static inline void parse_args(int argc, char *argv[], EpicatArgs *args) {
    bool positional_only_args = false;

    *args = (EpicatArgs){.listen = false,
                         .buffer_size = DEFAULT_BUFFER_SIZE,
                         .message_size = DEFAULT_MESSAGE_SIZE,
                         .loop_time = 50,
                         .address = NULL,
                         .verbose = false,
                         .print_version = false,
                         .print_help = false};
    char *args_base = (char *)args;

    unsigned int positional_arg_index = 0;

    for (int i = 1; i < argc; ++i) {
        char *arg = argv[i];
        int arg_len = strnlen(arg, 1024);
        if (arg_len >= 1023) {
            USAGE_ERROR("argument '%s' too long\n", arg);
        } else if (arg_len == 0) {
            USAGE_ERROR("empty argument not allowed\n");
        }
        char *arg_name = NULL;
        char *arg_value = NULL;

        if (!strcmp("-", arg)) {
            USAGE_ERROR("ambiguous argument -\n");
        }

        if (!strcmp("--", arg)) {
            positional_only_args = true;
        } else if (!positional_only_args && arg[0] == '-') {
            // Handle options/flags.
            if (arg_len >= 2 && arg[1] == '-') {
                // Long options: --bla
                // Long options interpret = as delimiting a value.
                arg_value = strchr(arg, '=');

                if (arg_value != NULL) {
                    *arg_value = '\0';
                    arg_value++;
                }

                arg_name = &arg[2];
                const ArgDefinition *arg_def = get_non_positional_arg(arg_name, 0);
                if (arg_def == NULL) {
                    USAGE_ERROR("unrecognized option --%s\n", arg_name);
                }

                // Boolean flags: --listen
                if (arg_def->type == ARG_TYPE_FLAG) {
                    if (arg_value != NULL) {
                        USAGE_ERROR("option %s/-%c does not take an argument\n",
                                    arg_def->name, arg_def->char_);
                    }
                    *(bool *)(args_base + arg_def->struct_offset) = true;
                } else {
                    // Arguments that need values: --buffer-size=10

                    if (arg_value == NULL) {
                        // Take the next argument as the value for this option.
                        // ie. Support both --foo=bar and --foo bar
                        if (i + 1 < argc && argv[i + 1][0] != '-') {
                            arg_value = &argv[i + 1][0];
                            ++i;
                        }
                    }
                    if (arg_value == NULL || arg_value[0] == '\0') {
                        USAGE_ERROR("missing argument value for %s/-%c\n", arg_def->name,
                                    arg_def->char_);
                    }

                    parse_arg(arg_def, args, arg_value);
                }
            } else {
                // Handle short flags -b
                for (int char_index = 1; char_index < arg_len; char_index++) {
                    char char_ = arg[char_index];
                    const ArgDefinition *arg_def = get_non_positional_arg(NULL, char_);
                    if (arg_def == NULL) {
                        USAGE_ERROR("unrecognized short option -%c\n", char_);
                    }

                    // Boolean flags: --listen
                    if (arg_def->type == ARG_TYPE_FLAG) {
                        *(bool *)(args_base + arg_def->struct_offset) = true;
                    } else {
                        // Arguments that need values: -b1024 or -b=1024
                        arg_value = &arg[char_index + 1];

                        if (arg_value[0] == '=') {
                            arg_value++;
                        } else if (arg_value[0] == '\0') {
                            // Take the next argument as the value for this option.
                            // ie. Support both --foo=bar and --foo bar
                            if (i + 1 < argc && argv[i + 1][0] != '-') {
                                arg_value = &argv[i + 1][0];
                                ++i;
                            }
                        }

                        if (arg_value[0] == '\0') {
                            USAGE_ERROR("missing argument value for %s/-%c\n",
                                        arg_def->name, arg_def->char_);
                        }

                        parse_arg(arg_def, args, arg_value);
                        // Do not use any more flags from this argument.
                        break;
                    }
                }
            }
        } else {
            // Handle positional arguments.
            const ArgDefinition *arg_def = get_next_positional_arg(&positional_arg_index);
            if (arg_def == NULL) {
                USAGE_ERROR("extra argument '%s'\n", arg);
            }
            parse_arg(arg_def, args, arg);
        }
    }
}

static void check_error(EPCError err) {
    if (epc_error_ok(err)) {
        return;
    }

    fprintf(stderr, PROGRAM_NAME ": %s (%s)\n", epc_error_high_str(err),
            epc_error_low_description(err));
    exit(err.high);
}

static void check_error_allow_timeout(EPCError err) {
    if (epc_error_ok(err) || (err.low == EPC_ERR_L_TIMEOUT)) {
        return;
    }

    fprintf(stderr, PROGRAM_NAME ": %s (%s)\n", epc_error_high_str(err),
            epc_error_low_description(err));
    exit(err.high);
}

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
        CLIB_ERROR("CreateMutexW", GetLastError());
    }
#elif defined(EPC_POSIX)
    int err = 0;
    pthread_mutexattr_t attr;
    if ((err = pthread_mutexattr_init(&attr))) {
        CLIB_ERROR("pthread_mutexattr_init", err);
    }
    if ((err = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST))) {
        CLIB_ERROR("pthread_mutexattr_setrobust", err);
    }
    if ((err = pthread_mutex_init(&global_mutex, &attr))) {
        CLIB_ERROR("pthread_mutex_init", err);
    }
    pthread_mutexattr_destroy(&attr);
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
        CLIB_ERROR("WaitForSingleObject", GetLastError());
    }
#elif defined(EPC_POSIX)
    int status = pthread_mutex_lock(&global_mutex);
    if (status != 0) {
        CLIB_ERROR("pthread_mutex_lock", status);
    }
#endif
}

static void unlock_mutex() {
#ifdef EPC_WINDOWS
    BOOL success = ReleaseMutex(global_mutex);
    if (!success) {
        CLIB_ERROR("ReleaseMutex", GetLastError());
    }
#elif defined(EPC_POSIX)
    int status = pthread_mutex_lock(&global_mutex);
    if (status != 0) {
        CLIB_ERROR("pthread_mutex_lock", status);
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
        CLIB_ERROR("malloc", errno);
    }
    *((ThreadFunctionArgs *)heap_args) = args;

#ifdef EPC_WINDOWS
    *thread = CreateThread(NULL, 0, thread_function_wrapper, heap_args, 0, NULL);
    if (*thread == NULL) {
        CLIB_ERROR("CreateThread", GetLastError());
    }
#elif defined(EPC_POSIX)

    int status = pthread_create(thread, NULL, thread_function_wrapper, heap_args);
    if (status != 0) {
        CLIB_ERROR("pthread_create", status);
    }
#endif
}

static void join_thread(const Thread thread) {
#ifdef EPC_WINDOWS
    DWORD status = WaitForSingleObject(thread, INFINITE);
    if (status != WAIT_OBJECT_0) {
        CLIB_ERROR("WaitForSingleObject", GetLastError());
    }
#elif defined(EPC_POSIX)
    int status = pthread_join(thread, NULL);
    if (status != 0) {
        CLIB_ERROR("pthread_join", status);
    }
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

static const uint32_t DEFAULT_TIMEOUT_MS = 10;

// ███████ ███████ ██████  ██    ██ ███████ ██████
// ██      ██      ██   ██ ██    ██ ██      ██   ██
// ███████ █████   ██████  ██    ██ █████   ██████
//      ██ ██      ██   ██  ██  ██  ██      ██   ██
// ███████ ███████ ██   ██   ████   ███████ ██   ██

//  ██████ ██      ██ ███████ ███    ██ ████████
// ██      ██      ██ ██      ████   ██    ██
// ██      ██      ██ █████   ██ ██  ██    ██
// ██      ██      ██ ██      ██  ██ ██    ██
//  ██████ ███████ ██ ███████ ██   ████    ██

#ifdef EPC_WINDOWS
#elif defined(EPC_POSIX)
#endif

static_assert(sizeof(char) == 1,
              "strange architectures will not be supported unless needed");

int stdin_buf_i = 0;
int stdin_buf_len = 0;
int stdin_buf_capacity = 0;
char *stdin_buf;

uint32_t loop_time = 0;

static inline int min_i(int a, int b) { return a < b ? a : b; }

static void epicat_client_stdin(void *ignore) {
    (void)ignore;
    int end, read_len;

    // Read from stdin forever.
    // Simplifies dealing with cross platform non-blocking I/O.
    while (stdin_buf_capacity != 0) {
        lock_mutex();
        if (stdin_buf_len == stdin_buf_capacity) {
            end = -1;
        } else {
            int end = (stdin_buf_i + stdin_buf_len) % stdin_buf_capacity;
            if (end >= stdin_buf_i) {
                read_len = stdin_buf_capacity - end;
            } else {
                read_len = stdin_buf_i - end;
            }
        }
        unlock_mutex();

        if (end == -1) {
            sleep_ms(loop_time);
            continue;
        }

        size_t read_bytes = fread(&stdin_buf[end], sizeof(char), read_len, stdin);
        lock_mutex();
        stdin_buf_len += read_bytes;
        stdin_buf_i = (stdin_buf_i + read_bytes) % stdin_buf_capacity;
        unlock_mutex();
    }
}

static int epicat_client(EpicatArgs *args) {
    stdin_buf = malloc(args->buffer_size);
    stdin_buf_capacity = args->buffer_size;

    Thread stdin_thread;
    loop_time = args->loop_time;
    start_thread(&stdin_thread,
                 (ThreadFunctionArgs){.arg = NULL, .function = epicat_client_stdin});

    EPCClient client;
    check_error(epc_client_connect(&client, args->address, args->message_size, 1000));

    EPCError err;
    size_t stdin_len_to_send = 0;
    size_t stdin_i = 0;

    while (true) {
        EPCBuffer buffer = {.buf = NULL};

        // Handle sending data.
        // First, determine how much to send (only if sending is not in progress).
        if (stdin_len_to_send == 0) {
            lock_mutex();
            if (stdin_buf_len > 0) {
                stdin_i = stdin_buf_i;
                stdin_len_to_send =
                    min(stdin_i + stdin_buf_len, stdin_buf_capacity) - stdin_i;
            }
            unlock_mutex();
        }

        // Then, attempt to send the data.
        if (stdin_len_to_send != 0) {
            err = epc_client_try_send(client, &buffer, DEFAULT_TIMEOUT_MS);
            check_error_allow_timeout(err);
            if (err.low != EPC_ERR_L_TIMEOUT) {
                lock_mutex();
                stdin_buf_len -= stdin_len_to_send;
                stdin_buf_i = (stdin_buf_i + stdin_len_to_send) % stdin_buf_capacity;
                unlock_mutex();

                check_error(epc_client_end_send(client, stdin_len_to_send));
                stdin_len_to_send = 0;
            }
        }

        // Handle receiving data.
        EPCMessage message = {.buf = NULL};
        err = epc_client_try_recv(client, &message, loop_time);
        check_error_allow_timeout(err);
        if (err.low != EPC_ERR_L_TIMEOUT) {
            char *message_ = (char *)message.buf;
            if (fwrite(message_, sizeof(char), message.len, stdout) != message.len) {
                CLIB_ERROR("fwrite", ferror(stdout));
            }
        }
        check_error(epc_client_end_recv(client));
    }

    check_error(epc_client_disconnect(&client));
    free(stdin_buf);
    join_thread(stdin_thread);

    return 0;
}

int main(int argc, char *argv[]) {
    EpicatArgs args;
    parse_args(argc, argv, &args);

    if (args.print_help) {
        printf("%s", help_string);
        exit(0);
    } else if (args.print_version) {
        printf("%s", version_string);
        exit(0);
    }

    if (args.verbose) {
        printf("using config:   address: %s\n"
               "                buffer size: %d\n"
               "                listen: %s\n",
               repr_str(args.address), args.buffer_size, repr_bool(args.listen));
    }

    if (args.address == NULL) {
        USAGE_ERROR("address not provided\n");
    }

    if (args.buffer_size < 1) {
        USAGE_ERROR("internal buffer cannot have size 0\n");
    }

    if (args.message_size < 1) {
        USAGE_ERROR("message size cannot be 0\n");
    }

    if (args.loop_time < 1) {
        USAGE_ERROR("loop time cannot be 0\n");
    }

    if (args.message_size < args.buffer_size) {
        USAGE_ERROR("message size cannot be smaller than the buffer size\n");
    }

    init_mutex();
    int status = 0;
    if (args.listen) {

    } else {
        status = epicat_client(&args);
    }
    destroy_mutex();

    return status;
}
