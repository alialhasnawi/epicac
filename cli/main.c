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
    bool listen;
    bool verbose;
    bool print_version;
    bool print_help;
} EpicatArgs;

static const ArgDefinition ARGS[] = {
    {"address", .type = ARG_TYPE_STRING, INTO_ARG(address)},
    {"--buffer-size", 'b', ARG_TYPE_UINT32, INTO_ARG(buffer_size)},
    {"--message-size", 'm', ARG_TYPE_UINT32, INTO_ARG(message_size)},
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

// int epicat_client(EpicatArgs *args) {
//     HANDLE windows_stdin = GetStdHandle(STD_INPUT_HANDLE);
//     if (windows_stdin == INVALID_HANDLE_VALUE) {
//         EPICAT_ERROR("GetStdHandle() for stdin was invalid");
//         return 1;
//     }

//     char *buffer = malloc(sizeof(char) * args->buffer_size);

//     while (fgets(buffer, args->buffer_size, stdin) != NULL) {
//         if (fputs(buffer, stdout) == EOF) {
//             perror(PROGRAM_NAME ": fwrite");
//         }
//     };

//     return 0;
// }

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

    return 0;
}
