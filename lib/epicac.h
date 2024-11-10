/*
so basically:

// server.c
bind("blabla")

if (until_can_recv(1000ms))
    error!




// client.c
connect("blabla")

bufs = get_bufs()

if (until_can_send(1000ms))
    error!

bufs.send_buf[...] = ...
send()

if (until_can_recv(1000ms))
    error!

... = bufs.recv_buf[...]

recv()

*/

#ifndef EPC_H
#define EPC_H

#include <stddef.h>
#include <stdint.h>

#define EPC_VERSION_MAJOR 0
#define EPC_VERSION_MINOR 0
#define EPC_VERSION_PATCH 1

#define EPC_MAX_NAME 100

#define ERROR_HIGH                                                                       \
    X(OK, "Ok", "success")                                                               \
    X(ARGS, "Args", "argument(s) invalid")                                               \
    X(SYS, "Sys", "system call error")                                                   \
    X(IPC, "IPC", "internal epicac IPC error")                                           \
    X(POLL, "Poll", "polling status")                                                    \
    X(COUNT, "N/A", "this is a count and seeing this message is a severe error")

/// Error codes.
typedef enum EPCErrorHigh {
#define X(name, string, description) EPC_ERR_H_##name,
    ERROR_HIGH
#undef X
} EPCErrorHigh;

#define ERROR_LOW                                                                        \
    X(NONE, "none", "there is no problem :)")                                            \
    X(NOTHING_TO_DO, "nothing to do", "previous call did not need anything to happen")   \
    X(ACCEPTED, "accepted", "new connection was accepted")                               \
    X(GOT_MESSAGE, "got message", "received a message")                                  \
    X(OUT_OF_ORDER, "invalid operation order",                                           \
      "requested operation is out of regular send/receive message order")                \
    X(TIMEOUT, "timeout", "the operation timed out")                                     \
    X(NOT_INITIALIZED, "not initialized", "argument is not initialized")                 \
    X(IS_NULL, "is null", "argument is NULL")                                            \
    X(INDEX, "index", "index out of bounds")                                             \
    X(ENUM, "enum", "invalid enum value")                                                \
    X(ID, "ID", "invalid ID or no longer in use")                                        \
    X(STRING_TOO_LONG, "string too long", "string too long")                             \
    X(STRING_TOO_SHORT, "string too short", "string too short")                          \
    X(STRING_INVALID, "string invalid", "string has invalid format or characters")       \
    X(STRING_UTF8_INVALID, "string utf8 invalid", "string is not valid UTF-8")           \
    X(MALLOC, "malloc()", "memory or resource allocation failed")                        \
    X(FREE, "free()", "memory or resource freeing failed")                               \
    X(DISK, "disk", "disk operation unsucessful")                                        \
    X(PERMISSIONS, "permissions", "invalid permissions for completing the operation")    \
    X(FD_LIMIT, "fd limit", "file descriptor limit has been reached")                    \
    X(SIZE_TOO_SMALL, "size too small", "given size is too small")                       \
    X(NAME_COLLISION, "name collision", "given name already in use")                     \
    X(SEM_OPEN, "semaphore open", "failure to open/create semaphore")                    \
    X(SEM_CLOSE, "semaphore close", "failure to close semaphore")                        \
    X(SHM_OPEN, "shm open", "failure to open/create shared memory")                      \
    X(SHM_CLOSE, "shm close", "failure to close shared memory")                          \
    X(MUTEX_OPEN, "mutex open", "failure to open/create mutex")                          \
    X(MUTEX_CLOSE, "mutex close", "failure to close mutex")                              \
    X(MMAP, "memory mapping file", "failure to map file view into memory")               \
    X(SEM, "semaphore", "failure to wait or post semaphore")                             \
    X(MUTEX, "mutex", "failure to lock or unlock mutex")                                 \
    X(TIME, "time", "failure to get a time counter")                                     \
    X(ALREADY_OPEN, "already open", "already open")                                      \
    X(COULD_NOT_CONNECT, "could not connect", "could not connect")                       \
    X(VERSION_INCOMPATIBLE, "version incompatible", "version incompatible with current") \
    X(HEADER_MALFORMED, "header malformed", "header malformed or partially initialized") \
    X(INVALID_MESSAGE_SIZE, "invalid message size", "message size given is invalid")     \
    X(MESSAGE_TOO_LARGE, "message too large",                                            \
      "message size given is too large for buffer")                                      \
    X(CLOSED, "connection closed", "connection closed")                                  \
    X(CLIENT, "client", "client error")                                                  \
    X(SERVER, "server", "server error")                                                  \
    X(UNKNOWN, "unknown", "unknown error")                                               \
    X(COUNT, "count", "this is a count and seeing this message is a severe error")

/// Error details.
typedef enum EPCErrorLow {
#define X(name, string, description) EPC_ERR_L_##name,
    ERROR_LOW
#undef X
} EPCErrorLow;

typedef struct EPCError {
    uint8_t high;
    uint8_t low;
} EPCError;

/// Normal return.
#define EPC_OK                                                                           \
    (EPCError) { 0, 0 }

const char *epc_error_low_str(EPCError error);
const char *epc_error_low_description(EPCError error);
const char *epc_error_high_str(EPCError error);
const char *epc_error_high_description(EPCError error);
int epc_error_ok(EPCError error);
int epc_error_not_ok(EPCError error);

typedef struct {
    void *internal;
    uint32_t value;
} EPCClient;
typedef struct {
    void *internal;
    uint32_t value;
} EPCServer;

typedef struct {
    uint64_t id;
} EPCClientID;

typedef struct EPCBuffer {
    volatile uint8_t *buf;
    size_t size;
} EPCBuffer;

typedef struct EPCMessage {
    volatile uint8_t *buf;
    size_t len;
} EPCMessage;

#define EPC_OPTIONAL

/**
 * Create a new server socket to listen to new connections.
 */
EPCError epc_server_bind(EPCServer *server, const char *name, uint32_t timeout_ms);
EPCError epc_server_close(EPCServer *server);

EPCError epc_server_try_recv_or_accept(EPCServer server,
                                       EPC_OPTIONAL EPCClientID *client_id,
                                       EPCMessage *message, uint32_t requested_size,
                                       uint32_t timeout_ms);
EPCError epc_server_end_recv(EPCServer server, EPCClientID client_id);
EPCError epc_server_try_send(EPCServer server, EPCClientID client_id, EPCBuffer *buf,
                             uint32_t timeout_ms);
EPCError epc_server_end_send(EPCServer server, EPCClientID client_id,
                             uint32_t message_size);

/**
 * Create a new client socket and connect to a server.
 */
EPCError epc_client_connect(EPCClient *client, const char *name, uint32_t requested_size,
                            uint32_t timeout_ms);
EPCError epc_client_disconnect(EPCClient *client);

EPCError epc_client_try_recv(EPCClient client, EPCMessage *buf, uint32_t timeout_ms);
EPCError epc_client_end_recv(EPCClient client);
EPCError epc_client_try_send(EPCClient client, EPCBuffer *buf, uint32_t timeout_ms);
EPCError epc_client_end_send(EPCClient client, uint32_t message_size);

#endif