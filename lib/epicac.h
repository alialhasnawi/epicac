// TODO: API design.
// Need to allow 0-copy messaging
// Should be sync
/*
- client and server are created (order doesn't matter)
- client or server can send as long as the other allows it
- send API is made of multiple steps
    - can send: only return when allowed to send
    - send: signals to the other that a message was sent
    * in between the 2, the actual writes happen
- recieve API is simillar:
    - can receive: only return when there's data to be used
    - receive: signal to the other that the message has been used

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

#include <stdint.h>

#define EPC_MAX_NAME 100

/// Error codes.
typedef enum EPCErrorHigh {
    EPC_ERR_H_OK = 0x0,
    EPC_ERR_H_ARGS,
    EPC_ERR_H_SYS,
    EPC_ERR_H_IPC,
    EPC_ERR_H_POLL,

    EPC_ERR_H_COUNT,
} EPCErrorHigh;

/// Error details.
typedef enum EPCErrorLow {
    EPC_ERR_L_NONE = 0x0,

    EPC_ERR_L_NOTHING_TO_DO,

    EPC_ERR_L_TIMEOUT,

    EPC_ERR_L_NOT_INITIALIZED,
    EPC_ERR_L_IS_NULL,
    EPC_ERR_L_INDEX,
    EPC_ERR_L_STRING_TOO_LONG,
    EPC_ERR_L_STRING_TOO_SHORT,
    EPC_ERR_L_STRING_INVALID,
    EPC_ERR_L_STRING_UTF8_INVALID,

    EPC_ERR_L_MALLOC,
    EPC_ERR_L_FREE,
    EPC_ERR_L_DISK,
    EPC_ERR_L_PERMISSIONS,
    EPC_ERR_L_FD_LIMIT,
    EPC_ERR_L_SIZE_TOO_SMALL,
    EPC_ERR_L_NAME_COLLISION,
    EPC_ERR_L_SEM_OPEN,
    EPC_ERR_L_SEM_CLOSE,
    EPC_ERR_L_SHM_OPEN,
    EPC_ERR_L_SHM_CLOSE,
    EPC_ERR_L_MUTEX_OPEN,
    EPC_ERR_L_MUTEX_CLOSE,
    EPC_ERR_L_MMAP,
    EPC_ERR_L_SEM,
    EPC_ERR_L_MUTEX,
    EPC_ERR_L_TIME,

    EPC_ERR_L_ALREADY_OPEN,
    EPC_ERR_L_COULD_NOT_CONNECT,
    EPC_ERR_L_VERSION_INCOMPATIBLE,
    EPC_ERR_L_HEADER_MALFORMED,
    EPC_ERR_L_INVALID_MESSAGE_SIZE,
    EPC_ERR_L_CLIENT,
    EPC_ERR_L_SERVER,

    EPC_ERR_L_UNKNOWN,

    EPC_ERR_L_COUNT,
} EPCErrorLow;

typedef struct EPCError {
    uint8_t high;
    uint8_t low;
} EPCError;

/// Normal return.
#define EPC_OK                                                                           \
    (EPCError) { 0, 0 }

typedef uint8_t EPCPollStatus;
#define EPC_POLL_ERROR 0x1
/// The socket is ready to send data.
#define EPC_POLL_SEND 0x2
/// The socket is ready to receive data.
#define EPC_POLL_RECV 0x4

typedef struct {
    void *internal;
} EPCClient;
typedef struct {
    void *internal;
} EPCServer;

typedef struct {
    uint64_t id;
} EPCClientID;

typedef struct EPCBuffer {
    char *buf;
    size_t size;
} EPCBuffer;

typedef struct EPCMessage {
    char *buf;
    size_t len;
    EPCClientID id;
} EPCMessage;

/**
 * Create a new server socket to listen to new connections.
 */
typedef struct EPC_server_bind_args {
    char *name;
    uint32_t timeout_ms;
} EPC_server_bind_args;
EPCError epc_server_bind(EPCServer *server, char *name, uint32_t timeout_ms);
EPCError epc_server_close(EPCServer server);

typedef struct EPC_server_try_recv_args {
    uint32_t timeout_ms;
} EPC_server_try_recv_args;
EPCError epc_server_try_recv(EPCServer server, EPCMessage *message, uint32_t timeout_ms);
EPCError epc_server_end_recv(EPCServer server, EPCClientID client_id);
EPCError epc_server_try_send(EPCServer server, EPCClientID client_id, EPCBuffer *buf,
                             uint32_t timeout_ms);
EPCError epc_server_end_send(EPCServer server, EPCClientID client_id);
EPCError epc_server_resize(EPCServer server, EPCClientID client_id,
                           uint32_t new_send_size);

/**
 * Create a new client socket and connect to a server.
 */
EPCError epc_client_connect(EPCClient *client, char *name, uint32_t timeout_ms);
EPCError epc_client_disconnect(EPCClient client);

EPCError epc_client_try_recv(EPCClient client, EPCBuffer *buf, uint32_t timeout_ms);
EPCError epc_client_end_recv(EPCClient client);
EPCError epc_client_try_send(EPCClient client, EPCBuffer *buf, uint32_t timeout_ms);
EPCError epc_client_end_send(EPCClient client);
EPCError epc_client_resize(EPCClient client, uint32_t new_send_size);

#endif