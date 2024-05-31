#ifndef IPCACK_H
#define IPCACK_H

#include <stdint.h>

#define IPCACK_MAX_NAME 100

typedef uint16_t IPCAckError;

/// Error codes.
typedef enum IPCAckErrorHigh {
    IPCACK_ERR_H_OK = 0x0,
    IPCACK_ERR_H_ARGS,
    IPCACK_ERR_H_SYS,
    IPCACK_ERR_H_IPC,

    IPCACK_ERR_H_COUNT,
} IPCAckErrorHigh;

/// Error details.
typedef enum IPCAckErrorLow {
    IPCACK_ERR_L_NONE = 0x0,

    IPCACK_ERR_L_NOT_INITIALIZED,
    IPCACK_ERR_L_IS_NULL,
    IPCACK_ERR_L_INDEX,
    IPCACK_ERR_L_STRING_TOO_LONG,
    IPCACK_ERR_L_STRING_TOO_SHORT,
    IPCACK_ERR_L_STRING_INVALID,
    IPCACK_ERR_L_STRING_UTF8_INVALID,

    IPCACK_ERR_L_MALLOC,
    IPCACK_ERR_L_FREE,
    IPCACK_ERR_L_DISK,
    IPCACK_ERR_L_PERMISSIONS,
    IPCACK_ERR_L_FD_LIMIT,
    IPCACK_ERR_L_SIZE_TOO_SMALL,
    IPCACK_ERR_L_NAME_COLLISION,
    IPCACK_ERR_L_SEM_OPEN,
    IPCACK_ERR_L_SEM_CLOSE,
    IPCACK_ERR_L_SHM_OPEN,
    IPCACK_ERR_L_SHM_CLOSE,
    IPCACK_ERR_L_MMAP,
    IPCACK_ERR_L_SEM,

    IPCACK_ERR_L_ALREADY_OPEN,

    IPCACK_ERR_L_UNKNOWN,

    IPCACK_ERR_L_COUNT,
} IPCAckErrorLow;

/// Normal return.
#define IPCACK_OK IPCACK_ERR_H_OK

typedef uint8_t IPCAckPollStatus;
#define IPCACK_POLL_ERROR 0x1
/// The socket is ready to send data.
#define IPCACK_POLL_SEND 0x2
/// The socket is ready to receive data.
#define IPCACK_POLL_RECV 0x4

typedef struct {
    void *internal;
} IPCAckClient;
typedef struct {
    void *internal;
} IPCAckServer;

/**
 * Create a new server socket to listen to new connections.
 */
IPCAckError ipcack_server_bind(IPCAckServer *server, char *name);
IPCAckError ipcack_server_close(IPCAckServer server);

typedef struct IPCAckClientMessage {
    uint64_t client;
    size_t incoming_len;
    size_t max_outgoing_len;
    char *incoming;
    char *outgoing;
} IPCAckClientMessage;
IPCAckError ipcack_server_recv(IPCAckServer server, IPCAckClientMessage *message);

IPCAckError ipcack_server_send(IPCAckServer server, uint64_t client, size_t len);
IPCAckError ipcack_server_resize(IPCAckServer server, uint64_t client, size_t new_len);

/**
 * Create a new client socket and connect to a server.
 */
IPCAckError ipcack_client_connect(IPCAckClient *client, char *name);
IPCAckError ipcack_client_disconnect(IPCAckClient client);

/**
 * Get read/write buffer.
 */
typedef struct IPCAckBuffers {
    char *read;
    size_t read_len;
    char *write;
    size_t write_len;
} IPCAckBuffers;
IPCAckError ipcack_client_getbufs(IPCAckClient client, IPCAckBuffers buffers);

/**
 * Send data.
 */
IPCAckError ipcack_client_send(IPCAckClient client, size_t len, size_t timeout_ms);

/**
 * Receive data.
 */
IPCAckError ipcack_client_recv(IPCAckClient client, size_t *len, size_t timeout_ms);

/**
 * Poll for or get socket status.
 */
IPCAckPollStatus ipcack_client_poll(IPCAckClient client, IPCAckPollStatus flags,
                                    uint32_t timeout_ns);

IPCAckError ipcack_client_resize(IPCAckClient client, size_t new_len);
#endif