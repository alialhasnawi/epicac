#ifndef IPCACK_H
#define IPCACK_H

#include <stdint.h>

#define IPCACK_MAX_NAME 100

typedef uint16_t IPCAckError;
/// Normal return.
#define IPCACK_ERROR_NO_ERROR 0
/// Given string is too long.
#define IPCACK_ERROR_NAME_TOO_LONG 1
/// Given string is not a valid address.
#define IPCACK_ERROR_NAME_INVALID 2
/// Given argument is invalid.
#define IPCACK_ERROR_ARG_INVALID 3
/// OS error while creating or opening resource.
#define IPCACK_ERROR_SYSTEM 12
/// The resource already exists.
#define IPCACK_ERROR_EXISTS 13
/// The buffer was wrongly edited.
#define IPCACK_ERROR_BUFFER 14
/// Call timed out.
#define IPCACK_ERROR_TIMEOUT 100

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