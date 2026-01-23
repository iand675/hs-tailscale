/*
 * tsnet.h - C header for tsnet FFI bindings
 *
 * This header declares the C-compatible interface to the tsnet Go library.
 * The implementation is in go/tsnet_ffi.go and must be built as a shared
 * library using: cd go && go build -buildmode=c-shared -o ../libtsnet.so
 */

#ifndef TSNET_H
#define TSNET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result structure for operations that can fail */
typedef struct {
    int success;      /* 0 = error, 1 = success, 2 = EOF (for reads) */
    char* error;      /* Error message (caller must free with tsnet_free_string) */
} TSNetResult;

/* IP address pair */
typedef struct {
    char* ipv4;       /* IPv4 address (caller must free) */
    char* ipv6;       /* IPv6 address (caller must free) */
} TSNetIPs;

/* Listener address info */
typedef struct {
    char* network;    /* Network type (e.g., "tcp") */
    char* addr;       /* Address (e.g., "100.64.1.1:8080") */
} TSNetListenerAddr;

/*
 * Server lifecycle
 */

/* Create a new tsnet server. Returns server handle ID (0 on error). */
uint64_t tsnet_server_new(
    const char* hostname,   /* Hostname for this node (can be NULL) */
    const char* authKey,    /* Auth key (can be NULL for interactive auth) */
    int ephemeral,          /* 1 for ephemeral node, 0 otherwise */
    const char* stateDir    /* State directory (can be NULL for default) */
);

/* Start the server (connects to tailnet). */
TSNetResult tsnet_server_start(uint64_t serverID);

/* Start and wait until connected. */
TSNetResult tsnet_server_up(uint64_t serverID);

/* Close and cleanup the server. */
TSNetResult tsnet_server_close(uint64_t serverID);

/*
 * Server information
 */

/* Get Tailscale IPs for this server. */
TSNetIPs tsnet_server_tailscale_ips(uint64_t serverID);

/* Get certificate domains. Returns array of strings. */
char** tsnet_server_cert_domains(uint64_t serverID, int* outLen);

/*
 * Listening
 */

/* Listen on the tailnet. Returns listener ID and result. */
uint64_t tsnet_server_listen(
    uint64_t serverID,
    const char* network,    /* "tcp", "tcp4", "tcp6" */
    const char* addr,       /* ":port" or "ip:port" */
    TSNetResult* result     /* Out parameter for result */
);

/* Listen with automatic TLS. Returns listener ID and result. */
uint64_t tsnet_server_listen_tls(
    uint64_t serverID,
    const char* network,
    const char* addr,
    TSNetResult* result
);

/* Listen via Tailscale Funnel (public internet). */
uint64_t tsnet_server_listen_funnel(
    uint64_t serverID,
    const char* network,
    const char* addr,
    int funnelOnly,         /* 1 to only accept Funnel connections */
    TSNetResult* result
);

/*
 * Dialing (outbound connections)
 */

/* Dial a connection over the tailnet. Returns connection ID and result. */
uint64_t tsnet_server_dial(
    uint64_t serverID,
    const char* network,    /* "tcp", "udp" */
    const char* address,    /* "host:port" */
    TSNetResult* result
);

/*
 * Listener operations
 */

/* Accept a connection. Returns connection ID and result. */
uint64_t tsnet_listener_accept(uint64_t listenerID, TSNetResult* result);

/* Get listener address. */
TSNetListenerAddr tsnet_listener_addr(uint64_t listenerID);

/* Close listener. */
TSNetResult tsnet_listener_close(uint64_t listenerID);

/*
 * Connection operations
 */

/* Read from connection. Returns bytes read and result. */
int tsnet_conn_read(
    uint64_t connID,
    char* buf,
    int bufLen,
    TSNetResult* result
);

/* Write to connection. Returns bytes written and result. */
int tsnet_conn_write(
    uint64_t connID,
    const char* buf,
    int bufLen,
    TSNetResult* result
);

/* Get remote address. Caller must free result. */
char* tsnet_conn_remote_addr(uint64_t connID);

/* Get local address. Caller must free result. */
char* tsnet_conn_local_addr(uint64_t connID);

/* Close connection. */
TSNetResult tsnet_conn_close(uint64_t connID);

/*
 * Memory management
 */

/* Free a string returned by tsnet functions. */
void tsnet_free_string(char* s);

/* Free an array of strings. */
void tsnet_free_string_array(char** arr, int len);

#ifdef __cplusplus
}
#endif

#endif /* TSNET_H */
