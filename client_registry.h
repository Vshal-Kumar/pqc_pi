/*
 * client_registry.h — Thread-safe multi-client registry
 *
 * Tracks all active PQC sessions. Each entry holds the conn_t, metrics,
 * client IP string, assigned client ID (1..MAX_CLIENTS), and a per-client
 * mutex so the TX terminal can safely send to a specific client without
 * blocking others.
 *
 * Design rules:
 *   - All public functions are thread-safe (global mutex + per-slot mutex).
 *   - Slot IDs are stable for the lifetime of a session (never reused
 *     while the session is live). After disconnect, the slot is cleared
 *     and may be reused by the next client.
 *   - registry_get_snapshot() fills a caller-allocated array so the TX
 *     terminal can render the client list without holding the global lock.
 */

#ifndef CLIENT_REGISTRY_H
#define CLIENT_REGISTRY_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>
#include "transport.h"
#include "ipc.h"   /* MAX_CLIENTS, IPC path constants */
#define CLIENT_TAG_MAX  48   /* "192.168.1.42:54321" + nul */

/* ── Per-client slot ─────────────────────────────────────────────── */
typedef struct {
    /* Connection + crypto state */
    conn_t      conn;
    metrics_t   metrics;

    /* Identity */
    int         client_id;            /* 1-based, stable per session      */
    char        ip_str[INET_ADDRSTRLEN];
    uint16_t    port;
    char        tag[CLIENT_TAG_MAX];  /* "CLIENT-03  192.168.1.42:54321"   */
    uint64_t    session_id;

    /* Lifecycle */
    int         active;               /* 1 = session live                 */
    double      connect_time_ms;      /* now_ms() at session establish    */

    /* TX thread sends through this; RX thread reads on conn.sock */
    pthread_mutex_t tx_mutex;         /* serialize sends to this client   */

    /* Performance: last-send timestamp for external latency tracking */
    uint64_t    last_send_ns;         /* updated by registry_send()       */
    uint64_t    last_recv_ns;         /* updated by registry_mark_recv()  */

} client_slot_t;

/* ── Snapshot entry (lock-free copy for TX terminal UI) ──────────── */
typedef struct {
    int      client_id;
    char     tag[CLIENT_TAG_MAX];
    char     ip_str[INET_ADDRSTRLEN];
    uint16_t port;
    uint64_t session_id;
    double   hs_total_ms;
    uint64_t msg_count;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    double   jitter_ms;
} client_info_t;

/* ── Registry API ────────────────────────────────────────────────── */

/* Must be called once before any other function. */
void registry_init(void);

/*
 * Add a newly established session.
 * conn + metrics are copied in. Returns the assigned client_id (>0)
 * or -1 if the registry is full.
 */
int registry_add(const conn_t *conn, const metrics_t *metrics);

/*
 * Remove a session by client_id. Safe to call from any thread.
 */
void registry_remove(int client_id);

/*
 * Send a message to one client.
 * Acquires the per-slot TX mutex, calls data_send(), updates last_send_ns.
 * Returns 0 on success, -1 on error or if client_id not found.
 */
int registry_send(int client_id, const uint8_t *msg, uint32_t len);

/*
 * Broadcast a message to all active clients.
 * Sends to each in turn; a failure on one client does not abort others.
 * Returns the number of successful sends.
 */
int registry_broadcast(const uint8_t *msg, uint32_t len);

/*
 * Update per-slot recv timestamp (call from each client's RX thread).
 */
void registry_mark_recv(int client_id, uint64_t recv_ns);

/*
 * Snapshot: fills `out` (caller-allocated, capacity `max`) with info
 * about all currently active clients. Returns actual count written.
 * Safe to call from any thread with no locks held.
 */
int registry_get_snapshot(client_info_t *out, int max);

/*
 * Look up the conn_t pointer for a client_id.
 * Returns NULL if not found. Caller must NOT hold the global lock.
 * The pointer is valid while the slot is active — the RX thread for
 * that client keeps it alive.
 */
conn_t *registry_get_conn(int client_id);

/*
 * Return a pointer to a client's metrics (for RX thread to update).
 * Returns NULL if not found.
 */
metrics_t *registry_get_metrics(int client_id);

/*
 * Total number of currently active clients.
 */
int registry_count(void);

#endif /* CLIENT_REGISTRY_H */
