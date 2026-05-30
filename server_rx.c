/*
 * server_rx.c — PQC Multi-Client Receiver Terminal
 *
 * Connects to the running server via UNIX socket (IPC_RX_PATH).
 * Displays every inbound message in a styled block with:
 *   - Client ID, IP address, port, session ID
 *   - Timestamp
 *   - Decrypted plaintext
 *   - Per-packet metrics (decrypt time, inter-arrival, jitter, bytes)
 *     measured locally by the server — NOT from the wire packet.
 *
 * This terminal is read-only. To send, use server_tx.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "ipc.h"
#include "transport.h"   /* for DATA_CHUNK_MAX, now_hms() */

/* ── ANSI color helpers ──────────────────────────────────────────── */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_GRAY    "\033[0;37m"
#define CLR_WHITE   "\033[1;37m"
#define CLR_RED     "\033[1;31m"

/* ── Per-client display colors (cycles through palette) ──────────── */
static const char *CLIENT_COLORS[] = {
    "\033[1;36m",  /* cyan    */
    "\033[1;32m",  /* green   */
    "\033[1;33m",  /* yellow  */
    "\033[1;35m",  /* magenta */
    "\033[1;34m",  /* blue    */
    "\033[1;31m",  /* red     */
    "\033[1;37m",  /* white   */
    "\033[0;36m",  /* dark cyan */
};
#define NUM_COLORS  (int)(sizeof(CLIENT_COLORS)/sizeof(CLIENT_COLORS[0]))

static const char *client_color(int client_id)
{
    return CLIENT_COLORS[(client_id - 1) % NUM_COLORS];
}

/* ── Stop flag ───────────────────────────────────────────────────── */
static volatile int g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ── Tracked per-client state (for multi-line display) ───────────── */
#define MAX_TRACKED 32
typedef struct {
    int      client_id;
    char     ip_str[INET_ADDRSTRLEN];
    uint16_t port;
    uint32_t msg_count;
} tracked_client_t;

static tracked_client_t g_tracked[MAX_TRACKED];
static int g_tracked_count = 0;

static tracked_client_t *find_or_add_tracked(int cid, const char *ip, uint16_t port)
{
    for (int i = 0; i < g_tracked_count; i++)
        if (g_tracked[i].client_id == cid) return &g_tracked[i];
    if (g_tracked_count >= MAX_TRACKED) return NULL;
    tracked_client_t *t = &g_tracked[g_tracked_count++];
    t->client_id = cid;
    strncpy(t->ip_str, ip, sizeof(t->ip_str)-1);
    t->port      = port;
    t->msg_count = 0;
    return t;
}

static void remove_tracked(int cid)
{
    for (int i = 0; i < g_tracked_count; i++) {
        if (g_tracked[i].client_id == cid) {
            g_tracked[i] = g_tracked[--g_tracked_count];
            return;
        }
    }
}

/* ── Print the separator bar ─────────────────────────────────────── */

/* ── Render one received message block ───────────────────────────── */
static void render_rx_block(const ipc_rx_payload_t *info,
                             const uint8_t *msg, uint32_t msg_len,
                             const ipc_metrics_rx_t *metrics)
{
    char ts[20]; now_hms(ts, sizeof(ts));
    int  cid   = (int)info->client_id;
    const char *col = client_color(cid);

    tracked_client_t *t = find_or_add_tracked(cid, info->ip_str, info->port);
    if (t) t->msg_count++;
    uint32_t msg_seq = t ? t->msg_count : 0;

    printf("\n");

    /* ── Top border ─────────────────────────────────────────────── */
    printf("%s╔══ ▼ RECEIVED  CLIENT-%02d  [%s] %s\n",
           col, cid, ts, CLR_RESET);
    printf("%s║%s  %s%s:%u%s  │  SID: %016llx  │  Msg #%u\n",
           col, CLR_RESET,
           CLR_WHITE, info->ip_str, info->port, CLR_RESET,
           (unsigned long long)info->session_id,
           msg_seq);

    /* ── Message content ────────────────────────────────────────── */
    printf("%s╠══ MESSAGE %s\n", col, CLR_RESET);
    printf("%s║  %s%.*s%s\n", col, CLR_WHITE, (int)msg_len, (const char *)msg, CLR_RESET);

    /* ── Metrics block ──────────────────────────────────────────── */
    if (metrics) {
        printf("%s╠══ METRICS (local — not from wire) %s\n", col, CLR_RESET);
        printf("%s║%s  Decrypt    : %s%.1f µs%s  avg %.1f µs\n",
               col, CLR_RESET,
               CLR_GREEN, metrics->decrypt_us, CLR_RESET,
               metrics->avg_decrypt_us);

        if (metrics->pkt_seq > 1) {
            printf("%s║%s  Inter-arr  : %s%.3f ms%s  jitter %.3f ms  (RFC 3550 EWMA)\n",
                   col, CLR_RESET,
                   CLR_YELLOW, metrics->interarrival_ms, CLR_RESET,
                   metrics->jitter_ms);
        } else {
            printf("%s║%s  Inter-arr  : %sN/A (first packet)%s\n",
                   col, CLR_RESET, CLR_DIM, CLR_RESET);
        }

        printf("%s║%s  Bytes recv : %llu B  │  Pkt seq: #%u\n",
               col, CLR_RESET,
               (unsigned long long)metrics->bytes_recv,
               metrics->pkt_seq);
    }

    /* ── Bottom border ──────────────────────────────────────────── */
    printf("%s╚═══════════════════════════════════════════════════════╝%s\n\n",
           col, CLR_RESET);

    fflush(stdout);
}

/* ── Render a connect/disconnect event ───────────────────────────── */
static void render_connect_event(int cid, const char *ip, uint16_t port, int connected)
{
    char ts[20]; now_hms(ts, sizeof(ts));
    const char *col = client_color(cid);

    if (connected) {
        printf("\n%s┌── ✓ CLIENT-%02d CONNECTED%s  [%s]  %s:%u\n\n",
               col, cid, CLR_RESET, ts, ip, port);
    } else {
        printf("\n%s└── ✗ CLIENT-%02d DISCONNECTED%s  [%s]  %s:%u\n\n",
               col, cid, CLR_RESET, ts, ip, port);
        remove_tracked(cid);
    }
    fflush(stdout);
}

/* ── Connect to server IPC RX socket ────────────────────────────── */
static int connect_to_server(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IPC_RX_PATH, sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    return fd;
}

/* ════════════════════════════════════════════════════════════════════
 * main()
 * ════════════════════════════════════════════════════════════════════ */
int main(void)
{
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    /* ── Banner ──────────────────────────────────────────────────── */
    printf("\033[2J\033[H");  /* clear screen */
    printf("\033[1;36m");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║        PQC Secure Chat  ─  RECEIVER TERMINAL            ║\n");
    printf("║  Displays all inbound messages from all clients          ║\n");
    printf("║  Metrics: local timestamps only — zero wire overhead     ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf(CLR_RESET "\n");

    char ts[20]; now_hms(ts, sizeof(ts));
    printf("[%s] Connecting to server at %s ...\n", ts, IPC_RX_PATH);

    int fd = -1;
    while (!g_stop && fd < 0) {
        fd = connect_to_server();
        if (fd < 0) {
            printf("  Waiting for server...\r");
            fflush(stdout);
            sleep(1);
        }
    }
    if (fd < 0) return 0;

    now_hms(ts, sizeof(ts));
    printf("[%s] " CLR_GREEN "Connected to server" CLR_RESET
           " — waiting for messages...\n\n", ts);

    /* ── Receive and display loop ────────────────────────────────── */
    /*
     * We buffer the last received metrics so we can print them alongside
     * the message that follows (metrics arrive as a separate IPC frame).
     */
    ipc_metrics_rx_t last_metrics[MAX_TRACKED + 1];
    int              has_metrics[MAX_TRACKED + 1];
    memset(has_metrics, 0, sizeof(has_metrics));

    uint8_t buf[sizeof(ipc_rx_payload_t) + DATA_CHUNK_MAX + 64];

    while (!g_stop) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 500) <= 0) continue;

        ipc_hdr_t hdr;
        ssize_t n = ipc_recv_frame(fd, &hdr, buf, sizeof(buf));
        if (n < 0) {
            printf("\n[rx] Server disconnected. Reconnecting...\n");
            close(fd); fd = -1;
            while (!g_stop && fd < 0) {
                sleep(1); fd = connect_to_server();
            }
            if (fd < 0) break;
            printf("[rx] Reconnected.\n");
            continue;
        }

        switch (hdr.type) {

        case IPC_MSG_RX: {
            if (n < (ssize_t)sizeof(ipc_rx_payload_t)) break;
            ipc_rx_payload_t *info = (ipc_rx_payload_t *)buf;
            const uint8_t *msg = buf + sizeof(ipc_rx_payload_t);
            uint32_t msg_len   = info->msg_len;
            if (msg_len > DATA_CHUNK_MAX) msg_len = DATA_CHUNK_MAX;

            /* Look up buffered metrics for this client */
            ipc_metrics_rx_t *met = NULL;
            int cid = (int)info->client_id;
            if (cid >= 1 && cid <= MAX_TRACKED && has_metrics[cid]) {
                met = &last_metrics[cid];
            }
            render_rx_block(info, msg, msg_len, met);
            if (cid >= 1 && cid <= MAX_TRACKED)
                has_metrics[cid] = 0;   /* consumed */
            break;
        }

        case IPC_METRICS_RX: {
            if (n < (ssize_t)sizeof(ipc_metrics_rx_t)) break;
            ipc_metrics_rx_t *m = (ipc_metrics_rx_t *)buf;
            int cid = (int)m->client_id;
            if (cid >= 1 && cid <= MAX_TRACKED) {
                last_metrics[cid] = *m;
                has_metrics[cid]  = 1;
            }
            break;
        }

        case IPC_CLIENT_CONNECT: {
            if (n < (ssize_t)sizeof(ipc_client_entry_t)) break;
            ipc_client_entry_t *ce = (ipc_client_entry_t *)buf;
            render_connect_event((int)ce->client_id, ce->ip_str, ce->port, 1);
            break;
        }

        case IPC_CLIENT_DISCONNECT: {
            render_connect_event((int)hdr.client_id, "?", 0, 0);
            break;
        }

        default:
            break;
        }
    }

    if (fd >= 0) close(fd);
    printf("\n[server_rx] Exit.\n");
    return 0;
}
