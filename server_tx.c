/*
 * server_tx.c — PQC Multi-Client Sender Terminal
 *
 * Connects to the running server via UNIX socket (IPC_TX_PATH).
 *
 * Features:
 *  - Live client list that updates automatically as clients connect/disconnect
 *  - Selection interface: choose a target client or broadcast before each send
 *  - Per-send metrics display (encrypt time, bytes sent, retransmissions)
 *  - Metrics measured locally via timestamps — not from the wire packet
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
#include <pthread.h>

#include "ipc.h"
#include "transport.h"   /* for DATA_CHUNK_MAX, now_hms() */

/* ── ANSI helpers ────────────────────────────────────────────────── */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_WHITE   "\033[1;37m"
#define CLR_RED     "\033[1;31m"
#define CLR_GRAY    "\033[0;37m"

static const char *CLIENT_COLORS[] = {
    "\033[1;36m", "\033[1;32m", "\033[1;33m", "\033[1;35m",
    "\033[1;34m", "\033[1;31m", "\033[1;37m", "\033[0;36m",
};
#define NUM_COLORS  (int)(sizeof(CLIENT_COLORS)/sizeof(CLIENT_COLORS[0]))
static const char *client_color(int cid) {
    return CLIENT_COLORS[(cid - 1) % NUM_COLORS];
}

/* ── Stop flag ───────────────────────────────────────────────────── */
static volatile int g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ── Shared client list (updated by background RX thread) ────────── */
static ipc_client_entry_t g_clients[MAX_CLIENTS];
static int                g_client_count = 0;
static pthread_mutex_t    g_clients_mu   = PTHREAD_MUTEX_INITIALIZER;

/* Notification pipe: background thread writes a byte when list changes */
static int g_notify_pipe[2] = {-1, -1};

static void clients_update(const uint8_t *buf, uint32_t len)
{
    if (len < sizeof(uint16_t)) return;
    uint16_t cnt;
    memcpy(&cnt, buf, sizeof(cnt));
    if (cnt > MAX_CLIENTS) cnt = MAX_CLIENTS;

    size_t expected = sizeof(uint16_t) + (size_t)cnt * sizeof(ipc_client_entry_t);
    if (len < expected) return;

    pthread_mutex_lock(&g_clients_mu);
    g_client_count = (int)cnt;
    memcpy(g_clients, buf + sizeof(uint16_t),
           (size_t)cnt * sizeof(ipc_client_entry_t));
    pthread_mutex_unlock(&g_clients_mu);

    /* Notify main thread */
    if (g_notify_pipe[1] >= 0) {
        char b = 'U';
        { ssize_t _w = write(g_notify_pipe[1], &b, 1); (void)_w; }
    }
}

/* ── Background IPC reader thread ────────────────────────────────── */
typedef struct { int fd; } bg_args_t;

static void *bg_rx_thread(void *arg)
{
    bg_args_t *a = (bg_args_t *)arg;
    int fd = a->fd;
    free(a);

    uint8_t buf[sizeof(uint16_t) + MAX_CLIENTS * sizeof(ipc_client_entry_t) + 256];

    while (!g_stop) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, 300) <= 0) continue;

        ipc_hdr_t hdr;
        ssize_t n = ipc_recv_frame(fd, &hdr, buf, sizeof(buf));
        if (n < 0) break;

        switch (hdr.type) {
        case IPC_CLIENT_LIST:
            clients_update(buf, (uint32_t)n);
            break;
        case IPC_CLIENT_CONNECT:
        case IPC_CLIENT_DISCONNECT:
            /* List update will follow */
            break;
        case IPC_METRICS_TX: {
            if (n >= (ssize_t)sizeof(ipc_metrics_tx_t)) {
                ipc_metrics_tx_t *m = (ipc_metrics_tx_t *)buf;
                /* Notify main thread about TX metrics update */
                if (g_notify_pipe[1] >= 0) {
                    /* Pack client_id and metrics into a mini frame via pipe */
                    /* We reuse the notification byte; main thread re-reads metrics
                     * from the last sent record stored below. */
                    char b = 'M';
                    { ssize_t _w = write(g_notify_pipe[1], &b, 1); (void)_w; }
                    /* Also print inline since we're in a bg thread */
                    /* (Safe to fprintf here; races with printf in main are visible
                     *  but only cosmetic — no data corruption.) */
                    printf("\n" CLR_GREEN "  ✓ Sent to CLIENT-%02d"
                           CLR_RESET "  │  encrypt %.1f µs  │  "
                           "msgs=%u  bytes=%llu B  retx=%u\n",
                           m->client_id,
                           m->avg_encrypt_us,
                           m->msg_count,
                           (unsigned long long)m->bytes_sent,
                           m->retransmissions);
                    fflush(stdout);
                }
            }
            break;
        }
        default: break;
        }
    }
    return NULL;
}

/* ── Render the client selection menu ────────────────────────────── */
static void render_client_menu(int current_target)
{
    printf("\033[2J\033[H");  /* clear screen */

    printf(CLR_CYAN
           "╔══════════════════════════════════════════════════════════╗\n"
           "║        PQC Secure Chat  ─  SENDER TERMINAL              ║\n"
           "╚══════════════════════════════════════════════════════════╝\n"
           CLR_RESET "\n");

    pthread_mutex_lock(&g_clients_mu);
    int cnt = g_client_count;

    if (cnt == 0) {
        printf(CLR_DIM "  No clients connected.\n" CLR_RESET);
        printf(CLR_DIM "  Run ./client on the remote device to connect.\n" CLR_RESET);
    } else {
        printf(CLR_BOLD "  Connected Clients:\n" CLR_RESET);
        printf(CLR_GRAY "  ─────────────────────────────────────────────────────────\n" CLR_RESET);
        printf("  %s%-4s  %-18s %-6s %-10s %-8s %-8s%s\n",
               CLR_BOLD, "ID", "IP:Port", "Msgs", "Sent (KB)",
               "Recv (KB)", "HS (ms)", CLR_RESET);
        printf(CLR_GRAY "  ─────────────────────────────────────────────────────────\n" CLR_RESET);

        for (int i = 0; i < cnt; i++) {
            ipc_client_entry_t *c = &g_clients[i];
            const char *col = client_color((int)c->client_id);
            char addr[32];
            snprintf(addr, sizeof(addr), "%s:%u", c->ip_str, c->port);

            int is_selected = ((int)c->client_id == current_target);
            printf("  %s[%2d]%s  %s%-18s%s  %-6u  %-9u  %-8u  %.2f %s%s\n",
                   col, c->client_id, CLR_RESET,
                   CLR_WHITE, addr, CLR_RESET,
                   c->msg_count,
                   c->bytes_sent_kb,
                   c->bytes_recv_kb,
                   c->hs_total_ms,
                   is_selected ? CLR_GREEN "◀ selected" CLR_RESET : "",
                   "");
        }
        printf(CLR_GRAY "  ─────────────────────────────────────────────────────────\n" CLR_RESET);
        printf("  %s[0]%s  BROADCAST to all %d client(s) %s\n",
               CLR_YELLOW, CLR_RESET, cnt,
               (current_target == 0) ? CLR_GREEN "◀ selected" CLR_RESET : "");
    }

    pthread_mutex_unlock(&g_clients_mu);

    printf("\n");
    if (cnt > 0) {
        printf(CLR_BOLD "  Select target:"
               CLR_RESET " Enter client ID [1-%d] or 0 for broadcast\n"
               "  (press Enter to keep current selection [%s%d%s])\n\n",
               cnt, CLR_YELLOW,
               current_target, CLR_RESET);
    }
}

/* ── Prompt for send ─────────────────────────────────────────────── */
static void print_send_prompt(int target)
{
    pthread_mutex_lock(&g_clients_mu);
    const char *label = "BROADCAST";
    char buf[32] = {0};
    if (target > 0) {
        for (int i = 0; i < g_client_count; i++) {
            if (g_clients[i].client_id == (uint16_t)target) {
                snprintf(buf, sizeof(buf), "CLIENT-%02d (%s)",
                         target, g_clients[i].ip_str);
                label = buf;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_clients_mu);

    const char *col = (target == 0) ? CLR_YELLOW : client_color(target);
    printf("%s[TX → %-28s]%s ", col, label, CLR_RESET);
    fflush(stdout);
}

/* ── Send a TX command via IPC ───────────────────────────────────── */
static int send_tx_cmd(int ipc_fd, uint16_t client_id,
                        const uint8_t *msg, uint32_t msg_len)
{
    uint8_t buf[sizeof(ipc_tx_cmd_t) + DATA_CHUNK_MAX];
    ipc_tx_cmd_t *cmd = (ipc_tx_cmd_t *)buf;
    cmd->client_id = client_id;
    cmd->msg_len   = msg_len;
    if (msg_len <= DATA_CHUNK_MAX)
        memcpy(buf + sizeof(ipc_tx_cmd_t), msg, msg_len);

    return ipc_send_frame(ipc_fd, IPC_MSG_TX_CMD, client_id,
                          buf, (uint32_t)(sizeof(ipc_tx_cmd_t) + msg_len));
}

/* ── Connect to server IPC TX socket ────────────────────────────── */
static int connect_to_server(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    struct sockaddr_un a = {0};
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, IPC_TX_PATH, sizeof(a.sun_path)-1);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
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

    if (pipe(g_notify_pipe) < 0) {
        perror("pipe"); return 1;
    }

    /* ── Banner ──────────────────────────────────────────────────── */
    printf("\033[2J\033[H");
    printf(CLR_MAGENTA
           "╔══════════════════════════════════════════════════════════╗\n"
           "║        PQC Secure Chat  ─  SENDER TERMINAL              ║\n"
           "╚══════════════════════════════════════════════════════════╝\n"
           CLR_RESET "\n");

    char ts[20]; now_hms(ts, sizeof(ts));
    printf("[%s] Connecting to server at %s ...\n", ts, IPC_TX_PATH);

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
    printf("[%s] " CLR_GREEN "Connected to server" CLR_RESET "\n\n", ts);

    /* Start background IPC reader */
    bg_args_t *bga = malloc(sizeof(bg_args_t));
    bga->fd = fd;
    pthread_t bg_tid;
    pthread_create(&bg_tid, NULL, bg_rx_thread, bga);
    pthread_detach(bg_tid);

    /* ── Main interaction loop ───────────────────────────────────── */
    int current_target = 0;  /* 0 = broadcast, >0 = specific client */
    int need_menu      = 1;

    char line[DATA_CHUNK_MAX];

    while (!g_stop) {
        if (need_menu) {
            render_client_menu(current_target);
            need_menu = 0;
        }

        /* ── Target selection ─────────────────────────────────── */
        /* Show selection prompt only if there are clients */
        pthread_mutex_lock(&g_clients_mu);
        int cnt = g_client_count;
        pthread_mutex_unlock(&g_clients_mu);

        if (cnt == 0) {
            /* No clients — wait for one to connect */
            printf(CLR_DIM "  Waiting for clients..." CLR_RESET "\r");
            fflush(stdout);

            /* Poll: stdin (won't arrive, but check for Ctrl-C) or notify pipe */
            struct pollfd pfds[2] = {
                { .fd = STDIN_FILENO,    .events = POLLIN },
                { .fd = g_notify_pipe[0], .events = POLLIN },
            };
            int r = poll(pfds, 2, 1000);
            if (r > 0 && (pfds[1].revents & POLLIN)) {
                char b; { ssize_t _r = read(g_notify_pipe[0], &b, 1); (void)_r; }
                need_menu = 1;
            }
            if (r > 0 && (pfds[0].revents & POLLIN)) {
                /* Read and discard — no target yet */
                if (!fgets(line, sizeof(line), stdin)) break;
            }
            continue;
        }

        /* Show selection prompt */
        printf(CLR_BOLD "  Target [0-%d, Enter=keep %d]: " CLR_RESET,
               cnt, current_target);
        fflush(stdout);

        /* Wait for input or notify-pipe update */
        struct pollfd pfds[2] = {
            { .fd = STDIN_FILENO,     .events = POLLIN },
            { .fd = g_notify_pipe[0], .events = POLLIN },
        };
        int r = poll(pfds, 2, 5000);

        if (r < 0) break;

        if (pfds[1].revents & POLLIN) {
            char b; { ssize_t _r = read(g_notify_pipe[0], &b, 1); (void)_r; }
            printf("\r\033[2K");  /* erase line */
            need_menu = 1;
            continue;
        }

        if (!(pfds[0].revents & POLLIN)) {
            /* Timeout: redraw menu to show updated stats */
            need_menu = 1;
            continue;
        }

        /* Read selection */
        if (!fgets(line, sizeof(line), stdin)) break;
        size_t slen = strlen(line);
        while (slen > 0 && (line[slen-1] == '\n' || line[slen-1] == '\r'))
            line[--slen] = '\0';

        if (slen > 0) {
            /* Parse numeric selection */
            int sel = atoi(line);
            pthread_mutex_lock(&g_clients_mu);
            int valid = (sel == 0);
            if (!valid) {
                for (int i = 0; i < g_client_count; i++) {
                    if (g_clients[i].client_id == (uint16_t)sel) {
                        valid = 1; break;
                    }
                }
            }
            pthread_mutex_unlock(&g_clients_mu);

            if (valid) {
                current_target = sel;
            } else {
                printf(CLR_RED "  Invalid selection '%s'\n" CLR_RESET, line);
                need_menu = 1;
                continue;
            }
        }
        /* If empty input: keep current_target */

        /* ── Message input ──────────────────────────────────────── */
        print_send_prompt(current_target);

        /* Poll again for message or notification */
        r = poll(pfds, 2, -1);
        if (r < 0) break;

        if (pfds[1].revents & POLLIN) {
            char b; { ssize_t _r = read(g_notify_pipe[0], &b, 1); (void)_r; }
            printf("\r\033[2K");
            need_menu = 1;
            continue;
        }

        if (!fgets(line, sizeof(line), stdin)) break;
        slen = strlen(line);
        if (slen == 0) { need_menu = 1; continue; }

        /* Keep newline for the receiver display (strip trailing \r) */
        while (slen > 0 && line[slen-1] == '\r') line[--slen] = '\0';
        if (slen == 0) { need_menu = 1; continue; }

        /* Send */
        if (send_tx_cmd(fd, (uint16_t)current_target,
                        (const uint8_t *)line, (uint32_t)slen) != 0) {
            printf(CLR_RED "  [tx] IPC send failed — server may have disconnected\n"
                   CLR_RESET);
        }

        /* Redraw menu after send to show updated counters */
        need_menu = 1;
    }

    close(fd);
    close(g_notify_pipe[0]);
    close(g_notify_pipe[1]);
    printf("\n[server_tx] Exit.\n");
    return 0;
}
