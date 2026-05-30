/*
 * server.c — PQC Multi-Client Chat Server
 *
 * Project: Performance Evaluation of SIMD-Accelerated Post-Quantum
 *          Cryptography on Embedded ARM Platforms
 *
 * Architecture:
 *
 *  Main thread       : UDP accept loop on port 9877
 *                      - Peeks at each datagram
 *                      - Routes PKT_DATA to the correct registered client
 *                      - Spawns session_thread for new CLIENT_HELLO peers
 *  session_thread    : PQC 4-way handshake using the SHARED listen socket
 *                      (the client only knows port 9877 — we never change ports)
 *  client_rx_thread  : continuous RX loop per established client,
 *                      also reads from the shared socket (peer-filtered)
 *  ipc_rx_thread     : holds UNIX socket to server_rx terminal
 *  ipc_tx_thread     : holds UNIX socket to server_tx terminal, dispatches sends
 *
 * Key design decisions:
 *  - ALL traffic uses a SINGLE UDP socket on port 9877.
 *    The client never learns a different port — it sends everything to 9877.
 *  - Per-client demux is done by comparing recvfrom() peer address.
 *  - A per-client recv pipe (socketpair) lets the main dispatch thread
 *    hand pre-read datagrams to the correct client_rx_thread without
 *    races. The session_thread and client_rx_thread read from their pipe;
 *    the main thread writes to it after filtering by peer addr.
 *
 * Packet wire format (PKT_DATA — simplified vs original):
 *   NONCE(12) | TAG(16) | CIPHERTEXT(n)   — no net_metrics_t prefix
 *
 * 4-Way PQC Handshake (unchanged):
 *  Phase 1  <- CLIENT_HELLO : client_KEM_PK || client_DSA_PK
 *  Phase 2  -> SERVER_HELLO : server_KEM_PK || server_DSA_PK || KEM_CT || SID
 *  Phase 3  <- CLIENT_AUTH  : DSA_sig(SID || server_DSA_PK || SS)
 *  Phase 4  -> session active
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/rand.h>

#include "transport.h"
#include "crypto/aead.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"
#include "client_registry.h"
#include "ipc.h"

#define AUTH_CTX_LEN  (SESSION_ID_BYTES + DSA_PK_BYTES + KEM_SS_BYTES)

/* ── Max raw datagram we ever dispatch through a pipe ────────────── */
#define PIPE_PKT_MAX  (PKT_HDR_BYTES + KEM_PK_BYTES + DSA_PK_BYTES + \
                       KEM_CT_BYTES + SESSION_ID_BYTES + DSA_SIG_BYTES + \
                       12 + 16 + DATA_CHUNK_MAX + 64)

/* ── Long-term server identity ───────────────────────────────────── */
static uint8_t g_srv_dsa_pk[DSA_PK_BYTES];
static uint8_t g_srv_dsa_sk[DSA_SK_BYTES];
static double  g_dsa_keygen_ms = 0.0;

/* ── Pre-generated ephemeral KEM cache ───────────────────────────── */
static uint8_t         g_srv_kem_pk[KEM_PK_BYTES];
static uint8_t         g_srv_kem_sk[KEM_SK_BYTES];
static double          g_kem_keygen_ms  = 0.0;
static int             g_kem_cache_valid = 0;
static pthread_mutex_t g_kem_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_kem_ready = PTHREAD_COND_INITIALIZER;

/* ── Global stop ─────────────────────────────────────────────────── */
static volatile int    g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ── Shared listen socket (all clients use port 9877) ────────────── */
static int g_listen_sock = -1;
/* Mutex for sends on the shared socket (multiple threads send ACKs/data) */
static pthread_mutex_t g_sock_send_mu = PTHREAD_MUTEX_INITIALIZER;

/* ── IPC connections ─────────────────────────────────────────────── */
static int             g_ipc_rx_fd = -1;
static int             g_ipc_tx_fd = -1;
static pthread_mutex_t g_ipc_rx_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_ipc_tx_mu = PTHREAD_MUTEX_INITIALIZER;

/* ════════════════════════════════════════════════════════════════════
 * Per-client dispatch pipe
 *
 * The main accept/dispatch loop reads every datagram from the shared
 * socket and writes it into the matching client's pipe.
 * Each session_thread / client_rx_thread reads from its own pipe end.
 *
 * Wire format inside the pipe (length-prefixed raw datagram):
 *   uint16_t total_len | uint8_t data[total_len]
 * ════════════════════════════════════════════════════════════════════ */

#define DISPATCH_PIPE_MAX  MAX_CLIENTS

typedef struct {
    int      write_fd;   /* main thread writes here */
    int      read_fd;    /* session/rx thread reads here */
    uint32_t ip;         /* network byte order */
    uint16_t port;       /* network byte order */
    int      used;
    pthread_mutex_t mu;  /* protects write_fd */
} dispatch_pipe_t;

static dispatch_pipe_t g_pipes[DISPATCH_PIPE_MAX];
static pthread_mutex_t g_pipes_mu = PTHREAD_MUTEX_INITIALIZER;

static int dispatch_alloc(uint32_t ip, uint16_t port)
{
    pthread_mutex_lock(&g_pipes_mu);
    for (int i = 0; i < DISPATCH_PIPE_MAX; i++) {
        if (!g_pipes[i].used) {
            int fds[2];
            if (pipe(fds) < 0) {
                pthread_mutex_unlock(&g_pipes_mu);
                return -1;
            }
            g_pipes[i].read_fd  = fds[0];
            g_pipes[i].write_fd = fds[1];
            g_pipes[i].ip       = ip;
            g_pipes[i].port     = port;
            g_pipes[i].used     = 1;
            pthread_mutex_unlock(&g_pipes_mu);
            return i;
        }
    }
    pthread_mutex_unlock(&g_pipes_mu);
    return -1;
}

static void dispatch_free(int idx)
{
    pthread_mutex_lock(&g_pipes_mu);
    if (g_pipes[idx].used) {
        close(g_pipes[idx].read_fd);
        close(g_pipes[idx].write_fd);
        g_pipes[idx].used = 0;
    }
    pthread_mutex_unlock(&g_pipes_mu);
}

/* Write a raw datagram into a pipe (length-prefixed). */
static void dispatch_write(int write_fd, const uint8_t *pkt, uint16_t len)
{
    uint8_t lenbuf[2];
    lenbuf[0] = (uint8_t)(len >> 8);
    lenbuf[1] = (uint8_t)(len & 0xFF);
    /*
     * Best-effort: drop silently if the pipe is full.
     * The client's retransmit timer will resend and the next attempt
     * will succeed once the reader drains the pipe.
     * We read the return values to satisfy -Wunused-result.
     */
    ssize_t w1 = write(write_fd, lenbuf, 2);
    ssize_t w2 = write(write_fd, pkt,    len);
    if (w1 != 2 || w2 != (ssize_t)len)
        fprintf(stderr, "[dispatch] pipe write short — packet dropped\n");
}

/* Read one length-prefixed datagram from a pipe. Returns payload bytes or -1. */
static ssize_t dispatch_read(int read_fd, uint8_t *out, size_t max,
                              int timeout_ms)
{
    struct pollfd pfd = { .fd = read_fd, .events = POLLIN };
    if (poll(&pfd, 1, timeout_ms) <= 0) return -1;

    uint8_t lenbuf[2];
    if (read(read_fd, lenbuf, 2) != 2) return -1;
    uint16_t len = ((uint16_t)lenbuf[0] << 8) | lenbuf[1];
    if (len == 0 || len > max) return -1;

    ssize_t got = 0;
    while ((size_t)got < len) {
        ssize_t r = read(read_fd, out + got, len - (uint16_t)got);
        if (r <= 0) return -1;
        got += r;
    }
    return got;
}

/* ════════════════════════════════════════════════════════════════════
 * Keygen helpers
 * ════════════════════════════════════════════════════════════════════ */

static void *dsa_keygen_thread(void *arg)
{
    (void)arg;
    double t0 = now_ms();
    if (dsa_keypair(g_srv_dsa_pk, g_srv_dsa_sk) != 0) {
        fprintf(stderr, "[server] DSA keygen failed\n"); exit(1);
    }
    g_dsa_keygen_ms = now_ms() - t0;
    return NULL;
}

static void *kem_keygen_thread(void *arg)
{
    (void)arg;
    uint8_t pk[KEM_PK_BYTES], sk[KEM_SK_BYTES];
    double t0 = now_ms();
    if (kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "[server] KEM keygen failed\n"); exit(1);
    }
    double ms = now_ms() - t0;

    pthread_mutex_lock(&g_kem_mutex);
    memcpy(g_srv_kem_pk, pk, KEM_PK_BYTES);
    memcpy(g_srv_kem_sk, sk, KEM_SK_BYTES);
    g_kem_keygen_ms   = ms;
    g_kem_cache_valid = 1;
    pthread_cond_signal(&g_kem_ready);
    pthread_mutex_unlock(&g_kem_mutex);
    explicit_bzero(sk, sizeof(sk));
    return NULL;
}

static void kem_cache_consume(uint8_t pk[KEM_PK_BYTES], uint8_t sk[KEM_SK_BYTES],
                               double *ms_out)
{
    pthread_mutex_lock(&g_kem_mutex);
    while (!g_kem_cache_valid)
        pthread_cond_wait(&g_kem_ready, &g_kem_mutex);
    memcpy(pk, g_srv_kem_pk, KEM_PK_BYTES);
    memcpy(sk, g_srv_kem_sk, KEM_SK_BYTES);
    *ms_out           = g_kem_keygen_ms;
    g_kem_cache_valid = 0;
    pthread_mutex_unlock(&g_kem_mutex);
}

static void kem_cache_refresh_async(void)
{
    pthread_t tid;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &a, kem_keygen_thread, NULL);
    pthread_attr_destroy(&a);
}

/* ════════════════════════════════════════════════════════════════════
 * Shared-socket send (thread-safe sendto wrapper)
 * ════════════════════════════════════════════════════════════════════ */

static ssize_t shared_sendto(const void *buf, size_t len,
                              const struct sockaddr_in *peer)
{
    pthread_mutex_lock(&g_sock_send_mu);
    ssize_t n = sendto(g_listen_sock, buf, len, 0,
                       (const struct sockaddr *)peer, sizeof(*peer));
    pthread_mutex_unlock(&g_sock_send_mu);
    return n;
}

/* ════════════════════════════════════════════════════════════════════
 * Pipe-backed conn_t helpers
 *
 * The session and RX threads use a conn_t whose "socket" is actually
 * the read end of their dispatch pipe.  We override pkt_send to use
 * shared_sendto and pkt_recv to read from the pipe.
 * ════════════════════════════════════════════════════════════════════ */

/*
 * pkt_send_to_peer: send a header+payload directly to a known peer via
 * the shared socket.  Used during handshake and data TX.
 */
static ssize_t pkt_send_to_peer(conn_t *c, uint8_t type,
                                 const uint8_t *payload, uint16_t payload_len)
{
    uint8_t wire[PKT_HDR_BYTES + PIPE_PKT_MAX];
    pkt_hdr_t hdr;
    hdr.seq  = htonl(c->tx_seq++);
    hdr.type = type;
    hdr.len  = htons(payload_len);
    memcpy(wire, &hdr, PKT_HDR_BYTES);
    if (payload_len > 0)
        memcpy(wire + PKT_HDR_BYTES, payload, payload_len);
    return shared_sendto(wire, PKT_HDR_BYTES + payload_len, &c->peer);
}

/*
 * send_ack_to_peer: send ACK for ack_seq to the peer via shared socket.
 */
static void send_ack_to_peer(conn_t *c, uint32_t ack_seq)
{
    uint8_t pl[4];
    pl[0] = (ack_seq >> 24) & 0xFF;
    pl[1] = (ack_seq >> 16) & 0xFF;
    pl[2] = (ack_seq >>  8) & 0xFF;
    pl[3] =  ack_seq        & 0xFF;
    pkt_send_to_peer(c, PKT_ACK, pl, 4);
}

/*
 * pkt_recv_from_pipe: read one dispatched datagram from the pipe, parse header.
 * timeout_ms: -1 = block forever, 0 = nonblocking, >0 = timeout ms.
 */
static ssize_t pkt_recv_from_pipe(int pipe_fd, pkt_hdr_t *hdr,
                                   uint8_t *payload_out, size_t payload_max,
                                   int timeout_ms)
{
    uint8_t raw[PKT_HDR_BYTES + PIPE_PKT_MAX];
    ssize_t n = dispatch_read(pipe_fd, raw, sizeof(raw), timeout_ms);
    if (n < (ssize_t)PKT_HDR_BYTES) return -1;

    memcpy(hdr, raw, PKT_HDR_BYTES);
    hdr->seq = ntohl(hdr->seq);
    hdr->len = ntohs(hdr->len);

    ssize_t payload_len = n - PKT_HDR_BYTES;
    if (payload_len < 0) payload_len = 0;
    if ((size_t)payload_len > payload_max) payload_len = (ssize_t)payload_max;
    if (payload_len > 0 && payload_out)
        memcpy(payload_out, raw + PKT_HDR_BYTES, (size_t)payload_len);
    return payload_len;
}

/*
 * recv_type_pipe: wait for a specific packet type from the pipe.
 * Sends ACK for matching packet. Drops non-matching non-ACK packets.
 */
static ssize_t recv_type_pipe(conn_t *c, int pipe_fd, uint8_t want,
                               uint8_t *buf, size_t max)
{
    pkt_hdr_t hdr;
    for (;;) {
        ssize_t n = pkt_recv_from_pipe(pipe_fd, &hdr, buf, max, -1);
        if (n < 0) return -1;
        if (hdr.type == want) {
            send_ack_to_peer(c, hdr.seq);
            return n;
        }
        /* Drop unexpected packets (they may be retransmits of earlier phases) */
    }
}

/*
 * pkt_send_reliable_to_peer: send with ACK, reading ACKs from pipe.
 */
static int pkt_send_reliable_pipe(conn_t *c, int pipe_fd, uint8_t type,
                                   const uint8_t *payload, uint16_t payload_len)
{
    uint32_t our_seq = c->tx_seq;

    for (int attempt = 0; attempt < RETX_MAX; attempt++) {
        if (attempt > 0) c->tx_seq = our_seq;

        pkt_send_to_peer(c, type, payload, payload_len);

        pkt_hdr_t hdr;
        uint8_t   ack_buf[64];
        int timeout_ms = ACK_TIMEOUT_US / 1000;

        ssize_t n = pkt_recv_from_pipe(pipe_fd, &hdr, ack_buf,
                                        sizeof(ack_buf), timeout_ms);
        if (n >= 4 && hdr.type == PKT_ACK) {
            uint32_t acked = ((uint32_t)ack_buf[0] << 24)
                           | ((uint32_t)ack_buf[1] << 16)
                           | ((uint32_t)ack_buf[2] <<  8)
                           |  (uint32_t)ack_buf[3];
            if (acked == our_seq) return 0;
        }
    }
    return -1;
}

/* ════════════════════════════════════════════════════════════════════
 * IPC helpers
 * ════════════════════════════════════════════════════════════════════ */

static void ipc_push_rx_msg(int cid, const char *ip, uint16_t port,
                             uint64_t sid,
                             const uint8_t *msg, uint32_t msg_len)
{
    pthread_mutex_lock(&g_ipc_rx_mu);
    if (g_ipc_rx_fd < 0) { pthread_mutex_unlock(&g_ipc_rx_mu); return; }

    uint8_t buf[sizeof(ipc_rx_payload_t) + DATA_CHUNK_MAX];
    ipc_rx_payload_t *p = (ipc_rx_payload_t *)buf;
    p->client_id  = (uint16_t)cid;
    strncpy(p->ip_str, ip, sizeof(p->ip_str) - 1);
    p->ip_str[sizeof(p->ip_str)-1] = '\0';
    p->port        = port;
    p->session_id  = sid;
    p->msg_len     = msg_len;
    if (msg_len <= DATA_CHUNK_MAX)
        memcpy(buf + sizeof(ipc_rx_payload_t), msg, msg_len);

    ipc_send_frame(g_ipc_rx_fd, IPC_MSG_RX, (uint16_t)cid,
                   buf, (uint32_t)(sizeof(ipc_rx_payload_t) + msg_len));
    pthread_mutex_unlock(&g_ipc_rx_mu);
}

static void ipc_push_rx_metrics(int cid, float dec_us, float ia_ms,
                                 float jitter, float avg_dec,
                                 uint64_t bytes_recv, uint32_t seq)
{
    pthread_mutex_lock(&g_ipc_rx_mu);
    if (g_ipc_rx_fd < 0) { pthread_mutex_unlock(&g_ipc_rx_mu); return; }

    ipc_metrics_rx_t m = {0};
    m.client_id       = (uint16_t)cid;
    m.decrypt_us      = dec_us;
    m.interarrival_ms = ia_ms;
    m.jitter_ms       = jitter;
    m.avg_decrypt_us  = avg_dec;
    m.bytes_recv      = bytes_recv;
    m.pkt_seq         = seq;
    ipc_send_frame(g_ipc_rx_fd, IPC_METRICS_RX, (uint16_t)cid,
                   &m, sizeof(m));
    pthread_mutex_unlock(&g_ipc_rx_mu);
}

static void ipc_push_client_list(void)
{
    pthread_mutex_lock(&g_ipc_tx_mu);
    if (g_ipc_tx_fd < 0) { pthread_mutex_unlock(&g_ipc_tx_mu); return; }

    client_info_t infos[MAX_CLIENTS];
    int cnt = registry_get_snapshot(infos, MAX_CLIENTS);

    size_t sz = sizeof(uint16_t) + (size_t)cnt * sizeof(ipc_client_entry_t);
    uint8_t *buf = malloc(sz);
    if (!buf) { pthread_mutex_unlock(&g_ipc_tx_mu); return; }

    uint16_t c16 = (uint16_t)cnt;
    memcpy(buf, &c16, sizeof(c16));
    ipc_client_entry_t *e = (ipc_client_entry_t *)(buf + sizeof(uint16_t));
    for (int i = 0; i < cnt; i++) {
        e[i].client_id     = (uint16_t)infos[i].client_id;
        memcpy(e[i].ip_str, infos[i].ip_str, sizeof(e[i].ip_str));
        e[i].port          = infos[i].port;
        e[i].session_id    = infos[i].session_id;
        e[i].hs_total_ms   = (float)infos[i].hs_total_ms;
        e[i].msg_count     = (uint32_t)infos[i].msg_count;
        e[i].bytes_sent_kb = (uint32_t)(infos[i].bytes_sent / 1024);
        e[i].bytes_recv_kb = (uint32_t)(infos[i].bytes_recv / 1024);
    }

    ipc_send_frame(g_ipc_tx_fd, IPC_CLIENT_LIST, 0, buf, (uint32_t)sz);
    free(buf);
    pthread_mutex_unlock(&g_ipc_tx_mu);
}

/* ════════════════════════════════════════════════════════════════════
 * Per-client RX thread
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    int      client_id;
    int      pipe_fd;     /* read end of dispatch pipe */
    volatile int stop;
} client_rx_args_t;

static void *client_rx_thread(void *arg)
{
    client_rx_args_t *a = (client_rx_args_t *)arg;
    int cid     = a->client_id;
    int pipe_fd = a->pipe_fd;

    conn_t    *c = registry_get_conn(cid);
    metrics_t *m = registry_get_metrics(cid);
    if (!c || !m) { free(a); return NULL; }

    char     ip_str[INET_ADDRSTRLEN] = "?";
    uint16_t port = 0;
    uint64_t sid  = c->session_id;
    {
        client_info_t all[MAX_CLIENTS];
        int cnt = registry_get_snapshot(all, MAX_CLIENTS);
        for (int i = 0; i < cnt; i++) {
            if (all[i].client_id == cid) {
                strncpy(ip_str, all[i].ip_str, sizeof(ip_str)-1);
                port = all[i].port;
                break;
            }
        }
    }

    char ts[16];
    now_hms(ts, sizeof(ts));
    printf("[%s] RX thread live: CLIENT-%02d (%s:%u)\n",
           ts, cid, ip_str, port);

    uint8_t pt[DATA_CHUNK_MAX + 16];

    while (!a->stop && !g_stop) {
        pkt_hdr_t hdr;
        uint8_t raw[12 + 16 + DATA_CHUNK_MAX + 64];

        ssize_t n = pkt_recv_from_pipe(pipe_fd, &hdr, raw, sizeof(raw),
                                        RX_POLL_TIMEOUT_US / 1000);
        if (n < 0) continue;
        if (hdr.type != PKT_DATA) continue;
        if (n < 28) continue;

        uint64_t recv_ns = now_ns();

        const uint8_t *nonce = raw;
        const uint8_t *tag   = raw + 12;
        const uint8_t *ct    = raw + 28;
        int ct_len = (int)n - 28;
        if (ct_len <= 0) continue;

        double dec_t0 = now_ms();
        int pt_len = aead_decrypt(ct, ct_len, c->session_key, nonce, tag, pt);
        double dec_us = (now_ms() - dec_t0) * 1000.0;

        if (pt_len <= 0) {
            fprintf(stderr, "[CLIENT-%02d] AEAD auth failure\n", cid);
            continue;
        }

        if (pt_len < (int)sizeof(pt)) pt[pt_len] = '\0';
        while (pt_len > 0 &&
               (pt[pt_len-1] == '\n' || pt[pt_len-1] == '\r'))
            pt[--pt_len] = '\0';

        m->bytes_recv       += (uint64_t)(PKT_HDR_BYTES + n);
        m->total_decrypt_us += dec_us;
        m->decrypt_count++;
        metrics_update_rtt(m, recv_ns);
        registry_mark_recv(cid, recv_ns);

        float avg_dec = (m->decrypt_count > 0)
            ? (float)(m->total_decrypt_us / (double)m->decrypt_count) : 0.f;

        ipc_push_rx_msg(cid, ip_str, port, sid, pt, (uint32_t)pt_len);
        ipc_push_rx_metrics(cid, (float)dec_us,
                            (float)m->msg_last_rtt_ms,
                            (float)m->jitter_ms,
                            avg_dec, m->bytes_recv,
                            (uint32_t)m->decrypt_count);

        now_hms(ts, sizeof(ts));
        printf("[%s] \033[1;36m[CLIENT-%02d %s:%u]\033[0m %s\n",
               ts, cid, ip_str, port, (char *)pt);
        fflush(stdout);
    }

    now_hms(ts, sizeof(ts));
    printf("[%s] CLIENT-%02d session ended (%s:%u)\n",
           ts, cid, ip_str, port);
    metrics_print(m);

    registry_remove(cid);
    ipc_push_client_list();

    pthread_mutex_lock(&g_ipc_tx_mu);
    if (g_ipc_tx_fd >= 0)
        ipc_send_frame(g_ipc_tx_fd, IPC_CLIENT_DISCONNECT,
                       (uint16_t)cid, NULL, 0);
    pthread_mutex_unlock(&g_ipc_tx_mu);

    free(a);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════
 * Session thread — PQC handshake
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    struct sockaddr_in peer;
    int                pipe_idx;   /* index into g_pipes[] */
} session_args_t;

static void *session_thread(void *arg)
{
    session_args_t *sa   = (session_args_t *)arg;
    struct sockaddr_in peer = sa->peer;
    int    pipe_idx      = sa->pipe_idx;
    free(sa);

    int pipe_fd = g_pipes[pipe_idx].read_fd;

    /* Build a conn_t pointing at this peer.
     * sock field is not used for recv (we use the pipe) but is needed
     * for the tx_seq counter and peer address. */
    conn_t c = {0};
    c.sock     = g_listen_sock;   /* only used indirectly via pkt_send_to_peer */
    c.peer     = peer;
    c.peer_len = sizeof(peer);
    c.tx_seq   = 1;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer.sin_addr, ip_str, sizeof(ip_str));
    uint16_t peer_port = ntohs(peer.sin_port);

    /* Consume pre-cached KEM keypair */
    uint8_t srv_kem_pk[KEM_PK_BYTES];
    uint8_t srv_kem_sk[KEM_SK_BYTES];
    double  kem_ms = 0.0;
    kem_cache_consume(srv_kem_pk, srv_kem_sk, &kem_ms);
    kem_cache_refresh_async();

    metrics_t metrics = {0};
    metrics.msg_min_rtt_ms   = 1e15;
    metrics.hs_kem_keygen_ms = kem_ms;
    metrics.hs_dsa_keygen_ms = g_dsa_keygen_ms;

    char ts[16]; now_hms(ts, sizeof(ts));
    printf("[%s] Handshake: %s:%u\n", ts, ip_str, peer_port);

    /* ── Phase 1: CLIENT_HELLO ─────────────────────────────────── */
    uint8_t cli_kem_pk[KEM_PK_BYTES], cli_dsa_pk[DSA_PK_BYTES];
    {
        uint8_t buf[KEM_PK_BYTES + DSA_PK_BYTES + 32];
        ssize_t n = recv_type_pipe(&c, pipe_fd, PKT_CLIENT_HELLO,
                                   buf, sizeof(buf));
        if (n < (ssize_t)(KEM_PK_BYTES + DSA_PK_BYTES)) {
            fprintf(stderr, "[server] CLIENT_HELLO too short from %s\n",
                    ip_str);
            goto fail;
        }
        memcpy(cli_kem_pk, buf,                KEM_PK_BYTES);
        memcpy(cli_dsa_pk, buf + KEM_PK_BYTES, DSA_PK_BYTES);
    }

    /* ── Phase 2: KEM encaps → SERVER_HELLO ─────────────────────── */
    uint8_t kem_ct[KEM_CT_BYTES];
    uint8_t shared_secret[KEM_SS_BYTES];
    uint8_t session_id[SESSION_ID_BYTES];
    {
        double t0 = now_ms();
        if (kem_enc(kem_ct, shared_secret, cli_kem_pk) != 0) goto fail;
        metrics.hs_encap_ms = now_ms() - t0;

        if (RAND_bytes(session_id, SESSION_ID_BYTES) != 1) {
            uint64_t t = now_ns();
            memcpy(session_id, &t, SESSION_ID_BYTES);
        }

        uint8_t sh[KEM_PK_BYTES + DSA_PK_BYTES + KEM_CT_BYTES + SESSION_ID_BYTES];
        size_t off = 0;
        memcpy(sh + off, srv_kem_pk,   KEM_PK_BYTES);   off += KEM_PK_BYTES;
        memcpy(sh + off, g_srv_dsa_pk, DSA_PK_BYTES);   off += DSA_PK_BYTES;
        memcpy(sh + off, kem_ct,       KEM_CT_BYTES);   off += KEM_CT_BYTES;
        memcpy(sh + off, session_id,   SESSION_ID_BYTES);

        if (pkt_send_reliable_pipe(&c, pipe_fd, PKT_SERVER_HELLO,
                                    sh, (uint16_t)sizeof(sh)) != 0) {
            fprintf(stderr, "[server] SERVER_HELLO unacknowledged by %s\n",
                    ip_str);
            goto fail;
        }
    }

    /* ── Phase 3: CLIENT_AUTH ────────────────────────────────────── */
    {
        uint8_t sig_buf[DSA_SIG_BYTES + 32];
        ssize_t sig_len = recv_type_pipe(&c, pipe_fd, PKT_CLIENT_AUTH,
                                          sig_buf, sizeof(sig_buf));
        if (sig_len <= 0) goto fail;

        uint8_t auth_ctx[AUTH_CTX_LEN];
        size_t off = 0;
        memcpy(auth_ctx + off, session_id,    SESSION_ID_BYTES); off += SESSION_ID_BYTES;
        memcpy(auth_ctx + off, g_srv_dsa_pk,  DSA_PK_BYTES);    off += DSA_PK_BYTES;
        memcpy(auth_ctx + off, shared_secret, KEM_SS_BYTES);

        double t0 = now_ms();
        int vrc = dsa_verify(sig_buf, (size_t)sig_len,
                             auth_ctx, AUTH_CTX_LEN, cli_dsa_pk);
        metrics.hs_verify_ms = now_ms() - t0;
        explicit_bzero(auth_ctx, sizeof(auth_ctx));

        if (vrc != 0) {
            fprintf(stderr, "[server] Signature INVALID from %s\n", ip_str);
            explicit_bzero(shared_secret, sizeof(shared_secret));
            goto fail;
        }
    }

    /* ── Phase 4: session active ─────────────────────────────────── */
    memcpy(c.session_key, shared_secret, KEM_SS_BYTES);
    c.established = 1;
    explicit_bzero(srv_kem_sk, sizeof(srv_kem_sk));
    explicit_bzero(shared_secret, sizeof(shared_secret));

    metrics.hs_total_ms = metrics.hs_encap_ms + metrics.hs_verify_ms;
    {
        uint64_t sid64 = 0;
        for (int i = 0; i < SESSION_ID_BYTES; i++)
            sid64 = (sid64 << 8) | session_id[i];
        c.session_id = sid64;
    }
    metrics.session_start_ns = now_ns();

    printf("\n  ┌── PQC Handshake [%s:%u] ─────────────────────┐\n",
           ip_str, peer_port);
    printf("  │  KEM-keygen : %7.3f ms  DSA-keygen : %7.3f ms  │\n",
           metrics.hs_kem_keygen_ms, metrics.hs_dsa_keygen_ms);
    printf("  │  KEM-encaps : %7.3f ms  DSA-verify : %7.3f ms  │\n",
           metrics.hs_encap_ms, metrics.hs_verify_ms);
    printf("  │  Total      : %7.3f ms  %s                      │\n",
           metrics.hs_total_ms,
           metrics.hs_total_ms <= 1.0 ? "\033[32m✓ <1ms\033[0m"
                                      : "\033[33m⚠ >1ms\033[0m");
    printf("  └───────────────────────────────────────────────────┘\n\n");

    /* Register client */
    int cid = registry_add(&c, &metrics);
    if (cid < 0) {
        fprintf(stderr, "[server] Registry full — dropping %s\n", ip_str);
        goto fail;
    }

    now_hms(ts, sizeof(ts));
    printf("[%s] \033[1;32m✓ CLIENT-%02d\033[0m  %s:%u  "
           "SID=%016llx  HS=%.3fms  Active=%d\n\n",
           ts, cid, ip_str, peer_port,
           (unsigned long long)c.session_id,
           metrics.hs_total_ms,
           registry_count());

    /* Notify TX terminal */
    ipc_push_client_list();
    pthread_mutex_lock(&g_ipc_tx_mu);
    if (g_ipc_tx_fd >= 0) {
        ipc_client_entry_t ce = {0};
        ce.client_id   = (uint16_t)cid;
        strncpy(ce.ip_str, ip_str, sizeof(ce.ip_str)-1);
        ce.port        = peer_port;
        ce.session_id  = c.session_id;
        ce.hs_total_ms = (float)metrics.hs_total_ms;
        ipc_send_frame(g_ipc_tx_fd, IPC_CLIENT_CONNECT,
                       (uint16_t)cid, &ce, sizeof(ce));
    }
    pthread_mutex_unlock(&g_ipc_tx_mu);

    /* Spawn RX thread — it owns this pipe slot from here on */
    {
        client_rx_args_t *rx = malloc(sizeof(client_rx_args_t));
        rx->client_id = cid;
        rx->pipe_fd   = pipe_fd;
        rx->stop      = 0;
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, client_rx_thread, rx);
        pthread_attr_destroy(&attr);
    }
    /* NOTE: do NOT call dispatch_free here — rx thread owns the pipe now */
    return NULL;

fail:
    explicit_bzero(srv_kem_sk, sizeof(srv_kem_sk));
    dispatch_free(pipe_idx);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════
 * IPC accept threads
 * ════════════════════════════════════════════════════════════════════ */

static void *ipc_rx_accept_thread(void *arg)
{
    int lfd = *(int *)arg; free(arg);
    while (!g_stop) {
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        if (poll(&pfd, 1, 500) <= 0) continue;
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) continue;

        pthread_mutex_lock(&g_ipc_rx_mu);
        if (g_ipc_rx_fd >= 0) close(g_ipc_rx_fd);
        g_ipc_rx_fd = fd;
        pthread_mutex_unlock(&g_ipc_rx_mu);
        printf("[server] server_rx connected (fd=%d)\n", fd);

        char drain[64];
        while (!g_stop && recv(fd, drain, sizeof(drain), 0) > 0) {}

        pthread_mutex_lock(&g_ipc_rx_mu);
        close(g_ipc_rx_fd); g_ipc_rx_fd = -1;
        pthread_mutex_unlock(&g_ipc_rx_mu);
        printf("[server] server_rx disconnected\n");
    }
    close(lfd);
    return NULL;
}

static void *ipc_tx_accept_thread(void *arg)
{
    int lfd = *(int *)arg; free(arg);
    while (!g_stop) {
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        if (poll(&pfd, 1, 500) <= 0) continue;
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) continue;

        pthread_mutex_lock(&g_ipc_tx_mu);
        if (g_ipc_tx_fd >= 0) close(g_ipc_tx_fd);
        g_ipc_tx_fd = fd;
        pthread_mutex_unlock(&g_ipc_tx_mu);
        printf("[server] server_tx connected (fd=%d)\n", fd);

        ipc_push_client_list();

        char ts[16];
        uint8_t buf[sizeof(ipc_tx_cmd_t) + DATA_CHUNK_MAX + 8];
        while (!g_stop) {
            ipc_hdr_t hdr;
            ssize_t n = ipc_recv_frame(fd, &hdr, buf, sizeof(buf));
            if (n < 0) break;
            if (hdr.type != IPC_MSG_TX_CMD) continue;
            if (n < (ssize_t)sizeof(ipc_tx_cmd_t)) continue;

            ipc_tx_cmd_t *cmd  = (ipc_tx_cmd_t *)buf;
            uint32_t msg_len   = cmd->msg_len;
            uint16_t target    = cmd->client_id;
            const uint8_t *msg = buf + sizeof(ipc_tx_cmd_t);
            if (msg_len == 0 || msg_len > DATA_CHUNK_MAX) continue;

            now_hms(ts, sizeof(ts));
            if (target == 0) {
                int ok = registry_broadcast(msg, msg_len);
                printf("[%s] BROADCAST → %d client(s): %.*s\n",
                       ts, ok, (int)msg_len, msg);
            } else {
                if (registry_send((int)target, msg, msg_len) == 0) {
                    printf("[%s] TX → CLIENT-%02d: %.*s\n",
                           ts, target, (int)msg_len, msg);

                    metrics_t *m = registry_get_metrics((int)target);
                    if (m) {
                        ipc_metrics_tx_t mt = {0};
                        mt.client_id       = target;
                        mt.encrypt_us      = (m->encrypt_count > 0)
                            ? (float)(m->total_encrypt_us / (double)m->encrypt_count) : 0.f;
                        mt.avg_encrypt_us  = mt.encrypt_us;
                        mt.bytes_sent      = m->bytes_sent;
                        mt.msg_count       = (uint32_t)m->msg_count;
                        mt.retransmissions = (uint32_t)m->retransmissions;
                        pthread_mutex_lock(&g_ipc_tx_mu);
                        ipc_send_frame(fd, IPC_METRICS_TX, target,
                                       &mt, sizeof(mt));
                        pthread_mutex_unlock(&g_ipc_tx_mu);
                    }
                } else {
                    fprintf(stderr, "[server] TX to CLIENT-%02d failed\n",
                            target);
                }
            }
            ipc_push_client_list();
        }

        pthread_mutex_lock(&g_ipc_tx_mu);
        close(g_ipc_tx_fd); g_ipc_tx_fd = -1;
        pthread_mutex_unlock(&g_ipc_tx_mu);
        printf("[server] server_tx disconnected\n");
    }
    close(lfd);
    return NULL;
}

static int make_ipc_server(const char *path)
{
    unlink(path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket(ipc)"); return -1; }
    struct sockaddr_un a = {0};
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, path, sizeof(a.sun_path)-1);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        perror("bind(ipc)"); close(fd); return -1;
    }
    if (listen(fd, 4) < 0) {
        perror("listen(ipc)"); close(fd); return -1;
    }
    return fd;
}

/* ════════════════════════════════════════════════════════════════════
 * main() — accept / dispatch loop
 *
 * Reads every datagram from the single shared UDP socket.
 * Routes it to the correct client pipe (or spawns a new session).
 * ════════════════════════════════════════════════════════════════════ */
int main(void)
{
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    memset(g_pipes, 0, sizeof(g_pipes));
    for (int i = 0; i < DISPATCH_PIPE_MAX; i++)
        pthread_mutex_init(&g_pipes[i].mu, NULL);

    char ts[16]; now_hms(ts, sizeof(ts));
    printf("[%s] PQC Multi-Client Chat Server\n", ts);
    printf("  Protocol : ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305\n");
    printf("  Address  : 0.0.0.0:%d  |  Max clients: %d\n\n",
           SERVER_PORT, MAX_CLIENTS);

    registry_init();

    /* Warmup */
    { double wu = now_ms(); kem_warmup(); dsa_warmup();
      printf("  [warmup] %.2f ms\n\n", now_ms() - wu); }

    /* Parallel DSA + KEM keygen */
    {
        pthread_t dt, kt;
        pthread_create(&dt, NULL, dsa_keygen_thread, NULL);
        pthread_create(&kt, NULL, kem_keygen_thread, NULL);
        g_listen_sock = make_server_sock();
        if (g_listen_sock < 0) return 1;
        pthread_join(dt, NULL);
        pthread_join(kt, NULL);
    }
    printf("  DSA keygen : %.3f ms (long-term identity)\n", g_dsa_keygen_ms);
    printf("  KEM keygen : %.3f ms (first session pre-cached)\n\n",
           g_kem_keygen_ms);

    /* IPC servers */
    {
        int rx_lfd = make_ipc_server(IPC_RX_PATH);
        int tx_lfd = make_ipc_server(IPC_TX_PATH);
        if (rx_lfd < 0 || tx_lfd < 0) return 1;
        printf("  IPC RX : %s\n  IPC TX : %s\n\n", IPC_RX_PATH, IPC_TX_PATH);

        int *rp = malloc(sizeof(int)); *rp = rx_lfd;
        int *tp = malloc(sizeof(int)); *tp = tx_lfd;
        pthread_t rt, tt;
        pthread_create(&rt, NULL, ipc_rx_accept_thread, rp);
        pthread_create(&tt, NULL, ipc_tx_accept_thread, tp);
        pthread_detach(rt);
        pthread_detach(tt);
    }

    printf("\033[1;32m╔══════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;32m║  PQC Server — Multi-Client Mode          ║\033[0m\n");
    printf("\033[1;32m║  Run: ./server_rx  (receiver terminal)   ║\033[0m\n");
    printf("\033[1;32m║  Run: ./server_tx  (sender terminal)     ║\033[0m\n");
    printf("\033[1;32m╚══════════════════════════════════════════╝\033[0m\n\n");

    /*
     * Main dispatch loop.
     *
     * Reads every datagram from the shared listen socket.
     * - If it matches an active client's (ip, port): write to their pipe.
     * - If it's a PKT_CLIENT_HELLO from a new peer: allocate a pipe and
     *   spawn a session_thread.
     * - Otherwise: discard.
     *
     * This is the ONLY thread that ever calls recvfrom() on the shared
     * socket, so there are no races on the receive side.
     */
    uint8_t raw[PKT_HDR_BYTES + PIPE_PKT_MAX];

    while (!g_stop) {
        struct pollfd pfd = { .fd = g_listen_sock, .events = POLLIN };
        if (poll(&pfd, 1, 500) <= 0) continue;

        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t n = recvfrom(g_listen_sock, raw, sizeof(raw), 0,
                             (struct sockaddr *)&from, &from_len);
        if (n < (ssize_t)PKT_HDR_BYTES) continue;

        uint32_t from_ip   = from.sin_addr.s_addr;
        uint16_t from_port = from.sin_port;  /* network byte order */

        /* ── Route to existing client pipe ───────────────────── */
        int routed = 0;
        pthread_mutex_lock(&g_pipes_mu);
        for (int i = 0; i < DISPATCH_PIPE_MAX; i++) {
            if (g_pipes[i].used &&
                g_pipes[i].ip   == from_ip &&
                g_pipes[i].port == from_port) {
                dispatch_write(g_pipes[i].write_fd, raw, (uint16_t)n);
                routed = 1;
                break;
            }
        }
        pthread_mutex_unlock(&g_pipes_mu);
        if (routed) continue;

        /* ── New client ──────────────────────────────────────── */
        uint8_t pkt_type = raw[4];   /* type at offset 4 in pkt_hdr_t */
        if (pkt_type != PKT_CLIENT_HELLO) continue;  /* ignore stray pkts */

        if (registry_count() >= MAX_CLIENTS) {
            char tip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, tip, sizeof(tip));
            fprintf(stderr, "[server] At capacity, rejecting %s\n", tip);
            continue;
        }

        /* Allocate dispatch pipe */
        int idx = dispatch_alloc(from_ip, from_port);
        if (idx < 0) {
            fprintf(stderr, "[server] dispatch_alloc failed\n");
            continue;
        }

        /* Write the CLIENT_HELLO into the new pipe immediately */
        dispatch_write(g_pipes[idx].write_fd, raw, (uint16_t)n);

        {
            char tip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, tip, sizeof(tip));
            now_hms(ts, sizeof(ts));
            printf("[%s] New client: %s:%u  (active=%d)\n",
                   ts, tip, ntohs(from_port), registry_count());
        }

        /* Spawn session thread */
        session_args_t *sa = malloc(sizeof(session_args_t));
        sa->peer     = from;
        sa->pipe_idx = idx;

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, session_thread, sa);
        pthread_attr_destroy(&attr);
    }

    close(g_listen_sock);
    unlink(IPC_RX_PATH);
    unlink(IPC_TX_PATH);
    explicit_bzero(g_srv_dsa_sk, sizeof(g_srv_dsa_sk));
    explicit_bzero(g_srv_kem_sk, sizeof(g_srv_kem_sk));
    printf("\n[server] Shutdown complete.\n");
    return 0;
}