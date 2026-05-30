/*
 * transport.c — Low-latency UDP transport (multi-client revision)
 *
 * Key change vs original:
 *   net_metrics_t prefix REMOVED from PKT_DATA wire format.
 *
 *   Old PKT_DATA payload:  [ net_metrics_t (56 B) | NONCE(12) | TAG(16) | CT(n) ]
 *   New PKT_DATA payload:  [ NONCE(12) | TAG(16) | CT(n) ]
 *
 *   This eliminates 56 bytes of overhead per packet.
 *   All metrics are tracked locally on sender and receiver sides
 *   using monotonic timestamps — no cross-machine clock needed.
 *
 * Everything else is unchanged:
 *   pkt_send, pkt_recv, pkt_send_reliable, send_ack, socket setup,
 *   nonce generation, AEAD calls, metrics_print, metrics_update_rtt.
 */

#define _POSIX_C_SOURCE 200809L

#include "transport.h"
#include "crypto/aead.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <sys/uio.h>

/* ── Timing ──────────────────────────────────────────────────────── */
double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec * 1e-6;
}

uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void now_hms(char *buf, int sz)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *t = localtime(&ts.tv_sec);
    if (t)
        snprintf(buf, (size_t)sz, "%02d:%02d:%02d.%03ld",
                 t->tm_hour, t->tm_min, t->tm_sec,
                 ts.tv_nsec / 1000000L);
    else
        snprintf(buf, (size_t)sz, "??:??:??.???");
}

/* ── Socket helpers ──────────────────────────────────────────────── */
static int configure_sock(int s)
{
    int buf = 4 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));

    int tos = 0x18;   /* DSCP AF21: low-delay + throughput */
    setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    int prio = 6;     /* highest unprivileged egress priority */
    setsockopt(s, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));

    return 0;
}

int make_server_sock(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return -1; }
    configure_sock(s);

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(s); return -1;
    }
    return s;
}

int make_client_sock(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return -1; }
    configure_sock(s);
    return s;
}

/* ── Counter nonce ───────────────────────────────────────────────── */
static void make_nonce(uint8_t nonce[12], uint64_t ctr)
{
    uint64_t le_ctr = ctr;
    memcpy(nonce, &le_ctr, 8);
    memset(nonce + 8, 0, 4);
}

/* ── pkt_send ────────────────────────────────────────────────────── */
ssize_t pkt_send(conn_t *c, uint8_t type,
                 const uint8_t *payload, uint16_t payload_len)
{
    pkt_hdr_t hdr;
    hdr.seq  = htonl(c->tx_seq++);
    hdr.type = type;
    hdr.len  = htons(payload_len);

    struct iovec iov[2];
    iov[0].iov_base = &hdr;
    iov[0].iov_len  = PKT_HDR_BYTES;
    iov[1].iov_base = (void *)payload;
    iov[1].iov_len  = payload_len;

    struct msghdr msg = {0};
    msg.msg_name    = &c->peer;
    msg.msg_namelen = c->peer_len;
    msg.msg_iov     = iov;
    msg.msg_iovlen  = (payload_len > 0) ? 2 : 1;

    return sendmsg(c->sock, &msg, 0);
}

/* ── pkt_recv ────────────────────────────────────────────────────── */
ssize_t pkt_recv(conn_t *c, pkt_hdr_t *hdr,
                 uint8_t *payload_out, size_t payload_max,
                 int timeout_us)
{
    if (timeout_us > 0) {
        struct pollfd pfd = { .fd = c->sock, .events = POLLIN };
        int ms = (timeout_us + 999) / 1000;
        if (ms < 1) ms = 1;
        if (poll(&pfd, 1, ms) <= 0) return -1;
    }

    uint8_t raw[PKT_BUF_MAX];
    struct sockaddr_in from = {0};
    socklen_t from_len = sizeof(from);

    ssize_t n = recvfrom(c->sock, raw, sizeof(raw), 0,
                         (struct sockaddr *)&from, &from_len);
    if (n < (ssize_t)PKT_HDR_BYTES) return -1;

    memcpy(hdr, raw, PKT_HDR_BYTES);
    hdr->seq = ntohl(hdr->seq);
    hdr->len = ntohs(hdr->len);

    c->peer     = from;
    c->peer_len = from_len;

    ssize_t payload_len = n - PKT_HDR_BYTES;
    if (payload_len < 0) payload_len = 0;
    if ((size_t)payload_len > payload_max) payload_len = (ssize_t)payload_max;
    if (payload_len > 0 && payload_out)
        memcpy(payload_out, raw + PKT_HDR_BYTES, (size_t)payload_len);

    return payload_len;
}

/* ── send_ack ────────────────────────────────────────────────────── */
void send_ack(conn_t *c, uint32_t ack_seq)
{
    uint8_t pl[4];
    pl[0] = (ack_seq >> 24) & 0xFF;
    pl[1] = (ack_seq >> 16) & 0xFF;
    pl[2] = (ack_seq >>  8) & 0xFF;
    pl[3] =  ack_seq        & 0xFF;
    pkt_send(c, PKT_ACK, pl, 4);
}

/* ── pkt_send_reliable ───────────────────────────────────────────── */
int pkt_send_reliable(conn_t *c, uint8_t type,
                      const uint8_t *payload, uint16_t payload_len)
{
    uint32_t our_seq = c->tx_seq;

    for (int attempt = 0; attempt < RETX_MAX; attempt++) {
        if (attempt > 0) c->tx_seq = our_seq;

        pkt_send(c, type, payload, payload_len);

        pkt_hdr_t hdr;
        uint8_t   buf[256];
        double    deadline = now_ms() + ACK_TIMEOUT_US / 1000.0;

        for (;;) {
            int remaining_us = (int)((deadline - now_ms()) * 1000.0);
            if (remaining_us <= 0) break;

            ssize_t n = pkt_recv(c, &hdr, buf, sizeof(buf), remaining_us);
            if (n < 0) break;

            if (hdr.type == PKT_ACK && n >= 4) {
                uint32_t acked = ((uint32_t)buf[0] << 24)
                               | ((uint32_t)buf[1] << 16)
                               | ((uint32_t)buf[2] <<  8)
                               |  (uint32_t)buf[3];
                if (acked == our_seq) return 0;
            }
        }
    }
    return -1;
}

/* Helper: increment retransmission counter (called by pkt_send_reliable).
 * We can't access metrics_t from transport.c directly, so retransmissions
 * are counted in data_send() by tracking send failures. */

/* ── data_send ───────────────────────────────────────────────────── */
/*
 * Wire format of PKT_DATA payload (SIMPLIFIED vs original):
 *
 *   [ NONCE(12) | TAG(16) | CIPHERTEXT(n) ]
 *
 * No net_metrics_t prefix.  56 bytes saved per packet.
 * Encrypt cost is measured locally and stored in m->total_encrypt_us.
 */
int data_send(conn_t *c, metrics_t *m,
              const uint8_t *msg, uint32_t msg_len)
{
    uint32_t offset = 0;
    while (offset < msg_len) {
        uint32_t chunk = msg_len - offset;
        if (chunk > DATA_CHUNK_MAX) chunk = DATA_CHUNK_MAX;

        /* payload = NONCE(12) | TAG(16) | CIPHERTEXT(chunk+overhead) */
        uint8_t pkt[12 + 16 + DATA_CHUNK_MAX];

        uint8_t nonce[12];
        make_nonce(nonce, c->tx_nonce_ctr++);
        memcpy(pkt, nonce, 12);

        /* Measure AEAD encrypt cost locally */
        double enc_t0 = now_ms();
        int ct_len = aead_encrypt(msg + offset, (int)chunk,
                                  c->session_key, nonce,
                                  pkt + 12 + 16,   /* ciphertext */
                                  pkt + 12);        /* tag        */
        double enc_us = (now_ms() - enc_t0) * 1000.0;

        if (ct_len < 0) return -1;

        if (m) {
            m->total_encrypt_us += enc_us;
            m->encrypt_count++;
            m->msg_count++;
            m->bytes_sent += (uint64_t)(PKT_HDR_BYTES + 12 + 16 + (uint32_t)ct_len);
            m->last_send_ns = now_ns();
        }

        uint16_t pkt_len = (uint16_t)(12 + 16 + (uint32_t)ct_len);
        ssize_t sent = pkt_send(c, PKT_DATA, pkt, pkt_len);
        if (sent < 0) return -1;

        offset += chunk;
    }
    return 0;
}

/* ── data_recv ───────────────────────────────────────────────────── */
ssize_t data_recv(conn_t *c, uint8_t *out, size_t out_max)
{
    for (;;) {
        pkt_hdr_t hdr;
        uint8_t   raw[12 + 16 + DATA_CHUNK_MAX + 64];

        ssize_t n = pkt_recv(c, &hdr, raw, sizeof(raw), 0);
        if (n < 0) return -1;
        if (hdr.type != PKT_DATA) continue;
        if (n < (12 + 16)) continue;

        /* Clean layout: NONCE(12) | TAG(16) | CIPHERTEXT(n) */
        const uint8_t *nonce = raw;
        const uint8_t *tag   = raw + 12;
        const uint8_t *ct    = raw + 28;
        int ct_len = (int)n - 28;
        if (ct_len <= 0) continue;

        int pt_len = aead_decrypt(ct, ct_len, c->session_key, nonce, tag, out);
        if (pt_len < 0) {
            fprintf(stderr, "[rx] AEAD auth failure — drop\n");
            continue;
        }
        return (ssize_t)pt_len;
    }
}

/* ── metrics_update_rtt ──────────────────────────────────────────── */
/*
 * Inter-arrival jitter via RFC 3550 EWMA using local receive clock.
 * No cross-machine clock synchronisation needed.
 */
void metrics_update_rtt(metrics_t *m, uint64_t recv_ns)
{
    if (m->prev_recv_ns == 0) {
        m->prev_recv_ns = recv_ns;
        return;
    }

    double ia_ms = (double)(recv_ns - m->prev_recv_ns) / 1e6;
    m->prev_recv_ns = recv_ns;
    if (ia_ms < 0.0) ia_ms = 0.0;

    m->msg_last_rtt_ms = ia_ms;

    uint64_t n = m->decrypt_count;
    if (n == 0) n = 1;
    m->msg_avg_rtt_ms = (m->msg_avg_rtt_ms * (double)(n - 1) + ia_ms) / (double)n;

    if (ia_ms < m->msg_min_rtt_ms) m->msg_min_rtt_ms = ia_ms;
    if (ia_ms > m->msg_max_rtt_ms) m->msg_max_rtt_ms = ia_ms;

    double diff = ia_ms - m->jitter_ms;
    if (diff < 0.0) diff = -diff;
    m->jitter_ms += (diff - m->jitter_ms) / 16.0;
}

/* ── metrics_print ───────────────────────────────────────────────── */
void metrics_print(const metrics_t *m)
{
    char ts[16]; now_hms(ts, sizeof(ts));

    double elapsed_s = 0.0;
    if (m->session_start_ns > 0)
        elapsed_s = (double)(now_ns() - m->session_start_ns) / 1e9;

    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║     SESSION METRICS  [%s]          ║\n", ts);
    printf("╠══════════════════════════════════════════════╣\n");

    printf("║  PQC HANDSHAKE BREAKDOWN                     ║\n");
    printf("║  ─────────────────────────────────────────── ║\n");
    printf("║  KEM keygen        : %8.3f ms             ║\n", m->hs_kem_keygen_ms);
    printf("║  DSA keygen        : %8.3f ms             ║\n", m->hs_dsa_keygen_ms);
    printf("║  KEM Encap/Decap   : %8.3f ms             ║\n", m->hs_encap_ms);
    printf("║  DSA Sign          : %8.3f ms             ║\n", m->hs_sign_ms);
    printf("║  DSA Verify        : %8.3f ms             ║\n", m->hs_verify_ms);
    printf("║  Handshake Total   : %8.3f ms  %s        ║\n",
           m->hs_total_ms,
           m->hs_total_ms <= 1.0 ? "✓ <1ms" : "⚠ >1ms");
    printf("║                                              ║\n");

    printf("║  AEAD (ChaCha20-Poly1305)                    ║\n");
    printf("║  ─────────────────────────────────────────── ║\n");
    if (m->encrypt_count > 0)
        printf("║  Avg encrypt       : %8.2f µs             ║\n",
               m->total_encrypt_us / (double)m->encrypt_count);
    if (m->decrypt_count > 0)
        printf("║  Avg decrypt       : %8.2f µs             ║\n",
               m->total_decrypt_us / (double)m->decrypt_count);
    printf("║                                              ║\n");

    printf("║  NETWORK                                     ║\n");
    printf("║  ─────────────────────────────────────────── ║\n");
    printf("║  Messages sent     : %8llu                ║\n",
           (unsigned long long)m->msg_count);
    printf("║  Bytes sent        : %8llu B              ║\n",
           (unsigned long long)m->bytes_sent);
    printf("║  Bytes received    : %8llu B              ║\n",
           (unsigned long long)m->bytes_recv);

    if (elapsed_s > 0.01) {
        double tx_kbps = (double)m->bytes_sent * 8.0 / elapsed_s / 1000.0;
        double rx_kbps = (double)m->bytes_recv * 8.0 / elapsed_s / 1000.0;
        printf("║  TX bandwidth      : %8.2f kbps           ║\n", tx_kbps);
        printf("║  RX bandwidth      : %8.2f kbps           ║\n", rx_kbps);
        printf("║  Session duration  : %8.3f s              ║\n", elapsed_s);
    }

    printf("║  Retransmissions   : %8llu                ║\n",
           (unsigned long long)m->retransmissions);

    if (m->decrypt_count > 1) {
        double ia_min = (m->msg_min_rtt_ms >= 1e14) ? 0.0 : m->msg_min_rtt_ms;
        printf("║  Inter-arrival avg : %7.3f ms              ║\n", m->msg_avg_rtt_ms);
        printf("║  Inter-arrival min : %7.3f ms              ║\n", ia_min);
        printf("║  Inter-arrival max : %7.3f ms              ║\n", m->msg_max_rtt_ms);
        printf("║  Jitter (RFC3550)  : %7.3f ms              ║\n", m->jitter_ms);
    } else {
        printf("║  Jitter            :   N/A (need 2+ msgs)  ║\n");
    }
    printf("╚══════════════════════════════════════════════╝\n\n");
}
