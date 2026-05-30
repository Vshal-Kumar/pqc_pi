/*
 * client.c — PQC Chat Client  (multi-client server revision)
 *
 * Project: Performance Evaluation of SIMD-Accelerated Post-Quantum
 *          Cryptography on Embedded ARM Platforms
 *
 * 4-Way Handshake — Client Role (unchanged):
 *
 *  Phase 1  → CLIENT_HELLO : client_KEM_PK ‖ client_DSA_PK
 *  Phase 2  ← SERVER_HELLO : server_KEM_PK ‖ server_DSA_PK ‖ KEM_CT ‖ SID
 *             Decapsulate KEM_CT → shared secret
 *  Phase 3  → CLIENT_AUTH  : DSA_sign(SID ‖ srv_DSA_PK ‖ SS)
 *  Phase 4  → (session active)
 *
 * CHANGE vs previous client.c:
 *   PKT_DATA wire format simplified — net_metrics_t prefix REMOVED.
 *   New payload:  NONCE(12) | TAG(16) | CIPHERTEXT(n)
 *   All metrics tracked locally via timestamps; nothing sent in-packet.
 *
 * Everything else is unchanged:
 *   Parallel KEM+DSA keygen, warmup, handshake, RX thread, TX loop.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "transport.h"
#include "crypto/aead.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"

/* ── Auth context ────────────────────────────────────────────────── */
#define AUTH_CTX_LEN  (SESSION_ID_BYTES + DSA_PK_BYTES + KEM_SS_BYTES)

/* ── Key material ────────────────────────────────────────────────── */
typedef struct {
    uint8_t kem_pk[KEM_PK_BYTES];
    uint8_t kem_sk[KEM_SK_BYTES];
    uint8_t dsa_pk[DSA_PK_BYTES];
    uint8_t dsa_sk[DSA_SK_BYTES];
    double  kem_keygen_ms;
    double  dsa_keygen_ms;
} keygen_result_t;

static keygen_result_t g_keys;
static volatile int    g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ── Parallel keygen threads ─────────────────────────────────────── */
static void *kem_keygen_thread(void *arg)
{
    keygen_result_t *k = (keygen_result_t *)arg;
    double t0 = now_ms();
    if (kem_keypair(k->kem_pk, k->kem_sk) != 0) {
        fprintf(stderr, "[client] KEM keygen failed\n"); exit(1);
    }
    k->kem_keygen_ms = now_ms() - t0;
    return NULL;
}

static void *dsa_keygen_thread(void *arg)
{
    keygen_result_t *k = (keygen_result_t *)arg;
    double t0 = now_ms();
    if (dsa_keypair(k->dsa_pk, k->dsa_sk) != 0) {
        fprintf(stderr, "[client] DSA keygen failed\n"); exit(1);
    }
    k->dsa_keygen_ms = now_ms() - t0;
    return NULL;
}

/* ── Recv helper (handshake only) ────────────────────────────────── */
static ssize_t recv_type(conn_t *c, uint8_t want_type,
                          uint8_t *payload, size_t payload_max)
{
    pkt_hdr_t hdr;
    for (;;) {
        ssize_t n = pkt_recv(c, &hdr, payload, payload_max, 0);
        if (n < 0) return -1;
        if (hdr.type == want_type) { send_ack(c, hdr.seq); return n; }
        if (hdr.type != PKT_ACK && hdr.type != PKT_DATA)
            send_ack(c, hdr.seq);
    }
}

/* ── RX thread ───────────────────────────────────────────────────── */
typedef struct {
    conn_t    *conn;
    metrics_t *metrics;
    volatile int stop;
} rx_args_t;

static void *rx_thread(void *arg)
{
    rx_args_t *a = (rx_args_t *)arg;
    uint8_t pt[DATA_CHUNK_MAX + 16];

    while (!a->stop && !g_stop) {
        pkt_hdr_t hdr;
        /*
         * Clean wire format: NONCE(12) | TAG(16) | CIPHERTEXT(n)
         * No net_metrics_t prefix — 56 bytes less overhead per packet.
         */
        uint8_t raw[12 + 16 + DATA_CHUNK_MAX + 64];
        ssize_t n = pkt_recv(a->conn, &hdr, raw, sizeof(raw),
                             RX_POLL_TIMEOUT_US);
        if (n < 0) continue;
        if (hdr.type != PKT_DATA) continue;
        if (n < 28) continue;    /* need at least NONCE+TAG */

        uint64_t recv_ns = now_ns();

        const uint8_t *nonce = raw;
        const uint8_t *tag   = raw + 12;
        const uint8_t *ct    = raw + 28;
        int ct_len = (int)n - 28;
        if (ct_len <= 0) continue;

        /* Measure decrypt cost locally */
        double dec_t0  = now_ms();
        int pt_len = aead_decrypt(ct, ct_len, a->conn->session_key,
                                  nonce, tag, pt);
        double dec_us  = (now_ms() - dec_t0) * 1000.0;

        if (pt_len <= 0) {
            fprintf(stderr, "\r[rx] AEAD auth failure\n");
            continue;
        }

        if (pt_len < (int)sizeof(pt)) pt[pt_len] = '\0';
        while (pt_len > 0 && (pt[pt_len-1] == '\n' || pt[pt_len-1] == '\r'))
            pt[--pt_len] = '\0';

        char ts[16]; now_hms(ts, sizeof(ts));
        printf("\r\033[2K\033[1;36m[%s] PC :\033[0m %s\n", ts, pt);

        /* Update local metrics */
        a->metrics->bytes_recv        += (uint64_t)(PKT_HDR_BYTES + 28 + ct_len);
        a->metrics->total_decrypt_us  += dec_us;
        a->metrics->decrypt_count++;
        metrics_update_rtt(a->metrics, recv_ns);

        /* Compact per-message metrics line */
        double avg_dec = (a->metrics->decrypt_count > 0)
            ? a->metrics->total_decrypt_us / (double)a->metrics->decrypt_count : 0.0;
        printf("\033[90m  [rx] decrypt=%.1fµs  avg=%.1fµs"
               "  ia=%.3fms  jitter=%.3fms  rx=%lluB\033[0m\n",
               dec_us, avg_dec,
               a->metrics->msg_last_rtt_ms,
               a->metrics->jitter_ms,
               (unsigned long long)a->metrics->bytes_recv);

        printf("\033[1;35mPi  >\033[0m ");
        fflush(stdout);
    }
    return NULL;
}

/* ════════════════════════════════════════════════════════════════
 * do_handshake() — 4-way PQC handshake, client side (unchanged)
 * ════════════════════════════════════════════════════════════════ */
static int do_handshake(conn_t *c, metrics_t *m,
                        const keygen_result_t *k)
{
    double t0, t1;
    double hs_start = now_ms();

    uint8_t srv_kem_pk[KEM_PK_BYTES];
    uint8_t srv_dsa_pk[DSA_PK_BYTES];
    uint8_t kem_ct[KEM_CT_BYTES];
    uint8_t shared_secret[KEM_SS_BYTES];
    uint8_t session_id[SESSION_ID_BYTES];
    uint8_t sig[DSA_SIG_BYTES];
    size_t  sig_len = 0;

    m->hs_kem_keygen_ms = k->kem_keygen_ms;
    m->hs_dsa_keygen_ms = k->dsa_keygen_ms;

    /* Phase 1: Send CLIENT_HELLO */
    uint8_t hello[KEM_PK_BYTES + DSA_PK_BYTES];
    memcpy(hello,              k->kem_pk, KEM_PK_BYTES);
    memcpy(hello + KEM_PK_BYTES, k->dsa_pk, DSA_PK_BYTES);
    if (pkt_send_reliable(c, PKT_CLIENT_HELLO, hello, (uint16_t)sizeof(hello)) != 0) {
        fprintf(stderr, "[client] CLIENT_HELLO send failed\n"); return -1;
    }
    printf("  CLIENT_HELLO sent (%zu bytes)\n", sizeof(hello));

    /* Phase 2: Receive SERVER_HELLO */
    size_t srv_hello_min = KEM_PK_BYTES + DSA_PK_BYTES + KEM_CT_BYTES + SESSION_ID_BYTES;
    uint8_t srv_hello[KEM_PK_BYTES + DSA_PK_BYTES + KEM_CT_BYTES + SESSION_ID_BYTES + 32];
    ssize_t srv_len = recv_type(c, PKT_SERVER_HELLO, srv_hello, sizeof(srv_hello));
    if (srv_len < (ssize_t)srv_hello_min) {
        fprintf(stderr, "[client] SERVER_HELLO too short\n"); return -1;
    }
    {
        size_t off = 0;
        memcpy(srv_kem_pk, srv_hello + off, KEM_PK_BYTES);    off += KEM_PK_BYTES;
        memcpy(srv_dsa_pk, srv_hello + off, DSA_PK_BYTES);    off += DSA_PK_BYTES;
        memcpy(kem_ct,     srv_hello + off, KEM_CT_BYTES);    off += KEM_CT_BYTES;
        memcpy(session_id, srv_hello + off, SESSION_ID_BYTES);
        (void)srv_kem_pk;
    }
    printf("  SERVER_HELLO received (%zu bytes)\n", (size_t)srv_len);

    /* KEM decapsulate */
    t0 = now_ms();
    if (kem_dec(shared_secret, kem_ct, k->kem_sk) != 0) {
        fprintf(stderr, "[client] KEM decaps failed\n"); return -1;
    }
    t1 = now_ms();
    m->hs_encap_ms = t1 - t0;
    printf("  kem_decaps          : %.3f ms\n", m->hs_encap_ms);

    /* DSA sign */
    uint8_t auth_ctx[AUTH_CTX_LEN];
    {
        size_t off = 0;
        memcpy(auth_ctx + off, session_id,    SESSION_ID_BYTES); off += SESSION_ID_BYTES;
        memcpy(auth_ctx + off, srv_dsa_pk,    DSA_PK_BYTES);    off += DSA_PK_BYTES;
        memcpy(auth_ctx + off, shared_secret, KEM_SS_BYTES);
    }
    t0 = now_ms();
    if (dsa_sign(sig, &sig_len, auth_ctx, AUTH_CTX_LEN, k->dsa_sk) != 0) {
        fprintf(stderr, "[client] DSA sign failed\n");
        explicit_bzero(shared_secret, sizeof(shared_secret));
        explicit_bzero(auth_ctx, sizeof(auth_ctx));
        return -1;
    }
    t1 = now_ms();
    m->hs_sign_ms = t1 - t0;
    explicit_bzero(auth_ctx, sizeof(auth_ctx));
    printf("  dsa_sign            : %.3f ms  (sig=%zu bytes)\n",
           m->hs_sign_ms, sig_len);

    /* Phase 3: Send CLIENT_AUTH */
    if (pkt_send_reliable(c, PKT_CLIENT_AUTH, sig, (uint16_t)sig_len) != 0) {
        fprintf(stderr, "[client] CLIENT_AUTH send failed\n");
        explicit_bzero(shared_secret, sizeof(shared_secret));
        return -1;
    }
    printf("  CLIENT_AUTH sent\n");

    /* Phase 4: session active */
    memcpy(c->session_key, shared_secret, KEM_SS_BYTES);
    c->established = 1;
    explicit_bzero(shared_secret, sizeof(shared_secret));
    explicit_bzero(sig, sizeof(sig));

    uint64_t sid = 0;
    for (int i = 0; i < SESSION_ID_BYTES; i++) sid = (sid << 8) | session_id[i];
    c->session_id = sid;

    m->hs_total_ms = now_ms() - hs_start;

    printf("\n  ┌── PQC Handshake Summary ──────────────────────┐\n");
    printf("  │  ML-KEM-768  keygen  : %7.3f ms              │\n", m->hs_kem_keygen_ms);
    printf("  │  ML-DSA-65   keygen  : %7.3f ms              │\n", m->hs_dsa_keygen_ms);
    printf("  │  ML-KEM-768  decaps  : %7.3f ms              │\n", m->hs_encap_ms);
    printf("  │  ML-DSA-65   sign    : %7.3f ms              │\n", m->hs_sign_ms);
    printf("  │  Total handshake     : %7.3f ms  %s           │\n",
           m->hs_total_ms,
           m->hs_total_ms <= 1.0 ? "✓ <1ms" : "⚠  >1ms");
    printf("  └───────────────────────────────────────────────┘\n");

    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * main()
 * ════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    const char *server_ip = (argc > 1) ? argv[1] : SERVER_ADDR;

    char ts[16]; now_hms(ts, sizeof(ts));
    printf("[%s] PQC Chat Client\n", ts);
    printf("  Protocol : ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305\n");
    printf("  Server   : %s:%d\n\n", server_ip, SERVER_PORT);

    /* Warmup */
    {
        double wu_t0 = now_ms();
        kem_warmup();
        dsa_warmup();
        printf("  [warmup] KEM+DSA cold-start : %.2f ms\n\n", now_ms() - wu_t0);
    }

    /* Parallel KEM + DSA keygen */
    memset(&g_keys, 0, sizeof(g_keys));
    pthread_t kem_tid, dsa_tid;
    pthread_create(&kem_tid, NULL, kem_keygen_thread, &g_keys);
    pthread_create(&dsa_tid, NULL, dsa_keygen_thread, &g_keys);

    int sock = make_client_sock();
    if (sock < 0) return 1;

    conn_t c = {0};
    c.sock     = sock;
    c.peer_len = sizeof(c.peer);
    c.peer.sin_family = AF_INET;
    c.peer.sin_port   = htons(SERVER_PORT);
    if (inet_pton(AF_INET, server_ip, &c.peer.sin_addr) != 1) {
        fprintf(stderr, "Invalid server address: %s\n", server_ip); return 1;
    }
    c.tx_seq = 1;

    pthread_join(kem_tid, NULL);
    pthread_join(dsa_tid, NULL);

    printf("  kem_keygen (thread) : %.3f ms\n", g_keys.kem_keygen_ms);
    printf("  dsa_keygen (thread) : %.3f ms\n", g_keys.dsa_keygen_ms);
    printf("  (ran in parallel — wall-clock = max of above)\n\n");

    /* Handshake */
    metrics_t metrics = {0};
    metrics.msg_min_rtt_ms = 1e15;

    if (do_handshake(&c, &metrics, &g_keys) != 0) {
        fprintf(stderr, "[client] Handshake failed\n");
        close(sock); return 1;
    }

    explicit_bzero(g_keys.kem_sk, sizeof(g_keys.kem_sk));
    explicit_bzero(g_keys.dsa_sk, sizeof(g_keys.dsa_sk));

    now_hms(ts, sizeof(ts));
    printf("\n[%s] Session established  (ID: %016llx)\n",
           ts, (unsigned long long)c.session_id);
    printf("  Handshake total     : %.3f ms\n\n", metrics.hs_total_ms);

    metrics.session_start_ns = now_ns();

    printf("\033[1;35m╔══════════════════════════════════════╗\033[0m\n");
    printf("\033[1;35m║  PQC Secure Chat — Client (Pi)       ║\033[0m\n");
    printf("\033[1;35m║  Type to chat  |  Ctrl-D to exit     ║\033[0m\n");
    printf("\033[1;35m╚══════════════════════════════════════╝\033[0m\n\n");

    /* Start RX thread */
    rx_args_t rx_args = { .conn = &c, .metrics = &metrics, .stop = 0 };
    pthread_t rx_tid;
    pthread_create(&rx_tid, NULL, rx_thread, &rx_args);

    /* TX loop */
    printf("\033[1;35mPi  >\033[0m ");
    fflush(stdout);

    char line[DATA_CHUNK_MAX];
    while (!g_stop && fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len == 0) {
            printf("\033[1;35mPi  >\033[0m ");
            fflush(stdout);
            continue;
        }

        double enc_t0 = now_ms();
        if (data_send(&c, &metrics, (const uint8_t *)line, (uint32_t)len) != 0)
            fprintf(stderr, "[client] send failed\n");
        double enc_us = (now_ms() - enc_t0) * 1000.0;

        printf("\033[90m  [tx] encrypt=%.1fµs  msgs=%llu  sent=%lluB\033[0m\n",
               enc_us,
               (unsigned long long)metrics.msg_count,
               (unsigned long long)metrics.bytes_sent);

        printf("\033[1;35mPi  >\033[0m ");
        fflush(stdout);
    }

    rx_args.stop = 1;
    pthread_join(rx_tid, NULL);

    metrics_print(&metrics);

    close(sock);
    explicit_bzero(c.session_key, sizeof(c.session_key));
    printf("[client] Exit.\n");
    return 0;
}
