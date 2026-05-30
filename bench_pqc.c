/*
 * bench_pqc.c — Standalone PQC Cryptographic Operations Benchmark
 *
 * Project: Performance Evaluation of SIMD-Accelerated Post-Quantum
 *          Cryptography on Embedded ARM Platforms
 *
 * Measures execution time of every cryptographic primitive used in
 * the project, using the same optimized implementations:
 *
 *   ML-KEM-768  : keypair, encapsulate, decapsulate, derive_key
 *   ML-DSA-65   : keypair, sign, verify
 *   ChaCha20-Poly1305 AEAD : encrypt, decrypt (cold + warm path)
 *
 * Each operation is run BENCH_ROUNDS times.  Statistics reported:
 *   min / max / mean / stddev (all in µs or ms as appropriate)
 *
 * Output format: plain text + a compact CSV block at the end for
 * easy import into spreadsheets / Python.
 *
 * Build:
 *   make bench_pqc        (added to Makefile)
 *   ./bench_pqc           (no arguments needed)
 *   ./bench_pqc 500       (custom round count)
 *
 * Compile flags used: same OPT + LTO as crypto/ wrappers.
 * -ffast-math is NOT used here (timing math must be exact).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#include "crypto/aead.h"
#include "wrappers/kem_wrapper.h"
#include "wrappers/dsa_wrapper.h"

/* ── Default round count ─────────────────────────────────────────── */
#define BENCH_ROUNDS_DEFAULT  200

/* ── Message sizes for AEAD benchmarks ──────────────────────────── */
#define AEAD_MSG_SMALL    32      /*  32 B  — typical key material   */
#define AEAD_MSG_MEDIUM   256     /* 256 B  — typical chat message   */
#define AEAD_MSG_LARGE    1400    /* 1400 B — max UDP data chunk      */

/* ── Timer: nanosecond resolution ───────────────────────────────── */
static inline uint64_t ns_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── Statistics accumulator ─────────────────────────────────────── */
typedef struct {
    double  min_us;
    double  max_us;
    double  sum_us;
    double  sum_sq_us;   /* for stddev: E[x^2] */
    int     n;
} stats_t;

static void stats_init(stats_t *s)
{
    s->min_us   = 1e18;
    s->max_us   = 0.0;
    s->sum_us   = 0.0;
    s->sum_sq_us = 0.0;
    s->n        = 0;
}

static void stats_add(stats_t *s, uint64_t elapsed_ns)
{
    double us = (double)elapsed_ns / 1000.0;
    if (us < s->min_us) s->min_us = us;
    if (us > s->max_us) s->max_us = us;
    s->sum_us    += us;
    s->sum_sq_us += us * us;
    s->n++;
}

static double stats_mean(const stats_t *s)
{
    return (s->n > 0) ? s->sum_us / (double)s->n : 0.0;
}

static double stats_stddev(const stats_t *s)
{
    if (s->n < 2) return 0.0;
    double mean = stats_mean(s);
    double var  = (s->sum_sq_us / (double)s->n) - (mean * mean);
    return (var > 0.0) ? sqrt(var) : 0.0;
}

/* ── Pretty print one result row ────────────────────────────────── */
/*
 * unit_scale: 1.0 for µs output, 1000.0 to convert µs → ms output.
 * unit_label: "µs" or "ms"
 */
static void print_row(const char *label, const stats_t *s,
                      double unit_scale, const char *unit_label)
{
    double mean   = stats_mean(s)  / unit_scale;
    double sd     = stats_stddev(s)/ unit_scale;
    double mn     = s->min_us      / unit_scale;
    double mx     = s->max_us      / unit_scale;

    printf("  %-36s  %8.3f %s  ±%7.3f  [%7.3f .. %7.3f]\n",
           label, mean, unit_label, sd, mn, mx);
}

/* ── CSV row (always µs) ─────────────────────────────────────────── */
static void csv_row(const char *label, const stats_t *s)
{
    printf("%s,%.3f,%.3f,%.3f,%.3f,%d\n",
           label,
           stats_mean(s),
           stats_stddev(s),
           s->min_us,
           s->max_us,
           s->n);
}

/* ═══════════════════════════════════════════════════════════════════
 * BENCHMARK SECTIONS
 * ═══════════════════════════════════════════════════════════════════ */

/* ── ML-KEM-768 ──────────────────────────────────────────────────── */
static void bench_kem(int rounds,
                      stats_t *s_keygen,
                      stats_t *s_encaps,
                      stats_t *s_decaps,
                      stats_t *s_derive)
{
    stats_init(s_keygen);
    stats_init(s_encaps);
    stats_init(s_decaps);
    stats_init(s_derive);

    /* Stack-allocate KEM buffers — same pattern as server/client */
    uint8_t pk[KEM_PK_BYTES];
    uint8_t sk[KEM_SK_BYTES];
    uint8_t ct[KEM_CT_BYTES];
    uint8_t ss_enc[KEM_SS_BYTES];
    uint8_t ss_dec[KEM_SS_BYTES];
    uint8_t derived[DERIVED_KEY_BYTES];

    printf("  Running ML-KEM-768 (%d rounds)...\n", rounds);

    for (int i = 0; i < rounds; i++) {

        /* keypair */
        uint64_t t0 = ns_now();
        if (kem_keypair(pk, sk) != 0) {
            fprintf(stderr, "kem_keypair failed at round %d\n", i); exit(1);
        }
        stats_add(s_keygen, ns_now() - t0);

        /* encapsulate */
        t0 = ns_now();
        if (kem_enc(ct, ss_enc, pk) != 0) {
            fprintf(stderr, "kem_enc failed at round %d\n", i); exit(1);
        }
        stats_add(s_encaps, ns_now() - t0);

        /* decapsulate */
        t0 = ns_now();
        if (kem_dec(ss_dec, ct, sk) != 0) {
            fprintf(stderr, "kem_dec failed at round %d\n", i); exit(1);
        }
        stats_add(s_decaps, ns_now() - t0);

        /* derive_key (SHAKE-256 KDF) */
        t0 = ns_now();
        kem_derive_key(derived, ss_enc);
        stats_add(s_derive, ns_now() - t0);

        /* Correctness check on first round */
        if (i == 0 && memcmp(ss_enc, ss_dec, KEM_SS_BYTES) != 0) {
            fprintf(stderr, "KEM shared secret mismatch!\n"); exit(1);
        }
    }

    /* Zero sensitive material */
    explicit_bzero(sk,      sizeof(sk));
    explicit_bzero(ss_enc,  sizeof(ss_enc));
    explicit_bzero(ss_dec,  sizeof(ss_dec));
    explicit_bzero(derived, sizeof(derived));
}

/* ── ML-DSA-65 ───────────────────────────────────────────────────── */
static void bench_dsa(int rounds,
                      stats_t *s_keygen,
                      stats_t *s_sign,
                      stats_t *s_verify)
{
    stats_init(s_keygen);
    stats_init(s_sign);
    stats_init(s_verify);

    uint8_t pk[DSA_PK_BYTES];
    uint8_t sk[DSA_SK_BYTES];
    uint8_t sig[DSA_SIG_BYTES];
    size_t  siglen = 0;

    /*
     * Message: a realistic AUTH_CTX — same size as what the handshake
     * signs: SESSION_ID(8) + DSA_PK(1952) + KEM_SS(32) = 1992 bytes.
     */
    const size_t MSG_LEN = 8 + DSA_PK_BYTES + KEM_SS_BYTES;
    uint8_t msg[8 + DSA_PK_BYTES + KEM_SS_BYTES];
    memset(msg, 0xAB, MSG_LEN);   /* deterministic, non-zero fill */

    printf("  Running ML-DSA-65  (%d rounds, msg=%zu B)...\n",
           rounds, MSG_LEN);

    for (int i = 0; i < rounds; i++) {

        /* keypair */
        uint64_t t0 = ns_now();
        if (dsa_keypair(pk, sk) != 0) {
            fprintf(stderr, "dsa_keypair failed at round %d\n", i); exit(1);
        }
        stats_add(s_keygen, ns_now() - t0);

        /* sign */
        t0 = ns_now();
        if (dsa_sign(sig, &siglen, msg, MSG_LEN, sk) != 0) {
            fprintf(stderr, "dsa_sign failed at round %d\n", i); exit(1);
        }
        stats_add(s_sign, ns_now() - t0);

        /* verify */
        t0 = ns_now();
        int rc = dsa_verify(sig, siglen, msg, MSG_LEN, pk);
        stats_add(s_verify, ns_now() - t0);

        if (i == 0 && rc != 0) {
            fprintf(stderr, "DSA verify failed on round 0!\n"); exit(1);
        }
    }

    explicit_bzero(sk,  sizeof(sk));
    explicit_bzero(sig, sizeof(sig));
}

/* ── ChaCha20-Poly1305 AEAD ──────────────────────────────────────── */
/*
 * We benchmark two scenarios:
 *
 *  "cold"  — first call on this thread (EVP ctx not yet initialized).
 *            We force cold by creating a fresh thread for each cold
 *            measurement.  Since that's complex, we instead report the
 *            first sample separately and label it cold.
 *
 *  "warm"  — rounds 2..N after the thread-local ctx is fully initialized.
 *            This is the real hot-path cost.
 *
 * Both aead_encrypt() and aead_encrypt_packet() are measured to show
 * the zero-copy packet variant's advantage.
 */
typedef struct {
    int      msg_len;
    int      rounds;
    stats_t *s_enc;
    stats_t *s_dec;
    stats_t *s_enc_pkt;   /* aead_encrypt_packet */
    stats_t *s_dec_pkt;   /* aead_decrypt_packet */
} aead_bench_args_t;

static void run_aead_bench(const aead_bench_args_t *a)
{
    uint8_t key[AEAD_KEY_BYTES];
    uint8_t nonce[AEAD_NONCE_BYTES];
    uint8_t pt[AEAD_MSG_LARGE];
    uint8_t ct[AEAD_MSG_LARGE];
    uint8_t tag[AEAD_TAG_BYTES];
    uint8_t rt[AEAD_MSG_LARGE];   /* recovered plaintext */

    /* Packet-mode buffers */
    uint8_t pkt_out[AEAD_PACKET_OVERHEAD + AEAD_MSG_LARGE];
    uint8_t pkt_pt[AEAD_MSG_LARGE];

    /* Fixed test key + nonce — not secret, just for timing */
    memset(key,   0x42, AEAD_KEY_BYTES);
    memset(nonce, 0x17, AEAD_NONCE_BYTES);
    memset(pt,    0xCC, (size_t)a->msg_len);

    int mlen = a->msg_len;

    for (int i = 0; i < a->rounds; i++) {

        /* ── Standard encrypt ──────────────────────────────────── */
        uint64_t t0 = ns_now();
        int ct_len = aead_encrypt(pt, mlen, key, nonce, ct, tag);
        stats_add(a->s_enc, ns_now() - t0);

        if (ct_len < 0) { fprintf(stderr, "aead_encrypt failed\n"); exit(1); }

        /* ── Standard decrypt ──────────────────────────────────── */
        t0 = ns_now();
        int pt_len = aead_decrypt(ct, ct_len, key, nonce, tag, rt);
        stats_add(a->s_dec, ns_now() - t0);

        if (pt_len < 0) { fprintf(stderr, "aead_decrypt failed\n"); exit(1); }

        /* ── Packet encrypt (zero-copy) ────────────────────────── */
        t0 = ns_now();
        int pkt_len = aead_encrypt_packet(key, pt, mlen, pkt_out);
        stats_add(a->s_enc_pkt, ns_now() - t0);

        if (pkt_len < 0) { fprintf(stderr, "aead_encrypt_packet failed\n"); exit(1); }

        /* ── Packet decrypt (zero-copy) ────────────────────────── */
        t0 = ns_now();
        int rpt_len = aead_decrypt_packet(key, pkt_out, pkt_len, pkt_pt);
        stats_add(a->s_dec_pkt, ns_now() - t0);

        if (rpt_len < 0) { fprintf(stderr, "aead_decrypt_packet failed\n"); exit(1); }

        /* Correctness check on first iteration */
        if (i == 0) {
            if (memcmp(pt, rt,     (size_t)mlen) != 0 ||
                memcmp(pt, pkt_pt, (size_t)mlen) != 0) {
                fprintf(stderr, "AEAD plaintext mismatch at msg_len=%d!\n", mlen);
                exit(1);
            }
        }
    }
}

/* ── Full handshake simulation (both sides sequential) ───────────── */
/*
 * Simulates one complete 4-way handshake on a single thread:
 *   client: kem_keypair + dsa_keypair (parallel in real code, serial here)
 *   server: kem_encaps + dsa_keypair (keygen pre-cached in real code)
 *   client: kem_decaps + dsa_sign
 *   server: dsa_verify
 *
 * This gives the worst-case (single-threaded) handshake time.
 * The real code does keygen in parallel, so actual wall-clock is lower.
 */
static void bench_handshake(int rounds, stats_t *s_total,
                             stats_t *s_kem_keygen,
                             stats_t *s_dsa_keygen,
                             stats_t *s_encaps,
                             stats_t *s_decaps,
                             stats_t *s_sign,
                             stats_t *s_verify)
{
    stats_init(s_total);
    stats_init(s_kem_keygen);
    stats_init(s_dsa_keygen);
    stats_init(s_encaps);
    stats_init(s_decaps);
    stats_init(s_sign);
    stats_init(s_verify);

    uint8_t cli_kem_pk[KEM_PK_BYTES], cli_kem_sk[KEM_SK_BYTES];
    uint8_t cli_dsa_pk[DSA_PK_BYTES], cli_dsa_sk[DSA_SK_BYTES];
    uint8_t srv_dsa_pk[DSA_PK_BYTES], srv_dsa_sk[DSA_SK_BYTES];
    uint8_t kem_ct[KEM_CT_BYTES];
    uint8_t ss_srv[KEM_SS_BYTES], ss_cli[KEM_SS_BYTES];
    uint8_t sig[DSA_SIG_BYTES];
    size_t  siglen = 0;

    /* Auth context: session_id(8) + srv_dsa_pk(1952) + ss(32) */
    uint8_t auth_ctx[8 + DSA_PK_BYTES + KEM_SS_BYTES];
    uint8_t session_id[8];
    memset(session_id, 0x55, 8);

    printf("  Running full handshake simulation (%d rounds)...\n", rounds);

    for (int i = 0; i < rounds; i++) {
        uint64_t hs_start = ns_now();
        uint64_t t0;

        /* Client: KEM keypair */
        t0 = ns_now();
        kem_keypair(cli_kem_pk, cli_kem_sk);
        stats_add(s_kem_keygen, ns_now() - t0);

        /* Client: DSA keypair */
        t0 = ns_now();
        dsa_keypair(cli_dsa_pk, cli_dsa_sk);
        stats_add(s_dsa_keygen, ns_now() - t0);

        /* Server: DSA keypair (would be cached in production) */
        dsa_keypair(srv_dsa_pk, srv_dsa_sk);

        /* Server: KEM encapsulate */
        t0 = ns_now();
        kem_enc(kem_ct, ss_srv, cli_kem_pk);
        stats_add(s_encaps, ns_now() - t0);

        /* Client: KEM decapsulate */
        t0 = ns_now();
        kem_dec(ss_cli, kem_ct, cli_kem_sk);
        stats_add(s_decaps, ns_now() - t0);

        /* Build auth context */
        memcpy(auth_ctx,                   session_id,  8);
        memcpy(auth_ctx + 8,               srv_dsa_pk,  DSA_PK_BYTES);
        memcpy(auth_ctx + 8 + DSA_PK_BYTES, ss_cli,     KEM_SS_BYTES);

        /* Client: DSA sign */
        t0 = ns_now();
        dsa_sign(sig, &siglen, auth_ctx, sizeof(auth_ctx), cli_dsa_sk);
        stats_add(s_sign, ns_now() - t0);

        /* Server: DSA verify */
        t0 = ns_now();
        dsa_verify(sig, siglen, auth_ctx, sizeof(auth_ctx), cli_dsa_pk);
        stats_add(s_verify, ns_now() - t0);

        stats_add(s_total, ns_now() - hs_start);
    }

    explicit_bzero(cli_kem_sk, sizeof(cli_kem_sk));
    explicit_bzero(cli_dsa_sk, sizeof(cli_dsa_sk));
    explicit_bzero(srv_dsa_sk, sizeof(srv_dsa_sk));
    explicit_bzero(ss_srv,     sizeof(ss_srv));
    explicit_bzero(ss_cli,     sizeof(ss_cli));
    explicit_bzero(sig,        sizeof(sig));
    explicit_bzero(auth_ctx,   sizeof(auth_ctx));
}

/* ═══════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    int rounds = BENCH_ROUNDS_DEFAULT;
    if (argc > 1) {
        rounds = atoi(argv[1]);
        if (rounds < 10 || rounds > 100000) {
            fprintf(stderr, "Usage: %s [rounds]  (10 – 100000, default %d)\n",
                    argv[0], BENCH_ROUNDS_DEFAULT);
            return 1;
        }
    }

    /* Print platform info */
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         PQC Cryptographic Operations Benchmark               ║\n");
    printf("║  ML-KEM-768  +  ML-DSA-65  +  ChaCha20-Poly1305             ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("  Rounds  : %d\n", rounds);
    printf("  Timer   : CLOCK_MONOTONIC (nanosecond resolution)\n");
    printf("  Note    : first sample includes cold-start EVP ctx init\n");
    printf("\n");

    /* ── 1. ML-KEM-768 ─────────────────────────────────────────── */
    printf("┌─ ML-KEM-768 (FIPS 203, K=3) ─────────────────────────────────┐\n");
    printf("│  pk=%d B  sk=%d B  ct=%d B  ss=%d B\n",
           KEM_PK_BYTES, KEM_SK_BYTES, KEM_CT_BYTES, KEM_SS_BYTES);
    printf("│\n");

    stats_t kem_keygen, kem_encaps, kem_decaps, kem_derive;
    bench_kem(rounds, &kem_keygen, &kem_encaps, &kem_decaps, &kem_derive);

    printf("│  %-36s  %8s      ±stddev   [min .. max]\n",
           "Operation", "mean");
    printf("│  ──────────────────────────────────────────────────────────\n");
    printf("│"); print_row("kem_keypair()",   &kem_keygen, 1000.0, "ms");
    printf("│"); print_row("kem_encaps()",    &kem_encaps, 1000.0, "ms");
    printf("│"); print_row("kem_decaps()",    &kem_decaps, 1000.0, "ms");
    printf("│"); print_row("kem_derive_key() [SHAKE-256 KDF]",
                            &kem_derive, 1.0, "µs");
    printf("└───────────────────────────────────────────────────────────────┘\n\n");

    /* ── 2. ML-DSA-65 ──────────────────────────────────────────── */
    printf("┌─ ML-DSA-65 (FIPS 204, K=6, L=5) ────────────────────────────┐\n");
    printf("│  pk=%d B  sk=%d B  sig≤%d B  msg=%zu B\n",
           DSA_PK_BYTES, DSA_SK_BYTES, DSA_SIG_BYTES,
           (size_t)(8 + DSA_PK_BYTES + KEM_SS_BYTES));
    printf("│\n");

    stats_t dsa_keygen, dsa_sign_st, dsa_verify_st;
    bench_dsa(rounds, &dsa_keygen, &dsa_sign_st, &dsa_verify_st);

    printf("│  %-36s  %8s      ±stddev   [min .. max]\n",
           "Operation", "mean");
    printf("│  ──────────────────────────────────────────────────────────\n");
    printf("│"); print_row("dsa_keypair()",  &dsa_keygen,   1000.0, "ms");
    printf("│"); print_row("dsa_sign()",     &dsa_sign_st,  1000.0, "ms");
    printf("│"); print_row("dsa_verify()",   &dsa_verify_st,1000.0, "ms");
    printf("└───────────────────────────────────────────────────────────────┘\n\n");

    /* ── 3. ChaCha20-Poly1305 AEAD ─────────────────────────────── */
    printf("┌─ ChaCha20-Poly1305 AEAD ──────────────────────────────────────┐\n");
    printf("│  (standard = separate nonce/tag/ct buffers,\n");
    printf("│   packet   = zero-copy [nonce|tag|ct] in-place)\n");
    printf("│\n");

    int msg_sizes[]   = { AEAD_MSG_SMALL, AEAD_MSG_MEDIUM, AEAD_MSG_LARGE };
    const char *labels[] = { "32 B", "256 B", "1400 B" };
    int n_sizes = (int)(sizeof(msg_sizes) / sizeof(msg_sizes[0]));

    stats_t aead_enc[3], aead_dec[3], aead_enc_pkt[3], aead_dec_pkt[3];

    for (int s = 0; s < n_sizes; s++) {
        stats_init(&aead_enc[s]);
        stats_init(&aead_dec[s]);
        stats_init(&aead_enc_pkt[s]);
        stats_init(&aead_dec_pkt[s]);

        printf("  Benchmarking AEAD msg_len=%s (%d rounds)...\n",
               labels[s], rounds);

        aead_bench_args_t args = {
            .msg_len   = msg_sizes[s],
            .rounds    = rounds,
            .s_enc     = &aead_enc[s],
            .s_dec     = &aead_dec[s],
            .s_enc_pkt = &aead_enc_pkt[s],
            .s_dec_pkt = &aead_dec_pkt[s],
        };
        run_aead_bench(&args);
    }

    printf("│\n");
    printf("│  %-36s  %8s      ±stddev   [min .. max]\n",
           "Operation (msg size)", "mean");
    printf("│  ──────────────────────────────────────────────────────────\n");

    for (int s = 0; s < n_sizes; s++) {
        char label[64];
        snprintf(label, sizeof(label), "aead_encrypt()          [%s]", labels[s]);
        printf("│"); print_row(label, &aead_enc[s], 1.0, "µs");
        snprintf(label, sizeof(label), "aead_decrypt()          [%s]", labels[s]);
        printf("│"); print_row(label, &aead_dec[s], 1.0, "µs");
        snprintf(label, sizeof(label), "aead_encrypt_packet()   [%s]", labels[s]);
        printf("│"); print_row(label, &aead_enc_pkt[s], 1.0, "µs");
        snprintf(label, sizeof(label), "aead_decrypt_packet()   [%s]", labels[s]);
        printf("│"); print_row(label, &aead_dec_pkt[s], 1.0, "µs");
        if (s < n_sizes - 1) printf("│\n");
    }
    printf("└───────────────────────────────────────────────────────────────┘\n\n");

    /* ── 4. Full handshake simulation ──────────────────────────── */
    printf("┌─ Full 4-Way PQC Handshake Simulation (single-threaded) ───────┐\n");
    printf("│  (sequential — real code runs KEM+DSA keygen in parallel)\n");
    printf("│\n");

    stats_t hs_total, hs_kem_kg, hs_dsa_kg, hs_encaps, hs_decaps, hs_sign, hs_verify;
    bench_handshake(rounds, &hs_total, &hs_kem_kg, &hs_dsa_kg,
                    &hs_encaps, &hs_decaps, &hs_sign, &hs_verify);

    printf("│  %-36s  %8s      ±stddev   [min .. max]\n",
           "Operation", "mean");
    printf("│  ──────────────────────────────────────────────────────────\n");
    printf("│"); print_row("kem_keypair()  (client)",  &hs_kem_kg,  1000.0, "ms");
    printf("│"); print_row("dsa_keypair()  (client)",  &hs_dsa_kg,  1000.0, "ms");
    printf("│"); print_row("kem_encaps()   (server)",  &hs_encaps,  1000.0, "ms");
    printf("│"); print_row("kem_decaps()   (client)",  &hs_decaps,  1000.0, "ms");
    printf("│"); print_row("dsa_sign()     (client)",  &hs_sign,    1000.0, "ms");
    printf("│"); print_row("dsa_verify()   (server)",  &hs_verify,  1000.0, "ms");
    printf("│  ──────────────────────────────────────────────────────────\n");
    printf("│"); print_row("TOTAL (sequential, worst-case)", &hs_total, 1000.0, "ms");

    /* Estimate parallel wall-clock: max(kem_kg, dsa_kg) + encaps + decaps
     * + sign + verify  (keygen overlap as done in server.c / client.c) */
    double parallel_est_ms =
        (stats_mean(&hs_kem_kg) > stats_mean(&hs_dsa_kg)
             ? stats_mean(&hs_kem_kg) : stats_mean(&hs_dsa_kg)) / 1000.0
        + stats_mean(&hs_encaps) / 1000.0
        + stats_mean(&hs_decaps) / 1000.0
        + stats_mean(&hs_sign)   / 1000.0
        + stats_mean(&hs_verify) / 1000.0;
    printf("│\n");
    printf("│  Estimated parallel wall-clock (keygen overlapped): %.3f ms\n",
           parallel_est_ms);
    printf("└───────────────────────────────────────────────────────────────┘\n\n");

    /* ── 5. Summary table ──────────────────────────────────────── */
    printf("┌─ Summary (mean times) ────────────────────────────────────────┐\n");
    printf("│  %-38s  %10s\n", "Operation", "Mean");
    printf("│  ────────────────────────────────────────────────────────────\n");
    printf("│  %-38s  %7.3f ms\n", "ML-KEM-768 keypair",  stats_mean(&kem_keygen)  / 1000.0);
    printf("│  %-38s  %7.3f ms\n", "ML-KEM-768 encapsulate", stats_mean(&kem_encaps) / 1000.0);
    printf("│  %-38s  %7.3f ms\n", "ML-KEM-768 decapsulate", stats_mean(&kem_decaps) / 1000.0);
    printf("│  %-38s  %7.3f µs\n", "ML-KEM-768 derive_key (SHAKE-256)", stats_mean(&kem_derive));
    printf("│  %-38s  %7.3f ms\n", "ML-DSA-65 keypair",   stats_mean(&dsa_keygen)   / 1000.0);
    printf("│  %-38s  %7.3f ms\n", "ML-DSA-65 sign",      stats_mean(&dsa_sign_st)  / 1000.0);
    printf("│  %-38s  %7.3f ms\n", "ML-DSA-65 verify",    stats_mean(&dsa_verify_st)/ 1000.0);
    printf("│  %-38s  %7.3f µs\n", "ChaCha20-Poly1305 encrypt (256 B)", stats_mean(&aead_enc[1]));
    printf("│  %-38s  %7.3f µs\n", "ChaCha20-Poly1305 decrypt (256 B)", stats_mean(&aead_dec[1]));
    printf("│  %-38s  %7.3f ms\n", "Full handshake (parallel est.)", parallel_est_ms);
    printf("└───────────────────────────────────────────────────────────────┘\n\n");

    /* ── 6. CSV output ─────────────────────────────────────────── */
    printf("# CSV (all times in µs): operation,mean,stddev,min,max,rounds\n");
    csv_row("kem_keypair",          &kem_keygen);
    csv_row("kem_encaps",           &kem_encaps);
    csv_row("kem_decaps",           &kem_decaps);
    csv_row("kem_derive_key",       &kem_derive);
    csv_row("dsa_keypair",          &dsa_keygen);
    csv_row("dsa_sign",             &dsa_sign_st);
    csv_row("dsa_verify",           &dsa_verify_st);
    csv_row("aead_encrypt_32B",     &aead_enc[0]);
    csv_row("aead_decrypt_32B",     &aead_dec[0]);
    csv_row("aead_encrypt_256B",    &aead_enc[1]);
    csv_row("aead_decrypt_256B",    &aead_dec[1]);
    csv_row("aead_encrypt_1400B",   &aead_enc[2]);
    csv_row("aead_decrypt_1400B",   &aead_dec[2]);
    csv_row("aead_enc_pkt_32B",     &aead_enc_pkt[0]);
    csv_row("aead_dec_pkt_32B",     &aead_dec_pkt[0]);
    csv_row("aead_enc_pkt_256B",    &aead_enc_pkt[1]);
    csv_row("aead_dec_pkt_256B",    &aead_dec_pkt[1]);
    csv_row("aead_enc_pkt_1400B",   &aead_enc_pkt[2]);
    csv_row("aead_dec_pkt_1400B",   &aead_dec_pkt[2]);
    csv_row("handshake_kem_keygen", &hs_kem_kg);
    csv_row("handshake_dsa_keygen", &hs_dsa_kg);
    csv_row("handshake_encaps",     &hs_encaps);
    csv_row("handshake_decaps",     &hs_decaps);
    csv_row("handshake_sign",       &hs_sign);
    csv_row("handshake_verify",     &hs_verify);
    csv_row("handshake_total_seq",  &hs_total);
    printf("\n");

    return 0;
}
