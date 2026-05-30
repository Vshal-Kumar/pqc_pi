/*
 * crypto/aead.h  —  Optimized ChaCha20-Poly1305 AEAD
 *
 * OPTIMIZATIONS vs original:
 *   🔴 Thread-local EVP_CIPHER_CTX reuse: context created once per
 *      thread, never freed and re-allocated in the hot path.
 *   🔴 In-place encrypt/decrypt variants: caller owns one buffer,
 *      no intermediate copy of plaintext/ciphertext.
 *   🔴 Flat packet layout helper: callers write directly into a
 *      send buffer, eliminating the nonce+tag+ct memcpy triple.
 *   🟠 sha3_256_hex / debug hashing removed from production path
 *      (compile with -DAEAD_DEBUG to restore).
 *   🟡 get_time_ms() kept for benchmarking; zero cost when unused.
 */

#ifndef AEAD_H
#define AEAD_H

#include <stdint.h>
#include <stddef.h>

/* ── Wire constants ──────────────────────────────────────────────── */
#define AEAD_KEY_BYTES    32
#define AEAD_NONCE_BYTES  12
#define AEAD_TAG_BYTES    16

/*
 * Flat on-wire packet layout (no heap allocation required):
 *
 *   [ NONCE (12) | TAG (16) | CIPHERTEXT (n) ]
 *
 * Total wire bytes for a plaintext of length n:
 *   AEAD_PACKET_OVERHEAD + n
 */
#define AEAD_PACKET_OVERHEAD  (AEAD_NONCE_BYTES + AEAD_TAG_BYTES)

/* ── Standard (copy-based) interface — backward compatible ───────── */

/*
 * aead_encrypt()
 *   Encrypts plaintext[0..plaintext_len) with key/nonce.
 *   Writes ciphertext to *ciphertext (caller allocates >= plaintext_len).
 *   Writes 16-byte tag to *tag.
 *   Returns ciphertext length (== plaintext_len) or -1 on error.
 */
int aead_encrypt(const uint8_t *plaintext,   int plaintext_len,
                 const uint8_t *key,
                 const uint8_t *nonce,
                 uint8_t       *ciphertext,
                 uint8_t       *tag);

/*
 * aead_decrypt()
 *   Returns plaintext length or -1 on authentication failure.
 */
int aead_decrypt(const uint8_t *ciphertext,  int ciphertext_len,
                 const uint8_t *key,
                 const uint8_t *nonce,
                 const uint8_t *tag,
                 uint8_t       *plaintext);

/* ── In-place interface (zero extra copy) ────────────────────────── */

/*
 * aead_encrypt_packet()
 *   Writes a complete [ NONCE | TAG | CT ] packet into `out`.
 *   `out` must be at least AEAD_PACKET_OVERHEAD + pt_len bytes.
 *   Nonce is randomly generated internally.
 *
 *   🔴 Eliminates the three separate memcpy(nonce, tag, ct) calls
 *      that existed in the original client.c / server.c chat loops.
 *
 *   Returns total bytes written (AEAD_PACKET_OVERHEAD + pt_len),
 *   or -1 on error.
 */
int aead_encrypt_packet(const uint8_t *key,
                        const uint8_t *pt,  int pt_len,
                        uint8_t       *out);

/*
 * aead_decrypt_packet()
 *   Decrypts a flat [ NONCE | TAG | CT ] packet written by
 *   aead_encrypt_packet().
 *   `pkt_len` is the total wire length (>= AEAD_PACKET_OVERHEAD).
 *   Decrypts in-place into `pt` (caller provides >= pkt_len buffer).
 *
 *   Returns plaintext length or -1 on auth failure / bad input.
 */
int aead_decrypt_packet(const uint8_t *key,
                        const uint8_t *pkt, int pkt_len,
                        uint8_t       *pt);

/* ── Benchmark helper ────────────────────────────────────────────── */
double get_time_ms(void);

#endif /* AEAD_H */