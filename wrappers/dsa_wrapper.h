/*
 * wrappers/dsa_wrapper.h
 *
 * Thin wrapper over ML-DSA-65 (pqcrystals-dilithium AVX2).
 *
 * The underlying implementation is compiled from:
 *   ml-dsa/pqcrystals-dilithium-standard_ml-dsa-65_avx2/
 * which is a verbatim copy from liboqs 0.13.0.
 *
 * On x86_64 with AVX2 the NTT, inverse NTT, pointwise multiply,
 * and rejection sampling all use YMM registers (see ntt.S, invntt.S,
 * pointwise.S, shuffle.S).
 *
 * The public API is identical to the old dsa_wrapper.h.
 */

#ifndef DSA_WRAPPER_H
#define DSA_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

/* Buffer sizes for ML-DSA-65 (FIPS 204, K=6, L=5) */
#define DSA_PK_BYTES   1952   /* pqcrystals_dilithium3_PUBLICKEYBYTES */
#define DSA_SK_BYTES   4032   /* pqcrystals_dilithium3_SECRETKEYBYTES */
#define DSA_SIG_BYTES  3309   /* pqcrystals_dilithium3_BYTES          */

/*
 * dsa_keypair() — generate a ML-DSA-65 key pair.
 * Internally calls OQS_SIG_ml_dsa_65_keeypair().
 * Returns 0 on success.
 */
int dsa_keypair(uint8_t pk[DSA_PK_BYTES], uint8_t sk[DSA_SK_BYTES]);

/*
 * dsa_sign() — compute a detached ML-DSA-65 signature.
 * Internally calls OQS_SIG_ml_dsa_65_sign() (empty context string).
 * Returns 0 on success. *siglen is set to the actual signature length.e
 */
int dsa_sign(uint8_t sig[DSA_SIG_BYTES],
             size_t *siglen,
             const uint8_t *m, size_t mlen,
             const uint8_t sk[DSA_SK_BYTES]);

/*
 * dsa_verify() — verify a detached ML-DSA-65 signature.
 * Internally calls OQS_SIG_ml_dsa_65_verify() (empty context string).
 * Returns 0 if valid, non-zero otherwise.
 */
int dsa_verify(const uint8_t *sig, size_t siglen,
               const uint8_t *m,   size_t mlen,
               const uint8_t pk[DSA_PK_BYTES]);

/*
 * dsa_warmup() — one-time process startup call.
 *
 * Eliminates the 1–3 ms cold-start penalty on the first real DSA keygen by:
 *   1. Triggering OQS CPU feature detection (CPUID dispatch, ~10–50 µs)
 *   2. Waking AVX2/NEON execution units from power-gate (~100–500 µs)
 *   3. Ensuring OpenSSL DRBG is seeded (if kem_warmup() not already called)
 *
 * Call once at process start BEFORE any handshake or keygen thread.
 * After this call every dsa_keypair() runs at its steady-state speed
 * (50–56 µs on x86_64 AVX2).
 *
 * The throw-away keypair is zeroed immediately — no key material leaks.
 */
void dsa_warmup(void);

#endif /* DSA_WRAPPER_H */
