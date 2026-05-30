/*
 * wrappers/kem_wrapper.h
 *
 * Thin wrapper over ML-KEM-768 (mlkem-native x86_64 AVX2 / AArch64 NEON).
 *
 * The underlying functions are compiled from:
 *   ml-kem/mlkem-native_ml-kem-768_x86_64/   (x86_64, AVX2)
 *   ml-kem/mlkem-native_ml-kem-768_aarch64/  (AArch64, NEON)
 * Both folders are verbatim copies from liboqs 0.13.0.
 *
 * At runtime liboqs selects the best backend automatically via
 * CPU feature detection baked into the compiled library.
 *
 * The public API exposed here is intentionally identical to the
 * old kem_wrapper.h so server.c / client.c need zero changes.
 */

#ifndef KEM_WRAPPER_H
#define KEM_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

/* Buffer sizes for ML-KEM-768 (FIPS 203, K=3) */
#define KEM_PK_BYTES    1184   /* MLKEM_INDCCA_PUBLICKEYBYTES  */
#define KEM_SK_BYTES    2400   /* MLKEM_INDCCA_SECRETKEYBYTES  */
#define KEM_CT_BYTES    1088   /* MLKEM_INDCCA_CIPHERTEXTBYTES */
#define KEM_SS_BYTES      32   /* MLKEM_SSBYTES                */

/*
 * Derived key: SHAKE-256 stretch of the 32-byte shared secret.
 * Both sides call kem_derive_key() → same output.
 */
#define DERIVED_KEY_BYTES 64

/*
 * kem_keypair() — generate a ML-KEM-768 key pair.
 * Internally calls OQS_KEM_ml_kem_768_keypair().
 * Returns 0 on success.
 */
int kem_keypair(uint8_t pk[KEM_PK_BYTES], uint8_t sk[KEM_SK_BYTES]);

/*
 * kem_enc() — encapsulate: produce ciphertext + shared secret from pk.
 * Internally calls OQS_KEM_ml_kem_768_encaps().
 * Returns 0 on success.
 */
int kem_enc(uint8_t ct[KEM_CT_BYTES],
            uint8_t ss[KEM_SS_BYTES],
            const uint8_t pk[KEM_PK_BYTES]);

/*
 * kem_dec() — decapsulate: recover shared secret from ct + sk.
 * Internally calls OQS_KEM_ml_kem_768_decaps().
 * Returns 0 on success.
 */
int kem_dec(uint8_t ss[KEM_SS_BYTES],
            const uint8_t ct[KEM_CT_BYTES],
            const uint8_t sk[KEM_SK_BYTES]);

/*
 * kem_derive_key() — SHAKE-256("KEM-DERIVE" || ss) → DERIVED_KEY_BYTES.
 */
void kem_derive_key(uint8_t out[DERIVED_KEY_BYTES],
                    const uint8_t ss[KEM_SS_BYTES]);

/*
 * kem_warmup() — one-time process startup call.
 *
 * Eliminates the 1–3 ms cold-start penalty on the first real keygen by:
 *   1. Triggering OQS CPU feature detection (CPUID dispatch, ~10-50 µs)
 *   2. Waking the AVX2/NEON execution units from power-gate (~100-500 µs)
 *   3. Seeding the OpenSSL DRBG via getrandom() (~0.5-2 ms, happens once)
 *
 * Call once at process start BEFORE any handshake or keygen thread.
 * After this call every kem_keypair() runs at its steady-state speed
 * (22–25 µs on x86_64 AVX2, ~90 µs on AArch64 NEON).
 *
 * The throw-away keypair is zeroed immediately — no key material leaks.
 */
void kem_warmup(void);

#endif /* KEM_WRAPPER_H */
