#ifndef crypto_core_aes_H
#define crypto_core_aes_H

#include <stddef.h>
#include <stdint.h>

#include <bmc_crypt/export.h>
#include <bmc_crypt/private/aes_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AES-128 block size */
#define crypto_core_aes128_BYTES 16U
#define crypto_core_aes128_KEYBYTES 16U

/* AES-192 block size */
#define crypto_core_aes192_BYTES 16U
#define crypto_core_aes192_KEYBYTES 24U

/* AES-256 block size */
#define crypto_core_aes256_BYTES 16U
#define crypto_core_aes256_KEYBYTES 32U

/* AES block size (same for all key sizes) */
#define crypto_core_aes_BYTES crypto_core_aes128_BYTES

BMC_CRYPT_EXPORT
void crypto_core_aes_ctr_encrypt(const unsigned char *in,
                                unsigned char *out,
                                size_t len,
                                const AES_KEY *key,
                                const unsigned char *ivec,
                                unsigned char ecount_buf[16],   // Buffer chứa keystream hiện tại (sẽ bị ghi đè)
                                unsigned int *num);

BMC_CRYPT_EXPORT
int crypto_core_aes_ecb_set_key(const unsigned char *user_key,
                                int bits,
                                AES_KEY *key,
                                const int enc);

BMC_CRYPT_EXPORT
int crypto_core_aes_ecb_encrypt(const unsigned char *in,
                                unsigned char *out,
                                const AES_KEY *key,
                                const int enc);

/**
 * Generate a keystream using AES-256 in CTR mode (IETF format)
 * This function replaces crypto_stream_chacha20_ietf for AES-based systems
 * 
 * @param[out] c The output keystream
 * @param[in] clen Length of keystream to generate
 * @param[in] n The nonce (12 bytes, IETF format)
 * @param[in] k The key (32 bytes for AES-256)
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_ctr_ietf(unsigned char *c, unsigned long long clen, 
                             const unsigned char *n, const unsigned char *k);

/**
 * XOR data with keystream using AES-256 in CTR mode (IETF format)
 * This function replaces crypto_stream_chacha20_xor for AES-based systems
 * 
 * @param[out] c The output (input XORed with keystream)
 * @param[in] m The input data to XOR
 * @param[in] mlen Length of input data
 * @param[in] n The nonce (12 bytes, IETF format)
 * @param[in] k The key (32 bytes for AES-256)
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_ctr_ietf_xor(unsigned char *c, const unsigned char *m, 
                                 unsigned long long mlen,
                                 const unsigned char *n, const unsigned char *k);
BMC_CRYPT_EXPORT
int crypto_core_aes_cbc_encrypt(const unsigned char *in,
                                unsigned char *out,
                                size_t len,
                                const AES_KEY *key,
                                const unsigned char *ivec,
                                const int enc);


/* =============================================================================
 * AES GCM Mode
 * ============================================================================= */

/* GCM tag size */
#define crypto_core_aes128_gcm_TAGBYTES 16U
#define crypto_core_aes256_gcm_TAGBYTES 16U

/**
 * Encrypt data using AES-128 in GCM mode
 * 
 * @param[out] out The output ciphertext
 * @param[out] tag The authentication tag (16 bytes)
 * @param[in] in The input plaintext
 * @param[in] inlen Length of input data
 * @param[in] key The encryption key (16 bytes)
 * @param[in] nonce The nonce (12 bytes)
 * @param[in] ad The additional authenticated data
 * @param[in] adlen Length of additional data
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes128_gcm_encrypt(unsigned char *out,
                                   unsigned char *tag,
                                   const unsigned char *in,
                                   size_t inlen,
                                   const unsigned char *key,
                                   const unsigned char *nonce,
                                   const unsigned char *ad,
                                   size_t adlen);

/**
 * Decrypt data using AES-128 in GCM mode
 * 
 * @param[out] out The output plaintext
 * @param[in] in The input ciphertext
 * @param[in] inlen Length of input data
 * @param[in] tag The authentication tag (16 bytes)
 * @param[in] key The decryption key (16 bytes)
 * @param[in] nonce The nonce (12 bytes)
 * @param[in] ad The additional authenticated data
 * @param[in] adlen Length of additional data
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes128_gcm_decrypt(unsigned char *out,
                                   const unsigned char *in,
                                   size_t inlen,
                                   const unsigned char *tag,
                                   const unsigned char *key,
                                   const unsigned char *nonce,
                                   const unsigned char *ad,
                                   size_t adlen);

/**
 * Encrypt data using AES-256 in GCM mode
 * 
 * @param[out] out The output ciphertext
 * @param[out] tag The authentication tag (16 bytes)
 * @param[in] in The input plaintext
 * @param[in] inlen Length of input data
 * @param[in] key The encryption key (32 bytes)
 * @param[in] nonce The nonce (12 bytes)
 * @param[in] ad The additional authenticated data
 * @param[in] adlen Length of additional data
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes256_gcm_encrypt(unsigned char *out,
                                   unsigned char *tag,
                                   const unsigned char *in,
                                   size_t inlen,
                                   const unsigned char *key,
                                   const unsigned char *nonce,
                                   const unsigned char *ad,
                                   size_t adlen);

/**
 * Decrypt data using AES-256 in GCM mode
 * 
 * @param[out] out The output plaintext
 * @param[in] in The input ciphertext
 * @param[in] inlen Length of input data
 * @param[in] tag The authentication tag (16 bytes)
 * @param[in] key The decryption key (32 bytes)
 * @param[in] nonce The nonce (12 bytes)
 * @param[in] ad The additional authenticated data
 * @param[in] adlen Length of additional data
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes256_gcm_decrypt(unsigned char *out,
                                   const unsigned char *in,
                                   size_t inlen,
                                   const unsigned char *tag,
                                   const unsigned char *key,
                                   const unsigned char *nonce,
                                   const unsigned char *ad,
                                   size_t adlen);

/* =============================================================================
 * Utility Functions
 * ============================================================================= */

/**
 * Generate a random AES key
 * 
 * @param[out] key The generated key
 * @param[in] keylen Length of key (16, 24, or 32 bytes)
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_keygen(unsigned char *key, size_t keylen);

/**
 * Generate a random nonce for GCM/CTR modes
 * 
 * @param[out] nonce The generated nonce (12 bytes)
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_noncegen(unsigned char *nonce);

/**
 * Generate a random IV for CBC mode
 * 
 * @param[out] iv The generated IV (16 bytes)
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_ivgen(unsigned char *iv);

#ifdef __cplusplus
}
#endif

#endif /* crypto_core_aes_H */