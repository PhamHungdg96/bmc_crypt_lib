#ifndef crypto_core_aes_H
#define crypto_core_aes_H

#include <stddef.h>
#include <stdint.h>

#include <bmc_crypt/private/modes.h>
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

/* =============================================================================
 * Common AES Context for all modes
 * ============================================================================= */

/* AES mode enumeration */
typedef enum {
    AES_MODE_ECB = 0,
    AES_MODE_CBC = 1,
    AES_MODE_CTR = 2,
    AES_MODE_GCM = 3
} aes_mode_t;

/* Common AES context structure */
typedef struct {
    AES_KEY key;                    /* AES key schedule */
    block128_f block_encrypt;       /* Block encryption function */
    block128_f block_decrypt;       /* Block decryption function */
    aes_mode_t mode;                /* Encryption mode */
    int enc;                        /* 1 for encrypt, 0 for decrypt */
    
    /* Mode-specific data */
    union {
        /* ECB mode - no additional data needed */
        struct {
            int dummy; /* Dummy member to satisfy C requirement */
        } ecb;
        
        /* CBC mode */
        struct {
            unsigned char iv[16];    /* Initialization vector */
            unsigned char last_block[16]; /* Last processed block for padding */
            size_t last_block_len;   /* Length of data in last_block */
        } cbc;
        
        /* CTR mode */
        struct {
            unsigned char nonce[16]; /* Counter block (16 bytes for full CTR mode) */
            unsigned char keystream[16]; /* Current keystream block */
            unsigned int keystream_pos; /* Position in current keystream */
        } ctr;
        
        /* GCM mode */
        struct {
            GCM128_CONTEXT *gcm_ctx; /* GCM context from modes.h */
            unsigned char tag[16];   /* Authentication tag */
        } gcm;
    } mode_data;
    
    /* Common state */
    int initialized;                /* 1 if context is initialized */
} crypto_core_aes_ctx;

/* =============================================================================
 * Common Context Functions (Init/Update/Finish)
 * ============================================================================= */

/**
 * Initialize AES context for encryption/decryption
 * 
 * @param[out] ctx The AES context to initialize
 * @param[in] key The encryption/decryption key
 * @param[in] keylen Length of key (16, 24, or 32 bytes)
 * @param[in] mode The AES mode to use
 * @param[in] enc 1 for encryption, 0 for decryption
 * @param[in] iv_nonce Initialization vector or nonce (mode-dependent)
 * @param[in] iv_nonce_len Length of IV/nonce
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_init(crypto_core_aes_ctx *ctx,
                         const unsigned char *key,
                         size_t keylen,
                         aes_mode_t mode,
                         int enc,
                         const unsigned char *iv_nonce,
                         size_t iv_nonce_len);

BMC_CRYPT_EXPORT
crypto_core_aes_ctx *crypto_core_aes_init_ex(const unsigned char *key,
                         size_t keylen,
                         aes_mode_t mode,
                         int enc,
                         const unsigned char *iv_nonce,
                         size_t iv_nonce_len);
/**
 * Process data with AES context
 * 
 * @param[in,out] ctx The AES context
 * @param[out] out Output buffer
 * @param[in] in Input buffer
 * @param[in] inlen Length of input data
 * @return Number of bytes processed, or -1 on error
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_update(crypto_core_aes_ctx *ctx,
                          unsigned char *out,
                          const unsigned char *in,
                          size_t inlen);

/**
 * Finalize AES operation and get any remaining output
 * 
 * @param[in,out] ctx The AES context
 * @param[out] out Output buffer for final data
 * @param[out] outlen Length of final output data
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_finish(crypto_core_aes_ctx *ctx,
                          unsigned char *out,
                          size_t *outlen);

/**
 * Reset AES context for reuse with same key and mode
 * 
 * @param[in,out] ctx The AES context to reset
 * @param[in] iv_nonce New IV/nonce
 * @param[in] iv_nonce_len Length of new IV/nonce
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_reset(crypto_core_aes_ctx *ctx,
                         const unsigned char *iv_nonce,
                         size_t iv_nonce_len);

/**
 * Clean up AES context and free allocated resources
 * 
 * @param[in,out] ctx The AES context to clean up
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_cleanup(crypto_core_aes_ctx *ctx);

/* =============================================================================
 * GCM-specific functions for AAD
 * ============================================================================= */

/**
 * Add additional authenticated data (GCM mode only)
 * 
 * @param[in,out] ctx The AES context (must be in GCM mode)
 * @param[in] aad Additional authenticated data
 * @param[in] aadlen Length of additional data
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_gcm_aad(crypto_core_aes_ctx *ctx,
                           const unsigned char *aad,
                           size_t aadlen);

/**
 * Get authentication tag (GCM mode only)
 * 
 * @param[in] ctx The AES context (must be in GCM mode)
 * @param[out] tag Authentication tag (16 bytes)
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_gcm_get_tag(crypto_core_aes_ctx *ctx,
                               unsigned char *tag);

/**
 * Set authentication tag for verification (GCM decryption only)
 * 
 * @param[in,out] ctx The AES context (must be in GCM decryption mode)
 * @param[in] tag Authentication tag to verify (16 bytes)
 * @return 0 on success, -1 on failure
 */
BMC_CRYPT_EXPORT
int crypto_core_aes_gcm_set_tag(crypto_core_aes_ctx *ctx,
                               const unsigned char *tag);


BMC_CRYPT_EXPORT
void crypto_core_aes_ctr_encrypt(const unsigned char *in,
                                unsigned char *out,
                                size_t len,
                                const AES_KEY *key,
                                const unsigned char *ivec,
                                unsigned char ecount_buf[16],   // Buffer chứa keystream hiện tại (sẽ bị ghi đè)
                                unsigned int *num);

BMC_CRYPT_EXPORT
int crypto_core_aes_set_key(const unsigned char *user_key,
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

BMC_CRYPT_EXPORT
int crypto_core_aes128_gcm_decrypt(unsigned char *out,
                                   const unsigned char *in,
                                   size_t inlen,
                                   const unsigned char *tag,
                                   const unsigned char *key,
                                   const unsigned char *nonce,
                                   const unsigned char *ad,
                                   size_t adlen);

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