#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <bmc_crypt/crypto_core_aes.h>
#include <bmc_crypt/private/aes_internal.h>
#include <bmc_crypt/private/modes.h>
#include <bmc_crypt/utils.h>

void crypto_core_aes_ctr_encrypt(const unsigned char *in,
                                unsigned char *out,
                                size_t len,
                                const AES_KEY *key,
                                const unsigned char *ivec,
                                unsigned char ecount_buf[16],   // Buffer chứa keystream hiện tại (sẽ bị ghi đè)
                                unsigned int *num){
    // If input is NULL, we're generating keystream only
    if (in == NULL) {
        // Generate keystream by encrypting zeros
        unsigned char *zero_input = NULL;
        if (len > 0) {
            zero_input = calloc(len, 1);
            if (zero_input == NULL) {
                return;  // Memory allocation failed
            }
        }
        
        CRYPTO_ctr128_encrypt(zero_input, out, len, key, ivec, ecount_buf, num,
                              (block128_f) AES_encrypt);
        
        if (zero_input != NULL) {
            free(zero_input);
        }
    } else {
        // Normal encryption/decryption
        CRYPTO_ctr128_encrypt(in, out, len, key, ivec, ecount_buf, num,
                              (block128_f) AES_encrypt);
    }
}

int crypto_core_aes_ctr_ietf(unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k) {
    AES_KEY aes_key;
    unsigned char ivec[16];  // IV for CTR mode (16 bytes)
    unsigned char ecount_buf[16];  // Keystream buffer
    unsigned int num = 0;
    int ret;
    
    // Validate parameters
    if (c == NULL || n == NULL || k == NULL) {
        return -1;
    }
    
    // Set up AES-256 key
    ret = crypto_core_aes_set_key(k, 256, &aes_key, AES_ENCRYPT);
    if (ret != 0) {
        return -1;
    }
    
    // Prepare IV for CTR mode
    // IETF format: nonce (12 bytes) + counter (4 bytes, big-endian)
    memset(ivec, 0, sizeof(ivec));
    memcpy(ivec, n, 12);  // Copy nonce to first 12 bytes
    // Counter starts at 0, stored in last 4 bytes (big-endian)
    ivec[12] = 0;
    ivec[13] = 0;
    ivec[14] = 0;
    ivec[15] = 0;
    
    // Initialize ecount_buf
    memset(ecount_buf, 0, sizeof(ecount_buf));
    
    // Generate keystream using CTR mode
    // Since we want to generate keystream (not encrypt data), we pass NULL as input
    crypto_core_aes_ctr_encrypt(NULL, c, (size_t)clen, &aes_key, ivec, ecount_buf, &num);
    
    // Clear sensitive data
    bmc_crypt_memzero(&aes_key, sizeof(aes_key));
    bmc_crypt_memzero(ivec, sizeof(ivec));
    bmc_crypt_memzero(ecount_buf, sizeof(ecount_buf));
    
    return 0;
}

int crypto_core_aes_ctr_ietf_xor(unsigned char *c, const unsigned char *m, 
                                 unsigned long long mlen,
                                 const unsigned char *n, const unsigned char *k) {
    AES_KEY aes_key;
    unsigned char ivec[16];  // IV for CTR mode (16 bytes)
    unsigned char ecount_buf[16];  // Keystream buffer
    unsigned int num = 0;
    int ret;
    
    // Validate parameters
    if (c == NULL || m == NULL || n == NULL || k == NULL) {
        return -1;
    }
    
    // Set up AES-256 key
    ret = crypto_core_aes_set_key(k, 256, &aes_key, AES_ENCRYPT);
    if (ret != 0) {
        return -1;
    }
    
    // Prepare IV for CTR mode
    // IETF format: nonce (12 bytes) + counter (4 bytes, big-endian)
    memset(ivec, 0, sizeof(ivec));
    memcpy(ivec, n, 12);  // Copy nonce to first 12 bytes
    // Counter starts at 0, stored in last 4 bytes (big-endian)
    ivec[12] = 0;
    ivec[13] = 0;
    ivec[14] = 0;
    ivec[15] = 0;
    
    // Initialize ecount_buf
    memset(ecount_buf, 0, sizeof(ecount_buf));
    
    // XOR data with keystream using CTR mode
    crypto_core_aes_ctr_encrypt(m, c, (size_t)mlen, &aes_key, ivec, ecount_buf, &num);
    
    // Clear sensitive data
    bmc_crypt_memzero(&aes_key, sizeof(aes_key));
    bmc_crypt_memzero(ivec, sizeof(ivec));
    bmc_crypt_memzero(ecount_buf, sizeof(ecount_buf));
    
    return 0;
}