#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <bmc_crypt/crypto_core_aes.h>
#include <bmc_crypt/private/aes_internal.h>
#include <bmc_crypt/private/modes.h>
// AES block function for GCM
static void aes_block(const unsigned char in[16], unsigned char out[16], const AES_KEY *key) {
    AES_encrypt(in, out, key);
}

// AES-128 GCM encryption
int crypto_core_aes128_gcm_encrypt(unsigned char *out,
                                   unsigned char *tag,
                                   const unsigned char *in,
                                   size_t inlen,
                                   const unsigned char *key,
                                   const unsigned char *nonce,
                                   const unsigned char *ad,
                                   size_t adlen) {
    GCM128_CONTEXT *ctx;
    AES_KEY aes_key;
    int ret = 0;
    
    if (!out || !tag || !key || !nonce) {
        return -1;
    }
    
    // Set up AES key
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        return -1;
    }
    
    // Create GCM context
    ctx = CRYPTO_gcm128_new(&aes_key, aes_block);
    if (!ctx) {
        return -1;
    }
    
    // Initialize GCM
    CRYPTO_gcm128_init(ctx, &aes_key, aes_block);
    
    // Set IV/nonce
    CRYPTO_gcm128_setiv(ctx, nonce, 12);
    
    // Process AAD if provided
    if (ad && adlen > 0) {
        ret = CRYPTO_gcm128_aad(ctx, ad, adlen);
        if (ret != 0) {
            CRYPTO_gcm128_release(ctx);
            return -1;
        }
    }
    
    // Process data
    if (in && inlen > 0) {
        ret = CRYPTO_gcm128_encrypt(ctx, in, out, inlen);
        if (ret != 0) {
            CRYPTO_gcm128_release(ctx);
            return -1;
        }
    }
    
    // Generate tag
    CRYPTO_gcm128_tag(ctx, tag, 16);
    
    // Clean up
    CRYPTO_gcm128_release(ctx);
    
    return 0;
}

// AES-128 GCM decryption
int crypto_core_aes128_gcm_decrypt(unsigned char *out,
                                   const unsigned char *in,
                                   size_t inlen,
                                   const unsigned char *tag,
                                   const unsigned char *key,
                                   const unsigned char *nonce,
                                   const unsigned char *ad,
                                   size_t adlen) {
    GCM128_CONTEXT *ctx;
    AES_KEY aes_key;
    int ret = 0;
    
    if (!out || !in || !tag || !key || !nonce) {
        return -1;
    }
    
    // Set up AES key
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        return -1;
    }
    
    // Create GCM context
    ctx = CRYPTO_gcm128_new(&aes_key, aes_block);
    if (!ctx) {
        return -1;
    }
    
    // Initialize GCM
    CRYPTO_gcm128_init(ctx, &aes_key, aes_block);
    
    // Set IV/nonce
    CRYPTO_gcm128_setiv(ctx, nonce, 12);
    
    // Process AAD if provided
    if (ad && adlen > 0) {
        ret = CRYPTO_gcm128_aad(ctx, ad, adlen);
        if (ret != 0) {
            CRYPTO_gcm128_release(ctx);
            return -1;
        }
    }
    
    // Process data
    if (inlen > 0) {
        ret = CRYPTO_gcm128_decrypt(ctx, in, out, inlen);
        if (ret != 0) {
            CRYPTO_gcm128_release(ctx);
            return -1;
        }
    }
    
    // Verify tag
    ret = CRYPTO_gcm128_finish(ctx, tag, 16);
    
    // Clean up
    CRYPTO_gcm128_release(ctx);
    
    return ret;
}