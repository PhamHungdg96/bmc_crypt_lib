#include <string.h>
#include <stdlib.h>
#include <bmc_crypt/crypto_core_aes.h>
#include <bmc_crypt/private/aes_internal.h>
#include <bmc_crypt/private/modes.h>
#include <bmc_crypt/randombytes.h>
#include <bmc_crypt/utils.h>

/* =============================================================================
 * Forward declarations
 * ============================================================================= */

static int aes_ecb_update(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t inlen);
static int aes_cbc_update(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t inlen);
static int aes_ctr_update(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t inlen);
static int aes_gcm_update(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t inlen);
static int aes_ecb_finish(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         size_t *outlen);
static int aes_cbc_finish(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         size_t *outlen);
static int aes_ctr_finish(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         size_t *outlen);
static int aes_gcm_finish(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         size_t *outlen);

/* =============================================================================
 * Internal helper functions
 * ============================================================================= */



static void xor_block(unsigned char *out, const unsigned char *a, const unsigned char *b) {
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}



/* =============================================================================
 * Context initialization
 * ============================================================================= */

int crypto_core_aes_init(crypto_core_aes_ctx *ctx,
                         const unsigned char *key,
                         size_t keylen,
                         aes_mode_t mode,
                         int enc,
                         const unsigned char *iv_nonce,
                         size_t iv_nonce_len) {
    if (!ctx || !key) {
        return -1;
    }

    if(enc!=AES_ENCRYPT && enc!=AES_DECRYPT){
        return -1;
    }
    
    /* Validate key length */
    if (keylen != 16 && keylen != 24 && keylen != 32) {
        return -1;
    }
    
    /* Validate IV/nonce length based on mode */
    switch (mode) {
        case AES_MODE_ECB:
            /* ECB doesn't need IV */
            break;
        case AES_MODE_CBC:
            if (iv_nonce_len != 16) return -1;
            break;
        case AES_MODE_CTR:
            if (iv_nonce_len != 16) return -1;
            break;
        case AES_MODE_GCM:
            if (iv_nonce_len != 12) return -1;
            break;
        default:
            return -1;
    }
    
    /* Clear context */
    bmc_crypt_memzero(ctx, sizeof(crypto_core_aes_ctx));

    /* Set block cipher functions */
    ctx->block_encrypt = AES_encrypt;
    ctx->block_decrypt = AES_decrypt;
    
    /* Set mode and encryption flag */
    ctx->mode = mode;
    ctx->enc = enc;
    /* Set up AES key */
    int bits = (int)(keylen * 8);
    int enc_tmp = ctx->enc;
    if(mode == AES_MODE_CTR || mode == AES_MODE_GCM){
        enc_tmp = AES_ENCRYPT;
    }
    int ret = crypto_core_aes_set_key(key, bits, &ctx->key, enc_tmp);
    if (ret != 0) {
        return -1;
    }
    
    /* Initialize mode-specific data */
    switch (mode) {
        case AES_MODE_ECB:
            /* No additional initialization needed */
            break;
            
        case AES_MODE_CBC:
            if (iv_nonce) {
                memcpy(ctx->mode_data.cbc.iv, iv_nonce, 16);
            }
            ctx->mode_data.cbc.last_block_len = 0;
            break;
            
        case AES_MODE_CTR:
            if (iv_nonce) {
                memcpy(ctx->mode_data.ctr.nonce, iv_nonce, 16);
            }
            ctx->mode_data.ctr.keystream_pos = 0; /* Initialize keystream position */
            break;
            
        case AES_MODE_GCM:
            
            /* Create and initialize GCM context */
            ctx->mode_data.gcm.gcm_ctx = CRYPTO_gcm128_new(&ctx->key, ctx->block_encrypt);
            if (!ctx->mode_data.gcm.gcm_ctx) {
                return -1;
            }
            if (iv_nonce)
                /* Set IV */
                CRYPTO_gcm128_setiv(ctx->mode_data.gcm.gcm_ctx, iv_nonce, 12);
            
            /* Initialize tag buffer */
            bmc_crypt_memzero(ctx->mode_data.gcm.tag, 16);
            break;
    }
    
    ctx->initialized = 1;
    return 0;
}

/* =============================================================================
 * Context update
 * ============================================================================= */

int crypto_core_aes_update(crypto_core_aes_ctx *ctx,
                          unsigned char *out,
                          const unsigned char *in,
                          size_t inlen) {
    if (!ctx || !ctx->initialized || !out || !in) {
        return -1;
    }
    
    switch (ctx->mode) {
        case AES_MODE_ECB:
            return aes_ecb_update(ctx, out, in, inlen);
            
        case AES_MODE_CBC:
            return aes_cbc_update(ctx, out, in, inlen);
            
        case AES_MODE_CTR:
            return aes_ctr_update(ctx, out, in, inlen);
            
        case AES_MODE_GCM:
            return aes_gcm_update(ctx, out, in, inlen);
            
        default:
            return -1;
    }
}

/* =============================================================================
 * Context finish
 * ============================================================================= */

int crypto_core_aes_finish(crypto_core_aes_ctx *ctx,
                          unsigned char *out,
                          size_t *outlen) {
    if (!ctx || !ctx->initialized || !out || !outlen) {
        return -1;
    }
    
    *outlen = 0;
    
    switch (ctx->mode) {
        case AES_MODE_ECB:
            return aes_ecb_finish(ctx, out, outlen);
            
        case AES_MODE_CBC:
            return aes_cbc_finish(ctx, out, outlen);
            
        case AES_MODE_CTR:
            return aes_ctr_finish(ctx, out, outlen);
            
        case AES_MODE_GCM:
            return aes_gcm_finish(ctx, out, outlen);
            
        default:
            return -1;
    }
}

/* =============================================================================
 * Context reset
 * ============================================================================= */

int crypto_core_aes_reset(crypto_core_aes_ctx *ctx,
                         const unsigned char *iv_nonce,
                         size_t iv_nonce_len) {
    if (!ctx || !ctx->initialized || !iv_nonce) {
        return -1;
    }
    
    /* Validate IV/nonce length based on mode */
    switch (ctx->mode) {
        case AES_MODE_ECB:
            /* ECB doesn't need IV */
            break;
        case AES_MODE_CBC:
            if (iv_nonce_len != 16) return -1;
            break;
        case AES_MODE_CTR:
            if (iv_nonce_len != 16) return -1;
            break;
        case AES_MODE_GCM:
            if (iv_nonce_len != 12) return -1;
            break;
        default:
            return -1;
    }
    
    /* Reset mode-specific data */
    switch (ctx->mode) {
        case AES_MODE_ECB:
            /* No reset needed */
            break;
            
        case AES_MODE_CBC:
            memcpy(ctx->mode_data.cbc.iv, iv_nonce, 16);
            ctx->mode_data.cbc.last_block_len = 0;
            break;
            
        case AES_MODE_CTR:
            memcpy(ctx->mode_data.ctr.nonce, iv_nonce, 16);
            ctx->mode_data.ctr.keystream_pos = 0;
            break;
            
        case AES_MODE_GCM:
            if(iv_nonce)
                /* Reset GCM context with new IV */
                CRYPTO_gcm128_setiv(ctx->mode_data.gcm.gcm_ctx, iv_nonce, 12);
            /* Clear tag buffer */
            bmc_crypt_memzero(ctx->mode_data.gcm.tag, 16);
            break;
    }
    
    return 0;
}

/* =============================================================================
 * Context cleanup
 * ============================================================================= */

int crypto_core_aes_cleanup(crypto_core_aes_ctx *ctx) {
    if (!ctx || !ctx->initialized) {
        return -1;
    }
    
    /* Clean up mode-specific resources */
    switch (ctx->mode) {
        case AES_MODE_ECB:
        case AES_MODE_CBC:
        case AES_MODE_CTR:
            /* No cleanup needed */
            break;
            
        case AES_MODE_GCM:
            if (ctx->mode_data.gcm.gcm_ctx) {
                CRYPTO_gcm128_release(ctx->mode_data.gcm.gcm_ctx);
                ctx->mode_data.gcm.gcm_ctx = NULL;
            }
            break;
    }
    
    /* Clear context */
    bmc_crypt_memzero(ctx, sizeof(crypto_core_aes_ctx));
    return 0;
}

/* =============================================================================
 * Mode-specific update functions
 * ============================================================================= */

static int aes_ecb_update(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t inlen) {
    /* Handle empty input */
    if (inlen == 0) {
        return 0;
    }
    
    size_t blocks = inlen / 16;
    size_t processed = blocks * 16;
    
    /* Process full blocks */
    for (size_t i = 0; i < blocks; i++) {
        if (ctx->enc) {
            ctx->block_encrypt(in + i * 16, out + i * 16, &ctx->key);
        } else {
            ctx->block_decrypt(in + i * 16, out + i * 16, &ctx->key);
        }
    }
    
    return (int)processed;
}

static int aes_cbc_update(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t inlen) {
    /* Handle empty input */
    if (inlen == 0) {
        return 0;
    }
    
    size_t blocks = inlen / 16;
    size_t processed = blocks * 16;
    size_t remain = inlen % 16;

    if (ctx->enc) {
        /* CBC encryption */
        for (size_t i = 0; i < blocks; i++) {
            xor_block(out + i * 16, in + i * 16, ctx->mode_data.cbc.iv);
            ctx->block_encrypt(out + i * 16, out + i * 16, &ctx->key);
            memcpy(ctx->mode_data.cbc.iv, out + i * 16, 16);
        }
        // Lưu phần dư vào last_block
        if (remain > 0) {
            memcpy(ctx->mode_data.cbc.last_block, in + blocks * 16, remain);
            ctx->mode_data.cbc.last_block_len = remain;
        } else {
            ctx->mode_data.cbc.last_block_len = 0;
        }
    } else {
        if(remain == 0) {
            blocks--;
            remain = 16;
            processed = blocks * 16;
        }
        /* CBC decryption */
        for (size_t i = 0; i < blocks; i++) {
            unsigned char temp[16];
            memcpy(temp, in + i * 16, 16);
            ctx->block_decrypt(in + i * 16, out + i * 16, &ctx->key);
            xor_block(out + i * 16, out + i * 16, ctx->mode_data.cbc.iv);
            memcpy(ctx->mode_data.cbc.iv, temp, 16);
        }
        // Lưu phần dư vào last_block (nếu có)
        if (remain > 0) {
            memcpy(ctx->mode_data.cbc.last_block, in + blocks * 16, remain);
            ctx->mode_data.cbc.last_block_len = remain;
        } else {
            ctx->mode_data.cbc.last_block_len = 0;
        }
    }
    return (int)processed;
}

static int aes_ctr_update(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t inlen) {
    /* Handle empty input */
    if (inlen == 0) {
        return 0;
    }
    
    /* Use the optimized CTR implementation from modes/ctr_128.c */
    CRYPTO_ctr128_encrypt(in, out, inlen, &ctx->key, 
                         ctx->mode_data.ctr.nonce,
                         ctx->mode_data.ctr.keystream, 
                         &ctx->mode_data.ctr.keystream_pos,
                         ctx->block_encrypt);
    
    return (int)inlen;
}

static int aes_gcm_update(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t inlen) {
    int ret;
    
    /* Handle empty input */
    if (inlen == 0) {
        return 0;
    }

    if(!ctx->mode_data.gcm.gcm_ctx){
        return -1;
    }
    
    if (ctx->enc) {
        ret = CRYPTO_gcm128_encrypt(ctx->mode_data.gcm.gcm_ctx, in, out, inlen);
    } else {
        ret = CRYPTO_gcm128_decrypt(ctx->mode_data.gcm.gcm_ctx, in, out, inlen);
    }
    
    /* GCM functions return 0 on success, -1 on error */
    /* We need to return number of bytes processed on success */
    if (ret == 0) {
        return (int)inlen;
    } else {
        return -1;
    }
}

/* =============================================================================
 * Mode-specific finish functions
 * ============================================================================= */

static int aes_ecb_finish(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         size_t *outlen) {
    /* ECB doesn't need padding or finalization */
    *outlen = 0;
    return 0;
}

static int aes_cbc_finish(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         size_t *outlen) {
    if (ctx->enc) {
        /* PKCS7 padding for encryption */
        int padding = 16 - (ctx->mode_data.cbc.last_block_len % 16);
        if (padding == 16) padding = 0;
        if (padding > 0) {
            for (int i = 0; i < padding; i++) {
                ctx->mode_data.cbc.last_block[ctx->mode_data.cbc.last_block_len + i] = (unsigned char)padding;
            }
            xor_block(out, ctx->mode_data.cbc.last_block, ctx->mode_data.cbc.iv);
            ctx->block_encrypt(out, out, &ctx->key);
            *outlen = 16;
        } else {
            *outlen = 0;
        }
    } else {
        /* Remove padding for decryption */
        if (ctx->mode_data.cbc.last_block_len == 16) {
            // Giải mã block cuối
            unsigned char tmp[16];
            ctx->block_decrypt(ctx->mode_data.cbc.last_block, tmp, &ctx->key);
            xor_block(tmp, tmp, ctx->mode_data.cbc.iv);
            int padding = tmp[15];
            if (padding <= 0 || padding > 16) {
                return -1; // padding lỗi
            }
            // Kiểm tra tất cả byte padding
            for (int i = 16 - padding; i < 16; i++) {
                if (tmp[i] != (unsigned char)padding) {
                    return -1; // padding lỗi
                }
            }
            memcpy(out, tmp, 16 - padding);
            *outlen = 16 - padding;
        } else {
            *outlen = 0;
        }
    }
    return 0;
}

static int aes_ctr_finish(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         size_t *outlen) {
    /* CTR mode doesn't need padding or finalization */
    *outlen = 0;
    return 0;
}

static int aes_gcm_finish(crypto_core_aes_ctx *ctx,
                         unsigned char *out,
                         size_t *outlen) {
    *outlen = 0;
    
    if (ctx->enc) {
        /* Generate authentication tag */
        CRYPTO_gcm128_tag(ctx->mode_data.gcm.gcm_ctx, ctx->mode_data.gcm.tag, 16);
    } else {
        /* Verify authentication tag */
        /* First, generate the expected tag from the processed data */
        unsigned char expected_tag[16];
        CRYPTO_gcm128_tag(ctx->mode_data.gcm.gcm_ctx, expected_tag, 16);
        
        /* Compare with the provided tag */
        if (bmc_crypt_memcmp(expected_tag, ctx->mode_data.gcm.tag, 16) != 0) {
            return -1; /* Authentication failed */
        }
    }
    
    return 0;
}

/* =============================================================================
 * GCM-specific functions
 * ============================================================================= */

int crypto_core_aes_gcm_aad(crypto_core_aes_ctx *ctx,
                           const unsigned char *aad,
                           size_t aadlen) {
    if (!ctx || !ctx->initialized || ctx->mode != AES_MODE_GCM) {
        return -1;
    }
    if (aad && aadlen > 0) {
        return CRYPTO_gcm128_aad(ctx->mode_data.gcm.gcm_ctx, aad, aadlen);
    }
    return 0;
}

int crypto_core_aes_gcm_get_tag(crypto_core_aes_ctx *ctx,
                               unsigned char *tag) {
    if (!ctx || !ctx->initialized || ctx->mode != AES_MODE_GCM || !ctx->enc || !tag) {
        return -1;
    }
    
    /* Copy the generated tag */
    memcpy(tag, ctx->mode_data.gcm.tag, 16);
    return 0;
}

int crypto_core_aes_gcm_set_tag(crypto_core_aes_ctx *ctx,
                               const unsigned char *tag) {
    if (!ctx || !ctx->initialized || ctx->mode != AES_MODE_GCM || ctx->enc || !tag) {
        return -1;
    }
    
    /* Set the tag for verification */
    memcpy(ctx->mode_data.gcm.tag, tag, 16);
    return 0;
} 