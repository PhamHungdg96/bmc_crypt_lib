#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/crypto_core_aes.h>
#include <bmc_crypt/randombytes.h>

/* =============================================================================
 * NIST Test Vectors for AES
 * ============================================================================= */

/* Test Vector 1: AES-128 ECB */
static const unsigned char aes128_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char aes128_plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const unsigned char aes128_ciphertext[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};

/* Test Vector 2: AES-256 ECB */
static const unsigned char aes256_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const unsigned char aes256_plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const unsigned char aes256_ciphertext[16] = {
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
};

/* Test Vector 3: AES-128 CBC */
static const unsigned char aes128_cbc_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const unsigned char aes128_cbc_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char aes128_cbc_plaintext[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

static const unsigned char aes128_cbc_ciphertext[16] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d
};

/* Test Vector 4: AES-128 CTR */
static const unsigned char aes128_ctr_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const unsigned char aes128_ctr_nonce[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

static const unsigned char aes128_ctr_plaintext[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const unsigned char aes128_ctr_ciphertext[64] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
    0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
    0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
    0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
    0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
    0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
    0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
};

/* Test Vector 5: AES-128 GCM */
static const unsigned char aes128_gcm_key[16] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

static const unsigned char aes128_gcm_nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};

static const unsigned char aes128_gcm_aad[16] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef
};

static const unsigned char aes128_gcm_plaintext[16] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a
};

static const unsigned char aes128_gcm_ciphertext[16] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
    0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c
};

static const unsigned char aes128_gcm_tag[16] = {
    0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
    0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};

/* =============================================================================
 * Test Functions
 * ============================================================================= */

/* Test AES-128 ECB with NIST vector */
static int test_aes128_ecb_nist(void) {
    printf("Testing AES-128 ECB with NIST vector...\n");
    
    crypto_core_aes_ctx *ctx;
    unsigned char iv[16] = {0}; /* ECB doesn't use IV */
    unsigned char ciphertext[16];
    unsigned char decrypted[16];
    size_t outlen;
    int ret;
    
    /* Initialize for encryption */
    ctx = crypto_core_aes_init_ex(aes128_key, 16, AES_MODE_ECB, 1, iv, 16);
    assert(ret == 0);
    
    /* Encrypt data */
    int processed = crypto_core_aes_update(ctx, ciphertext, aes128_plaintext, 16);
    assert(processed == 16);
    
    /* Finish encryption */
    ret = crypto_core_aes_finish(ctx, ciphertext + processed, &outlen);
    assert(ret == 0);
    
    /* Verify ciphertext matches NIST vector */
    assert(memcmp(ciphertext, aes128_ciphertext, 16) == 0);
    printf("  AES-128 ECB encryption matches NIST vector\n");
    
    /* Initialize for decryption */
    ctx = crypto_core_aes_init_ex(aes128_key, 16, AES_MODE_ECB, 0, iv, 16);
    assert(ret == 0);
    
    /* Decrypt data */
    processed = crypto_core_aes_update(ctx, decrypted, ciphertext, 16);
    assert(processed == 16);
    
    /* Finish decryption */
    ret = crypto_core_aes_finish(ctx, decrypted + processed, &outlen);
    assert(ret == 0);
    
    /* Verify decryption matches original plaintext */
    assert(memcmp(decrypted, aes128_plaintext, 16) == 0);
    printf("  AES-128 ECB decryption successful\n");
    
    return 0;
}

/* Test AES-256 ECB with NIST vector */
static int test_aes256_ecb_nist(void) {
    printf("Testing AES-256 ECB with NIST vector...\n");
    
    crypto_core_aes_ctx ctx;
    unsigned char iv[16] = {0}; /* ECB doesn't use IV */
    unsigned char ciphertext[16];
    unsigned char decrypted[16];
    size_t outlen;
    
    /* Initialize for encryption */
    int ret = crypto_core_aes_init(&ctx, aes256_key, 32, AES_MODE_ECB, 1, iv, 16);
    assert(ret == 0);
    
    /* Encrypt data */
    int processed = crypto_core_aes_update(&ctx, ciphertext, aes256_plaintext, 16);
    assert(processed == 16);
    
    /* Finish encryption */
    ret = crypto_core_aes_finish(&ctx, ciphertext + processed, &outlen);
    assert(ret == 0);
    
    /* Verify ciphertext matches NIST vector */
    assert(memcmp(ciphertext, aes256_ciphertext, 16) == 0);
    printf("  AES-256 ECB encryption matches NIST vector\n");
    
    /* Initialize for decryption */
    ret = crypto_core_aes_init(&ctx, aes256_key, 32, AES_MODE_ECB, 0, iv, 16);
    assert(ret == 0);
    
    /* Decrypt data */
    processed = crypto_core_aes_update(&ctx, decrypted, ciphertext, 16);
    assert(processed == 16);
    
    /* Finish decryption */
    ret = crypto_core_aes_finish(&ctx, decrypted + processed, &outlen);
    assert(ret == 0);
    
    /* Verify decryption matches original plaintext */
    assert(memcmp(decrypted, aes256_plaintext, 16) == 0);
    printf("  AES-256 ECB decryption successful\n");
    
    return 0;
}

/* Test AES-128 CBC with NIST vector */
static int test_aes128_cbc_nist(void) {
    printf("Testing AES-128 CBC with NIST vector...\n");
    
    crypto_core_aes_ctx ctx;
    unsigned char ciphertext[32];
    unsigned char decrypted[32];
    size_t outlen;
    
    /* Initialize for encryption */
    int ret = crypto_core_aes_init(&ctx, aes128_cbc_key, 16, AES_MODE_CBC, 1, aes128_cbc_iv, 16);
    assert(ret == 0);
    
    /* Encrypt data */
    int processed = crypto_core_aes_update(&ctx, ciphertext, aes128_cbc_plaintext, 16);
    assert(processed == 32);
    
    /* Finish encryption */
    ret = crypto_core_aes_finish(&ctx, ciphertext + processed, &outlen);
    assert(ret == 0);
    
    /* Verify ciphertext matches NIST vector */
    assert(memcmp(ciphertext, aes128_cbc_ciphertext, 32) == 0);
    printf("  AES-128 CBC encryption matches NIST vector\n");
    
    /* Initialize for decryption */
    ret = crypto_core_aes_init(&ctx, aes128_cbc_key, 16, AES_MODE_CBC, 0, aes128_cbc_iv, 16);
    assert(ret == 0);
    
    /* Decrypt data */
    processed = crypto_core_aes_update(&ctx, decrypted, ciphertext, 32);
    assert(processed == 32);
    
    /* Finish decryption */
    ret = crypto_core_aes_finish(&ctx, decrypted + processed, &outlen);
    assert(ret == 0);
    
    /* Verify decryption matches original plaintext */
    assert(memcmp(decrypted, aes128_cbc_plaintext, 16) == 0);
    printf("  AES-128 CBC decryption successful\n");
    
    return 0;
}

/* Test AES-128 CTR with NIST vector */
static int test_aes128_ctr_nist(void) {
    printf("Testing AES-128 CTR with NIST vector...\n");
    
    crypto_core_aes_ctx ctx;
    unsigned char ciphertext[64];
    unsigned char decrypted[64];
    size_t outlen;
    
    /* Initialize for encryption */
    int ret = crypto_core_aes_init(&ctx, aes128_ctr_key, 16, AES_MODE_CTR, 1, aes128_ctr_nonce, 16);
    assert(ret == 0);
    
    /* Encrypt data */
    int processed = crypto_core_aes_update(&ctx, ciphertext, aes128_ctr_plaintext, sizeof(aes128_ctr_plaintext));
    assert(processed == sizeof(aes128_ctr_plaintext));
    
    /* Finish encryption */
    ret = crypto_core_aes_finish(&ctx, ciphertext + processed, &outlen);
    assert(ret == 0);
    
    /* Verify ciphertext matches NIST vector */
    assert(memcmp(ciphertext, aes128_ctr_ciphertext, sizeof(aes128_ctr_ciphertext)) == 0);
    printf("  AES-128 CTR encryption matches NIST vector\n");
    
    /* Initialize for decryption */
    ret = crypto_core_aes_init(&ctx, aes128_ctr_key, 16, AES_MODE_CTR, 0, aes128_ctr_nonce, 16);
    assert(ret == 0);
    
    /* Decrypt data */
    processed = crypto_core_aes_update(&ctx, decrypted, ciphertext, sizeof(ciphertext));
    assert(processed == sizeof(ciphertext));
    
    /* Finish decryption */
    ret = crypto_core_aes_finish(&ctx, decrypted + processed, &outlen);
    assert(ret == 0);
    
    /* Verify decryption matches original plaintext */
    assert(memcmp(decrypted, aes128_ctr_plaintext, sizeof(aes128_ctr_plaintext)) == 0);
    printf("  AES-128 CTR decryption successful\n");
    
    return 0;
}

/* Test AES-128 GCM with NIST vector */
static int test_aes128_gcm_nist(void) {
    printf("Testing AES-128 GCM with NIST vector...\n");
    
    crypto_core_aes_ctx ctx;
    unsigned char ciphertext[16];
    unsigned char decrypted[16];
    unsigned char tag[16];
    size_t outlen;
    
    /* Initialize for encryption */
    int ret = crypto_core_aes_init(&ctx, aes128_gcm_key, 16, AES_MODE_GCM, 1, aes128_gcm_nonce, 12);
    assert(ret == 0);
    
    /* Verify GCM context is created */
    assert(ctx.mode_data.gcm.gcm_ctx != NULL);
    
    /* Add AAD */
    ret = crypto_core_aes_gcm_aad(&ctx, aes128_gcm_aad, 16);
    assert(ret == 0);
    
    /* Encrypt data */
    int processed = crypto_core_aes_update(&ctx, ciphertext, aes128_gcm_plaintext, 16);
    assert(processed == 16);
    
    /* Finish encryption */
    ret = crypto_core_aes_finish(&ctx, ciphertext + processed, &outlen);
    assert(ret == 0);
    
    /* Get authentication tag */
    ret = crypto_core_aes_gcm_get_tag(&ctx, tag);
    assert(ret == 0);
    
    /* Verify ciphertext matches NIST vector */
    assert(memcmp(ciphertext, aes128_gcm_ciphertext, 16) == 0);
    printf("  AES-128 GCM encryption matches NIST vector\n");
    
    /* Verify tag matches NIST vector */
    assert(memcmp(tag, aes128_gcm_tag, 16) == 0);
    printf("  AES-128 GCM tag matches NIST vector\n");
    
    /* Clean up encryption context */
    crypto_core_aes_cleanup(&ctx);
    
    /* Initialize for decryption */
    ret = crypto_core_aes_init(&ctx, aes128_gcm_key, 16, AES_MODE_GCM, 0, aes128_gcm_nonce, 12);
    assert(ret == 0);
    
    /* Set authentication tag */
    ret = crypto_core_aes_gcm_set_tag(&ctx, tag);
    assert(ret == 0);
    
    /* Add AAD */
    ret = crypto_core_aes_gcm_aad(&ctx, aes128_gcm_aad, 16);
    assert(ret == 0);
    
    /* Decrypt data */
    processed = crypto_core_aes_update(&ctx, decrypted, ciphertext, 16);
    assert(processed == 16);
    
    /* Finish decryption */
    ret = crypto_core_aes_finish(&ctx, decrypted + processed, &outlen);
    assert(ret == 0);
    
    /* Verify decryption matches original plaintext */
    assert(memcmp(decrypted, aes128_gcm_plaintext, 16) == 0);
    printf("  AES-128 GCM decryption successful\n");
    
    /* Clean up decryption context */
    crypto_core_aes_cleanup(&ctx);
    
    return 0;
}

/* Test multiple blocks with padding */
static int test_multiple_blocks(void) {
    printf("Testing multiple blocks with padding...\n");
    
    crypto_core_aes_ctx ctx;
    unsigned char key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    const char *plaintext = "This is a test message that is longer than one block and needs padding.";
    size_t plaintext_len = strlen(plaintext);
    
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    size_t outlen;
    
    /* Test CBC mode with multiple blocks */
    int ret = crypto_core_aes_init(&ctx, key, 16, AES_MODE_CBC, 1, iv, 16);
    assert(ret == 0);
    
    int processed = crypto_core_aes_update(&ctx, ciphertext, (const unsigned char*)plaintext, plaintext_len);
    assert(processed >= 0);
    
    ret = crypto_core_aes_finish(&ctx, ciphertext + processed, &outlen);
    assert(ret == 0);
    
    printf("  CBC encrypted %d bytes (including padding)\n", processed + (int)outlen);
    
    /* Decrypt */
    ret = crypto_core_aes_init(&ctx, key, 16, AES_MODE_CBC, 0, iv, 16);
    assert(ret == 0);
    
    processed = crypto_core_aes_update(&ctx, decrypted, ciphertext, processed + (int)outlen);
    assert(processed >= 0);
    
    ret = crypto_core_aes_finish(&ctx, decrypted + processed, &outlen);
    assert(ret == 0);
    
    /* Verify decryption */
    assert(memcmp(decrypted, plaintext, plaintext_len) == 0);
    printf("  CBC multiple blocks decryption successful\n");
    
    return 0;
}

int main(void) {
    printf("Testing AES Context with NIST Test Vectors\n");
    printf("==========================================\n\n");
    bmc_crypt_init();
    /* Test NIST vectors */
    test_aes128_ecb_nist();
    test_aes256_ecb_nist();
    test_aes128_cbc_nist();
    test_aes128_ctr_nist();
    test_aes128_gcm_nist();
    
    /* Test multiple blocks */
    test_multiple_blocks();
    
    printf("\nAll NIST test vectors passed!\n");
    return 0;
} 