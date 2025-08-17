#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/crypto_core_aes.h>

// Test vectors for AES-128 CBC
static const unsigned char test_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const unsigned char test_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char test_plaintext[32] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};

static const unsigned char expected_ciphertext_block1[16] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d
};


void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void test_aes_cbc_encryption() {
    printf("Testing AES CBC encryption...\n");
    
    crypto_core_aes_ctx *ctx;
    unsigned char ciphertext[64];
    size_t outlen;
    
    // Initialize context for encryption
    int ret = crypto_core_aes_init(&ctx, test_key, 16, AES_MODE_CBC, 1, test_iv, 16);
    if (ret != 0) {
        printf("ERROR: Failed to initialize encryption context\n");
        exit(1);
    }
    
    // Encrypt data
    int processed = crypto_core_aes_update(ctx, ciphertext, test_plaintext, 32);
    if (processed != 32) {
        printf("ERROR: AES CBC encryption failed\n");
        exit(1);
    }
    
    // Finish encryption
    ret = crypto_core_aes_finish(ctx, ciphertext + processed, &outlen);
    if (ret != 0) {
        printf("ERROR: AES CBC encryption finish failed\n");
        exit(1);
    }
    
    // Verify first block ciphertext (we know the expected result)
    if (memcmp(ciphertext, expected_ciphertext_block1, 16) != 0) {
        printf("ERROR: First block ciphertext mismatch\n");
        print_hex("Expected", expected_ciphertext_block1, 16);
        print_hex("Got     ", ciphertext, 16);
        exit(1);
    }
    crypto_core_aes_cleanup(ctx);
    printf("AES CBC encryption test passed\n");
}

void test_aes_cbc_decryption() {
    printf("Testing AES CBC decryption...\n");
    
    crypto_core_aes_ctx *encrypt_ctx, *decrypt_ctx;
    unsigned char decrypted[64];
    unsigned char ciphertext[64];
    size_t outlen_enc = 0, outlen_dec = 0;
    
    // Initialize encryption context to get ciphertext
    int ret = crypto_core_aes_init(&encrypt_ctx, test_key, 16, AES_MODE_CBC, 1, test_iv, 16);
    if (ret != 0) {
        printf("ERROR: Failed to initialize encryption context for decryption test\n");
        exit(1);
    }
    
    // First encrypt to get ciphertext
    int enc_processed = crypto_core_aes_update(encrypt_ctx, ciphertext, test_plaintext, 32);
    if (enc_processed != 32) {
        printf("ERROR: Failed to encrypt data for decryption test\n");
        exit(1);
    }
    ret = crypto_core_aes_finish(encrypt_ctx, ciphertext + enc_processed, &outlen_enc);
    if (ret != 0) {
        printf("ERROR: Failed to finish encryption for decryption test\n");
        exit(1);
    }
    crypto_core_aes_cleanup(encrypt_ctx);
    size_t ciphertext_len = (size_t)enc_processed + outlen_enc;
    printf("OK %d\n", ciphertext_len);

    // Initialize decryption context
    ret = crypto_core_aes_init(&decrypt_ctx, test_key, 16, AES_MODE_CBC, 0, test_iv, 16);
    if (ret != 0) {
        printf("ERROR: Failed to initialize decryption context\n");
        exit(1);
    }
    
    // Decrypt data
    int dec_processed  = crypto_core_aes_update(decrypt_ctx, decrypted, ciphertext, ciphertext_len);
    if (dec_processed  != (int)(ciphertext_len - 16)) {
        printf("ERROR: AES CBC decryption failed\n");
        exit(1);
    }
    
    ret = crypto_core_aes_finish(decrypt_ctx, decrypted + dec_processed, &outlen_dec);
    if (ret != 0) {
        printf("ERROR: AES CBC decryption finish failed\n");
        exit(1);
    }
    size_t plaintext_len = (size_t)dec_processed + outlen_dec;
    // Verify decrypted text matches original plaintext
    if (plaintext_len != 32 || memcmp(decrypted, test_plaintext, 32) != 0) {
        printf("ERROR: Decryption result mismatch\n");
        print_hex("Expected", test_plaintext, 32);
        print_hex("Got     ", decrypted, 32);
        exit(1);
    }
    crypto_core_aes_cleanup(decrypt_ctx);
    printf("AES CBC decryption test passed\n");
}

void test_aes_cbc_roundtrip() {
    printf("Testing AES CBC roundtrip (encrypt -> decrypt)...\n");
    
    crypto_core_aes_ctx *encrypt_ctx, *decrypt_ctx;
    unsigned char ciphertext[80];
    unsigned char decrypted[80];
    unsigned char random_data[64];
    unsigned char iv[16];
    size_t outlen;
    
    // Generate random test data
    for (int i = 0; i < 64; i++) {
        random_data[i] = rand() % 256;
    }
    
    // Generate random IV
    for (int i = 0; i < 16; i++) {
        iv[i] = rand() % 256;
    }
    
    // Initialize encryption context
    int ret = crypto_core_aes_init(&encrypt_ctx, test_key, 16, AES_MODE_CBC, 1, iv, 16);
    if (ret != 0) {
        printf("ERROR: Failed to initialize encryption context in roundtrip test\n");
        exit(1);
    }
    
    // Initialize decryption context
    ret = crypto_core_aes_init(&decrypt_ctx, test_key, 16, AES_MODE_CBC, 0, iv, 16);
    if (ret != 0) {
        printf("ERROR: Failed to initialize decryption context in roundtrip test\n");
        exit(1);
    }
    
    // Encrypt
    int processed = crypto_core_aes_update(encrypt_ctx, ciphertext, random_data, 64);
    if (processed != 64) {
        printf("ERROR: AES CBC encryption failed in roundtrip test\n");
        exit(1);
    }
    
    ret = crypto_core_aes_finish(encrypt_ctx, ciphertext + processed, &outlen);
    if (ret != 0) {
        printf("ERROR: AES CBC encryption finish failed in roundtrip test\n");
        exit(1);
    }
    size_t ciphertext_len = (size_t)processed + outlen;
    
    // Decrypt
    processed = crypto_core_aes_update(decrypt_ctx, decrypted, ciphertext, ciphertext_len);
    if (processed != 64) {
        printf("ERROR: AES CBC decryption failed in roundtrip test\n");
        exit(1);
    }
    
    ret = crypto_core_aes_finish(decrypt_ctx, decrypted + processed, &outlen);
    if (ret != 0) {
        printf("ERROR: AES CBC decryption finish failed in roundtrip test\n");
        exit(1);
    }
    size_t plaintext_len = (size_t)processed + outlen;
    // Verify roundtrip
    if (plaintext_len!=64 || memcmp(decrypted, random_data, 64) != 0) {
        printf("ERROR: Roundtrip test failed\n");
        print_hex("Original", random_data, 32);
        print_hex("Decrypted", decrypted, 32);
        exit(1);
    }
    
    printf("AES CBC roundtrip test passed\n");
}

void test_aes_cbc_padding() {
    printf("Testing AES CBC with different data lengths...\n");
    
    crypto_core_aes_ctx *encrypt_ctx, *decrypt_ctx;
    unsigned char iv[16];
    size_t outlen;
    
    // Generate random IV
    for (int i = 0; i < 16; i++) {
        iv[i] = rand() % 256;
    }
    
    // Test different data lengths
    const int test_lengths[] = {16, 32, 48, 64};
    const int num_tests = sizeof(test_lengths) / sizeof(test_lengths[0]);
    
    for (int test_idx = 0; test_idx < num_tests; test_idx++) {
        int len = test_lengths[test_idx];
        unsigned char *data = malloc(len);
        unsigned char *ciphertext = malloc(len);
        unsigned char *decrypted = malloc(len);
        
        // Generate random data
        for (int i = 0; i < len; i++) {
            data[i] = rand() % 256;
        }
        
        // Initialize encryption context
        int ret = crypto_core_aes_init(&encrypt_ctx, test_key, 16, AES_MODE_CBC, 1, iv, 16);
        if (ret != 0) {
            printf("ERROR: Failed to initialize encryption context for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        // Encrypt
        int processed = crypto_core_aes_update(encrypt_ctx, ciphertext, data, len);
        if (processed != len) {
            printf("ERROR: AES CBC encryption failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        ret = crypto_core_aes_finish(encrypt_ctx, ciphertext + processed, &outlen);
        if (ret != 0) {
            printf("ERROR: AES CBC encryption finish failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        // Initialize decryption context
        ret = crypto_core_aes_init(&decrypt_ctx, test_key, 16, AES_MODE_CBC, 0, iv, 16);
        if (ret != 0) {
            printf("ERROR: Failed to initialize decryption context for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        // Decrypt
        processed = crypto_core_aes_update(decrypt_ctx, decrypted, ciphertext, len);
        if (processed != len) {
            printf("ERROR: AES CBC decryption failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        ret = crypto_core_aes_finish(decrypt_ctx, decrypted + processed, &outlen);
        if (ret != 0) {
            printf("ERROR: AES CBC decryption finish failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        // Verify
        if (memcmp(decrypted, data, len) != 0) {
            printf("ERROR: Padding test failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        free(data);
        free(ciphertext);
        free(decrypted);
    }
    
    printf("AES CBC padding test passed\n");
}

void test_aes_cbc_iv_modification() {
    printf("Testing AES CBC IV modification behavior...\n");
    
    crypto_core_aes_ctx *ctx;
    unsigned char iv1[16], iv2[16];
    size_t outlen;
    
    // Generate two different IVs
    for (int i = 0; i < 16; i++) {
        iv1[i] = rand() % 256;
        iv2[i] = rand() % 256;
    }
    
    // Make iv2 slightly different (increment last byte)
    iv2[15] = iv1[15] + 1;
    
    unsigned char plaintext[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    unsigned char ciphertext1[32], ciphertext2[32];
    
    // Encrypt with iv1
    int ret = crypto_core_aes_init(&ctx, test_key, 16, AES_MODE_CBC, 1, iv1, 16);
    if (ret != 0) {
        printf("ERROR: Failed to initialize context for iv1 test\n");
        exit(1);
    }
    
    int processed = crypto_core_aes_update(ctx, ciphertext1, plaintext, 16);
    if (processed != 16) {
        printf("ERROR: AES CBC encryption failed for iv1\n");
        exit(1);
    }
    
    ret = crypto_core_aes_finish(ctx, ciphertext1 + processed, &outlen);
    if (ret != 0) {
        printf("ERROR: AES CBC finish failed for iv1\n");
        exit(1);
    }

    size_t ciphertext_len = processed+outlen;
    
    // Encrypt with iv2
    ret = crypto_core_aes_init(&ctx, test_key, 16, AES_MODE_CBC, 1, iv2, 16);
    if (ret != 0) {
        printf("ERROR: Failed to initialize context for iv2 test\n");
        exit(1);
    }
    
    processed = crypto_core_aes_update(ctx, ciphertext2, plaintext, 16);
    if (processed != ciphertext_len - 16) {
        printf("ERROR: AES CBC encryption failed for iv2\n");
        exit(1);
    }
    
    ret = crypto_core_aes_finish(ctx, ciphertext2 + processed, &outlen);
    if (ret != 0) {
        printf("ERROR: AES CBC finish failed for iv2\n");
        exit(1);
    }
    crypto_core_aes_cleanup(ctx);
    // Results should be different due to different IVs
    if (memcmp(ciphertext1, ciphertext2, 16) == 0) {
        printf("ERROR: Different IVs produced same ciphertext\n");
        print_hex("IV1 result", ciphertext1, 16);
        print_hex("IV2 result", ciphertext2, 16);
        exit(1);
    }
    
    printf("AES CBC IV modification test passed\n");
}

void test_aes256_cbc_arbitrary_length() {
    printf("Testing AES-256 CBC with arbitrary message length...\n");
    
    // Dữ liệu test
    const unsigned char key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char *message = "Hello, Bob!";
    size_t message_len = strlen(message);
    
    crypto_core_aes_ctx *enc_ctx, *dec_ctx;
    unsigned char ciphertext[64];
    unsigned char decrypted[64];
    unsigned char final_block[32];
    size_t outlen = 0;
    
    // Encrypt
    if (crypto_core_aes_init(&enc_ctx, key, 32, AES_MODE_CBC, 1, iv, 16) != 0) {
        printf("ERROR: AES-256 CBC encrypt init failed\n");
        exit(1);
    }
    int clen = crypto_core_aes_update(enc_ctx, ciphertext, message, message_len);
    printf("clen: %d\n", clen);
    size_t total_clen = clen;
    if (crypto_core_aes_finish(enc_ctx, ciphertext + clen, &outlen) != 0) {
        printf("ERROR: AES-256 CBC encrypt finish failed\n");
        exit(1);
    }
    total_clen += outlen;
    printf("Ciphertext: ");
    for (size_t i = 0; i < total_clen; i++) printf("%02x", ciphertext[i]);
    printf("\n");
    
    // Decrypt
    if (crypto_core_aes_init(&dec_ctx, key, 32, AES_MODE_CBC, 0, iv, 16) != 0) {
        printf("ERROR: AES-256 CBC decrypt init failed\n");
        exit(1);
    }
    int dlen = crypto_core_aes_update(dec_ctx, decrypted, ciphertext, total_clen);
    size_t total_dlen = dlen;
    printf("dlen: %zu\n", dlen);
    if (crypto_core_aes_finish(dec_ctx, decrypted + dlen, &outlen) != 0) {
        printf("ERROR: AES-256 CBC decrypt finish failed\n");
        exit(1);
    }
    total_dlen += outlen;
    printf("Decrypted: %.*s\n", (int)total_dlen, decrypted);
    printf("total_dlen: %zu\n", total_dlen);
    // Sau khi finish giải mã
    // outlen là số byte thực sự của block cuối (đã loại padding)
    if (total_dlen != message_len || memcmp(decrypted, message, message_len) != 0) {
        printf("ERROR: AES-256 CBC roundtrip failed!\n");
        exit(1);
    }
    printf("AES-256 CBC arbitrary length test passed!\n");
}

int main() {
    printf("Starting AES CBC tests...\n");
    printf("========================\n");
    
    // Initialize random seed
    // bmc_crypt_init();
    
    test_aes_cbc_encryption();
    test_aes_cbc_decryption();
    // test_aes_cbc_roundtrip();
    // test_aes_cbc_padding();
    // test_aes_cbc_iv_modification();
    // Thêm test mới:
    test_aes256_cbc_arbitrary_length();
    
    printf("========================\n");
    printf("All AES CBC tests passed!\n");
    
    return 0;
} 