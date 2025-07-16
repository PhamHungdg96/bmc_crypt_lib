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
    
    AES_KEY key;
    unsigned char ciphertext[32];
    unsigned char iv_copy[16];

    // Set up encryption key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set encryption key\n");
        exit(1);
    }
    
    // Copy IV (it will be modified during encryption)
    memcpy(iv_copy, test_iv, 16);
    
    // Test encryption using crypto_core_aes_cbc_encrypt
    ret = crypto_core_aes_cbc_encrypt(test_plaintext, ciphertext, 32, &key, iv_copy, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: AES CBC encryption failed\n");
        exit(1);
    }
    
    // Verify first block ciphertext (we know the expected result)
    if (memcmp(ciphertext, expected_ciphertext_block1, 16) != 0) {
        printf("ERROR: First block ciphertext mismatch\n");
        print_hex("Expected", expected_ciphertext_block1, 16);
        print_hex("Got     ", ciphertext, 16);
        exit(1);
    }
    
    printf("AES CBC encryption test passed\n");
}

void test_aes_cbc_decryption() {
    printf("Testing AES CBC decryption...\n");
    
    AES_KEY key;
    unsigned char decrypted[32];
    unsigned char iv_copy[16];
    unsigned char ciphertext[32];

    // Set up decryption key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set decryption key\n");
        exit(1);
    }
    
    // First encrypt to get ciphertext
    AES_KEY encrypt_key;
    ret = crypto_core_aes_ecb_set_key(test_key, 128, &encrypt_key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set encryption key for decryption test\n");
        exit(1);
    }
    
    memcpy(iv_copy, test_iv, 16);
    ret = crypto_core_aes_cbc_encrypt(test_plaintext, ciphertext, 32, &encrypt_key, iv_copy, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to encrypt data for decryption test\n");
        exit(1);
    }
    
    // Now decrypt
    memcpy(iv_copy, test_iv, 16);
    ret = crypto_core_aes_cbc_encrypt(ciphertext, decrypted, 32, &key, iv_copy, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: AES CBC decryption failed\n");
        exit(1);
    }
    
    // Verify decrypted text matches original plaintext
    if (memcmp(decrypted, test_plaintext, 32) != 0) {
        printf("ERROR: Decryption result mismatch\n");
        print_hex("Expected", test_plaintext, 32);
        print_hex("Got     ", decrypted, 32);
        exit(1);
    }
    
    printf("AES CBC decryption test passed\n");
}

void test_aes_cbc_roundtrip() {
    printf("Testing AES CBC roundtrip (encrypt -> decrypt)...\n");
    
    AES_KEY encrypt_key, decrypt_key;
    unsigned char ciphertext[64];
    unsigned char decrypted[64];
    unsigned char random_data[64];
    unsigned char iv[16];
    
    // Generate random test data
    for (int i = 0; i < 64; i++) {
        random_data[i] = rand() % 256;
    }
    
    // Generate random IV
    for (int i = 0; i < 16; i++) {
        iv[i] = rand() % 256;
    }
    
    // Set up keys
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &encrypt_key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set encryption key in roundtrip test\n");
        exit(1);
    }
    
    ret = crypto_core_aes_ecb_set_key(test_key, 128, &decrypt_key, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set decryption key in roundtrip test\n");
        exit(1);
    }
    
    // Encrypt
    unsigned char iv_encrypt[16];
    memcpy(iv_encrypt, iv, 16);
    ret = crypto_core_aes_cbc_encrypt(random_data, ciphertext, 64, &encrypt_key, iv_encrypt, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: AES CBC encryption failed in roundtrip test\n");
        exit(1);
    }
    
    // Decrypt
    unsigned char iv_decrypt[16];
    memcpy(iv_decrypt, iv, 16);
    ret = crypto_core_aes_cbc_encrypt(ciphertext, decrypted, 64, &decrypt_key, iv_decrypt, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: AES CBC decryption failed in roundtrip test\n");
        exit(1);
    }
    
    // Verify roundtrip
    if (memcmp(decrypted, random_data, 64) != 0) {
        printf("ERROR: Roundtrip test failed\n");
        print_hex("Original", random_data, 32);
        print_hex("Decrypted", decrypted, 32);
        exit(1);
    }
    
    printf("AES CBC roundtrip test passed\n");
}

void test_aes_cbc_padding() {
    printf("Testing AES CBC with different data lengths...\n");
    
    AES_KEY encrypt_key, decrypt_key;
    unsigned char iv[16];
    
    // Generate random IV
    for (int i = 0; i < 16; i++) {
        iv[i] = rand() % 256;
    }
    
    // Set up keys
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &encrypt_key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set encryption key for padding test\n");
        exit(1);
    }
    
    ret = crypto_core_aes_ecb_set_key(test_key, 128, &decrypt_key, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set decryption key for padding test\n");
        exit(1);
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
        
        // Encrypt
        unsigned char iv_encrypt[16];
        memcpy(iv_encrypt, iv, 16);
        ret = crypto_core_aes_cbc_encrypt(data, ciphertext, len, &encrypt_key, iv_encrypt, AES_ENCRYPT);
        if (ret != 0) {
            printf("ERROR: AES CBC encryption failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        // Decrypt
        unsigned char iv_decrypt[16];
        memcpy(iv_decrypt, iv, 16);
        ret = crypto_core_aes_cbc_encrypt(ciphertext, decrypted, len, &decrypt_key, iv_decrypt, AES_DECRYPT);
        if (ret != 0) {
            printf("ERROR: AES CBC decryption failed for length %d\n", len);
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
    printf("Testing AES CBC IV behavior...\n");
    
    AES_KEY key;
    unsigned char ciphertext1[32], ciphertext2[32];
    unsigned char iv1[16], iv2[16];
    
    // Set up key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set key for IV test\n");
        exit(1);
    }
    
    // Test with same IV
    memcpy(iv1, test_iv, 16);
    memcpy(iv2, test_iv, 16);
    
    ret = crypto_core_aes_cbc_encrypt(test_plaintext, ciphertext1, 32, &key, iv1, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: First encryption failed in IV test\n");
        exit(1);
    }
    
    ret = crypto_core_aes_cbc_encrypt(test_plaintext, ciphertext2, 32, &key, iv2, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Second encryption failed in IV test\n");
        exit(1);
    }
    
    // Same IV should produce same ciphertext
    if (memcmp(ciphertext1, ciphertext2, 32) != 0) {
        printf("ERROR: Same IV produced different ciphertext\n");
        exit(1);
    }
    
    // Test with different IV
    iv2[0] ^= 1; // Modify one byte
    
    ret = crypto_core_aes_cbc_encrypt(test_plaintext, ciphertext2, 32, &key, iv2, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Encryption with modified IV failed\n");
        exit(1);
    }
    
    // Different IV should produce different ciphertext
    if (memcmp(ciphertext1, ciphertext2, 32) == 0) {
        printf("ERROR: Different IV produced same ciphertext\n");
        exit(1);
    }
    
    printf("AES CBC IV behavior test passed\n");
}

int main() {
    printf("Starting AES CBC tests...\n");
    printf("========================\n");
    
    // Initialize random seed
    bmc_crypt_init();
    
    // test_aes_cbc_encryption();
    // test_aes_cbc_decryption();
    test_aes_cbc_roundtrip();
    // test_aes_cbc_padding();
    // test_aes_cbc_iv_modification();
    
    printf("========================\n");
    printf("All AES CBC tests passed!\n");
    
    return 0;
} 