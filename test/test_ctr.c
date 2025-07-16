#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/crypto_core_aes.h>

// Test vectors for AES-128 CTR
static const unsigned char test_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const unsigned char test_nonce[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

static const unsigned char test_plaintext[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

// Expected ciphertext for the first 16 bytes (calculated manually for verification)
static const unsigned char expected_ciphertext_block1[16] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
    0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
};

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void test_aes_ctr_encryption() {
    printf("Testing AES CTR encryption...\n");
    
    AES_KEY key;
    unsigned char ciphertext[64];
    unsigned char nonce_copy[16];
    unsigned char ecount_buf[16];
    unsigned int num = 0;

    // Set up encryption key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set encryption key\n");
        exit(1);
    }
    
    // Copy nonce (it will be modified during encryption)
    memcpy(nonce_copy, test_nonce, 16);
    
    // Initialize ecount_buf
    memset(ecount_buf, 0, 16);
    
    // Test encryption using crypto_core_aes_ctr_encrypt
    crypto_core_aes_ctr_encrypt(test_plaintext, ciphertext, 64, &key, nonce_copy, ecount_buf, &num);
    
    // Verify first block ciphertext (we know the expected result)
    if (memcmp(ciphertext, expected_ciphertext_block1, 16) != 0) {
        printf("ERROR: First block ciphertext mismatch\n");
        print_hex("Expected", expected_ciphertext_block1, 16);
        print_hex("Got     ", ciphertext, 16);
        exit(1);
    }
    
    printf("AES CTR encryption test passed\n");
}

void test_aes_ctr_decryption() {
    printf("Testing AES CTR decryption...\n");
    
    AES_KEY key;
    unsigned char decrypted[64];
    unsigned char nonce_copy[16];
    unsigned char ecount_buf[16];
    unsigned int num = 0;
    unsigned char ciphertext[64];

    // Set up encryption key (CTR uses same key for encryption and decryption)
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set key for decryption test\n");
        exit(1);
    }
    
    // First encrypt to get ciphertext
    memcpy(nonce_copy, test_nonce, 16);
    memset(ecount_buf, 0, 16);
    crypto_core_aes_ctr_encrypt(test_plaintext, ciphertext, 64, &key, nonce_copy, ecount_buf, &num);
    
    // Now decrypt (CTR decryption is same as encryption)
    memcpy(nonce_copy, test_nonce, 16);
    memset(ecount_buf, 0, 16);
    num = 0;
    crypto_core_aes_ctr_encrypt(ciphertext, decrypted, 64, &key, nonce_copy, ecount_buf, &num);
    
    // Verify decrypted text matches original plaintext
    if (memcmp(decrypted, test_plaintext, 64) != 0) {
        printf("ERROR: Decryption result mismatch\n");
        print_hex("Expected", test_plaintext, 32);
        print_hex("Got     ", decrypted, 32);
        exit(1);
    }
    
    printf("AES CTR decryption test passed\n");
}

void test_aes_ctr_roundtrip() {
    printf("Testing AES CTR roundtrip (encrypt -> decrypt)...\n");
    
    AES_KEY key;
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    unsigned char random_data[128];
    unsigned char nonce[16];
    unsigned char ecount_buf[16];
    unsigned int num = 0;
    
    // Generate random test data
    for (int i = 0; i < 128; i++) {
        random_data[i] = rand() % 256;
    }
    
    // Generate random nonce
    for (int i = 0; i < 16; i++) {
        nonce[i] = rand() % 256;
    }
    
    // Set up key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set key in roundtrip test\n");
        exit(1);
    }
    
    // Encrypt
    unsigned char nonce_encrypt[16];
    memcpy(nonce_encrypt, nonce, 16);
    memset(ecount_buf, 0, 16);
    crypto_core_aes_ctr_encrypt(random_data, ciphertext, 128, &key, nonce_encrypt, ecount_buf, &num);
    
    // Decrypt
    unsigned char nonce_decrypt[16];
    memcpy(nonce_decrypt, nonce, 16);
    memset(ecount_buf, 0, 16);
    num = 0;
    crypto_core_aes_ctr_encrypt(ciphertext, decrypted, 128, &key, nonce_decrypt, ecount_buf, &num);
    
    // Verify roundtrip
    if (memcmp(decrypted, random_data, 128) != 0) {
        printf("ERROR: Roundtrip test failed\n");
        print_hex("Original", random_data, 32);
        print_hex("Decrypted", decrypted, 32);
        exit(1);
    }
    
    printf("AES CTR roundtrip test passed\n");
}

void test_aes_ctr_streaming() {
    printf("Testing AES CTR streaming behavior...\n");
    
    AES_KEY key;
    unsigned char nonce[16];
    unsigned char ecount_buf[16];
    unsigned int num = 0;
    
    // Generate random nonce
    for (int i = 0; i < 16; i++) {
        nonce[i] = rand() % 256;
    }
    
    // Set up key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set key for streaming test\n");
        exit(1);
    }
    
    // Test streaming: encrypt data in chunks
    const int chunk_size = 16;
    const int num_chunks = 4;
    unsigned char *data = malloc(chunk_size * num_chunks);
    unsigned char *ciphertext_stream = malloc(chunk_size * num_chunks);
    unsigned char *ciphertext_single = malloc(chunk_size * num_chunks);
    
    // Generate random data
    for (int i = 0; i < chunk_size * num_chunks; i++) {
        data[i] = rand() % 256;
    }
    
    // Encrypt in chunks (streaming)
    unsigned char nonce_stream[16];
    memcpy(nonce_stream, nonce, 16);
    memset(ecount_buf, 0, 16);
    num = 0;
    
    for (int i = 0; i < num_chunks; i++) {
        crypto_core_aes_ctr_encrypt(data + i * chunk_size, 
                                   ciphertext_stream + i * chunk_size, 
                                   chunk_size, &key, nonce_stream, ecount_buf, &num);
    }
    
    // Encrypt all at once (single call)
    unsigned char nonce_single[16];
    memcpy(nonce_single, nonce, 16);
    memset(ecount_buf, 0, 16);
    num = 0;
    crypto_core_aes_ctr_encrypt(data, ciphertext_single, chunk_size * num_chunks, 
                               &key, nonce_single, ecount_buf, &num);
    
    // Results should be identical
    if (memcmp(ciphertext_stream, ciphertext_single, chunk_size * num_chunks) != 0) {
        printf("ERROR: Streaming vs single call results differ\n");
        print_hex("Streaming", ciphertext_stream, 32);
        print_hex("Single   ", ciphertext_single, 32);
        free(data);
        free(ciphertext_stream);
        free(ciphertext_single);
        exit(1);
    }
    
    free(data);
    free(ciphertext_stream);
    free(ciphertext_single);
    
    printf("AES CTR streaming test passed\n");
}

void test_aes_ctr_counter_behavior() {
    printf("Testing AES CTR counter behavior...\n");
    
    AES_KEY key;
    unsigned char nonce1[16], nonce2[16];
    unsigned char ecount_buf[16];
    unsigned int num = 0;
    
    // Set up key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set key for counter test\n");
        exit(1);
    }
    
    // Test with same nonce
    memcpy(nonce1, test_nonce, 16);
    memcpy(nonce2, test_nonce, 16);
    
    unsigned char ciphertext1[32], ciphertext2[32];
    
    memset(ecount_buf, 0, 16);
    crypto_core_aes_ctr_encrypt(test_plaintext, ciphertext1, 32, &key, nonce1, ecount_buf, &num);
    
    memset(ecount_buf, 0, 16);
    num = 0;
    crypto_core_aes_ctr_encrypt(test_plaintext, ciphertext2, 32, &key, nonce2, ecount_buf, &num);
    
    // Same nonce should produce same ciphertext
    if (memcmp(ciphertext1, ciphertext2, 32) != 0) {
        printf("ERROR: Same nonce produced different ciphertext\n");
        exit(1);
    }
    
    // Test with different nonce (increment counter)
    nonce2[15]++; // Increment last byte of nonce
    
    memset(ecount_buf, 0, 16);
    num = 0;
    crypto_core_aes_ctr_encrypt(test_plaintext, ciphertext2, 32, &key, nonce2, ecount_buf, &num);
    
    // Different nonce should produce different ciphertext
    if (memcmp(ciphertext1, ciphertext2, 32) == 0) {
        printf("ERROR: Different nonce produced same ciphertext\n");
        exit(1);
    }
    
    printf("AES CTR counter behavior test passed\n");
}

void test_aes_ctr_partial_blocks() {
    printf("Testing AES CTR with partial blocks...\n");
    
    AES_KEY key;
    unsigned char nonce[16];
    unsigned char ecount_buf[16];
    unsigned int num = 0;
    
    // Generate random nonce
    for (int i = 0; i < 16; i++) {
        nonce[i] = rand() % 256;
    }
    
    // Set up key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set key for partial blocks test\n");
        exit(1);
    }
    
    // Test different data lengths
    const int test_lengths[] = {1, 15, 16, 17, 31, 32, 33, 63, 64, 65};
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
        unsigned char nonce_encrypt[16];
        memcpy(nonce_encrypt, nonce, 16);
        memset(ecount_buf, 0, 16);
        num = 0;
        crypto_core_aes_ctr_encrypt(data, ciphertext, len, &key, nonce_encrypt, ecount_buf, &num);
        
        // Decrypt
        unsigned char nonce_decrypt[16];
        memcpy(nonce_decrypt, nonce, 16);
        memset(ecount_buf, 0, 16);
        num = 0;
        crypto_core_aes_ctr_encrypt(ciphertext, decrypted, len, &key, nonce_decrypt, ecount_buf, &num);
        
        // Verify
        if (memcmp(decrypted, data, len) != 0) {
            printf("ERROR: Partial blocks test failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        free(data);
        free(ciphertext);
        free(decrypted);
    }
    
    printf("AES CTR partial blocks test passed\n");
}

int main() {
    printf("Starting AES CTR tests...\n");
    printf("========================\n");
    
    // Initialize random seed and library
    bmc_crypt_init();
    
    test_aes_ctr_encryption();
    test_aes_ctr_decryption();
    test_aes_ctr_roundtrip();
    test_aes_ctr_streaming();
    test_aes_ctr_counter_behavior();
    test_aes_ctr_partial_blocks();
    
    printf("========================\n");
    printf("All AES CTR tests passed!\n");
    
    return 0;
} 