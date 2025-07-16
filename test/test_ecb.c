#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/crypto_core_aes.h>

// // Test vectors từ NIST FIPS 197
static const unsigned char test_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char test_plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const unsigned char expected_ciphertext[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};

void test_aes_ecb_encryption() {
    printf("Testing AES ECB encryption...\n");
    
    AES_KEY key;
    unsigned char ciphertext[16];

    // Set up encryption key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set encryption key\n");
        exit(1);
    }
    
    // Test encryption using crypto_core_aes_ecb_encrypt
    ret = crypto_core_aes_ecb_encrypt(ciphertext, test_plaintext, &key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: AES ECB encryption failed\n");
        exit(1);
    }
    
    // Verify ciphertext
    if (memcmp(ciphertext, expected_ciphertext, 16) != 0) {
        printf("ERROR: Ciphertext mismatch\n");
        printf("Expected: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", expected_ciphertext[i]);
        }
        printf("\nGot:      ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", ciphertext[i]);
        }
        printf("\n");
        exit(1);
    }
    
    printf("AES ECB encryption test passed\n");
}

void test_aes_ecb_decryption() {
    printf("Testing AES ECB decryption...\n");
    
    AES_KEY key;
    unsigned char decrypted[16];
    
    // Set up decryption key
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &key, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set decryption key\n");
        exit(1);
    }
    
    // Test decryption using crypto_core_aes_ecb_encrypt with AES_DECRYPT flag
    ret = crypto_core_aes_ecb_encrypt(decrypted, expected_ciphertext, &key, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: AES ECB decryption failed\n");
        exit(1);
    }
    
    // Verify decrypted text matches original plaintext
    if (memcmp(decrypted, test_plaintext, 16) != 0) {
        printf("ERROR: Decryption result mismatch\n");
        printf("Expected: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", test_plaintext[i]);
        }
        printf("\nGot:      ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", decrypted[i]);
        }
        printf("\n");
        exit(1);
    }
    
    printf("AES ECB decryption test passed\n");
}

void test_aes_ecb_roundtrip() {
    printf("Testing AES ECB roundtrip (encrypt -> decrypt)...\n");
    
    AES_KEY encrypt_key, decrypt_key;
    unsigned char ciphertext[16];
    unsigned char decrypted[16];
    unsigned char random_data[16];
    
    // Generate random test data
    for (int i = 0; i < 16; i++) {
        random_data[i] = rand() % 256;
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
    ret = crypto_core_aes_ecb_encrypt(ciphertext, random_data, &encrypt_key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: AES ECB encryption failed in roundtrip test\n");
        exit(1);
    }
    
    // Decrypt
    ret = crypto_core_aes_ecb_encrypt(decrypted, ciphertext, &decrypt_key, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: AES ECB decryption failed in roundtrip test\n");
        exit(1);
    }
    
    // Verify roundtrip
    if (memcmp(decrypted, random_data, 16) != 0) {
        printf("ERROR: Roundtrip test failed\n");
        printf("Original: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", random_data[i]);
        }
        printf("\nDecrypted: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", decrypted[i]);
        }
        printf("\n");
        exit(1);
    }
    
    printf("AES ECB roundtrip test passed\n");
}

void test_aes_ecb_multiple_blocks() {
    printf("Testing AES ECB with multiple blocks...\n");
    
    AES_KEY encrypt_key, decrypt_key;
    unsigned char multi_plaintext[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    unsigned char multi_ciphertext[32];
    unsigned char multi_decrypted[32];
    
    // Set up keys
    int ret = crypto_core_aes_ecb_set_key(test_key, 128, &encrypt_key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set encryption key for multiple blocks test\n");
        exit(1);
    }
    
    ret = crypto_core_aes_ecb_set_key(test_key, 128, &decrypt_key, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: Failed to set decryption key for multiple blocks test\n");
        exit(1);
    }
    
    // Encrypt each block separately (ECB mode)
    ret = crypto_core_aes_ecb_encrypt(multi_ciphertext, multi_plaintext, &encrypt_key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: AES ECB encryption failed for first block\n");
        exit(1);
    }
    
    ret = crypto_core_aes_ecb_encrypt(multi_ciphertext + 16, multi_plaintext + 16, &encrypt_key, AES_ENCRYPT);
    if (ret != 0) {
        printf("ERROR: AES ECB encryption failed for second block\n");
        exit(1);
    }
    
    // Decrypt each block separately
    ret = crypto_core_aes_ecb_encrypt(multi_decrypted, multi_ciphertext, &decrypt_key, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: AES ECB decryption failed for first block\n");
        exit(1);
    }
    
    ret = crypto_core_aes_ecb_encrypt(multi_decrypted + 16, multi_ciphertext + 16, &decrypt_key, AES_DECRYPT);
    if (ret != 0) {
        printf("ERROR: AES ECB decryption failed for second block\n");
        exit(1);
    }
    
    // Verify roundtrip
    if (memcmp(multi_decrypted, multi_plaintext, 32) != 0) {
        printf("ERROR: Multiple blocks roundtrip test failed\n");
        exit(1);
    }
    
    printf("AES ECB multiple blocks test passed\n");
}

int main() {
    printf("Starting AES ECB tests...\n");
    printf("========================\n");
    
    // Initialize random seed
    bmc_crypt_init();
    
    test_aes_ecb_encryption();
    test_aes_ecb_decryption();
    test_aes_ecb_roundtrip();
    test_aes_ecb_multiple_blocks();
    
    printf("========================\n");
    printf("All AES ECB tests passed!\n");
    
    return 0;
} 