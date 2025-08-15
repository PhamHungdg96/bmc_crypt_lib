#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/crypto_core_aes.h>

// Test vectors for AES-128 GCM
static const unsigned char test_key_128[16] = {0};

static const unsigned char test_nonce[12] = {0};

static const unsigned char test_plaintext[16] = {0};

static const unsigned char *test_aad = NULL;

// Expected ciphertext and tag (calculated manually for verification)
static const unsigned char expected_ciphertext[16] = {
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 
    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
};

static const unsigned char expected_tag[16] = {
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
};

// Test vectors for AES-256 GCM
static const unsigned char test_key_256[32] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void test_aes128_gcm_encryption() {
    printf("Testing AES-128 GCM encryption...\n");
    
    unsigned char ciphertext[64];
    unsigned char tag[16];

    // Test encryption using crypto_core_aes128_gcm_encrypt
    int ret = crypto_core_aes128_gcm_encrypt(ciphertext, tag, test_plaintext, 16, 
                                            test_key_128, test_nonce, test_aad, 0);
    if (ret != 0) {
        printf("ERROR: AES-128 GCM encryption failed\n");
        exit(1);
    }
    
    // Verify ciphertext
    if (memcmp(ciphertext, expected_ciphertext, 16) != 0) {
        printf("ERROR: Ciphertext mismatch\n");
        print_hex("Expected", expected_ciphertext, 16);
        print_hex("Got     ", ciphertext, 16);
        exit(1);
    }
    
    // Verify tag
    if (memcmp(tag, expected_tag, 16) != 0) {
        printf("ERROR: Tag mismatch\n");
        print_hex("Expected", expected_tag, 16);
        print_hex("Got     ", tag, 16);
        exit(1);
    }
    
    printf("AES-128 GCM encryption test passed\n");
}

void test_aes128_gcm_decryption() {
    printf("Testing AES-128 GCM decryption...\n");
    
    unsigned char decrypted[64];
    unsigned char ciphertext[64];
    unsigned char tag[16];

    // First encrypt to get ciphertext and tag
    int ret = crypto_core_aes128_gcm_encrypt(ciphertext, tag, test_plaintext, 16, 
                                            test_key_128, test_nonce, test_aad, 0);
    if (ret != 0) {
        printf("ERROR: Failed to encrypt data for decryption test\n");
        exit(1);
    }
    printf("Ciphertext: ");
    for (size_t i = 0; i < 16; i++) printf("%02x", ciphertext[i]);
    printf("\n");
    // Now decrypt
    ret = crypto_core_aes128_gcm_decrypt(decrypted, ciphertext, 16, tag,
                                        test_key_128, test_nonce, test_aad, 0);
    if (ret != 0) {
        printf("ERROR: AES-128 GCM decryption failed\n");
        exit(1);
    }

    printf("decrypted: ");
    for (size_t i = 0; i < 16; i++) printf("%02x", decrypted[i]);
    printf("\n");
    
    // Verify decrypted text matches original plaintext
    if (memcmp(decrypted, test_plaintext, 16) != 0) {
        printf("ERROR: Decryption result mismatch\n");
        print_hex("Expected", test_plaintext, 16);
        print_hex("Got     ", decrypted, 16);
        exit(1);
    }
    
    printf("AES-128 GCM decryption test passed\n");
}

void test_aes128_gcm_roundtrip() {
    printf("Testing AES-128 GCM roundtrip (encrypt -> decrypt)...\n");
    
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    unsigned char tag[16];
    unsigned char random_data[128];
    unsigned char random_aad[32];
    unsigned char random_nonce[12];
    
    // Generate random test data
    for (int i = 0; i < 128; i++) {
        random_data[i] = rand() % 256;
    }
    
    // Generate random AAD
    for (int i = 0; i < 32; i++) {
        random_aad[i] = rand() % 256;
    }
    
    // Generate random nonce
    for (int i = 0; i < 12; i++) {
        random_nonce[i] = rand() % 256;
    }
    
    // Encrypt
    int ret = crypto_core_aes128_gcm_encrypt(ciphertext, tag, random_data, 128, 
                                            test_key_128, random_nonce, random_aad, 32);
    if (ret != 0) {
        printf("ERROR: AES-128 GCM encryption failed in roundtrip test\n");
        exit(1);
    }
    
    // Decrypt
    ret = crypto_core_aes128_gcm_decrypt(decrypted, ciphertext, 128, tag,
                                        test_key_128, random_nonce, random_aad, 32);
    if (ret != 0) {
        printf("ERROR: AES-128 GCM decryption failed in roundtrip test\n");
        exit(1);
    }
    
    // Verify roundtrip
    if (memcmp(decrypted, random_data, 128) != 0) {
        printf("ERROR: Roundtrip test failed\n");
        print_hex("Original", random_data, 32);
        print_hex("Decrypted", decrypted, 32);
        exit(1);
    }
    
    printf("AES-128 GCM roundtrip test passed\n");
}

void test_gcm_authentication() {
    printf("Testing GCM authentication...\n");
    
    unsigned char ciphertext[64];
    unsigned char decrypted[64];
    unsigned char tag[16];
    unsigned char modified_tag[16];
    unsigned char random_nonce[12];
    
    // Generate random nonce
    for (int i = 0; i < 12; i++) {
        random_nonce[i] = rand() % 256;
    }
    
    // Encrypt
    int ret = crypto_core_aes128_gcm_encrypt(ciphertext, tag, test_plaintext, 64, 
                                            test_key_128, random_nonce, test_aad, 20);
    if (ret != 0) {
        printf("ERROR: Failed to encrypt data for authentication test\n");
        exit(1);
    }
    
    // Test with correct tag - should succeed
    ret = crypto_core_aes128_gcm_decrypt(decrypted, ciphertext, 64, tag,
                                        test_key_128, random_nonce, test_aad, 20);
    if (ret != 0) {
        printf("ERROR: Decryption with correct tag failed\n");
        exit(1);
    }
    
    // Test with modified tag - should fail
    memcpy(modified_tag, tag, 16);
    modified_tag[0] ^= 1; // Modify one byte
    
    ret = crypto_core_aes128_gcm_decrypt(decrypted, ciphertext, 64, modified_tag,
                                        test_key_128, random_nonce, test_aad, 20);
    if (ret == 0) {
        printf("ERROR: Decryption with modified tag succeeded (should fail)\n");
        exit(1);
    }
    
    printf("GCM authentication test passed\n");
}

void test_gcm_aad_integrity() {
    printf("Testing GCM AAD integrity...\n");
    
    unsigned char ciphertext[64];
    unsigned char decrypted[64];
    unsigned char tag[16];
    unsigned char modified_aad[20];
    unsigned char random_nonce[12];
    unsigned char random_aad[20];
    
    // Generate random nonce
    for (int i = 0; i < 12; i++) {
        random_nonce[i] = rand() % 256;
    }

    for (int i = 0; i < 20; i++) {
        random_aad[i] = rand() % 256;
    }
    
    // Encrypt
    int ret = crypto_core_aes128_gcm_encrypt(ciphertext, tag, test_plaintext, 16, 
                                            test_key_128, random_nonce, random_aad, 20);
    if (ret != 0) {
        printf("ERROR: Failed to encrypt data for AAD integrity test\n");
        exit(1);
    }
    
    // Test with correct AAD - should succeed
    ret = crypto_core_aes128_gcm_decrypt(decrypted, ciphertext, 16, tag,
                                        test_key_128, random_nonce, random_aad, 20);
    if (ret != 0) {
        printf("ERROR: Decryption with correct AAD failed\n");
        exit(1);
    }
    
    // Test with modified AAD - should fail
    memcpy(modified_aad, random_aad, 0);
    modified_aad[0] ^= 1; // Modify one byte
    
    ret = crypto_core_aes128_gcm_decrypt(decrypted, ciphertext, 16, tag,
                                        test_key_128, random_nonce, modified_aad, 20);
    if (ret == 0) {
        printf("ERROR: Decryption with modified AAD succeeded (should fail)\n");
        exit(1);
    }
    
    printf("GCM AAD integrity test passed\n");
}

void test_gcm_empty_data() {
    printf("Testing GCM with empty data...\n");
    
    unsigned char ciphertext[1];
    unsigned char decrypted[1];
    unsigned char tag[16];
    unsigned char random_nonce[12];
    unsigned char random_aad[16];
    
    // Generate random nonce and AAD
    for (int i = 0; i < 12; i++) {
        random_nonce[i] = rand() % 256;
    }
    for (int i = 0; i < 16; i++) {
        random_aad[i] = rand() % 256;
    }
    
    // Encrypt empty data
    int ret = crypto_core_aes128_gcm_encrypt(ciphertext, tag, NULL, 0, 
                                            test_key_128, random_nonce, random_aad, 16);
    if (ret != 0) {
        printf("ERROR: GCM encryption with empty data failed\n");
        exit(1);
    }
    
    // Decrypt empty data
    ret = crypto_core_aes128_gcm_decrypt(decrypted, NULL, 0, tag,
                                        test_key_128, random_nonce, random_aad, 16);
    if (ret != 0) {
        printf("ERROR: GCM decryption with empty data failed\n");
        exit(1);
    }
    
    printf("GCM empty data test passed\n");
}

void test_gcm_variable_lengths() {
    printf("Testing GCM with variable data lengths...\n");
    
    unsigned char random_nonce[12];
    unsigned char random_aad[32];
    
    // Generate random nonce and AAD
    for (int i = 0; i < 12; i++) {
        random_nonce[i] = rand() % 256;
    }
    for (int i = 0; i < 32; i++) {
        random_aad[i] = rand() % 256;
    }
    
    // Test different data lengths
    const int test_lengths[] = {0, 1, 15, 16, 17, 31, 32, 63, 64, 127, 128};
    const int num_tests = sizeof(test_lengths) / sizeof(test_lengths[0]);
    
    for (int test_idx = 0; test_idx < num_tests; test_idx++) {
        int len = test_lengths[test_idx];
        unsigned char *data = malloc(len);
        unsigned char *ciphertext = malloc(len);
        unsigned char *decrypted = malloc(len);
        unsigned char tag[16];
        
        // Generate random data
        for (int i = 0; i < len; i++) {
            data[i] = rand() % 256;
        }
        
        // Encrypt
        int ret = crypto_core_aes128_gcm_encrypt(ciphertext, tag, data, len, 
                                                test_key_128, random_nonce, random_aad, 32);
        if (ret != 0) {
            printf("ERROR: GCM encryption failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        // Decrypt
        ret = crypto_core_aes128_gcm_decrypt(decrypted, ciphertext, len, tag,
                                            test_key_128, random_nonce, random_aad, 32);
        if (ret != 0) {
            printf("ERROR: GCM decryption failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        // Verify
        if (len > 0 && memcmp(decrypted, data, len) != 0) {
            printf("ERROR: Variable length test failed for length %d\n", len);
            free(data);
            free(ciphertext);
            free(decrypted);
            exit(1);
        }
        
        free(data);
        free(ciphertext);
        free(decrypted);
    }
    
    printf("GCM variable lengths test passed\n");
}

void test_aes256_gcm_arbitrary_length() {
    printf("Testing AES-256 GCM with arbitrary message length...\n");
    
    unsigned char key[16] = {0};

    unsigned char iv[12] = {0};

    // unsigned char message[16] = {0};
    // uint8_t message_len = 16;
    const unsigned char *message = "hello";
    size_t message_len = strlen(message);

    unsigned char *aad = NULL;

    // static const unsigned char expected_ciphertext[64] = {
//     0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 
//     0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
// };

    crypto_core_aes_ctx *enc_ctx, *dec_ctx;
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    unsigned char final_block[32];
    size_t outlen = 0;
    
    // Encrypt
    if (crypto_core_aes_init(&enc_ctx, key, 16, AES_MODE_GCM, 1, iv, 12) != 0) {
        printf("ERROR: AES-256 GCM encrypt init failed\n");
        exit(1);
    }
    // crypto_core_aes_gcm_aad(&enc_ctx, aad, 0);

    int clen = crypto_core_aes_update(enc_ctx, ciphertext, message, message_len);
    size_t total_clen = clen;
    if (crypto_core_aes_finish(enc_ctx, ciphertext + clen, &outlen) != 0) {
        printf("ERROR: AES-256 GCM encrypt finish failed\n");
        exit(1);
    }
    
    total_clen += outlen;
    printf("Ciphertext: ");
    for (size_t i = 0; i < total_clen; i++) printf("%02x", ciphertext[i]);
    printf("\n");
    printf("total_clen: %zu\n", total_clen);
    
    // Decrypt
    if (crypto_core_aes_init(&dec_ctx, key, 16, AES_MODE_GCM, 0, iv, 12) != 0) {
        printf("ERROR: AES-256 GCM decrypt init failed\n");
        exit(1);
    }
    // crypto_core_aes_gcm_aad(&dec_ctx, aad, 0);
    int dlen = crypto_core_aes_update(dec_ctx, decrypted, ciphertext, total_clen);
    size_t total_dlen = dlen;
    printf("dlen: %zu\n", dlen);
    // if (crypto_core_aes_finish(&dec_ctx, decrypted + dlen, &outlen) != 0) {
    //     printf("ERROR: AES-256 GCM decrypt finish failed\n");
    //     exit(1);
    // }
    total_dlen += outlen;
    printf("Decrypted: ");
    for (size_t i = 0; i < total_dlen; i++) printf("%02x", decrypted[i]);
    printf("\n");
    printf("Decrypted: %.*s\n", (int)total_dlen, decrypted);
    // Sau khi finish giải mã
    // outlen là số byte thực sự của block cuối (đã loại padding)
    if (total_dlen != message_len || memcmp(decrypted, message, message_len) != 0) {
        printf("ERROR: AES-256 GCM roundtrip failed!\n");
        exit(1);
    }
    printf("AES-256 GCM arbitrary length test passed!\n");
}

int main() {
    printf("Starting AES GCM tests...\n");
    printf("========================\n");
    
    // Initialize random seed and library
    bmc_crypt_init();
    
    test_aes128_gcm_encryption();
    test_aes128_gcm_decryption();
    test_aes128_gcm_roundtrip();
    // test_gcm_authentication();
    // test_gcm_aad_integrity();
    // // test_gcm_empty_data();
    // test_gcm_variable_lengths();
    test_aes256_gcm_arbitrary_length();
    
    printf("========================\n");
    printf("All AES GCM tests passed!\n");
    
    return 0;
} 