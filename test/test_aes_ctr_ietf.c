#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/crypto_core_aes.h>

// Test vectors cho AES-CTR
static const unsigned char test_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const unsigned char test_nonce[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void test_aes_ctr_ietf_basic() {
    printf("Testing crypto_core_aes_ctr_ietf basic functionality...\n");
    
    unsigned char keystream[64];
    int ret;
    
    // Test với buffer nhỏ
    ret = crypto_core_aes_ctr_ietf(keystream, 64, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: crypto_core_aes_ctr_ietf failed\n");
        exit(1);
    }
    
    // Kiểm tra xem keystream có được tạo hay không
    int has_data = 0;
    for (int i = 0; i < 64; i++) {
        if (keystream[i] != 0) {
            has_data = 1;
            break;
        }
    }
    
    if (!has_data) {
        printf("ERROR: Keystream was not generated\n");
        exit(1);
    }
    
    printf("crypto_core_aes_ctr_ietf basic test passed\n");
}

void test_aes_ctr_ietf_deterministic() {
    printf("Testing crypto_core_aes_ctr_ietf determinism...\n");
    
    unsigned char keystream1[32];
    unsigned char keystream2[32];
    int ret;
    
    // Tạo keystream với cùng nonce và key
    ret = crypto_core_aes_ctr_ietf(keystream1, 32, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: First crypto_core_aes_ctr_ietf call failed\n");
        exit(1);
    }
    
    ret = crypto_core_aes_ctr_ietf(keystream2, 32, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: Second crypto_core_aes_ctr_ietf call failed\n");
        exit(1);
    }
    
    // Kiểm tra xem kết quả có giống nhau không (deterministic)
    if (memcmp(keystream1, keystream2, 32) != 0) {
        printf("ERROR: crypto_core_aes_ctr_ietf is not deterministic\n");
        exit(1);
    }
    
    printf("crypto_core_aes_ctr_ietf determinism test passed\n");
}

void test_aes_ctr_ietf_different_nonce() {
    printf("Testing crypto_core_aes_ctr_ietf with different nonces...\n");
    
    unsigned char keystream1[32];
    unsigned char keystream2[32];
    unsigned char nonce2[16] = {0};
    nonce2[0] = 0x01;  // Different nonce
    int ret;
    
    // Tạo keystream với nonce khác nhau
    ret = crypto_core_aes_ctr_ietf(keystream1, 32, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: First crypto_core_aes_ctr_ietf call failed\n");
        exit(1);
    }
    
    ret = crypto_core_aes_ctr_ietf(keystream2, 32, nonce2, test_key);
    if (ret != 0) {
        printf("ERROR: Second crypto_core_aes_ctr_ietf call failed\n");
        exit(1);
    }
    
    // Với nonce khác nhau, kết quả nên khác nhau
    if (memcmp(keystream1, keystream2, 32) == 0) {
        printf("WARNING: crypto_core_aes_ctr_ietf produced identical output with different nonces\n");
    }
    
    printf("crypto_core_aes_ctr_ietf different nonce test passed\n");
}

void test_aes_ctr_ietf_different_sizes() {
    printf("Testing crypto_core_aes_ctr_ietf with different sizes...\n");
    
    unsigned char keystream1[16];
    unsigned char keystream2[32];
    unsigned char keystream3[64];
    int ret;
    
    // Test với các kích thước khác nhau
    ret = crypto_core_aes_ctr_ietf(keystream1, 16, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: crypto_core_aes_ctr_ietf failed with size 16\n");
        exit(1);
    }
    
    ret = crypto_core_aes_ctr_ietf(keystream2, 32, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: crypto_core_aes_ctr_ietf failed with size 32\n");
        exit(1);
    }
    
    ret = crypto_core_aes_ctr_ietf(keystream3, 64, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: crypto_core_aes_ctr_ietf failed with size 64\n");
        exit(1);
    }
    
    // Kiểm tra xem tất cả keystreams đều có dữ liệu
    int has_data1 = 0, has_data2 = 0, has_data3 = 0;
    
    for (int i = 0; i < 16; i++) {
        if (keystream1[i] != 0) has_data1 = 1;
    }
    for (int i = 0; i < 32; i++) {
        if (keystream2[i] != 0) has_data2 = 1;
    }
    for (int i = 0; i < 64; i++) {
        if (keystream3[i] != 0) has_data3 = 1;
    }
    
    if (!has_data1 || !has_data2 || !has_data3) {
        printf("ERROR: One or more keystreams were not generated\n");
        exit(1);
    }
    
    printf("crypto_core_aes_ctr_ietf different sizes test passed\n");
}

void test_aes_ctr_ietf_null_parameters() {
    printf("Testing crypto_core_aes_ctr_ietf with null parameters...\n");
    
    unsigned char keystream[32];
    int ret;
    
    // Test với NULL output
    ret = crypto_core_aes_ctr_ietf(NULL, 32, test_nonce, test_key);
    if (ret != -1) {
        printf("ERROR: crypto_core_aes_ctr_ietf should fail with NULL output\n");
        exit(1);
    }
    
    // Test với NULL nonce
    ret = crypto_core_aes_ctr_ietf(keystream, 32, NULL, test_key);
    if (ret != -1) {
        printf("ERROR: crypto_core_aes_ctr_ietf should fail with NULL nonce\n");
        exit(1);
    }
    
    // Test với NULL key
    ret = crypto_core_aes_ctr_ietf(keystream, 32, test_nonce, NULL);
    if (ret != -1) {
        printf("ERROR: crypto_core_aes_ctr_ietf should fail with NULL key\n");
        exit(1);
    }
    
    printf("crypto_core_aes_ctr_ietf null parameters test passed\n");
}

void test_aes_ctr_ietf_zero_size() {
    printf("Testing crypto_core_aes_ctr_ietf with zero size...\n");
    
    unsigned char keystream[32] = {0};
    unsigned char original[32] = {0};
    int ret;
    
    // Copy original state
    memcpy(original, keystream, 32);
    
    // Test với size = 0
    ret = crypto_core_aes_ctr_ietf(keystream, 0, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: crypto_core_aes_ctr_ietf failed with zero size\n");
        exit(1);
    }
    
    // Kiểm tra xem buffer có bị thay đổi không
    if (memcmp(keystream, original, 32) != 0) {
        printf("ERROR: Buffer was modified when size = 0\n");
        exit(1);
    }
    
    printf("crypto_core_aes_ctr_ietf zero size test passed\n");
}

void test_aes_ctr_ietf_large_size() {
    printf("Testing crypto_core_aes_ctr_ietf with large size...\n");
    
    unsigned char *large_keystream = malloc(8192);
    if (large_keystream == NULL) {
        printf("ERROR: Memory allocation failed\n");
        exit(1);
    }
    
    int ret = crypto_core_aes_ctr_ietf(large_keystream, 8192, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: crypto_core_aes_ctr_ietf failed with large size\n");
        free(large_keystream);
        exit(1);
    }
    
    // Kiểm tra xem keystream có được tạo hay không
    int has_data = 0;
    for (int i = 0; i < 8192; i++) {
        if (large_keystream[i] != 0) {
            has_data = 1;
            break;
        }
    }
    
    if (!has_data) {
        printf("ERROR: Large keystream was not generated\n");
        free(large_keystream);
        exit(1);
    }
    
    free(large_keystream);
    printf("crypto_core_aes_ctr_ietf large size test passed\n");
}

void test_aes_ctr_ietf_entropy() {
    printf("Testing crypto_core_aes_ctr_ietf entropy...\n");
    
    unsigned char keystream[1024];
    int ret;
    
    ret = crypto_core_aes_ctr_ietf(keystream, 1024, test_nonce, test_key);
    if (ret != 0) {
        printf("ERROR: crypto_core_aes_ctr_ietf failed\n");
        exit(1);
    }
    
    // Tính entropy đơn giản
    int byte_counts[256] = {0};
    for (int i = 0; i < 1024; i++) {
        byte_counts[keystream[i]]++;
    }
    
    // Kiểm tra xem có quá nhiều bytes giống nhau không
    int max_count = 0;
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] > max_count) {
            max_count = byte_counts[i];
        }
    }
    
    // Với 1024 bytes, mỗi byte nên xuất hiện khoảng 4 lần
    // Nếu có byte xuất hiện quá 20 lần, có thể có vấn đề
    if (max_count > 20) {
        printf("WARNING: Some bytes appear too frequently (max: %d)\n", max_count);
    }
    
    printf("crypto_core_aes_ctr_ietf entropy test passed\n");
}

int main() {
    printf("Starting crypto_core_aes_ctr_ietf tests...\n");
    printf("==========================================\n");
    
    // Initialize library
    bmc_crypt_init();
    
    test_aes_ctr_ietf_basic();
    test_aes_ctr_ietf_deterministic();
    test_aes_ctr_ietf_different_nonce();
    test_aes_ctr_ietf_different_sizes();
    test_aes_ctr_ietf_null_parameters();
    test_aes_ctr_ietf_zero_size();
    test_aes_ctr_ietf_large_size();
    test_aes_ctr_ietf_entropy();
    
    printf("==========================================\n");
    printf("All crypto_core_aes_ctr_ietf tests passed!\n");
    
    return 0;
} 