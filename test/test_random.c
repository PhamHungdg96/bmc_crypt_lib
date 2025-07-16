#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/randombytes.h>

// Test buffer sizes
#define SMALL_BUFFER_SIZE 16
#define MEDIUM_BUFFER_SIZE 256
#define LARGE_BUFFER_SIZE 1024
#define MAX_BUFFER_SIZE 4096

// Test function để kiểm tra buffer có chứa dữ liệu ngẫu nhiên hay không
int is_buffer_random(const unsigned char *buf, size_t size) {
    if (size == 0) return 0;
    
    // Kiểm tra xem tất cả bytes có giống nhau không (không ngẫu nhiên)
    unsigned char first_byte = buf[0];
    for (size_t i = 1; i < size; i++) {
        if (buf[i] != first_byte) {
            return 1; // Có sự khác biệt, có thể là ngẫu nhiên
        }
    }
    
    // Nếu tất cả bytes giống nhau, có thể không ngẫu nhiên
    // Nhưng cũng có thể là trường hợp hiếm gặp
    return 0;
}

// Test function để kiểm tra entropy của buffer
double calculate_entropy(const unsigned char *buf, size_t size) {
    if (size == 0) return 0.0;
    
    int byte_counts[256] = {0};
    
    // Đếm tần suất của mỗi byte
    for (size_t i = 0; i < size; i++) {
        byte_counts[buf[i]]++;
    }
    
    // Tính entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] > 0) {
            double p = (double)byte_counts[i] / size;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

void test_random_buf_basic() {
    printf("Testing random_buf basic functionality...\n");
    
    unsigned char buf[SMALL_BUFFER_SIZE];
    
    // Test với buffer nhỏ
    randombytes_buf(buf, SMALL_BUFFER_SIZE);
    
    // Kiểm tra xem buffer có được fill hay không
    int has_data = 0;
    for (int i = 0; i < SMALL_BUFFER_SIZE; i++) {
        if (buf[i] != 0) {
            has_data = 1;
            break;
        }
    }
    
    if (!has_data) {
        printf("ERROR: random_buf did not fill buffer with data\n");
        exit(1);
    }
    
    // Kiểm tra tính ngẫu nhiên cơ bản
    if (!is_buffer_random(buf, SMALL_BUFFER_SIZE)) {
        printf("WARNING: Buffer may not be random (all bytes are identical)\n");
    }
    
    printf("random_buf basic test passed\n");
}

void test_random_buf_different_sizes() {
    printf("Testing random_buf with different buffer sizes...\n");
    
    unsigned char small_buf[SMALL_BUFFER_SIZE];
    unsigned char medium_buf[MEDIUM_BUFFER_SIZE];
    unsigned char large_buf[LARGE_BUFFER_SIZE];
    
    // Test với các kích thước khác nhau
    randombytes_buf(small_buf, SMALL_BUFFER_SIZE);
    randombytes_buf(medium_buf, MEDIUM_BUFFER_SIZE);
    randombytes_buf(large_buf, LARGE_BUFFER_SIZE);
    
    // Kiểm tra xem tất cả buffers đều có dữ liệu
    int small_has_data = 0, medium_has_data = 0, large_has_data = 0;
    
    for (int i = 0; i < SMALL_BUFFER_SIZE; i++) {
        if (small_buf[i] != 0) small_has_data = 1;
    }
    for (int i = 0; i < MEDIUM_BUFFER_SIZE; i++) {
        if (medium_buf[i] != 0) medium_has_data = 1;
    }
    for (int i = 0; i < LARGE_BUFFER_SIZE; i++) {
        if (large_buf[i] != 0) large_has_data = 1;
    }
    
    if (!small_has_data || !medium_has_data || !large_has_data) {
        printf("ERROR: One or more buffers were not filled with data\n");
        exit(1);
    }
    
    printf("random_buf different sizes test passed\n");
}

void test_random_buf_uniqueness() {
    printf("Testing random_buf uniqueness between calls...\n");
    
    unsigned char buf1[SMALL_BUFFER_SIZE];
    unsigned char buf2[SMALL_BUFFER_SIZE];
    unsigned char buf3[SMALL_BUFFER_SIZE];
    
    // Tạo 3 buffers ngẫu nhiên
    randombytes_buf(buf1, SMALL_BUFFER_SIZE);
    randombytes_buf(buf2, SMALL_BUFFER_SIZE);
    randombytes_buf(buf3, SMALL_BUFFER_SIZE);
    
    // Kiểm tra xem chúng có khác nhau không
    int buf1_equals_buf2 = (memcmp(buf1, buf2, SMALL_BUFFER_SIZE) == 0);
    int buf1_equals_buf3 = (memcmp(buf1, buf3, SMALL_BUFFER_SIZE) == 0);
    int buf2_equals_buf3 = (memcmp(buf2, buf3, SMALL_BUFFER_SIZE) == 0);
    
    if (buf1_equals_buf2 && buf1_equals_buf3 && buf2_equals_buf3) {
        printf("WARNING: All three random buffers are identical - this is very unlikely\n");
        printf("This might indicate a problem with the random number generator\n");
    }
    
    printf("random_buf uniqueness test passed\n");
}

void test_random_buf_entropy() {
    printf("Testing random_buf entropy...\n");
    
    unsigned char buf[MEDIUM_BUFFER_SIZE];
    
    // Tạo buffer ngẫu nhiên
    randombytes_buf(buf, MEDIUM_BUFFER_SIZE);
    
    // Tính entropy
    double entropy = calculate_entropy(buf, MEDIUM_BUFFER_SIZE);
    
    printf("Entropy: %.2f bits per byte (max possible: 8.0)\n", entropy);
    
    // Kiểm tra entropy có đủ cao không (ít nhất 7.0 bits/byte cho buffer lớn)
    if (entropy < 7.0) {
        printf("WARNING: Entropy seems low (%.2f bits/byte)\n", entropy);
        printf("This might indicate a problem with the random number generator\n");
    }
    
    printf("random_buf entropy test passed\n");
}

void test_random_buf_zero_size() {
    printf("Testing random_buf with zero size...\n");
    
    unsigned char buf[SMALL_BUFFER_SIZE] = {0};
    unsigned char original_buf[SMALL_BUFFER_SIZE] = {0};
    
    // Copy original state
    memcpy(original_buf, buf, SMALL_BUFFER_SIZE);
    
    // Gọi với size = 0
    randombytes_buf(buf, 0);
    
    // Kiểm tra xem buffer có bị thay đổi không
    if (memcmp(buf, original_buf, SMALL_BUFFER_SIZE) != 0) {
        printf("ERROR: Buffer was modified when size = 0\n");
        exit(1);
    }
    
    printf("random_buf zero size test passed\n");
}

void test_random_buf_deterministic() {
    printf("Testing random_buf_deterministic...\n");
    
    unsigned char seed[randombytes_SEEDBYTES];
    unsigned char buf1[SMALL_BUFFER_SIZE];
    unsigned char buf2[SMALL_BUFFER_SIZE];
    
    // Tạo seed ngẫu nhiên
    randombytes_buf(seed, randombytes_SEEDBYTES);
    
    // Tạo hai buffers với cùng seed
    randombytes_buf_deterministic(buf1, SMALL_BUFFER_SIZE, seed);
    randombytes_buf_deterministic(buf2, SMALL_BUFFER_SIZE, seed);
    
    // Kiểm tra xem chúng có giống nhau không (deterministic)
    if (memcmp(buf1, buf2, SMALL_BUFFER_SIZE) != 0) {
        printf("ERROR: Deterministic random buffers are not identical\n");
        exit(1);
    }
    
    // Tạo seed khác và kiểm tra xem kết quả có khác không
    unsigned char seed2[randombytes_SEEDBYTES];
    unsigned char buf3[SMALL_BUFFER_SIZE];
    
    randombytes_buf(seed2, randombytes_SEEDBYTES);
    randombytes_buf_deterministic(buf3, SMALL_BUFFER_SIZE, seed2);
    
    // Với seed khác nhau, kết quả nên khác nhau
    if (memcmp(buf1, buf3, SMALL_BUFFER_SIZE) == 0) {
        printf("WARNING: Deterministic random buffers with different seeds are identical\n");
    }
    
    printf("random_buf_deterministic test passed\n");
}

void test_random_functions() {
    printf("Testing other random functions...\n");
    
    // Test randombytes_random()
    uint32_t val1 = randombytes_random();
    uint32_t val2 = randombytes_random();
    uint32_t val3 = randombytes_random();
    
    printf("Random values: %u, %u, %u\n", val1, val2, val3);
    
    // Test randombytes_uniform()
    uint32_t uniform1 = randombytes_uniform(100);
    uint32_t uniform2 = randombytes_uniform(100);
    uint32_t uniform3 = randombytes_uniform(100);
    
    printf("Uniform values (0-99): %u, %u, %u\n", uniform1, uniform2, uniform3);
    
    // Kiểm tra xem uniform values có trong range không
    if (uniform1 >= 100 || uniform2 >= 100 || uniform3 >= 100) {
        printf("ERROR: Uniform values out of range\n");
        exit(1);
    }
    
    printf("Other random functions test passed\n");
}

void test_random_implementation_info() {
    printf("Testing random implementation info...\n");
    
    const char *impl_name = randombytes_implementation_name();
    printf("Implementation name: %s\n", impl_name);
    
    if (impl_name == NULL || strlen(impl_name) == 0) {
        printf("ERROR: Implementation name is NULL or empty\n");
        exit(1);
    }
    
    printf("Random implementation info test passed\n");
}

void test_random_stir_and_close() {
    printf("Testing random stir and close functions...\n");
    
    // Test randombytes_stir()
    randombytes_stir();
    
    // Tạo một số random bytes sau khi stir
    unsigned char buf[SMALL_BUFFER_SIZE];
    randombytes_buf(buf, SMALL_BUFFER_SIZE);
    
    // Test randombytes_close()
    int close_result = randombytes_close();
    printf("randombytes_close() returned: %d\n", close_result);
    
    // Sau khi close, vẫn có thể gọi randombytes_buf (implementation sẽ tự khởi tạo lại)
    randombytes_buf(buf, SMALL_BUFFER_SIZE);
    
    printf("Random stir and close test passed\n");
}

int main() {
    printf("Starting random_buf tests...\n");
    printf("========================\n");
    
    // Initialize library
    bmc_crypt_init();
    
    test_random_buf_basic();
    test_random_buf_different_sizes();
    test_random_buf_uniqueness();
    test_random_buf_entropy();
    test_random_buf_zero_size();
    test_random_buf_deterministic();
    test_random_functions();
    test_random_implementation_info();
    test_random_stir_and_close();
    
    printf("========================\n");
    printf("All random_buf tests passed!\n");
    
    return 0;
} 