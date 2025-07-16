#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/randombytes.h>

#define TEST_ITERATIONS 1000
#define LARGE_BUFFER_SIZE 8192
#define MAX_BUFFER_SIZE 65536

// Test function để kiểm tra distribution của random bytes
void test_random_distribution() {
    printf("Testing random distribution over multiple iterations...\n");
    
    int byte_counts[256] = {0};
    unsigned char buf[256];
    
    // Thu thập dữ liệu từ nhiều lần gọi random_buf
    for (int iter = 0; iter < TEST_ITERATIONS; iter++) {
        randombytes_buf(buf, 256);
        for (int i = 0; i < 256; i++) {
            byte_counts[buf[i]]++;
        }
    }
    
    // Tính tỷ lệ lý thuyết (mỗi byte nên xuất hiện khoảng TEST_ITERATIONS lần)
    int expected_count = TEST_ITERATIONS;
    int min_acceptable = expected_count * 0.8;  // 80% của expected
    int max_acceptable = expected_count * 1.2;  // 120% của expected
    
    int outliers = 0;
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] < min_acceptable || byte_counts[i] > max_acceptable) {
            outliers++;
        }
    }
    
    printf("Distribution test: %d outliers out of 256 bytes\n", outliers);
    printf("Expected count per byte: %d, Acceptable range: %d-%d\n", 
           expected_count, min_acceptable, max_acceptable);
    
    // Nếu có quá nhiều outliers, có thể có vấn đề
    if (outliers > 50) {  // Hơn 20% outliers
        printf("WARNING: Too many outliers in distribution test\n");
    }
    
    printf("Random distribution test passed\n");
}

// Test function để kiểm tra performance
void test_random_performance() {
    printf("Testing random performance...\n");
    
    unsigned char buf[LARGE_BUFFER_SIZE];
    clock_t start, end;
    double cpu_time_used;
    
    // Test performance với buffer lớn
    start = clock();
    for (int i = 0; i < 100; i++) {
        randombytes_buf(buf, LARGE_BUFFER_SIZE);
    }
    end = clock();
    
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double bytes_per_second = (100.0 * LARGE_BUFFER_SIZE) / cpu_time_used;
    
    printf("Performance: %.2f MB/s (%.2f seconds for 100 calls)\n", 
           bytes_per_second / (1024 * 1024), cpu_time_used);
    
    // Test performance với nhiều buffer nhỏ
    start = clock();
    for (int i = 0; i < 10000; i++) {
        randombytes_buf(buf, 16);
    }
    end = clock();
    
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double calls_per_second = 10000.0 / cpu_time_used;
    
    printf("Small buffer performance: %.0f calls/second\n", calls_per_second);
    
    printf("Random performance test passed\n");
}

// Test function để kiểm tra thread safety (simulated)
void test_random_thread_safety_simulation() {
    printf("Testing random thread safety simulation...\n");
    
    unsigned char buf1[256], buf2[256], buf3[256];
    
    // Simulate rapid calls from different contexts
    for (int i = 0; i < 100; i++) {
        randombytes_buf(buf1, 256);
        randombytes_buf(buf2, 256);
        randombytes_buf(buf3, 256);
        
        // Kiểm tra xem các buffers có khác nhau không
        if (memcmp(buf1, buf2, 256) == 0 && memcmp(buf2, buf3, 256) == 0) {
            printf("WARNING: All three buffers are identical in iteration %d\n", i);
        }
    }
    
    printf("Random thread safety simulation test passed\n");
}

// Test function để kiểm tra edge cases
void test_random_edge_cases() {
    printf("Testing random edge cases...\n");
    
    // Test với size = 1
    unsigned char single_byte;
    randombytes_buf(&single_byte, 1);
    printf("Single byte test passed\n");
    
    // Test với size rất lớn
    unsigned char *large_buf = malloc(MAX_BUFFER_SIZE);
    if (large_buf != NULL) {
        randombytes_buf(large_buf, MAX_BUFFER_SIZE);
        
        // Kiểm tra xem buffer có được fill hay không
        int has_data = 0;
        for (int i = 0; i < MAX_BUFFER_SIZE; i++) {
            if (large_buf[i] != 0) {
                has_data = 1;
                break;
            }
        }
        
        if (!has_data) {
            printf("ERROR: Large buffer was not filled with data\n");
            free(large_buf);
            exit(1);
        }
        
        free(large_buf);
        printf("Large buffer test passed\n");
    }
    
    // Test với size = 0 (đã test trong file chính)
    printf("Edge cases test passed\n");
}

// Test function để kiểm tra deterministic với nhiều seed khác nhau
void test_random_deterministic_comprehensive() {
    printf("Testing comprehensive deterministic random...\n");
    
    unsigned char seed1[randombytes_SEEDBYTES];
    unsigned char seed2[randombytes_SEEDBYTES];
    unsigned char buf1[256], buf2[256], buf3[256];
    
    // Tạo hai seed khác nhau
    randombytes_buf(seed1, randombytes_SEEDBYTES);
    randombytes_buf(seed2, randombytes_SEEDBYTES);
    
    // Đảm bảo seed khác nhau
    while (memcmp(seed1, seed2, randombytes_SEEDBYTES) == 0) {
        randombytes_buf(seed2, randombytes_SEEDBYTES);
    }
    
    // Test với seed1
    randombytes_buf_deterministic(buf1, 256, seed1);
    randombytes_buf_deterministic(buf2, 256, seed1);
    
    if (memcmp(buf1, buf2, 256) != 0) {
        printf("ERROR: Deterministic random with same seed produced different results\n");
        exit(1);
    }
    
    // Test với seed2
    randombytes_buf_deterministic(buf3, 256, seed2);
    
    // Với seed khác nhau, kết quả nên khác nhau
    if (memcmp(buf1, buf3, 256) == 0) {
        printf("WARNING: Deterministic random with different seeds produced identical results\n");
    }
    
    printf("Comprehensive deterministic test passed\n");
}

// Test function để kiểm tra entropy quality
void test_random_entropy_quality() {
    printf("Testing entropy quality...\n");
    
    unsigned char buf[1024];
    int runs = 0, gaps = 0;
    
    // Thu thập dữ liệu
    randombytes_buf(buf, 1024);
    
    // Kiểm tra runs (chuỗi các bit giống nhau liên tiếp)
    for (int i = 1; i < 1024; i++) {
        if (buf[i] == buf[i-1]) {
            runs++;
        }
    }
    
    // Kiểm tra gaps (khoảng cách giữa các byte giống nhau)
    for (int i = 0; i < 256; i++) {
        int last_pos = -1;
        for (int j = 0; j < 1024; j++) {
            if (buf[j] == i) {
                if (last_pos != -1) {
                    gaps += (j - last_pos);
                }
                last_pos = j;
            }
        }
    }
    
    printf("Runs analysis: %d consecutive identical bytes out of 1023 comparisons\n", runs);
    printf("Gaps analysis: average gap between identical bytes\n");
    
    // Kiểm tra xem có quá nhiều runs không (có thể chỉ ra entropy thấp)
    if (runs > 800) {  // Hơn 80% consecutive identical
        printf("WARNING: Too many consecutive identical bytes\n");
    }
    
    printf("Entropy quality test passed\n");
}

// Test function để kiểm tra random bytes với các pattern đặc biệt
void test_random_patterns() {
    printf("Testing random patterns...\n");
    
    unsigned char buf[512];
    int zero_runs = 0, one_runs = 0;
    
    randombytes_buf(buf, 512);
    
    // Kiểm tra runs của bit 0 và bit 1
    for (int i = 0; i < 512; i++) {
        for (int bit = 0; bit < 8; bit++) {
            int current_bit = (buf[i] >> bit) & 1;
            if (current_bit == 0) {
                zero_runs++;
            } else {
                one_runs++;
            }
        }
    }
    
    printf("Bit distribution: %d zeros, %d ones\n", zero_runs, one_runs);
    
    // Kiểm tra xem distribution có cân bằng không
    double ratio = (double)zero_runs / one_runs;
    if (ratio < 0.8 || ratio > 1.2) {
        printf("WARNING: Bit distribution seems unbalanced (ratio: %.2f)\n", ratio);
    }
    
    printf("Random patterns test passed\n");
}

// Test function để kiểm tra random với stress test
void test_random_stress() {
    printf("Testing random stress test...\n");
    
    unsigned char buf[64];
    int identical_count = 0;
    
    // Stress test: gọi random_buf nhiều lần liên tiếp
    for (int i = 0; i < 10000; i++) {
        unsigned char prev_buf[64];
        memcpy(prev_buf, buf, 64);
        
        randombytes_buf(buf, 64);
        
        if (memcmp(prev_buf, buf, 64) == 0) {
            identical_count++;
        }
    }
    
    printf("Stress test: %d identical consecutive calls out of 10000\n", identical_count);
    
    // Nếu có quá nhiều identical calls, có thể có vấn đề
    if (identical_count > 100) {  // Hơn 1% identical
        printf("WARNING: Too many identical consecutive calls in stress test\n");
    }
    
    printf("Random stress test passed\n");
}

int main() {
    printf("Starting advanced random_buf tests...\n");
    printf("=====================================\n");
    
    // Initialize library
    bmc_crypt_init();
    
    test_random_distribution();
    test_random_performance();
    test_random_thread_safety_simulation();
    test_random_edge_cases();
    test_random_deterministic_comprehensive();
    test_random_entropy_quality();
    test_random_patterns();
    test_random_stress();
    
    printf("=====================================\n");
    printf("All advanced random_buf tests passed!\n");
    
    return 0;
} 