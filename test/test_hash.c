#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/crypto_hash_sha256.h>
#include <bmc_crypt/crypto_hash_sha512.h>
#include <bmc_crypt/crypto_hmacsha256.h>
#include <bmc_crypt/crypto_hmacsha512.h>

// Test vectors từ NIST và RFC 4231

// SHA256 test vectors
static const char *sha256_test_strings[] = {
    "",
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
};

static const unsigned char sha256_expected_hashes[][32] = {
    {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
     0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55},
    {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
     0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad},
    {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
     0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1},
    {0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
     0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1}
};

// SHA512 test vectors
static const char *sha512_test_strings[] = {
    "",
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
};

static const unsigned char sha512_expected_hashes[][64] = {
    {0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
     0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
     0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
     0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e},
    {0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
     0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
     0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
     0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f},
    {0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
     0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
     0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
     0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45},
    {0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
     0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
     0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
     0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09}
};

// HMAC test vectors từ RFC 4231
static const unsigned char hmac_key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b
};

static const char *hmac_data = "Hi There";

// static const char hmac_data[] = {
//     0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
// };

static const unsigned char hmac_sha256_expected[] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
    0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
    0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
};

static const unsigned char hmac_sha512_expected[] = {
    0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d,
    0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0,
    0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
    0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
    0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02,
    0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
    0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
    0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54
};

void test_sha256_basic() {
    printf("Testing SHA256 basic functionality...\n");
    
    unsigned char hash[crypto_hash_sha256_BYTES];
    int ret;
    
    // Test với empty string
    ret = crypto_hash_sha256(hash, (const unsigned char *)"", 0);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha256 failed with empty string\n");
        exit(1);
    }
    
    if (memcmp(hash, sha256_expected_hashes[0], crypto_hash_sha256_BYTES) != 0) {
        printf("ERROR: SHA256 hash mismatch for empty string\n");
        exit(1);
    }
    
    printf("SHA256 basic test passed\n");
}

void test_sha256_test_vectors() {
    printf("Testing SHA256 with test vectors...\n");
    
    unsigned char hash[crypto_hash_sha256_BYTES];
    int ret;
    
    for (int i = 0; i < 4; i++) {
        ret = crypto_hash_sha256(hash, (const unsigned char *)sha256_test_strings[i], 
                                 strlen(sha256_test_strings[i]));
        if (ret != 0) {
            printf("ERROR: crypto_hash_sha256 failed for test vector %d\n", i);
            exit(1);
        }
        
        if (memcmp(hash, sha256_expected_hashes[i], crypto_hash_sha256_BYTES) != 0) {
            printf("ERROR: SHA256 hash mismatch for test vector %d\n", i);
            printf("Expected: ");
            for (int j = 0; j < crypto_hash_sha256_BYTES; j++) {
                printf("%02x ", sha256_expected_hashes[i][j]);
            }
            printf("\nGot:      ");
            for (int j = 0; j < crypto_hash_sha256_BYTES; j++) {
                printf("%02x ", hash[j]);
            }
            printf("\n");
            exit(1);
        }
    }
    
    printf("SHA256 test vectors passed\n");
}

void test_sha256_incremental() {
    printf("Testing SHA256 incremental hashing...\n");
    
    crypto_hash_sha256_state state;
    unsigned char hash[crypto_hash_sha256_BYTES];
    int ret;
    
    // Test incremental hashing
    ret = crypto_hash_sha256_init(&state);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha256_init failed\n");
        exit(1);
    }
    
    ret = crypto_hash_sha256_update(&state, (const unsigned char *)"abc", 3);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha256_update failed\n");
        exit(1);
    }
    
    ret = crypto_hash_sha256_final(&state, hash);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha256_final failed\n");
        exit(1);
    }
    
    if (memcmp(hash, sha256_expected_hashes[1], crypto_hash_sha256_BYTES) != 0) {
        printf("ERROR: SHA256 incremental hash mismatch\n");
        exit(1);
    }
    
    printf("SHA256 incremental test passed\n");
}

void test_sha512_basic() {
    printf("Testing SHA512 basic functionality...\n");
    
    unsigned char hash[crypto_hash_sha512_BYTES];
    int ret;
    
    // Test với empty string
    ret = crypto_hash_sha512(hash, (const unsigned char *)"", 0);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha512 failed with empty string\n");
        exit(1);
    }
    
    if (memcmp(hash, sha512_expected_hashes[0], crypto_hash_sha512_BYTES) != 0) {
        printf("ERROR: SHA512 hash mismatch for empty string\n");
        exit(1);
    }
    
    printf("SHA512 basic test passed\n");
}

void test_sha512_test_vectors() {
    printf("Testing SHA512 with test vectors...\n");
    
    unsigned char hash[crypto_hash_sha512_BYTES];
    int ret;
    
    for (int i = 0; i < 4; i++) {
        ret = crypto_hash_sha512(hash, (const unsigned char *)sha512_test_strings[i], 
                                 strlen(sha512_test_strings[i]));
        if (ret != 0) {
            printf("ERROR: crypto_hash_sha512 failed for test vector %d\n", i);
            exit(1);
        }
        
        if (memcmp(hash, sha512_expected_hashes[i], crypto_hash_sha512_BYTES) != 0) {
            printf("ERROR: SHA512 hash mismatch for test vector %d\n", i);
            printf("Expected: ");
            for (int j = 0; j < crypto_hash_sha512_BYTES; j++) {
                printf("%02x ", sha512_expected_hashes[i][j]);
            }
            printf("\nGot:      ");
            for (int j = 0; j < crypto_hash_sha512_BYTES; j++) {
                printf("%02x ", hash[j]);
            }
            printf("\n");
            exit(1);
        }
    }
    
    printf("SHA512 test vectors passed\n");
}

void test_sha512_incremental() {
    printf("Testing SHA512 incremental hashing...\n");
    
    crypto_hash_sha512_state state;
    unsigned char hash[crypto_hash_sha512_BYTES];
    int ret;
    
    // Test incremental hashing
    ret = crypto_hash_sha512_init(&state);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha512_init failed\n");
        exit(1);
    }
    
    ret = crypto_hash_sha512_update(&state, (const unsigned char *)"abc", 3);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha512_update failed\n");
        exit(1);
    }
    
    ret = crypto_hash_sha512_final(&state, hash);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha512_final failed\n");
        exit(1);
    }
    
    if (memcmp(hash, sha512_expected_hashes[1], crypto_hash_sha512_BYTES) != 0) {
        printf("ERROR: SHA512 incremental hash mismatch\n");
        exit(1);
    }
    
    printf("SHA512 incremental test passed\n");
}

void test_hmac_sha256_basic() {
    printf("Testing HMAC-SHA256 basic functionality...\n");
    
    unsigned char hmac[crypto_hmacsha256_BYTES];
    int ret;
    
    // Test với RFC 4231 test vector
    ret = crypto_hmacsha256(hmac, (const unsigned char *)hmac_data, 8, hmac_key, 20);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha256 failed\n");
        exit(1);
    }
    
    if (memcmp(hmac, hmac_sha256_expected, crypto_hmacsha256_BYTES) != 0) {
        printf("ERROR: HMAC-SHA256 mismatch\n");
        printf("Expected: ");
        for (int i = 0; i < crypto_hmacsha256_BYTES; i++) {
            printf("%02x ", hmac_sha256_expected[i]);
        }
        printf("\nGot:      ");
        for (int i = 0; i < crypto_hmacsha256_BYTES; i++) {
            printf("%02x ", hmac[i]);
        }
        printf("\n");
        exit(1);
    }
    
    printf("HMAC-SHA256 basic test passed\n");
}

void test_hmac_sha256_incremental() {
    printf("Testing HMAC-SHA256 incremental...\n");
    
    crypto_hmacsha256_state state;
    unsigned char hmac[crypto_hmacsha256_BYTES];
    int ret;
    
    // Test incremental HMAC
    ret = crypto_hmacsha256_init(&state, hmac_key, sizeof(hmac_key));
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha256_init failed\n");
        exit(1);
    }
    
    ret = crypto_hmacsha256_update(&state, (const unsigned char *)hmac_data, 8);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha256_update failed\n");
        exit(1);
    }
    
    ret = crypto_hmacsha256_final(&state, hmac);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha256_final failed\n");
        exit(1);
    }
    
    if (memcmp(hmac, hmac_sha256_expected, crypto_hmacsha256_BYTES) != 0) {
        printf("ERROR: HMAC-SHA256 incremental mismatch\n");
        exit(1);
    }
    
    printf("HMAC-SHA256 incremental test passed\n");
}

void test_hmac_sha256_verify() {
    printf("Testing HMAC-SHA256 verify...\n");
    
    unsigned char hmac[crypto_hmacsha256_BYTES];
    int ret;
    
    // Generate HMAC
    ret = crypto_hmacsha256(hmac, (const unsigned char *)hmac_data, 8, hmac_key, 20);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha256 failed\n");
        exit(1);
    }
    
    // Verify HMAC
    ret = crypto_hmacsha256_verify(hmac, (const unsigned char *)hmac_data, 8, hmac_key, 20);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha256_verify failed\n");
        exit(1);
    }
    
    // Test with wrong HMAC
    hmac[0] ^= 1;  // Flip one bit
    ret = crypto_hmacsha256_verify(hmac, (const unsigned char *)hmac_data, 8, hmac_key, 20);
    if (ret == 0) {
        printf("ERROR: crypto_hmacsha256_verify should fail with wrong HMAC\n");
        exit(1);
    }
    
    printf("HMAC-SHA256 verify test passed\n");
}

void test_hmac_sha512_basic() {
    printf("Testing HMAC-SHA512 basic functionality...\n");
    
    unsigned char hmac[crypto_hmacsha512_BYTES];
    int ret;
    
    // Test với RFC 4231 test vector
    ret = crypto_hmacsha512(hmac, (const unsigned char *)hmac_data, 8, hmac_key, 20);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha512 failed\n");
        exit(1);
    }
    
    if (memcmp(hmac, hmac_sha512_expected, crypto_hmacsha512_BYTES) != 0) {
        printf("ERROR: HMAC-SHA512 mismatch\n");
        printf("Expected: ");
        for (int i = 0; i < crypto_hmacsha512_BYTES; i++) {
            printf("%02x ", hmac_sha512_expected[i]);
        }
        printf("\nGot:      ");
        for (int i = 0; i < crypto_hmacsha512_BYTES; i++) {
            printf("%02x ", hmac[i]);
        }
        printf("\n");
        exit(1);
    }
    
    printf("HMAC-SHA512 basic test passed\n");
}

void test_hmac_sha512_incremental() {
    printf("Testing HMAC-SHA512 incremental...\n");
    
    crypto_hmacsha512_state state;
    unsigned char hmac[crypto_hmacsha512_BYTES];
    int ret;
    
    // Test incremental HMAC
    ret = crypto_hmacsha512_init(&state, hmac_key, sizeof(hmac_key));
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha512_init failed\n");
        exit(1);
    }
    
    ret = crypto_hmacsha512_update(&state, (const unsigned char *)hmac_data, 8);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha512_update failed\n");
        exit(1);
    }
    
    ret = crypto_hmacsha512_final(&state, hmac);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha512_final failed\n");
        exit(1);
    }
    
    if (memcmp(hmac, hmac_sha512_expected, crypto_hmacsha512_BYTES) != 0) {
        printf("ERROR: HMAC-SHA512 incremental mismatch\n");
        exit(1);
    }
    
    printf("HMAC-SHA512 incremental test passed\n");
}

void test_hmac_sha512_verify() {
    printf("Testing HMAC-SHA512 verify...\n");
    
    unsigned char hmac[crypto_hmacsha512_BYTES];
    int ret;
    
    // Generate HMAC
    ret = crypto_hmacsha512(hmac, (const unsigned char *)hmac_data, 8, hmac_key, 20);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha512 failed\n");
        exit(1);
    }
    
    // Verify HMAC
    ret = crypto_hmacsha512_verify(hmac, (const unsigned char *)hmac_data, 8, hmac_key, 20);
    if (ret != 0) {
        printf("ERROR: crypto_hmacsha512_verify failed\n");
        exit(1);
    }
    
    // Test with wrong HMAC
    hmac[0] ^= 1;  // Flip one bit
    ret = crypto_hmacsha512_verify(hmac, (const unsigned char *)hmac_data, 8, hmac_key,20);
    if (ret == 0) {
        printf("ERROR: crypto_hmacsha512_verify should fail with wrong HMAC\n");
        exit(1);
    }
    
    printf("HMAC-SHA512 verify test passed\n");
}

void test_hash_large_data() {
    printf("Testing hash functions with large data...\n");
    
    unsigned char hash_sha256[crypto_hash_sha256_BYTES];
    unsigned char hash_sha512[crypto_hash_sha512_BYTES];
    unsigned char *large_data = malloc(1000000);  // 1MB
    int ret;
    
    if (!large_data) {
        printf("ERROR: Memory allocation failed\n");
        exit(1);
    }
    
    // Fill with pattern
    for (int i = 0; i < 1000000; i++) {
        large_data[i] = i & 0xFF;
    }
    
    // Test SHA256
    ret = crypto_hash_sha256(hash_sha256, large_data, 1000000);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha256 failed with large data\n");
        free(large_data);
        exit(1);
    }
    
    // Test SHA512
    ret = crypto_hash_sha512(hash_sha512, large_data, 1000000);
    if (ret != 0) {
        printf("ERROR: crypto_hash_sha512 failed with large data\n");
        free(large_data);
        exit(1);
    }
    
    // Check that hashes are not all zeros
    int all_zero_sha256 = 1, all_zero_sha512 = 1;
    
    for (int i = 0; i < crypto_hash_sha256_BYTES; i++) {
        if (hash_sha256[i] != 0) all_zero_sha256 = 0;
    }
    
    for (int i = 0; i < crypto_hash_sha512_BYTES; i++) {
        if (hash_sha512[i] != 0) all_zero_sha512 = 0;
    }
    
    if (all_zero_sha256 || all_zero_sha512) {
        printf("ERROR: Hash of large data is all zeros\n");
        free(large_data);
        exit(1);
    }
    
    free(large_data);
    printf("Hash large data test passed\n");
}

int main() {
    printf("Starting hash and HMAC tests...\n");
    printf("==============================\n");
    
    // Initialize library
    bmc_crypt_init();
    
    // SHA256 tests
    test_sha256_basic();
    test_sha256_test_vectors();
    test_sha256_incremental();
    
    // SHA512 tests
    test_sha512_basic();
    test_sha512_test_vectors();
    test_sha512_incremental();
    
    // HMAC-SHA256 tests
    test_hmac_sha256_basic();
    test_hmac_sha256_incremental();
    test_hmac_sha256_verify();
    
    // HMAC-SHA512 tests
    test_hmac_sha512_basic();
    test_hmac_sha512_incremental();
    test_hmac_sha512_verify();
    
    // Large data tests
    test_hash_large_data();
    
    printf("==============================\n");
    printf("All hash and HMAC tests passed!\n");
    
    return 0;
} 