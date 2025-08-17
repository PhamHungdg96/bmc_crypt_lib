#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/utils.h>
#include <bmc_crypt/crypto_hkdf_256.h>

// Test vectors từ RFC 5869
static const unsigned char test_ikm[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static const unsigned char test_salt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const unsigned char test_info[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9
};

static const unsigned char expected_prk[] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
    0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
    0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
};

static const unsigned char expected_okm[] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65
};

void test_hkdf_create_destroy() {
    printf("Testing HKDF create and destroy...\n");
    
    hkdf_context *context = NULL;
    int ret;
    
    // Test create
    ret = hkdf_create(&context);
    if (ret != 0) {
        printf("ERROR: hkdf_create failed\n");
        exit(1);
    }
    
    if (context == NULL) {
        printf("ERROR: context is NULL after creation\n");
        exit(1);
    }
    
    if (context->state == NULL) {
        printf("ERROR: HMAC state is NULL after creation\n");
        exit(1);
    }
    
    if (context->iteration_start_offset != 1) {
        printf("ERROR: Wrong iteration start offset\n");
        exit(1);
    }
    
    hkdf_destroy(context);
    
    // Test create with NULL context
    ret = hkdf_create(NULL);
    if (ret == 0) {
        printf("ERROR: hkdf_create should fail with NULL context\n");
        exit(1);
    }
    
    printf("HKDF create and destroy test passed\n");
}

void test_hkdf_extract() {
    printf("Testing HKDF extract...\n");
    
    hkdf_context *context = NULL;
    unsigned char prk[crypto_hkdf_sha256_KEYBYTES];
    int ret;
    
    ret = hkdf_create(&context);
    if (ret != 0) {
        printf("ERROR: Failed to create HKDF context\n");
        exit(1);
    }
    
    // Test extract with RFC 5869 test vector
    ret = hkdf_extract(context, prk, test_salt, sizeof(test_salt), 
                       test_ikm, sizeof(test_ikm));
    if (ret != 0) {
        printf("ERROR: hkdf_extract failed\n");
        exit(1);
    }
    
    // Verify PRK
    if (memcmp(prk, expected_prk, crypto_hkdf_sha256_KEYBYTES) != 0) {
        printf("ERROR: PRK mismatch\n");
        printf("Expected: ");
        for (int i = 0; i < crypto_hkdf_sha256_KEYBYTES; i++) {
            printf("%02x ", expected_prk[i]);
        }
        printf("\nGot:      ");
        for (int i = 0; i < crypto_hkdf_sha256_KEYBYTES; i++) {
            printf("%02x ", prk[i]);
        }
        printf("\n");
        exit(1);
    }
    
    // Test extract with NULL salt (should use empty salt)
    ret = hkdf_extract(context, prk, NULL, 0, test_ikm, sizeof(test_ikm));
    if (ret != 0) {
        printf("ERROR: hkdf_extract failed with NULL salt\n");
        exit(1);
    }
    
    // Test extract with NULL parameters
    ret = hkdf_extract(NULL, prk, test_salt, sizeof(test_salt), 
                       test_ikm, sizeof(test_ikm));
    if (ret == 0) {
        printf("ERROR: hkdf_extract should fail with NULL context\n");
        exit(1);
    }
    
    ret = hkdf_extract(context, NULL, test_salt, sizeof(test_salt), 
                       test_ikm, sizeof(test_ikm));
    if (ret == 0) {
        printf("ERROR: hkdf_extract should fail with NULL PRK\n");
        exit(1);
    }
    
    hkdf_destroy(context);
    printf("HKDF extract test passed\n");
}

void test_hkdf_expand() {
    printf("Testing HKDF expand...\n");
    
    hkdf_context *context = NULL;
    unsigned char *output = NULL;
    int ret;
    
    ret = hkdf_create(&context);
    if (ret != 0) {
        printf("ERROR: Failed to create HKDF context\n");
        exit(1);
    }
    
    // Test expand with RFC 5869 test vector
    ret = hkdf_expand(context, &output, expected_prk, crypto_hkdf_sha256_KEYBYTES,
                      test_info, sizeof(test_info), 42);
    if (ret != 0) {
        printf("ERROR: hkdf_expand failed\n");
        exit(1);
    }
    
    if (output == NULL) {
        printf("ERROR: Output is NULL after expand\n");
        exit(1);
    }
    
    // Verify output
    if (memcmp(output, expected_okm, 42) != 0) {
        printf("ERROR: Output mismatch\n");
        printf("Expected: ");
        for (int i = 0; i < 42; i++) {
            printf("%02x ", expected_okm[i]);
        }
        printf("\nGot:      ");
        for (int i = 0; i < 42; i++) {
            printf("%02x ", output[i]);
        }
        printf("\n");
        exit(1);
    }
    
    bmc_crypt_free(output);
    
    // Test expand with NULL parameters
    ret = hkdf_expand(NULL, &output, expected_prk, crypto_hkdf_sha256_KEYBYTES,
                      test_info, sizeof(test_info), 42);
    if (ret == 0) {
        printf("ERROR: hkdf_expand should fail with NULL context\n");
        exit(1);
    }
    
    ret = hkdf_expand(context, NULL, expected_prk, crypto_hkdf_sha256_KEYBYTES,
                      test_info, sizeof(test_info), 42);
    if (ret == 0) {
        printf("ERROR: hkdf_expand should fail with NULL output\n");
        exit(1);
    }
    
    ret = hkdf_expand(context, &output, NULL, crypto_hkdf_sha256_KEYBYTES,
                      test_info, sizeof(test_info), 42);
    if (ret == 0) {
        printf("ERROR: hkdf_expand should fail with NULL PRK\n");
        exit(1);
    }
    
    hkdf_destroy(context);
    printf("HKDF expand test passed\n");
}

void test_hkdf_derive_secrets() {
    printf("Testing HKDF derive secrets...\n");
    
    hkdf_context *context = NULL;
    unsigned char *output = NULL;
    int ret;
    
    ret = hkdf_create(&context);
    if (ret != 0) {
        printf("ERROR: Failed to create HKDF context\n");
        exit(1);
    }
    
    // Test derive secrets with RFC 5869 test vector
    ret = hkdf_derive_secrets(context, &output, test_ikm, sizeof(test_ikm),
                              test_salt, sizeof(test_salt),
                              test_info, sizeof(test_info), 42);
    if (ret != 0) {
        printf("ERROR: hkdf_derive_secrets failed\n");
        exit(1);
    }
    
    if (output == NULL) {
        printf("ERROR: Output is NULL after derive secrets\n");
        exit(1);
    }
    
    // Verify output
    if (memcmp(output, expected_okm, 42) != 0) {
        printf("ERROR: Output mismatch in derive secrets\n");
        printf("Expected: ");
        for (int i = 0; i < 42; i++) {
            printf("%02x ", expected_okm[i]);
        }
        printf("\nGot:      ");
        for (int i = 0; i < 42; i++) {
            printf("%02x ", output[i]);
        }
        printf("\n");
        exit(1);
    }
    
    bmc_crypt_free(output);
    
    // Test derive secrets with NULL parameters
    ret = hkdf_derive_secrets(NULL, &output, test_ikm, sizeof(test_ikm),
                              test_salt, sizeof(test_salt),
                              test_info, sizeof(test_info), 42);
    if (ret == 0) {
        printf("ERROR: hkdf_derive_secrets should fail with NULL context\n");
        exit(1);
    }
    
    ret = hkdf_derive_secrets(context, NULL, test_ikm, sizeof(test_ikm),
                              test_salt, sizeof(test_salt),
                              test_info, sizeof(test_info), 42);
    if (ret == 0) {
        printf("ERROR: hkdf_derive_secrets should fail with NULL output\n");
        exit(1);
    }
    
    ret = hkdf_derive_secrets(context, &output, NULL, sizeof(test_ikm),
                              test_salt, sizeof(test_salt),
                              test_info, sizeof(test_info), 42);
    if (ret == 0) {
        printf("ERROR: hkdf_derive_secrets should fail with NULL IKM\n");
        exit(1);
    }
    
    hkdf_destroy(context);
    printf("HKDF derive secrets test passed\n");
}

void test_hkdf_compare() {
    printf("Testing HKDF compare...\n");
    
    hkdf_context *context1 = NULL, *context2 = NULL;
    int ret;
    
    ret = hkdf_create(&context1);
    if (ret != 0) {
        printf("ERROR: Failed to create first HKDF context\n");
        exit(1);
    }
    
    ret = hkdf_create(&context2);
    if (ret != 0) {
        printf("ERROR: Failed to create second HKDF context\n");
        exit(1);
    }
    
    // Test compare with different contexts
    ret = hkdf_compare(context1, context2);
    if (ret != 0) {
        printf("ERROR: hkdf_compare should return negative for different contexts\n");
        exit(1);
    }
    
    ret = hkdf_compare(context2, context1);
    if (ret != 0) {
        printf("ERROR: hkdf_compare should return positive for different contexts\n");
        exit(1);
    }
    
    // Test compare with same context
    ret = hkdf_compare(context1, context1);
    if (ret != 0) {
        printf("ERROR: hkdf_compare should return 0 for same context\n");
        exit(1);
    }
    
    hkdf_destroy(context1);
    hkdf_destroy(context2);
    printf("HKDF compare test passed\n");
}

void test_hkdf_large_output() {
    printf("Testing HKDF with large output...\n");
    
    hkdf_context *context = NULL;
    unsigned char *output = NULL;
    int ret;
    
    ret = hkdf_create(&context);
    if (ret != 0) {
        printf("ERROR: Failed to create HKDF context\n");
        exit(1);
    }
    
    // Test with large output (requires multiple iterations)
    ret = hkdf_derive_secrets(context, &output, test_ikm, sizeof(test_ikm),
                              test_salt, sizeof(test_salt),
                              test_info, sizeof(test_info), 1000);
    if (ret != 0) {
        printf("ERROR: hkdf_derive_secrets failed with large output\n");
        exit(1);
    }
    
    if (output == NULL) {
        printf("ERROR: Output is NULL after large derive secrets\n");
        exit(1);
    }
    
    // Check that output is not all zeros
    int all_zero = 1;
    for (int i = 0; i < 1000; i++) {
        if (output[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    
    if (all_zero) {
        printf("ERROR: Large output is all zeros\n");
        exit(1);
    }
    
    bmc_crypt_free(output);
    hkdf_destroy(context);
    printf("HKDF large output test passed\n");
}

int main() {
    printf("Starting HKDF tests...\n");
    printf("====================\n");
    
    // Initialize library
    bmc_crypt_init();
    
    test_hkdf_create_destroy();
    test_hkdf_extract();
    test_hkdf_expand();
    test_hkdf_derive_secrets();
    test_hkdf_compare();
    test_hkdf_large_output();
    
    printf("====================\n");
    printf("All HKDF tests passed!\n");
    
    return 0;
} 