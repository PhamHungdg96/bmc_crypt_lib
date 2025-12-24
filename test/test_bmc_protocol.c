#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/crypto_bmc_protocol.h>

void test_x25519_keypair_null_checks() {
    printf("Testing x25519 keypair NULL pointer checks...\n");
    unsigned char sk[CURVE25519_KEYLEN];
    unsigned char pk[CURVE25519_KEYLEN];
    
    // Test NULL secret key
    int ret = bmc_protocol_generate_x25519_keypair(NULL, pk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL secret key\n");
        exit(1);
    }
    
    // Test NULL public key
    ret = bmc_protocol_generate_x25519_keypair(sk, NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL public key\n");
        exit(1);
    }
    
    // Test both NULL
    ret = bmc_protocol_generate_x25519_keypair(NULL, NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with both NULL\n");
        exit(1);
    }
    
    // Test valid pointers
    ret = bmc_protocol_generate_x25519_keypair(sk, pk);
    if (ret != 0) {
        printf("ERROR: Should succeed with valid pointers\n");
        exit(1);
    }
    
    printf("x25519 keypair NULL checks passed!\n");
}

void test_ed25519_keypair_null_checks() {
    printf("Testing ed25519 keypair NULL pointer checks...\n");
    unsigned char sk[SKLEN];
    unsigned char pk[PKLEN];
    
    // Test NULL secret key
    int ret = bmc_protocol_generate_ed25519_keypair(NULL, pk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL secret key\n");
        exit(1);
    }
    
    // Test NULL public key
    ret = bmc_protocol_generate_ed25519_keypair(sk, NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL public key\n");
        exit(1);
    }
    
    // Test both NULL
    ret = bmc_protocol_generate_ed25519_keypair(NULL, NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with both NULL\n");
        exit(1);
    }
    
    // Test valid pointers
    ret = bmc_protocol_generate_ed25519_keypair(sk, pk);
    if (ret != 0) {
        printf("ERROR: Should succeed with valid pointers\n");
        exit(1);
    }
    
    printf("ed25519 keypair NULL checks passed!\n");
}

void test_convert_ed25519_to_x25519_null_checks() {
    printf("Testing ed25519 to x25519 conversion NULL pointer checks...\n");
    unsigned char curve_sk[CURVE25519_KEYLEN];
    unsigned char curve_pk[CURVE25519_KEYLEN];
    unsigned char ed_sk[SKLEN];
    unsigned char ed_pk[PKLEN];
    
    // Generate valid ed25519 keypair first
    bmc_protocol_generate_ed25519_keypair(ed_sk, ed_pk);
    
    // Test NULL curve25519 secret key
    int ret = bmc_protocol_convert_ed25519_to_x25519(NULL, curve_pk, ed_sk, ed_pk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL curve25519 secret key\n");
        exit(1);
    }
    
    // Test NULL curve25519 public key
    ret = bmc_protocol_convert_ed25519_to_x25519(curve_sk, NULL, ed_sk, ed_pk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL curve25519 public key\n");
        exit(1);
    }
    
    // Test NULL ed25519 secret key
    ret = bmc_protocol_convert_ed25519_to_x25519(curve_sk, curve_pk, NULL, ed_pk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL ed25519 secret key\n");
        exit(1);
    }
    
    // Test NULL ed25519 public key
    ret = bmc_protocol_convert_ed25519_to_x25519(curve_sk, curve_pk, ed_sk, NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL ed25519 public key\n");
        exit(1);
    }
    
    // Test valid pointers
    ret = bmc_protocol_convert_ed25519_to_x25519(curve_sk, curve_pk, ed_sk, ed_pk);
    if (ret != 0) {
        printf("ERROR: Should succeed with valid pointers\n");
        exit(1);
    }
    
    printf("ed25519 to x25519 conversion NULL checks passed!\n");
}

void test_calculate_secret_null_checks() {
    printf("Testing calculate secret NULL pointer checks...\n");
    unsigned char secret[CURVE25519_KEYLEN];
    unsigned char sk[CURVE25519_KEYLEN];
    unsigned char pk[CURVE25519_KEYLEN];
    
    // Generate valid keypair first
    bmc_protocol_generate_x25519_keypair(sk, pk);
    
    // Test NULL secret
    int ret = bmc_protocol_caculate_secret(NULL, sk, pk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL secret\n");
        exit(1);
    }
    
    // Test NULL secret key
    ret = bmc_protocol_caculate_secret(secret, NULL, pk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL secret key\n");
        exit(1);
    }
    
    // Test NULL public key
    ret = bmc_protocol_caculate_secret(secret, sk, NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL public key\n");
        exit(1);
    }
    
    // Test all NULL
    ret = bmc_protocol_caculate_secret(NULL, NULL, NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with all NULL\n");
        exit(1);
    }
    
    // Test valid pointers
    ret = bmc_protocol_caculate_secret(secret, sk, pk);
    if (ret != 0) {
        printf("ERROR: Should succeed with valid pointers\n");
        exit(1);
    }
    
    printf("calculate secret NULL checks passed!\n");
}

void test_sign_null_checks() {
    printf("Testing sign NULL pointer checks...\n");
    unsigned char sig[SIGLEN];
    unsigned long long siglen;
    unsigned char message[] = "Test message";
    unsigned char sk[SKLEN];
    unsigned char pk[PKLEN];
    
    // Generate valid keypair first
    bmc_protocol_generate_ed25519_keypair(sk, pk);
    
    // Test NULL signature
    int ret = bmc_protocol_sign(NULL, &siglen, message, sizeof(message), sk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL signature\n");
        exit(1);
    }
    
    // Test NULL message
    ret = bmc_protocol_sign(sig, &siglen, NULL, sizeof(message), sk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL message\n");
        exit(1);
    }
    
    // Test NULL secret key
    ret = bmc_protocol_sign(sig, &siglen, message, sizeof(message), NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL secret key\n");
        exit(1);
    }
    
    // Test valid pointers
    ret = bmc_protocol_sign(sig, &siglen, message, sizeof(message), sk);
    if (ret != 0) {
        printf("ERROR: Should succeed with valid pointers\n");
        exit(1);
    }
    
    printf("sign NULL checks passed!\n");
}

void test_verify_null_checks() {
    printf("Testing verify NULL pointer checks...\n");
    unsigned char sig[SIGLEN];
    unsigned long long siglen;
    unsigned char message[] = "Test message";
    unsigned char sk[SKLEN];
    unsigned char pk[PKLEN];
    
    // Generate valid keypair and signature first
    bmc_protocol_generate_ed25519_keypair(sk, pk);
    bmc_protocol_sign(sig, &siglen, message, sizeof(message), sk);
    
    // Test NULL signature
    int ret = bmc_protocol_verify(NULL, message, sizeof(message), pk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL signature\n");
        exit(1);
    }
    
    // Test NULL message
    ret = bmc_protocol_verify(sig, NULL, sizeof(message), pk);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL message\n");
        exit(1);
    }
    
    // Test NULL public key
    ret = bmc_protocol_verify(sig, message, sizeof(message), NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL public key\n");
        exit(1);
    }
    
    // Test valid pointers
    ret = bmc_protocol_verify(sig, message, sizeof(message), pk);
    if (ret != 0) {
        printf("ERROR: Should succeed with valid pointers\n");
        exit(1);
    }
    
    printf("verify NULL checks passed!\n");
}

void test_derive_session_keys_null_checks() {
    printf("Testing derive session keys NULL pointer checks...\n");
    unsigned char shared_secret[CURVE25519_KEYLEN];
    unsigned char ephemeral_pk[CURVE25519_KEYLEN];
    unsigned char peer_pk[CURVE25519_KEYLEN];
    unsigned char root_key[KEY_LEN];
    unsigned char send_chain_key[KEY_LEN];
    unsigned char recv_chain_key[KEY_LEN];
    
    // Generate some test data
    unsigned char sk1[CURVE25519_KEYLEN];
    unsigned char sk2[CURVE25519_KEYLEN];
    bmc_protocol_generate_x25519_keypair(sk1, ephemeral_pk);
    bmc_protocol_generate_x25519_keypair(sk2, peer_pk);
    bmc_protocol_caculate_secret(shared_secret, sk1, peer_pk);
    
    // Test NULL shared_secret
    int ret = bmc_protocol_derive_session_keys(NULL, ephemeral_pk, peer_pk, 
                                               root_key, send_chain_key, recv_chain_key);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL shared_secret\n");
        exit(1);
    }
    
    // Test NULL ephemeral_pk
    ret = bmc_protocol_derive_session_keys(shared_secret, NULL, peer_pk, 
                                           root_key, send_chain_key, recv_chain_key);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL ephemeral_pk\n");
        exit(1);
    }
    
    // Test NULL peer_pk
    ret = bmc_protocol_derive_session_keys(shared_secret, ephemeral_pk, NULL, 
                                           root_key, send_chain_key, recv_chain_key);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL peer_pk\n");
        exit(1);
    }
    
    // Test NULL root_key
    ret = bmc_protocol_derive_session_keys(shared_secret, ephemeral_pk, peer_pk, 
                                           NULL, send_chain_key, recv_chain_key);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL root_key\n");
        exit(1);
    }
    
    // Test NULL send_chain_key
    ret = bmc_protocol_derive_session_keys(shared_secret, ephemeral_pk, peer_pk, 
                                           root_key, NULL, recv_chain_key);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL send_chain_key\n");
        exit(1);
    }
    
    // Test NULL recv_chain_key
    ret = bmc_protocol_derive_session_keys(shared_secret, ephemeral_pk, peer_pk, 
                                           root_key, send_chain_key, NULL);
    if (ret != -1) {
        printf("ERROR: Should fail with NULL recv_chain_key\n");
        exit(1);
    }
    
    // Test valid pointers
    ret = bmc_protocol_derive_session_keys(shared_secret, ephemeral_pk, peer_pk, 
                                           root_key, send_chain_key, recv_chain_key);
    if (ret != 0) {
        printf("ERROR: Should succeed with valid pointers\n");
        exit(1);
    }
    
    printf("derive session keys NULL checks passed!\n");
}

int main() {
    printf("Starting BMC Protocol NULL pointer checks tests...\n");
    bmc_crypt_init();
    
    test_x25519_keypair_null_checks();
    test_ed25519_keypair_null_checks();
    test_convert_ed25519_to_x25519_null_checks();
    test_calculate_secret_null_checks();
    test_sign_null_checks();
    test_verify_null_checks();
    test_derive_session_keys_null_checks();
    
    printf("\nAll BMC Protocol NULL pointer checks tests passed!\n");
    return 0;
}
