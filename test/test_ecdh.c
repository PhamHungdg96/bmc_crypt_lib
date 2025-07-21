#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/crypto_scalarmult_curve25519.h>
#include <bmc_crypt/randombytes.h>

void test_ecdh_curve25519() {
    printf("Testing ECDH Curve25519 key exchange...\n");
    unsigned char alice_sk[crypto_scalarmult_curve25519_SCALARBYTES];
    unsigned char alice_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char bob_sk[crypto_scalarmult_curve25519_SCALARBYTES];
    unsigned char bob_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char alice_shared[crypto_scalarmult_curve25519_BYTES];
    unsigned char bob_shared[crypto_scalarmult_curve25519_BYTES];

    // Sinh khoá bí mật ngẫu nhiên
    randombytes_buf(alice_sk, sizeof(alice_sk));
    randombytes_buf(bob_sk, sizeof(bob_sk));

    // Sinh public key
    int ret = crypto_scalarmult_curve25519_base(alice_pk, alice_sk);
    if (ret != 0) {
        printf("ERROR: Alice public key generation failed\n");
        exit(1);
    }
    ret = crypto_scalarmult_curve25519_base(bob_pk, bob_sk);
    if (ret != 0) {
        printf("ERROR: Bob public key generation failed\n");
        exit(1);
    }

    // Tính shared secret
    ret = crypto_scalarmult_curve25519(alice_shared, alice_sk, bob_pk);
    if (ret != 0) {
        printf("ERROR: Alice shared secret calculation failed\n");
        exit(1);
    }
    ret = crypto_scalarmult_curve25519(bob_shared, bob_sk, alice_pk);
    if (ret != 0) {
        printf("ERROR: Bob shared secret calculation failed\n");
        exit(1);
    }

    // So sánh shared secret
    if (memcmp(alice_shared, bob_shared, crypto_scalarmult_curve25519_BYTES) != 0) {
        printf("ERROR: Shared secrets do not match!\n");
        exit(1);
    }
    printf("ECDH Curve25519 test passed!\n");
}

int main() {
    printf("Starting ECDH tests...\n");
    bmc_crypt_init();
    test_ecdh_curve25519();
    printf("All ECDH tests passed!\n");
    return 0;
} 