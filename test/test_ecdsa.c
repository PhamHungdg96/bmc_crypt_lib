#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <bmc_crypt/core.h>
#include <bmc_crypt/crypto_sign.h>

void test_eddsa_ed25519() {
    printf("Testing EdDSA (Ed25519) signature...\n");
    unsigned char pk[32];
    unsigned char sk[64];
    unsigned char sig[64];
    unsigned long long siglen;
    const unsigned char message[] = "BMC Crypto Lib - Ed25519 test";
    size_t mlen = sizeof(message) - 1;

    // Sinh khoá
    int ret = crypto_sign_ed25519_keypair(pk, sk);
    if (ret != 0) {
        printf("ERROR: Keypair generation failed\n");
        exit(1);
    }

    // Ký
    ret = crypto_sign_ed25519_detached(sig, &siglen, message, mlen, sk);
    if (ret != 0 || siglen != 64) {
        printf("ERROR: Signing failed\n");
        exit(1);
    }

    // Xác thực chữ ký đúng
    ret = crypto_sign_ed25519_verify_detached(sig, message, mlen, pk);
    if (ret != 0) {
        printf("ERROR: Signature verification failed\n");
        exit(1);
    }

    // Thay đổi message, xác thực phải fail
    unsigned char tampered[64];
    memcpy(tampered, message, mlen);
    tampered[0] ^= 0xFF;
    ret = crypto_sign_ed25519_verify_detached(sig, tampered, mlen, pk);
    if (ret == 0) {
        printf("ERROR: Tampered message should not verify!\n");
        exit(1);
    }

    // Thay đổi chữ ký, xác thực phải fail
    sig[0] ^= 0xFF;
    ret = crypto_sign_ed25519_verify_detached(sig, message, mlen, pk);
    if (ret == 0) {
        printf("ERROR: Tampered signature should not verify!\n");
        exit(1);
    }

    printf("EdDSA (Ed25519) signature test passed!\n");
}

int main() {
    printf("Starting EdDSA/Ed25519 tests...\n");
    bmc_crypt_init();
    test_eddsa_ed25519();
    printf("All EdDSA/Ed25519 tests passed!\n");
    return 0;
} 