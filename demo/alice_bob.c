#include <stdio.h>
#include <string.h>
#include <bmc_crypt/crypto_sign.h>
#include <bmc_crypt/crypto_scalarmult_curve25519.h>
#include <bmc_crypt/crypto_hash_sha256.h>
#include <bmc_crypt/randombytes.h>
#include <bmc_crypt/utils.h>
#include <bmc_crypt/crypto_hkdf_256.h> // Added for HKDF
#include <bmc_crypt/crypto_hmacsha256.h>
#include <bmc_crypt/crypto_core_aes.h>

#define PKLEN crypto_sign_ed25519_PUBLICKEYBYTES
#define SKLEN crypto_sign_ed25519_SECRETKEYBYTES
#define CURVE25519_KEYLEN crypto_scalarmult_curve25519_BYTES
#define SIGLEN crypto_sign_ed25519_BYTES

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
    printf("\n");
}

// Hàm dẫn xuất 3 khóa từ shared secret, ephemeral_pk, bob_ecdh_pk
int derive_session_keys(const unsigned char *shared_secret,
                       const unsigned char *ephemeral_pk,
                       const unsigned char *bob_ecdh_pk,
                       unsigned char *root_key,
                       unsigned char *send_chain_key,
                       unsigned char *recv_chain_key) {
    unsigned char salt[crypto_hash_sha256_BYTES];
    unsigned char salt_input[CURVE25519_KEYLEN * 2];
    memcpy(salt_input, ephemeral_pk, CURVE25519_KEYLEN);
    memcpy(salt_input + CURVE25519_KEYLEN, bob_ecdh_pk, CURVE25519_KEYLEN);
    crypto_hash_sha256(salt, salt_input, sizeof(salt_input));

    const char info[] = "BMC_KDF_CTX";
    hkdf_context *hkdf_ctx = NULL;
    unsigned char *derived = NULL;
    int ret = hkdf_create(&hkdf_ctx);
    if (ret != 0) {
        return 1;
    }
    ret = hkdf_derive_secrets(hkdf_ctx, &derived,
        shared_secret, CURVE25519_KEYLEN,
        salt, crypto_hash_sha256_BYTES,
        (const unsigned char*)info, strlen(info),
        32 * 3
    );
    if (ret != 0 || !derived) {
        hkdf_destroy(hkdf_ctx);
        return 1;
    }
    memcpy(root_key, derived, 32);
    memcpy(send_chain_key, derived + 32, 32);
    memcpy(recv_chain_key, derived + 64, 32);
    hkdf_destroy(hkdf_ctx);
    bmc_crypt_free(derived);
    return 0;
}

// Hàm dẫn xuất message_key, next_chain_key, mac_key từ chain_key bằng HKDF
int derive_message_key_and_next_chain_key(const unsigned char *chain_key, 
                                            unsigned char *message_key, 
                                            unsigned char *next_chain_key, 
                                            unsigned char *mac_key,
                                            unsigned char *iv) {
    const char info[] = "BMC_MSG_CTX";
    hkdf_context *hkdf_ctx = NULL;
    unsigned char *derived = NULL;
    int ret = hkdf_create(&hkdf_ctx);
    if (ret != 0) {
        return 1;
    }
    ret = hkdf_derive_secrets(hkdf_ctx, &derived,
        chain_key, 32, // input_key_material
        NULL, 0,       // salt (NULL)
        (const unsigned char*)info, strlen(info),
        32 * 3 + 16         // output_len
    );
    if (ret != 0 || !derived) {
        hkdf_destroy(hkdf_ctx);
        return 1;
    }
    memcpy(message_key, derived, 32);
    memcpy(next_chain_key, derived + 32, 32);
    memcpy(mac_key, derived + 64, 32);
    memcpy(iv, derived + 96, 16);
    hkdf_destroy(hkdf_ctx);
    bmc_crypt_free(derived);
    return 0;
}

int main() {
    // 1. Sinh khóa cho Alice và Bob
    unsigned char alice_sign_pk[PKLEN], alice_sign_sk[SKLEN];
    unsigned char alice_ecdh_sk[CURVE25519_KEYLEN], alice_ecdh_pk[CURVE25519_KEYLEN];
    unsigned char bob_sign_pk[PKLEN], bob_sign_sk[SKLEN];
    unsigned char bob_ecdh_sk[CURVE25519_KEYLEN], bob_ecdh_pk[CURVE25519_KEYLEN];

    // Alice
    crypto_sign_ed25519_keypair(alice_sign_pk, alice_sign_sk);
    crypto_sign_ed25519_sk_to_curve25519(alice_ecdh_sk, alice_sign_sk);
    crypto_sign_ed25519_pk_to_curve25519(alice_ecdh_pk, alice_sign_pk);
    // Bob
    crypto_sign_ed25519_keypair(bob_sign_pk, bob_sign_sk);
    crypto_sign_ed25519_sk_to_curve25519(bob_ecdh_sk, bob_sign_sk);
    crypto_sign_ed25519_pk_to_curve25519(bob_ecdh_pk, bob_sign_pk);

    print_hex("Alice sign pk", alice_sign_pk, PKLEN);
    print_hex("Alice sign sk", alice_sign_sk, SKLEN);
    print_hex("Alice ecdh pk", alice_ecdh_pk, CURVE25519_KEYLEN);
    print_hex("Alice ecdh sk", alice_ecdh_sk, CURVE25519_KEYLEN);
    print_hex("Bob sign pk", bob_sign_pk, PKLEN);
    print_hex("Bob sign sk", bob_sign_sk, SKLEN);
    print_hex("Bob ecdh pk", bob_ecdh_pk, CURVE25519_KEYLEN);
    print_hex("Bob ecdh sk", bob_ecdh_sk, CURVE25519_KEYLEN);

    // 2. Alice gửi tin nhắn cho Bob
    // Alice sinh khóa tạm thời
    unsigned char alice_tmp_sk[CURVE25519_KEYLEN], alice_tmp_pk[CURVE25519_KEYLEN];
    randombytes_buf(alice_tmp_sk, CURVE25519_KEYLEN);
    crypto_scalarmult_curve25519_base(alice_tmp_pk, alice_tmp_sk);
    print_hex("Alice ephemeral pk", alice_tmp_pk, CURVE25519_KEYLEN);
    print_hex("Alice ephemeral sk", alice_tmp_sk, CURVE25519_KEYLEN);

    // Alice tính shared secret với Bob (ECDH)
    unsigned char alice_shared[CURVE25519_KEYLEN];
    crypto_scalarmult_curve25519(alice_shared, alice_tmp_sk, bob_ecdh_pk);
    print_hex("Alice shared secret", alice_shared, CURVE25519_KEYLEN);

    // Alice ký khóa tạm thời
    unsigned char sig[SIGLEN];
    unsigned long long siglen = 0;
    crypto_sign_ed25519_detached(sig, &siglen, alice_tmp_pk, CURVE25519_KEYLEN, alice_sign_sk);
    print_hex("Alice signature on ephemeral pk", sig, SIGLEN);

    // Alice gửi: alice_tmp_pk, sig cho Bob
    // 3. Bob nhận và xác minh
    int verify = crypto_sign_ed25519_verify_detached(sig, alice_tmp_pk, CURVE25519_KEYLEN, alice_sign_pk);
    printf("Bob verify signature: %s\n", verify == 0 ? "OK" : "FAIL");

    // Bob tính shared secret với khóa tạm thời của Alice
    unsigned char bob_shared[CURVE25519_KEYLEN];
    crypto_scalarmult_curve25519(bob_shared, bob_ecdh_sk, alice_tmp_pk);
    print_hex("Bob shared secret", bob_shared, CURVE25519_KEYLEN);

    // So sánh shared secret
    printf("Shared secret match: %s\n", bmc_crypt_memcmp(alice_shared, bob_shared, CURVE25519_KEYLEN) == 0 ? "YES" : "NO");

    // 4. Alice và Bob dẫn xuất khóa
    unsigned char root_key[32], send_chain_key[32], recv_chain_key[32];
    if (derive_session_keys(alice_shared, alice_tmp_pk, bob_ecdh_pk, root_key, send_chain_key, recv_chain_key) != 0) {
        printf("derive_session_keys failed\n");
        return 1;
    }
    print_hex("Root key", root_key, 32);
    print_hex("Send chain key", send_chain_key, 32);
    print_hex("Recv chain key", recv_chain_key, 32);

    // Ví dụ sử dụng hàm derive_message_key_and_next_chain_key với send_chain_key
    unsigned char message_key[32], next_chain_key[32], mac_key[32], iv[16];
    print_hex("Input send_chain_key", send_chain_key, 32);
    if (derive_message_key_and_next_chain_key(send_chain_key, message_key, next_chain_key, mac_key, iv) != 0) {
        printf("derive_message_key_and_next_chain_key failed\n");
        return 1;
    }
    print_hex("Message key", message_key, 32);
    print_hex("Next chain key", next_chain_key, 32);
    print_hex("MAC key", mac_key, 32);
    print_hex("IV", iv, 16);

    // Giả sử message, message_len, message_key (32 bytes), iv (16 bytes), mac_key (32 bytes) đã có

    crypto_core_aes_ctx *ctx;
    unsigned char ciphertext[1024]; // đủ lớn cho message + padding
    unsigned char final_block[32];  // để nhận dữ liệu còn lại từ finish
    size_t outlen = 0;

    // Khởi tạo context AES CBC
    if (crypto_core_aes_init(&ctx, message_key, 32, AES_MODE_CBC, 1, iv, 16) != 0) {
        printf("AES CBC init failed\n");
        return 1;
    }

    // Mã hóa (update)
    const unsigned char *message = "Hello, Bob!";
    size_t message_len = strlen(message);
    int clen = crypto_core_aes_update(ctx, ciphertext, (const unsigned char*)message, message_len);
    printf("clen: %d\n", clen);
    // Kết thúc (finish)
    if (crypto_core_aes_finish(ctx, ciphertext + clen, &outlen) != 0) {
        printf("AES CBC finish failed\n");
        return 1;
    }
    size_t total_clen = clen + outlen;

    // Tính HMAC tag cho ciphertext
    // unsigned char tag[32];
    // crypto_hmacsha256(tag, ciphertext, outlen, mac_key, 32);

    printf("total_clen: %zu\n", total_clen);
    // In kết quả
    print_hex("Ciphertext", ciphertext, total_clen);
    // print_hex("HMAC tag", tag, 32);

    return 0;
}
