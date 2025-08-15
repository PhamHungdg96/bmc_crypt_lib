#include <stdio.h>
#include <string.h>
#include <bmc_crypt/crypto_bmc_protocol.h>
#include <bmc_crypt/crypto_sign.h>
#include <bmc_crypt/crypto_scalarmult_curve25519.h>
#include <bmc_crypt/crypto_hash_sha256.h>
#include <bmc_crypt/randombytes.h>
#include <bmc_crypt/utils.h>
#include <bmc_crypt/crypto_hkdf_256.h> // Added for HKDF
#include <bmc_crypt/crypto_hmacsha256.h>

// Hàm dẫn xuất khóa phiên từ shared secret
int bmc_protocol_derive_session_keys(const unsigned char *shared_secret,
                               const unsigned char *ephemeral_pk,
                               const unsigned char *peer_ecdh_pk,
                               unsigned char *root_key,
                               unsigned char *send_chain_key,
                               unsigned char *recv_chain_key) {
    unsigned char salt[crypto_hash_sha256_BYTES];
    unsigned char salt_input[CURVE25519_KEYLEN * 2];

    if(!shared_secret){
        return -1;
    }
    
    // Tạo salt từ ephemeral_pk và peer_ecdh_pk
    memcpy(salt_input, ephemeral_pk, CURVE25519_KEYLEN);
    memcpy(salt_input + CURVE25519_KEYLEN, peer_ecdh_pk, CURVE25519_KEYLEN);
    crypto_hash_sha256(salt, salt_input, sizeof(salt_input));

    const char info[] = "BMC_SESSION_KDF";
    hkdf_context *hkdf_ctx = NULL;
    unsigned char *derived = NULL;
    
    int ret = hkdf_create(&hkdf_ctx);
    if (ret != 0) {
        return -1;
    }
    
    ret = hkdf_derive_secrets(hkdf_ctx, &derived,
                             shared_secret, CURVE25519_KEYLEN,
                             salt, crypto_hash_sha256_BYTES,
                             (const unsigned char*)info, strlen(info),
                             KEY_LEN * 3);
    
    if (ret != 0 || !derived) {
        hkdf_destroy(hkdf_ctx);
        return -1;
    }
    
    memcpy(root_key, derived, KEY_LEN);
    memcpy(send_chain_key, derived + KEY_LEN, KEY_LEN);
    memcpy(recv_chain_key, derived + KEY_LEN * 2, KEY_LEN);
    
    hkdf_destroy(hkdf_ctx);
    bmc_crypt_free(derived);
    return 0;
}

// Hàm dẫn xuất message key, next chain key, mac key và IV
int bmc_protocol_derive_message_keys(const unsigned char *chain_key,
                               unsigned char *message_key,
                               unsigned char *next_chain_key,
                               unsigned char *mac_key,
                               unsigned char *iv) {
    const char info[] = "BMC_MSG_KDF";
    hkdf_context *hkdf_ctx = NULL;
    unsigned char *derived = NULL;

    if(!chain_key){
        return -1;
    }
    
    int ret = hkdf_create(&hkdf_ctx);
    if (ret != 0) {
        return -1;
    }
    
    ret = hkdf_derive_secrets(hkdf_ctx, &derived,
                             chain_key, KEY_LEN,
                             NULL, 0,
                             (const unsigned char*)info, strlen(info),
                             KEY_LEN * 3 + IV_LEN);
    
    if (ret != 0 || !derived) {
        hkdf_destroy(hkdf_ctx);
        return -1;
    }
    
    memcpy(message_key, derived, KEY_LEN);
    memcpy(next_chain_key, derived + KEY_LEN, KEY_LEN);
    memcpy(mac_key, derived + KEY_LEN * 2, KEY_LEN);
    memcpy(iv, derived + KEY_LEN * 3, IV_LEN);
    
    hkdf_destroy(hkdf_ctx);
    bmc_crypt_free(derived);
    return 0;
}

int bmc_protocol_convert_ed25519_to_x25519(unsigned char curve25519_sk[CURVE25519_KEYLEN], 
                            unsigned char curve25519_pk[CURVE25519_KEYLEN],
                            const unsigned char ed25519_sk[SKLEN],
                            const unsigned char ed25519_pk[PKLEN]){
    if(crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk)!=0){
        return -1;
    }
    if(crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk)!=0){
        return -1;
    }
    return 0;
}

int bmc_protocol_generate_ephemeral_keypair(unsigned char curve25519_sk[CURVE25519_KEYLEN], 
                                            unsigned char curve25519_pk[CURVE25519_KEYLEN]){
    randombytes_buf(curve25519_sk, CURVE25519_KEYLEN);
    if(crypto_scalarmult_curve25519_base(curve25519_pk, curve25519_sk)!=0){
        return -1;
    }
    return 0;
}

int bmc_protocol_caculate_secret(unsigned char secret_shared[CURVE25519_KEYLEN],
                                unsigned char curve25519_sk[CURVE25519_KEYLEN], 
                                unsigned char curve25519_pk[CURVE25519_KEYLEN]){
    return crypto_scalarmult_curve25519(secret_shared, curve25519_sk, curve25519_pk);
}

int bmc_protocol_sign(unsigned char *sig, unsigned long long *siglen_p,
                             const unsigned char *m, unsigned long long mlen,
                             const unsigned char ed25519_sk[SKLEN]){
    return crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, ed25519_sk);
}

int bmc_protocol_verify(const unsigned char *sig,
                        const unsigned char *m,
                        unsigned long long   mlen,
                        const unsigned char ed25519_sk[PKLEN]){
    return crypto_sign_ed25519_verify_detached(sig, m, mlen, ed25519_sk);
}
