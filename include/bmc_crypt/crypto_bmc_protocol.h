#ifndef CRYPTO_BMC_PROTOCOL_H
#define CRYPTO_BMC_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <bmc_crypt/export.h>
#include <bmc_crypt/crypto_hmacsha256.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PKLEN 32U
#define SKLEN (32U + 32U)
#define CURVE25519_KEYLEN 32U
#define SIGLEN 64U
#define KEY_LEN 32U
#define MAC_LEN 32U
#define IV_LEN 16U

//common
BMC_CRYPT_EXPORT
int bmc_protocol_derive_session_keys(const unsigned char *shared_secret,
                        const unsigned char *ephemeral_pk,
                        const unsigned char *x_pk_peer,
                        unsigned char *root_key,
                        unsigned char *send_chain_key,
                        unsigned char *recv_chain_key);
BMC_CRYPT_EXPORT                     
int bmc_protocol_derive_message_keys(const unsigned char *chain_key,
                        unsigned char *message_key,
                        unsigned char *next_chain_key,
                        unsigned char *mac_key,
                        unsigned char *iv);

BMC_CRYPT_EXPORT
int bmc_protocol_convert_ed25519_to_x25519(unsigned char curve25519_sk[CURVE25519_KEYLEN], 
                            unsigned char curve25519_pk[CURVE25519_KEYLEN],
                            const unsigned char ed25519_sk[SKLEN],
                            const unsigned char ed25519_pk[PKLEN]);

BMC_CRYPT_EXPORT
int bmc_protocol_generate_ed25519_keypair(unsigned char ed25519_sk[SKLEN], 
                                            unsigned char ed25519_pk[PKLEN]);

BMC_CRYPT_EXPORT
int bmc_protocol_generate_x25519_keypair(unsigned char curve25519_sk[CURVE25519_KEYLEN], 
                                            unsigned char curve25519_pk[CURVE25519_KEYLEN]);

BMC_CRYPT_EXPORT
int bmc_protocol_caculate_secret(unsigned char secret_shared[CURVE25519_KEYLEN],
                                unsigned char curve25519_sk[CURVE25519_KEYLEN], 
                                unsigned char curve25519_pk[CURVE25519_KEYLEN]);

BMC_CRYPT_EXPORT
int bmc_protocol_sign(unsigned char *sig, unsigned long long *siglen_p,
                             const unsigned char *m, unsigned long long mlen,
                             const unsigned char ed25519_sk[SKLEN]);

BMC_CRYPT_EXPORT
int bmc_protocol_verify(const unsigned char *sig,
                        const unsigned char *m,
                        unsigned long long   mlen,
                        const unsigned char ed25519_sk[PKLEN]);
//for hmac
BMC_CRYPT_EXPORT
int bmc_protocol_hmac_sha256_init(crypto_hmacsha256_state **state,
                                const unsigned char *key,
                                size_t keylen);
BMC_CRYPT_EXPORT
int bmc_protocol_hmac_sha256_update(crypto_hmacsha256_state *state,
                                  const unsigned char *in,
                                  unsigned long long inlen);

BMC_CRYPT_EXPORT
int bmc_protocol_hmac_sha256_finish(crypto_hmacsha256_state *state,
                                 unsigned char *out);

BMC_CRYPT_EXPORT
int bmc_protocol_hmac_sha256_cleanup(crypto_hmacsha256_state *state);

BMC_CRYPT_EXPORT
int bmc_protocol_encrypt(unsigned char **ciphertext, size_t *ciphertext_len,
                        const unsigned char *plaintext, size_t plaintext_len,
                        const unsigned char *key, const unsigned char *iv,
                        const unsigned char *mac_key);
BMC_CRYPT_EXPORT
int bmc_protocol_decrypt(unsigned char **plaintext, size_t *plaintext_len,
                        const unsigned char *ciphertext, size_t ciphertext_len,
                        const unsigned char *key, const unsigned char *iv,
                        const unsigned char *mac_key);

#ifdef __cplusplus
}
#endif

#endif /* crypto_bmc_protocol_H */
