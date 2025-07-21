#ifndef BMC_CRYPT_CRYPTO_SIGN_H
#define BMC_CRYPT_CRYPTO_SIGN_H

#include "bmc_crypt/export.h"

#ifdef __cplusplus
extern "C" {
#endif

#define crypto_sign_ed25519_BYTES 64U
#define crypto_sign_ed25519_MESSAGEBYTES_MAX (BMC_CRYPT_SIZE_MAX - crypto_sign_ed25519_BYTES)

BMC_CRYPT_EXPORT
int crypto_sign_ed25519_detached(unsigned char *sig, unsigned long long *siglen_p,
                             const unsigned char *m, unsigned long long mlen,
                             const unsigned char *sk)
            __attribute__ ((nonnull(1, 5)));

BMC_CRYPT_EXPORT
int crypto_sign_ed25519(unsigned char *sm, unsigned long long *smlen_p,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *sk)
            __attribute__ ((nonnull(1, 5)));

BMC_CRYPT_EXPORT
int crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                        const unsigned char *m,
                        unsigned long long mlen,
                        const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

BMC_CRYPT_EXPORT
int crypto_sign_ed25519_open(unsigned char *m, unsigned long long *mlen_p,
                             const unsigned char *sm, unsigned long long smlen,
                             const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5)));

/**
 * Key generate */            
BMC_CRYPT_EXPORT
int crypto_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk)
            __attribute__ ((nonnull));

BMC_CRYPT_EXPORT
int crypto_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                     const unsigned char *seed)
            __attribute__ ((nonnull));

/**
 * Key Convert
 */
BMC_CRYPT_EXPORT
int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                         const unsigned char *ed25519_pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

BMC_CRYPT_EXPORT
int crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                         const unsigned char *ed25519_sk)
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif