#ifndef crypto_hmacsha256_H
#define crypto_hmacsha256_H

#include <stddef.h>
#include <bmc_crypt/crypto_hash_sha256.h>
#include <bmc_crypt/export.h>

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_hmacsha256_BYTES 32U
BMC_CRYPT_EXPORT
size_t crypto_hmacsha256_bytes(void);

BMC_CRYPT_EXPORT
int crypto_hmacsha256(unsigned char *out,
                           const unsigned char *in,
                           unsigned long long inlen,
                           const unsigned char *k, unsigned long long keylen) __attribute__ ((nonnull(1, 4)));

BMC_CRYPT_EXPORT
int crypto_hmacsha256_verify(const unsigned char *h,
                                  const unsigned char *in,
                                  unsigned long long inlen,
                                  const unsigned char *k, unsigned long long keylen)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

/* ------------------------------------------------------------------------- */

typedef struct crypto_hmacsha256_state {
    crypto_hash_sha256_state ictx;
    crypto_hash_sha256_state octx;
} crypto_hmacsha256_state;

BMC_CRYPT_EXPORT
int crypto_hmacsha256_init(crypto_hmacsha256_state *state,
                                const unsigned char *key,
                                size_t keylen) __attribute__ ((nonnull));

BMC_CRYPT_EXPORT
int crypto_hmacsha256_update(crypto_hmacsha256_state *state,
                                  const unsigned char *in,
                                  unsigned long long inlen)
            __attribute__ ((nonnull(1)));

BMC_CRYPT_EXPORT
int crypto_hmacsha256_final(crypto_hmacsha256_state *state,
                                 unsigned char *out) __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
