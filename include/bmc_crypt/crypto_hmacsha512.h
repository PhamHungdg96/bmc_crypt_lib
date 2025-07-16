#ifndef crypto_hmacsha512_H
#define crypto_hmacsha512_H

#include <stddef.h>
#include <bmc_crypt/crypto_hash_sha512.h>
#include <bmc_crypt/export.h>

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_hmacsha512_BYTES 64U
BMC_CRYPT_EXPORT
size_t crypto_hmacsha512_bytes(void);

BMC_CRYPT_EXPORT
int crypto_hmacsha512(unsigned char *out,
                           const unsigned char *in,
                           unsigned long long inlen,
                           const unsigned char *k, unsigned long long keylen) __attribute__ ((nonnull(1, 4)));

BMC_CRYPT_EXPORT
int crypto_hmacsha512_verify(const unsigned char *h,
                                  const unsigned char *in,
                                  unsigned long long inlen,
                                  const unsigned char *k, unsigned long long keylen)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

/* ------------------------------------------------------------------------- */

typedef struct crypto_hmacsha512_state {
    crypto_hash_sha512_state ictx;
    crypto_hash_sha512_state octx;
} crypto_hmacsha512_state;

BMC_CRYPT_EXPORT
size_t crypto_hmacsha512_statebytes(void);

BMC_CRYPT_EXPORT
int crypto_hmacsha512_init(crypto_hmacsha512_state *state,
                                const unsigned char *key,
                                size_t keylen) __attribute__ ((nonnull));

BMC_CRYPT_EXPORT
int crypto_hmacsha512_update(crypto_hmacsha512_state *state,
                                  const unsigned char *in,
                                  unsigned long long inlen) __attribute__ ((nonnull(1)));

BMC_CRYPT_EXPORT
int crypto_hmacsha512_final(crypto_hmacsha512_state *state,
                                 unsigned char *out) __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
