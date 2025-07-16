#ifndef crypto_verify_64_H
#define crypto_verify_64_H

#include <stddef.h>
#include <bmc_crypt/export.h>

#ifdef __cplusplus
extern "C" {
#endif

#define crypto_verify_64_BYTES 64U
BMC_CRYPT_EXPORT
size_t crypto_verify_64_bytes(void);

BMC_CRYPT_EXPORT
int crypto_verify_64(const unsigned char *x, const unsigned char *y)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
