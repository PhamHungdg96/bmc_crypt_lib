#ifndef crypto_verify_32_H
#define crypto_verify_32_H

#include <stddef.h>
#include <bmc_crypt/export.h>

#ifdef __cplusplus
extern "C" {
#endif

#define crypto_verify_32_BYTES 32U
BMC_CRYPT_EXPORT
size_t crypto_verify_32_bytes(void);

BMC_CRYPT_EXPORT
int crypto_verify_32(const unsigned char *x, const unsigned char *y)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
