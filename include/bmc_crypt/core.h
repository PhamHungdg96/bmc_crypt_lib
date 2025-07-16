
#ifndef bmc_crypt_core_H
#define bmc_crypt_core_H

#include <bmc_crypt/export.h>

#ifdef __cplusplus
extern "C" {
#endif

BMC_CRYPT_EXPORT
int bmc_crypt_init(void)
            __attribute__ ((warn_unused_result));

/* ---- */

BMC_CRYPT_EXPORT
int bmc_crypt_set_misuse_handler(void (*handler)(void));

BMC_CRYPT_EXPORT
void bmc_crypt_misuse(void)
            __attribute__ ((noreturn));

#ifdef __cplusplus
}
#endif

#endif
