
#ifndef randombytes_sysrandom_H
#define randombytes_sysrandom_H

#include <bmc_crypt/export.h>
#include <bmc_crypt/randombytes.h>

#ifdef __cplusplus
extern "C" {
#endif

BMC_CRYPT_EXPORT
extern struct randombytes_implementation randombytes_sysrandom_implementation;

#ifdef __cplusplus
}
#endif

#endif
