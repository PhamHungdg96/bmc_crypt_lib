
#ifndef randombytes_internal_random_H
#define randombytes_internal_random_H

#include <bmc_crypt/export.h>
#include <bmc_crypt/randombytes.h>

#ifdef __cplusplus
extern "C" {
#endif

BMC_CRYPT_EXPORT
extern struct randombytes_implementation randombytes_internal_implementation;

#ifdef __cplusplus
}
#endif

#endif
