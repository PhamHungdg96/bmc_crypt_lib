
#ifndef bmc_crypt_runtime_H
#define bmc_crypt_runtime_H

#include <bmc_crypt/export.h>

#ifdef __cplusplus
extern "C" {
#endif

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_neon(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_armcrypto(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_sse2(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_sse3(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_ssse3(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_sse41(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_avx(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_avx2(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_avx512f(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_pclmul(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_aesni(void);

BMC_CRYPT_EXPORT_WEAK
int bmc_crypt_runtime_has_rdrand(void);

BMC_CRYPT_EXPORT_WEAK 
int bmc_crypt_runtime_is_little_endian(void);

/* ------------------------------------------------------------------------- */

int _bmc_crypt_runtime_get_cpu_features(void);

#ifdef __cplusplus
}
#endif

#endif
