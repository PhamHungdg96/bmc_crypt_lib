#ifndef HKDF_H
#define HKDF_H

#include <stdint.h>
#include <stddef.h>

#include <bmc_crypt/export.h>
#include <bmc_crypt/crypto_hmacsha256.h>

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_hkdf_sha256_KEYBYTES crypto_hmacsha256_BYTES

struct hkdf_context
{
    crypto_hmacsha256_state *state;
    int iteration_start_offset;
};

typedef struct hkdf_context hkdf_context;

BMC_CRYPT_EXPORT
int hkdf_create(hkdf_context **context);

BMC_CRYPT_EXPORT
int hkdf_extract(hkdf_context *context,
        unsigned char prk[crypto_hkdf_sha256_KEYBYTES],
        const unsigned char *salt, size_t salt_len,
        const unsigned char *input_key_material, size_t input_key_material_len);

BMC_CRYPT_EXPORT
int hkdf_expand(hkdf_context *context,
        unsigned char **output,
        const unsigned char *prk, size_t prk_len,
        const unsigned char *info, size_t info_len,
        size_t output_len);

BMC_CRYPT_EXPORT
int hkdf_derive_secrets(hkdf_context *context,
        unsigned char **output,
        const unsigned char *input_key_material, size_t input_key_material_len,
        const unsigned char *salt, size_t salt_len,
        const unsigned char *info, size_t info_len,
        size_t output_len);

BMC_CRYPT_EXPORT
int hkdf_compare(const hkdf_context *context1, const hkdf_context *context2);

BMC_CRYPT_EXPORT
void hkdf_destroy(hkdf_context *context);

#ifdef __cplusplus
}
#endif

#endif /* HKDF_H */