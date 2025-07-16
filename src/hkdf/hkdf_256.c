#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <bmc_crypt/crypto_hkdf_256.h>
#include <bmc_crypt/crypto_hmacsha256.h>
#include <bmc_crypt/crypto_hash_sha256.h>
#include <bmc_crypt/utils.h>

int hkdf_create(hkdf_context **context)
{
    if (context == NULL) {
        return -1;
    }
    
    *context = bmc_crypt_malloc(sizeof(hkdf_context));
    if (!(*context)) {
        return -1;
    }

    bmc_crypt_memzero(*context, sizeof(hkdf_context));

    // Allocate HMAC state
    (*context)->state = bmc_crypt_malloc(sizeof(crypto_hmacsha256_state));
    if (!(*context)->state) {
        bmc_crypt_free(*context);
        *context = NULL;
        return -1;
    }

    bmc_crypt_memzero((*context)->state, sizeof(crypto_hmacsha256_state));
    (*context)->iteration_start_offset = 1;
    return 0;
}

int hkdf_extract(hkdf_context *context,
        unsigned char prk[crypto_hkdf_sha256_KEYBYTES],
        const unsigned char *salt, size_t salt_len,
        const unsigned char *input_key_material, size_t input_key_material_len)
{
    int result = 0;

    if (!context || !prk) {
        return -1;
    }

    // If salt is NULL or empty, use zero salt
    if (!salt || salt_len == 0) {
        salt = (const unsigned char *)"";
        salt_len = 0;
    }

    result = crypto_hmacsha256_init(context->state, salt, salt_len);
    if (result < 0) {
        return result;
    }

    result = crypto_hmacsha256_update(context->state, input_key_material, input_key_material_len);
    if (result < 0) {
        return result;
    }

    result = crypto_hmacsha256_final(context->state, prk);
    return result;
}

int hkdf_expand(hkdf_context *context,
        unsigned char **output,
        const unsigned char *prk, size_t prk_len,
        const unsigned char *info, size_t info_len,
        size_t output_len)
{
    int iterations = (int)ceil((double)output_len / (double)crypto_hash_sha256_BYTES);
    size_t remaining_len = output_len;
    unsigned char *result_buf = NULL;
    size_t result_buf_len = 0;
    crypto_hmacsha256_state hmac_state;
    int result = 0;
    unsigned char i;
    unsigned char t[crypto_hash_sha256_BYTES];
    unsigned char *prev_t = NULL;

    if (!context || !output || !prk) {
        return -1;
    }

    *output = NULL;

    // Allocate output buffer
    result_buf = bmc_crypt_malloc(output_len);
    if (!result_buf) {
        return -1;
    }

    for (i = context->iteration_start_offset; i < iterations + context->iteration_start_offset; i++) {
        result = crypto_hmacsha256_init(&hmac_state, prk, prk_len);
        if (result < 0) {
            goto cleanup;
        }

        // Add previous T value if not first iteration
        if (prev_t) {
            result = crypto_hmacsha256_update(&hmac_state, prev_t, crypto_hash_sha256_BYTES);
            if (result < 0) {
                goto cleanup;
            }
        }

        // Add info if provided
        if (info && info_len > 0) {
            result = crypto_hmacsha256_update(&hmac_state, info, info_len);
            if (result < 0) {
                goto cleanup;
            }
        }

        // Add counter
        result = crypto_hmacsha256_update(&hmac_state, &i, 1);
        if (result < 0) {
            goto cleanup;
        }

        result = crypto_hmacsha256_final(&hmac_state, t);
        if (result < 0) {
            goto cleanup;
        }

        // Copy to output
        size_t step_size = (remaining_len < crypto_hash_sha256_BYTES) ? remaining_len : crypto_hash_sha256_BYTES;
        memcpy(result_buf + result_buf_len, t, step_size);
        result_buf_len += step_size;
        remaining_len -= step_size;

        // Save current T for next iteration
        if (prev_t) {
            bmc_crypt_free(prev_t);
        }
        prev_t = bmc_crypt_malloc(crypto_hash_sha256_BYTES);
        if (!prev_t) {
            result = -1;
            goto cleanup;
        }
        memcpy(prev_t, t, crypto_hash_sha256_BYTES);
    }

    *output = result_buf;
    result_buf = NULL; // Prevent cleanup

cleanup:
    if (prev_t) {
        bmc_crypt_free(prev_t);
    }
    if (result_buf) {
        bmc_crypt_free(result_buf);
    }
    return result;
}

int hkdf_derive_secrets(hkdf_context *context,
        unsigned char **output,
        const unsigned char *input_key_material, size_t input_key_material_len,
        const unsigned char *salt, size_t salt_len,
        const unsigned char *info, size_t info_len,
        size_t output_len)
{
    int result = 0;
    unsigned char prk[crypto_hkdf_sha256_KEYBYTES];

    if (!context || !output || !input_key_material) {
        return -1;
    }

    // Extract phase
    result = hkdf_extract(context, prk, salt, salt_len, input_key_material, input_key_material_len);
    if (result < 0) {
        return result;
    }

    // Expand phase
    result = hkdf_expand(context, output, prk, crypto_hkdf_sha256_KEYBYTES, info, info_len, output_len);

    // Clear PRK
    bmc_crypt_memzero(prk, sizeof(prk));

    return result;
}

int hkdf_compare(const hkdf_context *context1, const hkdf_context *context2)
{
    if (context1 == context2) {
        return 0;
    }
    else if (context1 == NULL && context2 != NULL) {
        return -1;
    }
    else if (context1 != NULL && context2 == NULL) {
        return 1;
    }
    else if (context1->iteration_start_offset < context2->iteration_start_offset) {
        return -1;
    }
    else if (context1->iteration_start_offset > context2->iteration_start_offset) {
        return 1;
    }
    else {
        return 0;
    }
}

void hkdf_destroy(hkdf_context *context)
{
    if (context) {
        if (context->state) {
            bmc_crypt_memzero(context->state, sizeof(crypto_hmacsha256_state));
            bmc_crypt_free(context->state);
        }
        bmc_crypt_memzero(context, sizeof(hkdf_context));
        bmc_crypt_free(context);
    }
}