#include <assert.h>
#include <bmc_crypt/crypto_core_aes.h>
#include <bmc_crypt/private/aes_internal.h>
#include <bmc_crypt/private/modes.h>

int crypto_core_aes_cbc_encrypt(const unsigned char *in,
                                unsigned char *out,
                                size_t len,
                                const AES_KEY *key,
                                const unsigned char *ivec,
                                const int enc){
    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
                              (block128_f) AES_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
                              (block128_f) AES_decrypt);
    return 0;
}