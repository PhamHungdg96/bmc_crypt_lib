#include <assert.h>
#include <bmc_crypt/crypto_core_aes.h>
#include <bmc_crypt/private/aes_internal.h>

int crypto_core_aes_set_key(const unsigned char *user_key,
                                int bits,
                                AES_KEY *key,
                                const int enc){
    assert(user_key && key);
    assert((AES_ENCRYPT == enc) || (AES_DECRYPT == enc));
    if(enc == AES_ENCRYPT){
        return AES_set_encrypt_key(user_key, bits, key);
    }else{
        return AES_set_decrypt_key(user_key, bits, key);
    }
}

int crypto_core_aes_ecb_encrypt(const unsigned char *in,
    unsigned char *out,
    const AES_KEY *key,
    const int enc){
    assert(out && in && key);
    assert((AES_ENCRYPT == enc) || (AES_DECRYPT == enc));
    if(enc == AES_ENCRYPT){
        AES_encrypt(in, out, key);
    }else{
        AES_decrypt(in, out, key);
    }
    return 0;
}