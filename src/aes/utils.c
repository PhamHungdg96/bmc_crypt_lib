#include <bmc_crypt/crypto_core_aes.h>
#include <bmc_crypt/randombytes.h>

int crypto_core_aes_keygen(unsigned char *key, size_t keylen){
    randombytes_buf(key, keylen);
    return 0;
}

int crypto_core_aes_noncegen(unsigned char *nonce){
    randombytes_buf(nonce, 12U);
    return 0;
}

int crypto_core_aes_ivgen(unsigned char *iv){
    randombytes_buf(iv, 16U);
    return 0;
}