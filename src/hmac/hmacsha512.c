
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <bmc_crypt/crypto_hmacsha512.h>
#include <bmc_crypt/crypto_hash_sha512.h>
#include <bmc_crypt/crypto_verify_64.h>
#include <bmc_crypt/randombytes.h>
#include <bmc_crypt/utils.h>

#define BLOCK_SIZE 128
#define DIGEST_SIZE 64

size_t
crypto_hmacsha512_bytes(void)
{
    return crypto_hmacsha512_BYTES;
}

int
crypto_hmacsha512_init(crypto_hmacsha512_state *state,
                            const unsigned char *key, size_t keylen)
{
    unsigned char pad[BLOCK_SIZE];
    unsigned char khash[DIGEST_SIZE];
    size_t        i;

    if (keylen > BLOCK_SIZE) {
        crypto_hash_sha512_init(&state->ictx);
        crypto_hash_sha512_update(&state->ictx, key, keylen);
        crypto_hash_sha512_final(&state->ictx, khash);
        key    = khash;
        keylen = DIGEST_SIZE;
    }
    crypto_hash_sha512_init(&state->ictx);
    memset(pad, 0x36, BLOCK_SIZE);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    crypto_hash_sha512_update(&state->ictx, pad, BLOCK_SIZE);

    crypto_hash_sha512_init(&state->octx);
    memset(pad, 0x5c, BLOCK_SIZE);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    crypto_hash_sha512_update(&state->octx, pad, BLOCK_SIZE);

    bmc_crypt_memzero((void *) pad, sizeof pad);
    bmc_crypt_memzero((void *) khash, sizeof khash);

    return 0;
}

int
crypto_hmacsha512_update(crypto_hmacsha512_state *state,
                              const unsigned char *in, unsigned long long inlen)
{
    crypto_hash_sha512_update(&state->ictx, in, inlen);

    return 0;
}

int
crypto_hmacsha512_final(crypto_hmacsha512_state *state,
                             unsigned char                *out)
{
    unsigned char ihash[DIGEST_SIZE];

    crypto_hash_sha512_final(&state->ictx, ihash);
    crypto_hash_sha512_update(&state->octx, ihash, DIGEST_SIZE);
    crypto_hash_sha512_final(&state->octx, out);

    bmc_crypt_memzero((void *) ihash, sizeof ihash);

    return 0;
}

int
crypto_hmacsha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k, unsigned long long keylen)
{
    crypto_hmacsha512_state state;

    crypto_hmacsha512_init(&state, k, keylen);
    crypto_hmacsha512_update(&state, in, inlen);
    crypto_hmacsha512_final(&state, out);

    return 0;
}

int
crypto_hmacsha512_verify(const unsigned char *h, const unsigned char *in,
                              unsigned long long inlen, const unsigned char *k, unsigned long long keylen)
{
    unsigned char correct[DIGEST_SIZE];

    crypto_hmacsha512(correct, in, inlen, k, keylen);

    return crypto_verify_64(h, correct) | (-(h == correct)) |
           bmc_crypt_memcmp(correct, h, DIGEST_SIZE);
}
