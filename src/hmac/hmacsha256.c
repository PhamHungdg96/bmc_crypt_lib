
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <bmc_crypt/crypto_hmacsha256.h>
#include <bmc_crypt/crypto_hash_sha256.h>
#include <bmc_crypt/crypto_verify_32.h>
#include <bmc_crypt/randombytes.h>
#include <bmc_crypt/utils.h>

#define BLOCK_SIZE 64
#define DIGEST_SIZE 32

size_t
crypto_hmacsha256_bytes(void)
{
    return crypto_hmacsha256_BYTES;
}

int
crypto_hmacsha256_init(crypto_hmacsha256_state *state,
                            const unsigned char *key, size_t keylen)
{
    unsigned char key_hash[DIGEST_SIZE];
    size_t        i;
    uint8_t key_pad[BLOCK_SIZE];

    // Step 1: Hash key if too long
    if (keylen > BLOCK_SIZE) {
        crypto_hash_sha256_init(&state->ictx);
        crypto_hash_sha256_update(&state->ictx, key, keylen);
        crypto_hash_sha256_final(&state->ictx, key_hash);
        key    = key_hash;
        keylen = DIGEST_SIZE;
    }

    // Step 2: Pad key with zeros
    memset(key_pad, 0, BLOCK_SIZE);
    memcpy(key_pad, key, keylen);

    // Step 3: Compute inner hash context
    crypto_hash_sha256_init(&state->ictx);
    for (i = 0; i < BLOCK_SIZE; ++i) {
        key_pad[i] ^= 0x36;
    }
    crypto_hash_sha256_update(&state->ictx, key_pad, BLOCK_SIZE);

    // Step 4: Compute outer hash context
    crypto_hash_sha256_init(&state->octx);
    for (i = 0; i < BLOCK_SIZE; ++i) {
        key_pad[i] ^= (0x36 ^ 0x5c); // Undo 0x36, apply 0x5c
    }
    crypto_hash_sha256_update(&state->octx, key_pad, BLOCK_SIZE);

    bmc_crypt_memzero((void *) key_pad, sizeof key_pad);
    bmc_crypt_memzero((void *) key_hash, sizeof key_hash);

    return 0;
}

int
crypto_hmacsha256_update(crypto_hmacsha256_state *state,
                              const unsigned char *in, unsigned long long inlen)
{
    crypto_hash_sha256_update(&state->ictx, in, inlen);
    return 0;
}

int
crypto_hmacsha256_final(crypto_hmacsha256_state *state,
                             unsigned char *out)
{
    unsigned char inner_hash[DIGEST_SIZE];

    // Finish inner hash
    crypto_hash_sha256_final(&state->ictx, inner_hash);

    // Continue with outer hash
    crypto_hash_sha256_update(&state->octx, inner_hash, DIGEST_SIZE);
    crypto_hash_sha256_final(&state->octx, out);

    bmc_crypt_memzero((void *) inner_hash, sizeof inner_hash);

    return 0;
}

int
crypto_hmacsha256(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k, unsigned long long keylen)
{
    crypto_hmacsha256_state state;

    crypto_hmacsha256_init(&state, k, keylen);
    crypto_hmacsha256_update(&state, in, inlen);
    crypto_hmacsha256_final(&state, out);

    return 0;
}

int
crypto_hmacsha256_verify(const unsigned char *h, const unsigned char *in,
                              unsigned long long inlen, const unsigned char *k, unsigned long long keylen)
{
    unsigned char correct[DIGEST_SIZE];

    crypto_hmacsha256(correct, in, inlen, k, keylen);

    return crypto_verify_32(h, correct) | (-(h == correct)) |
           bmc_crypt_memcmp(correct, h, DIGEST_SIZE);
}
