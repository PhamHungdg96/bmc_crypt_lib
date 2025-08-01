#include <string.h>

#include <bmc_crypt/crypto_hash_sha512.h>
#include <bmc_crypt/crypto_scalarmult_curve25519.h>
#include <bmc_crypt/crypto_sign.h>
#include <bmc_crypt/private/ed25519_ref10.h>
#include <bmc_crypt/randombytes.h>
#include <bmc_crypt/utils.h>

#include "sign_ed25519_ref10.h"

int
crypto_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                 const unsigned char *seed)
{
    ge25519_p3 A;

    crypto_hash_sha512(sk, seed, 32);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    ge25519_scalarmult_base(&A, sk);
    ge25519_p3_tobytes(pk, &A);

    memmove(sk, seed, 32);
    memmove(sk + 32, pk, 32);

    return 0;
}

int
crypto_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk)
{
    unsigned char seed[32];
    int           ret;

    randombytes_buf(seed, sizeof seed);
    ret = crypto_sign_ed25519_seed_keypair(pk, sk, seed);
    bmc_crypt_memzero(seed, sizeof seed);

    return ret;
}

int
crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                     const unsigned char *ed25519_pk)
{
    ge25519_p3 A;
    fe25519    x;
    fe25519    one_minus_y;

    if (ge25519_has_small_order(ed25519_pk) != 0 ||
        ge25519_frombytes_negate_vartime(&A, ed25519_pk) != 0 ||
        ge25519_is_on_main_subgroup(&A) == 0) {
        return -1;
    }
    fe25519_1(one_minus_y);
    /* assumes A.Z=1 */
    fe25519_sub(one_minus_y, one_minus_y, A.Y);
    fe25519_1(x);
    fe25519_add(x, x, A.Y);
    fe25519_invert(one_minus_y, one_minus_y);
    fe25519_mul(x, x, one_minus_y);
    fe25519_tobytes(curve25519_pk, x);

    return 0;
}

int
crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                     const unsigned char *ed25519_sk)
{
    unsigned char h[crypto_hash_sha512_BYTES];

    crypto_hash_sha512(h, ed25519_sk, 32);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    memcpy(curve25519_sk, h, crypto_scalarmult_curve25519_BYTES);
    bmc_crypt_memzero(h, sizeof h);

    return 0;
}
