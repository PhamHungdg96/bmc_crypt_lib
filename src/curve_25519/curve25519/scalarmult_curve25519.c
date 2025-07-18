
#include <bmc_crypt/crypto_scalarmult_curve25519.h>
#include <bmc_crypt/private/implementations.h>
#include "scalarmult_curve25519.h"
#include "ref10/x25519_ref10.h"
static const crypto_scalarmult_curve25519_implementation *implementation =
    &crypto_scalarmult_curve25519_ref10_implementation;

int
crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                             const unsigned char *p)
{
    size_t                 i;
    volatile unsigned char d = 0;

    if (implementation->mult(q, n, p) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    for (i = 0; i < crypto_scalarmult_curve25519_BYTES; i++) {
        d |= q[i];
    }
    return -(1 & ((d - 1) >> 8));
}

int
crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
{
    return crypto_scalarmult_curve25519_ref10_implementation
        .mult_base(q, n);
}

size_t
crypto_scalarmult_curve25519_bytes(void)
{
    return crypto_scalarmult_curve25519_BYTES;
}

size_t
crypto_scalarmult_curve25519_scalarbytes(void)
{
    return crypto_scalarmult_curve25519_SCALARBYTES;
}

int
_crypto_scalarmult_curve25519_pick_best_implementation(void)
{
    implementation = &crypto_scalarmult_curve25519_ref10_implementation;
    return 0;
}
