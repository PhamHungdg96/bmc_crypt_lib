#include <assert.h>
#include <bmc_crypt/runtime.h>
#include <bmc_crypt/private/modes.h>

#if defined(__GNUC__) && !defined(STRICT_ALIGNMENT)
typedef size_t size_t_aX __attribute((__aligned__(1)));
#else
typedef size_t size_t_aX;
#endif

/*
 * NOTE: the IV/counter CTR mode is big-endian.  The code itself is
 * endian-neutral.
 */

/* increment counter (128-bit int) by 1 */
static void ctr128_inc(unsigned char *counter)
{
    u32 n = 16, c = 1;

    do {
        --n;
        c += counter[n];
        counter[n] = (u8)c;
        c >>= 8;
    } while (n);
}

#if !defined(BMC_SMALL_FOOTPRINT)
static void ctr128_inc_aligned(unsigned char *counter)
{
    size_t *data, c, d, n;

    if (bmc_crypt_runtime_is_little_endian() || ((size_t)counter % sizeof(size_t)) != 0) {
        ctr128_inc(counter);
        return;
    }

    data = (size_t *)counter;
    c = 1;
    n = 16 / sizeof(size_t);
    do {
        --n;
        d = data[n] += c;
        /* did addition carry? */
        c = ((d - c) & ~d) >> (sizeof(size_t) * 8 - 1);
    } while (n);
}
#endif

/*
 * The input encrypted as though 128bit counter mode is being used.  The
 * extra state information to record how much of the 128bit block we have
 * used is contained in *num, and the encrypted counter is kept in
 * ecount_buf.  Both *num and ecount_buf must be initialised with zeros
 * before the first call to CRYPTO_ctr128_encrypt(). This algorithm assumes
 * that the counter is in the x lower bits of the IV (ivec), and that the
 * application has full control over overflow and the rest of the IV.  This
 * implementation takes NO responsibility for checking that the counter
 * doesn't overflow into the rest of the IV when incremented.
 */
void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char ivec[16],
                           unsigned char ecount_buf[16], unsigned int *num,
                           block128_f block)
{
    unsigned int n;
    size_t l = 0;

    n = *num;

#if !defined(BMC_SMALL_FOOTPRINT)
    if (16 % sizeof(size_t) == 0) { /* always true actually */
        do {
            while (n && len) {
                *(out++) = *(in++) ^ ecount_buf[n];
                --len;
                n = (n + 1) % 16;
            }

# if defined(STRICT_ALIGNMENT)
            if (((size_t)in | (size_t)out | (size_t)ecount_buf)
                % sizeof(size_t) != 0)
                break;
# endif
            while (len >= 16) {
                (*block) (ivec, ecount_buf, key);
                ctr128_inc_aligned(ivec);
                for (n = 0; n < 16; n += sizeof(size_t))
                    *(size_t_aX *)(out + n) =
                        *(size_t_aX *)(in + n)
                        ^ *(size_t_aX *)(ecount_buf + n);
                len -= 16;
                out += 16;
                in += 16;
                n = 0;
            }
            if (len) {
                (*block) (ivec, ecount_buf, key);
                ctr128_inc_aligned(ivec);
                while (len--) {
                    out[n] = in[n] ^ ecount_buf[n];
                    ++n;
                }
            }
            *num = n;
            return;
        } while (0);
    }
    /* the rest would be commonly eliminated by x86* compiler */
#endif
    while (l < len) {
        if (n == 0) {
            (*block) (ivec, ecount_buf, key);
            ctr128_inc(ivec);
        }
        out[l] = in[l] ^ ecount_buf[n];
        ++l;
        n = (n + 1) % 16;
    }

    *num = n;
}