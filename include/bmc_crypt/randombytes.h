
#ifndef randombytes_H
#define randombytes_H

#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

typedef struct randombytes_implementation {
    const char *(*implementation_name)(void); /* required */
    uint32_t    (*random)(void);              /* required */
    void        (*stir)(void);                /* optional */
    uint32_t    (*uniform)(const uint32_t upper_bound); /* optional, a default implementation will be used if NULL */
    void        (*buf)(void * const buf, const size_t size); /* required */
    int         (*close)(void);               /* optional */
} randombytes_implementation;

#define randombytes_BYTES_MAX BMC_CRYPT_MIN(BMC_CRYPT_SIZE_MAX, 0xffffffffUL)

#define randombytes_SEEDBYTES 32U
BMC_CRYPT_EXPORT
size_t randombytes_seedbytes(void);

BMC_CRYPT_EXPORT
void randombytes_buf(void * const buf, const size_t size)
            __attribute__ ((nonnull));

BMC_CRYPT_EXPORT
void randombytes_buf_deterministic(void * const buf, const size_t size,
                                   const unsigned char seed[randombytes_SEEDBYTES])
            __attribute__ ((nonnull));

BMC_CRYPT_EXPORT
uint32_t randombytes_random(void);

BMC_CRYPT_EXPORT
uint32_t randombytes_uniform(const uint32_t upper_bound);

BMC_CRYPT_EXPORT
void randombytes_stir(void);

BMC_CRYPT_EXPORT
int randombytes_close(void);

BMC_CRYPT_EXPORT
int randombytes_set_implementation(const randombytes_implementation *impl)
            __attribute__ ((nonnull));

BMC_CRYPT_EXPORT
const char *randombytes_implementation_name(void);

/* -- NaCl compatibility interface -- */

BMC_CRYPT_EXPORT
void randombytes(unsigned char * const buf, const unsigned long long buf_len)
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
