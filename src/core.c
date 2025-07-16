
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
# include <windows.h>
#elif defined(HAVE_PTHREAD)
# include <pthread.h>
#endif


#include <bmc_crypt/core.h>
#include <bmc_crypt/runtime.h>
// #include "crypto_generichash.h"

#include <bmc_crypt/randombytes.h>
#include <bmc_crypt/utils.h>
#include <bmc_crypt/private/implementations.h>
#include <bmc_crypt/private/mutex.h>

static volatile int initialized;
static volatile int locked;

int
bmc_crypt_init(void)
{
    if (bmc_crypt_crit_enter() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    if (initialized != 0) {
        if (bmc_crypt_crit_leave() != 0) {
            return -1; /* LCOV_EXCL_LINE */
        }
        return 1;
    }
    _bmc_crypt_runtime_get_cpu_features();
    randombytes_stir();
    _bmc_crypt_alloc_init();
    _crypto_scalarmult_curve25519_pick_best_implementation();
    initialized = 1;
    if (bmc_crypt_crit_leave() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}

#ifdef _WIN32

static CRITICAL_SECTION _bmc_crypt_lock;
static volatile LONG    _bmc_crypt_lock_initialized;

static int
_bmc_crypt_crit_init(void)
{
    LONG status = 0L;

    while ((status = InterlockedCompareExchange(&_bmc_crypt_lock_initialized,
                                                1L, 0L)) == 1L) {
        Sleep(0);
    }

    switch (status) {
    case 0L:
        InitializeCriticalSection(&_bmc_crypt_lock);
        return InterlockedExchange(&_bmc_crypt_lock_initialized, 2L) == 1L ? 0 : -1;
    case 2L:
        return 0;
    default: /* should never be reached */
        return -1;
    }
}

int
bmc_crypt_crit_enter(void)
{
    if (_bmc_crypt_crit_init() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    EnterCriticalSection(&_bmc_crypt_lock);
    assert(locked == 0);
    locked = 1;

    return 0;
}

int
bmc_crypt_crit_leave(void)
{
    if (locked == 0) {
# ifdef EPERM
        errno = EPERM;
# endif
        return -1;
    }
    locked = 0;
    LeaveCriticalSection(&_bmc_crypt_lock);

    return 0;
}

#elif defined(HAVE_PTHREAD) && !defined(__EMSCRIPTEN__)

static pthread_mutex_t _bmc_crypt_lock = PTHREAD_MUTEX_INITIALIZER;

int
bmc_crypt_crit_enter(void)
{
    int ret;

    if ((ret = pthread_mutex_lock(&_bmc_crypt_lock)) == 0) {
        assert(locked == 0);
        locked = 1;
    }
    return ret;
}

int
bmc_crypt_crit_leave(void)
{
    if (locked == 0) {
# ifdef EPERM
        errno = EPERM;
# endif
        return -1;
    }
    locked = 0;

    return pthread_mutex_unlock(&_bmc_crypt_lock);
}

#elif defined(HAVE_ATOMIC_OPS) && !defined(__EMSCRIPTEN__)

static volatile int _bmc_crypt_lock;

int
bmc_crypt_crit_enter(void)
{
# ifdef HAVE_NANOSLEEP
    struct timespec q;
    memset(&q, 0, sizeof q);
# endif
    while (__sync_lock_test_and_set(&_bmc_crypt_lock, 1) != 0) {
# ifdef HAVE_NANOSLEEP
        (void) nanosleep(&q, NULL);
# elif defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__ ("pause");
# endif
    }
    return 0;
}

int
bmc_crypt_crit_leave(void)
{
    __sync_lock_release(&_bmc_crypt_lock);

    return 0;
}

#else

int
bmc_crypt_crit_enter(void)
{
    return 0;
}

int
bmc_crypt_crit_leave(void)
{
    return 0;
}

#endif

static void (*_misuse_handler)(void);

void
bmc_crypt_misuse(void)
{
    void (*handler)(void);

    (void) bmc_crypt_crit_leave();
    if (bmc_crypt_crit_enter() == 0) {
        handler = _misuse_handler;
        if (handler != NULL) {
            handler();
        }
    }
/* LCOV_EXCL_START */
    abort();
}
/* LCOV_EXCL_STOP */

int
bmc_crypt_set_misuse_handler(void (*handler)(void))
{
    if (bmc_crypt_crit_enter() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    _misuse_handler = handler;
    if (bmc_crypt_crit_leave() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}
