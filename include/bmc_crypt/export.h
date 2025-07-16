
#ifndef bmc_crypt_export_H
#define bmc_crypt_export_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#if !defined(__clang__) && !defined(__GNUC__)
# ifdef __attribute__
#  undef __attribute__
# endif
# define __attribute__(a)
#endif

#ifdef BMC_CRYPT_STATIC
# define BMC_CRYPT_EXPORT
# define BMC_CRYPT_EXPORT_WEAK
#else
# if defined(_MSC_VER)
#  ifdef BMC_CRYPT_DLL_EXPORT
#   define BMC_CRYPT_EXPORT __declspec(dllexport)
#  else
#   define BMC_CRYPT_EXPORT __declspec(dllimport)
#  endif
# else
#  if defined(__SUNPRO_C)
#   ifndef __GNU_C__
#    define BMC_CRYPT_EXPORT __attribute__ (visibility(__global))
#   else
#    define BMC_CRYPT_EXPORT __attribute__ __global
#   endif
#  elif defined(_MSG_VER)
#   define BMC_CRYPT_EXPORT extern __declspec(dllexport)
#  else
#   define BMC_CRYPT_EXPORT __attribute__ ((visibility ("default")))
#  endif
# endif
# if defined(__ELF__) && !defined(BMC_CRYPT_DISABLE_WEAK_FUNCTIONS)
#  define BMC_CRYPT_EXPORT_WEAK BMC_CRYPT_EXPORT __attribute__((weak))
# else
#  define BMC_CRYPT_EXPORT_WEAK BMC_CRYPT_EXPORT
# endif
#endif

#ifndef CRYPTO_ALIGN
# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  define CRYPTO_ALIGN(x) __declspec(align(x))
# else
#  define CRYPTO_ALIGN(x) __attribute__ ((aligned(x)))
# endif
#endif

#define BMC_CRYPT_MIN(A, B) ((A) < (B) ? (A) : (B))
#define BMC_CRYPT_SIZE_MAX BMC_CRYPT_MIN(UINT64_MAX, SIZE_MAX)

#endif
