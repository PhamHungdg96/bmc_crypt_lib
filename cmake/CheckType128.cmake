include(CheckCSourceCompiles)

# First check endianness
set(_ENDIAN_CODE "
#include <stdint.h>

int main() {
    union {
        uint16_t value;
        uint8_t bytes[2];
    } test = {0x0102};
    
    return test.bytes[0] == 0x01 ? 0 : 1;
}
")

check_c_source_compiles("${_ENDIAN_CODE}" IS_LITTLE_ENDIAN)

if(IS_LITTLE_ENDIAN)
    message(STATUS "Detected little-endian architecture for 128-bit check")
else()
    message(STATUS "Detected big-endian architecture for 128-bit check")
endif()

# Only check 128-bit support on little-endian systems
if(IS_LITTLE_ENDIAN)
set(_128BIT_CODE "
#if !defined(__clang__) && !defined(__GNUC__) && !defined(__SIZEOF_INT128__)
#error mode(TI) is a gcc extension, and __int128 is not available
#endif

#if defined(__clang__) && !defined(__x86_64__) && !defined(__aarch64__)
#error clang does not properly handle the 128-bit type on 32-bit systems
#endif

#ifdef __EMSCRIPTEN__
#error emscripten currently doesn't support some operations on integers larger than 64 bits
#endif

#include <stddef.h>
#include <stdint.h>

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
#else
typedef unsigned uint128_t __attribute__((mode(TI)));
#endif

void fcontract(uint128_t *t) {
  *t += 0x8000000000000ULL - 1;
  *t *= *t;
  *t >>= 84;
}

int main() {
  uint128_t x = 1;
  fcontract(&x);
  return 0;
}
")

    check_c_source_compiles("${_128BIT_CODE}" HAVE_TI_MODE)

    if(HAVE_TI_MODE)
        message(STATUS "128-bit arithmetic is supported (TI mode)")
    else()
        message(STATUS "128-bit arithmetic is NOT supported")
    endif()
else()
    message(STATUS "128-bit arithmetic check skipped (big-endian system)")
    set(HAVE_TI_MODE FALSE)
endif()
