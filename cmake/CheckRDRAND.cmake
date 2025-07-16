include(CheckCSourceCompiles)

# Check if RDRAND is supported (only on x86/x86_64)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3-6]86|amd64|x86_64|AMD64")
    # Check if RDRAND is supported
    set(_RDRAND_CODE "
#include <immintrin.h>

int main() {
    unsigned int val;
    return _rdrand32_step(&val);
}
")

    check_c_source_compiles("${_RDRAND_CODE}" HAVE_RDRAND)

    if(HAVE_RDRAND)
        message(STATUS "RDRAND instruction is supported")
    else()
        message(STATUS "RDRAND instruction is NOT supported")
    endif()
else()
    message(STATUS "RDRAND check skipped (not x86/x86_64 architecture)")
    set(HAVE_RDRAND FALSE)
endif() 