include(CheckCSourceCompiles)

# Check if __STDC_LIMIT_MACROS is required
set(_STDC_LIMIT_CODE "
#include <limits.h>
#include <stdint.h>

int main() {
    (void) SIZE_MAX;
    (void) UINT64_MAX;
    return 0;
}
")

# First try without __STDC_LIMIT_MACROS
check_c_source_compiles("${_STDC_LIMIT_CODE}" HAVE_STDC_LIMIT_MACROS_WITHOUT_DEFINE)

if(NOT HAVE_STDC_LIMIT_MACROS_WITHOUT_DEFINE)
    # Try with __STDC_LIMIT_MACROS defined
    set(CMAKE_REQUIRED_DEFINITIONS "-D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS")
    check_c_source_compiles("${_STDC_LIMIT_CODE}" HAVE_STDC_LIMIT_MACROS_WITH_DEFINE)
    unset(CMAKE_REQUIRED_DEFINITIONS)
    
    if(HAVE_STDC_LIMIT_MACROS_WITH_DEFINE)
        message(STATUS "__STDC_LIMIT_MACROS is required")
        set(REQUIRE_STDC_LIMIT_MACROS TRUE)
    else()
        message(STATUS "__STDC_LIMIT_MACROS check failed")
        set(REQUIRE_STDC_LIMIT_MACROS FALSE)
    endif()
else()
    message(STATUS "__STDC_LIMIT_MACROS is NOT required")
    set(REQUIRE_STDC_LIMIT_MACROS FALSE)
endif() 