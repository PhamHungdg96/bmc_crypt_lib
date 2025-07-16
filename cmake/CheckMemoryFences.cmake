include(CheckCSourceCompiles)

# Check if C11 memory fences are supported
set(_C11_MEMORY_FENCES_CODE "
#include <stdatomic.h>

int main() {
    atomic_thread_fence(memory_order_acquire);
    return 0;
}
")

check_c_source_compiles("${_C11_MEMORY_FENCES_CODE}" HAVE_C11_MEMORY_FENCES)

if(HAVE_C11_MEMORY_FENCES)
    message(STATUS "C11 memory fences are supported")
else()
    message(STATUS "C11 memory fences are NOT supported")
endif()

# Check if gcc memory fences are supported
set(_GCC_MEMORY_FENCES_CODE "
int main() {
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return 0;
}
")

check_c_source_compiles("${_GCC_MEMORY_FENCES_CODE}" HAVE_GCC_MEMORY_FENCES)

if(HAVE_GCC_MEMORY_FENCES)
    message(STATUS "GCC memory fences are supported")
else()
    message(STATUS "GCC memory fences are NOT supported")
endif() 