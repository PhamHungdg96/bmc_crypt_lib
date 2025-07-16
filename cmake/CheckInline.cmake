include(CheckCSourceCompiles)

# Check for inline support
set(_INLINE_CODE "
static inline int test_inline(int x) {
    return x + 1;
}

int main() {
    return test_inline(5);
}
")

check_c_source_compiles("${_INLINE_CODE}" HAVE_INLINE)

if(HAVE_INLINE)
    message(STATUS "Inline functions are supported")
else()
    message(STATUS "Inline functions are NOT supported")
endif() 