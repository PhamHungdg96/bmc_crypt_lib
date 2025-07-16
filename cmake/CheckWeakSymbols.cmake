include(CheckCSourceCompiles)

# Check if weak symbols are supported
set(_WEAK_SYMBOLS_CODE "
#if !defined(__ELF__) && !defined(__APPLE_CC__)
# error Support for weak symbols may not be available
#endif

__attribute__((weak)) void __dummy(void *x) { }
void f(void *x) { __dummy(x); }

int main() {
    return 0;
}
")

check_c_source_compiles("${_WEAK_SYMBOLS_CODE}" HAVE_WEAK_SYMBOLS)

if(HAVE_WEAK_SYMBOLS)
    message(STATUS "Weak symbols are supported")
else()
    message(STATUS "Weak symbols are NOT supported")
endif() 