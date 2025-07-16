include(CheckCSourceCompiles)

# Check if atomic operations are supported
set(_ATOMIC_OPS_CODE "
int main() {
    static volatile int _bmc_crypt_lock;
    __sync_lock_test_and_set(&_bmc_crypt_lock, 1);
    __sync_lock_release(&_bmc_crypt_lock);
    return 0;
}
")

check_c_source_compiles("${_ATOMIC_OPS_CODE}" HAVE_ATOMIC_OPS)

if(HAVE_ATOMIC_OPS)
    message(STATUS "Atomic operations are supported")
else()
    message(STATUS "Atomic operations are NOT supported")
endif() 