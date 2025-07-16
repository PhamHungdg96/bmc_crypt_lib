include(CheckFunctionExists)

# Skip checks for Emscripten
if(EMSCRIPTEN)
    message(STATUS "Skipping system function checks for Emscripten")
    return()
endif()

# Check for arc4random functions
check_function_exists(arc4random HAVE_ARC4RANDOM)
check_function_exists(arc4random_buf HAVE_ARC4RANDOM_BUF)

if(HAVE_ARC4RANDOM)
    message(STATUS "arc4random function is available")
else()
    message(STATUS "arc4random function is NOT available")
endif()

if(HAVE_ARC4RANDOM_BUF)
    message(STATUS "arc4random_buf function is available")
else()
    message(STATUS "arc4random_buf function is NOT available")
endif()

# Skip memory management checks for WASI
if(WASI)
    message(STATUS "Skipping memory management checks for WASI")
else()
    # Check for memory management functions
    check_function_exists(mmap HAVE_MMAP)
    check_function_exists(mlock HAVE_MLOCK)
    check_function_exists(madvise HAVE_MADVISE)
    check_function_exists(mprotect HAVE_MPROTECT)
    
    if(HAVE_MMAP)
        message(STATUS "mmap function is available")
    else()
        message(STATUS "mmap function is NOT available")
    endif()
    
    if(HAVE_MLOCK)
        message(STATUS "mlock function is available")
    else()
        message(STATUS "mlock function is NOT available")
    endif()
    
    if(HAVE_MADVISE)
        message(STATUS "madvise function is available")
    else()
        message(STATUS "madvise function is NOT available")
    endif()
    
    if(HAVE_MPROTECT)
        message(STATUS "mprotect function is available")
    else()
        message(STATUS "mprotect function is NOT available")
    endif()
endif()

# Check for other system functions
check_function_exists(raise HAVE_RAISE)
check_function_exists(sysconf HAVE_SYSCONF)

if(HAVE_RAISE)
    message(STATUS "raise function is available")
else()
    message(STATUS "raise function is NOT available")
endif()

if(HAVE_SYSCONF)
    message(STATUS "sysconf function is available")
else()
    message(STATUS "sysconf function is NOT available")
endif() 