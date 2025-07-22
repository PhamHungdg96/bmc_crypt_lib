cmake_minimum_required(VERSION 3.10)
project(bmc_crypt_lib VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include(cmake/TestEndian.cmake)
include(cmake/CheckType128.cmake)
include(cmake/CheckStdCLimits.cmake)
include(cmake/CheckInline.cmake)
include(cmake/CheckWeakSymbols.cmake)
include(cmake/CheckAtomicOps.cmake)
include(cmake/CheckMemoryFences.cmake)
include(cmake/CheckAlloca.cmake)
include(cmake/CheckSystemFunctions.cmake)
include(cmake/CheckRandomFunctions.cmake)
include(cmake/CheckRDRAND.cmake)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Collect all source files
file(GLOB_RECURSE SOURCES 
    "src/aes/*.c"
    "src/modes/*.c"
    "src/curve_25519/curve25519/*.c"
    "src/curve_25519/curve25519/ref10/*.c"
    "src/curve_25519/ed25519/*.c"
    "src/curve_25519/ed25519/ref10/*.c"
    "src/curve_25519/sign/*.c"
    "src/randombytes/*.c"
    "src/randombytes/internal/*.c"
    "src/randombytes/sysrandom/*.c"
    "src/hash/*.c"
    "src/hmac/*.c"
    "src/hkdf/*.c"
    "src/verify.c"
    "src/core.c"
    "src/utils.c"
    "src/runtime.c"
)

# Options
option(BUILD_SHARED_LIBS "Build shared libraries instead of static libraries" ON)
option(USE_BLOCKING_RANDOM "Use blocking random number generation" OFF)

# Create library based on option
if(BUILD_SHARED_LIBS)
    add_library(bmc_crypt SHARED ${SOURCES})
    set_target_properties(bmc_crypt PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER "${CMAKE_SOURCE_DIR}/include/bmc_crypt/*.h"
    )
    
    # Set compiler flags for shared library
    target_compile_options(bmc_crypt PRIVATE
        $<$<C_COMPILER_ID:GNU>:-Wall -Wextra -Wpedantic>
        $<$<C_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic>
        $<$<C_COMPILER_ID:MSVC>:/W3>
    )
    
    # Set definitions for shared library
    target_compile_definitions(bmc_crypt PRIVATE
        $<$<CONFIG:Debug>:DEBUG>
        $<$<CONFIG:Release>:NDEBUG>
        BMC_CRYPT_DLL_EXPORT
        $<$<BOOL:${USE_BLOCKING_RANDOM}>:USE_BLOCKING_RANDOM>
        $<$<BOOL:${HAVE_TI_MODE}>:HAVE_TI_MODE=1>
        $<$<BOOL:${IS_BIG_ENDIAN}>:NATIVE_BIG_ENDIAN=1>
        $<$<NOT:$<BOOL:${IS_BIG_ENDIAN}>>:NATIVE_LITTLE_ENDIAN=1>
        $<$<BOOL:${REQUIRE_STDC_LIMIT_MACROS}>:__STDC_LIMIT_MACROS>
        $<$<BOOL:${REQUIRE_STDC_LIMIT_MACROS}>:__STDC_CONSTANT_MACROS>
        $<$<BOOL:${HAVE_WEAK_SYMBOLS}>:HAVE_WEAK_SYMBOLS=1>
        $<$<BOOL:${HAVE_ATOMIC_OPS}>:HAVE_ATOMIC_OPS=1>
        $<$<BOOL:${HAVE_C11_MEMORY_FENCES}>:HAVE_C11_MEMORY_FENCES=1>
        $<$<BOOL:${HAVE_GCC_MEMORY_FENCES}>:HAVE_GCC_MEMORY_FENCES=1>
        $<$<BOOL:${HAVE_ALLOCA}>:HAVE_ALLOCA=1>
        $<$<BOOL:${HAVE_ARC4RANDOM}>:HAVE_ARC4RANDOM=1>
        $<$<BOOL:${HAVE_ARC4RANDOM_BUF}>:HAVE_ARC4RANDOM_BUF=1>
        $<$<BOOL:${HAVE_MMAP}>:HAVE_MMAP=1>
        $<$<BOOL:${HAVE_MLOCK}>:HAVE_MLOCK=1>
        $<$<BOOL:${HAVE_MADVISE}>:HAVE_MADVISE=1>
        $<$<BOOL:${HAVE_MPROTECT}>:HAVE_MPROTECT=1>
        $<$<BOOL:${HAVE_RAISE}>:HAVE_RAISE=1>
        $<$<BOOL:${HAVE_SYSCONF}>:HAVE_SYSCONF=1>
        $<$<BOOL:${HAVE_GETRANDOM}>:HAVE_GETRANDOM=1>
        $<$<BOOL:${HAVE_GETENTROPY}>:HAVE_GETENTROPY=1>
        $<$<BOOL:${HAVE_RDRAND}>:HAVE_RDRAND=1>
    )
else()
    add_library(bmc_crypt STATIC ${SOURCES})
    set_target_properties(bmc_crypt PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER "${CMAKE_SOURCE_DIR}/include/bmc_crypt/*.h"
    )
    
    # Set compiler flags for static library
    target_compile_options(bmc_crypt PRIVATE
        $<$<C_COMPILER_ID:GNU>:-Wall -Wextra -Wpedantic>
        $<$<C_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic>
        $<$<C_COMPILER_ID:MSVC>:/W3>
    )
    
    # Set definitions for static library
    target_compile_definitions(bmc_crypt PRIVATE
        $<$<CONFIG:Debug>:DEBUG>
        $<$<CONFIG:Release>:NDEBUG>
        BMC_CRYPT_STATIC
        $<$<BOOL:${USE_BLOCKING_RANDOM}>:USE_BLOCKING_RANDOM>
        $<$<BOOL:${HAVE_TI_MODE}>:HAVE_TI_MODE=1>
        $<$<BOOL:${IS_BIG_ENDIAN}>:NATIVE_BIG_ENDIAN=1>
        $<$<NOT:$<BOOL:${IS_BIG_ENDIAN}>>:NATIVE_LITTLE_ENDIAN=1>
        $<$<BOOL:${REQUIRE_STDC_LIMIT_MACROS}>:__STDC_LIMIT_MACROS>
        $<$<BOOL:${REQUIRE_STDC_LIMIT_MACROS}>:__STDC_CONSTANT_MACROS>
        $<$<BOOL:${HAVE_WEAK_SYMBOLS}>:HAVE_WEAK_SYMBOLS=1>
        $<$<BOOL:${HAVE_ATOMIC_OPS}>:HAVE_ATOMIC_OPS=1>
        $<$<BOOL:${HAVE_C11_MEMORY_FENCES}>:HAVE_C11_MEMORY_FENCES=1>
        $<$<BOOL:${HAVE_GCC_MEMORY_FENCES}>:HAVE_GCC_MEMORY_FENCES=1>
        $<$<BOOL:${HAVE_ALLOCA}>:HAVE_ALLOCA=1>
        $<$<BOOL:${HAVE_ARC4RANDOM}>:HAVE_ARC4RANDOM=1>
        $<$<BOOL:${HAVE_ARC4RANDOM_BUF}>:HAVE_ARC4RANDOM_BUF=1>
        $<$<BOOL:${HAVE_MMAP}>:HAVE_MMAP=1>
        $<$<BOOL:${HAVE_MLOCK}>:HAVE_MLOCK=1>
        $<$<BOOL:${HAVE_MADVISE}>:HAVE_MADVISE=1>
        $<$<BOOL:${HAVE_MPROTECT}>:HAVE_MPROTECT=1>
        $<$<BOOL:${HAVE_RAISE}>:HAVE_RAISE=1>
        $<$<BOOL:${HAVE_SYSCONF}>:HAVE_SYSCONF=1>
        $<$<BOOL:${HAVE_GETRANDOM}>:HAVE_GETRANDOM=1>
        $<$<BOOL:${HAVE_GETENTROPY}>:HAVE_GETENTROPY=1>
        $<$<BOOL:${HAVE_RDRAND}>:HAVE_RDRAND=1>
    )
endif()

# Install rules
install(TARGETS bmc_crypt
    EXPORT bmc_cryptTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/bmc_crypt
)

# Install headers
install(DIRECTORY include/bmc_crypt/
    DESTINATION include/bmc_crypt
    FILES_MATCHING PATTERN "*.h"
)

# Export targets
install(EXPORT bmc_cryptTargets
    FILE bmc_cryptTargets.cmake
    NAMESPACE bmc_crypt::
    DESTINATION lib/cmake/bmc_crypt
)

# Create config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    bmc_cryptConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Set package variables
set(PACKAGE_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include")

# Create config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/bmc_cryptConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/bmc_cryptConfig.cmake
    @ONLY
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/bmc_cryptConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/bmc_cryptConfigVersion.cmake
    DESTINATION lib/cmake/bmc_crypt
)



# Optional: Create test executable
option(BUILD_TESTS "Build test executable" ON)
if(BUILD_TESTS)
    add_subdirectory(test)
endif()

# Optional: Create demo executable
option(BUILD_DEMO "Build demo executable" ON)
if(BUILD_DEMO)
    add_subdirectory(demo)
endif()

# Print configuration summary
message(STATUS "Configuration Summary:")
message(STATUS "  Project: ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  Build shared libraries: ${BUILD_SHARED_LIBS}")
message(STATUS "  Use blocking random: ${USE_BLOCKING_RANDOM}")
message(STATUS "  Use ti mode: ${HAVE_TI_MODE}")
if(IS_BIG_ENDIAN)
    message(STATUS "  Endianness: big")
else()
    message(STATUS "  Endianness: little")
endif()
message(STATUS "  Require __STDC_LIMIT_MACROS: ${REQUIRE_STDC_LIMIT_MACROS}")
message(STATUS "  Inline support: ${HAVE_INLINE}")
message(STATUS "  Weak symbols: ${HAVE_WEAK_SYMBOLS}")
message(STATUS "  Atomic operations: ${HAVE_ATOMIC_OPS}")
message(STATUS "  C11 memory fences: ${HAVE_C11_MEMORY_FENCES}")
message(STATUS "  GCC memory fences: ${HAVE_GCC_MEMORY_FENCES}")
message(STATUS "  Alloca function: ${HAVE_ALLOCA}")
message(STATUS "  Arc4random: ${HAVE_ARC4RANDOM}")
message(STATUS "  Arc4random_buf: ${HAVE_ARC4RANDOM_BUF}")
message(STATUS "  Mmap: ${HAVE_MMAP}")
message(STATUS "  Mlock: ${HAVE_MLOCK}")
message(STATUS "  Madvise: ${HAVE_MADVISE}")
message(STATUS "  Mprotect: ${HAVE_MPROTECT}")
message(STATUS "  Raise: ${HAVE_RAISE}")
message(STATUS "  Sysconf: ${HAVE_SYSCONF}")
message(STATUS "  Getrandom: ${HAVE_GETRANDOM}")
message(STATUS "  Getentropy: ${HAVE_GETENTROPY}")
message(STATUS "  RDRAND: ${HAVE_RDRAND}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Source files: ${SOURCES}") 