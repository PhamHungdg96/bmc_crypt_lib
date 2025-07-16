include(TestBigEndian)

# Check host CPU for known little-endian architectures
if(CMAKE_SYSTEM_PROCESSOR MATCHES "i[3-6]86|amd64|x86_64|AMD64")
    message(STATUS "Detected x86/x86_64 architecture - assuming little-endian")
    set(IS_BIG_ENDIAN FALSE)
else()
    # Use CMake's built-in endianness test
    test_big_endian(IS_BIG_ENDIAN)
endif()

if(IS_BIG_ENDIAN)
    message(STATUS "Detected big-endian architecture")
else()
    message(STATUS "Detected little-endian architecture")
endif()
