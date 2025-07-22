# Test configuration for bmc_crypt_lib

# Test executable for AES ECB
add_executable(alice_bob alice_bob.c)

# Link with the library
target_link_libraries(alice_bob bmc_crypt)

# Set include directories
target_include_directories(alice_bob PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME alice_bob COMMAND alice_bob)

# Set test properties
set_tests_properties(alice_bob PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)