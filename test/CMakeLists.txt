# Test configuration for bmc_crypt_lib

# Enable testing
enable_testing()



# Test executable for AES ECB
add_executable(test_ecb test_ecb.c)

# Link with the library
target_link_libraries(test_ecb bmc_crypt)

# Set include directories
target_include_directories(test_ecb PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME test_ecb COMMAND test_ecb)

# Set test properties
set_tests_properties(test_ecb PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test executable for AES CBC
add_executable(test_cbc test_cbc.c)

# Link with the library
target_link_libraries(test_cbc bmc_crypt)

# Set include directories
target_include_directories(test_cbc PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME test_cbc COMMAND test_cbc)

# Set test properties
set_tests_properties(test_cbc PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test executable for AES CTR
add_executable(test_ctr test_ctr.c)

# Link with the library
target_link_libraries(test_ctr bmc_crypt)

# Set include directories
target_include_directories(test_ctr PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME test_ctr COMMAND test_ctr)

# Set test properties
set_tests_properties(test_ctr PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test executable for AES GCM
add_executable(test_gcm test_gcm.c)

# Link with the library
target_link_libraries(test_gcm bmc_crypt)

# Set include directories
target_include_directories(test_gcm PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME test_gcm COMMAND test_gcm)

# Set test properties
set_tests_properties(test_gcm PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test executable for random_buf
add_executable(test_random test_random.c)

# Link with the library
target_link_libraries(test_random bmc_crypt)

# Set include directories
target_include_directories(test_random PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME test_random COMMAND test_random)

# Set test properties
set_tests_properties(test_random PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test executable for advanced random_buf tests
add_executable(test_random_advanced test_random_advanced.c)

# Link with the library
target_link_libraries(test_random_advanced bmc_crypt)

# Set include directories
target_include_directories(test_random_advanced PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME test_random_advanced COMMAND test_random_advanced)

# Set test properties
set_tests_properties(test_random_advanced PROPERTIES
    TIMEOUT 60
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test executable for AES CTR IETF
add_executable(test_aes_ctr_ietf test_aes_ctr_ietf.c)

# Link with the library
target_link_libraries(test_aes_ctr_ietf bmc_crypt)

# Set include directories
target_include_directories(test_aes_ctr_ietf PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME test_aes_ctr_ietf COMMAND test_aes_ctr_ietf)

# Set test properties
set_tests_properties(test_aes_ctr_ietf PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test executable for HKDF
add_executable(test_hkdf test_hkdf.c)

# Link with the library
target_link_libraries(test_hkdf bmc_crypt)

# Set include directories
target_include_directories(test_hkdf PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME test_hkdf COMMAND test_hkdf)

# Set test properties
set_tests_properties(test_hkdf PROPERTIES
    TIMEOUT 30
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test executable for hash functions (SHA256, SHA512, HMAC)
add_executable(test_hash test_hash.c)

# Link with the library
target_link_libraries(test_hash bmc_crypt)

# Set include directories
target_include_directories(test_hash PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
)

# Add test
add_test(NAME test_hash COMMAND test_hash)

# Set test properties
set_tests_properties(test_hash PROPERTIES
    TIMEOUT 60
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Optional: Add more test executables here
# add_executable(test_ed25519 test_ed25519.c)
# target_link_libraries(test_ed25519 bmc_crypt::bmc_crypt)
# add_test(NAME test_ed25519 COMMAND test_ed25519)

# Optional: Add test suite
# add_executable(test_suite test_suite.c)
# target_link_libraries(test_suite bmc_crypt::bmc_crypt)
# add_test(NAME test_suite COMMAND test_suite) 