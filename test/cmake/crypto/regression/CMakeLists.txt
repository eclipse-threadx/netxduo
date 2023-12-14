cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
cmake_policy(SET CMP0057 NEW)

project(regression_test LANGUAGES C)

get_filename_component(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../regression/nx_secure_test
                       ABSOLUTE)

set(crypto_test_cases
    ${SOURCE_DIR}/nx_secure_3des_test.c
    ${SOURCE_DIR}/nx_secure_3des_error_checking_test.c
    ${SOURCE_DIR}/nx_secure_sha_additional_test.c
    ${SOURCE_DIR}/nx_secure_sha256_rfc_test.c
    ${SOURCE_DIR}/nx_secure_sha256_test.c
    ${SOURCE_DIR}/nx_secure_sha384_test.c
    ${SOURCE_DIR}/nx_secure_sha512_test.c
    ${SOURCE_DIR}/nx_secure_hmac_md5_test.c
    ${SOURCE_DIR}/nx_secure_hmac_md5_error_checking_test.c
    ${SOURCE_DIR}/nx_secure_hmac_sha1_test.c
    ${SOURCE_DIR}/nx_secure_hmac_sha256_test.c
    ${SOURCE_DIR}/nx_secure_hmac_sha384_test.c
    ${SOURCE_DIR}/nx_secure_hmac_sha512_test.c
    ${SOURCE_DIR}/nx_secure_rsa_test.c
    ${SOURCE_DIR}/nx_secure_rsa_error_checking_test.c
    ${SOURCE_DIR}/nx_secure_aes_test.c
    ${SOURCE_DIR}/nx_secure_aes_additional_test.c
    ${SOURCE_DIR}/nx_secure_aes_ccm_test.c
    ${SOURCE_DIR}/nx_secure_des_test.c
    ${SOURCE_DIR}/nx_secure_des_error_checking_test.c
    ${SOURCE_DIR}/nx_secure_drbg_test.c
    ${SOURCE_DIR}/nx_secure_ec_test.c
    ${SOURCE_DIR}/nx_secure_ec_additional_test.c
    ${SOURCE_DIR}/nx_secure_ecdh_test.c
    ${SOURCE_DIR}/nx_secure_ecdh_error_checking_test.c
    ${SOURCE_DIR}/nx_secure_ecdh_self_test.c
    ${SOURCE_DIR}/nx_secure_ecdsa_test.c
    ${SOURCE_DIR}/nx_secure_ecdsa_error_checking_test.c
    ${SOURCE_DIR}/nx_secure_ecjpake_self_test.c
    ${SOURCE_DIR}/nx_secure_huge_number_test.c
    ${SOURCE_DIR}/nx_secure_md5_test.c
    ${SOURCE_DIR}/nx_secure_phash_prf_test.c
    ${SOURCE_DIR}/nx_secure_pkcs1_v1_5_test.c)
set(test_utility_files ${SOURCE_DIR}/../crypto_test/cryptotestcontrol.c)
if(("${CMAKE_BUILD_TYPE}" STREQUAL "standalone_build"))
    include(${CMAKE_CURRENT_SOURCE_DIR}/crypto_standalone.cmake)
endif()

if(NOT("${CMAKE_BUILD_TYPE}" STREQUAL "standalone_build"))
   add_library(test_utility ${test_utility_files})
   target_link_libraries(test_utility PUBLIC azrtos::netxduo)
else()
   add_library(test_utility ${crypto_source_files} ${test_utility_files})
endif()

target_include_directories(test_utility PUBLIC ${SOURCE_DIR}/test)
target_compile_definitions(test_utility PUBLIC BATCH_TEST CTEST)
if(("${CMAKE_BUILD_TYPE}" STREQUAL "fips_build_coverage") OR ("${CMAKE_BUILD_TYPE}" STREQUAL "standalone_build"))
  target_link_libraries(test_utility PUBLIC crypto)
endif()

foreach(test_case ${crypto_test_cases})
  get_filename_component(test_name ${test_case} NAME_WE)
  add_executable(${test_name} ${test_case})
  target_link_libraries(${test_name} PRIVATE test_utility)
  add_test(
    NAME ${CMAKE_BUILD_TYPE}::${test_name}
    COMMAND ${test_name}
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/..)
endforeach()
