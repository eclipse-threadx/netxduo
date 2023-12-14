cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

project(nx_secure_test LANGUAGES C)

# Set build configurations
set(BUILD_CONFIGURATIONS
    default_build_coverage
    psk_build_coverage
    tls_1_0_enable_build
    tls_1_1_enable_build
    tls_1_3_enable_build_coverage
    client_disable_build
    server_disable_build
    tls_1_3_client_disable_build
    tls_1_3_server_disable_build
    ecjpake_build
    dtls_build_coverage
    eal4_build_coverage
    sesip_build_coverage
    no_ecc_build_coverage
    no_renegotiation_build
    no_client_renegotiation_build
    no_x509_build
    hash_clone_build
    curve25519_448_build)
set(CMAKE_CONFIGURATION_TYPES
    ${BUILD_CONFIGURATIONS}
    CACHE STRING "list of supported configuration types" FORCE)
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                                             ${CMAKE_CONFIGURATION_TYPES})
list(GET CMAKE_CONFIGURATION_TYPES 0 BUILD_TYPE)
if((NOT CMAKE_BUILD_TYPE) OR (NOT ("${CMAKE_BUILD_TYPE}" IN_LIST
                                   CMAKE_CONFIGURATION_TYPES)))
  set(CMAKE_BUILD_TYPE
      "${BUILD_TYPE}"
      CACHE STRING "Build Type of the project" FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}.")

set(default_build_coverage -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY -DNX_DISABLE_ASSERT)
set(psk_build_coverage
    -DNX_SECURE_ENABLE_PSK_CIPHERSUITES -DNX_SECURE_ENABLE_AEAD_CIPHER
    -DNX_SECURE_X509_DISABLE_CRL)
set(tls_1_3_enable_build_coverage
    -DNX_SECURE_TLS_ENABLE_TLS_1_3
    -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY
    -DNX_SECURE_ENABLE_PSK_CIPHERSUITES)
set(tls_1_1_enable_build -DNX_SECURE_TLS_ENABLE_TLS_1_1
                         -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY)
set(tls_1_0_enable_build
    -DNX_SECURE_TLS_ENABLE_TLS_1_0 -DNX_SECURE_TLS_ENABLE_TLS_1_1
    -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY)
set(client_disable_build -DNX_SECURE_TLS_CLIENT_DISABLED)
set(server_disable_build -DNX_SECURE_TLS_SERVER_DISABLED)
set(tls_1_3_client_disable_build -DNX_SECURE_TLS_ENABLE_TLS_1_3 -DNX_SECURE_TLS_CLIENT_DISABLED)
set(tls_1_3_server_disable_build -DNX_SECURE_TLS_ENABLE_TLS_1_3 -DNX_SECURE_TLS_SERVER_DISABLED)
set(dtls_build_coverage
    -DNX_SECURE_ENABLE_DTLS -DNX_SECURE_ENABLE_PSK_CIPHERSUITES
    -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY -DNX_SECURE_TLS_ENABLE_TLS_1_1)
set(ecjpake_build
    -DNX_SECURE_ENABLE_DTLS -DNX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE
    -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY)
set(eal4_build_coverage
    -DNX_SECURE_KEY_CLEAR -DNX_SECURE_POWER_ON_SELF_TEST_MODULE_INTEGRITY_CHECK
    -DCERT_BUILD -DNX_SECURE_DISABLE_ECC_CIPHERSUITE)
set(sesip_build_coverage
    -DNX_SECURE_KEY_CLEAR -DNX_SECURE_POWER_ON_SELF_TEST_MODULE_INTEGRITY_CHECK
    -DNX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION -DNX_SECURE_TLS_ENABLE_TLS_1_3)
set(no_ecc_build_coverage
    -DNX_SECURE_DISABLE_ECC_CIPHERSUITE
    -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY
    -DNX_SECURE_ENABLE_PSK_CIPHERSUITES
    -DNX_SECURE_ENABLE_AEAD_CIPHER
    -DNX_SECURE_TLS_ENABLE_TLS_1_0
    -DNX_SECURE_ENABLE_DTLS
    -DNX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
set(no_renegotiation_build -DNX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION -DNX_SECURE_TLS_SNI_EXTENSION_DISABLED -DNX_SECURE_TLS_USE_SCSV_CIPHPERSUITE)
set(no_client_renegotiation_build -DNX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
set(no_x509_build
    -DNX_SECURE_ENABLE_PSK_CIPHERSUITES -DNX_SECURE_ENABLE_AEAD_CIPHER
    -DNX_SECURE_DISABLE_X509 -DNX_SECURE_DISABLE_ECC_CIPHERSUITE)
set(hash_clone_build -DNX_SECURE_INCLUDE_USER_DEFINE_FILE -DHASH_CLONE_BUILD)
set(curve25519_448_build
    -DNX_CRYPTO_ENABLE_CURVE25519_448
    -DNX_SECURE_TLS_ENABLE_TLS_1_3
    -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY
    -DNX_SECURE_ENABLE_PSK_CIPHERSUITES)

add_compile_options(
  -ggdb
  -g3
  -gdwarf-2
  -fdiagnostics-color
  -Werror
  -DTX_INCLUDE_USER_DEFINE_FILE
  -DNX_SECURE_X509_STRICT_NAME_COMPARE
  -DNX_SECURE_ALLOW_SELF_SIGNED_CERTIFICATES
  -DNX_ENABLE_EXTENDED_NOTIFY_SUPPORT
  ${${CMAKE_BUILD_TYPE}})

if($ENV{ENABLE_64})
  message(STATUS "Building for 64bit")
else()
  add_compile_options(-m32)
  add_link_options(-m32)
  message(STATUS "Building for 32bit")
endif()

enable_testing()


if("s${CMAKE_BUILD_TYPE}" STREQUAL "shash_clone_build")
  include_directories(${CMAKE_CURRENT_LIST_DIR}/../../regression/nx_secure_test/hash_clone)
endif()

set(NXD_ENABLE_FILE_SERVERS OFF CACHE BOOL "Includes a dependency on FileX to support 'server' protocol handlers" FORCE)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../.. netxduo)
add_subdirectory(${PROJECT_SOURCE_DIR}/regression regression)

# Coverage
if(CMAKE_BUILD_TYPE MATCHES ".*_coverage")
  target_compile_options(netxduo PRIVATE -fprofile-arcs -ftest-coverage)
  target_link_options(netxduo PRIVATE -fprofile-arcs -ftest-coverage)
endif()

# Build ThreadX library once
execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run.sh build_libs)
add_custom_target(build_libs ALL COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run.sh
                                         build_libs)
add_dependencies(netxduo build_libs)
target_include_directories(netxduo PUBLIC ${CMAKE_BINARY_DIR}/../libs/inc)
add_library(threadx SHARED IMPORTED GLOBAL)
add_library("azrtos::threadx" ALIAS threadx)
set_target_properties(
  threadx PROPERTIES IMPORTED_LOCATION
                     ${CMAKE_BINARY_DIR}/../libs/threadx/libthreadx.so)

target_compile_options(
  netxduo
  PRIVATE -Wall
          -Wextra
          -pedantic
          -fmessage-length=0
          -fsigned-char
          -ffunction-sections
          -fdata-sections
          -Wunused
          -Wuninitialized
          -Wmissing-declarations
          -Wconversion
          -Wpointer-arith
          -Wshadow
          -Wlogical-op
          -Waggregate-return
          -Wfloat-equal
          -std=c99)

# Remove addons
get_target_property(SOURCES_LIST netxduo SOURCES)
set(NEW_SOURCES_LIST "")
foreach(SOURCE ${SOURCES_LIST})
  if(NOT ("${SOURCE}" MATCHES ".*addons.*"))
    list(APPEND NEW_SOURCES_LIST ${SOURCE})
  endif()
endforeach()
set_target_properties(netxduo PROPERTIES SOURCES "${NEW_SOURCES_LIST}")
