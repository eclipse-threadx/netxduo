cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

project(nx_secure_test LANGUAGES C)
include(${CMAKE_CURRENT_SOURCE_DIR}/../nx_secure/CMakeLists.txt)

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
    hash_clone_build
    curve25519_448_build)
