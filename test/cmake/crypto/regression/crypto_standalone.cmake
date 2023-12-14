cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
set(CPU_ARCH "linux")
set(COMPILER "gnu")

get_filename_component(CRYPTO_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../crypto_libraries
                       ABSOLUTE)

set(crypto_source_files 
    # Network security and crypto components (CRYPTO - STANDALONE)
    ${CRYPTO_DIR}/src/nx_crypto_3des.c
    ${CRYPTO_DIR}/src/nx_crypto_aes.c
    ${CRYPTO_DIR}/src/nx_crypto_cbc.c
    ${CRYPTO_DIR}/src/nx_crypto_ccm.c
    ${CRYPTO_DIR}/src/nx_crypto_ctr.c
    ${CRYPTO_DIR}/src/nx_crypto_des.c
    ${CRYPTO_DIR}/src/nx_crypto_dh.c
    ${CRYPTO_DIR}/src/nx_crypto_drbg.c
    ${CRYPTO_DIR}/src/nx_crypto_ec.c
    ${CRYPTO_DIR}/src/nx_crypto_ec_secp192r1_fixed_points.c
    ${CRYPTO_DIR}/src/nx_crypto_ec_secp224r1_fixed_points.c
    ${CRYPTO_DIR}/src/nx_crypto_ec_secp256r1_fixed_points.c
    ${CRYPTO_DIR}/src/nx_crypto_ec_secp384r1_fixed_points.c
    ${CRYPTO_DIR}/src/nx_crypto_ec_secp521r1_fixed_points.c
    ${CRYPTO_DIR}/src/nx_crypto_ecdh.c
    ${CRYPTO_DIR}/src/nx_crypto_ecdsa.c
    ${CRYPTO_DIR}/src/nx_crypto_ecjpake.c
    ${CRYPTO_DIR}/src/nx_crypto_gcm.c
    ${CRYPTO_DIR}/src/nx_crypto_hkdf.c
    ${CRYPTO_DIR}/src/nx_crypto_hmac.c
    ${CRYPTO_DIR}/src/nx_crypto_hmac_md5.c
    ${CRYPTO_DIR}/src/nx_crypto_hmac_sha1.c
    ${CRYPTO_DIR}/src/nx_crypto_hmac_sha2.c
    ${CRYPTO_DIR}/src/nx_crypto_hmac_sha5.c
    ${CRYPTO_DIR}/src/nx_crypto_huge_number.c
    ${CRYPTO_DIR}/src/nx_crypto_huge_number_extended.c
    ${CRYPTO_DIR}/src/nx_crypto_initialize.c
    ${CRYPTO_DIR}/src/nx_crypto_md5.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_3des.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_aes.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_des.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_drbg.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_ecdh.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_ecdsa.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_hmac_md5.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_hmac_sha.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_md5.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_pkcs1.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_prf.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_rsa.c
    ${CRYPTO_DIR}/src/nx_crypto_method_self_test_sha.c
    ${CRYPTO_DIR}/src/nx_crypto_methods.c
    ${CRYPTO_DIR}/src/nx_crypto_null_cipher.c
    ${CRYPTO_DIR}/src/nx_crypto_phash.c
    ${CRYPTO_DIR}/src/nx_crypto_pkcs1_v1.5.c
    ${CRYPTO_DIR}/src/nx_crypto_rsa.c
    ${CRYPTO_DIR}/src/nx_crypto_sha1.c
    ${CRYPTO_DIR}/src/nx_crypto_sha2.c
    ${CRYPTO_DIR}/src/nx_crypto_sha5.c
    ${CRYPTO_DIR}/src/nx_crypto_tls_prf_1.c
    ${CRYPTO_DIR}/src/nx_crypto_tls_prf_sha256.c
    ${CRYPTO_DIR}/src/nx_crypto_tls_prf_sha384.c
    ${CRYPTO_DIR}/src/nx_crypto_tls_prf_sha512.c
    ${CRYPTO_DIR}/src/nx_crypto_xcbc_mac.c)
    
include_directories(crypto_source_files PUBLIC ${CRYPTO_DIR}/inc)
include_directories(crypto_source_files PUBLIC  "${CRYPTO_DIR}/ports/${CPU_ARCH}/${COMPILER}/inc")
