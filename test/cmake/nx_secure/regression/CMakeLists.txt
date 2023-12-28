cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
cmake_policy(SET CMP0057 NEW)

project(regression_test LANGUAGES C)

get_filename_component(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../regression
                       ABSOLUTE)

set(nx_secure_test_cases
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_session_receive_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_send_record_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_client_handshake_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_finished_hash_generate_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_generate_keys_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_generate_premaster_secret_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_handshake_hash_init_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ecc_generate_keys_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_session_renegotiate_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_session_keys_set_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_newest_supported_version_coverage_test.c  
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_verify_mac_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_hash_record_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_certificate_initialize_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_certificate_verify_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_crl_verify_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_parse_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_list_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_store_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_name_check_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_crl_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_error_checking_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_expiration_check_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_key_usage_test.c 
    ${SOURCE_DIR}/nx_secure_test/nx_secure_x509_pkcs7_decode_coverage_test.c 
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_handshake_header_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_session_sni_extension_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_handshake_fragmentation_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_handshake_fragmentation_ecc_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_hash_clone_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_header_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_two_way_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_two_way_test_version_1_1.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_alert_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_error_checking_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_error_checking_2_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_tcp_fragment_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_user_defined_key_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_no_client_cert_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_metadata_size_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_multiple_handshake_msg_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_multithread_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_distinguished_name_compare_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ciphersuites_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_client_handshake_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_clienthello_extension_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_coverage_2_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_coverage_3_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_handshake_fail_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_packet_chain_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_receive_alert_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_receive_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_record_decrypt_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_record_encrypt_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_record_layer_version_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_record_length_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_serverhello_extension_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_unrecognized_ciphersuites_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_unsupported_ciphersuites_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_non_blocking_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ecc_basic_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ecc_protocol_version_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ecc_client_cert_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ecc_ciphersuites_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ecc_curves_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ecc_crl_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ecc_packet_chain_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_ecc_point_format_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_receive_wrong_packet_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_shutdown_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_session_delete_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_cert_verify_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_session_start_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_basic_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_error_checking_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_sliding_window_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_retransmit_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_retransmit_interval_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_retransmit_change_cipher_spec_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_ciphersuites_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_handshake_fail_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_ecjpake_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_multiple_sessions_receive_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_multiple_sessions_connect_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_multiple_sessions_reuse_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_multiple_sessions_connect_fail_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_multiple_sessions_send_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_multiple_sessions_retransmit_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_multiple_sessions_ecjpake_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_multiple_ip_address_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_no_free_sessions_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_concurrent_sessions_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_concurrent_sessions_retransmit_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_abort_waiting_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_fragment_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_abnormal_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_out_of_order_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_version_1_0_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_nxe_api_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_ecc_basic_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_ecc_ciphersuites_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_ecc_curves_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_dtls_ecc_client_cert_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_nxe_api_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_server_handshake_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_cert_callback_fail_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_send_and_receive_record_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_branch_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_crypto_self_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_crypto_cleanup_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_crypto_method_cleanup_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_certificate_verify_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_no_remote_certs_allocated_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_partial_remote_certs_allocated_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_process_certificate_verify_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_process_changecipherspec_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_process_certificate_request_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_process_finished_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_packet_trim_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_process_record_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_rsa_4096_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_rsa_private_key_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_serverhello_session_id_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_version_negotiation_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_handshake_fail_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_ciphersuites_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_clienthello_length_checking_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_key_share_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_provisioned_psk_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_hello_retry_cookie_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_client_ca_select_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_receive_invalid_server_handshake_message_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_invalid_client_state_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_serverhello_length_checking_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_session_create_ext_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_1_3_before_key_generation_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_send_plaintext_alert_after_key_generation_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_server_ciphersuite_priority_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_session_create_ext_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_transmit_mutex_wait_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_empty_clienthello_extension_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_payload_size_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_serverhello_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_hash_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_certificate_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_server_key_exchange_coverage_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_send_certificate_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_tls_send_clienthello_test.c)

# Pure crypto related test cases
if("s${CMAKE_BUILD_TYPE}" STREQUAL "sdefault_build_coverage")
  list(
    APPEND
    nx_secure_test_cases
    ${SOURCE_DIR}/nx_secure_test/nx_secure_3des_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_aes_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_aes_ccm_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_des_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_ec_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_ecdh_self_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_ecdh_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_ecdsa_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_ecjpake_self_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_hkdf_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_hmac_md5_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_hmac_sha1_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_hmac_sha224_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_hmac_sha256_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_hmac_sha384_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_hmac_sha512_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_phash_prf_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_rsa_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_sha256_rfc_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_sha224_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_sha256_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_sha384_test.c
    ${SOURCE_DIR}/nx_secure_test/nx_secure_sha512_test.c)
endif()

set(test_utility_files
    ${SOURCE_DIR}/nx_secure_test/netxtestcontrol.c
    ${SOURCE_DIR}/nx_secure_test/nx_crypto_ciphersuites_regression.c
    ${SOURCE_DIR}/test/nx_ram_network_driver_test_1500.c)

if("s${CMAKE_BUILD_TYPE}" STREQUAL "shash_clone_build")
list(APPEND test_utility_files
    ${SOURCE_DIR}/nx_secure_test/hash_clone/nx_crypto_clone_cleanup_test.c
    ${SOURCE_DIR}/nx_secure_test/hash_clone/nx_crypto_hash_clone_test.c
    ${SOURCE_DIR}/nx_secure_test/hash_clone/nx_crypto_ciphersuites_hc.c)
endif()

add_library(test_utility ${test_utility_files})
target_link_libraries(test_utility PUBLIC azrtos::netxduo)
target_include_directories(test_utility PUBLIC ${SOURCE_DIR}/test)
target_compile_definitions(test_utility PUBLIC BATCH_TEST CTEST)

foreach(test_case ${nx_secure_test_cases})
  get_filename_component(test_name ${test_case} NAME_WE)
  add_executable(${test_name} ${test_case})
  target_link_libraries(${test_name} PRIVATE test_utility)
  add_test(
    NAME ${CMAKE_BUILD_TYPE}::${test_name}
    COMMAND ${test_name}
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/..)
endforeach()
