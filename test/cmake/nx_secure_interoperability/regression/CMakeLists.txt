cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
cmake_policy(SET CMP0057 NEW)

project(regression_test LANGUAGES C)

get_filename_component(
  SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../regression/interoperability_test/nx_secure_test
  ABSOLUTE)

list(APPEND nx_secure_test_cases demo_ping_test)
set(demo_ping_test_file_list ${SOURCE_DIR}/demo_ping_test.c)

list(APPEND nx_secure_test_cases demo_tls_test)
set(demo_tls_test_file_list ${SOURCE_DIR}/demo_tls_test.c
                            ${SOURCE_DIR}/demo_tls_test_server.c)

list(APPEND nx_secure_test_cases
     tls_1_0_openssl_echo_server_nx_secure_echo_client_test)
set(tls_1_0_openssl_echo_server_nx_secure_echo_client_test_file_list
    ${SOURCE_DIR}/tls_1_0_openssl_echo_server_entry.c
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
    ${SOURCE_DIR}/nx_secure_1_0_1_1_echo_client_entry.c)

list(APPEND nx_secure_test_cases
     tls_1_1_openssl_echo_server_nx_secure_echo_client_test)
set(tls_1_1_openssl_echo_server_nx_secure_echo_client_test_file_list
    ${SOURCE_DIR}/tls_1_1_openssl_echo_server_entry.c
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
    ${SOURCE_DIR}/nx_secure_1_0_1_1_echo_client_entry.c)

list(APPEND nx_secure_test_cases
     tls_1_2_openssl_echo_server_nx_secure_echo_client_test)
set(tls_1_2_openssl_echo_server_nx_secure_echo_client_test_file_list
    ${SOURCE_DIR}/tls_1_2_openssl_echo_server_entry.c
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
    ${SOURCE_DIR}/nx_secure_echo_client_entry.c)

list(APPEND nx_secure_test_cases
     override_tls_1_1_openssl_echo_server_nx_secure_echo_client_test)
set(override_tls_1_1_openssl_echo_server_nx_secure_echo_client_test_file_list
    ${SOURCE_DIR}/tls_1_1_openssl_echo_server_entry.c
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_long_time_test.c
    ${SOURCE_DIR}/nx_secure_override_tls_1_1_echo_client_entry.c)

list(APPEND nx_secure_test_cases tls_1_2_protocol_version_negotiation_test)
set(tls_1_2_protocol_version_negotiation_test_file_list
    ${SOURCE_DIR}/tls_negotiation_test.c
    ${SOURCE_DIR}/nx_secure_echo_server_entry.c
    ${SOURCE_DIR}/tls_1_2_openssl_echo_client_entry.c)

list(APPEND nx_secure_test_cases openssl_1_1_protocol_version_negotiation_test)
set(openssl_1_1_protocol_version_negotiation_test_file_list
    ${SOURCE_DIR}/tls_ecc_negotiation_test.c
    ${SOURCE_DIR}/nx_secure_ecc_echo_server_entry.c
    ${SOURCE_DIR}/tls_openssl_1_1_prime256v1_echo_client_entry.c)

list(APPEND nx_secure_test_cases tls_1_1_protocol_version_negotiation_test)
set(tls_1_1_protocol_version_negotiation_test_file_list
    ${SOURCE_DIR}/tls_negotiation_test.c
    ${SOURCE_DIR}/nx_secure_1_0_1_1_echo_server_entry.c
    ${SOURCE_DIR}/tls_1_1_openssl_echo_client_entry.c)

list(APPEND nx_secure_test_cases tls_1_0_protocol_version_negotiation_test)
set(tls_1_0_protocol_version_negotiation_test_file_list
    ${SOURCE_DIR}/tls_negotiation_test.c
    ${SOURCE_DIR}/nx_secure_echo_server_entry.c
    ${SOURCE_DIR}/tls_1_0_openssl_echo_client_entry.c)

list(APPEND nx_secure_test_cases tls_ecc_client_ciphersuites_test)
set(tls_ecc_client_ciphersuites_test_file_list
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_long_time_test.c
    ${SOURCE_DIR}/nx_secure_ecc_echo_client_entry.c
    ${SOURCE_DIR}/ecc_tls_1_2_openssl_echo_server_entry.c)

list(APPEND nx_secure_test_cases rsa_aes128_sha_ciphersuite_test)
set(rsa_aes128_sha_ciphersuite_test_file_list
    ${SOURCE_DIR}/tls_negotiation_test.c
    ${SOURCE_DIR}/nx_secure_echo_server_entry.c
    ${SOURCE_DIR}/rsa_aes128_sha_openssl_echo_client_entry.c)

list(APPEND nx_secure_test_cases rsa_aes256_sha_ciphersuite_test)
set(rsa_aes256_sha_ciphersuite_test_file_list
    ${SOURCE_DIR}/tls_negotiation_test.c
    ${SOURCE_DIR}/nx_secure_echo_server_entry.c
    ${SOURCE_DIR}/rsa_aes256_sha_openssl_echo_client_entry.c)

list(APPEND nx_secure_test_cases rsa_aes128_gcm_ciphersuite_test)
set(rsa_aes128_gcm_ciphersuite_test_file_list
    ${SOURCE_DIR}/tls_negotiation_test.c
    ${SOURCE_DIR}/nx_secure_echo_server_entry.c
    ${SOURCE_DIR}/rsa_aes128_gcm_openssl_echo_client_entry.c)

list(APPEND nx_secure_test_cases rsa_aes128_gcm_ciphersuite_client_test)
set(rsa_aes128_gcm_ciphersuite_client_test_file_list
    ${SOURCE_DIR}/tls_1_2_openssl_echo_server_entry.c
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
    ${SOURCE_DIR}/nx_secure_echo_client_aes128_gcm_entry.c)

list(APPEND nx_secure_test_cases tls_ecc_server_basic_test)
set(tls_ecc_server_basic_test_file_list
    ${SOURCE_DIR}/tls_ecc_negotiation_test.c
    ${SOURCE_DIR}/nx_secure_ecc_echo_server_entry.c
    ${SOURCE_DIR}/tls_1_2_openssl_echo_client_entry.c)

list(APPEND nx_secure_test_cases client_certificate_verify_server_test)
set(client_certificate_verify_server_test_file_list
    ${SOURCE_DIR}/tls_negotiation_test.c
    ${SOURCE_DIR}/openssl_client_certificate_verify_test_client_entry.c
    ${SOURCE_DIR}/nx_secure_client_certificate_verify_test_server_entry.c)

list(APPEND nx_secure_test_cases client_certificate_verify_client_test)
set(client_certificate_verify_client_test_file_list
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
    ${SOURCE_DIR}/openssl_client_certificate_verify_test_server_entry.c
    ${SOURCE_DIR}/nx_secure_client_certificate_verify_test_client_entry.c)

list(APPEND nx_secure_test_cases tls_ecc_server_ciphersuites_test)
set(tls_ecc_server_ciphersuites_test_file_list
    ${SOURCE_DIR}/tls_ecc_server_ciphersuites_test.c
    ${SOURCE_DIR}/nx_secure_ecc_server_ciphersuites_entry.c)

list(APPEND nx_secure_test_cases tls_ecc_server_curves_test)
set(tls_ecc_server_curves_test_file_list
    ${SOURCE_DIR}/tls_ecc_server_curves_test.c
    ${SOURCE_DIR}/nx_secure_ecc_server_curves_entry.c)

list(APPEND nx_secure_test_cases tls_ecc_client_curves_test)
set(tls_ecc_client_curves_test_file_list
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_long_time_test.c
    ${SOURCE_DIR}/ecc_tls_1_2_openssl_curves_test_server_entry.c
    ${SOURCE_DIR}/nx_secure_ecc_curves_test_client_entry.c)

list(APPEND nx_secure_test_cases tls_ecc_server_cert_test)
set(tls_ecc_server_cert_test_file_list
    ${SOURCE_DIR}/tls_ecc_server_cert_test.c
    ${SOURCE_DIR}/nx_secure_ecc_server_cert_entry.c)

list(APPEND nx_secure_test_cases tls_ecc_client_cert_test)
set(tls_ecc_client_cert_test_file_list
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
    ${SOURCE_DIR}/ecc_tls_1_2_openssl_client_cert_test_server_entry.c
    ${SOURCE_DIR}/nx_secure_ecc_client_cert_test_client_entry.c)

list(APPEND nx_secure_test_cases tls_1_0_1_1_ecc_server_test)
set(tls_1_0_1_1_ecc_server_test_file_list
    ${SOURCE_DIR}/tls_1_0_1_1_ecc_server_test.c
    ${SOURCE_DIR}/nx_secure_ecc_1_0_1_1_server_entry.c)

if("-DNX_SECURE_ENABLE_DTLS" IN_LIST ${CMAKE_BUILD_TYPE})
  list(APPEND nx_secure_test_cases demo_dtls_test)
  set(demo_dtls_test_file_list ${SOURCE_DIR}/demo_dtls_test.c
                               ${SOURCE_DIR}/demo_dtls_test_server.c)

  list(APPEND nx_secure_test_cases
       dtls_openssl_echo_server_nx_secure_echo_client_test)
  set(dtls_openssl_echo_server_nx_secure_echo_client_test_file_list
      ${SOURCE_DIR}/dtls_openssl_echo_server_entry.c
      ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
      ${SOURCE_DIR}/nx_secure_dtls_echo_client_entry.c)

  list(APPEND nx_secure_test_cases
       dtls_reuse_nx_secure_server_openssl_client_test)
  set(dtls_reuse_nx_secure_server_openssl_client_test_file_list
      ${SOURCE_DIR}/dtls_two_instance_test.c
      ${SOURCE_DIR}/dtls_reuse_nx_secure_server_entry.c
      ${SOURCE_DIR}/dtls_reuse_openssl_client_entry.c)

  list(APPEND nx_secure_test_cases dtls_rsa_aes128_sha_ciphersuite_test)
  set(dtls_rsa_aes128_sha_ciphersuite_test_file_list
      ${SOURCE_DIR}/dtls_two_instance_test.c
      ${SOURCE_DIR}/dtls_nx_secure_server_entry.c
      ${SOURCE_DIR}/dtls_rsa_aes128_sha_openssl_client_entry.c)

  list(APPEND nx_secure_test_cases dtls_rsa_aes256_sha_ciphersuite_test)
  set(dtls_rsa_aes256_sha_ciphersuite_test_file_list
      ${SOURCE_DIR}/dtls_two_instance_test.c
      ${SOURCE_DIR}/dtls_nx_secure_server_entry.c
      ${SOURCE_DIR}/dtls_rsa_aes256_sha_openssl_client_entry.c)

  list(APPEND nx_secure_test_cases dtls_rsa_aes128_gcm_ciphersuite_test)
  set(dtls_rsa_aes128_gcm_ciphersuite_test_file_list
      ${SOURCE_DIR}/dtls_two_instance_test.c
      ${SOURCE_DIR}/dtls_nx_secure_server_entry.c
      ${SOURCE_DIR}/dtls_rsa_aes128_gcm_openssl_client_entry.c)

  list(APPEND nx_secure_test_cases dtls_rsa_aes128_gcm_ciphersuite_client_test)
  set(dtls_rsa_aes128_gcm_ciphersuite_client_test_file_list
      ${SOURCE_DIR}/dtls_two_instance_test.c
      ${SOURCE_DIR}/dtls_openssl_server_entry.c
      ${SOURCE_DIR}/dtls_aes128_gcm_nx_secure_client_entry.c)

  list(APPEND nx_secure_test_cases dtls_client_certificate_verify_client_test)
  set(dtls_client_certificate_verify_client_test_file_list
      ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
      ${SOURCE_DIR}/dtls_openssl_client_certificate_verify_test_server_entry.c
      ${SOURCE_DIR}/dtls_nx_secure_client_certificate_verify_test_client_entry.c
  )

  list(APPEND nx_secure_test_cases dtls_client_certificate_verify_server_test)
  set(dtls_client_certificate_verify_server_test_file_list
      ${SOURCE_DIR}/dtls_two_instance_test.c
      ${SOURCE_DIR}/dtls_openssl_client_certificate_verify_test_client_entry.c
      ${SOURCE_DIR}/dtls_nx_secure_client_certificate_verify_test_server_entry.c
  )

  list(APPEND nx_secure_test_cases dtls_version_1_0_server_test)
  set(dtls_version_1_0_server_test_file_list
      ${SOURCE_DIR}/dtls_two_instance_test.c
      ${SOURCE_DIR}/dtls_version_1_0_openssl_client_entry.c
      ${SOURCE_DIR}/dtls_nx_secure_server_entry.c)

  list(APPEND nx_secure_test_cases dtls_version_1_0_client_test)
  set(dtls_version_1_0_client_test_file_list
      ${SOURCE_DIR}/dtls_two_instance_test.c
      ${SOURCE_DIR}/dtls_version_1_0_openssl_server_entry.c
      ${SOURCE_DIR}/dtls_version_1_0_nx_secure_client_entry.c)

  list(APPEND nx_secure_test_cases dtls_ecc_server_test)
  set(dtls_ecc_server_test_file_list
      ${SOURCE_DIR}/dtls_two_instance_test.c
      ${SOURCE_DIR}/dtls_openssl_ecc_test_client_entry.c
      ${SOURCE_DIR}/dtls_nx_secure_ecc_test_server_entry.c)

  list(APPEND nx_secure_test_cases dtls_ecc_client_test)
  set(dtls_ecc_client_test_file_list
      ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
      ${SOURCE_DIR}/dtls_openssl_ecc_test_server_entry.c
      ${SOURCE_DIR}/dtls_nx_secure_ecc_test_client_entry.c)
endif()

list(APPEND nx_secure_test_cases signature_algorithm_client_test)
set(signature_algorithm_client_test_file_list
    ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_long_time_test.c
    ${SOURCE_DIR}/signature_algorithm_test_openssl_echo_server_entry.c
    ${SOURCE_DIR}/signature_algorithm_test_nx_secure_echo_client_entry.c)

list(APPEND nx_secure_test_cases signature_algorithm_server_test)
set(signature_algorithm_server_test_file_list
    ${SOURCE_DIR}/tls_ecc_negotiation_test.c
    ${SOURCE_DIR}/signature_algorithm_test_openssl_echo_client_entry.c
    ${SOURCE_DIR}/signature_algorithm_test_nx_secure_echo_server_entry.c)

if("-DNX_SECURE_TLS_ENABLE_TLS_1_3" IN_LIST ${CMAKE_BUILD_TYPE})
  list(APPEND nx_secure_test_cases
       tls_1_3_openssl_echo_server_nx_secure_echo_client_test)
  set(tls_1_3_openssl_echo_server_nx_secure_echo_client_test_file_list
      ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
      ${SOURCE_DIR}/tls_1_3_openssl_echo_server_entry.c
      ${SOURCE_DIR}/tls_1_3_nx_secure_echo_client_entry.c)

  list(APPEND nx_secure_test_cases
       tls_1_3_client_certificate_verify_client_test)
  set(tls_1_3_client_certificate_verify_client_test_file_list
      ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
      ${SOURCE_DIR}/tls_1_3_client_certificate_verify_test_openssl_echo_server_entry.c
      ${SOURCE_DIR}/tls_1_3_client_certificate_verify_test_nx_secure_echo_client_entry.c
  )

  list(APPEND nx_secure_test_cases
       tls_1_3_client_certificate_verify_server_test)
  set(tls_1_3_client_certificate_verify_server_test_file_list
      ${SOURCE_DIR}/tls_negotiation_test.c
      ${SOURCE_DIR}/tls_1_3_client_certificate_verify_test_openssl_echo_client_entry.c
      ${SOURCE_DIR}/tls_1_3_client_certificate_verify_test_nx_secure_echo_server_entry.c
  )

  list(APPEND nx_secure_test_cases tls_1_3_client_session_reuse_test)
  set(tls_1_3_client_session_reuse_test_file_list
      ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
      ${SOURCE_DIR}/tls_1_3_client_session_reuse_test_openssl_echo_server_entry.c
      ${SOURCE_DIR}/tls_1_3_client_session_reuse_test_nx_secure_echo_client_entry.c
  )

  list(APPEND nx_secure_test_cases tls_1_3_client_hello_retry_request_test)
  set(tls_1_3_client_hello_retry_request_test_file_list
      ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
      ${SOURCE_DIR}/tls_1_3_hello_retry_request_test_openssl_echo_server_entry.c
      ${SOURCE_DIR}/tls_1_3_nx_secure_echo_client_entry.c)

  list(APPEND nx_secure_test_cases tls_1_3_server_hello_retry_request_test)
  set(tls_1_3_server_hello_retry_request_test_file_list
      ${SOURCE_DIR}/tls_ecc_negotiation_test.c
      ${SOURCE_DIR}/nx_secure_ecc_echo_server_entry.c
      ${SOURCE_DIR}/tls_openssl_1_1_echo_client_entry.c)

  list(APPEND nx_secure_test_cases tls_1_3_hello_retry_cookie_test)
  set(tls_1_3_hello_retry_cookie_test_file_list
      ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
      ${SOURCE_DIR}/tls_1_3_hello_retry_cookie_test_openssl_echo_server_entry.c
      ${SOURCE_DIR}/tls_1_3_hello_retry_cookie_test_nx_secure_echo_client_entry.c
  )

  list(APPEND nx_secure_test_cases tls_1_3_alert_server_test)
  set(tls_1_3_alert_server_test_file_list
      ${SOURCE_DIR}/tls_ecc_negotiation_test.c
      ${SOURCE_DIR}/tls_1_3_alert_test_openssl_echo_client_entry.c
      ${SOURCE_DIR}/tls_1_3_alert_test_nx_secure_echo_server_entry.c)

  list(APPEND nx_secure_test_cases tls_1_3_psk_client_test)
  set(tls_1_3_psk_client_test_file_list
      ${SOURCE_DIR}/openssl_echo_server_nx_secure_echo_client_test.c
      ${SOURCE_DIR}/tls_1_3_psk_test_openssl_echo_server_entry.c
      ${SOURCE_DIR}/tls_1_3_psk_test_nx_secure_echo_client_entry.c)

  list(APPEND nx_secure_test_cases tls_1_3_psk_server_test)
  set(tls_1_3_psk_server_test_file_list
      ${SOURCE_DIR}/tls_ecc_negotiation_test.c
      ${SOURCE_DIR}/tls_1_3_psk_test_openssl_echo_client_entry.c
      ${SOURCE_DIR}/tls_1_3_psk_test_nx_secure_echo_server_entry.c)

  list(APPEND nx_secure_test_cases tls_1_3_psk_hello_retry_server_test)
  set(tls_1_3_psk_hello_retry_server_test_file_list
      ${SOURCE_DIR}/tls_ecc_negotiation_test.c
      ${SOURCE_DIR}/tls_1_3_psk_hello_retry_test_openssl_echo_client_entry.c
      ${SOURCE_DIR}/tls_1_3_psk_test_nx_secure_echo_server_entry.c)
endif()

set(test_utility_files
    ${SOURCE_DIR}/netxtestcontrol.c
    ${SOURCE_DIR}/nx_crypto_ciphersuites_regression.c
    ${SOURCE_DIR}/nx_ram_network_driver_test_1500.c
    ${SOURCE_DIR}/nx_secure_fips_test_utility.c)

get_filename_component(
  UTILITY_SOURCE_DIR
  ${CMAKE_CURRENT_LIST_DIR}/../../../regression/interoperability_test/test_frame
  ABSOLUTE)
set(test_utility_files
  ${UTILITY_SOURCE_DIR}/tls_test_get_external_test_process_output.c
  ${UTILITY_SOURCE_DIR}/tls_test_launch_external_test_process.c
  ${UTILITY_SOURCE_DIR}/tls_test_launch_external_test_process_in_background.c
  ${UTILITY_SOURCE_DIR}/tls_test_director_clean_all.c
  ${UTILITY_SOURCE_DIR}/tls_test_director_cleanup_registered_instances.c
  ${UTILITY_SOURCE_DIR}/tls_test_director_create.c
  ${UTILITY_SOURCE_DIR}/tls_test_director_destroy.c
  ${UTILITY_SOURCE_DIR}/tls_test_director_register_test_instance.c
  ${UTILITY_SOURCE_DIR}/tls_test_director_test_start.c
  ${UTILITY_SOURCE_DIR}/tls_test_instance_attributes_access.c
  ${UTILITY_SOURCE_DIR}/tls_test_instance_append.c
  ${UTILITY_SOURCE_DIR}/tls_test_instance_create.c
  ${UTILITY_SOURCE_DIR}/tls_test_instance_destroy.c
  ${UTILITY_SOURCE_DIR}/tls_test_instance_find_next.c
  ${UTILITY_SOURCE_DIR}/tls_test_instance_set_exit_status.c
  ${UTILITY_SOURCE_DIR}/tls_test_instance_shared_buffer_manipulate.c
  ${UTILITY_SOURCE_DIR}/tls_test_kill_external_test_process.c
  ${UTILITY_SOURCE_DIR}/tls_test_semaphore_create.c
  ${UTILITY_SOURCE_DIR}/tls_test_semaphore_destroy.c
  ${UTILITY_SOURCE_DIR}/tls_test_semaphore_post.c
  ${UTILITY_SOURCE_DIR}/tls_test_semaphore_wait.c
  ${UTILITY_SOURCE_DIR}/tls_test_wait_all_child_process.c
  ${UTILITY_SOURCE_DIR}/tls_test_wait_external_test_process.c
  ${UTILITY_SOURCE_DIR}/tls_test_uninterruptable_wait.c)

if("s${CMAKE_BUILD_TYPE}" STREQUAL "shash_clone_build")
list(APPEND test_utility_files
  ${CMAKE_CURRENT_LIST_DIR}/../../../regression/nx_secure_test/hash_clone/nx_crypto_clone_cleanup_test.c
  ${CMAKE_CURRENT_LIST_DIR}/../../../regression/nx_secure_test/hash_clone/nx_crypto_hash_clone_test.c
  ${CMAKE_CURRENT_LIST_DIR}/../../../regression/nx_secure_test/hash_clone/nx_crypto_ciphersuites_hc.c)
endif()

add_library(test_utility ${test_utility_files})
target_link_libraries(test_utility PUBLIC azrtos::netxduo)
target_include_directories(test_utility PUBLIC ${UTILITY_SOURCE_DIR})
target_compile_definitions(test_utility PUBLIC BATCH_TEST CTEST)

include(network_config.cmake)

set(PCAP_SOURCE
  ${CMAKE_CURRENT_LIST_DIR}/../../../regression/interoperability_test/nx_pcap_network_driver.c
)
foreach(test_case ${nx_secure_test_cases})
  add_executable(${test_case} ${${test_case}_file_list} ${PCAP_SOURCE})
  network_config(${test_case})
  target_link_libraries(${test_case} PRIVATE test_utility pcap)
  add_test(
    NAME ${CMAKE_BUILD_TYPE}::${test_case}
    COMMAND
      bash -c
      "export PATH=${SOURCE_DIR}/test_scripts/:$PATH;
       ip link del ${${test_case}_interface}>/dev/null 2>&1;
       ip link add ${${test_case}_interface} type veth peer name ${${test_case}_remote_interface} || exit 1;
       ifconfig ${${test_case}_interface} up || { ip link del ${${test_case}_interface}; exit 1; };
       ifconfig ${${test_case}_remote_interface} ${${test_case}_remote_ip} up netmask ${TEST_NETMASK} || { ip link del ${${test_case}_interface};exit 1; };
       ethtool --offload ${${test_case}_remote_interface} tx off || { ip link del ${${test_case}_interface}; exit 1; };
       tcpdump -i ${${test_case}_remote_interface} -s 0 -w ${CMAKE_CURRENT_BINARY_DIR}/${test_case}.pcap&
       pid=$!
       ${CMAKE_CURRENT_BINARY_DIR}/${test_case};
       exit_code=$?
       sleep 1;
       kill -TERM $pid
       [[ $exit_code = 0 ]] || [[ $exit_code = 233 ]] || { echo Exit code: $exit_code; exit $exit_code; };"
    WORKING_DIRECTORY ${SOURCE_DIR})
endforeach()
