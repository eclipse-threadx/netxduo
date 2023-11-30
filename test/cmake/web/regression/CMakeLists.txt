cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
cmake_policy(SET CMP0057 NEW)

project(regression_test LANGUAGES C)

get_filename_component(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../regression
                       ABSOLUTE)

set(web_test_cases
    ${SOURCE_DIR}/web_test/netx_https_api_test.c
    ${SOURCE_DIR}/web_test/netx_web_basic_test.c
    ${SOURCE_DIR}/web_test/netx_web_basic_ecc_test.c
    ${SOURCE_DIR}/web_test/netx_web_head_basic_test.c
    ${SOURCE_DIR}/web_test/netx_web_post_basic_test.c
    ${SOURCE_DIR}/web_test/netx_web_put_basic_test.c
    ${SOURCE_DIR}/web_test/netx_web_delete_basic_test.c
    ${SOURCE_DIR}/web_test/netx_web_basic_authenticate_test.c
    ${SOURCE_DIR}/web_test/netx_web_if_modified_since_test.c
    ${SOURCE_DIR}/web_test/netx_web_get_content_length_test.c
    ${SOURCE_DIR}/web_test/netx_web_request_in_multiple_packets_test.c
    ${SOURCE_DIR}/web_test/netx_web_multipart_fragment_test.c
    ${SOURCE_DIR}/web_test/netx_web_multipart_underflow_test.c
    ${SOURCE_DIR}/web_test/netx_web_get_put_referred_URI_test.c
    ${SOURCE_DIR}/web_test/netx_web_status_404_test.c
    ${SOURCE_DIR}/web_test/netx_web_multiple_sessions_test.c
    ${SOURCE_DIR}/web_test/netx_web_multiple_sessions_timeout_test.c
    ${SOURCE_DIR}/web_test/netx_web_response_in_multiple_packets_test.c
    ${SOURCE_DIR}/web_test/netx_web_connect_three_times_test.c
    ${SOURCE_DIR}/web_test/netx_web_keep_alive_test.c
    ${SOURCE_DIR}/web_test/netx_web_digest_authenticate_test.c
    ${SOURCE_DIR}/web_test/netx_web_digest_authenticate_test2.c
    ${SOURCE_DIR}/web_test/netx_web_server_content_process_test.c
    ${SOURCE_DIR}/web_test/netx_web_concurrent_sessions_test.c
    ${SOURCE_DIR}/web_test/netx_web_post_long_message_test.c
    ${SOURCE_DIR}/web_test/netx_web_host_field_test.c
    ${SOURCE_DIR}/web_test/netx_web_chunked_request_test.c
    ${SOURCE_DIR}/web_test/netx_web_chunked_request_additional_test.c
    ${SOURCE_DIR}/web_test/netx_web_chunked_response_test.c
    ${SOURCE_DIR}/web_test/netx_web_chunked_response_process_test.c
    ${SOURCE_DIR}/web_test/netx_web_chunked_response_packet_chain_test.c
    ${SOURCE_DIR}/web_test/netx_web_client_cleanup_test.c
    ${SOURCE_DIR}/web_test/netx_web_server_chunked_content_process_test.c
    ${SOURCE_DIR}/web_test/netx_web_packet_allocate_test.c
    ${SOURCE_DIR}/web_test/netx_web_status_code_test.c
    ${SOURCE_DIR}/web_test/netx_web_secure_connect_fail_test.c
    ${SOURCE_DIR}/web_test/netx_web_tcpserver_rst_test.c
    ${SOURCE_DIR}/web_test/netx_web_tcpserver_two_listen_test.c
    ${SOURCE_DIR}/web_test/netx_web_abnormal_test.c
    ${SOURCE_DIR}/web_test/netx_web_client_send_fail_test.c
    ${SOURCE_DIR}/web_test/netx_web_client_receive_no_packet_test.c
    ${SOURCE_DIR}/web_test/netx_web_keep_alive_abnormal_test.c
    ${SOURCE_DIR}/web_test/netx_web_one_session_test.c
    ${SOURCE_DIR}/web_test/netx_web_server_type_get_extended_test.c
    ${SOURCE_DIR}/web_test/netx_web_secure_reconnect_test.c
    ${SOURCE_DIR}/web_test/netx_web_non_block_basic_test.c
    ${SOURCE_DIR}/web_test/netx_web_non_block_reconnect_test.c
    ${SOURCE_DIR}/web_test/netx_web_tcpserver_tls_fail_rst_test.c
    ${SOURCE_DIR}/web_test/netx_web_invalid_release_test.c
    ${SOURCE_DIR}/web_test/netx_web_certifiacte_verify_test.c
    ${SOURCE_DIR}/web_test/netx_web_client_rst_test.c
    ${SOURCE_DIR}/web_test/netx_web_basic_authenticate_empty_test.c
    ${SOURCE_DIR}/web_test/netx_web_digest_authenticate_timeout_test.c)

set(test_utility_files
    ${SOURCE_DIR}/test/nx_ram_network_driver_test_1500.c
    ${SOURCE_DIR}/web_test/netx_https_testcontrol.c)

add_library(test_utility ${test_utility_files})
target_link_libraries(test_utility PUBLIC azrtos::netxduo)
target_include_directories(test_utility PUBLIC ${SOURCE_DIR}/test)
target_compile_definitions(test_utility PUBLIC BATCH_TEST CTEST)

foreach(
  test_case
  ${web_test_cases})
  get_filename_component(test_name ${test_case} NAME_WE)
  add_executable(${test_name} ${test_case})
  target_link_libraries(${test_name} PRIVATE test_utility)
  add_test(${CMAKE_BUILD_TYPE}::${test_name} ${test_name})
endforeach()
