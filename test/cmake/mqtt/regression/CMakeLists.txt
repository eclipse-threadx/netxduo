cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
cmake_policy(SET CMP0057 NEW)

project(regression_test LANGUAGES C)

get_filename_component(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../regression
                       ABSOLUTE)

set(mqtt_test_cases
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_api_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_auth_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_auth_empty_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_packet_send_failure_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_v6_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_non_block_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_non_block_2_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_null_password_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_publish_qos0_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_publish_qos1_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_receive_qos0_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_receive_qos1_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_subscribe_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_unsubscribe_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_will_message_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_will_topic_only_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_not_connected_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connect_with_auth_will_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_keepalive_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_keepalive_timeout_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_multiple_receive_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_remaining_length_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_publish_non_zero_packet_id_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_subscribe_non_zero_packet_id_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_packet_leak_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_receive_span_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_publish_packet_chain_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_subscribe_packet_chain_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_connack_error_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_branch_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_transmit_queue_depth_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_websocket_non_block_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_websocket_block_test.c)

set(test_utility_files
    ${SOURCE_DIR}/test/nx_ram_network_driver_test_1500.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_testcontrol.c)

add_library(test_utility ${test_utility_files})
target_link_libraries(test_utility PUBLIC azrtos::netxduo)
target_include_directories(test_utility PUBLIC ${SOURCE_DIR}/test)
target_compile_definitions(test_utility PUBLIC BATCH_TEST CTEST)

foreach(
  test_case
  ${mqtt_test_cases})
  get_filename_component(test_name ${test_case} NAME_WE)
  add_executable(${test_name} ${test_case})
  target_link_libraries(${test_name} PRIVATE test_utility)
  add_test(${CMAKE_BUILD_TYPE}::${test_name} ${test_name})
endforeach()
