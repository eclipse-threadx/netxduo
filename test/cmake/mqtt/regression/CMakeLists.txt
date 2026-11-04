# Portions of this file were generated with AI assistance.
cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0057 NEW)

project(regression_test LANGUAGES C)

get_filename_component(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../regression
                       ABSOLUTE)

set(mqtt_test_cases
    ${SOURCE_DIR}/mqtt_test/netx_mqtt5_codec_test.c
    ${SOURCE_DIR}/uprotocol_test/netx_uprotocol_mqtt_test.c
    ${SOURCE_DIR}/uprotocol_test/netx_uprotocol_codec_test.c
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
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_websocket_block_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_tls_to_plain_reconnect_test.c
    ${SOURCE_DIR}/mqtt_test/netx_mqtt_malformed_publish_test.c)

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

# Optional broker interoperability using existing host test tools; no root or
# virtual Ethernet interface is needed because the RAM broker relays TCP bytes.
option(NXD_UPROTOCOL_BROKER_TESTS "Run uProtocol MQTT 5 tests with Mosquitto" OFF)
if(NXD_UPROTOCOL_BROKER_TESTS AND CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_BUILD_TYPE MATCHES "require_secure")
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    find_program(UPROTOCOL_MOSQUITTO mosquitto)
    if(NOT UPROTOCOL_MOSQUITTO)
        message(FATAL_ERROR "Mosquitto is required for NXD_UPROTOCOL_BROKER_TESTS")
    endif()
    add_test(NAME ${CMAKE_BUILD_TYPE}::netx_uprotocol_mosquitto_test
             COMMAND ${Python3_EXECUTABLE} ${SOURCE_DIR}/uprotocol_test/run_mosquitto.py
                     ${UPROTOCOL_MOSQUITTO} $<TARGET_FILE:netx_uprotocol_mqtt_test>)
endif()

add_library(uprotocol_sample OBJECT ${SOURCE_DIR}/../../samples/demo_uprotocol_mqtt.c)
target_link_libraries(uprotocol_sample PRIVATE azrtos::netxduo)
