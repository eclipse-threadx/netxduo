cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
cmake_policy(SET CMP0057 NEW)

project(regression_test LANGUAGES C)

get_filename_component(
  SOURCE_DIR
  ${CMAKE_CURRENT_LIST_DIR}/../../../regression/interoperability_test/mqtt_test
  ABSOLUTE)

if(NOT "-DNXD_MQTT_REQUIRE_TLS" IN_LIST ${CMAKE_BUILD_TYPE})
  list(APPEND mqtt_test_cases mqtt_subscriber_test)
  set(mqtt_subscriber_test_file_list
      ${SOURCE_DIR}/linux_mqtt_subscriber_test_entry.c
      ${SOURCE_DIR}/linux_mqtt_subscriber_test_server.c
      ${SOURCE_DIR}/linux_mqtt_subscriber_test_publisher.c
      ${SOURCE_DIR}/netx_mqtt_subscriber_test.c)
  list(APPEND mqtt_test_cases mqtt_subscriber_empty_message_test)
  set(mqtt_subscriber_empty_message_test_file_list
      ${SOURCE_DIR}/linux_mqtt_subscriber_test_entry.c
      ${SOURCE_DIR}/linux_mqtt_subscriber_test_server.c
      ${SOURCE_DIR}/linux_mqtt_subscriber_empty_message_test_publisher.c
      ${SOURCE_DIR}/netx_mqtt_subscriber_empty_message_test.c)
endif()

if("-DNX_SECURE_ENABLE" IN_LIST ${CMAKE_BUILD_TYPE})
  list(APPEND mqtt_test_cases mqtt_tls_subscriber_twice_test)
  set(mqtt_tls_subscriber_twice_test_file_list
      ${SOURCE_DIR}/linux_mqtt_tls_subscriber_test_entry.c
      ${SOURCE_DIR}/linux_mqtt_tls_subscriber_test_server.c
      ${SOURCE_DIR}/linux_mqtt_tls_subscriber_twice_test_publisher.c
      ${SOURCE_DIR}/netx_mqtt_tls_subscriber_twice_test.c)

  list(APPEND mqtt_test_cases mqtt_double_subscribers_test)
  set(mqtt_double_subscribers_test_file_list
      ${SOURCE_DIR}/linux_mqtt_tls_subscriber_test_entry.c
      ${SOURCE_DIR}/linux_mqtt_tls_subscriber_test_server.c
      ${SOURCE_DIR}/linux_mqtt_tls_subscriber_test_publisher.c
      ${SOURCE_DIR}/netx_mqtt_double_subscribers_test.c)

  list(APPEND mqtt_test_cases mqtt_tls_subscriber_test)
  set(mqtt_tls_subscriber_test_file_list
      ${SOURCE_DIR}/linux_mqtt_tls_subscriber_test_entry.c
      ${SOURCE_DIR}/linux_mqtt_tls_subscriber_test_server.c
      ${SOURCE_DIR}/linux_mqtt_tls_subscriber_test_publisher.c
      ${SOURCE_DIR}/netx_mqtt_tls_subscriber_test.c)

  list(APPEND debug_secure_build_mqtt_test_cases mqtt_tls_debug_test)
  set(mqtt_tls_debug_test_file_list
      ${SOURCE_DIR}/netx_mqtt_tls_subscriber_test.c)
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
add_library(
  test_utility
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
target_link_libraries(test_utility PUBLIC azrtos::netxduo)
target_include_directories(test_utility PUBLIC ${UTILITY_SOURCE_DIR})

include(network_config.cmake)

set(PCAP_SOURCE
  ${CMAKE_CURRENT_LIST_DIR}/../../../regression/interoperability_test/nx_pcap_network_driver.c
)
foreach(test_case ${mqtt_test_cases})
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
       ip link del ${${test_case}_interface} || exit 1;
       [[ $exit_code = 0 ]] || [[ $exit_code = 233 ]] || { echo Exit code: $exit_code; exit $exit_code; };"
    WORKING_DIRECTORY ${SOURCE_DIR})
endforeach()
