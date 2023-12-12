# Enable testing
enable_testing()

set(SDK_FOLDER "${PROJECT_SOURCE_DIR}/../../../addons/azure_iot")
set(SDK_CERT_SAMPLE_FOLDER "${SDK_FOLDER}/samples/cert")
set(AZURE_EMBEDDED_SDK_TESTS_FOLDER "${PROJECT_SOURCE_DIR}/../../regression/azure_iot")

include_directories("${SDK_CERT_SAMPLE_FOLDER}/")
aux_source_directory(${SDK_CERT_SAMPLE_FOLDER}/ CERT_SAMPLE_SRC)

set(unit_tests
    initialization_unit_test
    connection_unit_test
    connection_non_block_ram_test
    connection_sas_expiry_ram_test
    d2c_unit_test
    c2d_property_unit_test
    c2d_unit_test
    iot_provisioning_client_unit_test
    nx_azure_iot_unit_test
    direct_method_unit_test
    device_twin_unit_test
    device_cert_unit_test
    trusted_cert_unit_test
    user_agent_string_unit_test
    api_unit_test
    nx_azure_iot_json_writer_unit_test
    nx_azure_iot_json_reader_unit_test
    nx_azure_iot_pnp_client_telemetry_unit_test
    nx_azure_iot_pnp_client_command_unit_test
    nx_azure_iot_pnp_client_properties_unit_test
    nx_azure_iot_adu_agent_unit_test)

# Unit test cases
if(UNIX)
  add_executable(
    initialization_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/initialization_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(initialization_unit_test initialization_unit_test)

  target_link_libraries(
    initialization_unit_test
    PUBLIC netxduo -Wl,-wrap,_nxde_mqtt_client_receive_notify_set
           -Wl,-wrap,_nxde_mqtt_client_delete)

  add_executable(
    connection_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/connection_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(connection_unit_test connection_unit_test)

  target_link_libraries(
    connection_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)

  add_executable(
    connection_non_block_ram_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/connection_non_block_ram_test.c
    ${CERT_SAMPLE_SRC})
  add_test(connection_non_block_ram_test connection_non_block_ram_test)

  target_link_libraries(
    connection_non_block_ram_test PUBLIC netxduo
                                         -Wl,-wrap,_nxde_dns_host_by_name_get)

  add_executable(
    connection_sas_expiry_ram_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/connection_sas_expiry_ram_test.c
    ${CERT_SAMPLE_SRC})
  add_test(connection_sas_expiry_ram_test connection_sas_expiry_ram_test)

  target_link_libraries(
    connection_sas_expiry_ram_test PUBLIC netxduo
                                          -Wl,-wrap,_nxde_dns_host_by_name_get)

  add_executable(
    d2c_unit_test ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/d2c_unit_test.c
                  ${CERT_SAMPLE_SRC})
  add_test(d2c_unit_test d2c_unit_test)

  target_link_libraries(
    d2c_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxd_mqtt_client_publish_packet_send
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)

  # This test case should be able to run in Windows. But cmocka.h can not be
  # found. Disable Windows build for now.
  add_executable(
    c2d_property_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/c2d_property_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(c2d_property_unit_test c2d_property_unit_test)

  add_executable(
    c2d_unit_test ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/c2d_unit_test.c
                  ${CERT_SAMPLE_SRC})
  add_test(c2d_unit_test c2d_unit_test)

  target_link_libraries(
    c2d_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_receive_notify_set
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_subscribe
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,_nxde_mqtt_client_unsubscribe
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)

  add_executable(
    iot_provisioning_client_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/iot_provisioning_client_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(iot_provisioning_client_unit_test iot_provisioning_client_unit_test)

  target_link_libraries(
    iot_provisioning_client_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_subscribe
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,_nxde_mqtt_client_receive_notify_set
           -Wl,-wrap,_nxd_mqtt_client_publish_packet_send
           -Wl,-wrap,nx_azure_iot_buffer_allocate
           -Wl,-wrap,_nx_packet_data_append
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)

  add_executable(
    nx_azure_iot_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/nx_azure_iot_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(nx_azure_iot_unit_test nx_azure_iot_unit_test)

  add_executable(
    direct_method_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/direct_method_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(direct_method_unit_test direct_method_unit_test)

  target_link_libraries(
    direct_method_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxde_mqtt_client_subscribe
           -Wl,-wrap,_nxde_mqtt_client_unsubscribe
           -Wl,-wrap,_nxd_mqtt_client_publish_packet_send
           -Wl,-wrap,_nxde_mqtt_client_receive_notify_set
           -Wl,-wrap,nx_azure_iot_buffer_allocate
           -Wl,-wrap,_nx_packet_data_append
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)

  add_executable(
    device_twin_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/device_twin_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(device_twin_unit_test device_twin_unit_test)

  target_link_libraries(
    device_twin_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxde_mqtt_client_subscribe
           -Wl,-wrap,_nxde_mqtt_client_unsubscribe
           -Wl,-wrap,_nxd_mqtt_client_publish_packet_send
           -Wl,-wrap,_nxde_mqtt_client_receive_notify_set
           -Wl,-wrap,nx_azure_iot_buffer_allocate
           -Wl,-wrap,_nx_packet_data_append
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)

  add_executable(
    device_cert_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/device_cert_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(device_cert_unit_test device_cert_unit_test)

  target_link_libraries(
    device_cert_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_login_set
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)

  add_executable(
    trusted_cert_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/trusted_cert_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(trusted_cert_unit_test trusted_cert_unit_test)

  add_executable(
    user_agent_string_unit_test 
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/user_agent_string_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(user_agent_string_unit_test user_agent_string_unit_test)

  target_link_libraries(
    user_agent_string_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxd_mqtt_client_publish_packet_send
           -Wl,-wrap,_nxe_ip_driver_interface_direct_command
           -Wl,-wrap,nx_azure_iot_security_module_disable
           -Wl,-wrap,nx_azure_iot_security_module_enable)

  add_executable(
    nx_azure_iot_json_writer_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/nx_azure_iot_json_writer_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(nx_azure_iot_json_writer_unit_test nx_azure_iot_json_writer_unit_test)

  add_executable(
    nx_azure_iot_json_reader_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/nx_azure_iot_json_reader_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(nx_azure_iot_json_reader_unit_test nx_azure_iot_json_reader_unit_test)

  add_executable(
    nx_azure_iot_pnp_client_telemetry_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/nx_azure_iot_pnp_client_telemetry_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(nx_azure_iot_pnp_client_telemetry_unit_test nx_azure_iot_pnp_client_telemetry_unit_test)

  target_link_libraries(
    nx_azure_iot_pnp_client_telemetry_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nx_tcp_socket_send
           -Wl,-wrap,nx_azure_iot_buffer_allocate
           -Wl,-wrap,_nx_packet_data_append
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)

  add_executable(
    nx_azure_iot_pnp_client_command_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/nx_azure_iot_pnp_client_command_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(nx_azure_iot_pnp_client_command_unit_test nx_azure_iot_pnp_client_command_unit_test)

  target_link_libraries(
    nx_azure_iot_pnp_client_command_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxde_mqtt_client_subscribe
           -Wl,-wrap,_nxd_mqtt_client_publish_packet_send
           -Wl,-wrap,_nxde_mqtt_client_receive_notify_set
           -Wl,-wrap,nx_azure_iot_buffer_allocate
           -Wl,-wrap,_nx_packet_data_append
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)

  add_executable(
    nx_azure_iot_pnp_client_properties_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/nx_azure_iot_pnp_client_properties_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(nx_azure_iot_pnp_client_properties_unit_test nx_azure_iot_pnp_client_properties_unit_test)

  target_link_libraries(
    nx_azure_iot_pnp_client_properties_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxde_mqtt_client_subscribe
           -Wl,-wrap,_nxd_mqtt_client_publish_packet_send
           -Wl,-wrap,_nxde_mqtt_client_receive_notify_set
           -Wl,-wrap,nx_azure_iot_buffer_allocate
           -Wl,-wrap,_nx_packet_data_append
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable)
           
  add_executable(
    api_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/api_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(api_unit_test api_unit_test)

  target_link_libraries(
    api_unit_test
    PUBLIC netxduo
           -Wl,-wrap,nx_azure_iot_publish_packet_get
           -Wl,-wrap,az_iot_hub_client_properties_builder_begin_component
           -Wl,-wrap,az_iot_hub_client_properties_builder_end_component
           -Wl,-wrap,az_iot_hub_client_properties_builder_begin_response_status
           -Wl,-wrap,az_iot_hub_client_properties_builder_end_response_status)

  add_executable(
    nx_azure_iot_adu_agent_unit_test
    ${AZURE_EMBEDDED_SDK_TESTS_FOLDER}/nx_azure_iot_adu_agent_unit_test.c
    ${CERT_SAMPLE_SRC})
  add_test(nx_azure_iot_adu_agent_unit_test nx_azure_iot_adu_agent_unit_test)

  target_link_libraries(
    nx_azure_iot_adu_agent_unit_test
    PUBLIC netxduo
           -Wl,-wrap,_nxde_mqtt_client_secure_connect
           -Wl,-wrap,_nxde_mqtt_client_disconnect
           -Wl,-wrap,_nxde_dns_host_by_name_get
           -Wl,-wrap,_nxde_mqtt_client_subscribe
           -Wl,-wrap,_nxd_mqtt_client_publish_packet_send
           -Wl,-wrap,_nxde_mqtt_client_receive_notify_set
           -Wl,-wrap,nx_azure_iot_buffer_allocate
           -Wl,-wrap,_nx_packet_data_append
           -Wl,-wrap,nx_azure_iot_security_module_enable
           -Wl,-wrap,nx_azure_iot_security_module_disable
           -Wl,-wrap,_nxe_web_http_client_connect
           -Wl,-wrap,_nxe_web_http_client_request_send
           -Wl,-wrap,_nxe_web_http_client_response_body_get)
endif()

# Link cmocka
foreach(test ${unit_tests})
  target_link_libraries(${test} PUBLIC cmocka netxduo)
endforeach()

# Disable idle for unit test.
foreach(test ${unit_tests})
  get_target_property(sources ${test} SOURCES)
  set_property(
    TARGET ${test}
    PROPERTY SOURCES ${sources}
             ${TX_FOLDER}/ports/linux/gnu/src/tx_initialize_low_level.c
             ${TX_FOLDER}/ports/linux/gnu/src/tx_thread_schedule.c)
  target_compile_options(${test} PUBLIC -DTX_LINUX_NO_IDLE_ENABLE)
endforeach()
