/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>  /* macros: https://api.cmocka.org/group__cmocka__asserts.html */

#include "nx_api.h"
#include "nx_azure_iot_hub_client.h"
#include "nx_azure_iot_hub_client_properties.h"
#include "nx_azure_iot_cert.h"
#include "nx_azure_iot_ciphersuites.h"


#define DEMO_DHCP_DISABLE
#define DEMO_IPV4_ADDRESS         IP_ADDRESS(192, 168, 100, 33)
#define DEMO_IPV4_MASK            0xFFFFFF00UL
#define DEMO_GATEWAY_ADDRESS      IP_ADDRESS(192, 168, 100, 1)
#define DEMO_DNS_SERVER_ADDRESS   IP_ADDRESS(192, 168, 100, 1)
#define NETWORK_DRIVER            _nx_ram_network_driver

/* Include main.c in the test case since we need to disable DHCP in this test. */
#include "main.c"


#define STRING_UNSIGNED_ARGS(s) (UCHAR *)s, strlen(s)

#ifndef DEMO_CLOUD_STACK_SIZE
#define DEMO_CLOUD_STACK_SIZE   2048
#endif /* DEMO_CLOUD_STACK_SIZE */

#ifndef DEMO_CLOUD_THREAD_PRIORITY
#define DEMO_CLOUD_THREAD_PRIORITY  (4)
#endif /* DEMO_CLOUD_THREAD_PRIORITY */

static UINT api_no_model_id_test();
static VOID api_model_id_test();

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iot_client;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];

NX_SECURE_X509_CERT device_certificate;
NX_PACKET *packet_ptr;
UCHAR *property_name = "propertyA";
USHORT property_name_length = sizeof("propertyA") - 1;
UCHAR *property_value;
USHORT property_value_lenght;
UCHAR *name;
USHORT name_length;
UCHAR *context_ptr;
USHORT context_length;
UCHAR *component_name;
USHORT component_name_length;
UCHAR message_buffer[1024];
UINT message_length = 1024;
UINT request_id;
UINT response_status;
ULONG version;
NX_AZURE_IOT_JSON_WRITER json_writer;
NX_AZURE_IOT_JSON_READER json_reader;
UCHAR json_buffer[2014];

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{

    /* Initialize root certificate.  */
    assert_int_equal(nx_secure_x509_certificate_initialize(&root_ca_cert, (UCHAR *)_nx_azure_iot_root_cert, (USHORT)_nx_azure_iot_root_cert_size,
                                                           NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                         sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                     NX_AZURE_IOT_SUCCESS);

    /* Perform actual tests. */
    api_no_model_id_test();
    api_model_id_test();    
}

static VOID connection_status_callback(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, UINT status)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);
    NX_PARAMETER_NOT_USED(status);
}

static VOID message_receive_callback_properties(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *context)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);
    NX_PARAMETER_NOT_USED(context);
}

static VOID reported_properties_response_callback(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, UINT request_id,
                                                  UINT response_status, ULONG version, VOID *args)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);
    NX_PARAMETER_NOT_USED(request_id);
    NX_PARAMETER_NOT_USED(response_status);
    NX_PARAMETER_NOT_USED(version);
    NX_PARAMETER_NOT_USED(args);
}

static UINT api_no_model_id_test()
{

    /* Using IoT Hub APIs if nx_azure_iot_hub_client_model_id_set is not called after initialization.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                        STRING_UNSIGNED_ARGS("host_name"),
                                                        STRING_UNSIGNED_ARGS("device_id"),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_device_cert_set(&iot_client, &device_certificate),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_symmetric_key_set(&iot_client, "symmetric_key", sizeof("symmetric_key") - 1),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_component_add(&iot_client, "componentA", sizeof("componentA") - 1),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_connection_status_callback_set(&iot_client, connection_status_callback),
                         NX_AZURE_IOT_NOT_SUPPORTED);
                         
    assert_int_not_equal(nx_azure_iot_hub_client_receive_callback_set(&iot_client, NX_AZURE_IOT_HUB_PROPERTIES, 
                                                                      message_receive_callback_properties, NX_NULL),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_disconnect(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* C2D APIs.  */    
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_property_get(&iot_client, packet_ptr,
                                                                            property_name, property_name_length,
                                                                            (const UCHAR **)&property_value, &property_value_lenght),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Telemetry APIs.  */             
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);
                         
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_component_set(packet_ptr, 
                                                                        "componentA", sizeof("componentA") - 1,
                                                                         NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);
                         
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr, 
                                                                        "propertyA", sizeof("propertyA") - 1,
                                                                        "valueA", sizeof("valueA") - 1,
                                                                        NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_send(&iot_client, packet_ptr, 
                                                                "data", sizeof("data") - 1,
                                                                NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);
                         
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Direct Method APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_message_receive(&iot_client, 
                                                                               (const UCHAR **)&name, (USHORT *)&name_length,
                                                                               (void **)&context_ptr, &context_length,
                                                                               &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_message_response(&iot_client, 200,
                                                                                "12222", sizeof("12222") - 1,
                                                                                "payload", sizeof("payload") - 1,
                                                                                NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Command APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_command_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_command_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_command_message_receive(&iot_client, 
                                                                         (const UCHAR **)&component_name, &component_name_length,
                                                                         (const UCHAR **)&name, &name_length,
                                                                         (void **)&context_ptr, &context_length,
                                                                         &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_command_message_response(&iot_client, 200,
                                                                          "12222", sizeof("12222") - 1,
                                                                          "payload", sizeof("payload") - 1,
                                                                          NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Device twin APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_response_callback_set(&iot_client,
                                                                                           reported_properties_response_callback, 
                                                                                           NX_NULL),
                        NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_reported_properties_send(&iot_client, 
                                                                                      message_buffer, message_length,
                                                                                      &request_id, &response_status,
                                                                                      &version, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_properties_request(&iot_client, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_properties_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_desired_properties_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Properties APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_properties_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_response_callback_set(&iot_client,
                                                                                           reported_properties_response_callback, 
                                                                                           NX_NULL),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_create(&iot_client, 
                                                                            &packet_ptr, 
                                                                            NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_equal(nx_azure_iot_json_writer_with_buffer_init(&json_writer, json_buffer, sizeof(json_buffer)),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_json_writer_append_begin_object(&json_writer),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_component_begin(&iot_client, 
                                                                                     &json_writer,
                                                                                     "componentA",
                                                                                     sizeof("componentA") - 1),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_component_end(&iot_client, &json_writer),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_status_begin(&iot_client, &json_writer,
                                                                                  "property_name", sizeof("property_name") - 1,
                                                                                  200, 20,
                                                                                  NX_NULL, 0),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_equal(nx_azure_iot_json_writer_append_int32(&json_writer, 20),
                     NX_AZURE_IOT_SUCCESS);


    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_status_end(&iot_client, &json_writer),
                         NX_AZURE_IOT_NOT_SUPPORTED);
                     
    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_send(&iot_client, 
                                                                          packet_ptr,
                                                                          &request_id, &response_status,
                                                                          &version, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_request(&iot_client, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_receive(&iot_client,
                                                                    &packet_ptr,
                                                                    NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_writable_properties_receive(&iot_client,
                                                                             &packet_ptr,
                                                                             NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_component_property_next_get(&iot_client,
                                                                                        &json_reader,
                                                                                        NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                                        NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                                        (const UCHAR **)&component_name,
                                                                                         &component_name_length),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Deinitialize.  */
    assert_int_not_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);
}

static VOID api_model_id_test()
{

    /* Using PnP APIs if nx_azure_iot_hub_client_model_id_set is called after initialization.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                        STRING_UNSIGNED_ARGS("host_name"),
                                                        STRING_UNSIGNED_ARGS("device_id"),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&iot_client, 
                                                          "pnp_model_id_unit_test",
                                                          sizeof("pnp_model_id_unit_test") - 1),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_device_cert_set(&iot_client, &device_certificate),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_symmetric_key_set(&iot_client, "symmetric_key", sizeof("symmetric_key") - 1),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_component_add(&iot_client, "componentA", sizeof("componentA") - 1),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_connection_status_callback_set(&iot_client, connection_status_callback),
                         NX_AZURE_IOT_NOT_SUPPORTED);
                         
    assert_int_not_equal(nx_azure_iot_hub_client_receive_callback_set(&iot_client, NX_AZURE_IOT_HUB_PROPERTIES, 
                                                                      message_receive_callback_properties, NX_NULL),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_disconnect(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* C2D APIs.  */    
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_property_get(&iot_client, packet_ptr,
                                                                            property_name, property_name_length,
                                                                            (const UCHAR **)&property_value, &property_value_lenght),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Telemetry APIs.  */             
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_component_set(packet_ptr, 
                                                                        "componentA", sizeof("componentA") - 1,
                                                                         NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);
                         
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr, 
                                                                        "propertyA", sizeof("propertyA") - 1,
                                                                        "valueA", sizeof("valueA") - 1,
                                                                        NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_send(&iot_client, packet_ptr, 
                                                                "data", sizeof("data") - 1,
                                                                NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);
                         
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Direct Method APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_message_receive(&iot_client, 
                                                                               (const UCHAR **)&name, (USHORT *)&name_length,
                                                                               (void **)&context_ptr, &context_length,
                                                                               &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_message_response(&iot_client, 200,
                                                                                "12222", sizeof("12222") - 1,
                                                                                "payload", sizeof("payload") - 1,
                                                                                NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Command APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_command_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_command_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_command_message_receive(&iot_client, 
                                                                         (const UCHAR **)&component_name, &component_name_length,
                                                                         (const UCHAR **)&name, &name_length,
                                                                         (void **)&context_ptr, &context_length,
                                                                         &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_command_message_response(&iot_client, 200,
                                                                          "12222", sizeof("12222") - 1,
                                                                          "payload", sizeof("payload") - 1,
                                                                          NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Device twin APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_response_callback_set(&iot_client,
                                                                                           reported_properties_response_callback, 
                                                                                           NX_NULL),
                        NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_reported_properties_send(&iot_client, 
                                                                                      message_buffer, message_length,
                                                                                      &request_id, &response_status,
                                                                                      &version, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_properties_request(&iot_client, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_properties_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_device_twin_desired_properties_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Properties APIs.  */
    assert_int_not_equal(nx_azure_iot_hub_client_properties_enable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_disable(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_response_callback_set(&iot_client,
                                                                                           reported_properties_response_callback, 
                                                                                           NX_NULL),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_create(&iot_client, 
                                                                            &packet_ptr, 
                                                                            NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_equal(nx_azure_iot_json_writer_with_buffer_init(&json_writer, json_buffer, sizeof(json_buffer)),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_json_writer_append_begin_object(&json_writer),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_component_begin(&iot_client, 
                                                                                     &json_writer,
                                                                                     "componentA",
                                                                                     sizeof("componentA") - 1),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_component_end(&iot_client, &json_writer),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_status_begin(&iot_client, &json_writer,
                                                                                  "property_name", sizeof("property_name") - 1,
                                                                                  200, 20,
                                                                                  NX_NULL, 0),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_equal(nx_azure_iot_json_writer_append_int32(&json_writer, 20),
                     NX_AZURE_IOT_SUCCESS);


    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_status_end(&iot_client, &json_writer),
                         NX_AZURE_IOT_NOT_SUPPORTED);
                     
    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_send(&iot_client, 
                                                                          packet_ptr,
                                                                          &request_id, &response_status,
                                                                          &version, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_request(&iot_client, NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_receive(&iot_client,
                                                                    &packet_ptr,
                                                                    NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_writable_properties_receive(&iot_client,
                                                                             &packet_ptr,
                                                                             NX_NO_WAIT),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_component_property_next_get(&iot_client,
                                                                                        &json_reader,
                                                                                        NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                                        NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                                        (const UCHAR **)&component_name,
                                                                                         &component_name_length),
                         NX_AZURE_IOT_NOT_SUPPORTED);

    /* Deinitialize.  */
    assert_int_not_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                         NX_AZURE_IOT_NOT_SUPPORTED);
}

UINT __wrap_nx_azure_iot_publish_packet_get(NX_AZURE_IOT *nx_azure_iot_ptr, NXD_MQTT_CLIENT *client_ptr,
                                            NX_PACKET **packet_pptr, UINT wait_option)
{
    return(NX_AZURE_IOT_FAILURE);
}

UINT __wrap_az_iot_hub_client_properties_builder_begin_component(az_iot_hub_client const* client,
                                                                 az_json_writer* ref_json_writer,
                                                                 az_span component_name)
{
    return(NX_AZURE_IOT_FAILURE);
}

UINT __wrap_az_iot_hub_client_properties_builder_end_component(az_iot_hub_client const* client,
                                                               az_json_writer* ref_json_writer)
{
    return(NX_AZURE_IOT_FAILURE);
}

UINT __wrap_az_iot_hub_client_properties_builder_begin_response_status(az_iot_hub_client const* client,
                                                                       az_json_writer* ref_json_writer,
                                                                       az_span property_name,
                                                                       int32_t ack_code,
                                                                       int32_t ack_version,
                                                                       az_span ack_description)
{
    return(NX_AZURE_IOT_FAILURE);
}

UINT __wrap_az_iot_hub_client_properties_builder_end_response_status(az_iot_hub_client const* client,
                                                                     az_json_writer* ref_json_writer)
{
    return(NX_AZURE_IOT_FAILURE);
}
