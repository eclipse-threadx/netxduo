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

#include "azure/core/az_span.h"
#include "nx_api.h"
#include "nx_azure_iot_hub_client.h"
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

#ifndef DEMO_CLOUD_STACK_SIZE
#define DEMO_CLOUD_STACK_SIZE           2048
#endif /* DEMO_CLOUD_STACK_SIZE */

#ifndef DEMO_CLOUD_THREAD_PRIORITY
#define DEMO_CLOUD_THREAD_PRIORITY      (4)
#endif /* DEMO_CLOUD_THREAD_PRIORITY */

#ifndef MAXIMUM_PAYLOAD_LENGTH
#define MAXIMUM_PAYLOAD_LENGTH          10240
#endif /* MAXIMUM_PAYLOAD_LENGTH */

#define STRING_UNSIGNED_ARGS(s) (UCHAR *)s, sizeof(s) - 1

#define MQTT_CLIENT_GET(c)              ((c) -> nx_azure_iot_hub_client_resource.resource_mqtt)

typedef VOID (*NX_AZURE_TEST_FN)();

static const UCHAR g_hostname[] = "unit-test.iot-azure.com";
static const UCHAR g_device_id[] = "unit_test_device";
static const UCHAR g_pnp_model_id[] = "pnp_model_id_unit_test";
static const UCHAR g_symmetric_key[] = "6CLK6It9jOiABpFVu11CQDv9O49ebAneK3KbsvaoU1o=";
static const UCHAR g_test_component[] = "sample_test";
static const UCHAR g_test_property_name[] = "sample_test_property_name";
static const UCHAR g_test_property_value[] = "sample_test_property_value";
static const UCHAR g_test_telemetry_data[] = "sample_telemetry_test_data";

static UINT g_total_append = 0;
static UINT g_failed_append_index = 0;
static UINT g_total_allocation = 0;
static UINT g_failed_allocation_index = -1;
static UINT g_telemetry_ack_count = 0;
static NX_IP* g_ip_ptr;
static NX_PACKET_POOL* g_pool_ptr;
static NX_DNS* g_dns_ptr;
static ULONG g_available_packet;
static CHAR *g_expected_message;
static UINT g_connect_status;
static VOID (*test_connect_notify)(struct NXD_MQTT_CLIENT_STRUCT *client_ptr, UINT status, VOID *context) = NX_NULL;
static VOID *test_connect_notify_context = NX_NULL;
static VOID (*test_telemetry_ack_notify)(NXD_MQTT_CLIENT *client_ptr, UINT message_count) = NX_NULL;

extern UINT _nxd_mqtt_client_append_message(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, CHAR *message,
                                            UINT length, ULONG wait_option);
extern UINT _nxd_mqtt_client_set_fixed_header(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                              UCHAR control_header, UINT length, UINT wait_option);

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT hub_client;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];
static UCHAR message_payload[MAXIMUM_PAYLOAD_LENGTH];
static UCHAR result_buffer[MAXIMUM_PAYLOAD_LENGTH];

UINT __wrap_nx_azure_iot_security_module_enable(NX_AZURE_IOT *nx_azure_iot_ptr)
{
    printf("HIJACKED: %s\n", __func__);
    return(NX_AZURE_IOT_SUCCESS);
}

UINT __wrap_nx_azure_iot_security_module_disable(NX_AZURE_IOT *nx_azure_iot_ptr)
{
    printf("HIJACKED: %s\n", __func__);
    return(NX_AZURE_IOT_SUCCESS);
}

UINT __real__nx_packet_data_append(NX_PACKET *packet_ptr, VOID *data_start, ULONG data_size,
                                     NX_PACKET_POOL *pool_ptr, ULONG wait_option);
UINT __wrap__nx_packet_data_append(NX_PACKET *packet_ptr, VOID *data_start, ULONG data_size,
                                     NX_PACKET_POOL *pool_ptr, ULONG wait_option)
{
    printf("HIJACKED: %s\n", __func__);

    if (g_failed_append_index == g_total_append)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    g_total_append++;
    return __real__nx_packet_data_append(packet_ptr, data_start, data_size, pool_ptr, wait_option);
}

UINT __real_nx_azure_iot_buffer_allocate(NX_AZURE_IOT *nx_azure_iot_ptr, UCHAR **buffer_pptr,
                                         UINT *buffer_size, VOID **buffer_context);
UINT __wrap_nx_azure_iot_buffer_allocate(NX_AZURE_IOT *nx_azure_iot_ptr, UCHAR **buffer_pptr,
                                         UINT *buffer_size, VOID **buffer_context)
{
    printf("HIJACKED: %s\n", __func__);

    if (g_failed_allocation_index == g_total_allocation)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    g_total_allocation++;
    return __real_nx_azure_iot_buffer_allocate(nx_azure_iot_ptr, buffer_pptr, buffer_size, buffer_context);
}

UINT __wrap__nx_tcp_socket_send(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, ULONG wait_option)
{
UINT status = (UINT)mock();

    printf("HIJACKED: %s\n", __func__);

    if (status == NX_SUCCESS)
    {

        /* packet ownership taken and released */
        nx_packet_release(packet_ptr);
    }

    return(status);
}

UINT __wrap__nxde_mqtt_client_secure_connect(NXD_MQTT_CLIENT *client_ptr, NXD_ADDRESS *server_ip, UINT server_port,
                                             UINT (*tls_setup)(NXD_MQTT_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *,
                                                               NX_SECURE_X509_CERT *, NX_SECURE_X509_CERT *),
                                             UINT keepalive, UINT clean_session, ULONG wait_option)
{
az_span source = az_span_create(client_ptr -> nxd_mqtt_client_username,
                                (INT)client_ptr -> nxd_mqtt_client_username_length);
az_span target = az_span_create((UCHAR *)g_pnp_model_id, sizeof(g_pnp_model_id) - 1);
UINT status = (UINT)mock();

    printf("HIJACKED: %s\n", __func__);

    if ((status != NXD_MQTT_SUCCESS) && (status != NX_IN_PROGRESS))
    {
        return(status);
    }

    /* Check username and client Id to contain modelId and device */
    assert_memory_equal(client_ptr -> nxd_mqtt_client_id, g_device_id, sizeof(g_device_id) - 1);
    assert_int_not_equal(az_span_find(source, target), -1);

    tx_thread_suspend(&(iot.nx_azure_iot_ip_ptr -> nx_ip_thread));
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_CONNECTED;
    client_ptr -> nxd_mqtt_client_packet_identifier = 1;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_id = NX_SECURE_TLS_ID;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_local_session_active = NX_FALSE;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_tcp_socket = &client_ptr -> nxd_mqtt_client_socket;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    test_connect_notify = client_ptr -> nxd_mqtt_connect_notify;
    test_connect_notify_context = client_ptr -> nxd_mqtt_connect_context;

    return(status);
}

UINT __wrap__nxde_mqtt_client_disconnect(NXD_MQTT_CLIENT *client_ptr)
{
    printf("HIJACKED: %s\n", __func__);
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_IDLE;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_CLOSED;

    if (client_ptr -> nxd_mqtt_disconnect_notify)
    {
        client_ptr -> nxd_mqtt_disconnect_notify(client_ptr);
    }

    return(NXD_MQTT_SUCCESS);
}

UINT __wrap__nxde_dns_host_by_name_get(NX_DNS *dns_ptr, UCHAR *host_name, NXD_ADDRESS *host_address_ptr,
                                       ULONG wait_option, UINT lookup_type)
{
    printf("HIJACKED: %s\n", __func__);
    host_address_ptr -> nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);
    return(NX_DNS_SUCCESS);
}

UINT __wrap__nxd_mqtt_client_sub_unsub(NXD_MQTT_CLIENT *client_ptr, CHAR *topic_name,
                                       UINT topic_name_length, UINT QoS)
{
    hub_client.nx_azure_iot_hub_client_properties_subscribe_ack = 0;

    return(NX_AZURE_IOT_SUCCESS);
}

static VOID telemetry_ack_callback(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, USHORT packet_id)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);
    NX_PARAMETER_NOT_USED(packet_id);
    
    g_telemetry_ack_count ++;
}

static UCHAR test_telemetry_ack_tcp_header[]={0x01, 0xbb, 0xcb, 0x84, 0x78, 0x58, 0x93, 0xd1,
                                              0x2d, 0x55, 0x45, 0x5f, 0xff, 0xff, 0x10, 0x50, 
                                              0xbd, 0xf0, 0x00, 0x00};

static UCHAR test_telemetry_ack_puback_header[] ={0x40, 0x02};

static VOID generate_test_telemetry_ack(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr, USHORT packet_id)
{
NX_PACKET *packet_ptr;
UCHAR      bytes[2];


    printf("Bytes : %s\n", __func__);
                   /* Create the socket. */
    nx_tcp_socket_create(g_ip_ptr, &(MQTT_CLIENT_GET(iothub_client_ptr).nxd_mqtt_client_socket), "mqtt client socket",
                         NX_IP_NORMAL, NX_DONT_FRAGMENT, 0x80, NXD_MQTT_CLIENT_SOCKET_WINDOW_SIZE,
                         NX_NULL, NX_NULL);


    /* Record the client_ptr in the socket structure. */
    MQTT_CLIENT_GET(iothub_client_ptr).nxd_mqtt_client_socket.nx_tcp_socket_reserved_ptr = (VOID *)iothub_client_ptr;

    nx_tcp_client_socket_bind(&(MQTT_CLIENT_GET(iothub_client_ptr).nxd_mqtt_client_socket), NX_ANY_PORT, NX_NO_WAIT);

    assert_int_equal(nx_packet_allocate(iot.nx_azure_iot_pool_ptr, &packet_ptr, 0, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);


    /* Fill the TCP header data.  */
    assert_int_equal(__real__nx_packet_data_append(packet_ptr, test_telemetry_ack_tcp_header,
                                                   sizeof(test_telemetry_ack_tcp_header),
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
                     
    /* Fill the MQTT PUBACK header data.  */
    assert_int_equal(__real__nx_packet_data_append(packet_ptr, test_telemetry_ack_puback_header,
                                                   sizeof(test_telemetry_ack_puback_header),
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set packet ID.  */
    bytes[0] = (UCHAR)(packet_id >> 8);
    bytes[1] = (UCHAR)(packet_id & 0xFF);
    assert_int_equal(__real__nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Simulate callback from MQTT layer.  */
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)0xBBBBBBBB;
    MQTT_CLIENT_GET(iothub_client_ptr).nxd_mqtt_client_socket.nx_tcp_socket_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).nxd_mqtt_client_socket.nx_tcp_socket_receive_queue_tail = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).nxd_mqtt_client_socket.nx_tcp_socket_receive_queue_count = 1;
    MQTT_CLIENT_GET(iothub_client_ptr).nxd_mqtt_client_socket.nx_tcp_socket_state = 1;
    nx_cloud_module_event_set(&(MQTT_CLIENT_GET(iothub_client_ptr).nxd_mqtt_client_cloud_module), 0x00000002); /* MQTT_PACKET_RECEIVE_EVENT */
}

static UINT mqtt_client_set_fixed_header(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, UCHAR control_header, UINT length, UINT wait_option)
{
UCHAR  fixed_header[5];
UCHAR *byte = fixed_header;
UINT   count = 0;
UINT   ret;

    *byte = control_header;
    byte++;

    do
    {
        if (length & 0xFFFFFF80)
        {
            *(byte + count) = (UCHAR)((length & 0x7F) | 0x80);
        }
        else
        {
            *(byte + count) = length & 0x7F;
        }
        length = length >> 7;

        count++;
    } while (length != 0);

    ret = __real__nx_packet_data_append(packet_ptr, fixed_header, count + 1,
                                        client_ptr -> nxd_mqtt_client_packet_pool_ptr, wait_option);

    return(ret);
}

static VOID connection_status_cb(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, UINT status)
{
    g_connect_status = status;
}

static VOID reset_global_state()
{
    /* reset global state */
    g_failed_append_index = (UINT)-1;
    g_total_append = 0;
    g_failed_allocation_index = (UINT)-1;
    g_total_allocation = 0;
    g_expected_message = NX_NULL;
    g_connect_status = NX_AZURE_IOT_FAILURE;
}

/* Hook execute before all tests. */
static VOID test_suit_begin()
{
    /* Initialize root certificate.  */
    assert_int_equal(nx_secure_x509_certificate_initialize(&root_ca_cert,
                                                           (UCHAR *)_nx_azure_iot_root_cert,
                                                           (USHORT)_nx_azure_iot_root_cert_size,
                                                           NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE),
                     NX_AZURE_IOT_SUCCESS);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT",
                                         g_ip_ptr, g_pool_ptr, g_dns_ptr,
                                         (UCHAR *)demo_cloud_thread_stack,
                                         sizeof(demo_cloud_thread_stack),
                                         DEMO_CLOUD_THREAD_PRIORITY, unix_time_get),
                     NX_AZURE_IOT_SUCCESS);
}

/* Hook execute after all tests are executed successfully */
static VOID test_suit_end()
{
    assert_int_equal(nx_azure_iot_delete(&iot),
                     NX_AZURE_IOT_SUCCESS);
}

/* Hook executed before every test */
static VOID test_begin()
{
    reset_global_state();

    /* Record number of available packet before test */
    g_available_packet = g_pool_ptr -> nx_packet_pool_available;
}

/* Hook execute after all tests are executed successfully */
static VOID test_end()
{
    /* Check if all the packet are released */
    assert_int_equal(g_pool_ptr -> nx_packet_pool_available, g_available_packet);
}

/**
 * Test invalid argument failure.
 *
 **/
static VOID test_nx_azure_iot_hub_client_invalid_argument_fail()
{
NX_PACKET *packet_ptr;

    printf("test starts =>: %s\n", __func__);

    /*********** Test nx_azure_iot_hub_client_model_id_set() ***********/
    /* NX_NULL iothub handle  */
    assert_int_not_equal(nx_azure_iot_hub_client_model_id_set(NX_NULL,
                                                              g_pnp_model_id, sizeof(g_pnp_model_id) - 1),
                        NX_AZURE_IOT_SUCCESS);

    /* NX_NULL model id pointer  */
    assert_int_not_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                              NX_NULL, sizeof(g_pnp_model_id) - 1),
                        NX_AZURE_IOT_SUCCESS);

    /* 0 model id string length  */
    assert_int_not_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                              g_pnp_model_id, 0),
                        NX_AZURE_IOT_SUCCESS);

    /*********** Test nx_azure_iot_hub_client_component_add() ***********/    
    /* NX_NULL iothub handle  */
    assert_int_not_equal(nx_azure_iot_hub_client_component_add(NX_NULL,
                                                               g_test_component, sizeof(g_test_component) - 1),
                        NX_AZURE_IOT_SUCCESS);

    /* NX_NULL component pointer  */
    assert_int_not_equal(nx_azure_iot_hub_client_component_add(&hub_client,
                                                               NX_NULL, sizeof(g_test_component) - 1),
                        NX_AZURE_IOT_SUCCESS);

    /* 0 model component name length  */
    assert_int_not_equal(nx_azure_iot_hub_client_component_add(&hub_client,
                                                               g_test_component, 0),
                        NX_AZURE_IOT_SUCCESS);

    /*********** Test nx_azure_iot_hub_client_telemetry_component_set() ***********/    
    /* NX_NULL packet  */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_component_set(NX_NULL,
                                                                         g_test_component, sizeof(g_test_component) - 1,
                                                                         NX_NO_WAIT),
                        NX_AZURE_IOT_SUCCESS);

    /* NX_NULL component pointer  */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_component_set(packet_ptr,
                                                                         NX_NULL, sizeof(g_test_component) - 1,
                                                                         NX_NO_WAIT),
                        NX_AZURE_IOT_SUCCESS);

    /* 0 component name length  */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_component_set(packet_ptr,
                                                                         g_test_component, 0,
                                                                         NX_NO_WAIT),
                        NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful pnp connect.
 *
 **/
static VOID test_nx_azure_iot_hub_client_connect_success()
{
    printf("test starts =>: %s\n", __func__);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Set symmetric key credentials  */
    assert_int_equal(nx_azure_iot_hub_client_symmetric_key_set(&hub_client,
                                                               g_symmetric_key,
                                                               sizeof(g_symmetric_key) - 1),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    will_return(__wrap__nxde_mqtt_client_secure_connect, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&hub_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful pnp connect with cert.
 *
 **/
static VOID test_nx_azure_iot_hub_client_connect_with_cert_success()
{
    printf("test starts =>: %s\n", __func__);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Set certificate  */
    assert_int_equal(nx_azure_iot_hub_client_device_cert_set(&hub_client,
                                                             &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    will_return(__wrap__nxde_mqtt_client_secure_connect, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&hub_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful pnp connect with NO_WAIT.
 *
 **/
static VOID test_nx_azure_iot_hub_client_connect_async_success()
{
    printf("test starts =>: %s\n", __func__);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Set certificate  */
    assert_int_equal(nx_azure_iot_hub_client_device_cert_set(&hub_client,
                                                             &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set connect callback  */
    assert_int_equal(nx_azure_iot_hub_client_connection_status_callback_set(&hub_client,
                                                                            connection_status_cb),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    will_return(__wrap__nxde_mqtt_client_secure_connect, NX_IN_PROGRESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&hub_client, NX_FALSE, NX_NO_WAIT),
                     NX_AZURE_IOT_CONNECTING);

    assert_non_null(test_connect_notify);
    test_connect_notify(&(MQTT_CLIENT_GET(&hub_client)),
                        NXD_MQTT_SUCCESS, test_connect_notify_context);

    assert_int_equal(g_connect_status, NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test failure pnp connect with NO_WAIT.
 *
 **/
static VOID test_nx_azure_iot_hub_client_connect_async_fail()
{
    printf("test starts =>: %s\n", __func__);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Set certificate  */
    assert_int_equal(nx_azure_iot_hub_client_device_cert_set(&hub_client,
                                                             &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set connect callback  */
    assert_int_equal(nx_azure_iot_hub_client_connection_status_callback_set(&hub_client,
                                                                            connection_status_cb),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    will_return(__wrap__nxde_mqtt_client_secure_connect, NX_IN_PROGRESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&hub_client, NX_FALSE, NX_NO_WAIT),
                     NX_AZURE_IOT_CONNECTING);

    assert_non_null(test_connect_notify);
    test_connect_notify(&(MQTT_CLIENT_GET(&hub_client)),
                        NXD_MQTT_CONNECT_FAILURE, test_connect_notify_context);

    assert_int_equal(g_connect_status, NXD_MQTT_CONNECT_FAILURE);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test pnp connect failure with OOM.
 *
 **/
static VOID test_nx_azure_iot_hub_client_connect_with_oom_failure()
{
UINT max_allocation;

    printf("test starts =>: %s\n", __func__);

    /* Set how many allocation required in g_total_allocation. */
    test_nx_azure_iot_hub_client_connect_success();
    max_allocation = g_total_allocation;

    reset_global_state();

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Set symmetric key credentials  */
    assert_int_equal(nx_azure_iot_hub_client_symmetric_key_set(&hub_client,
                                                               g_symmetric_key,
                                                               sizeof(g_symmetric_key) - 1),
                     NX_AZURE_IOT_SUCCESS);

    for (UINT index = 0; index < max_allocation; index++)
    {
        g_failed_allocation_index = index;

        /* Connect IoTHub client */
        assert_int_not_equal(nx_azure_iot_hub_client_connect(&hub_client, NX_FALSE, NX_NO_WAIT),
                             NX_AZURE_IOT_SUCCESS);

    }

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful pnp disconnect.
 *
 **/
static VOID test_nx_azure_iot_hub_client_disconnect_success()
{
    printf("test starts =>: %s\n", __func__);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Set connect callback  */
    assert_int_equal(nx_azure_iot_hub_client_connection_status_callback_set(&hub_client,
                                                                            connection_status_cb),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    will_return(__wrap__nxde_mqtt_client_secure_connect, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&hub_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_disconnect(&hub_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful telemetry send.
 *
 **/
static VOID test_nx_azure_iot_hub_client_telemetry_send_success()
{
NX_PACKET *packet_ptr;
UINT round = 0;

    printf("test starts =>: %s\n", __func__);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    will_return(__wrap__nxde_mqtt_client_secure_connect, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&hub_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    will_return(__wrap__nx_tcp_socket_send, NX_SUCCESS);

    while (NX_TRUE)
    {
        g_failed_append_index = g_total_append + round++;
        if (nx_azure_iot_hub_client_telemetry_message_create(&hub_client,
                                                             &packet_ptr, NX_NO_WAIT))
        {
            printf("Message creation failed\r\n");
        }
        else if (nx_azure_iot_hub_client_telemetry_component_set(packet_ptr,
                                                                 STRING_UNSIGNED_ARGS(g_test_component),
                                                                 NX_NO_WAIT))
        {
            nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
            printf("Add property failed\r\n");
        }
        else if (nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                STRING_UNSIGNED_ARGS(g_test_property_name),
                                                                STRING_UNSIGNED_ARGS(g_test_property_value),
                                                                NX_NO_WAIT))
        {
            nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
            printf("Add property failed\r\n");
        }
        else if (nx_azure_iot_hub_client_telemetry_send(&hub_client,
                                                        packet_ptr,
                                                        STRING_UNSIGNED_ARGS(g_test_telemetry_data),
                                                        NX_NO_WAIT))
        {
            nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
            printf("Send telemetry failed \r\n");
        }
        else
        {
            break;
        }
    }

    assert_int_equal(nx_azure_iot_hub_client_disconnect(&hub_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful telemetry send extended.
 *
 **/
static VOID test_nx_azure_iot_hub_client_telemetry_send_extended_success()
{
NX_PACKET *packet_ptr;
UINT round = 0;
USHORT packet_id;

    printf("test starts =>: %s\n", __func__);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);
                     
    /* Set telemetry ack callback.  */
    assert_int_equal(nx_azure_iot_hub_client_telemetry_ack_callback_set(&hub_client,
                                                                        telemetry_ack_callback),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    will_return(__wrap__nxde_mqtt_client_secure_connect, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&hub_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    will_return(__wrap__nx_tcp_socket_send, NX_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&hub_client, &packet_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_telemetry_send_extended(&hub_client,
                                                                     packet_ptr,
                                                                     STRING_UNSIGNED_ARGS(g_test_telemetry_data),
                                                                     &packet_id,
                                                                     NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Inject the telemetry puback message.  */
    generate_test_telemetry_ack(&hub_client, packet_id);

    /* Sleep 1 second.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    assert_int_not_equal(g_telemetry_ack_count, 0);

    assert_int_equal(nx_azure_iot_hub_client_disconnect(&hub_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test telemetry send publish failure.
 *
 **/
static VOID test_nx_azure_iot_hub_client_telemetry_send_fail()
{
NX_PACKET *packet_ptr;
UINT round = 0;

    printf("test starts =>: %s\n", __func__);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&hub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    will_return(__wrap__nxde_mqtt_client_secure_connect, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&hub_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&hub_client,
                                                                      &packet_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_telemetry_component_set(packet_ptr,
                                                                     STRING_UNSIGNED_ARGS(g_test_component),
                                                                     NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                    STRING_UNSIGNED_ARGS(g_test_property_name),
                                                                    STRING_UNSIGNED_ARGS(g_test_property_value),
                                                                    NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    will_return(__wrap__nx_tcp_socket_send, NX_AZURE_IOT_FAILURE);
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_send(&hub_client,
                                                                packet_ptr,
                                                                STRING_UNSIGNED_ARGS(g_test_telemetry_data),
                                                                NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr), NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_disconnect(&hub_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test telemetry send publish failure with mutex.
 *
 **/
static VOID test_nx_azure_iot_hub_client_telemetry_send_fail_mutex()
{
NX_PACKET *packet_ptr;

    printf("test starts =>: %s\n", __func__);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&hub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&hub_client,
                                                                      &packet_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Return NX_AZURE_IOT_DISCONNECTED as the connection is not established.  */
    assert_int_equal(nx_azure_iot_hub_client_telemetry_send(&hub_client,
                                                            packet_ptr,
                                                            STRING_UNSIGNED_ARGS(g_test_telemetry_data),
                                                            NX_NO_WAIT),
                     NX_AZURE_IOT_DISCONNECTED);

    /* Release the packet.  */
    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr), NX_AZURE_IOT_SUCCESS);

    /* Check if the mutex is released correctly before return.  */
    assert_int_equal(hub_client.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr -> tx_mutex_ownership_count, 0);
    
    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&hub_client),
                     NX_AZURE_IOT_SUCCESS);
}

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
    NX_AZURE_TEST_FN tests[] = {test_nx_azure_iot_hub_client_invalid_argument_fail,
                                test_nx_azure_iot_hub_client_connect_success,
                                test_nx_azure_iot_hub_client_connect_with_cert_success,
                                test_nx_azure_iot_hub_client_connect_async_success,
                                test_nx_azure_iot_hub_client_connect_async_fail,
                                test_nx_azure_iot_hub_client_connect_with_oom_failure,
                                test_nx_azure_iot_hub_client_disconnect_success,
                                test_nx_azure_iot_hub_client_telemetry_send_success,
                                test_nx_azure_iot_hub_client_telemetry_send_extended_success,
                                test_nx_azure_iot_hub_client_telemetry_send_fail,
                                test_nx_azure_iot_hub_client_telemetry_send_fail_mutex
                               };
    INT number_of_tests =  sizeof(tests)/sizeof(tests[0]);
    g_ip_ptr = ip_ptr;
    g_pool_ptr = pool_ptr;
    g_dns_ptr = dns_ptr;

    test_suit_begin();

    printf("Number of tests %d\r\n", number_of_tests);
    for (INT index = 0; index < number_of_tests; index++)
    {
        test_begin();
        tests[index]();
        test_end();
    }

    test_suit_end();
}
