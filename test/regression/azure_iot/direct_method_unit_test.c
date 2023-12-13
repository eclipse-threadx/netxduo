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

typedef VOID (*NX_AZURE_TEST_FN)();


static UCHAR g_hostname[] = "unit-test.iot-azure.com";
static UCHAR g_device_id[] = "unit_test_device";

static const CHAR direct_method_response_topic[] = "$iothub/methods/POST/test_method/?$rid=1";
static const CHAR test_method_response_payload[] = "{\"method\" : \"test_method\", \"parameter\": 1}";
static const CHAR test_method_name[] = "test_method";
static const CHAR test_request_id[] = "1";
static const CHAR test_send_payload[] = "{\"return\" : \"OK\"}";

static UINT g_total_append = 0;
static UINT g_failed_append_index = 0;
static UINT g_total_allocation = 0;
static UINT g_failed_allocation_index = -1;
static NX_IP* g_ip_ptr;
static NX_PACKET_POOL* g_pool_ptr;
static NX_DNS* g_dns_ptr;
static ULONG g_available_packet;
static CHAR *g_expected_message;

extern UINT _nxd_mqtt_client_append_message(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, CHAR *message,
                                            UINT length, ULONG wait_option);
extern UINT _nxd_mqtt_client_set_fixed_header(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                              UCHAR control_header, UINT length, UINT wait_option);

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iot_client;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];
static UCHAR message_payload[MAXIMUM_PAYLOAD_LENGTH];
static UCHAR result_buffer[MAXIMUM_PAYLOAD_LENGTH];
static VOID (*test_receive_notify)(NXD_MQTT_CLIENT *client_ptr, UINT message_count) = NX_NULL;

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

UINT __wrap__nxde_mqtt_client_receive_notify_set(NXD_MQTT_CLIENT *client_ptr,
                                                 VOID (*receive_notify)(NXD_MQTT_CLIENT *client_ptr, UINT message_count))
{
    printf("HIJACKED: %s\n", __func__);
    test_receive_notify = receive_notify;
    return(NX_AZURE_IOT_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_subscribe(NXD_MQTT_CLIENT *client_ptr, UINT op,
                                        CHAR *topic_name, UINT topic_name_length,
                                        USHORT *packet_id_ptr, UINT QoS)
{
    printf("HIJACKED: %s\n", __func__);

    return((UINT)mock());
}

UINT __wrap__nxde_mqtt_client_unsubscribe(NXD_MQTT_CLIENT *client_ptr, CHAR *topic_name,
                                          UINT topic_name_length, UINT QoS)
{
    printf("HIJACKED: %s\n", __func__);
    return((UINT)mock());
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

UINT __wrap__nxd_mqtt_client_publish_packet_send(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                                 USHORT packet_id, UINT QoS, ULONG wait_option)
{
UINT topic_name_length;
UINT message_length;
UCHAR *buffer_ptr;
UINT status = (UINT)mock();

    printf("HIJACKED: %s\n", __func__);
    tx_mutex_put(client_ptr -> nxd_mqtt_client_mutex_ptr);

    if (status)
    {
        return(status);
    }

    buffer_ptr = packet_ptr -> nx_packet_prepend_ptr;
    topic_name_length = (buffer_ptr[5] << 8) | (buffer_ptr[6]);
    message_length = packet_ptr -> nx_packet_length - (9 + topic_name_length);
    assert_memory_equal(&buffer_ptr[7 + topic_name_length], g_expected_message, message_length);
    assert_int_equal(QoS, 0);

    /* packet ownership taken and released */
    nx_packet_release(packet_ptr);

    return(status);
}

UINT __wrap__nxde_mqtt_client_secure_connect(NXD_MQTT_CLIENT *client_ptr, NXD_ADDRESS *server_ip, UINT server_port,
                                             UINT (*tls_setup)(NXD_MQTT_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *,
                                                               NX_SECURE_X509_CERT *, NX_SECURE_X509_CERT *),
                                             UINT keepalive, UINT clean_session, ULONG wait_option)
{
    printf("HIJACKED: %s\n", __func__);

    tx_thread_suspend(&(iot.nx_azure_iot_ip_ptr -> nx_ip_thread));
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_CONNECTED;
    client_ptr -> nxd_mqtt_client_packet_identifier = 1;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_id = NX_SECURE_TLS_ID;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_local_session_active = NX_FALSE;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_tcp_socket = &client_ptr -> nxd_mqtt_client_socket;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;

    return(NXD_MQTT_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_disconnect(NXD_MQTT_CLIENT *client_ptr)
{
    printf("HIJACKED: %s\n", __func__);
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_IDLE;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    return(NXD_MQTT_SUCCESS);
}

UINT __wrap__nxde_dns_host_by_name_get(NX_DNS *dns_ptr, UCHAR *host_name, NXD_ADDRESS *host_address_ptr,
                                       ULONG wait_option, UINT lookup_type)
{
    printf("HIJACKED: %s\n", __func__);
    host_address_ptr -> nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);
    return(NX_DNS_SUCCESS);
}

static VOID on_receive_callback(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *arg)
{
    *((UINT *)arg) = 1;
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

static VOID construct_direct_method_response(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                             const UCHAR *topic, ULONG topic_len,
                                             const UCHAR *message_payload_ptr, ULONG message_payload_length,
                                             NX_PACKET **packet_pptr)
{
NX_PACKET *packet_ptr;
ULONG total_length;
ULONG topic_length = topic_len;
UCHAR bytes[2];
UINT i;

    assert_int_equal(nx_packet_allocate(iot.nx_azure_iot_pool_ptr, &packet_ptr, 0, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
    total_length = topic_length + 2 + 2 + message_payload_length; /* Two bytes for fixed topic_length field
                                                                     and two bytes for packet id. */

    /* Set fixed header. */
    assert_int_equal(mqtt_client_set_fixed_header(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt), packet_ptr,
                                                  (UCHAR)((MQTT_CONTROL_PACKET_TYPE_PUBLISH << 4) | MQTT_PUBLISH_QOS_LEVEL_1),
                                                  total_length, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set topic length. */
    bytes[0] = (topic_length >> 8) & 0xFF;
    bytes[1] = topic_length & 0xFF;
    assert_int_equal(__real__nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set topic. */
    assert_int_equal(__real__nx_packet_data_append(packet_ptr, (VOID *)topic, topic_len,
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
    /* Set packet ID. The value does not matter. */
    assert_int_equal(__real__nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set message payload. */
    if (message_payload_length > 0)
    {
        assert_int_equal(__real__nx_packet_data_append(packet_ptr, (VOID *)message_payload_ptr, message_payload_length,
                                                       iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
    }

    *packet_pptr = packet_ptr;
}

static VOID generate_direct_method_response(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
NX_PACKET *packet_ptr;

    construct_direct_method_response(hub_client_ptr, direct_method_response_topic, sizeof(direct_method_response_topic) - 1,
                                     test_method_response_payload, sizeof(test_method_response_payload) - 1,
                                     &packet_ptr);

    /* Simulate callback from MQTT layer.  */
    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt.message_receive_queue_head = packet_ptr;
    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt.message_receive_queue_depth = 1;
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, NX_WAIT_FOREVER);
    test_receive_notify(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt), 1);
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
}

static VOID reset_global_state()
{
    /* reset global state */
    g_failed_append_index = (UINT)-1;
    g_total_append = 0;
    g_failed_allocation_index = (UINT)-1;
    g_total_allocation = 0;
    g_expected_message = NX_NULL;
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

    /* Record number of available packet before test */
    g_available_packet = g_pool_ptr -> nx_packet_pool_available;

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                        g_hostname, sizeof(g_hostname),
                                                        g_device_id, sizeof(g_device_id),
                                                        "", 0,
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
}

/* Hook execute after all tests are executed successfully */
static VOID test_suit_end()
{

    /* Disconnect IoTHub client */
    assert_int_equal(nx_azure_iot_hub_client_disconnect(&iot_client), NX_AZURE_IOT_SUCCESS);

    /* Check if all the packet are released */
    assert_int_equal(g_pool_ptr -> nx_packet_pool_available, g_available_packet);

    /* Deinitialize IoTHub Client */
    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: iot is deleted. */
    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
}

/* Hook executed before every test */
static VOID test_begin()
{
    reset_global_state();
}

/* Hook execute after all tests are executed successfully */
static VOID test_end()
{
}

/**
 * Test direct method enable with invalid argument failed.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_enable_invalid_argument_failure()
{
    printf("test starts =>: %s\n", __func__);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_enable(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test direct method enable with unsuccessful subscribe failed.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_enable_failure()
{
    printf("test starts =>: %s\n", __func__);

    will_return(__wrap__nxde_mqtt_client_subscribe, NX_NOT_SUCCESSFUL);
    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_enable(&iot_client),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test direct method enable succeeds.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_enable_success()
{
    printf("test starts =>: %s\n", __func__);

    will_return(__wrap__nxde_mqtt_client_subscribe, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_direct_method_enable(&iot_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test direct method disable with invalid argument failed.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_disable_invalid_argument_failure()
{
    printf("test starts =>: %s\n", __func__);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_disable(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test direct method disable with unsuccessful un-subscribe failed.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_disable_failure()
{
    printf("test starts =>: %s\n", __func__);

    will_return(__wrap__nxde_mqtt_client_unsubscribe, NX_NOT_SUCCESSFUL);
    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_disable(&iot_client),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test direct method disable succeeds.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_disable_success()
{
    printf("test starts =>: %s\n", __func__);

    will_return(__wrap__nxde_mqtt_client_unsubscribe, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_direct_method_disable(&iot_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test direct method receive with invalid argument failed.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_message_receive_invalid_argument_failure()
{
const UCHAR *method_name_ptr;
USHORT method_name_length;
VOID *context_ptr;
USHORT context_length;
NX_PACKET *packet_ptr;

    printf("test starts =>: %s\n", __func__);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_message_receive(NX_NULL,
                                                                               &method_name_ptr, &method_name_length,
                                                                               &context_ptr, &context_length,
                                                                               &packet_ptr, NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test direct method receive succeeds.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_message_receive_success()
{
const UCHAR *method_name_ptr;
USHORT method_name_length;
VOID *context_ptr;
USHORT context_length;
NX_PACKET *packet_ptr;
ULONG bytes_copied;

    printf("test starts =>: %s\n", __func__);

    will_return(__wrap__nxde_mqtt_client_subscribe, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_direct_method_enable(&iot_client),
                     NX_AZURE_IOT_SUCCESS);
    generate_direct_method_response(&iot_client);

    assert_int_equal(nx_azure_iot_hub_client_direct_method_message_receive(&iot_client,
                                                                           &method_name_ptr, &method_name_length,
                                                                           &context_ptr, &context_length,
                                                                           &packet_ptr, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_memory_equal(method_name_ptr, test_method_name, sizeof(test_method_name) - 1);
    assert_int_equal(nx_packet_data_extract_offset(packet_ptr, 0, result_buffer,
                                                   sizeof(result_buffer), &bytes_copied),
                     NX_AZURE_IOT_SUCCESS);
    assert_memory_equal(result_buffer, test_method_response_payload, sizeof(test_method_response_payload) - 1);

    nx_packet_release(packet_ptr);
}

/**
 * Test direct method receive succeeds with NX_NO_WAIT.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_message_receive_no_blocking_success()
{
const UCHAR *method_name_ptr;
USHORT method_name_length;
VOID *context_ptr;
USHORT context_length;
NX_PACKET *packet_ptr;
ULONG bytes_copied;
UINT received = 0;

    printf("test starts =>: %s\n", __func__);

    assert_int_equal(nx_azure_iot_hub_client_receive_callback_set(&iot_client,
                                                                  NX_AZURE_IOT_HUB_DIRECT_METHOD,
                                                                  on_receive_callback,
                                                                  (VOID *)&received),
                     NX_AZURE_IOT_SUCCESS);
    will_return(__wrap__nxde_mqtt_client_subscribe, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_direct_method_enable(&iot_client),
                     NX_AZURE_IOT_SUCCESS);
    generate_direct_method_response(&iot_client);

    while (!received)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(nx_azure_iot_hub_client_direct_method_message_receive(&iot_client,
                                                                           &method_name_ptr, &method_name_length,
                                                                           &context_ptr, &context_length,
                                                                           &packet_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    assert_memory_equal(method_name_ptr, test_method_name, sizeof(test_method_name) - 1);
    assert_int_equal(nx_packet_data_extract_offset(packet_ptr, 0, result_buffer,
                                                   sizeof(result_buffer), &bytes_copied),
                     NX_AZURE_IOT_SUCCESS);
    assert_memory_equal(result_buffer, test_method_response_payload, sizeof(test_method_response_payload) - 1);

    nx_packet_release(packet_ptr);
}

/**
 * Test no one is receiving direct method.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_message_no_receive()
{
const UCHAR *method_name_ptr;
USHORT method_name_length;
VOID *context_ptr;
USHORT context_length;
NX_PACKET *packet_ptr;
ULONG bytes_copied;

    printf("test starts =>: %s\n", __func__);

    will_return(__wrap__nxde_mqtt_client_subscribe, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_direct_method_enable(&iot_client),
                     NX_AZURE_IOT_SUCCESS);
    generate_direct_method_response(&iot_client);
}


/**
 * Test direct method response invalid argument fail.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_message_response_invalid_argument_fail()
{
    printf("test starts =>: %s\n", __func__);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_message_response(NX_NULL,
                                                                                200, (VOID *)test_request_id, sizeof(test_request_id) - 1,
                                                                                (UCHAR *)test_send_payload, sizeof(test_send_payload) - 1,
                                                                                NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_message_response(&iot_client,
                                                                                200, NX_NULL, 0,
                                                                                (UCHAR *)test_send_payload, sizeof(test_send_payload) - 1,
                                                                                NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);
}


/**
 * Test direct method response send fail.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_message_response_send_failure_fail()
{
    printf("test starts =>: %s\n", __func__);
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_NOT_SUCCESSFUL);

    assert_int_not_equal(nx_azure_iot_hub_client_direct_method_message_response(&iot_client,
                                                                                200, (VOID *)test_request_id, sizeof(test_request_id) - 1,
                                                                                (UCHAR *)test_send_payload, sizeof(test_send_payload) - 1,
                                                                                NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test direct method response succeeds.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_message_response_success()
{
    printf("test starts =>: %s\n", __func__);
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    g_expected_message = (CHAR *)test_send_payload;

    assert_int_equal(nx_azure_iot_hub_client_direct_method_message_response(&iot_client,
                                                                            200, (VOID *)test_request_id, sizeof(test_request_id) - 1,
                                                                            (UCHAR *)test_send_payload, sizeof(test_send_payload) - 1,
                                                                            NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test direct method response empty json succeeds.
 *
 **/
static VOID test_nx_azure_iot_hub_client_direct_method_message_response_empty_success()
{
    printf("test starts =>: %s\n", __func__);
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    g_expected_message = (CHAR *)"{}";

    assert_int_equal(nx_azure_iot_hub_client_direct_method_message_response(&iot_client,
                                                                            200, (VOID *)test_request_id, sizeof(test_request_id) - 1,
                                                                            NX_NULL, 0,
                                                                            NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
}

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
    NX_AZURE_TEST_FN tests[] = { test_nx_azure_iot_hub_client_direct_method_enable_invalid_argument_failure,
                               test_nx_azure_iot_hub_client_direct_method_enable_failure,
                               test_nx_azure_iot_hub_client_direct_method_enable_success,
                               test_nx_azure_iot_hub_client_direct_method_disable_invalid_argument_failure,
                               test_nx_azure_iot_hub_client_direct_method_disable_failure,
                               test_nx_azure_iot_hub_client_direct_method_disable_success,
                               test_nx_azure_iot_hub_client_direct_method_message_receive_invalid_argument_failure,
                               test_nx_azure_iot_hub_client_direct_method_message_receive_success,
                               test_nx_azure_iot_hub_client_direct_method_message_receive_no_blocking_success,
                               test_nx_azure_iot_hub_client_direct_method_message_no_receive,
                               test_nx_azure_iot_hub_client_direct_method_message_response_invalid_argument_fail,
                               test_nx_azure_iot_hub_client_direct_method_message_response_send_failure_fail,
                               test_nx_azure_iot_hub_client_direct_method_message_response_success,
                               test_nx_azure_iot_hub_client_direct_method_message_response_empty_success };
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
