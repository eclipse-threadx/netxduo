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


#define STRING_UNSIGNED_ARGS(s) (UCHAR *)s, strlen(s)

#ifndef DEMO_CLOUD_STACK_SIZE
#define DEMO_CLOUD_STACK_SIZE   2048
#endif /* DEMO_CLOUD_STACK_SIZE */

#ifndef DEMO_CLOUD_THREAD_PRIORITY
#define DEMO_CLOUD_THREAD_PRIORITY  (4)
#endif /* DEMO_CLOUD_THREAD_PRIORITY */

static UINT deplete_packets(NX_PACKET_POOL *pool_ptr, UINT remaining_packets);
static VOID release_packets(NX_PACKET_POOL *pool_ptr, UINT count);

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iot_client;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];
static NX_PACKET *allocated_packets[256];
static UCHAR large_property_name[2048];
static ULONG small_pool_stack[1024 >> 2];
static NX_PACKET_POOL small_pool;
extern int g_argc;
extern char **g_argv;

CHAR *expected_topic = "";
CHAR *expected_message = "";

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
CHAR *host_name = "host_name";
CHAR *device_id = "device_id";
CHAR *module_id = "module_id";
CHAR *symmetric_key = "symmetric_key";
CHAR property_name[] = "property_name";
CHAR property_value[] = "property_value";
NX_PACKET *packet_ptr;
UINT count;
ULONG pool_ptr_available_packet;
ULONG small_pool_available_packet;

    assert_int_equal(nx_packet_pool_create(&small_pool, "Small Packet Pool", 4,
                                           (UCHAR *)small_pool_stack , sizeof(small_pool_stack)),
                     NX_AZURE_IOT_SUCCESS);

    /* Initialize root certificate.  */
    assert_int_equal(nx_secure_x509_certificate_initialize(&root_ca_cert, (UCHAR *)_nx_azure_iot_root_cert, (USHORT)_nx_azure_iot_root_cert_size,
                                                           NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                         sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                     NX_AZURE_IOT_SUCCESS);

    /* Record number of available packet before test */
    pool_ptr_available_packet = pool_ptr -> nx_packet_pool_available;
    small_pool_available_packet = small_pool.nx_packet_pool_available;

    assert_int_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                        STRING_UNSIGNED_ARGS(host_name),
                                                        STRING_UNSIGNED_ARGS(device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* FAIL: allocate packet before connect. */
    iot_client.nx_azure_iot_hub_client_resource.resource_mqtt.nxd_mqtt_client_use_tls = NX_TRUE;
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    iot_client.nx_azure_iot_hub_client_resource.resource_mqtt.nxd_mqtt_client_use_tls = NX_FALSE;

    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    expected_topic = "devices/device_id/messages/events/";
    expected_message = "{\"Message\": \"Empty\"}";

    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NXD_MQTT_NOT_CONNECTED);
    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_send(&iot_client, packet_ptr, expected_message,
                                                                strlen(expected_message), NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr), NX_AZURE_IOT_SUCCESS);

    will_return_always(__wrap__nxd_mqtt_client_publish_packet_send, NXD_MQTT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /* FAIL: hub_client_ptr is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_send(NX_NULL, packet_ptr, expected_message,
                                                                strlen(expected_message), NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: packet_ptr is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_send(&iot_client, NX_NULL, expected_message,
                                                                strlen(expected_message), NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: Send telemetry as a device. */
    assert_int_equal(nx_azure_iot_hub_client_telemetry_send(&iot_client, packet_ptr, expected_message,
                                                            strlen(expected_message), NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /* FAIL: hub_client_ptr is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_message_create(NX_NULL, &packet_ptr, NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: packet_pptr is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, NX_NULL, NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: All packets are depleted. */
    count = deplete_packets(pool_ptr, 0);
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    release_packets(pool_ptr, count);

    /* FAIL: Packet pool is too small. */
    iot.nx_azure_iot_pool_ptr = &small_pool;
    iot_client.nx_azure_iot_hub_client_resource.resource_mqtt.nxd_mqtt_client_use_tls = NX_TRUE;
    iot_client.nx_azure_iot_hub_client_resource.resource_mqtt.nxd_mqtt_client_packet_pool_ptr = iot.nx_azure_iot_pool_ptr;
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    iot.nx_azure_iot_pool_ptr = pool_ptr;
    iot_client.nx_azure_iot_hub_client_resource.resource_mqtt.nxd_mqtt_client_use_tls = NX_FALSE;
    iot_client.nx_azure_iot_hub_client_resource.resource_mqtt.nxd_mqtt_client_packet_pool_ptr = iot.nx_azure_iot_pool_ptr;

    /* SUCCESS: All parameters are valid. */
    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /* FAIL: packet_ptr is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_property_add(NX_NULL,
                                                                        STRING_UNSIGNED_ARGS(property_name),
                                                                        STRING_UNSIGNED_ARGS(property_value),
                                                                        NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: property_name is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                        NX_NULL, 0,
                                                                        STRING_UNSIGNED_ARGS(property_value),
                                                                        NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: property_value is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                        STRING_UNSIGNED_ARGS(property_name),
                                                                        NX_NULL, 0,
                                                                        NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: All packets are depleted and current packet is too small to hold property. */
    count = deplete_packets(pool_ptr, 0);
    memset(large_property_name, 'A', sizeof(large_property_name) - 1);
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                        STRING_UNSIGNED_ARGS(large_property_name),
                                                                        STRING_UNSIGNED_ARGS(property_value),
                                                                        NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    nx_packet_release(packet_ptr);
    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: All parameters are valid. */
    assert_int_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                    STRING_UNSIGNED_ARGS(property_name),
                                                                    STRING_UNSIGNED_ARGS(property_value),
                                                                    NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /* FAIL: Adjust the current packet to full. No room to append '&' */
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_data_end;
    packet_ptr -> nx_packet_length = (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                        STRING_UNSIGNED_ARGS(property_name),
                                                                        STRING_UNSIGNED_ARGS(property_value),
                                                                        NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    nx_packet_release(packet_ptr);
    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /* FAIL: Adjust the current packet to full. Left two bytes for '&' and property name 'n' */
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_data_end - 2;
    packet_ptr -> nx_packet_length = (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) - 2;
    assert_int_not_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                        "n", 1,
                                                                        STRING_UNSIGNED_ARGS(property_value),
                                                                        NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    nx_packet_release(packet_ptr);
    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    release_packets(pool_ptr, count);

    /* SUCCESS: All parameters are valid. */
    assert_int_equal(nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                                    STRING_UNSIGNED_ARGS(property_name),
                                                                    STRING_UNSIGNED_ARGS(property_value),
                                                                    NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    nx_packet_release(packet_ptr);
    
    iot_client.nx_azure_iot_hub_client_resource.resource_mqtt.nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                        STRING_UNSIGNED_ARGS(host_name),
                                                        STRING_UNSIGNED_ARGS(device_id),
                                                        STRING_UNSIGNED_ARGS(module_id),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: Send telemetry as a module. */
    expected_topic = "devices/device_id/modules/module_id/messages/events/";
    expected_message = "{\"Message\": \"Empty\"}";
    assert_int_equal(nx_azure_iot_hub_client_telemetry_message_create(&iot_client, &packet_ptr, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_telemetry_send(&iot_client, packet_ptr, expected_message,
                                                            strlen(expected_message), NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    iot_client.nx_azure_iot_hub_client_resource.resource_mqtt.nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    /* Check if all the packet are released */
    assert_int_equal(pool_ptr -> nx_packet_pool_available, pool_ptr_available_packet);
    assert_int_equal(small_pool.nx_packet_pool_available, small_pool_available_packet);

    /* SUCCESS: iot is created. */
    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
}

static UINT deplete_packets(NX_PACKET_POOL *pool_ptr, UINT remaining_packets)
{
UINT count = 0;

    while (pool_ptr -> nx_packet_pool_available > remaining_packets)
    {
        nx_packet_allocate(pool_ptr, &allocated_packets[count++], 0, NX_WAIT_FOREVER);
    }
    return(count);
}

static VOID release_packets(NX_PACKET_POOL *pool_ptr, UINT count)
{
    while (count != 0)
    {
        nx_packet_release(allocated_packets[--count]);
    }
}

UINT __wrap__nxde_mqtt_client_secure_connect(NXD_MQTT_CLIENT *client_ptr, NXD_ADDRESS *server_ip, UINT server_port,
                                             UINT (*tls_setup)(NXD_MQTT_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *,
                                                               NX_SECURE_X509_CERT *, NX_SECURE_X509_CERT *),
                                             UINT keepalive, UINT clean_session, ULONG timeout)
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

UINT __wrap__nxde_dns_host_by_name_get(NX_DNS *dns_ptr, UCHAR *host_name, NXD_ADDRESS *host_address_ptr,
                                       ULONG wait_option, UINT lookup_type)
{
    printf("HIJACKED: %s\n", __func__);
    host_address_ptr -> nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);
    return(NX_DNS_SUCCESS);
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
    assert_int_equal(topic_name_length, strlen(expected_topic));
    assert_memory_equal(&buffer_ptr[7], expected_topic, topic_name_length);
    assert_int_equal(message_length, strlen(expected_message));
    assert_memory_equal(&buffer_ptr[9 + topic_name_length], expected_message, message_length);
    assert_int_equal(QoS, 1);
    
    /* packet ownership taken and released */
    nx_packet_release(packet_ptr);
    
    return(status);
}

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
