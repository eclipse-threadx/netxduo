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

static UINT interface_type_check(ULONG interface_type);
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

ULONG g_interface_type = 0;

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

    /* Fail to set the type.  */
    g_interface_type = NX_INTERFACE_TYPE_UNKNOWN;
    will_return(__wrap__nxe_ip_driver_interface_direct_command, NX_NOT_SUCCESSFUL);

    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    
    /* The interface type should not be updated.  */
    assert_int_equal(interface_type_check(NX_INTERFACE_TYPE_UNKNOWN), NX_AZURE_IOT_SUCCESS);

    nx_azure_iot_hub_client_disconnect(&iot_client);

    /* Set the type as NX_INTERFACE_TYPE_OTHER.  */
    g_interface_type = NX_INTERFACE_TYPE_OTHER;
    will_return(__wrap__nxe_ip_driver_interface_direct_command, NX_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    
    /* The interface type should be updated as NX_INTERFACE_TYPE_OTHER.  */
    assert_int_equal(interface_type_check(NX_INTERFACE_TYPE_OTHER), NX_AZURE_IOT_SUCCESS);

    nx_azure_iot_hub_client_disconnect(&iot_client);

    /* Set the type as NX_INTERFACE_TYPE_ETHERNET.  */
    g_interface_type = NX_INTERFACE_TYPE_ETHERNET;
    will_return(__wrap__nxe_ip_driver_interface_direct_command, NX_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    
    /* The interface type should be updated as NX_INTERFACE_TYPE_ETHERNET.  */
    assert_int_equal(interface_type_check(NX_INTERFACE_TYPE_ETHERNET), NX_AZURE_IOT_SUCCESS);

    nx_azure_iot_hub_client_disconnect(&iot_client);

    /* Set the type as NX_INTERFACE_TYPE_LORAWAN.  */
    g_interface_type = NX_INTERFACE_TYPE_LORAWAN;
    will_return(__wrap__nxe_ip_driver_interface_direct_command, NX_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    
    /* The interface type should be updated as NX_INTERFACE_TYPE_LORAWAN.  */
    assert_int_equal(interface_type_check(NX_INTERFACE_TYPE_LORAWAN), NX_AZURE_IOT_SUCCESS);

    nx_azure_iot_hub_client_disconnect(&iot_client);

    /* Set the type as NX_INTERFACE_TYPE_MAX - 1.  */
    g_interface_type = NX_INTERFACE_TYPE_MAX - 1;
    will_return(__wrap__nxe_ip_driver_interface_direct_command, NX_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    
    /* The interface type should be updated as NX_INTERFACE_TYPE_MAX - 1.  */
    assert_int_equal(interface_type_check(NX_INTERFACE_TYPE_MAX - 1), NX_AZURE_IOT_SUCCESS);

    nx_azure_iot_hub_client_disconnect(&iot_client);

    /* Set the type as NX_INTERFACE_TYPE_MAX.  */
    g_interface_type = NX_INTERFACE_TYPE_MAX;
    will_return(__wrap__nxe_ip_driver_interface_direct_command, NX_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_TRUE, NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);
    
    /* The interface type should be updated as NX_INTERFACE_TYPE_OTHER.  */
    assert_int_equal(interface_type_check(NX_INTERFACE_TYPE_OTHER), NX_AZURE_IOT_SUCCESS);

    nx_azure_iot_hub_client_disconnect(&iot_client);

    iot_client.nx_azure_iot_hub_client_resource.resource_mqtt.nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    /* Check if all the packet are released */
    assert_int_equal(pool_ptr -> nx_packet_pool_available, pool_ptr_available_packet);
    assert_int_equal(small_pool.nx_packet_pool_available, small_pool_available_packet);

    /* SUCCESS: iot is created. */
    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
}

static UINT interface_type_check(ULONG interface_type)
{
UINT index;
UCHAR type;

    /* Decode the interface type.  */
    for (index = 0; index < (iot_client.iot_hub_client_core._internal.options.user_agent._internal.size - 3); index++)
    {

        /* The interface type is after the first semicolon.  */
        if ((*(iot_client.iot_hub_client_core._internal.options.user_agent._internal.ptr + index) == '%') &&
            (*(iot_client.iot_hub_client_core._internal.options.user_agent._internal.ptr + index + 1) == '3') &&
            (*(iot_client.iot_hub_client_core._internal.options.user_agent._internal.ptr + index + 2) == 'B'))
        {
            type = *(iot_client.iot_hub_client_core._internal.options.user_agent._internal.ptr + index + 3) - '0';
            if (type == interface_type)
            {
                return(NX_AZURE_IOT_SUCCESS);
            }
            else
            {
                return(NX_AZURE_IOT_FAILURE); 
            }
        }
    }

    return(NX_AZURE_IOT_FAILURE); 
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

UINT __wrap__nxe_ip_driver_interface_direct_command(NX_IP *ip_ptr, UINT command, UINT interface_index, ULONG *return_value_ptr)
{
    printf("HIJACKED: %s\n", __func__);
    *return_value_ptr = g_interface_type;
    return((UINT)mock());
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
    host_address_ptr -> nxd_ip_version = NX_IP_VERSION_V4;
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
