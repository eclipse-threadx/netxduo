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

static VOID connection_status_cb(struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, UINT status);

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iot_client;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];
extern int g_argc;
extern char **g_argv;

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
CHAR *host_name = "host_name";
CHAR *device_id = "device_id";
CHAR *module_id = "module_id";
CHAR *symmetric_key = "symmetric_key";
UINT i;
ULONG pool_ptr_available_packet;

    /* Initialize root certificate.  */
    assert_int_equal(nx_secure_x509_certificate_initialize(&root_ca_cert, (UCHAR *)_nx_azure_iot_root_cert, (USHORT)_nx_azure_iot_root_cert_size,
                                                           NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                         sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                     NX_AZURE_IOT_SUCCESS);

    /* Record number of available packet before test */
    pool_ptr_available_packet = pool_ptr -> nx_packet_pool_available;

    assert_int_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                        STRING_UNSIGNED_ARGS(host_name),
                                                        STRING_UNSIGNED_ARGS(device_id),
                                                        NX_NULL, 0,
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Setup callback function. */
    /* FAIL: NX_AZURE_IOT_HUB_CLIENT pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_connection_status_callback_set(NX_NULL, connection_status_cb),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: Setup callback function. */
    assert_int_equal(nx_azure_iot_hub_client_connection_status_callback_set(&iot_client, connection_status_cb),
                     NX_AZURE_IOT_SUCCESS);

    /* Setup Setup model Id. */
    /* FAIL: NX_AZURE_IOT_HUB_CLIENT pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_model_id_set(NX_NULL, STRING_UNSIGNED_ARGS("test::pnp")),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: Setup model Id. */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&iot_client, STRING_UNSIGNED_ARGS("test::pnp")),
                     NX_AZURE_IOT_SUCCESS);

    /* Setup Setup symmetric key. */
    /* FAIL: NX_AZURE_IOT_HUB_CLIENT pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_symmetric_key_set(NX_NULL, STRING_UNSIGNED_ARGS("SGVsbG8gdGhpcyBpcyB0ZXN0")),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: Setup Setup symmetric key. */
    assert_int_equal(nx_azure_iot_hub_client_symmetric_key_set(&iot_client, STRING_UNSIGNED_ARGS("SGVsbG8gdGhpcyBpcyB0ZXN0")),
                     NX_AZURE_IOT_SUCCESS);

    /*********** Test nx_azure_iot_hub_client_connect() ***********/
    /* FAIL: NX_AZURE_IOT_HUB_CLIENT pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_connect(NX_NULL, NX_FALSE, 20 * NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: nx_azure_iot_ptr is null. */
    iot_client.nx_azure_iot_ptr = NX_NULL;
    assert_int_not_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, 20 * NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    iot_client.nx_azure_iot_ptr = &iot;

    /* FAIL: Invalid value of nx_azure_iot_hub_client_state. */
    iot_client.nx_azure_iot_hub_client_state = NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED;
    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, 20 * NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_ALREADY_CONNECTED);
    iot_client.nx_azure_iot_hub_client_state = NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTING;
    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, 20 * NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_CONNECTING);
    iot_client.nx_azure_iot_hub_client_state = NX_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED;

    /* FAIL: nxd_dns_host_by_name_get will fail by hijacked function. */
    will_return(__wrap__nxde_dns_host_by_name_get, NX_DNS_PARAM_ERROR);
    assert_int_not_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, 20 * NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    will_return_always(__wrap__nxde_dns_host_by_name_get, NXD_MQTT_SUCCESS);

    /* TODO: add more test points for packet buffer. */

    /* FAIL: nxd_mqtt_client_secure_connect will fail by hijacked function. */
    will_return(__wrap__nxde_mqtt_client_secure_connect, NXD_MQTT_INVALID_PARAMETER);
    expect_value(connection_status_cb, status, NXD_MQTT_INVALID_PARAMETER);
    assert_int_not_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, 20 * NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: connected. */
    will_return_always(__wrap__nxde_mqtt_client_secure_connect, NXD_MQTT_SUCCESS);
    expect_value(connection_status_cb, status, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, 20 * NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /*********** Test nx_azure_iot_hub_client_disconnect() ***********/
    /* FAIL: NX_AZURE_IOT_HUB_CLIENT pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_disconnect(NX_NULL), NX_AZURE_IOT_SUCCESS);

    /* FAIL: nxd_mqtt_client_disconnect will fail by hijacked function. */
    will_return(__wrap__nxde_mqtt_client_disconnect, NXD_MQTT_INVALID_PARAMETER);
    assert_int_not_equal(nx_azure_iot_hub_client_disconnect(&iot_client), NX_AZURE_IOT_SUCCESS);
    will_return_always(__wrap__nxde_mqtt_client_disconnect, NXD_MQTT_SUCCESS);

    /* SUCCESS: disconnected. */
    assert_int_equal(nx_azure_iot_hub_client_disconnect(&iot_client), NX_AZURE_IOT_SUCCESS);

    /* Try reconnect. */
    expect_value(connection_status_cb, status, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, 20 * NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: disconnected. */
    assert_int_equal(nx_azure_iot_hub_client_disconnect(&iot_client), NX_AZURE_IOT_SUCCESS);

    /*********** End Test ***********/

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    /* Check if all the packet are released */
    assert_int_equal(pool_ptr -> nx_packet_pool_available, pool_ptr_available_packet);

    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
}

UINT  __wrap__nxde_dns_host_by_name_get(NX_DNS *dns_ptr, UCHAR *host_name, NXD_ADDRESS *host_address_ptr,
                                        ULONG wait_option, UINT lookup_type)
{
UINT status = (UINT)mock();

    printf("HIJACKED: %s\n", __func__);
    if (status)
    {
        return(status);
    }

    assert_memory_equal(host_name, "host_name", strlen("host_name"));
    host_address_ptr -> nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);
    return(status);
}

UINT __wrap__nxde_mqtt_client_secure_connect(NXD_MQTT_CLIENT *client_ptr, NXD_ADDRESS *server_ip, UINT server_port,
                                             UINT (*tls_setup)(NXD_MQTT_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *,
                                                               NX_SECURE_X509_CERT *, NX_SECURE_X509_CERT *),
                                             UINT keepalive, UINT clean_session, ULONG wait_option)
{
UINT status = (UINT)mock();

    printf("HIJACKED: %s\n", __func__);
    if (status)
    {
        return(status);
    }

    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_CONNECTED;
    return(status);
}

UINT __wrap__nxde_mqtt_client_disconnect(NXD_MQTT_CLIENT *client_ptr)
{
UINT status = (UINT)mock();

    printf("HIJACKED: %s\n", __func__);
    if (status)
    {
        return(status);
    }
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_IDLE;
    return(status);
}

static VOID connection_status_cb(struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, UINT status)
{
    assert_ptr_equal(hub_client_ptr, &iot_client);
    check_expected(status);
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
