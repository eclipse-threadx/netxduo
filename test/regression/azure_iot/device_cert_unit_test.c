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
#include "nx_azure_iot_provisioning_client.h"


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

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iot_client;
static NX_AZURE_IOT_PROVISIONING_CLIENT iot_prov_client;
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
CHAR *endpoint = "host_name";
CHAR *id_scope = "id_scope";
CHAR *reg_id = "reg_id";
NX_SECURE_X509_CERT device_certificate;

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

    /* Initialize IoT hub client.  */
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

    /* FAIL: hub_client_ptr is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_device_cert_set(NX_NULL, &device_certificate),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: device_certificate is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_device_cert_set(&iot_client, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: set device certificate. */
    assert_int_equal(nx_azure_iot_hub_client_device_cert_set(&iot_client, &device_certificate),
                     NX_AZURE_IOT_SUCCESS);

#if NX_AZURE_IOT_MAX_NUM_OF_DEVICE_CERTS > 1
    /* SUCCESS: set device certificate again. */
    assert_int_equal(nx_azure_iot_hub_client_device_cert_set(&iot_client, &device_certificate),
                     NX_AZURE_IOT_SUCCESS);
#endif

    /* FAIL: no entry for device cert. */
    assert_int_not_equal(nx_azure_iot_hub_client_device_cert_set(&iot_client, &device_certificate),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: connected. */
    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, 20 * NX_IP_PERIODIC_RATE),
                     NX_AZURE_IOT_SUCCESS);

    /* Deinitialize IoT hub client.  */
    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);


    /* Initialize provisioning client.  */
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 endpoint, sizeof(endpoint) - 1,
                                                                 id_scope, sizeof(id_scope) - 1,
                                                                 reg_id, sizeof(reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* FAIL: prov_client_ptr is NULL. */
    assert_int_not_equal(nx_azure_iot_provisioning_client_device_cert_set(NX_NULL, &device_certificate),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: device_certificate is NULL. */
    assert_int_not_equal(nx_azure_iot_provisioning_client_device_cert_set(&iot_prov_client, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: set device certificate. */
    assert_int_equal(nx_azure_iot_provisioning_client_device_cert_set(&iot_prov_client, &device_certificate),
                     NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: pending. */
    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Deinitialize IoT provisioning client.  */
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);


    /* SUCCESS: iot is deleted. */
    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
}

UINT  __wrap__nxde_dns_host_by_name_get(NX_DNS *dns_ptr, UCHAR *host_name, NXD_ADDRESS *host_address_ptr,
                                        ULONG wait_option, UINT lookup_type)
{
    printf("HIJACKED: %s\n", __func__);
    host_address_ptr -> nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);
    return(NXD_MQTT_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_login_set(NXD_MQTT_CLIENT *client_ptr,
                                        CHAR *username, UINT username_length, CHAR *password, UINT password_length)
{
    printf("HIJACKED: %s\n", __func__);
    assert_null(password);
    return(NXD_MQTT_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_secure_connect(NXD_MQTT_CLIENT *client_ptr, NXD_ADDRESS *server_ip, UINT server_port,
                                             UINT (*tls_setup)(NXD_MQTT_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *,
                                                               NX_SECURE_X509_CERT *, NX_SECURE_X509_CERT *),
                                             UINT keepalive, UINT clean_session, ULONG wait_option)
{
    printf("HIJACKED: %s\n", __func__);
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_CONNECTED;
    return(NXD_MQTT_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_disconnect(NXD_MQTT_CLIENT *client_ptr)
{
    printf("HIJACKED: %s\n", __func__);
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_IDLE;
    return(NXD_MQTT_SUCCESS);
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