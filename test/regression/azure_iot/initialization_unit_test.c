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

UINT __wrap__nxde_mqtt_client_delete(NXD_MQTT_CLIENT *client_ptr);
UINT __wrap__nxde_mqtt_client_receive_notify_set(NXD_MQTT_CLIENT *client_ptr,
                                                 VOID (*receive_notify)(NXD_MQTT_CLIENT *client_ptr,
                                                                        UINT message_count));

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iot_client;
static NX_AZURE_IOT_HUB_CLIENT iot_clients[3];
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];
extern int g_argc;
extern char **g_argv;
extern NX_AZURE_IOT *_nx_azure_iot_created_ptr;

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
CHAR *host_name = "host_name";
CHAR *device_id = "device_id";
CHAR *module_id = "module_id";
CHAR *symmetric_key = "symmetric_key";
UINT i;

    /* Initialize root certificate.  */
    assert_int_equal(nx_secure_x509_certificate_initialize(&root_ca_cert, (UCHAR *)_nx_azure_iot_root_cert, (USHORT)_nx_azure_iot_root_cert_size,
                                                           NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE),
                     NX_AZURE_IOT_SUCCESS);

    /*********** Test nx_azure_iot_create() ***********/
    /* FAIL: NX_AZURE_IOT pointer is null. */
    assert_int_not_equal(nx_azure_iot_create(NX_NULL, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                             sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: NX_IP pointer is null. */
    assert_int_not_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", NX_NULL, pool_ptr, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                             sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: NX_PACKET_POOL pointer is null. */
    assert_int_not_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, NX_NULL, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                             sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: NX_DNS pointer is null. */
    assert_int_not_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, NX_NULL, (UCHAR *)demo_cloud_thread_stack,
                                             sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: stack pointer is null. */
    assert_int_not_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr, NX_NULL,
                                             sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: stack size is 0. */
    assert_int_not_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                             0, DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: all parameters are valid. */
    assert_int_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                         sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                     NX_AZURE_IOT_SUCCESS);

    /*********** Test nx_azure_iot_delete() ***********/
    /* FAIL: NX_AZURE_IOT pointer is null. */
    assert_int_not_equal(nx_azure_iot_delete(NX_NULL), NX_AZURE_IOT_SUCCESS);

    /* FAIL: nx_cloud_delete fail. */
    /* Manually set nx_cloud_modules_count to none zero. */
    iot.nx_azure_iot_cloud.nx_cloud_modules_count++;
    assert_int_not_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
    iot.nx_azure_iot_cloud.nx_cloud_modules_count--;

    /* SUCCESS: iot is created. */
    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);


    /*********** Test nx_azure_iot_hub_client_initialize() ***********/
    assert_int_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                         sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                     NX_AZURE_IOT_SUCCESS);

    /* FAIL: NX_AZURE_IOT pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_initialize(&iot_client, NX_NULL,
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

    /* FAIL: NX_AZURE_IOT_HUB_CLIENT pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_initialize(NX_NULL, &iot,
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

    /* FAIL: host_name pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                            NX_NULL, 0,
                                                            STRING_UNSIGNED_ARGS(device_id),
                                                            STRING_UNSIGNED_ARGS(module_id),
                                                            _nx_azure_iot_tls_supported_crypto,
                                                            _nx_azure_iot_tls_supported_crypto_size,
                                                            _nx_azure_iot_tls_ciphersuite_map,
                                                            _nx_azure_iot_tls_ciphersuite_map_size,
                                                            metadata_buffer, sizeof(metadata_buffer),
                                                            &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: device_id pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                            STRING_UNSIGNED_ARGS(host_name),
                                                            NX_NULL, 0,
                                                            STRING_UNSIGNED_ARGS(module_id),
                                                            _nx_azure_iot_tls_supported_crypto,
                                                            _nx_azure_iot_tls_supported_crypto_size,
                                                            _nx_azure_iot_tls_ciphersuite_map,
                                                            _nx_azure_iot_tls_ciphersuite_map_size,
                                                            metadata_buffer, sizeof(metadata_buffer),
                                                            &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: host_name_length is 0. */
    assert_int_not_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                            "", 0,
                                                            STRING_UNSIGNED_ARGS(device_id),
                                                            STRING_UNSIGNED_ARGS(module_id),
                                                            _nx_azure_iot_tls_supported_crypto,
                                                            _nx_azure_iot_tls_supported_crypto_size,
                                                            _nx_azure_iot_tls_ciphersuite_map,
                                                            _nx_azure_iot_tls_ciphersuite_map_size,
                                                            metadata_buffer, sizeof(metadata_buffer),
                                                            &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: device_id_length is 0. */
    assert_int_not_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                            STRING_UNSIGNED_ARGS(host_name),
                                                            "", 0,
                                                            STRING_UNSIGNED_ARGS(module_id),
                                                            _nx_azure_iot_tls_supported_crypto,
                                                            _nx_azure_iot_tls_supported_crypto_size,
                                                            _nx_azure_iot_tls_ciphersuite_map,
                                                            _nx_azure_iot_tls_ciphersuite_map_size,
                                                            metadata_buffer, sizeof(metadata_buffer),
                                                            &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: invalidate cloud_id manually. */
    iot.nx_azure_iot_cloud.nx_cloud_id = 0;
    assert_int_not_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
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
    iot.nx_azure_iot_cloud.nx_cloud_id = NX_CLOUD_ID;

    /* FAIL: nxd_mqtt_client_receive_notify_set will fail by hijacked function. */
    will_return(__wrap__nxde_mqtt_client_receive_notify_set, NXD_MQTT_INVALID_PARAMETER);
    will_return(__wrap__nxde_mqtt_client_delete, NXD_MQTT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
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

    /* SUCCESS: all parameters are valid. */
    will_return_always(__wrap__nxde_mqtt_client_receive_notify_set, NXD_MQTT_SUCCESS);
    will_return(__wrap__nxde_mqtt_client_delete, NXD_MQTT_SUCCESS);
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
    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: all parameters are valid and module_id pointer is null. */
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
    will_return(__wrap__nxde_mqtt_client_delete, NXD_MQTT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: all parameters are valid and module_id pointer is null. */
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


    /*********** Test nx_azure_iot_hub_client_deinitialize() ***********/
    /* FAIL: NX_AZURE_IOT_HUB_CLIENT pointer is null. */
    assert_int_not_equal(nx_azure_iot_hub_client_deinitialize(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    /* FAIL: iot_client is not deleted yet. */
    assert_int_not_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);

    /* FAIL: nxd_mqtt_client_delete will fail by hijacked function. */
    will_return(__wrap__nxde_mqtt_client_delete, NXD_MQTT_INVALID_PARAMETER);
    assert_int_not_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                         NX_AZURE_IOT_SUCCESS);

    /* SUCCESS: iot_client is created. */
    will_return_always(__wrap__nxde_mqtt_client_delete, NXD_MQTT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    /* FAIL: iot_client is already deleted. */
    assert_int_not_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                         NX_AZURE_IOT_SUCCESS);


    /*********** Test multiple nx_azure_iot_hub_client_initialize()/deinitialize() ***********/
    for (i = 0; i < sizeof(iot_clients) / sizeof(NX_AZURE_IOT_HUB_CLIENT); i++)
    {
        assert_int_equal(nx_azure_iot_hub_client_initialize(&iot_clients[i], &iot,
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
    }

    /* Manually remove the header of nx_azure_iot_hub_client_list_header. */
    /* FAIL: this one removed from nx_azure_iot_hub_client_list_header. */
    _nx_azure_iot_created_ptr -> nx_azure_iot_resource_list_header = _nx_azure_iot_created_ptr -> nx_azure_iot_resource_list_header -> resource_next;
    assert_int_not_equal(nx_azure_iot_hub_client_deinitialize(&iot_clients[sizeof(iot_clients) / sizeof(NX_AZURE_IOT_HUB_CLIENT) - 1]),
                         NX_AZURE_IOT_SUCCESS);

    for (i = 0; i < sizeof(iot_clients) / sizeof(NX_AZURE_IOT_HUB_CLIENT) - 1; i++)
    {
        assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_clients[i]),
                         NX_AZURE_IOT_SUCCESS);
    }


    /* SUCCESS: iot is created. */
    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
  
    /* Check if all the packet are released */
    assert_int_equal(pool_ptr -> nx_packet_pool_available, pool_ptr -> nx_packet_pool_total);
}

UINT __real__nxde_mqtt_client_receive_notify_set(NXD_MQTT_CLIENT *client_ptr,
                                                 VOID (*receive_notify)(NXD_MQTT_CLIENT *client_ptr,
                                                                        UINT message_count));
UINT __wrap__nxde_mqtt_client_receive_notify_set(NXD_MQTT_CLIENT *client_ptr,
                                                 VOID (*receive_notify)(NXD_MQTT_CLIENT *client_ptr,
                                                                        UINT message_count))
{
    if ((UINT)mock() != NXD_MQTT_SUCCESS)
    {
        printf("HIJACKED: %s\n", __func__);
        return(NXD_MQTT_INVALID_PARAMETER);
    }
    return(__real__nxde_mqtt_client_receive_notify_set(client_ptr, receive_notify));
}

UINT __real__nxde_mqtt_client_delete(NXD_MQTT_CLIENT *client_ptr);
UINT __wrap__nxde_mqtt_client_delete(NXD_MQTT_CLIENT *client_ptr)
{
    if ((UINT)mock() != NXD_MQTT_SUCCESS)
    {
        printf("HIJACKED: %s\n", __func__);
        return(NXD_MQTT_INVALID_PARAMETER);
    }
    return(__real__nxde_mqtt_client_delete(client_ptr));
}
