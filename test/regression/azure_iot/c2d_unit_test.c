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

#define C2D_TOPIC                 "devices/device_id/messages/devicebound/"

#define CALLBACK_ARGS             0x12345678

#define STRING_UNSIGNED_ARGS(s) (UCHAR *)s, strlen(s)

#ifndef DEMO_CLOUD_STACK_SIZE
#define DEMO_CLOUD_STACK_SIZE   2048
#endif /* DEMO_CLOUD_STACK_SIZE */

#ifndef DEMO_CLOUD_THREAD_PRIORITY
#define DEMO_CLOUD_THREAD_PRIORITY  (4)
#endif /* DEMO_CLOUD_THREAD_PRIORITY */

#ifndef MAXIMUM_PROPERTY_LENGTH
#define MAXIMUM_PROPERTY_LENGTH 1400 /* packet size */
#endif /* MAXIMUM_PROPERTY_LENGTH */

#ifndef MAXIMUM_PAYLOAD_LENGTH
#define MAXIMUM_PAYLOAD_LENGTH 10240
#endif /* MAXIMUM_PAYLOAD_LENGTH */

#define MQTT_CLIENT_GET(c)              ((c) -> nx_azure_iot_hub_client_resource.resource_mqtt)
#define TX_MUTEX_GET(c)                 ((c) -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr)

typedef struct
{
    UCHAR *name;
    ULONG name_length;
    UCHAR *value;
    ULONG value_length;
} PROPERTY;

#define PROPERTY_INIT(name, value) {(name), sizeof(name) - 1, (value), sizeof(value) - 1}

static VOID initialize_data();
static VOID property_payload_test(UINT packet_offset);
static VOID callback_test();
static VOID invalid_packet_test();
static VOID wait_timeout_test();
static VOID no_receiver_test();
static VOID construct_c2d_packet(NX_PACKET **packet_pptr, PROPERTY *properties, UINT property_count,
                                 UCHAR *message_payload_ptr, ULONG message_payload_length,
                                 UINT packet_offset);
static VOID c2d_callback(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *args);
extern UINT _nxd_mqtt_client_append_message(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, CHAR *message,
                                            UINT length, ULONG wait_option);
extern UINT _nxd_mqtt_client_set_fixed_header(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                              UCHAR control_header, UINT length, UINT wait_option);

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iot_client;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];
static UCHAR property_name[MAXIMUM_PROPERTY_LENGTH];
static UCHAR property_value[MAXIMUM_PROPERTY_LENGTH];
static UCHAR message_payload[MAXIMUM_PAYLOAD_LENGTH];
static UCHAR result_buffer[MAXIMUM_PAYLOAD_LENGTH];
static VOID (*test_receive_notify)(NXD_MQTT_CLIENT *client_ptr, UINT message_count) = NX_NULL;

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
CHAR *host_name = "host_name";
CHAR *device_id = "device_id";
CHAR *module_id = "module_id";
CHAR *symmetric_key = "symmetric_key";
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
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_cloud_message_enable(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    will_return(__wrap__nxde_mqtt_client_subscribe, NX_AZURE_IOT_SUCCESS);
    /* Connect IoTHub client */
    assert_int_equal(nx_azure_iot_hub_client_connect(&iot_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    /* Perform actual tests. */
    initialize_data();
    property_payload_test(0);    
    property_payload_test(1000);
    callback_test();
    invalid_packet_test();
    wait_timeout_test();
    no_receiver_test();


    will_return(__wrap__nxde_mqtt_client_unsubscribe, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_cloud_message_disable(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_disconnect(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);
    
    /* Check if all the packet are released */
    assert_int_equal(pool_ptr -> nx_packet_pool_available, pool_ptr_available_packet);
    
    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
}

static VOID initialize_data()
{
UINT i;

    for (i = 0; i < MAXIMUM_PROPERTY_LENGTH; i++)
    {
        property_name[i] = (NX_RAND() % 26) + 'a';
        property_value[i] = (NX_RAND() % 26) + 'a';
    }

    for (i = 0; i < sizeof(message_payload); i++)
    {
        message_payload[i] = (NX_RAND() % 26) + 'a';
    }
}

static VOID construct_c2d_packet(NX_PACKET **packet_pptr, PROPERTY *properties, UINT property_count,
                                 UCHAR *message_payload_ptr, ULONG message_payload_length, UINT packet_offset)
{
NX_PACKET *packet_ptr;
ULONG topic_length = sizeof(C2D_TOPIC) - 1;
ULONG total_length;
UCHAR bytes[2];
UINT i;

    assert_int_equal(nx_packet_allocate(iot.nx_azure_iot_pool_ptr, &packet_ptr, packet_offset, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    for (i = 0; i < property_count; i++)
    {
        topic_length += properties[i].name_length + properties[i].value_length + 2; /* '=' and '&' */
    }

    if (property_count)
    {
        topic_length--; /* Reduce by one since last '&' is not needed. */
    }
    total_length = topic_length + 2 + 2 + message_payload_length; /* Two bytes for fixed topic_length field
                                                                     and two bytes for packet id. */

    /* Set fixed header. */
    assert_int_equal(_nxd_mqtt_client_set_fixed_header(&(MQTT_CLIENT_GET(&iot_client)), packet_ptr,
                                                       (UCHAR)((MQTT_CONTROL_PACKET_TYPE_PUBLISH << 4) | MQTT_PUBLISH_QOS_LEVEL_1),
                                                       total_length, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set topic length. */
    bytes[0] = (topic_length >> 8) & 0xFF;
    bytes[1] = topic_length & 0xFF;
    assert_int_equal(nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                           iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set topic. */
    assert_int_equal(nx_packet_data_append(packet_ptr, C2D_TOPIC, sizeof(C2D_TOPIC) - 1,
                                           iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
    for (i = 0; i < property_count; i++)
    {
        if (i != 0)
        {
            assert_int_equal(nx_packet_data_append(packet_ptr, "&", 1,
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                             NX_AZURE_IOT_SUCCESS);
        }
        assert_int_equal(nx_packet_data_append(packet_ptr, properties[i].name, properties[i].name_length,
                                               iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_packet_data_append(packet_ptr, "=", 1,
                                               iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_packet_data_append(packet_ptr, properties[i].value, properties[i].value_length,
                                               iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
    }

    /* Set packet ID. The value does not matter. */
    assert_int_equal(nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                           iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set message payload. */
    if (message_payload_length > 0)
    {
        assert_int_equal(nx_packet_data_append(packet_ptr, message_payload_ptr, message_payload_length,
                                               iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
    }

    *packet_pptr = packet_ptr;
}

static VOID property_payload_test(UINT packet_offset)
{
NX_PACKET *packet_ptr;
ULONG bytes_copied;
USHORT result_size;
const UCHAR *result;
PROPERTY property = {property_name, 10, property_value, 10};
ULONG message_payload_length;
ULONG *length;
ULONG loop;
UINT i;

    for (i = 0; i < 3; i++)
    {
        if (i == 0)
        {

            /* First round, length of property name is variable. */
            loop = MAXIMUM_PROPERTY_LENGTH;
            length = &property.name_length;
            property.value_length = 10;
            message_payload_length = 10;
        }
        else if (i == 1)
        {

            /* Second round, length of property value is variable. */
            loop = MAXIMUM_PROPERTY_LENGTH;
            length = &property.value_length;
            property.name_length = 10;
            message_payload_length = 10;
        }
        else
        {

            /* Third round, length of message is variable. */
            loop = MAXIMUM_PAYLOAD_LENGTH; /* It is supported when message is spanned in multiple packets. */
            length = &message_payload_length;
            property.name_length = 10;
            property.value_length = 10;
        }
        for (*length = 0; *length < loop; (*length)++)
        {
            if ((i < 2) && (*length == 0))
            {

                /* Skip length 0 for property. */
                continue;
            }

            construct_c2d_packet(&packet_ptr, &property, 1, message_payload, message_payload_length, packet_offset);

            /* Simulate callback from MQTT layer.  */
            MQTT_CLIENT_GET(&iot_client).message_receive_queue_head = packet_ptr;
            MQTT_CLIENT_GET(&iot_client).message_receive_queue_depth = 1;
            tx_mutex_get(TX_MUTEX_GET(&iot_client), NX_WAIT_FOREVER);
            test_receive_notify(&(MQTT_CLIENT_GET(&iot_client)), 1);
            tx_mutex_put(TX_MUTEX_GET(&iot_client));

            assert_int_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                             NX_AZURE_IOT_SUCCESS);

            /* Validate property. */
            memset(result_buffer, property.value_length, 0);
            assert_int_equal(nx_azure_iot_hub_client_cloud_message_property_get(&iot_client, packet_ptr,
                                                                                property.name, property.name_length,
                                                                                &result, &result_size),
                             NX_AZURE_IOT_SUCCESS);
            assert_int_equal(property.value_length, result_size);
            assert_memory_equal(property.value, result, result_size);

            /* Validate payload. */
            memset(result_buffer, message_payload_length, 0);
            assert_int_equal(nx_packet_data_extract_offset(packet_ptr, 0, result_buffer,
                                                           sizeof(result_buffer), &bytes_copied),
                             NX_AZURE_IOT_SUCCESS);
            assert_int_equal(message_payload_length, bytes_copied);
            assert_memory_equal(message_payload, result_buffer, bytes_copied);

            nx_packet_release(packet_ptr);
        }
    }
}

static UINT (*c2d_message_process)(struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr,
                                   NX_PACKET *packet_ptr, ULONG topic_offset, USHORT topic_length);

static VOID callback_test()
{
ULONG arg = CALLBACK_ARGS;
NX_PACKET *packet_ptr;
ULONG bytes_copied;
ULONG message_payload_length = 10;
UINT c2d_control_flag;

    /* Expected fail: NX_AZURE_IOT_HUB_CLIENT is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_receive_callback_set(NX_NULL,
                                                                      NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE,
                                                                      c2d_callback,
                                                                      &arg),
                         NX_AZURE_IOT_SUCCESS);

    /* Expected fail: unknown message type. */
    assert_int_not_equal(nx_azure_iot_hub_client_receive_callback_set(&iot_client,
                                                                      0xFFFFFFFF,
                                                                      c2d_callback,
                                                                      &arg),
                         NX_AZURE_IOT_SUCCESS);

    /* Expect c2d_callback to be called once. */
    expect_function_calls(c2d_callback, 1);

    /* Set callback function. */
    assert_int_equal(nx_azure_iot_hub_client_receive_callback_set(&iot_client,
                                                                  NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE,
                                                                  c2d_callback,
                                                                  &arg),
                     NX_AZURE_IOT_SUCCESS);

    /* Put C2D packet to MQTT receive queue.  */
    construct_c2d_packet(&packet_ptr, NX_NULL, 0, message_payload, message_payload_length, 0);
    MQTT_CLIENT_GET(&iot_client).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(&iot_client).message_receive_queue_depth = 1;

    /* Expected callback function to be set. */
    assert_ptr_not_equal(test_receive_notify, NX_NULL);

    /* Simulate callback from MQTT layer.  */
    tx_mutex_get(TX_MUTEX_GET(&iot_client), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(&iot_client)), 1);
    tx_mutex_put(TX_MUTEX_GET(&iot_client));

    /* Expected fail: NX_AZURE_IOT_HUB_CLIENT is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(NX_NULL, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);

    /* Expected fail: packet pointer is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, NX_NULL, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);

    /* Expected fail: packet pointer is NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, NX_NULL, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);

    /* Expected fail: message_process is NULL. */
    c2d_message_process = iot_client.nx_azure_iot_hub_client_c2d_message.message_process;
    iot_client.nx_azure_iot_hub_client_c2d_message.message_process = NX_NULL;
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
    iot_client.nx_azure_iot_hub_client_c2d_message.message_process = c2d_message_process;

    /* Receive packet by API. */
    assert_int_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Validate payload. */
    memset(result_buffer, message_payload_length, 0);
    assert_int_equal(nx_packet_data_extract_offset(packet_ptr, 0, result_buffer,
                                                   sizeof(result_buffer), &bytes_copied),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(message_payload_length, bytes_copied);
    assert_memory_equal(message_payload, result_buffer, bytes_copied);
    nx_packet_release(packet_ptr);

    /* Expected fail: no packet available. */
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);

    /* Clear C2D callback function. */
    assert_int_equal(nx_azure_iot_hub_client_receive_callback_set(&iot_client,
                                                                  NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE,
                                                                  NX_NULL,
                                                                  NX_NULL),
                     NX_AZURE_IOT_SUCCESS);
}

static VOID invalid_packet_test()
{
NX_PACKET *packet_ptr;
UCHAR bytes[2] = {0, 0};

    assert_int_equal(nx_packet_allocate(iot.nx_azure_iot_pool_ptr, &packet_ptr, 0, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                           iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Put invalid packet to MQTT receive queue.  */
    MQTT_CLIENT_GET(&iot_client).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(&iot_client).message_receive_queue_depth = 1;

    /* Simulate callback from MQTT layer.  */
    tx_mutex_get(TX_MUTEX_GET(&iot_client), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(&iot_client)), 1);
    tx_mutex_put(TX_MUTEX_GET(&iot_client));

    /* Expected fail: no packet available. */
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);


    assert_int_equal(nx_packet_allocate(iot.nx_azure_iot_pool_ptr, &packet_ptr, 0, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                           iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Put invalid packet to receive header. */
    iot_client.nx_azure_iot_hub_client_c2d_message.message_head = packet_ptr;

    /* Expected fail: no packet available. */
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
}

static VOID wait_timeout_test()
{
NX_PACKET *packet_ptr;
ULONG message_payload_length = 10;

    /* Expect fail: no packet available. */
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, 1),
                         NX_AZURE_IOT_SUCCESS);

    /* Put C2D packet to MQTT receive queue.  */
    construct_c2d_packet(&packet_ptr, NX_NULL, 0, message_payload, message_payload_length, 0);
    MQTT_CLIENT_GET(&iot_client).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(&iot_client).message_receive_queue_depth = 1;

    /* Simulate callback from MQTT layer.  */
    tx_mutex_get(TX_MUTEX_GET(&iot_client), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(&iot_client)), 1);
    tx_mutex_put(TX_MUTEX_GET(&iot_client));

    /* Receive packet by API. */
    assert_int_equal(nx_azure_iot_hub_client_cloud_message_receive(&iot_client, &packet_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
    nx_packet_release(packet_ptr);
}

static VOID no_receiver_test()
{
NX_PACKET *packet_ptr;
ULONG message_payload_length = 10;

    /* Put C2D packet to MQTT receive queue.  */
    construct_c2d_packet(&packet_ptr, NX_NULL, 0, message_payload, message_payload_length, 0);
    MQTT_CLIENT_GET(&iot_client).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(&iot_client).message_receive_queue_depth = 1;

    /* Simulate callback from MQTT layer.  */
    tx_mutex_get(TX_MUTEX_GET(&iot_client), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(&iot_client)), 1);
    tx_mutex_put(TX_MUTEX_GET(&iot_client));

    /* No one will receive this packet. Packet leak will be checked at last step of test. */
}

static VOID c2d_callback(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *args)
{
    function_called();
    assert_ptr_equal(hub_client_ptr, &iot_client);
    assert_int_equal(*(ULONG *)args, CALLBACK_ARGS);
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
