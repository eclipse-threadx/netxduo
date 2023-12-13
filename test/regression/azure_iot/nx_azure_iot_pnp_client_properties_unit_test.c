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
#include "nx_packet.h"
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
#define TX_MUTEX_GET(c)                 ((c) -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr)

typedef VOID (*NX_AZURE_TEST_FN)();

static ULONG network_bytes_generate_stack[DEMO_HELPER_STACK_SIZE / sizeof(ULONG)];
static TX_THREAD network_bytes_generate_thread;

static const UCHAR g_hostname[] = "unit-test.iot-azure.com";
static const UCHAR g_device_id[] = "unit_test_device";
static const UCHAR g_pnp_model_id[] = "pnp_model_id_unit_test";
static const UCHAR g_symmetric_key[] = "6CLK6It9jOiABpFVu11CQDv9O49ebAneK3KbsvaoU1o=";
static const UCHAR g_test_component[] = "sample_test";
static const UCHAR g_test_reported_property_name[] = "test_temperature";
static const int32_t g_test_reported_property_value = 22;
static const UCHAR g_test_reported_property_name_2[] = "test_temperature_2";
static const int32_t g_test_reported_property_value_2 = 20;
static const UCHAR g_test_reported_property[] = "{\"test_temperature\":22}";
static const UCHAR g_test_reported_property_with_component[] = "{\"sample_test\":{\"__t\":\"c\",\"test_temperature\":22}}";
static const UCHAR g_test_reported_ack_description[] = "success";
static const UCHAR g_test_reported_property_status_with_component[] = "{\"sample_test\":{"
                                                                            "\"__t\":\"c\","
                                                                            "\"test_temperature\":{"
                                                                                "\"ac\":200,\"av\":6,\"ad\":\"success\",\"value\":23"
                                                                                "}"
                                                                            "}"
                                                                      "}";
static const UCHAR g_test_reported_property_status[] = "{\"test_temperature\":{\"ac\":200,\"av\":6,\"ad\":\"success\",\"value\":23}}";

static const UCHAR reported_property_success_topic[] = "$iothub/twin/res/204/?$rid=1&$version=6";
static const CHAR test_device_twin_reported_properties_throttled_response_topic[] = "$iothub/twin/res/429/?$rid=1";
static const CHAR test_device_twin_document_response_topic[] = "$iothub/twin/res/201/?$rid=2";
static const CHAR test_device_twin_document_response_payload[] = "{"
    "\"desired\":{"
        "\"sample_test\":{\"__t\":\"c\",\"test_temperature\":22,\"test_temperature1\":22},"
        "\"test_temperature\":22,"
        "\"$version\":6"
    "},"
    "\"reported\":{"
        "\"sample_test\":{\"__t\":\"c\",\"test_temperature\":22},"
        "\"test_temperature\":22,"
        "\"$version\":7"
    "}"
"}";
static const CHAR test_device_twin_document_response_throttled_topic[] = "$iothub/twin/res/429/?$rid=2";

static const CHAR test_device_twin_desired_properties_response_topic[] = "$iothub/twin/PATCH/properties/desired/?$version=6";
static const CHAR test_device_twin_desired_properties_response_payload[] = "{\"sample_test\":{"
                                                                                "\"__t\":\"c\","
                                                                                "\"test_temperature\":22,"
                                                                                "\"test_temperature_2\":20"
                                                                              "},"
                                                                             "\"test_temperature\":22,"
                                                                             "\"test_temperature_2\":20,"
                                                                             "\"$version\":6"
                                                                           "}";

static UINT g_total_append = 0;
static UINT g_failed_append_index = 0;
static UINT g_total_allocation = 0;
static UINT g_failed_allocation_index = -1;
static NX_IP* g_ip_ptr;
static NX_PACKET_POOL* g_pool_ptr;
static NX_DNS* g_dns_ptr;
static ULONG g_available_packet;
static const CHAR *g_expected_message;
static UINT generate_test_property_send_response_bytes = NX_FALSE;
static UINT generate_test_property_send_throttled_response_bytes = NX_FALSE;
static UINT generate_test_all_properties_bytes = NX_FALSE;
static UINT generate_test_all_properties__throttled_bytes = NX_FALSE;
static UINT generate_test_desired_properties_bytes = NX_FALSE;

extern UINT _nxd_mqtt_client_append_message(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, CHAR *message,
                                            UINT length, ULONG wait_option);
extern UINT _nxd_mqtt_client_set_fixed_header(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                              UCHAR control_header, UINT length, UINT wait_option);
extern UINT nx_azure_iot_hub_client_component_add_internal(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                                           const UCHAR *component_name_ptr,
                                                           UINT component_name_length,
                                                           UINT (*callback_ptr)(VOID *reader_ptr,
                                                                                ULONG version,
                                                                                VOID *args),
                                                           VOID *callback_args);
extern VOID nx_azure_iot_hub_client_properties_component_process(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                 NX_PACKET *packet_ptr, UINT message_type);


static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iothub_client;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];
static UCHAR message_payload[MAXIMUM_PAYLOAD_LENGTH];
static UCHAR result_buffer[MAXIMUM_PAYLOAD_LENGTH];
static VOID (*test_receive_notify)(NXD_MQTT_CLIENT *client_ptr, UINT message_count) = NX_NULL;
static UINT system_property_process(VOID *reader_ptr,
                                    ULONG version,
                                    VOID *args);

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

    iothub_client.nx_azure_iot_hub_client_properties_subscribe_ack = NX_TRUE;

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
    message_length = packet_ptr -> nx_packet_length - (7 + topic_name_length);
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
az_span source = az_span_create(client_ptr -> nxd_mqtt_client_username,
                                (INT)client_ptr -> nxd_mqtt_client_username_length);
az_span target = az_span_create((UCHAR *)g_pnp_model_id, sizeof(g_pnp_model_id) - 1);

    printf("HIJACKED: %s\n", __func__);

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

static VOID construct_command_message(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
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
    assert_int_equal(mqtt_client_set_fixed_header(&(MQTT_CLIENT_GET(iothub_client_ptr)), packet_ptr,
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

static VOID generate_test_property_send_response(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
NX_PACKET *packet_ptr;

    printf("Bytes : %s\n", __func__);
    construct_command_message(iothub_client_ptr, reported_property_success_topic,
                              sizeof(reported_property_success_topic) - 1,
                              "", 0, &packet_ptr);

    /* Simulate callback from MQTT layer.  */
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_depth = 1;
    tx_mutex_get(TX_MUTEX_GET(iothub_client_ptr), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(iothub_client_ptr)), 1);
    tx_mutex_put(TX_MUTEX_GET(iothub_client_ptr));
}

static VOID generate_test_property_send_throttled_response(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
NX_PACKET *packet_ptr;

    printf("Bytes : %s\n", __func__);
    construct_command_message(iothub_client_ptr, test_device_twin_reported_properties_throttled_response_topic,
                              sizeof(test_device_twin_reported_properties_throttled_response_topic) - 1,
                              "", 0, &packet_ptr);

    /* Simulate callback from MQTT layer.  */
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_depth = 1;
    tx_mutex_get(TX_MUTEX_GET(iothub_client_ptr), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(iothub_client_ptr)), 1);
    tx_mutex_put(TX_MUTEX_GET(iothub_client_ptr));
}

static VOID generate_test_all_properties(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
NX_PACKET *packet_ptr;

    printf("Bytes : %s\n", __func__);
    construct_command_message(iothub_client_ptr, test_device_twin_document_response_topic,
                              sizeof(test_device_twin_document_response_topic) - 1,
                              test_device_twin_document_response_payload,
                              sizeof(test_device_twin_document_response_payload) - 1,
                              &packet_ptr);

    /* Simulate callback from MQTT layer.  */
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_depth = 1;
    tx_mutex_get(TX_MUTEX_GET(iothub_client_ptr), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(iothub_client_ptr)), 1);
    tx_mutex_put(TX_MUTEX_GET(iothub_client_ptr));
}

static VOID generate_test_all_properties_throttled(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
NX_PACKET *packet_ptr;

    printf("Bytes : %s\n", __func__);
    construct_command_message(iothub_client_ptr, test_device_twin_document_response_throttled_topic,
                              sizeof(test_device_twin_document_response_throttled_topic) - 1,
                              "{}", sizeof("{}") - 1,
                              &packet_ptr);

    /* Simulate callback from MQTT layer.  */
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_depth = 1;
    tx_mutex_get(TX_MUTEX_GET(iothub_client_ptr), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(iothub_client_ptr)), 1);
    tx_mutex_put(TX_MUTEX_GET(iothub_client_ptr));
}

static VOID generate_test_desired_properties(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
NX_PACKET *packet_ptr;

    printf("Bytes : %s\n", __func__);
    construct_command_message(iothub_client_ptr, test_device_twin_desired_properties_response_topic,
                              sizeof(test_device_twin_desired_properties_response_topic) - 1,
                              test_device_twin_desired_properties_response_payload,
                              sizeof(test_device_twin_desired_properties_response_payload) - 1,
                              &packet_ptr);

    /* Simulate callback from MQTT layer.  */
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_depth = 1;
    tx_mutex_get(TX_MUTEX_GET(iothub_client_ptr), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(iothub_client_ptr)), 1);
    tx_mutex_put(TX_MUTEX_GET(iothub_client_ptr));
}

static UINT generate_test_properties(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                     NX_PACKET *packet_ptr,
                                     UINT use_component)
{
UINT status;
NX_AZURE_IOT_JSON_WRITER json_writer;

    if ((status = nx_azure_iot_json_writer_init(&json_writer, packet_ptr, NX_WAIT_FOREVER)))
    {
        return(status);
    }
    if ((status = nx_azure_iot_json_writer_append_begin_object(&json_writer)))
    {
        return(status);
    }
    if (use_component)
    {
        if ((status = nx_azure_iot_hub_client_reported_properties_component_begin(iothub_client_ptr,
                                                                                  &json_writer,
                                                                                  STRING_UNSIGNED_ARGS(g_test_component))))
        {
            return(status);
        }
    }

    if ((status = nx_azure_iot_json_writer_append_property_with_int32_value(&json_writer,
                                                                            STRING_UNSIGNED_ARGS(g_test_reported_property_name),
                                                                            22)))
    {
        return(status);
    }

    if (use_component)
    {
        if ((status = nx_azure_iot_hub_client_reported_properties_component_end(iothub_client_ptr,
                                                                                &json_writer)))
        {
            return(status);
        }

        g_expected_message = g_test_reported_property_with_component;
    }
    else
    {
        g_expected_message = g_test_reported_property;
    }

    if ((status = nx_azure_iot_json_writer_append_end_object(&json_writer)))
    {
        return(status);
    }

    return(status);
}

static UINT generate_test_properties_with_status(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                                 NX_PACKET *packet_ptr,
                                                 UINT use_component)
{
UINT status;
NX_AZURE_IOT_JSON_WRITER json_writer;

    if ((status = nx_azure_iot_json_writer_init(&json_writer, packet_ptr, NX_WAIT_FOREVER)))
    {
        return(status);
    }

    if ((status = nx_azure_iot_json_writer_append_begin_object(&json_writer)))
    {
        return(status);
    }

    if (use_component)
    {
        if ((status = nx_azure_iot_hub_client_reported_properties_component_begin(iothub_client_ptr,
                                                                                  &json_writer,
                                                                                  STRING_UNSIGNED_ARGS(g_test_component))))
        {
            return(status);
        }
    }

    if ((status = nx_azure_iot_hub_client_reported_properties_status_begin(iothub_client_ptr,
                                                                           &json_writer,
                                                                           STRING_UNSIGNED_ARGS(g_test_reported_property_name),
                                                                           200, 6,
                                                                           STRING_UNSIGNED_ARGS(g_test_reported_ack_description))))
    {
        return(status);
    }

    if ((status = nx_azure_iot_json_writer_append_int32(&json_writer, 23)))
    {
        return(status);
    }

    if ((status = nx_azure_iot_hub_client_reported_properties_status_end(iothub_client_ptr,
                                                                         &json_writer)))
    {
        return(status);
    }

    if (use_component)
    {
        if ((status = nx_azure_iot_hub_client_reported_properties_component_end(iothub_client_ptr,
                                                                                &json_writer)))
        {
            return(status);
        }

        g_expected_message = g_test_reported_property_status_with_component;
    }
    else
    {
        g_expected_message = g_test_reported_property_status;
    }

    if ((status = nx_azure_iot_json_writer_append_end_object(&json_writer)))
    {
        return(status);
    }

    return(status);
}

/* Generate network received bytes */
static VOID network_bytes_generate_entry(ULONG args)
{
    while (NX_TRUE)
    {
        if (generate_test_property_send_response_bytes)
        {
            generate_test_property_send_response_bytes = NX_FALSE;
            generate_test_property_send_response(&iothub_client);
        }

        if (generate_test_property_send_throttled_response_bytes)
        {
            generate_test_property_send_throttled_response_bytes = NX_FALSE;
            generate_test_property_send_throttled_response(&iothub_client);
        }

        if (generate_test_all_properties_bytes)
        {
            generate_test_all_properties_bytes = NX_FALSE;
            generate_test_all_properties(&iothub_client);
        }

        if (generate_test_all_properties__throttled_bytes)
        {
            generate_test_all_properties__throttled_bytes =  NX_FALSE;
            generate_test_all_properties_throttled(&iothub_client);
        }

        if (generate_test_desired_properties_bytes)
        {
            generate_test_desired_properties_bytes = NX_FALSE;
            generate_test_desired_properties(&iothub_client);
        }

        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }
}

static VOID on_receive_callback(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr, VOID *arg)
{
    *((UINT *)arg) = 1;
}

static VOID reported_property_cb(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                 UINT request_id, UINT response_status,
                                 ULONG version, VOID *args)
{
    *((UINT *)args) = response_status;
}

static VOID validate_json_reader(NX_AZURE_IOT_JSON_READER *reader_ptr, const CHAR *expected_json)
{
NX_AZURE_IOT_JSON_READER expected_json_reader;
UINT status;
UINT expected_status;

    assert_int_equal(nx_azure_iot_json_reader_with_buffer_init(&expected_json_reader,
                                                               (const UCHAR *)expected_json,
                                                               strlen(expected_json)),
                     NX_AZURE_IOT_SUCCESS);

    while (1)
    {
        status = nx_azure_iot_json_reader_next_token(reader_ptr);
        expected_status = nx_azure_iot_json_reader_next_token(&expected_json_reader);
        assert_int_equal(status, expected_status);

        if (expected_status)
        {
            break;
        }

        assert_int_equal(nx_azure_iot_json_reader_token_type(reader_ptr),
                         nx_azure_iot_json_reader_token_type(&expected_json_reader));
    }
}

static VOID reset_global_state()
{
    /* reset global state */
    g_failed_append_index = (UINT)-1;
    g_total_append = 0;
    g_failed_allocation_index = (UINT)-1;
    g_total_allocation = 0;
    g_expected_message = NX_NULL;
    generate_test_property_send_response_bytes = NX_FALSE;
}

/* Hook execute before all tests. */
static VOID test_suit_begin()
{
    assert_int_equal(tx_thread_create(&network_bytes_generate_thread,
                                      "UintTestNetworkBytesGenerator",
                                      network_bytes_generate_entry, 0,
                                      network_bytes_generate_stack,
                                      DEMO_HELPER_STACK_SIZE,
                                      DEMO_HELPER_THREAD_PRIORITY + 1,
                                      DEMO_HELPER_THREAD_PRIORITY + 1,
                                      TX_NO_TIME_SLICE, TX_AUTO_START),
                     NX_AZURE_IOT_SUCCESS);

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


    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&iothub_client, &iot,
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
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&iothub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Set symmetric key credentials  */
    assert_int_equal(nx_azure_iot_hub_client_symmetric_key_set(&iothub_client,
                                                               g_symmetric_key,
                                                               sizeof(g_symmetric_key) - 1),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_component_add_internal(&iothub_client,
                                                                    g_test_component,
                                                                    sizeof(g_test_component) - 1,
                                                                    system_property_process,
                                                                    NX_NULL),
                     NX_AZURE_IOT_SUCCESS);                     
    iothub_client.nx_azure_iot_hub_client_component_callback[0] = NX_NULL;

    will_return_always(__wrap__nxde_mqtt_client_subscribe, NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    assert_int_equal(nx_azure_iot_hub_client_connect(&iothub_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    /* Enable properties.  */     
    assert_int_equal(nx_azure_iot_hub_client_properties_enable(&iothub_client),
                     NX_AZURE_IOT_SUCCESS);       
}

/* Hook execute after all tests are executed successfully */
static VOID test_suit_end()
{
    assert_int_equal(nx_azure_iot_hub_client_disconnect(&iothub_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iothub_client),
                     NX_AZURE_IOT_SUCCESS);

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
NX_AZURE_IOT_JSON_WRITER writer;
NX_AZURE_IOT_JSON_READER reader;
const UCHAR *component_name;
USHORT component_name_length;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_create(NX_NULL,
                                                                            &packet_ptr,
                                                                            NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_create(&iothub_client,
                                                                            NX_NULL,
                                                                            NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_component_begin(NX_NULL,
                                                                                     &writer,
                                                                                     NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_component_begin(&iothub_client,
                                                                                     NX_NULL,
                                                                                     NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_component_end(&iothub_client,
                                                                                   NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_component_end(NX_NULL,
                                                                                   &writer),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_send(NX_NULL,
                                                                          packet_ptr,
                                                                          NX_NULL, NX_NULL,
                                                                          NX_NULL, NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_send(&iothub_client,
                                                                          NX_NULL,
                                                                          NX_NULL, NX_NULL,
                                                                          NX_NULL, NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_request(NX_NULL, NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_receive(NX_NULL,
                                                                    &packet_ptr, 
                                                                    NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_receive(&iothub_client,
                                                                    NX_NULL, 
                                                                    NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_writable_properties_receive(NX_NULL,
                                                                             &packet_ptr,
                                                                             NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                             NX_NULL,
                                                                             NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_version_get(NX_NULL,
                                                                        &reader,
                                                                        NX_AZURE_IOT_HUB_PROPERTIES,
                                                                        &version),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_version_get(&iothub_client,
                                                                        NX_NULL,
                                                                        NX_AZURE_IOT_HUB_PROPERTIES,
                                                                        &version),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_version_get(&iothub_client,
                                                                        &reader,
                                                                        0,
                                                                        &version),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_version_get(&iothub_client,
                                                                        &reader,
                                                                        NX_AZURE_IOT_HUB_PROPERTIES,
                                                                        NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_component_property_next_get(NX_NULL,
                                                                                        &reader, 
                                                                                        NX_AZURE_IOT_HUB_PROPERTIES,
                                                                                        NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                                        &component_name, &component_name_length),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_component_property_next_get(&iothub_client,
                                                                                        NX_NULL, 
                                                                                        NX_AZURE_IOT_HUB_PROPERTIES,
                                                                                        NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                                        &component_name, &component_name_length),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_component_property_next_get(&iothub_client,
                                                                                        &reader, 
                                                                                        1,
                                                                                        NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                                        &component_name, &component_name_length),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_component_property_next_get(&iothub_client,
                                                                                        &reader, 
                                                                                        NX_AZURE_IOT_HUB_PROPERTIES,
                                                                                        3,
                                                                                        &component_name, &component_name_length),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_component_property_next_get(&iothub_client,
                                                                                        &reader, 
                                                                                        NX_AZURE_IOT_HUB_PROPERTIES,
                                                                                        NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                                        NX_NULL, &component_name_length),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_component_property_next_get(&iothub_client,
                                                                                        &reader, 
                                                                                        NX_AZURE_IOT_HUB_PROPERTIES,
                                                                                        NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                                        &component_name, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_component_add(NX_NULL, NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_component_add(&iothub_client, NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_response_callback_set(NX_NULL, NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_status_begin(&iothub_client,
                                                                                  NX_NULL, NX_NULL,
                                                                                  0, 0, 0, NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_status_end(&iothub_client, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful pnp property send.
 *
 **/
static VOID test_nx_azure_iot_hub_client_property_send_success()
{
NX_PACKET *packet_ptr;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_create(&iothub_client,
                                                                        &packet_ptr,
                                                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_properties(&iothub_client, packet_ptr, NX_FALSE),
                     NX_AZURE_IOT_SUCCESS);
    generate_test_property_send_response_bytes = NX_TRUE;

    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_send(&iothub_client,
                                                                      packet_ptr,
                                                                      &request_id, &response_status,
                                                                      &version, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful pnp property send with NO_WAIT.
 *
 **/
static VOID test_nx_azure_iot_hub_client_property_send_async_success()
{
NX_PACKET *packet_ptr;
UINT response_status = 0;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_response_callback_set(&iothub_client,
                                                                                       reported_property_cb,
                                                                                       &response_status),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_reported_properties_create(&iothub_client,
                                                                        &packet_ptr,
                                                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_properties(&iothub_client, packet_ptr, NX_FALSE),
                     NX_AZURE_IOT_SUCCESS);
    generate_test_property_send_response_bytes = NX_TRUE;

    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_send(&iothub_client,
                                                                      packet_ptr,
                                                                      NX_NULL, &response_status,
                                                                      NX_NULL, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    while (response_status == 0)
    {
        tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
    }

    assert_int_equal(nx_azure_iot_hub_client_reported_properties_response_callback_set(&iothub_client,
                                                                                       NX_NULL, NX_NULL),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful pnp component property send.
 *
 **/
static VOID test_nx_azure_iot_hub_client_component_property_send_success()
{
NX_PACKET *packet_ptr;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;

    assert_int_equal(nx_azure_iot_hub_client_reported_properties_create(&iothub_client,
                                                                        &packet_ptr,
                                                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_properties(&iothub_client, packet_ptr, NX_TRUE),
                     NX_AZURE_IOT_SUCCESS);
    generate_test_property_send_response_bytes = NX_TRUE;

    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_send(&iothub_client,
                                                                      packet_ptr,
                                                                      &request_id, &response_status,
                                                                      &version, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful send reported pnp property status.
 *
 **/
static VOID test_nx_azure_iot_hub_client_reported_property_status_send_success()
{
NX_PACKET *packet_ptr;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_create(&iothub_client,
                                                                        &packet_ptr,
                                                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_properties_with_status(&iothub_client, packet_ptr, NX_FALSE),
                     NX_AZURE_IOT_SUCCESS);
    generate_test_property_send_response_bytes = NX_TRUE;

    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_send(&iothub_client,
                                                                      packet_ptr,
                                                                      &request_id, &response_status,
                                                                      &version, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful send reported pnp component property status.
 *
 **/
static VOID test_nx_azure_iot_hub_client_reported_component_property_status_send_success()
{
NX_PACKET *packet_ptr;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_create(&iothub_client,
                                                                        &packet_ptr,
                                                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_properties_with_status(&iothub_client, packet_ptr, NX_TRUE),
                     NX_AZURE_IOT_SUCCESS);
    generate_test_property_send_response_bytes = NX_TRUE;

    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_send(&iothub_client,
                                                                      packet_ptr,
                                                                      &request_id, &response_status,
                                                                      &version, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test pnp property send fail.
 *
 **/
static VOID test_nx_azure_iot_hub_client_property_send_fail()
{
NX_PACKET *packet_ptr;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;

    assert_int_equal(nx_azure_iot_hub_client_reported_properties_create(&iothub_client,
                                                                        &packet_ptr,
                                                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_properties(&iothub_client, packet_ptr, NX_FALSE),
                     NX_AZURE_IOT_SUCCESS);

    generate_test_property_send_response_bytes = NX_TRUE;
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_FAILURE);
    assert_int_not_equal(nx_azure_iot_hub_client_reported_properties_send(&iothub_client,
                                                                          packet_ptr,
                                                                          &request_id, &response_status,
                                                                          &version, NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);
    assert_ptr_not_equal(packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next, (NX_PACKET *)NX_PACKET_FREE);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test pnp property send fail due to throttling.
 *
 **/
static VOID test_nx_azure_iot_hub_client_property_send_throttled_fail()
{
NX_PACKET *packet_ptr;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_create(&iothub_client,
                                                                        &packet_ptr,
                                                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_properties(&iothub_client, packet_ptr, NX_FALSE),
                     NX_AZURE_IOT_SUCCESS);

    generate_test_property_send_throttled_response_bytes = NX_TRUE;
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_send(&iothub_client,
                                                                      packet_ptr,
                                                                      &request_id, &response_status,
                                                                      &version, 1 * NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_equal(response_status, 0);
    assert_int_not_equal(iothub_client.nx_azure_iot_hub_client_throttle_count, 0);
    assert_int_not_equal(iothub_client.nx_azure_iot_hub_client_throttle_end_time, 0);

    /* Create new message */
    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    assert_int_equal(nx_azure_iot_hub_client_reported_properties_create(&iothub_client,
                                                                        &packet_ptr,
                                                                        NX_WAIT_FOREVER),
                 NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_properties(&iothub_client, packet_ptr, NX_FALSE),
                     NX_AZURE_IOT_SUCCESS);

    generate_test_property_send_response_bytes = NX_TRUE;
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    while (nx_azure_iot_hub_client_reported_properties_send(&iothub_client,
                                                            packet_ptr,
                                                            &request_id, &response_status,
                                                            &version, NX_WAIT_FOREVER))
    {
        /* Do not sleep as we want to kick network response only when thread is inside send */
    }

    assert_int_not_equal(response_status, 429);
}

/**
 * Test get pnp properties success.
 *
 **/
static VOID test_nx_azure_iot_hub_client_property_get_success()
{
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER reader;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;

    g_expected_message = "";
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_properties_request(&iothub_client,
                                                                NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    generate_test_all_properties_bytes = NX_TRUE;

    assert_int_equal(nx_azure_iot_hub_client_properties_receive(&iothub_client,
                                                                &packet_ptr,
                                                                NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    validate_json_reader(&reader, test_device_twin_document_response_payload);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test get pnp properties success with NO_WAIT.
 *
 **/
static VOID test_nx_azure_iot_hub_client_property_get_async_success()
{
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER reader;
ULONG version;
UINT received_bytes = 0;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;

    assert_int_equal(nx_azure_iot_hub_client_receive_callback_set(&iothub_client,
                                                                  NX_AZURE_IOT_HUB_PROPERTIES,
                                                                  on_receive_callback,
                                                                  &received_bytes),
                     NX_AZURE_IOT_SUCCESS);

    g_expected_message = "";
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_properties_request(&iothub_client,
                                                                NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    generate_test_all_properties_bytes = NX_TRUE;

    while (received_bytes == 0)
    {
        tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
    }

    assert_int_equal(nx_azure_iot_hub_client_properties_receive(&iothub_client,
                                                                &packet_ptr,
                                                                NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    validate_json_reader(&reader, test_device_twin_document_response_payload);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_receive_callback_set(&iothub_client,
                                                                  NX_AZURE_IOT_HUB_PROPERTIES,
                                                                  NX_NULL, NX_NULL),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test get pnp properties fail to send request.
 *
 **/
static VOID test_nx_azure_iot_hub_client_property_get_send_fail()
{
NX_AZURE_IOT_JSON_READER reader;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;

    g_expected_message = "";
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_FAILURE);
    assert_int_not_equal(nx_azure_iot_hub_client_properties_request(&iothub_client,
                                                                    NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test get pnp properties fail to receive.
 *
 **/
static VOID test_nx_azure_iot_hub_client_property_get_receive_fail()
{
NX_PACKET *packet_ptr;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;

    g_expected_message = "";
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_properties_request(&iothub_client,
                                                                NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_hub_client_properties_receive(&iothub_client,
                                                                    &packet_ptr,
                                                                    5 * (NX_IP_PERIODIC_RATE)),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test get pnp properties fail due to throttled error.
 *
 **/
static VOID test_nx_azure_iot_hub_client_property_get_request_throttle_fail()
{
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER reader;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;

    g_expected_message = "";
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_properties_request(&iothub_client,
                                                                NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    generate_test_all_properties__throttled_bytes = NX_TRUE;
    assert_int_not_equal(nx_azure_iot_hub_client_properties_receive(&iothub_client,
                                                                    &packet_ptr,
                                                                    1 * NX_IP_PERIODIC_RATE),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_properties_request(&iothub_client, NX_NO_WAIT),
                     NX_AZURE_IOT_THROTTLED);

    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    while (nx_azure_iot_hub_client_properties_request(&iothub_client, NX_NO_WAIT))
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    generate_test_all_properties_bytes = NX_TRUE;
    assert_int_equal(nx_azure_iot_hub_client_properties_receive(&iothub_client,
                                                                &packet_ptr,
                                                                NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    validate_json_reader(&reader, test_device_twin_document_response_payload);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test receive pnp desired properties success.
 *
 **/
static VOID test_nx_azure_iot_hub_client_desired_property_receive_success()
{
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER reader;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    generate_test_desired_properties_bytes = NX_TRUE;

    assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                         &packet_ptr,
                                                                         NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_properties_version_get(&iothub_client, 
                                                                    &reader,
                                                                    NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                    &version),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    validate_json_reader(&reader, test_device_twin_desired_properties_response_payload);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test receive pnp desired properties success with NO_WAIT.
 *
 **/
static VOID test_nx_azure_iot_hub_client_desired_property_receive_async_success()
{
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER reader;
ULONG version;
UINT received_bytes = 0;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    generate_test_desired_properties_bytes = NX_TRUE;

    assert_int_equal(nx_azure_iot_hub_client_receive_callback_set(&iothub_client,
                                                                  NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                  on_receive_callback,
                                                                  &received_bytes),
                     NX_AZURE_IOT_SUCCESS);

    while (received_bytes == 0)
    {
        tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
    }

    assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                         &packet_ptr,
                                                                         NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_properties_version_get(&iothub_client, 
                                                                    &reader,
                                                                    NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                    &version),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    validate_json_reader(&reader, test_device_twin_desired_properties_response_payload);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_receive_callback_set(&iothub_client,
                                                                  NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                  NX_NULL, NX_NULL),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test scan desired PnP property.
 *
 **/
static VOID test_nx_azure_iot_hub_client_desired_property_iterate_success()
{
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER reader;
const UCHAR *component_ptr;
USHORT component_length = 0;
int32_t value;
UINT found_component = NX_FALSE;
UINT found_root_component = NX_FALSE;
ULONG version;
UINT index = 0;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    generate_test_desired_properties_bytes = NX_TRUE;
    assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                         &packet_ptr,
                                                                         NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
                     
    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_properties_version_get(&iothub_client, 
                                                                    &reader,
                                                                    NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                    &version),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    while (nx_azure_iot_hub_client_properties_component_property_next_get(&iothub_client, &reader,
                                                                          NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                          NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                          &component_ptr, &component_length) == NX_AZURE_IOT_SUCCESS)
    {
        if ((index == 0) || (index == 1))
        {
            assert_memory_equal(component_ptr, g_test_component, sizeof(g_test_component) - 1);
            found_component = NX_TRUE;
        }
        else
        {
            assert_non_null(found_component);
            found_root_component = NX_TRUE;
        }

        if ((index == 0) || (index == 2))
        {
            assert_int_equal(nx_azure_iot_json_reader_token_is_text_equal(&reader,
                                                                        (UCHAR *)g_test_reported_property_name,
                                                                        sizeof(g_test_reported_property_name) - 1),
                            NX_TRUE);
        }
        else
        {
            assert_int_equal(nx_azure_iot_json_reader_token_is_text_equal(&reader,
                                                                        (UCHAR *)g_test_reported_property_name_2,
                                                                        sizeof(g_test_reported_property_name_2) - 1),
                            NX_TRUE);
        }

        assert_int_equal(nx_azure_iot_json_reader_next_token(&reader),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_azure_iot_json_reader_token_int32_get(&reader, &value),
                         NX_AZURE_IOT_SUCCESS);

        if ((index == 0) || (index == 2))
        {
            assert_int_equal(value, g_test_reported_property_value);
        }
        else
        {
            assert_int_equal(value, g_test_reported_property_value_2);
        }

        assert_int_equal(nx_azure_iot_json_reader_next_token(&reader),
                         NX_AZURE_IOT_SUCCESS);

        index++;
    }

    assert_true(found_component);
    assert_true(found_root_component);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test get desired PnP properties version.
 *
 **/
static VOID test_nx_azure_iot_hub_client_desired_properties_version_success()
{
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER reader;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    generate_test_desired_properties_bytes = NX_TRUE;
    assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                         &packet_ptr,
                                                                         NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_properties_version_get(&iothub_client, 
                                                                    &reader,
                                                                    NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                    &version),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(version, 6);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;

    g_expected_message = "";
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_properties_request(&iothub_client,
                                                                NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    generate_test_all_properties_bytes = NX_TRUE;

    assert_int_equal(nx_azure_iot_hub_client_properties_receive(&iothub_client,
                                                                &packet_ptr,
                                                                NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_properties_version_get(&iothub_client, 
                                                                    &reader,
                                                                    NX_AZURE_IOT_HUB_PROPERTIES,
                                                                    &version),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(version, 6);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);
}

static UINT system_property_processed;
static UINT system_property_process(VOID *reader_ptr,
                                    ULONG version,
                                    VOID *args)
{
NX_AZURE_IOT_JSON_READER *json_reader_ptr = (NX_AZURE_IOT_JSON_READER *)reader_ptr;
    
    /* Update the flag.  */
    system_property_processed = NX_TRUE;
    
    /* Yes, skip it and find the next.  */
    nx_azure_iot_json_reader_next_token(json_reader_ptr);

    /* Skip children in case the property value is an object.  */
    if (nx_azure_iot_json_reader_token_type(json_reader_ptr) == NX_AZURE_IOT_READER_TOKEN_BEGIN_OBJECT)
    {
        nx_azure_iot_json_reader_skip_children(json_reader_ptr);
    }
    nx_azure_iot_json_reader_next_token(json_reader_ptr);
            
    return(NX_AZURE_IOT_SUCCESS);
}
                                                              
/**
 * Test system properties success.
 *
 **/
static VOID test_nx_azure_iot_hub_client_system_property_get_success()
{
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER reader;
const UCHAR *component_ptr;
USHORT component_length;
int32_t value;
UINT found_component = NX_FALSE;
UINT found_root_component = NX_FALSE;
ULONG version;


    printf("test starts =>: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_request_id = 0;
    
    /* Initialize.  */
    system_property_processed = NX_FALSE;
    
    /* Set component process routine for system component.  */
    iothub_client.nx_azure_iot_hub_client_component_properties_process = nx_azure_iot_hub_client_properties_component_process;

    /* Mark g_test_component as system component.  */
    iothub_client.nx_azure_iot_hub_client_component_callback[0] = system_property_process;
    
    g_expected_message = "";
    will_return(__wrap__nxd_mqtt_client_publish_packet_send, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_hub_client_properties_request(&iothub_client,
                                                                NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    generate_test_all_properties_bytes = NX_TRUE;

    assert_int_equal(nx_azure_iot_hub_client_properties_receive(&iothub_client,
                                                                &packet_ptr,
                                                                NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_properties_version_get(&iothub_client, 
                                                                    &reader,
                                                                    NX_AZURE_IOT_HUB_PROPERTIES,
                                                                    &version),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader, packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    while (nx_azure_iot_hub_client_properties_component_property_next_get(&iothub_client, &reader,
                                                                          NX_AZURE_IOT_HUB_PROPERTIES,
                                                                          NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                          &component_ptr, &component_length) == NX_AZURE_IOT_SUCCESS)
    {
        if (component_ptr != NX_NULL)
        {
            found_component = NX_TRUE;
        }
        else
        {
            found_root_component = NX_TRUE;
        }

        assert_int_equal(nx_azure_iot_json_reader_token_is_text_equal(&reader,
                                                                      (UCHAR *)g_test_reported_property_name,
                                                                      sizeof(g_test_reported_property_name) - 1),
                         NX_TRUE);
        assert_int_equal(nx_azure_iot_json_reader_next_token(&reader),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_azure_iot_json_reader_token_int32_get(&reader, &value),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(value, g_test_reported_property_value);
        assert_int_equal(nx_azure_iot_json_reader_next_token(&reader),
                         NX_AZURE_IOT_SUCCESS);
    }

    assert_false(found_component);
    assert_true(found_root_component);
    assert_true(system_property_processed);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    /* Mark g_test_component assystem component.  */
    iothub_client.nx_azure_iot_hub_client_component_callback[0] = NX_NULL;
}

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
    NX_AZURE_TEST_FN tests[] = {test_nx_azure_iot_hub_client_invalid_argument_fail,
                                test_nx_azure_iot_hub_client_property_send_success,
                                test_nx_azure_iot_hub_client_property_send_async_success,
                                test_nx_azure_iot_hub_client_component_property_send_success,
                                test_nx_azure_iot_hub_client_reported_property_status_send_success,
                                test_nx_azure_iot_hub_client_reported_component_property_status_send_success,
                                test_nx_azure_iot_hub_client_property_send_fail,
                                test_nx_azure_iot_hub_client_property_send_throttled_fail,
                                test_nx_azure_iot_hub_client_property_get_success,
                                test_nx_azure_iot_hub_client_property_get_async_success,
                                test_nx_azure_iot_hub_client_property_get_send_fail,
                                test_nx_azure_iot_hub_client_property_get_receive_fail,
                                test_nx_azure_iot_hub_client_property_get_request_throttle_fail,
                                test_nx_azure_iot_hub_client_desired_property_receive_success,
                                test_nx_azure_iot_hub_client_desired_property_receive_async_success,
                                test_nx_azure_iot_hub_client_desired_property_iterate_success,
                                test_nx_azure_iot_hub_client_desired_properties_version_success,
                                test_nx_azure_iot_hub_client_system_property_get_success
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
