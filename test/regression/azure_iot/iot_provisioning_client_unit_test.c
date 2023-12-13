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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>  /* macros: https://api.cmocka.org/group__cmocka__asserts.html */

#include "nx_api.h"
#include "nx_azure_iot_provisioning_client.h"
#include "nx_azure_iot_cert.h"
#include "nx_azure_iot_ciphersuites.h"


#define DEMO_DHCP_DISABLE
#define DEMO_IPV4_ADDRESS                           IP_ADDRESS(192, 168, 100, 33)
#define DEMO_IPV4_MASK                              0xFFFFFF00UL
#define DEMO_GATEWAY_ADDRESS                        IP_ADDRESS(192, 168, 100, 1)
#define DEMO_DNS_SERVER_ADDRESS                     IP_ADDRESS(192, 168, 100, 1)
#define NETWORK_DRIVER                              _nx_ram_network_driver

/* Include main.c in the test case since we need to disable DHCP in this test. */
#include "main.c"

#ifndef DEMO_CLOUD_STACK_SIZE
#define DEMO_CLOUD_STACK_SIZE                       2048
#endif /* DEMO_CLOUD_STACK_SIZE */

#ifndef DEMO_CLOUD_THREAD_PRIORITY
#define DEMO_CLOUD_THREAD_PRIORITY                  (4)
#endif /* DEMO_CLOUD_THREAD_PRIORITY */

#ifndef MAXIMUM_PROPERTY_BUFFER
#define MAXIMUM_PROPERTY_BUFFER                     256
#endif /* MAXIMUM_PROPERTY_BUFFER */

#ifndef TEST_DEFAULT_WAIT_TIME
#define TEST_DEFAULT_WAIT_TIME                      500
#endif /* TEST_DEFAULT_WAIT_TIME */

#define PROVISIONING_SERVICE_REPONSE_TOPIC          "$dps/registrations/res/202/?"
#define PROVISIONING_SERVICE_REPONSE_200_TOPIC      "$dps/registrations/res/200/?"
#define PROVISIONING_SERVICE_REPONSE_BAD_TOPIC      "$dps/registrations/res/401/?"
#define PROVISIONING_SERVICE_REPONSE_THROTTLE_TOPIC "$dps/registrations/res/429/?"

#define CUSTOM_PAYLOAD                              "{\"modelId\":\"pnp_model\"}"

typedef VOID (*NX_AZURE_TEST_FN)();

typedef struct
{
    UCHAR *name;
    ULONG name_length;
    UCHAR *value;
    ULONG value_length;
} PROPERTY;

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_PROVISIONING_CLIENT iot_prov_client;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];

static const CHAR *expected_register_topic_start = "$dps/registrations/PUT/iotdps-register/?$rid=";
static const CHAR *expected_query_topic_start = "$dps/registrations/GET/iotdps-get-operationstatus/?$rid=";
static const CHAR *expected_message = "{\"registrationId\" : \"reg_id\"}";
static const CHAR *expected_message_with_custom_payload = "{\"registrationId\" : \"reg_id\", \"payload\" : "CUSTOM_PAYLOAD"}";
static const CHAR assigned_hub_response[] = "{ \
    \"operationId\":\"4.002305f54fc89692.b1f11200-8776-4b5d-867b-dc21c4b59c12\",\"status\":\"assigned\",\"registrationState\": \
         {\"registrationId\":\"reg_id\",\"createdDateTimeUtc\":\"2019-12-27T19:51:41.6630592Z\",\"assignedHub\":\"test.azure-iothub.com\", \
          \"deviceId\":\"testId\",\"status\":\"assigned\",\"substatus\":\"initialAssignment\",\"lastUpdatedDateTimeUtc\":\"2019-12-27T19:51:41.8579703Z\", \
          \"etag\":\"XXXXXXXXXXX=\"\
         }\
}";
static const CHAR failure_hub_response[] = "{ \
    \"operationId\":\"4.002305f54fc89692.b1f11200-8776-4b5d-867b-dc21c4b59c12\",\"status\":\"failed\",\"registrationState\": \
         {\"registrationId\":\"reg_id\",\"createdDateTimeUtc\":\"2019-12-27T19:51:41.6630592Z\",\
          \"status\":\"failed\",\"errorCode\":400207,\"errorMessage\":\"Custom allocation failed with status code: 400\",\
          \"lastUpdatedDateTimeUtc\":\"2019-12-27T19:51:41.8579703Z\", \
          \"etag\":\"XXXXXXXXXXX=\"\
         }\
}";
static const CHAR *assigned_hub_name = "test.azure-iothub.com";
static const CHAR *assigned_device_id = "testId";
static const CHAR assigning_hub_response[] = "{ \
    \"operationId\":\"4.002305f54fc89692.b1f11200-8776-4b5d-867b-dc21c4b59c12\",\"status\":\"assigning\" \
}";
static const CHAR *invalid_response_data_set[] = {

    /* operationId in the response is invalid */
    "{ \
    \"operationId\": [],\"status\":\"assigned\",\"registrationState\": \
         {\"registrationId\":\"reg_id\",\"createdDateTimeUtc\":\"2019-12-27T19:51:41.6630592Z\",\"assignedHub\":\"test.azure-iothub.com\", \
          \"deviceId\":\"testId\",\"status\":\"assigned\",\"substatus\":\"initialAssignment\",\"lastUpdatedDateTimeUtc\":\"2019-12-27T19:51:41.8579703Z\", \
          \"etag\":\"XXXXXXXXXXX=\"\
         }\
    }",

    /* status in the response is invalid */
    "{ \
    \"operationId\":\"4.002305f54fc89692.b1f11200-8776-4b5d-867b-dc21c4b59c12\",\"status\":[],\"registrationState\": \
         {\"registrationId\":\"reg_id\",\"createdDateTimeUtc\":\"2019-12-27T19:51:41.6630592Z\",\"assignedHub\":\"test.azure-iothub.com\", \
          \"deviceId\":\"testId\",\"status\":[],\"substatus\":\"initialAssignment\",\"lastUpdatedDateTimeUtc\":\"2019-12-27T19:51:41.8579703Z\", \
          \"etag\":\"XXXXXXXXXXX=\"\
         }\
    }",

    /* invalid deviceId in the response */
    "{ \
    \"operationId\":\"4.002305f54fc89692.b1f11200-8776-4b5d-867b-dc21c4b59c12\",\"status\":\"assigned\",\"registrationState\": \
         {\"registrationId\":\"reg_id\",\"createdDateTimeUtc\":\"2019-12-27T19:51:41.6630592Z\",\"assignedHub\":\"test.azure-iothub.com\", \
          \"deviceId\":[],\"status\":\"assigned\",\"substatus\":\"initialAssignment\",\"lastUpdatedDateTimeUtc\":\"2019-12-27T19:51:41.8579703Z\", \
          \"etag\":\"XXXXXXXXXXX=\"\
         }\
    }",

    /* invalid assignedHub in the response */
    "{ \
    \"operationId\":\"4.002305f54fc89692.b1f11200-8776-4b5d-867b-dc21c4b59c12\",\"status\":\"assigned\",\"registrationState\": \
         {\"registrationId\":\"reg_id\",\"createdDateTimeUtc\":\"2019-12-27T19:51:41.6630592Z\",\"assignedHub\":[], \
          \"deviceId\":\"test1\",\"status\":\"assigned\",\"substatus\":\"initialAssignment\",\"lastUpdatedDateTimeUtc\":\"2019-12-27T19:51:41.8579703Z\", \
          \"etag\":\"XXXXXXXXXXX=\"\
         }\
    }",

    /* no JSON object return via dps */
    "[\"invalid dps response json\"]",

    /* Invalid JSON */
    "[\"invalid json\"}"

    /* Invalid JSON */
    "\n"
};
static const CHAR throttle_hub_response[] = "{ \
    \"errorCode\":429001, \
    \"trackingId\":\"\",\"message\":\"Operations are being throttled for this tenant.\", \
    \"timestampUtc\":\"2021-10-26T00:02:24.263671Z\" \
}";
static CHAR *symmetric_key = "MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXY=="; /* 1234567890abcdefghijklmnopqrstuv */

static NX_IP* g_ip_ptr;
static NX_PACKET_POOL* g_pool_ptr;
static NX_DNS* g_dns_ptr;
static ULONG g_available_packet;

static CHAR g_endpoint[] = "host_name";
static CHAR g_id_scope[] = "id_scope";
static CHAR g_reg_id[] = "reg_id";
static CHAR g_SAS_token[] = "SAS_token";
static UINT g_done = 0;
static UINT g__wrap__nxde_mqtt_client_secure_connect_status = 0;
static UINT g__wrap__nxde_mqtt_client_subscribe_status = 0;
static UINT g__wrap__nxde_mqtt_client_disconnect_status = 0;
static UINT g__wrap__nxd_mqtt_client_publish_packet_send_status = 0;
static UINT g__wrap__nxde_dns_host_by_name_get_status = 0;
static UINT g_req_id = 0;
static UINT g_assigned_response_after = 0;
static UINT g_total_append = 0;
static UINT g_failed_append_index = 0;
static UINT g_total_allocation = 0;
static UINT g_failed_allocation_index = 0;
static UCHAR property_value[MAXIMUM_PROPERTY_BUFFER];
static UCHAR property_value2[MAXIMUM_PROPERTY_BUFFER];
static PROPERTY req_id_property = { "$rid", sizeof("$rid") - 1, property_value, sizeof(property_value) };
static PROPERTY retry_after_property = { "retry-after", sizeof("retry-after") - 1 , property_value2, sizeof(property_value2) };
static VOID (*test_receive_notify)(NXD_MQTT_CLIENT *client_ptr, UINT message_count) = NX_NULL;
static VOID (*test_connect_notify)(struct NXD_MQTT_CLIENT_STRUCT *client_ptr, UINT status, VOID *context) = NX_NULL;
static VOID *test_connect_notify_context = NX_NULL;
static VOID (*test_disconnect_notify)(struct NXD_MQTT_CLIENT_STRUCT *client_ptr) = NX_NULL;
static UCHAR iothub_hostname[32];
static UCHAR iothub_device_id[32];

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

UINT __wrap__nxde_mqtt_client_secure_connect(NXD_MQTT_CLIENT *client_ptr, NXD_ADDRESS *server_ip, UINT server_port,
                                             UINT (*tls_setup)(NXD_MQTT_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *,
                                                               NX_SECURE_X509_CERT *, NX_SECURE_X509_CERT *),
                                             UINT keepalive, UINT clean_session, ULONG wait_option)
{
UINT status = g__wrap__nxde_mqtt_client_secure_connect_status;

    printf("HIJACKED: %s\n", __func__);
    if (status)
    {
        return(status);
    }

    tx_thread_suspend(&(iot.nx_azure_iot_ip_ptr -> nx_ip_thread));
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_CONNECTED;
    client_ptr -> nxd_mqtt_client_packet_identifier = 1;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_id = NX_SECURE_TLS_ID;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_local_session_active = NX_FALSE;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_tcp_socket = &client_ptr -> nxd_mqtt_client_socket;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    client_ptr -> nxd_mqtt_connect_notify(client_ptr, NXD_MQTT_SUCCESS, client_ptr -> nxd_mqtt_connect_context);
    test_connect_notify = client_ptr -> nxd_mqtt_connect_notify;
    test_connect_notify_context = client_ptr -> nxd_mqtt_connect_context;
    test_disconnect_notify = client_ptr -> nxd_mqtt_disconnect_notify;

    return(status);
}

UINT __wrap__nxde_dns_host_by_name_get(NX_DNS *dns_ptr, UCHAR *host_name, NXD_ADDRESS *host_address_ptr,
                                       ULONG wait_option, UINT lookup_type)
{
UINT status = g__wrap__nxde_dns_host_by_name_get_status;

    printf("HIJACKED: %s\n", __func__);
    if (status)
    {
        return(status);
    }

    host_address_ptr -> nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);
    return(NX_DNS_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_subscribe(NXD_MQTT_CLIENT *client_ptr, CHAR *topic_name,
                                        UINT topic_name_length, UINT QoS)
{
    printf("HIJACKED: %s\n", __func__);
    return(g__wrap__nxde_mqtt_client_subscribe_status);
}

UINT __wrap__nxde_mqtt_client_disconnect(NXD_MQTT_CLIENT *client_ptr)
{
UINT status = g__wrap__nxde_mqtt_client_disconnect_status;

    printf("HIJACKED: %s\n", __func__);
    if (status)
    {
        return(status);
    }

    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_IDLE;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    return(status);
}

UINT __wrap__nxd_mqtt_client_publish_packet_send(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                                 USHORT packet_id, UINT QoS, ULONG wait_option)
{
INT topic_name_length;
UINT message_length;
UCHAR *buffer_ptr;
UCHAR *topic_ptr;
UINT status = g__wrap__nxd_mqtt_client_publish_packet_send_status;

    printf("HIJACKED: %s\n", __func__);

    if (status)
    {
        return(status);
    }

    buffer_ptr = packet_ptr -> nx_packet_prepend_ptr;
    topic_name_length = (buffer_ptr[5] << 8) | (buffer_ptr[6]);
    message_length = packet_ptr -> nx_packet_length - (9 + topic_name_length);
    topic_ptr = &buffer_ptr[7];

    /* Check if it is query or register request */
    if (strstr((CHAR *)topic_ptr, "operationId=") != NULL)
    {
        assert_memory_equal(topic_ptr, expected_query_topic_start, strlen(expected_query_topic_start));
        assert_int_equal(sscanf((CHAR *)&topic_ptr[strlen(expected_query_topic_start)], "%u", &g_req_id), 1);
    }
    else
    {
        assert_memory_equal(topic_ptr, expected_register_topic_start, strlen(expected_register_topic_start));
        assert_int_equal(sscanf((CHAR *)&topic_ptr[strlen(expected_register_topic_start)], "%u", &g_req_id), 1);
    }

    if (iot_prov_client.nx_azure_iot_provisioning_client_registration_payload)
    {
        assert_int_equal(message_length, strlen(expected_message_with_custom_payload));
        assert_memory_equal(&buffer_ptr[9 + topic_name_length],
                            expected_message_with_custom_payload, message_length);
    }
    else
    {
        assert_int_equal(message_length, strlen(expected_message));
        assert_memory_equal(&buffer_ptr[9 + topic_name_length], expected_message, message_length);
    }

    assert_int_equal(QoS, 1);

    /* packet ownership taken and released */
    nx_packet_release(packet_ptr);

    return(status);
}

UINT __wrap__nxde_mqtt_client_receive_notify_set(NXD_MQTT_CLIENT *client_ptr,
                                                 VOID (*receive_notify)(NXD_MQTT_CLIENT *client_ptr, UINT message_count))
{
    printf("HIJACKED: %s\n", __func__);
    test_receive_notify = receive_notify;
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

static VOID on_complete_callback(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr, UINT status)
{
    g_done = 1;
}

static VOID construct_provisioning_service_response(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                    NX_PACKET **packet_pptr,
                                                    const UCHAR *topic, ULONG topic_len,
                                                    PROPERTY *properties, UINT property_count,
                                                    const UCHAR *message_payload_ptr, ULONG message_payload_length)
{
NX_PACKET *packet_ptr;
ULONG total_length;
ULONG topic_length = topic_len;
UCHAR bytes[2];
UINT i;

    assert_int_equal(nx_packet_allocate(iot.nx_azure_iot_pool_ptr, &packet_ptr, 0, NX_NO_WAIT),
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
    assert_int_equal(mqtt_client_set_fixed_header(&(prov_client_ptr -> nx_azure_iot_provisioning_client_resource.resource_mqtt), packet_ptr,
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
    for (i = 0; i < property_count; i++)
    {
        if (i != 0)
        {
            assert_int_equal(__real__nx_packet_data_append(packet_ptr, "&", 1,
                                                           iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                             NX_AZURE_IOT_SUCCESS);
        }
        assert_int_equal(__real__nx_packet_data_append(packet_ptr, properties[i].name, properties[i].name_length,
                                                       iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(__real__nx_packet_data_append(packet_ptr, "=", 1,
                                                       iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(__real__nx_packet_data_append(packet_ptr, properties[i].value, properties[i].value_length,
                                                       iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
    }

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


static VOID generate_response(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                              const UCHAR *topic, ULONG topic_length,
                              const UCHAR *message_payload_ptr, ULONG message_payload_length,
                              UINT retry_after)
{
PROPERTY response_properties[2] = { retry_after_property, req_id_property };
NX_PACKET *packet_ptr;

    /* Check if client expecting response */
    if (g_req_id == 0)
    {
        return;
    }

    response_properties[1].value_length = snprintf(response_properties[1].value,
                                                   response_properties[1].value_length, "%u", g_req_id);
    response_properties[0].value_length = snprintf(response_properties[0].value,
                                                   response_properties[0].value_length, "%u", retry_after);
    /* Put Provisioning response packet to MQTT receive queue.  */
    construct_provisioning_service_response(prov_client_ptr,
                                            &packet_ptr, topic, topic_length,
                                            response_properties,
                                            sizeof(response_properties)/sizeof(response_properties[0]),
                                            message_payload_ptr, message_payload_length);

    prov_client_ptr -> nx_azure_iot_provisioning_client_resource.resource_mqtt.message_receive_queue_head = packet_ptr;
    prov_client_ptr -> nx_azure_iot_provisioning_client_resource.resource_mqtt.message_receive_queue_depth = 1;

    /* Expected callback function to be set. */
    assert_ptr_not_equal(test_receive_notify, NX_NULL);

    /* Simulate callback from MQTT layer.  */
    tx_mutex_get(prov_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, NX_WAIT_FOREVER);
    test_receive_notify(&prov_client_ptr -> nx_azure_iot_provisioning_client_resource.resource_mqtt, 1);
    tx_mutex_put(prov_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    /* response generated for this req_id */
    g_req_id = 0;
}

static VOID generate_good_response(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr)
{
    if (g_req_id == 0)
    {
        return;
    }

    if (g_assigned_response_after == 0)
    {
        generate_response(prov_client_ptr,
                          PROVISIONING_SERVICE_REPONSE_TOPIC,
                          sizeof(PROVISIONING_SERVICE_REPONSE_TOPIC) - 1,
                          assigned_hub_response, sizeof(assigned_hub_response) - 1, 0);
    }
    else
    {
        generate_response(prov_client_ptr,
                          PROVISIONING_SERVICE_REPONSE_TOPIC,
                          sizeof(PROVISIONING_SERVICE_REPONSE_TOPIC) - 1,
                          assigning_hub_response, sizeof(assigning_hub_response) - 1, 3);
        g_assigned_response_after--;
    }
}

static VOID generate_good_response_with_throttle(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr)
{
    if (g_req_id == 0)
    {
        return;
    }

    if (g_assigned_response_after == 0)
    {
        generate_response(prov_client_ptr,
                          PROVISIONING_SERVICE_REPONSE_TOPIC,
                          sizeof(PROVISIONING_SERVICE_REPONSE_TOPIC) - 1,
                          assigned_hub_response, sizeof(assigned_hub_response) - 1, 0);
    }
    else
    {
        generate_response(prov_client_ptr,
                          PROVISIONING_SERVICE_REPONSE_THROTTLE_TOPIC,
                          sizeof(PROVISIONING_SERVICE_REPONSE_THROTTLE_TOPIC) - 1,
                          throttle_hub_response, sizeof(throttle_hub_response) - 1, 31);
        g_assigned_response_after--;
    }
}

static VOID generate_bad_response(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr)
{
    generate_response(prov_client_ptr,
                      PROVISIONING_SERVICE_REPONSE_BAD_TOPIC,
                      sizeof(PROVISIONING_SERVICE_REPONSE_BAD_TOPIC) - 1, " ", 1, 0);
}

static VOID generate_failure_response(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr)
{
    generate_response(prov_client_ptr,
                      PROVISIONING_SERVICE_REPONSE_200_TOPIC,
                      sizeof(PROVISIONING_SERVICE_REPONSE_200_TOPIC) - 1,
                      failure_hub_response, sizeof(failure_hub_response) - 1, 0);
}

static VOID reset_global_state()
{
   /* reset global state */
    g__wrap__nxde_mqtt_client_secure_connect_status = 0;
    g__wrap__nxde_mqtt_client_subscribe_status = 0;
    g__wrap__nxde_mqtt_client_disconnect_status = 0;
    g__wrap__nxd_mqtt_client_publish_packet_send_status = 0;
    g__wrap__nxde_dns_host_by_name_get_status = 0;
    g_done = 0;
    g_req_id = 0;
    g_assigned_response_after = 0;
    g_failed_append_index = (UINT)-1;
    g_total_append = 0;
    g_failed_allocation_index = (UINT)-1;
    g_total_allocation = 0;
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

    /* SUCCESS: iot is deleted. */
    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
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
 * Test provisioning client initialization with invalid parameter
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_initialize_invalid_arguments()
{
    assert_int_not_equal(nx_azure_iot_provisioning_client_initialize(NX_NULL, &iot,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     g_id_scope, sizeof(g_id_scope) - 1,
                                                                     g_reg_id, sizeof(g_reg_id) - 1,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, NX_NULL,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     g_id_scope, sizeof(g_id_scope) - 1,
                                                                     g_reg_id, sizeof(g_reg_id) - 1,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);


    assert_int_not_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     NX_NULL, 0,
                                                                     g_reg_id, sizeof(g_reg_id) - 1,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     NX_NULL, 0,
                                                                     g_reg_id, sizeof(g_reg_id) - 1,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     g_id_scope, sizeof(g_id_scope) - 1,
                                                                     NX_NULL, 0,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);


    assert_int_not_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     "", 0,
                                                                     g_reg_id, sizeof(g_reg_id) - 1,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     "", 0,
                                                                     g_reg_id, sizeof(g_reg_id) - 1,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     g_id_scope, sizeof(g_id_scope) - 1,
                                                                     "", 0,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client set device cert with invalid parameter
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_device_cert_set_invalid_arguments()
{
    assert_int_not_equal(nx_azure_iot_provisioning_client_device_cert_set(NX_NULL,
                                                                          &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client set symmetric key with invalid parameter
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_symmetric_key_set_invalid_arguments()
{
    assert_int_not_equal(nx_azure_iot_provisioning_client_symmetric_key_set(NX_NULL,
                                                                            symmetric_key, strlen(symmetric_key)),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_provisioning_client_symmetric_key_set(&iot_prov_client,
                                                                            NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client register with invalid parameter
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_invalid_arguments()
{
    assert_int_not_equal(nx_azure_iot_provisioning_client_register(NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client callback set with invalid parameter
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_completion_callback_set_invalid_arguments()
{
    assert_int_not_equal(nx_azure_iot_provisioning_client_completion_callback_set(NX_NULL, on_complete_callback),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client deinitialization with invalid parameter
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_deinitialize_invalid_arguments()
{
    assert_int_not_equal(nx_azure_iot_provisioning_client_deinitialize(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration payload set with invalid parameter
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_registration_payload_set_invalid_arguments()
{
    assert_int_not_equal(nx_azure_iot_provisioning_client_registration_payload_set(NX_NULL, NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client initialization
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_init_success()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration without initialization
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_without_initialization_fail()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_not_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration fails, if dns failed
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_dns_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);
    g__wrap__nxde_dns_host_by_name_get_status = NX_NOT_SUCCESSFUL;

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration fails, if subscribe fails
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_subscribe_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);
    g__wrap__nxde_mqtt_client_subscribe_status = NX_NOT_SUCCESSFUL;

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration fails, if publish to service fails
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_send_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);
    g__wrap__nxd_mqtt_client_publish_packet_send_status = NX_NOT_SUCCESSFUL;

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration fails, if mqtt client disconnect while waiting for response
 *
 **/
static VOID  test_nx_azure_iot_provisioning_client_register_receive_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);

    /* Expected callback function to be set. */
    assert_ptr_not_equal(test_connect_notify, NX_NULL);
    while (!g_done)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);

        if (g_req_id != 0)
        {
            /* Generate disconnect */
            test_connect_notify(&iot_prov_client.nx_azure_iot_provisioning_client_resource.resource_mqtt,
                                NXD_MQTT_CONNECT_FAILURE, test_connect_notify_context);
        }
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_DISCONNECTED);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);

}

/**
 * Test provisioning client registration fails, if bad response received by client
 *
 **/
static VOID  test_nx_azure_iot_provisioning_client_register_receive_bad_response_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_bad_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration fails, if bad JSON response received by client
 *
 **/
static VOID  test_nx_azure_iot_provisioning_client_register_receive_invalid_json_failed()
{
    printf("test starts =>: %s\n", __func__);

    for (INT index = 0; index < sizeof(invalid_response_data_set)/sizeof(invalid_response_data_set[0]); index++)
    {
        reset_global_state();
        assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     g_id_scope, sizeof(g_id_scope) - 1,
                                                                     g_reg_id, sizeof(g_reg_id) - 1,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                                  on_complete_callback),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                         NX_AZURE_IOT_PENDING);

        while (!g_done)
        {
            generate_response(&iot_prov_client,
                              PROVISIONING_SERVICE_REPONSE_TOPIC,
                              sizeof(PROVISIONING_SERVICE_REPONSE_TOPIC) - 1,
                              invalid_response_data_set[index], strlen(invalid_response_data_set[index]), 3);
            tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
        }

        assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                         NX_AZURE_IOT_SUCCESS);
    }
}

/**
 * Test provisioning client registration succeeds
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_success()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_symmetric_key_set(&iot_prov_client,
                                                                        symmetric_key, strlen(symmetric_key)),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_good_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration failed with failure response
 *
 **/
VOID test_nx_azure_iot_provisioning_client_register_failure_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_symmetric_key_set(&iot_prov_client,
                                                                        symmetric_key, strlen(symmetric_key)),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_failure_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration with payload succeeds
 *
 **/
VOID test_nx_azure_iot_provisioning_client_register_with_payload_success()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_symmetric_key_set(&iot_prov_client,
                                                                        symmetric_key, strlen(symmetric_key)),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_registration_payload_set(&iot_prov_client,
                                                                               CUSTOM_PAYLOAD, sizeof(CUSTOM_PAYLOAD) - 1),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_good_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration fails with allocation fail
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_allocation_fail_failure()
{
UINT total_allocation_in_success_case;
UINT status;

    printf("test starts =>: %s\n", __func__);

    test_nx_azure_iot_provisioning_client_register_success();
    total_allocation_in_success_case = g_total_allocation;

    for (INT index = 0; index < total_allocation_in_success_case; index++)
    {
        reset_global_state();
        g_failed_allocation_index = index;

        status = nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                             g_endpoint, sizeof(g_endpoint) - 1,
                                                             g_id_scope, sizeof(g_id_scope) - 1,
                                                             g_reg_id, sizeof(g_reg_id) - 1,
                                                             _nx_azure_iot_tls_supported_crypto,
                                                             _nx_azure_iot_tls_supported_crypto_size,
                                                             _nx_azure_iot_tls_ciphersuite_map,
                                                             _nx_azure_iot_tls_ciphersuite_map_size,
                                                             metadata_buffer, sizeof(metadata_buffer),
                                                             &root_ca_cert);

        if (status)
        {
            continue;
        }

        status = nx_azure_iot_provisioning_client_symmetric_key_set(&iot_prov_client,
                                                                    symmetric_key, strlen(symmetric_key));
        if (status)
        {
            assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                             NX_AZURE_IOT_SUCCESS);
            continue;
        }

        assert_int_equal(nx_azure_iot_provisioning_client_registration_payload_set(&iot_prov_client,
                                                                                   CUSTOM_PAYLOAD,
                                                                                   sizeof(CUSTOM_PAYLOAD) - 1),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                                  on_complete_callback),
                         NX_AZURE_IOT_SUCCESS);

        status = nx_azure_iot_provisioning_client_register(&iot_prov_client, 0);
        if (status != NX_AZURE_IOT_PENDING)
        {
            assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                             NX_AZURE_IOT_SUCCESS);
            continue;
        }

        while (!g_done)
        {
            generate_good_response(&iot_prov_client);
            tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
        }

        assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                         NX_AZURE_IOT_SUCCESS);
    }
}

/**
 * Test provisioning client registration fails with append data
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_append_data_fail_failure()
{
UINT total_append_in_success_case;
UINT status;

    printf("test starts =>: %s\n", __func__);

    test_nx_azure_iot_provisioning_client_register_success();
    total_append_in_success_case = g_total_append;

    for (INT index = 0; index < total_append_in_success_case; index++)
    {
        reset_global_state();
        g_failed_append_index = index;

        status = nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                             g_endpoint, sizeof(g_endpoint) - 1,
                                                             g_id_scope, sizeof(g_id_scope) - 1,
                                                             g_reg_id, sizeof(g_reg_id) - 1,
                                                             _nx_azure_iot_tls_supported_crypto,
                                                             _nx_azure_iot_tls_supported_crypto_size,
                                                             _nx_azure_iot_tls_ciphersuite_map,
                                                             _nx_azure_iot_tls_ciphersuite_map_size,
                                                             metadata_buffer, sizeof(metadata_buffer),
                                                             &root_ca_cert);

        if (status)
        {
            continue;
        }

        assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                                  on_complete_callback),
                         NX_AZURE_IOT_SUCCESS);

        status = nx_azure_iot_provisioning_client_register(&iot_prov_client, 0);
        if (status != NX_AZURE_IOT_PENDING)
        {
            assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                             NX_AZURE_IOT_SUCCESS);
            continue;
        }

        while (!g_done)
        {
            generate_good_response(&iot_prov_client);
            tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
        }

        assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                         NX_AZURE_IOT_SUCCESS);
    }
}

/**
 * Test provisioning client registration succeeds, when throttled by service.
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_with_throttle_response_success()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    g_assigned_response_after = 3;
    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_good_response_with_throttle(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration succeeds, when throttled by service after assigning .
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_with_throttle_response_2_success()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    g_assigned_response_after = 3;
    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        if (g_assigned_response_after == 3)
        {
            generate_good_response(&iot_prov_client);
        }
        else
        {
            generate_good_response_with_throttle(&iot_prov_client);
        }

        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration succeeds, when multiple request required.
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_with_multiple_response_success()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    g_assigned_response_after = 3;
    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_good_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration blocking fails, if dns failed
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_dns_blocking_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);
    g__wrap__nxde_dns_host_by_name_get_status = NX_NOT_SUCCESSFUL;

    assert_int_not_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration blocking fails, if subscribe fails
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_subscribe_blocking_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    g__wrap__nxde_mqtt_client_subscribe_status = NX_NOT_SUCCESSFUL;

    assert_int_not_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration blocking fails, if publish to service fails
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_send_blocking_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    g__wrap__nxd_mqtt_client_publish_packet_send_status = NX_NOT_SUCCESSFUL;

    assert_int_not_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration blocking fails, if mqtt client disconnect while waiting for response
 *
 **/
static VOID  test_nx_azure_iot_provisioning_client_register_receive_blocking_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, TEST_DEFAULT_WAIT_TIME),
                     NX_AZURE_IOT_PENDING);

    /* Expected callback function to be set. */
    assert_ptr_not_equal(test_connect_notify, NX_NULL);
    while (!g_done)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);

        if (g_reg_id != 0)
        {
            /* Generate disconnect */
            test_connect_notify(&iot_prov_client.nx_azure_iot_provisioning_client_resource.resource_mqtt,
                                NXD_MQTT_CONNECT_FAILURE, test_connect_notify_context);
        }
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_DISCONNECTED);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);

}

/**
 * Test provisioning client registration blocking fails, if bad response received by client
 *
 **/
static VOID  test_nx_azure_iot_provisioning_client_register_receive_bad_response_blocking_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, TEST_DEFAULT_WAIT_TIME),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_bad_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration blocking fails, if bad JSON response received by client
 *
 **/
static VOID  test_nx_azure_iot_provisioning_client_register_receive_invalid_json_blocking_failed()
{
    printf("test starts =>: %s\n", __func__);

    for (INT index = 0; index < sizeof(invalid_response_data_set)/sizeof(invalid_response_data_set[0]); index++)
    {
        reset_global_state();
        assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                     g_endpoint, sizeof(g_endpoint) - 1,
                                                                     g_id_scope, sizeof(g_id_scope) - 1,
                                                                     g_reg_id, sizeof(g_reg_id) - 1,
                                                                     _nx_azure_iot_tls_supported_crypto,
                                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                                     metadata_buffer, sizeof(metadata_buffer),
                                                                     &root_ca_cert),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                                  on_complete_callback),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, TEST_DEFAULT_WAIT_TIME),
                         NX_AZURE_IOT_PENDING);

        while (!g_done)
        {
            generate_response(&iot_prov_client,
                              PROVISIONING_SERVICE_REPONSE_TOPIC,
                              sizeof(PROVISIONING_SERVICE_REPONSE_TOPIC) - 1,
                              invalid_response_data_set[index], strlen(invalid_response_data_set[index]), 3);
            tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
        }

        assert_int_not_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                         NX_AZURE_IOT_SUCCESS);
    }
}

/**
 * Test provisioning client registration blocking succeeds
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_blocking_success()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, TEST_DEFAULT_WAIT_TIME),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_good_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration blocking succeeds, when multiple request required.
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_register_with_multiple_response_blocking_success()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    g_assigned_response_after = 3;
    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, TEST_DEFAULT_WAIT_TIME),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_good_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client registration fails, if mqtt client disconnect while waiting for response
 *
 **/
static VOID  test_nx_azure_iot_provisioning_client_register_disconnect_failed()
{
    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, 0),
                     NX_AZURE_IOT_PENDING);

    /* Expected callback function to be set. */
    assert_ptr_not_equal(test_connect_notify, NX_NULL);
    while (!g_done)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);

        if (g_reg_id != 0)
        {
            /* Generate disconnect */
            test_disconnect_notify(&iot_prov_client.nx_azure_iot_provisioning_client_resource.resource_mqtt);
        }
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_DISCONNECTED);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);

}

/**
 * Test provisioning client iothub device get fails if invalid arguments passed.
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_iothub_device_info_invalid_arguments_failed()
{
UINT iothub_hostname_len = 0;
UINT device_id_len =  0;

    printf("test starts =>: %s\n", __func__);
    assert_int_not_equal(nx_azure_iot_provisioning_client_iothub_device_info_get(NX_NULL,
                                                                                 iothub_hostname, &iothub_hostname_len,
                                                                                 iothub_device_id, &device_id_len),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_provisioning_client_iothub_device_info_get(&iot_prov_client,
                                                                                 NX_NULL, &iothub_hostname_len,
                                                                                 iothub_device_id, &device_id_len),
                         NX_AZURE_IOT_SUCCESS);


    assert_int_not_equal(nx_azure_iot_provisioning_client_iothub_device_info_get(&iot_prov_client,
                                                                                 iothub_hostname, &iothub_hostname_len,
                                                                                 NX_NULL, &device_id_len),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client iothub device get fails if buffers are too small.
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_iothub_device_info_invalid_state_failed()
{
UINT iothub_hostname_len = sizeof(iothub_hostname);
UINT device_id_len =  sizeof(iothub_device_id);

    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, TEST_DEFAULT_WAIT_TIME),
                     NX_AZURE_IOT_PENDING);
    assert_int_not_equal(nx_azure_iot_provisioning_client_iothub_device_info_get(&iot_prov_client,
                                                                                 iothub_hostname, &iothub_hostname_len,
                                                                                 iothub_device_id, &device_id_len),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client iothub device get fails if buffers are too small.
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_iothub_device_info_oom_failed()
{
UINT iothub_hostname_len = 0;
UINT device_id_len =  0;

    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, TEST_DEFAULT_WAIT_TIME),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_good_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_provisioning_client_iothub_device_info_get(&iot_prov_client,
                                                                                 iothub_hostname, &iothub_hostname_len,
                                                                                 iothub_device_id, &device_id_len),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test provisioning client iothub device get succeeds.
 *
 **/
static VOID test_nx_azure_iot_provisioning_client_iothub_device_info_success()
{
UINT iothub_hostname_len = sizeof(iothub_hostname);
UINT device_id_len =  sizeof(iothub_device_id);

    printf("test starts =>: %s\n", __func__);
    assert_int_equal(nx_azure_iot_provisioning_client_initialize(&iot_prov_client, &iot,
                                                                 g_endpoint, sizeof(g_endpoint) - 1,
                                                                 g_id_scope, sizeof(g_id_scope) - 1,
                                                                 g_reg_id, sizeof(g_reg_id) - 1,
                                                                 _nx_azure_iot_tls_supported_crypto,
                                                                 _nx_azure_iot_tls_supported_crypto_size,
                                                                 _nx_azure_iot_tls_ciphersuite_map,
                                                                 _nx_azure_iot_tls_ciphersuite_map_size,
                                                                 metadata_buffer, sizeof(metadata_buffer),
                                                                 &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_completion_callback_set(&iot_prov_client,
                                                                              on_complete_callback),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_provisioning_client_register(&iot_prov_client, TEST_DEFAULT_WAIT_TIME),
                     NX_AZURE_IOT_PENDING);
    while (!g_done)
    {
        generate_good_response(&iot_prov_client);
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
    }

    assert_int_equal(iot_prov_client.nx_azure_iot_provisioning_client_result, NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_provisioning_client_iothub_device_info_get(&iot_prov_client,
                                                                             iothub_hostname, &iothub_hostname_len,
                                                                             iothub_device_id, &device_id_len),
                     NX_AZURE_IOT_SUCCESS);
    assert_memory_equal(iothub_hostname, assigned_hub_name, strlen(assigned_hub_name));
    assert_memory_equal(iothub_device_id, assigned_device_id, strlen(assigned_device_id));
    assert_int_equal(nx_azure_iot_provisioning_client_deinitialize(&iot_prov_client),
                     NX_AZURE_IOT_SUCCESS);
}

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
    NX_AZURE_TEST_FN tests[] = { test_nx_azure_iot_provisioning_client_initialize_invalid_arguments,
                               test_nx_azure_iot_provisioning_client_device_cert_set_invalid_arguments,
                               test_nx_azure_iot_provisioning_client_symmetric_key_set_invalid_arguments,
                               test_nx_azure_iot_provisioning_client_register_invalid_arguments,
                               test_nx_azure_iot_provisioning_client_completion_callback_set_invalid_arguments,
                               test_nx_azure_iot_provisioning_client_deinitialize_invalid_arguments,
                               test_nx_azure_iot_provisioning_client_registration_payload_set_invalid_arguments,
                               test_nx_azure_iot_provisioning_client_register_without_initialization_fail,
                               test_nx_azure_iot_provisioning_client_init_success,
                               test_nx_azure_iot_provisioning_client_register_dns_failed,
                               test_nx_azure_iot_provisioning_client_register_subscribe_failed,
                               test_nx_azure_iot_provisioning_client_register_send_failed,
                               test_nx_azure_iot_provisioning_client_register_receive_failed,
                               test_nx_azure_iot_provisioning_client_register_receive_bad_response_failed,
                               test_nx_azure_iot_provisioning_client_register_receive_invalid_json_failed,
                               test_nx_azure_iot_provisioning_client_register_allocation_fail_failure,
                               test_nx_azure_iot_provisioning_client_register_append_data_fail_failure,
                               test_nx_azure_iot_provisioning_client_register_success,
                               test_nx_azure_iot_provisioning_client_register_failure_failed,
                               test_nx_azure_iot_provisioning_client_register_with_payload_success,
                               test_nx_azure_iot_provisioning_client_register_with_throttle_response_success,
                               test_nx_azure_iot_provisioning_client_register_with_throttle_response_2_success,
                               test_nx_azure_iot_provisioning_client_register_with_multiple_response_success,
                               test_nx_azure_iot_provisioning_client_register_dns_blocking_failed,
                               test_nx_azure_iot_provisioning_client_register_subscribe_blocking_failed,
                               test_nx_azure_iot_provisioning_client_register_send_blocking_failed,
                               test_nx_azure_iot_provisioning_client_register_receive_blocking_failed,
                               test_nx_azure_iot_provisioning_client_register_receive_bad_response_blocking_failed,
                               test_nx_azure_iot_provisioning_client_register_receive_invalid_json_blocking_failed,
                               test_nx_azure_iot_provisioning_client_register_blocking_success,
                               test_nx_azure_iot_provisioning_client_register_with_multiple_response_blocking_success,
                               test_nx_azure_iot_provisioning_client_register_disconnect_failed,
                               test_nx_azure_iot_provisioning_client_iothub_device_info_invalid_arguments_failed,
                               test_nx_azure_iot_provisioning_client_iothub_device_info_invalid_state_failed,
                               test_nx_azure_iot_provisioning_client_iothub_device_info_oom_failed,
                               test_nx_azure_iot_provisioning_client_iothub_device_info_success };
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
