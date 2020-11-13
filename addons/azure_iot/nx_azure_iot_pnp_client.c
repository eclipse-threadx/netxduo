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

/* Version: 6.1 PnP Preview 1 */

#include "nx_azure_iot_pnp_client.h"

#include "azure/core/az_version.h"

#define NX_AZURE_IOT_PNP_CLIENT_U32_MAX_BUFFER_SIZE     10
#define NX_AZURE_IOT_PNP_CLIENT_EMPTY_JSON              "{}"
#define NX_AZURE_IOT_PNP_CLIENT_THROTTLE_STATUS_CODE    429

#ifndef NX_AZURE_IOT_PNP_CLIENT_USER_AGENT

/* Useragent e.g: DeviceClientType=c%2F1.0.0-preview.1%20%28nx%206.0%3Bazrtos%206.0%29 */
#define NX_AZURE_IOT_PNP_CLIENT_STR(C)          #C
#define NX_AZURE_IOT_PNP_CLIENT_TO_STR(x)       NX_AZURE_IOT_PNP_CLIENT_STR(x)
#define NX_AZURE_IOT_PNP_CLIENT_USER_AGENT      "DeviceClientType=c%2F" AZ_SDK_VERSION_STRING "%20%28nx%20" \
                                                NX_AZURE_IOT_PNP_CLIENT_TO_STR(NETXDUO_MAJOR_VERSION) "." \
                                                NX_AZURE_IOT_PNP_CLIENT_TO_STR(NETXDUO_MINOR_VERSION) "%3Bazrtos%20"\
                                                NX_AZURE_IOT_PNP_CLIENT_TO_STR(THREADX_MAJOR_VERSION) "." \
                                                NX_AZURE_IOT_PNP_CLIENT_TO_STR(THREADX_MINOR_VERSION) "%29"
#endif /* NX_AZURE_IOT_PNP_CLIENT_USER_AGENT */

/* Queue index used in transport to receive the messages */
#define NX_AZURE_IOT_PNP_COMMAND_QUEUE_INDEX                                        0
#define NX_AZURE_IOT_PNP_PROPERTIES_QUEUE_INDEX                                     1
#define NX_AZURE_IOT_PNP_DESIRED_PROPERTIES_QUEUE_INDEX                             2
#define NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX                   3

extern UINT _nxd_mqtt_process_publish_packet(NX_PACKET *packet_ptr, ULONG *topic_offset_ptr,
                                             USHORT *topic_length_ptr, ULONG *message_offset_ptr,
                                             ULONG *message_length_ptr);

static UINT nx_azure_iot_pnp_client_mesg_type_to_queue_index(UINT message_type)
{
UINT queue_index;

    switch (message_type)
    {
        case NX_AZURE_IOT_PNP_COMMAND :
        {
            queue_index = NX_AZURE_IOT_PNP_COMMAND_QUEUE_INDEX;
        }
        break;

        case NX_AZURE_IOT_PNP_PROPERTIES :
        {
            queue_index = NX_AZURE_IOT_PNP_PROPERTIES_QUEUE_INDEX;
        }
        break;

        case NX_AZURE_IOT_PNP_DESIRED_PROPERTIES :
        {
            queue_index = NX_AZURE_IOT_PNP_DESIRED_PROPERTIES_QUEUE_INDEX;
        }
        break;

        case NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE :
        {
            queue_index = NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX;
        }
        break;

        default :
        {
            /* no queue */
            queue_index = NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE;
        }
        break;
    }

    return(queue_index);
}

static UINT nx_azure_iot_pnp_client_command_process(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                    NX_PACKET *packet_ptr,
                                                    ULONG topic_offset,
                                                    USHORT topic_length)
{
UCHAR *topic_name;
az_iot_pnp_client_command_request request;
az_span receive_topic;
az_result core_result;
NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr = (NX_AZURE_IOT_PNP_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    /* This function is protected by MQTT mutex.  */

    /* Check message type first.  */
    topic_name = &(packet_ptr -> nx_packet_prepend_ptr[topic_offset]);

    /* NOTE: Current implementation does not support topic to span multiple packets.  */
    if ((ULONG)(packet_ptr -> nx_packet_append_ptr - topic_name) < topic_length)
    {
        LogError(LogLiteralArgs("topic out of boundaries of single packet"));
        return(NX_AZURE_IOT_TOPIC_TOO_LONG);
    }

    receive_topic = az_span_create(topic_name, topic_length);
    core_result = az_iot_pnp_client_commands_parse_received_topic(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                  receive_topic, &request);
    if (az_result_failed(core_result))
    {

        /* Topic name does not match command format.  */
        return(NX_AZURE_IOT_NOT_FOUND);
    }

    return(nx_azure_iot_hub_transport_receive_notify(hub_trans_ptr, packet_ptr,
                                                     NX_AZURE_IOT_PNP_COMMAND_QUEUE_INDEX, 0));
}

static UINT nx_azure_iot_pnp_client_twin_request_id_get(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        UCHAR *buffer_ptr, UINT buffer_len,
                                                        az_span *request_id_span_ptr,
                                                        UINT *request_id_ptr, UINT odd_seq)
{
az_span span;

    /* Obtain the mutex.  */
    tx_mutex_get(pnp_client_ptr -> nx_azure_iot_pnp_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Check if current request_id is even and new requested is also even or
       current request_id is odd and new requested is also odd.  */
    if ((pnp_client_ptr -> nx_azure_iot_pnp_client_request_id & 0x1) == odd_seq)
    {
        pnp_client_ptr -> nx_azure_iot_pnp_client_request_id += 2;
    }
    else
    {
        pnp_client_ptr -> nx_azure_iot_pnp_client_request_id += 1;
    }

    if (pnp_client_ptr -> nx_azure_iot_pnp_client_request_id == 0)
    {
        pnp_client_ptr -> nx_azure_iot_pnp_client_request_id = 2;
    }

    *request_id_ptr = pnp_client_ptr -> nx_azure_iot_pnp_client_request_id;
    span = az_span_create(buffer_ptr, (INT)buffer_len);
    if (az_result_failed(az_span_u32toa(span, *request_id_ptr, &span)))
    {

        /* Release the mutex.  */
        tx_mutex_put(pnp_client_ptr -> nx_azure_iot_pnp_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        LogError(LogLiteralArgs("IoT PnP client device failed to u32toa"));
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    *request_id_span_ptr = az_span_create(buffer_ptr, (INT)(buffer_len - (UINT)az_span_size(span)));

    /* Release the mutex.  */
    tx_mutex_put(pnp_client_ptr -> nx_azure_iot_pnp_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT nx_azure_iot_pnp_client_device_twin_message_type_get(az_iot_pnp_client_property_response *out_twin_response_ptr,
                                                                 UINT request_id)
{
UINT message_type;

    switch (out_twin_response_ptr -> response_type)
    {
        case AZ_IOT_PNP_CLIENT_PROPERTY_RESPONSE_TYPE_GET :

        /* Fall through.  */

        case AZ_IOT_PNP_CLIENT_PROPERTY_RESPONSE_TYPE_REPORTED_PROPERTIES :
        {

            /* Odd requests are of reported properties and even of twin properties.  */
            message_type = request_id % 2 == 0 ? NX_AZURE_IOT_PNP_PROPERTIES :
                            NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE;
        }
        break;

        case AZ_IOT_PNP_CLIENT_PROPERTY_RESPONSE_TYPE_DESIRED_PROPERTIES :
        {
            message_type = NX_AZURE_IOT_PNP_DESIRED_PROPERTIES;
        }
        break;

        default :
        {
            message_type = NX_AZURE_IOT_PNP_NONE;
        }
    }

    return message_type;
}

static UINT nx_azure_iot_pnp_client_device_twin_parse(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      NX_PACKET *packet_ptr, ULONG topic_offset,
                                                      USHORT topic_length, UINT *request_id_ptr,
                                                      ULONG *version_ptr, UINT *message_type_ptr,
                                                      UINT *status_ptr)
{
az_result core_result;
az_span topic_span;
az_iot_pnp_client_property_response out_twin_response;
uint32_t request_id = 0;
uint32_t version;

    topic_span = az_span_create(&(packet_ptr -> nx_packet_prepend_ptr[topic_offset]), (INT)topic_length);
    core_result = az_iot_pnp_client_property_parse_received_topic(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                  topic_span, &out_twin_response);
    if (az_result_failed(core_result))
    {
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    if (version_ptr != NX_NULL && az_span_ptr(out_twin_response.version))
    {
        core_result = az_span_atou32(out_twin_response.version, &version);
        if (az_result_failed(core_result))
        {
            return(NX_AZURE_IOT_SDK_CORE_ERROR);
        }

        *version_ptr = (ULONG)version;
    }

    if (az_span_ptr(out_twin_response.request_id))
    {
        core_result = az_span_atou32(out_twin_response.request_id, &request_id);
        if (az_result_failed(core_result))
        {
            return(NX_AZURE_IOT_SDK_CORE_ERROR);
        }
    }

    if (request_id_ptr)
    {
        *request_id_ptr = (UINT)request_id;
    }

    if (message_type_ptr)
    {
        *message_type_ptr = nx_azure_iot_pnp_client_device_twin_message_type_get(&out_twin_response,
                                                                                 (UINT)request_id);
    }

    if (status_ptr)
    {
        *status_ptr = (UINT)out_twin_response.status;
    }

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT nx_azure_iot_pnp_client_throttle_with_jitter(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr)
{
UINT jitter;
UINT base_delay = NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_IN_SEC;
UINT retry_count = pnp_client_ptr -> nx_azure_iot_pnp_client_throttle_count;
uint64_t delay;

    if (retry_count < (sizeof(UINT) * 8 - 1))
    {
        retry_count++;
        delay = (uint64_t)((1 << retry_count) * NX_AZURE_IOT_PNP_CLIENT_INITIAL_BACKOFF_IN_SEC);

        if (delay <= (UINT)(-1))
        {
            base_delay = (UINT)delay;
        }
    }

    if (base_delay > NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_IN_SEC)
    {
        base_delay = NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_IN_SEC;
    }
    else
    {
       pnp_client_ptr -> nx_azure_iot_pnp_client_throttle_count = retry_count;
    }

    jitter = base_delay * NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_JITTER_PERCENT * (NX_RAND() & 0xFF) / 25600;
    return((UINT)(base_delay + jitter));
}

static UINT nx_azure_iot_pnp_client_throttled_check(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr)
{
ULONG current_time;
UINT status = NX_AZURE_IOT_SUCCESS;

    if (pnp_client_ptr -> nx_azure_iot_pnp_client_throttle_count != 0)
    {
        if ((status = nx_azure_iot_unix_time_get(pnp_client_ptr -> nx_azure_iot_pnp_client_transport.nx_azure_iot_ptr, &current_time)))
        {
            LogError(LogLiteralArgs("IoT PnP client fail to get unix time: %d"), status);
            return(status);
        }

        if (current_time < pnp_client_ptr -> nx_azure_iot_pnp_client_throttle_end_time)
        {
            return(NX_AZURE_IOT_THROTTLED);
        }
    }

    return(status);
}

static UINT nx_azure_iot_pnp_client_device_twin_process(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                        NX_PACKET *packet_ptr,
                                                        ULONG topic_offset,
                                                        USHORT topic_length)
{
UINT message_type;
UINT response_status;
UINT request_id = 0;
ULONG version = 0;
UINT correlation_id;
UINT status;
ULONG current_time;
UINT message_queue_index;
NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr = (NX_AZURE_IOT_PNP_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context ;

    /* This function is protected by MQTT mutex. */
    if ((status = nx_azure_iot_pnp_client_device_twin_parse(pnp_client_ptr, packet_ptr,
                                                            topic_offset, topic_length,
                                                            &request_id, &version,
                                                            &message_type, &response_status)))
    {
        return(status);
    }

    if (response_status == NX_AZURE_IOT_PNP_CLIENT_THROTTLE_STATUS_CODE)
    {
        if ((status = nx_azure_iot_unix_time_get(pnp_client_ptr -> nx_azure_iot_pnp_client_transport.nx_azure_iot_ptr, &current_time)))
        {
            LogError(LogLiteralArgs("IoT PnP client fail to get unix time: %d"), status);
            return(status);
        }

        pnp_client_ptr -> nx_azure_iot_pnp_client_throttle_end_time =
            current_time + nx_azure_iot_pnp_client_throttle_with_jitter(pnp_client_ptr);
    }
    else
    {
        pnp_client_ptr -> nx_azure_iot_pnp_client_throttle_count = 0;
        pnp_client_ptr -> nx_azure_iot_pnp_client_throttle_end_time = 0;
    }

    if (message_type == NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE)
    {

        /* Only requested thread should be woken.  */
        correlation_id = request_id;
    }
    else
    {

        /* Any thread can be woken.  */
        correlation_id = 0;
    }

    message_queue_index = nx_azure_iot_pnp_client_mesg_type_to_queue_index(message_type);
    status = nx_azure_iot_hub_transport_receive_notify(hub_trans_ptr, packet_ptr,
                                                       message_queue_index, correlation_id);

    return(status);
}

static az_result nx_azure_iot_pnp_client_client_id_get(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                       UCHAR *buffer, UINT buffer_len, UINT *bytes_copied)
{
NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr = (NX_AZURE_IOT_PNP_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    return(az_iot_pnp_client_get_client_id(&(pnp_client_ptr -> iot_pnp_client_core),
                                           (CHAR *)buffer, buffer_len, bytes_copied));
}

static az_result nx_azure_iot_pnp_client_username_get(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                      UCHAR *buffer, UINT buffer_len, UINT *bytes_copied)
{
NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr = (NX_AZURE_IOT_PNP_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    return(az_iot_pnp_client_get_user_name(&pnp_client_ptr -> iot_pnp_client_core,
                                           (CHAR *)buffer, buffer_len, bytes_copied));
}

static az_result nx_azure_iot_pnp_client_signature_get(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                       ULONG expiry_time_secs, az_span buffer, az_span *out_buffer)
{
NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr = (NX_AZURE_IOT_PNP_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    return(az_iot_pnp_client_sas_get_signature(&(pnp_client_ptr -> iot_pnp_client_core),
                                               expiry_time_secs, buffer, out_buffer));
}

static az_result nx_azure_iot_pnp_client_password_get(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                      ULONG expiry_time_secs, az_span hash_buffer, az_span key_name,
                                                      UCHAR *out_buffer, UINT out_buffer_len, UINT *bytes_copied)
{
NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr = (NX_AZURE_IOT_PNP_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    return(az_iot_pnp_client_sas_get_password(&(pnp_client_ptr -> iot_pnp_client_core),
                                              expiry_time_secs, hash_buffer, key_name,
                                              (CHAR *)out_buffer, out_buffer_len, bytes_copied));
}

static VOID nx_azure_iot_pnp_client_receive_callback(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                     NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg1,
                                                     VOID *arg2)
{
NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr = (NX_AZURE_IOT_PNP_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    ((VOID (*)(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr, VOID *args))arg1)(pnp_client_ptr, arg2);
}

static VOID nx_azure_iot_pnp_client_connection_status_callback(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                               UINT status, NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg)
{
NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr = (NX_AZURE_IOT_PNP_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    ((VOID (*)(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr, UINT status))arg)(pnp_client_ptr, status);
}

static VOID nx_azure_iot_pnp_client_reported_property_receive_callback(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                                       NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg1,
                                                                       VOID *arg2)
{
NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr = (NX_AZURE_IOT_PNP_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;
UINT status;
NX_PACKET *packet_ptr;
ULONG topic_offset;
USHORT topic_length;
UINT request_id;
UINT response_status;
ULONG version = 0;

    if ((status = nx_azure_iot_hub_transport_message_receive(hub_trans_ptr,
                                                             NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX, 0,
                                                             &packet_ptr, NX_NO_WAIT)))
    {
        LogError(LogLiteralArgs("IoTHub failed to find reported property: %d"), status);
        return;
    }

    if (nx_azure_iot_hub_transport_process_publish_packet(packet_ptr -> nx_packet_prepend_ptr, &topic_offset,
                                                          &topic_length))
    {

        /* Message not supported. It will be released.  */
        nx_packet_release(packet_ptr);
        return;
    }

    if ((status = nx_azure_iot_pnp_client_device_twin_parse(pnp_client_ptr, packet_ptr,
                                                            topic_offset, topic_length,
                                                            &request_id, &version,
                                                            NX_NULL, &response_status)))
    {
        nx_packet_release(packet_ptr);
        return;
    }

    ((VOID (*)(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
               UINT request_id, UINT response_status,
               ULONG version, VOID *arg))arg1)(pnp_client_ptr,
                                             request_id,
                                             response_status,
                                             version,
                                             arg2);
    nx_packet_release(packet_ptr);
}

UINT nx_azure_iot_pnp_client_initialize(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                        NX_AZURE_IOT *nx_azure_iot_ptr,
                                        const UCHAR *host_name, UINT host_name_length,
                                        const UCHAR *device_id, UINT device_id_length,
                                        const UCHAR *module_id, UINT module_id_length,
                                        const UCHAR *model_id, UINT model_id_length,
                                        const NX_CRYPTO_METHOD **crypto_array, UINT crypto_array_size,
                                        const NX_CRYPTO_CIPHERSUITE **cipher_map, UINT cipher_map_size,
                                        UCHAR *metadata_memory, UINT memory_size,
                                        NX_SECURE_X509_CERT *trusted_certificate)
{

UINT status;
az_span hostname_span = az_span_create((UCHAR *)host_name, (INT)host_name_length);
az_span device_id_span = az_span_create((UCHAR *)device_id, (INT)device_id_length);
az_span model_id_span = az_span_create((UCHAR *)model_id, (INT)model_id_length);
az_iot_pnp_client_options options = az_iot_pnp_client_options_default();
az_result core_result;

    if ((nx_azure_iot_ptr == NX_NULL) || (pnp_client_ptr == NX_NULL) || (host_name == NX_NULL) ||
        (device_id == NX_NULL) || (host_name_length == 0) || (device_id_length == 0) ||
        (model_id == NX_NULL) || (model_id_length == 0))
    {
        LogError(LogLiteralArgs("IoT PnP client initialization fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    memset(pnp_client_ptr, 0, sizeof(NX_AZURE_IOT_PNP_CLIENT));

    options.module_id = az_span_create((UCHAR *)module_id, (INT)module_id_length);
    options.user_agent = AZ_SPAN_FROM_STR(NX_AZURE_IOT_PNP_CLIENT_USER_AGENT);
    options.component_names = pnp_client_ptr -> nx_azure_iot_pnp_client_component_list;
    options.component_names_length = 0;

    core_result = az_iot_pnp_client_init(&pnp_client_ptr -> iot_pnp_client_core,
                                         hostname_span, device_id_span, model_id_span, &options);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoT PnP client failed initialization with error status: %d"), core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    status = nx_azure_iot_hub_transport_initialize(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                   nx_azure_iot_ptr, host_name, host_name_length,
                                                   nx_azure_iot_pnp_client_client_id_get,
                                                   nx_azure_iot_pnp_client_username_get,
                                                   crypto_array, crypto_array_size,
                                                   cipher_map, cipher_map_size,
                                                   metadata_memory, memory_size,
                                                   trusted_certificate, (VOID *)pnp_client_ptr);
    if (status)
    {
        LogError(LogLiteralArgs("IoTPnP client failed  to initialization transport with error status: %d"), core_result);
        return(status);
    }

    /* Enable all the features */
    if ((status = nx_azure_iot_hub_transport_receive_message_enable(&(pnp_client_ptr ->nx_azure_iot_pnp_client_transport),
                                                                    NX_AZURE_IOT_PNP_COMMAND_QUEUE_INDEX,
                                                                    (const UCHAR *)AZ_IOT_PNP_CLIENT_COMMANDS_SUBSCRIBE_TOPIC,
                                                                    sizeof(AZ_IOT_PNP_CLIENT_COMMANDS_SUBSCRIBE_TOPIC) - 1,
                                                                    nx_azure_iot_pnp_client_command_process)) ||
        (status = nx_azure_iot_hub_transport_receive_message_enable(&(pnp_client_ptr ->nx_azure_iot_pnp_client_transport),
                                                                    NX_AZURE_IOT_PNP_PROPERTIES_QUEUE_INDEX,
                                                                    (const UCHAR *)AZ_IOT_PNP_CLIENT_PROPERTY_RESPONSE_SUBSCRIBE_TOPIC,
                                                                    sizeof(AZ_IOT_PNP_CLIENT_PROPERTY_RESPONSE_SUBSCRIBE_TOPIC) - 1,
                                                                    nx_azure_iot_pnp_client_device_twin_process)) ||
        (status = nx_azure_iot_hub_transport_receive_message_enable(&(pnp_client_ptr ->nx_azure_iot_pnp_client_transport),
                                                                    NX_AZURE_IOT_PNP_DESIRED_PROPERTIES_QUEUE_INDEX,
                                                                    (const UCHAR *)AZ_IOT_PNP_CLIENT_PROPERTY_PATCH_SUBSCRIBE_TOPIC,
                                                                    sizeof(AZ_IOT_PNP_CLIENT_PROPERTY_PATCH_SUBSCRIBE_TOPIC) - 1,
                                                                    NX_NULL)) ||
        (status = nx_azure_iot_hub_transport_receive_message_enable(&(pnp_client_ptr ->nx_azure_iot_pnp_client_transport),
                                                                    NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX,
                                                                    NX_NULL, 0,
                                                                    NX_NULL)))
    {
        LogError(LogLiteralArgs("IoTPnP client failed to enable pnp features : %d"), status);
        nx_azure_iot_hub_transport_deinitialize(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport));
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_deinitialize(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr)
{

    /* Check for invalid input pointers.  */
    if (pnp_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTPnP client deinitialize fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_deinitialize(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport)));
}

UINT nx_azure_iot_pnp_client_component_add(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                           const UCHAR *component_name_ptr,
                                           UINT component_name_length)
{
UINT length_of_componet_list;

    if ((pnp_client_ptr == NX_NULL) ||
        (component_name_ptr == NX_NULL) ||
        (component_name_length == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP add component fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    tx_mutex_get(pnp_client_ptr -> nx_azure_iot_pnp_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    length_of_componet_list =
        (UINT)pnp_client_ptr -> iot_pnp_client_core._internal.options.component_names_length;

    if (length_of_componet_list >= NX_AZURE_IOT_PNP_CLIENT_MAX_PNP_COMPONENT_LIST)
    {
        LogError(LogLiteralArgs("IoT PnP fail due to buffer insufficient"));
        tx_mutex_put(pnp_client_ptr -> nx_azure_iot_pnp_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    /* Using internal fields for faster update */
    pnp_client_ptr -> nx_azure_iot_pnp_client_component_list[length_of_componet_list] =
        az_span_create((UCHAR *)component_name_ptr, (INT)component_name_length);
    pnp_client_ptr -> iot_pnp_client_core._internal.options.component_names_length++;

    tx_mutex_put(pnp_client_ptr -> nx_azure_iot_pnp_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_device_cert_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                             NX_SECURE_X509_CERT *device_certificate)
{
    if (pnp_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTPnP device certificate set fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_device_cert_set(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                      device_certificate));
}

UINT nx_azure_iot_pnp_client_symmetric_key_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                               const UCHAR *symmetric_key, UINT symmetric_key_length)
{
    if (pnp_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTPnP client symmetric key fail: Invalid argument"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_symmetric_key_auth_set(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                             nx_azure_iot_pnp_client_signature_get,
                                                             nx_azure_iot_pnp_client_password_get,
                                                             symmetric_key, symmetric_key_length));
}

UINT nx_azure_iot_pnp_client_connect(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                     UINT clean_session, UINT wait_option)
{

    /* Check for invalid input pointers.  */
    if (pnp_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTPnP client connect fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_connect(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                              clean_session, wait_option));
}

UINT nx_azure_iot_pnp_client_disconnect(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr)
{

    /* Check for invalid input pointers.  */
    if (pnp_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTPnP client disconnect fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_disconnect(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport)));
}

UINT nx_azure_iot_pnp_client_connection_status_callback_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                            VOID (*connection_status_cb)(
                                                                  struct NX_AZURE_IOT_PNP_CLIENT_STRUCT *client_ptr,
                                                                  UINT status))
{

    /* Check for invalid input pointers.  */
    if (pnp_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTPnP client connect callback fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_connection_callback_set(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                              nx_azure_iot_pnp_client_connection_status_callback,
                                                              (NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN)connection_status_cb));
}

UINT nx_azure_iot_pnp_client_receive_callback_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                  UINT message_type,
                                                  VOID (*callback_ptr)(
                                                        NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        VOID *args),
                                                  VOID *callback_args)
{
UINT message_queue_index;

    if ((pnp_client_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTPnP receive callback set fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    message_queue_index =  nx_azure_iot_pnp_client_mesg_type_to_queue_index(message_type);

    return(nx_azure_iot_hub_transport_receive_message_callback_set(&(pnp_client_ptr ->nx_azure_iot_pnp_client_transport),
                                                                   message_queue_index,
                                                                   callback_ptr != NX_NULL ? nx_azure_iot_pnp_client_receive_callback : NX_NULL,
                                                                   (NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN)callback_ptr, callback_args));
}

UINT nx_azure_iot_pnp_client_telemetry_message_create(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      const UCHAR *component_name_ptr,
                                                      UINT component_name_length,
                                                      NX_PACKET **packet_pptr,
                                                      UINT wait_option)
{
NX_PACKET *packet_ptr;
UINT topic_length;
UINT status;
az_result core_result;
az_span component_name = az_span_create((UCHAR *)component_name_ptr, (INT)component_name_length);

    if ((pnp_client_ptr == NX_NULL) ||
        (packet_pptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP telemetry message create fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_transport_publish_packet_get(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                           &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("Create telemetry data fail"));
        return(status);
    }

    topic_length = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    core_result = az_iot_pnp_client_telemetry_get_publish_topic(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                component_name, NULL,
                                                                (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                topic_length, &topic_length);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoT PnP client telemetry message create fail with error status: %d"), core_result);
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;
    *packet_pptr = packet_ptr;

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_telemetry_message_delete(NX_PACKET *packet_ptr)
{
    return(nx_packet_release(packet_ptr));
}

UINT nx_azure_iot_pnp_client_telemetry_property_add(NX_PACKET *packet_ptr,
                                                    const UCHAR *property_name,
                                                    USHORT property_name_length,
                                                    const UCHAR *property_value,
                                                    USHORT property_value_length,
                                                    UINT wait_option)
{
    return(nx_azure_iot_topic_property_append(packet_ptr, property_name, property_name_length,
                                              property_value, property_value_length, wait_option));
}

UINT nx_azure_iot_pnp_client_telemetry_send(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                            NX_PACKET *packet_ptr,
                                            const UCHAR *telemetry_data,
                                            UINT data_size, UINT wait_option)
{
    if ((pnp_client_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTPnP telemetry send fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_publish(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport), packet_ptr,
                                              telemetry_data, data_size, NX_AZURE_IOT_PNP_CLIENT_TELEMETRY_QOS, wait_option));
}

UINT nx_azure_iot_pnp_client_command_receive(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                             const UCHAR **component_name_pptr, UINT *component_name_length_ptr,
                                             const UCHAR **pnp_command_name_pptr, UINT *pnp_command_name_length_ptr,
                                             VOID **context_pptr, USHORT *context_length_ptr,
                                             NX_AZURE_IOT_JSON_READER *reader_ptr, UINT wait_option)
{
UINT status;
ULONG topic_offset;
USHORT topic_length;
az_span topic_span;
ULONG message_offset;
ULONG message_length;
NX_PACKET *start_packet_ptr;
NX_PACKET *packet_ptr;
az_result core_result;
az_iot_pnp_client_command_request request;

    if ((pnp_client_ptr == NX_NULL) ||
        (component_name_pptr == NX_NULL) ||
        (component_name_length_ptr == NX_NULL) ||
        (pnp_command_name_pptr == NX_NULL) ||
        (pnp_command_name_length_ptr == NX_NULL) ||
        (context_pptr == NX_NULL) ||
        (context_length_ptr == NX_NULL) ||
        (reader_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP client command receive fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_transport_message_receive(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                        NX_AZURE_IOT_PNP_COMMAND_QUEUE_INDEX, 0,
                                                        &packet_ptr, wait_option);
    if (status)
    {
        return(status);
    }

    status = _nxd_mqtt_process_publish_packet(packet_ptr, &topic_offset, &topic_length, &message_offset, &message_length);
    if (status)
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    topic_span = az_span_create(&(packet_ptr -> nx_packet_prepend_ptr[topic_offset]), topic_length);
    core_result = az_iot_pnp_client_commands_parse_received_topic(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                  topic_span, &request);
    if (az_result_failed(core_result))
    {
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    packet_ptr -> nx_packet_length = message_length;
    start_packet_ptr = packet_ptr;

    /* Adjust packet to pointer to message payload.  */
    while (packet_ptr)
    {
        if ((ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) > message_offset)
        {

            /* This packet contains message payload.  */
            packet_ptr -> nx_packet_prepend_ptr = packet_ptr -> nx_packet_prepend_ptr + message_offset;
            break;
        }

        message_offset -= (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);

        /* Set current packet to empty.  */
        packet_ptr -> nx_packet_prepend_ptr = packet_ptr -> nx_packet_append_ptr;

        /* Move to next packet.  */
        packet_ptr = packet_ptr -> nx_packet_next;
    }

    if ((status = nx_azure_iot_json_reader_init(reader_ptr, start_packet_ptr)))
    {
        nx_packet_release(start_packet_ptr);
        return(status);
    }

    *component_name_pptr = (const UCHAR *)az_span_ptr(request.component_name);
    *component_name_length_ptr = (UINT)az_span_size(request.component_name);
    *pnp_command_name_pptr = (const UCHAR *)az_span_ptr(request.command_name);
    *pnp_command_name_length_ptr = (UINT)az_span_size(request.command_name);
    *context_pptr = (VOID*)az_span_ptr(request.request_id);
    *context_length_ptr =  (USHORT)az_span_size(request.request_id);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_command_message_response(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      UINT status_code, VOID *context_ptr,
                                                      USHORT context_length, const UCHAR *payload_ptr,
                                                      UINT payload_length, UINT wait_option)
{
NX_PACKET *packet_ptr;
UINT topic_length;
az_span request_id_span;
UINT status;
az_result core_result;

    if ((pnp_client_ptr == NX_NULL) ||
        (context_ptr == NX_NULL) ||
        (context_length == 0))
    {
        LogError(LogLiteralArgs("IoT PnP command response fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Prepare response packet.  */
    status = nx_azure_iot_hub_transport_publish_packet_get(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                           &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("Create response data fail"));
        return(status);
    }

    topic_length = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    request_id_span = az_span_create((UCHAR*)context_ptr, (INT)context_length);
    core_result = az_iot_pnp_client_commands_response_get_publish_topic(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                        request_id_span, (USHORT)status_code,
                                                                        (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                        topic_length, &topic_length);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("Failed to create the command response topic"));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;

    if ((payload_ptr == NX_NULL) || (payload_length == 0))
    {
        payload_ptr = (const UCHAR *)NX_AZURE_IOT_PNP_CLIENT_EMPTY_JSON;
        payload_length = sizeof(NX_AZURE_IOT_PNP_CLIENT_EMPTY_JSON) - 1;
    }

    status = nx_azure_iot_hub_transport_publish(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport), packet_ptr,
                                                payload_ptr, payload_length, NX_AZURE_IOT_MQTT_QOS_0, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTPnP client command response fail: PUBLISH FAIL status: %d"), status);
        nx_packet_release(packet_ptr);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_reported_properties_create(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                        UINT wait_option)
{
UINT status;
NX_PACKET *packet_ptr;
UINT request_id;
UCHAR *buffer_ptr;
ULONG buffer_size;
az_span request_id_span;
az_result core_result;
UINT topic_length;

    if ((pnp_client_ptr == NX_NULL) ||
        (writer_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP reported property create fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_transport_publish_packet_get(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                           &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoT PnP client reported state send fail: BUFFER ALLOCATE FAIL"));
        return(status);
    }

    buffer_size = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    if (buffer_size <= NX_AZURE_IOT_PNP_CLIENT_U32_MAX_BUFFER_SIZE)
    {
        LogError(LogLiteralArgs("IoT PnP client reported state send fail: BUFFER INSUFFICENT"));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    buffer_size -= NX_AZURE_IOT_PNP_CLIENT_U32_MAX_BUFFER_SIZE;

    /* Generate odd request id for reported properties send */
    status = nx_azure_iot_pnp_client_twin_request_id_get(pnp_client_ptr,
                                                         (UCHAR *)(packet_ptr -> nx_packet_data_end -
                                                                   NX_AZURE_IOT_PNP_CLIENT_U32_MAX_BUFFER_SIZE),
                                                         NX_AZURE_IOT_PNP_CLIENT_U32_MAX_BUFFER_SIZE,
                                                         &request_id_span, &request_id, NX_TRUE);

    if (status)
    {
        LogError(LogLiteralArgs("IoT PnP client reported state send failed to get request id"));
        nx_packet_release(packet_ptr);
        return(status);
    }

    core_result = az_iot_pnp_client_property_patch_get_publish_topic(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                     request_id_span,
                                                                     (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                     buffer_size, &topic_length);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoT PnP client reported state send fail: NX_AZURE_IOT_PNP_CLIENT_TOPIC_SIZE is too small."));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;

    /* todo: use the macro for this magic number, possibly share it with nx_azure_iot.h */
    buffer_ptr = packet_ptr -> nx_packet_prepend_ptr - 7;

    /* encode topic length */
    buffer_ptr[5] = (UCHAR)(packet_ptr -> nx_packet_length >> 8);
    buffer_ptr[6] = (UCHAR)(packet_ptr -> nx_packet_length & 0xFF);

    /* encode request id */
    buffer_ptr[4] = (UCHAR)((request_id & 0xFF));
    request_id >>= 8;
    buffer_ptr[3] = (UCHAR)((request_id & 0xFF));
    request_id >>= 8;
    buffer_ptr[2] = (UCHAR)((request_id & 0xFF));
    request_id >>= 8;
    buffer_ptr[1] = (UCHAR)(request_id & 0xFF);

    if ((status = nx_azure_iot_json_writer_init(writer_ptr, packet_ptr, wait_option)) ||
        (status = nx_azure_iot_json_writer_append_begin_object(writer_ptr)))
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_reported_property_component_begin(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                               NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                               const UCHAR *component_name_ptr,
                                                               UINT component_name_length)
{
az_result core_result;
az_span component_name = az_span_create((UCHAR *)component_name_ptr, (INT)component_name_length);

    if ((pnp_client_ptr == NX_NULL) ||
        (writer_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP reported property begin fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    core_result = az_iot_pnp_client_property_builder_begin_component(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                     &(writer_ptr -> json_writer), component_name);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoT PnP failed to append component, core error : %d"), core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_reported_property_component_end(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                             NX_AZURE_IOT_JSON_WRITER *writer_ptr)
{
az_result core_result;

    if ((pnp_client_ptr == NX_NULL) ||
        (writer_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP reported property end fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    core_result = az_iot_pnp_client_property_builder_end_component(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                   &(writer_ptr -> json_writer));
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoT PnP failed to append component, core error : %d"), core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_reported_property_status_begin(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                            NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                            const UCHAR *property_name_ptr, UINT property_name_length,
                                                            UINT ack_code, ULONG ack_version,
                                                            const UCHAR *ack_description_ptr, UINT ack_description_length)
{
az_span property_name;
az_span description;
az_result core_result;

    if ((pnp_client_ptr == NX_NULL) ||
        (writer_ptr == NX_NULL) ||
        (property_name_ptr == NX_NULL) ||
        (property_name_length == 0) )
    {
        LogError(LogLiteralArgs("IoT PnP client begin reported status failed: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    property_name = az_span_create((UCHAR *)property_name_ptr, (INT)property_name_length);
    description = az_span_create((UCHAR *)ack_description_ptr, (INT)ack_description_length);

    core_result = az_iot_pnp_client_property_builder_begin_reported_status(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                           &(writer_ptr -> json_writer),
                                                                           property_name, (int32_t)ack_code,
                                                                           (int32_t)ack_version, description);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("Failed to prefix data with core error : %d"), core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_reported_property_status_end(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                          NX_AZURE_IOT_JSON_WRITER *writer_ptr)
{
az_result core_result;

    if ((pnp_client_ptr == NX_NULL) ||
        (writer_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP client end reported status failed: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    core_result = az_iot_pnp_client_property_builder_end_reported_status(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                         &(writer_ptr -> json_writer));
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("Failed to suffix data with core error : %d"), core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_report_properties_response_callback_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                                     VOID (*callback_ptr)(
                                                                           NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                                           UINT request_id,
                                                                           UINT response_status,
                                                                           ULONG version,
                                                                           VOID *args),
                                                                     VOID *callback_args)
{
    if (pnp_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTPnP client device twin set callback fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_receive_message_callback_set(&(pnp_client_ptr ->nx_azure_iot_pnp_client_transport),
                                                                   NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX,
                                                                   callback_ptr != NX_NULL ? nx_azure_iot_pnp_client_reported_property_receive_callback : NX_NULL,
                                                                   (NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN)callback_ptr, callback_args));
}

UINT nx_azure_iot_pnp_client_reported_properties_send(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                      UINT *request_id_ptr, UINT *response_status_ptr,
                                                      ULONG *version_ptr, UINT wait_option)
{
NX_PACKET *packet_ptr;
NX_PACKET *response_packet_ptr;
UINT topic_length;
UINT request_id = 0;
ULONG topic_offset;
USHORT length;
UCHAR *buffer_ptr;
UINT status;

    if ((pnp_client_ptr == NX_NULL) ||
        (writer_ptr == NX_NULL) ||
        (writer_ptr -> packet_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP client reported state send fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Check if twin response is subscribed */
    if ((status = nx_azure_iot_hub_transport_receive_message_is_subscribed(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                                           NX_AZURE_IOT_PNP_PROPERTIES_QUEUE_INDEX,
                                                                           wait_option)))
    {
        LogError(LogLiteralArgs("IoTPnP client reported state send fail with error %d"), status);
        return(status);
    }

    /* Check if the last request was throttled and if the next need to be throttled.  */
    if ((status = nx_azure_iot_pnp_client_throttled_check(pnp_client_ptr)))
    {
        LogError(LogLiteralArgs("IoT PnP client reported state send fail with error %d"), status);
        return(status);
    }

    if (writer_ptr -> json_writer._internal.bit_stack._internal.current_depth > 1)
    {
        LogError(LogLiteralArgs("IoT PnP client reported state send fail with JSON wrong state"));
        return(NX_AZURE_IOT_WRONG_STATE);
    }

    /* TODO: Need public api to get object depth */
    if (writer_ptr -> json_writer._internal.bit_stack._internal.current_depth > 0)
    {
        if ((status = nx_azure_iot_json_writer_append_end_object(writer_ptr)))
        {
            LogError(LogLiteralArgs("IoT PnP client reported state send fail to close object with error %d"), status);
            return(status);
        }
    }

    /* Steps.
     * 1. Publish message to topic "$iothub/twin/PATCH/properties/reported/?$rid={request id}"
     * 2. Wait for the response if required.
     * 3. Return result if present.
     * */

    packet_ptr = writer_ptr -> packet_ptr;
    buffer_ptr = packet_ptr -> nx_packet_prepend_ptr - 7;

    topic_length = (UINT)((buffer_ptr[5] << 8) | buffer_ptr[6]);

    request_id += (buffer_ptr[1] & 0xFF);
    request_id <<= 8;
    request_id += (buffer_ptr[2] & 0xFF);
    request_id <<= 8;
    request_id += (buffer_ptr[3] & 0xFF);
    request_id <<= 8;
    request_id += (buffer_ptr[4] & 0xFF);

    status = nx_azure_iot_hub_transport_request_response(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                         request_id, packet_ptr, topic_length, NX_NULL, 0,
                                                         NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX,
                                                         &response_packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTPnP client reported state send fail: append failed"));
        return(status);
    }

    /* Ownership of packet is taken by MQTT stack  */
    writer_ptr -> packet_ptr = NX_NULL;

    if (request_id_ptr)
    {
        *request_id_ptr = request_id;
    }

    if (response_packet_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoT PnP client reported state not responded"));
        if (pnp_client_ptr -> nx_azure_iot_pnp_client_transport.nx_azure_iot_hub_transport_state !=
                NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTED)
        {
            return(NX_AZURE_IOT_DISCONNECTED);
        }

        return(NX_AZURE_IOT_NO_PACKET);
    }

    if ((status = nx_azure_iot_hub_transport_process_publish_packet(response_packet_ptr -> nx_packet_prepend_ptr,
                                                                    &topic_offset, &length)))
    {
        nx_packet_release(response_packet_ptr);
        return(status);
    }

    if ((status = nx_azure_iot_pnp_client_device_twin_parse(pnp_client_ptr,
                                                            response_packet_ptr, topic_offset, length,
                                                            NX_NULL, version_ptr, NX_NULL,
                                                            response_status_ptr)))
    {
        nx_packet_release(response_packet_ptr);
        return(status);
    }

    /* Release message block.  */
    nx_packet_release(response_packet_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_properties_request(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                UINT wait_option)
{
UINT status;
UINT topic_length;
UINT buffer_size;
NX_PACKET *packet_ptr;
az_span request_id_span;
UINT request_id;
az_result core_result;

    if (pnp_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoT PnP client device twin get request fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if ((status = nx_azure_iot_hub_transport_receive_message_is_subscribed(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                                           NX_AZURE_IOT_PNP_PROPERTIES_QUEUE_INDEX,
                                                                           wait_option)))
    {
        LogError(LogLiteralArgs("IoTPnP client device twin publish fail with error %d"), status);
        return(status);
    }

    /* Check if the last request was throttled and if the next need to be throttled.  */
    if ((status = nx_azure_iot_pnp_client_throttled_check(pnp_client_ptr)))
    {
        LogError(LogLiteralArgs("IoT PnP client device twin get request failed with error %d"), status);
        return(status);
    }

    /* Steps.
     * 1. Publish message to topic "$iothub/twin/GET/?$rid={request id}"
     * */
    status = nx_azure_iot_hub_transport_publish_packet_get(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                           &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoT PnP client device twin get request fail: BUFFER ALLOCATE FAIL"));
        return(status);
    }

    buffer_size = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    if (buffer_size <= NX_AZURE_IOT_PNP_CLIENT_U32_MAX_BUFFER_SIZE)
    {
        LogError(LogLiteralArgs("IoT PnP client device twin get request fail: BUFFER ALLOCATE FAIL"));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    buffer_size -= NX_AZURE_IOT_PNP_CLIENT_U32_MAX_BUFFER_SIZE;

    /* Generate even request id for twin properties request.  */
    status = nx_azure_iot_pnp_client_twin_request_id_get(pnp_client_ptr,
                                                         (UCHAR *)(packet_ptr -> nx_packet_data_end -
                                                                   NX_AZURE_IOT_PNP_CLIENT_U32_MAX_BUFFER_SIZE),
                                                         NX_AZURE_IOT_PNP_CLIENT_U32_MAX_BUFFER_SIZE,
                                                         &request_id_span, &request_id, NX_FALSE);
    if (status)
    {
        LogError(LogLiteralArgs("IoT PnP client device twin failed to get request id"));
        nx_packet_release(packet_ptr);
        return(status);
    }

    core_result = az_iot_pnp_client_property_document_get_publish_topic(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                        request_id_span, (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                        buffer_size, &topic_length);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoT PnP client device twin get topic fail."));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;

    status = nx_azure_iot_hub_transport_publish(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport), packet_ptr,
                                                NX_NULL, 0, NX_AZURE_IOT_MQTT_QOS_0, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTPnP client device twin: PUBLISH FAIL status: %d"), status);
        nx_packet_release(packet_ptr);
        return(status);
    }


    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_properties_receive(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                NX_AZURE_IOT_JSON_READER *reader_ptr,
                                                ULONG *desired_properties_version_ptr,
                                                UINT wait_option)
{
UINT status;
ULONG topic_offset;
USHORT topic_length;
az_result core_result;
az_span topic_span;
az_iot_pnp_client_property_response out_twin_response;
NX_PACKET *packet_ptr;
int32_t version;

    if ((pnp_client_ptr == NX_NULL) || (reader_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP client device twin receive failed: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Check if the twin document is available to receive from linklist.
     * 2. If present check the response.
     * 3. Return the payload of the response.
     * */
    status = nx_azure_iot_hub_transport_message_receive(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                        NX_AZURE_IOT_PNP_PROPERTIES_QUEUE_INDEX, 0,
                                                        &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoT PnP client device twin receive failed status: %d"), status);
        return(status);
    }

    if (nx_azure_iot_hub_transport_process_publish_packet(packet_ptr -> nx_packet_prepend_ptr, &topic_offset,
                                                          &topic_length))
    {

        /* Message not supported. It will be released.  */
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INVALID_PACKET);
    }

    topic_span = az_span_create(&(packet_ptr -> nx_packet_prepend_ptr[topic_offset]), (INT)topic_length);
    core_result = az_iot_pnp_client_property_parse_received_topic(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                  topic_span, &out_twin_response);
    if (az_result_failed(core_result))
    {

        /* Topic name does not match device twin format.  */
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    if ((out_twin_response.status < 200) || (out_twin_response.status >= 300))
    {
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SERVER_RESPONSE_ERROR);
    }

    if ((status = nx_azure_iot_hub_transport_adjust_payload(packet_ptr)))
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    if ((status = nx_azure_iot_json_reader_init(reader_ptr, packet_ptr)))
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    if (desired_properties_version_ptr)
    {
        core_result = az_iot_pnp_client_property_get_property_version(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                      &(reader_ptr -> json_reader),
                                                                      AZ_IOT_PNP_CLIENT_PROPERTY_RESPONSE_TYPE_GET,
                                                                      &version);
        if (az_result_failed(core_result))
        {
            nx_azure_iot_json_reader_deinit(reader_ptr);
            return(NX_AZURE_IOT_SDK_CORE_ERROR);
        }

        /* Re-initialize the JSON reader state */
        if ((status = nx_azure_iot_json_reader_init(reader_ptr, packet_ptr)))
        {
            nx_packet_release(packet_ptr);
            return(status);
        }

        *desired_properties_version_ptr = (ULONG)version;
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_desired_properties_receive(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        NX_AZURE_IOT_JSON_READER *reader_ptr,
                                                        ULONG *properties_version_ptr,
                                                        UINT wait_option)
{
UINT status;
NX_PACKET *packet_ptr;
ULONG topic_offset;
USHORT topic_length;

    if ((pnp_client_ptr == NX_NULL) ||
        (reader_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoT PnP client device twin receive properties failed: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Check if the desired properties document is available to receive from linklist.
     * 2. Parse result if present.
     * 3. Return parse result.
     * */
    status = nx_azure_iot_hub_transport_message_receive(&(pnp_client_ptr -> nx_azure_iot_pnp_client_transport),
                                                        NX_AZURE_IOT_PNP_DESIRED_PROPERTIES_QUEUE_INDEX, 0,
                                                        &packet_ptr, wait_option);
    if (status)
    {
        return(status);
    }

    if (nx_azure_iot_hub_transport_process_publish_packet(packet_ptr -> nx_packet_prepend_ptr, &topic_offset,
                                                          &topic_length))
    {

        /* Message not supported. It will be released.  */
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INVALID_PACKET);
    }

    if ((status = nx_azure_iot_pnp_client_device_twin_parse(pnp_client_ptr, packet_ptr,
                                                            topic_offset, topic_length,
                                                            NX_NULL, properties_version_ptr,
                                                            NX_NULL, NX_NULL)))
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    if ((status = nx_azure_iot_hub_transport_adjust_payload(packet_ptr)))
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    if ((status = nx_azure_iot_json_reader_init(reader_ptr, packet_ptr)))
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_pnp_client_desired_component_property_value_next(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                                   NX_AZURE_IOT_JSON_READER *reader_ptr, UINT message_type,
                                                                   const UCHAR **component_pptr, UINT *component_len_ptr,
                                                                   NX_AZURE_IOT_JSON_READER *name_value_reader_ptr)
{
az_span component_name;
az_iot_pnp_client_property_response_type type;
az_result core_result;

    if ((pnp_client_ptr == NX_NULL) ||
        (reader_ptr == NX_NULL) ||
        (component_pptr == NX_NULL) ||
        (component_len_ptr == NX_NULL) )
    {
        LogError(LogLiteralArgs("IoT PnP client desired component next property failed: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if ((message_type != NX_AZURE_IOT_PNP_DESIRED_PROPERTIES) &&
        (message_type != NX_AZURE_IOT_PNP_PROPERTIES))
    {
        LogError(LogLiteralArgs("Invalid message type passed"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Copy reader control block but do not give NX_PACKET ownership  */
    *name_value_reader_ptr = *reader_ptr;
    name_value_reader_ptr -> packet_ptr = NX_NULL;
    type = (message_type == NX_AZURE_IOT_PNP_DESIRED_PROPERTIES) ? AZ_IOT_PNP_CLIENT_PROPERTY_RESPONSE_TYPE_DESIRED_PROPERTIES :
                AZ_IOT_PNP_CLIENT_PROPERTY_RESPONSE_TYPE_GET;

    core_result = az_iot_pnp_client_property_get_next_component_property(&(pnp_client_ptr -> iot_pnp_client_core),
                                                                         &(reader_ptr -> json_reader),
                                                                         type, &component_name,
                                                                         &(name_value_reader_ptr -> json_reader));
    if (core_result == AZ_ERROR_IOT_END_OF_PROPERTIES)
    {
        return(NX_AZURE_IOT_NOT_FOUND);
    }
    else if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("Failed to parse document with core error : %d"), core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    *component_pptr = az_span_ptr(component_name);
    *component_len_ptr = (UINT)az_span_size(component_name);

    return(NX_AZURE_IOT_SUCCESS);
}
