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

#include "nx_azure_iot_hub_client.h"

#include "azure/core/az_version.h"


#define NX_AZURE_IOT_HUB_CLIENT_U32_MAX_BUFFER_SIZE     10
#define NX_AZURE_IOT_HUB_CLIENT_EMPTY_JSON              "{}"
#define NX_AZURE_IOT_HUB_CLIENT_THROTTLE_STATUS_CODE    429

#ifndef NX_AZURE_IOT_HUB_CLIENT_USER_AGENT

/* Useragent e.g: DeviceClientType=c%2F1.0.0-preview.1%20%28nx%206.0%3Bazrtos%206.0%29 */
#define NX_AZURE_IOT_HUB_CLIENT_STR(C)          #C
#define NX_AZURE_IOT_HUB_CLIENT_TO_STR(x)       NX_AZURE_IOT_HUB_CLIENT_STR(x)
#define NX_AZURE_IOT_HUB_CLIENT_USER_AGENT      "DeviceClientType=c%2F" AZ_SDK_VERSION_STRING "%20%28nx%20" \
                                                NX_AZURE_IOT_HUB_CLIENT_TO_STR(NETXDUO_MAJOR_VERSION) "." \
                                                NX_AZURE_IOT_HUB_CLIENT_TO_STR(NETXDUO_MINOR_VERSION) "%3Bazrtos%20"\
                                                NX_AZURE_IOT_HUB_CLIENT_TO_STR(THREADX_MAJOR_VERSION) "." \
                                                NX_AZURE_IOT_HUB_CLIENT_TO_STR(THREADX_MINOR_VERSION) "%29"
#endif /* NX_AZURE_IOT_HUB_CLIENT_USER_AGENT */

/* Queue index used in transport to receive the messages */
#define NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_QUEUE_INDEX                                0
#define NX_AZURE_IOT_HUB_DIRECT_METHOD_QUEUE_INDEX                                  1
#define NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES_QUEUE_INDEX                         2
#define NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES_QUEUE_INDEX                 3
#define NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX       4

extern UINT _nxd_mqtt_process_publish_packet(NX_PACKET *packet_ptr, ULONG *topic_offset_ptr,
                                             USHORT *topic_length_ptr, ULONG *message_offset_ptr,
                                             ULONG *message_length_ptr);

static UINT nx_azure_iot_hub_client_c2d_process(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                NX_PACKET *packet_ptr, ULONG topic_offset,
                                                USHORT topic_length);
static UINT nx_azure_iot_hub_client_device_twin_process(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                        NX_PACKET *packet_ptr, ULONG topic_offset,
                                                        USHORT topic_length);
static UINT nx_azure_iot_hub_client_device_twin_parse(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                      NX_PACKET *packet_ptr, ULONG topic_offset,
                                                      USHORT topic_length, UINT *request_id_ptr,
                                                      ULONG *version_ptr, UINT *message_type_ptr,
                                                      UINT *status_ptr);

static UINT nx_azure_iot_hub_client_throttle_with_jitter(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT jitter;
UINT base_delay = NX_AZURE_IOT_HUB_CLIENT_MAX_BACKOFF_IN_SEC;
UINT retry_count = hub_client_ptr -> nx_azure_iot_hub_client_throttle_count;
uint64_t delay;

    if (retry_count < (sizeof(UINT) * 8 - 1))
    {
        retry_count++;
        delay = (uint64_t)((1 << retry_count) * NX_AZURE_IOT_HUB_CLIENT_INITIAL_BACKOFF_IN_SEC);

        if (delay <= (UINT)(-1))
        {
            base_delay = (UINT)delay;
        }
    }

    if (base_delay > NX_AZURE_IOT_HUB_CLIENT_MAX_BACKOFF_IN_SEC)
    {
        base_delay = NX_AZURE_IOT_HUB_CLIENT_MAX_BACKOFF_IN_SEC;
    }
    else
    {
       hub_client_ptr -> nx_azure_iot_hub_client_throttle_count = retry_count;
    }

    jitter = base_delay * NX_AZURE_IOT_HUB_CLIENT_MAX_BACKOFF_JITTER_PERCENT * (NX_RAND() & 0xFF) / 25600;
    return((UINT)(base_delay + jitter));
}

static UINT nx_azure_iot_hub_client_throttled_check(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
ULONG current_time;
UINT status = NX_AZURE_IOT_SUCCESS;

    if (hub_client_ptr -> nx_azure_iot_hub_client_throttle_count != 0)
    {
        if ((status = nx_azure_iot_unix_time_get(hub_client_ptr -> nx_azure_iot_hub_client_transport.nx_azure_iot_ptr, &current_time)))
        {
            LogError(LogLiteralArgs("IoTHub client fail to get unix time: %d"), status);
            return(status);
        }

        if (current_time < hub_client_ptr -> nx_azure_iot_hub_client_throttle_end_time)
        {
            return(NX_AZURE_IOT_THROTTLED);
        }
    }

    return(status);
}

static UINT nx_azure_iot_hub_client_mesg_type_to_queue_index(UINT message_type)
{
UINT queue_index;

    switch (message_type)
    {
        case NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE :
        {
            queue_index = NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_QUEUE_INDEX;
        }
        break;

        case NX_AZURE_IOT_HUB_DIRECT_METHOD :
        {
            queue_index = NX_AZURE_IOT_HUB_DIRECT_METHOD_QUEUE_INDEX;
        }
        break;

        case NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES :
        {
            queue_index = NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES_QUEUE_INDEX;
        }
        break;

        case NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES :
        {
            queue_index = NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES_QUEUE_INDEX;
        }
        break;

        case NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE :
        {
            queue_index = NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX;
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

static az_result nx_azure_iot_hub_client_client_id_get(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                       UCHAR *buffer, UINT buffer_len, UINT *bytes_copied)
{
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    return(az_iot_hub_client_get_client_id(&(hub_client_ptr -> iot_hub_client_core),
                                           (CHAR *)buffer, buffer_len, bytes_copied));
}

static az_result nx_azure_iot_hub_client_username_get(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                      UCHAR *buffer, UINT buffer_len, UINT *bytes_copied)
{
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    return(az_iot_hub_client_get_user_name(&hub_client_ptr -> iot_hub_client_core,
                                           (CHAR *)buffer, buffer_len, bytes_copied));
}

static az_result nx_azure_iot_hub_client_signature_get(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                       ULONG expiry_time_secs, az_span buffer, az_span *out_buffer)
{
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    return(az_iot_hub_client_sas_get_signature(&(hub_client_ptr -> iot_hub_client_core),
                                               expiry_time_secs, buffer, out_buffer));
}

static az_result nx_azure_iot_hub_client_password_get(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                      ULONG expiry_time_secs, az_span hash_buffer, az_span key_name,
                                                      UCHAR *out_buffer, UINT out_buffer_len, UINT *bytes_copied)
{
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    return(az_iot_hub_client_sas_get_password(&(hub_client_ptr -> iot_hub_client_core),
                                              expiry_time_secs, hash_buffer, key_name,
                                              (CHAR *)out_buffer, out_buffer_len, bytes_copied));
}

static VOID nx_azure_iot_hub_client_receive_callback(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                     NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg1,
                                                     VOID *arg2)
{
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    ((VOID (*)(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *args))arg1)(hub_client_ptr, arg2);
}

static VOID nx_azure_iot_hub_client_connection_status_callback(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                               UINT status, NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg)
{
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

    ((VOID (*)(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, UINT status))arg)(hub_client_ptr, status);
}

static VOID nx_azure_iot_hub_client_reported_property_receive_callback(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                                       NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg1,
                                                                       VOID *arg2)
{
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;
UINT status;
NX_PACKET *packet_ptr;
ULONG topic_offset;
USHORT topic_length;
UINT request_id;
UINT response_status;
ULONG version = 0;

    if ((status = nx_azure_iot_hub_transport_message_receive(hub_trans_ptr,
                                                             NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX, 0,
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

    if ((status = nx_azure_iot_hub_client_device_twin_parse(hub_client_ptr, packet_ptr,
                                                            topic_offset, topic_length,
                                                            &request_id, &version,
                                                            NX_NULL, &response_status)))
    {
        nx_packet_release(packet_ptr);
        return;
    }

    ((VOID (*)(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
               UINT request_id, UINT response_status,
               ULONG version, VOID *arg))arg1)(hub_client_ptr,
                                             request_id,
                                             response_status,
                                             version,
                                             arg2);
    nx_packet_release(packet_ptr);
}

UINT nx_azure_iot_hub_client_initialize(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                        NX_AZURE_IOT *nx_azure_iot_ptr,
                                        const UCHAR *host_name, UINT host_name_length,
                                        const UCHAR *device_id, UINT device_id_length,
                                        const UCHAR *module_id, UINT module_id_length,
                                        const NX_CRYPTO_METHOD **crypto_array, UINT crypto_array_size,
                                        const NX_CRYPTO_CIPHERSUITE **cipher_map, UINT cipher_map_size,
                                        UCHAR * metadata_memory, UINT memory_size,
                                        NX_SECURE_X509_CERT *trusted_certificate)
{

UINT status;
az_span hostname_span = az_span_create((UCHAR *)host_name, (INT)host_name_length);
az_span device_id_span = az_span_create((UCHAR *)device_id, (INT)device_id_length);
az_iot_hub_client_options options = az_iot_hub_client_options_default();
az_result core_result;

    if ((nx_azure_iot_ptr == NX_NULL) || (hub_client_ptr == NX_NULL) || (host_name == NX_NULL) ||
        (device_id == NX_NULL) || (host_name_length == 0) || (device_id_length == 0))
    {
        LogError(LogLiteralArgs("IoTHub client initialization fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    memset(hub_client_ptr, 0, sizeof(NX_AZURE_IOT_HUB_CLIENT));

    options.module_id = az_span_create((UCHAR *)module_id, (INT)module_id_length);
    options.user_agent = AZ_SPAN_FROM_STR(NX_AZURE_IOT_HUB_CLIENT_USER_AGENT);

    core_result = az_iot_hub_client_init(&hub_client_ptr -> iot_hub_client_core,
                                         hostname_span, device_id_span, &options);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoTHub client failed initialization with error status: %d"), core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    status = nx_azure_iot_hub_transport_initialize(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                   nx_azure_iot_ptr, host_name, host_name_length,
                                                   nx_azure_iot_hub_client_client_id_get,
                                                   nx_azure_iot_hub_client_username_get,
                                                   crypto_array, crypto_array_size,
                                                   cipher_map, cipher_map_size,
                                                   metadata_memory, memory_size,
                                                   trusted_certificate, (VOID *)hub_client_ptr);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client failed  to initialization transport with error status: %d"), core_result);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_connection_status_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            VOID (*connection_status_cb)(
                                                                  struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *client_ptr,
                                                                  UINT status))
{

    /* Check for invalid input pointers.  */
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client connect callback fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_connection_callback_set(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                              nx_azure_iot_hub_client_connection_status_callback,
                                                              (NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN)connection_status_cb));
}

UINT nx_azure_iot_hub_client_connect(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                     UINT clean_session, UINT wait_option)
{

    /* Check for invalid input pointers.  */
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client connect fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_connect(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                              clean_session, wait_option));
}

UINT nx_azure_iot_hub_client_disconnect(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{

    /* Check for invalid input pointers.  */
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client disconnect fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_disconnect(&(hub_client_ptr -> nx_azure_iot_hub_client_transport)));
}

UINT nx_azure_iot_hub_client_deinitialize(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{

    /* Check for invalid input pointers.  */
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client deinitialize fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_deinitialize(&(hub_client_ptr -> nx_azure_iot_hub_client_transport)));
}

UINT nx_azure_iot_hub_client_device_cert_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                             NX_SECURE_X509_CERT *device_certificate)
{
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub device certificate set fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_device_cert_set(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                      device_certificate));
}

UINT nx_azure_iot_hub_client_symmetric_key_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                               const UCHAR *symmetric_key, UINT symmetric_key_length)
{
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client symmetric key fail: Invalid argument"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_symmetric_key_auth_set(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                             nx_azure_iot_hub_client_signature_get,
                                                             nx_azure_iot_hub_client_password_get,
                                                             symmetric_key, symmetric_key_length));
}

UINT nx_azure_iot_hub_client_model_id_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                          const UCHAR *model_id_ptr, UINT model_id_length)
{
    if ((hub_client_ptr == NX_NULL)  ||
        (hub_client_ptr -> nx_azure_iot_hub_client_transport.nx_azure_iot_ptr == NX_NULL) ||
        (model_id_ptr == NX_NULL) || (model_id_length == 0))
    {
        LogError(LogLiteralArgs("IoTHub client model Id fail: Invalid argument"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_hub_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Had no way to update option, so had to access the internal fields of iot_hub_client_core.  */
    hub_client_ptr -> iot_hub_client_core._internal.options.model_id =
        az_span_create((UCHAR *)model_id_ptr, (INT)model_id_length);

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_hub_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_telemetry_message_create(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                      NX_PACKET **packet_pptr, UINT wait_option)
{
NX_PACKET *packet_ptr;
UINT topic_length;
UINT status;
az_result core_result;

    if ((hub_client_ptr == NX_NULL) ||
        (packet_pptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub telemetry message create fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_transport_publish_packet_get(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                           &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("Create telemetry data fail"));
        return(status);
    }

    topic_length = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    core_result = az_iot_hub_client_telemetry_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                NULL, (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                topic_length, &topic_length);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoTHub client telemetry message create fail with error status: %d"), core_result);
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;
    *packet_pptr = packet_ptr;
    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_telemetry_message_delete(NX_PACKET *packet_ptr)
{
    return(nx_packet_release(packet_ptr));
}

UINT nx_azure_iot_hub_client_telemetry_property_add(NX_PACKET *packet_ptr,
                                                    const UCHAR *property_name, USHORT property_name_length,
                                                    const UCHAR *property_value, USHORT property_value_length,
                                                    UINT wait_option)
{
    return(nx_azure_iot_topic_property_append(packet_ptr, property_name, property_name_length,
                                              property_value, property_value_length, wait_option));
}

UINT nx_azure_iot_hub_client_telemetry_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                            NX_PACKET *packet_ptr, const UCHAR *telemetry_data,
                                            UINT data_size, UINT wait_option)
{
    if ((hub_client_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub telemetry send fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_publish(&(hub_client_ptr -> nx_azure_iot_hub_client_transport), packet_ptr,
                                              telemetry_data, data_size, NX_AZURE_IOT_HUB_CLIENT_TELEMETRY_QOS, wait_option));
}

UINT nx_azure_iot_hub_client_receive_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  UINT message_type,
                                                  VOID (*callback_ptr)(
                                                        NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        VOID *args),
                                                  VOID *callback_args)
{
UINT message_queue_index;

    if ((hub_client_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub receive callback set fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    message_queue_index =  nx_azure_iot_hub_client_mesg_type_to_queue_index(message_type);

    return(nx_azure_iot_hub_transport_receive_message_callback_set(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                                   message_queue_index,
                                                                   callback_ptr != NX_NULL ? nx_azure_iot_hub_client_receive_callback : NX_NULL,
                                                                   (NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN)callback_ptr, callback_args));
}

UINT nx_azure_iot_hub_client_cloud_message_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub cloud message enable fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_receive_message_enable(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                             NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_QUEUE_INDEX,
                                                             (const UCHAR *)AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC,
                                                             sizeof(AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC) - 1,
                                                             nx_azure_iot_hub_client_c2d_process));
}

UINT nx_azure_iot_hub_client_cloud_message_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub cloud message disable fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_receive_message_disable(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                              NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_QUEUE_INDEX));
}

UINT nx_azure_iot_hub_client_cloud_message_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;

    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub cloud message receive fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_transport_message_receive(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                        NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_QUEUE_INDEX, 0,
                                                        packet_pptr, wait_option);
    if (status)
    {
        return(status);
    }

    return(nx_azure_iot_hub_transport_adjust_payload(*packet_pptr));
}

UINT nx_azure_iot_hub_client_cloud_message_property_get(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        NX_PACKET *packet_ptr, const UCHAR *property_name,
                                                        USHORT property_name_length, const UCHAR **property_value,
                                                        USHORT *property_value_length)
{
USHORT topic_size;
UINT status;
ULONG topic_offset;
UCHAR *topic_name;
az_iot_hub_client_c2d_request request;
az_span receive_topic;
az_result core_result;
az_span span;

    if (packet_ptr == NX_NULL ||
        property_name == NX_NULL ||
        property_value == NX_NULL ||
        property_value_length == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub cloud message get property fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_transport_process_publish_packet(packet_ptr -> nx_packet_data_start,
                                                               &topic_offset, &topic_size);
    if (status)
    {
        return(status);
    }

    topic_name = packet_ptr -> nx_packet_data_start + topic_offset;

    /* NOTE: Current implementation does not support topic to span multiple packets.  */
    if ((ULONG)(packet_ptr -> nx_packet_append_ptr - topic_name) < (ULONG)topic_size)
    {
        LogError(LogLiteralArgs("IoTHub cloud message get property fail: topic out of boundaries of single packet"));
        return(NX_AZURE_IOT_TOPIC_TOO_LONG);
    }

    receive_topic = az_span_create(topic_name, (INT)topic_size);
    core_result = az_iot_hub_client_c2d_parse_received_topic(&hub_client_ptr -> iot_hub_client_core,
                                                             receive_topic, &request);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoTHub cloud message get property fail: parsing error"));
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    span = az_span_create((UCHAR *)property_name, property_name_length);
    core_result = az_iot_message_properties_find(&request.properties, span, &span);
    if (az_result_failed(core_result))
    {
        if (core_result == AZ_ERROR_ITEM_NOT_FOUND)
        {
            status = NX_AZURE_IOT_NOT_FOUND;
        }
        else
        {
            LogError(LogLiteralArgs("IoTHub cloud message get property fail: property find"));
            status = NX_AZURE_IOT_SDK_CORE_ERROR;
        }

        return(status);
    }

    *property_value = (UCHAR *)az_span_ptr(span);
    *property_value_length = (USHORT)az_span_size(span);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_twin_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;

    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client device twin subscribe fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_transport_receive_message_enable(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                               NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES_QUEUE_INDEX,
                                                               (const UCHAR *)AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC,
                                                               sizeof(AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC) - 1,
                                                               nx_azure_iot_hub_client_device_twin_process);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client device twin subscribe fail status: %d"), status);
        return(status);
    }

    status = nx_azure_iot_hub_transport_receive_message_enable(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                               NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES_QUEUE_INDEX,
                                                               (const UCHAR *)AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC,
                                                               sizeof(AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC) - 1,
                                                               NX_NULL);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client device twin subscribe fail status: %d"), status);
        return(status);
    }

    status = nx_azure_iot_hub_transport_receive_message_enable(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                               NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX,
                                                               NX_NULL, 0, NX_NULL);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client device twin subscribe fail status: %d"), status);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_twin_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;

    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client device twin unsubscribe fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_transport_receive_message_disable(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                                NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES_QUEUE_INDEX);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client device twin unsubscribe fail status: %d"), status);
        return(status);
    }

    status = nx_azure_iot_hub_transport_receive_message_disable(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                                NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES_QUEUE_INDEX);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client device twin unsubscribe fail status: %d"), status);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_report_properties_response_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                     VOID (*callback_ptr)(
                                                                           NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                           UINT request_id,
                                                                           UINT response_status,
                                                                           ULONG version,
                                                                           VOID *args),
                                                                     VOID *callback_args)
{
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client device twin set callback fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_receive_message_callback_set(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                                   NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX,
                                                                   callback_ptr != NX_NULL ? nx_azure_iot_hub_client_reported_property_receive_callback : NX_NULL,
                                                                   (NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN)callback_ptr, callback_args));
}

static UINT nx_azure_iot_hub_client_twin_request_id_get(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        UCHAR *buffer_ptr, UINT buffer_len,
                                                        az_span *request_id_span_ptr,
                                                        UINT *request_id_ptr, UINT odd_seq)
{
az_span span;

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_hub_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Check if current request_id is even and new requested is also even or
       current request_id is odd and new requested is also odd.  */
    if ((hub_client_ptr -> nx_azure_iot_hub_client_request_id & 0x1) == odd_seq)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_request_id += 2;
    }
    else
    {
        hub_client_ptr -> nx_azure_iot_hub_client_request_id += 1;
    }

    if (hub_client_ptr -> nx_azure_iot_hub_client_request_id == 0)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_request_id = 2;
    }

    *request_id_ptr = hub_client_ptr -> nx_azure_iot_hub_client_request_id;
    span = az_span_create(buffer_ptr, (INT)buffer_len);
    if (az_result_failed(az_span_u32toa(span, *request_id_ptr, &span)))
    {

        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_hub_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        LogError(LogLiteralArgs("IoTHub client device failed to u32toa"));
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    *request_id_span_ptr = az_span_create(buffer_ptr, (INT)(buffer_len - (UINT)az_span_size(span)));

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_hub_client_transport.nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_twin_reported_properties_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                  const UCHAR *message_buffer, UINT message_length,
                                                                  UINT *request_id_ptr, UINT *response_status_ptr,
                                                                  ULONG *version_ptr, UINT wait_option)
{
UINT status;
UINT buffer_size;
NX_PACKET *packet_ptr;
UINT topic_length;
UINT request_id;
az_span request_id_span;
az_result core_result;
ULONG topic_offset;
USHORT length;
NX_PACKET *response_packet_ptr;

    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client reported state send fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Check if twin response is subscribed */
    if ((status = nx_azure_iot_hub_transport_receive_message_is_subscribed(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                                           NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES_QUEUE_INDEX,
                                                                           wait_option)))
    {
        LogError(LogLiteralArgs("IoTHub client reported state send fail with error %d"), status);
        return(status);
    }

    /* Check if the last request was throttled and if the next need to be throttled.  */
    if ((status = nx_azure_iot_hub_client_throttled_check(hub_client_ptr)))
    {
        LogError(LogLiteralArgs("IoTHub client reported state send fail with error %d"), status);
        return(status);
    }

    /* Steps.
     * 1. Publish message to topic "$iothub/twin/PATCH/properties/reported/?$rid={request id}"
     * 2. Wait for the response if required.
     * 3. Return result if present.
     * */
    status = nx_azure_iot_hub_transport_publish_packet_get(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                           &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client reported state send fail: BUFFER ALLOCATE FAIL"));
        return(status);
    }

    buffer_size = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    if (buffer_size <= NX_AZURE_IOT_HUB_CLIENT_U32_MAX_BUFFER_SIZE)
    {
        LogError(LogLiteralArgs("IoTHub client reported state send fail: BUFFER INSUFFICENT"));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    buffer_size -= NX_AZURE_IOT_HUB_CLIENT_U32_MAX_BUFFER_SIZE;

    /* Generate odd request id for reported properties send.  */
    status = nx_azure_iot_hub_client_twin_request_id_get(hub_client_ptr,
                                                         (UCHAR *)(packet_ptr -> nx_packet_data_end -
                                                                   NX_AZURE_IOT_HUB_CLIENT_U32_MAX_BUFFER_SIZE),
                                                         NX_AZURE_IOT_HUB_CLIENT_U32_MAX_BUFFER_SIZE,
                                                         &request_id_span, &request_id, NX_TRUE);

    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client reported state send failed to get request id"));
        nx_packet_release(packet_ptr);
        return(status);
    }

    core_result = az_iot_hub_client_twin_patch_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                 request_id_span, (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                 buffer_size, &topic_length);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoTHub client reported state send fail: NX_AZURE_IOT_HUB_CLIENT_TOPIC_SIZE is too small."));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;

    status = nx_azure_iot_hub_transport_request_response(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                         request_id, packet_ptr, topic_length, message_buffer, message_length,
                                                         NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE_QUEUE_INDEX,
                                                         &response_packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client reported state send fail: append failed"));
        nx_packet_release(packet_ptr);
        return(status);
    }

    if (request_id_ptr)
    {
        *request_id_ptr = request_id;
    }

    if (response_packet_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client reported state not responded"));
        if (hub_client_ptr -> nx_azure_iot_hub_client_transport.nx_azure_iot_hub_transport_state !=
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

    if ((status = nx_azure_iot_hub_client_device_twin_parse(hub_client_ptr,
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

UINT nx_azure_iot_hub_client_device_twin_properties_request(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            UINT wait_option)
{
UINT status;
UINT topic_length;
UINT buffer_size;
NX_PACKET *packet_ptr;
az_span request_id_span;
UINT request_id;
az_result core_result;

    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client device twin publish fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if ((status = nx_azure_iot_hub_transport_receive_message_is_subscribed(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                                           NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES_QUEUE_INDEX,
                                                                           wait_option)))
    {
        LogError(LogLiteralArgs("IoTHub client device twin publish fail with error %d"), status);
        return(status);
    }

    /* Check if the last request was throttled and if the next need to be throttled.  */
    if ((status = nx_azure_iot_hub_client_throttled_check(hub_client_ptr)))
    {
        LogError(LogLiteralArgs("IoTHub client device twin publish failed with error %d"), status);
        return(status);
    }

    /* Steps.
     * 1. Publish message to topic "$iothub/twin/GET/?$rid={request id}"
     * */
    status = nx_azure_iot_hub_transport_publish_packet_get(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                           &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client device twin publish fail: BUFFER ALLOCATE FAIL"));
        return(status);
    }

    buffer_size = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    if (buffer_size <= NX_AZURE_IOT_HUB_CLIENT_U32_MAX_BUFFER_SIZE)
    {
        LogError(LogLiteralArgs("IoTHub client device twin publish fail: BUFFER ALLOCATE FAIL"));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    buffer_size -= NX_AZURE_IOT_HUB_CLIENT_U32_MAX_BUFFER_SIZE;

    /* Generate even request id for twin properties request.  */
    status = nx_azure_iot_hub_client_twin_request_id_get(hub_client_ptr,
                                                         (UCHAR *)(packet_ptr -> nx_packet_data_end -
                                                                   NX_AZURE_IOT_HUB_CLIENT_U32_MAX_BUFFER_SIZE),
                                                         NX_AZURE_IOT_HUB_CLIENT_U32_MAX_BUFFER_SIZE,
                                                         &request_id_span, &request_id, NX_FALSE);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client device twin failed to get request id"));
        nx_packet_release(packet_ptr);
        return(status);
    }

    core_result = az_iot_hub_client_twin_document_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                    request_id_span, (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                    buffer_size, &topic_length);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoTHub client device twin get topic fail."));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;

    status = nx_azure_iot_hub_transport_publish(&(hub_client_ptr -> nx_azure_iot_hub_client_transport), packet_ptr,
                                                NX_NULL, 0, NX_AZURE_IOT_MQTT_QOS_0, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client device twin: PUBLISH FAIL status: %d"), status);
        nx_packet_release(packet_ptr);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_twin_properties_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;
ULONG topic_offset;
USHORT topic_length;
az_result core_result;
az_span topic_span;
az_iot_hub_client_twin_response out_twin_response;
NX_PACKET *packet_ptr;

    if ((hub_client_ptr == NX_NULL) ||
        (packet_pptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub client device twin receive failed: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Check if the twin document is available to receive from linklist.
     * 2. If present check the response.
     * 3. Return the payload of the response.
     * */
    status = nx_azure_iot_hub_transport_message_receive(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                        NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES_QUEUE_INDEX, 0,
                                                        &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client device twin receive failed status: %d"), status);
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
    core_result = az_iot_hub_client_twin_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
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

    *packet_pptr = packet_ptr;

    return(nx_azure_iot_hub_transport_adjust_payload(*packet_pptr));
}

UINT nx_azure_iot_hub_client_device_twin_desired_properties_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                    NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;

    if ((hub_client_ptr == NX_NULL) ||
        (packet_pptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub client device twin receive properties failed: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Check if the desired properties document is available to receive from linklist.
     * 2. Return result if present.
     * */
    status = nx_azure_iot_hub_transport_message_receive(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                        NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES_QUEUE_INDEX, 0,
                                                        packet_pptr, wait_option);
    if (status)
    {
        return(status);
    }

    return(nx_azure_iot_hub_transport_adjust_payload(*packet_pptr));
}

static UINT nx_azure_iot_hub_client_c2d_process(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                NX_PACKET *packet_ptr, ULONG topic_offset,
                                                USHORT topic_length)
{
UCHAR *topic_name;
az_iot_hub_client_c2d_request request;
az_span receive_topic;
az_result core_result;
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

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
    core_result = az_iot_hub_client_c2d_parse_received_topic(&hub_client_ptr -> iot_hub_client_core,
                                                             receive_topic, &request);
    if (az_result_failed(core_result))
    {

        /* Topic name does not match C2D format.  */
        return(NX_AZURE_IOT_NOT_FOUND);
    }

    return(nx_azure_iot_hub_transport_receive_notify(hub_trans_ptr, packet_ptr,
                                                     NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_QUEUE_INDEX, 0));
}

static UINT nx_azure_iot_hub_client_direct_method_process(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                          NX_PACKET *packet_ptr, ULONG topic_offset,
                                                          USHORT topic_length)
{
UCHAR *topic_name;
az_iot_hub_client_method_request request;
az_span receive_topic;
az_result core_result;
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;

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
    core_result = az_iot_hub_client_methods_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                 receive_topic, &request);
    if (az_result_failed(core_result))
    {

        /* Topic name does not match direct method format.  */
        return(NX_AZURE_IOT_NOT_FOUND);
    }

    return(nx_azure_iot_hub_transport_receive_notify(hub_trans_ptr, packet_ptr,
                                                     NX_AZURE_IOT_HUB_DIRECT_METHOD_QUEUE_INDEX, 0));
}

static UINT nx_azure_iot_hub_client_device_twin_message_type_get(az_iot_hub_client_twin_response *out_twin_response_ptr,
                                                                 UINT request_id)
{
UINT message_type;

    switch (out_twin_response_ptr -> response_type)
    {
        case AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_TYPE_GET :

        /* Fall through.  */

        case AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_TYPE_REPORTED_PROPERTIES :
        {

            /* Odd requests are of reported properties and even of twin properties.  */
            message_type = request_id % 2 == 0 ? NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES :
                                NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE;
        }
        break;

        case AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_TYPE_DESIRED_PROPERTIES :
        {
            message_type = NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES;
        }
        break;

        default :
        {
            message_type = NX_AZURE_IOT_HUB_NONE;
        }
    }

    return message_type;
}

static UINT nx_azure_iot_hub_client_device_twin_parse(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                      NX_PACKET *packet_ptr, ULONG topic_offset,
                                                      USHORT topic_length, UINT *request_id_ptr,
                                                      ULONG *version_ptr, UINT *message_type_ptr,
                                                      UINT *status_ptr)
{
az_result core_result;
az_span topic_span;
az_iot_hub_client_twin_response out_twin_response;
uint32_t request_id = 0;
uint32_t version;

    topic_span = az_span_create(&(packet_ptr -> nx_packet_prepend_ptr[topic_offset]), (INT)topic_length);
    core_result = az_iot_hub_client_twin_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
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
        *message_type_ptr = nx_azure_iot_hub_client_device_twin_message_type_get(&out_twin_response,
                                                                                 (UINT)request_id);
    }

    if (status_ptr)
    {
        *status_ptr = (UINT)out_twin_response.status;
    }

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT nx_azure_iot_hub_client_device_twin_process(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                        NX_PACKET *packet_ptr, ULONG topic_offset,
                                                        USHORT topic_length)
{
UINT message_type;
UINT response_status;
UINT request_id = 0;
ULONG version = 0;
UINT correlation_id;
UINT status;
ULONG current_time;
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)hub_trans_ptr -> nx_azure_iot_hub_transport_client_context;
UINT message_queue_index;

    /* This function is protected by MQTT mutex. */
    if ((status = nx_azure_iot_hub_client_device_twin_parse(hub_client_ptr, packet_ptr,
                                                            topic_offset, topic_length,
                                                            &request_id, &version,
                                                            &message_type, &response_status)))
    {
        return(status);
    }

    if (response_status == NX_AZURE_IOT_HUB_CLIENT_THROTTLE_STATUS_CODE)
    {
        if ((status = nx_azure_iot_unix_time_get(hub_client_ptr -> nx_azure_iot_hub_client_transport.nx_azure_iot_ptr, &current_time)))
        {
            LogError(LogLiteralArgs("IoTHub client fail to get unix time: %d"), status);
            return(status);
        }

        hub_client_ptr -> nx_azure_iot_hub_client_throttle_end_time =
            current_time + nx_azure_iot_hub_client_throttle_with_jitter(hub_client_ptr);
    }
    else
    {
        hub_client_ptr -> nx_azure_iot_hub_client_throttle_count = 0;
        hub_client_ptr -> nx_azure_iot_hub_client_throttle_end_time = 0;
    }

    if (message_type == NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE)
    {

        /* Only requested thread should be woken.  */
        correlation_id = request_id;
    }
    else
    {

        /* Any thread can be woken.  */
        correlation_id = 0;
    }

    message_queue_index = nx_azure_iot_hub_client_mesg_type_to_queue_index(message_type);
    status = nx_azure_iot_hub_transport_receive_notify(hub_trans_ptr, packet_ptr,
                                                       message_queue_index, correlation_id);

    return(status);
}

UINT nx_azure_iot_hub_client_direct_method_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client direct method subscribe fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_receive_message_enable(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                             NX_AZURE_IOT_HUB_DIRECT_METHOD_QUEUE_INDEX,
                                                             (const UCHAR *)AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC,
                                                             sizeof(AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC) - 1,
                                                             nx_azure_iot_hub_client_direct_method_process));
}

UINT nx_azure_iot_hub_client_direct_method_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    if (hub_client_ptr == NX_NULL)
    {
        LogError(LogLiteralArgs("IoTHub client direct method unsubscribe fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_hub_transport_receive_message_disable(&(hub_client_ptr ->nx_azure_iot_hub_client_transport),
                                                              NX_AZURE_IOT_HUB_DIRECT_METHOD_QUEUE_INDEX));
}

UINT nx_azure_iot_hub_client_direct_method_message_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                           const UCHAR **method_name_pptr, USHORT *method_name_length_ptr,
                                                           VOID **context_pptr, USHORT *context_length_ptr,
                                                           NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;
ULONG topic_offset;
USHORT topic_length;
az_span topic_span;
ULONG message_offset;
ULONG message_length;
NX_PACKET *packet_ptr;
az_result core_result;
az_iot_hub_client_method_request request;

    if ((hub_client_ptr == NX_NULL) ||
        (method_name_pptr == NX_NULL) ||
        (method_name_length_ptr == NX_NULL) ||
        (context_pptr == NX_NULL) ||
        (context_length_ptr == NX_NULL) ||
        (packet_pptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub client direct method receive fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_transport_message_receive(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                        NX_AZURE_IOT_HUB_DIRECT_METHOD_QUEUE_INDEX, 0,
                                                        packet_pptr, wait_option);
    if (status)
    {
        return(status);
    }

    packet_ptr = *packet_pptr;
    status = _nxd_mqtt_process_publish_packet(packet_ptr, &topic_offset, &topic_length, &message_offset, &message_length);
    if (status)
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    topic_span = az_span_create(&(packet_ptr -> nx_packet_prepend_ptr[topic_offset]), topic_length);
    core_result = az_iot_hub_client_methods_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                 topic_span, &request);
    if (az_result_failed(core_result))
    {
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    *packet_pptr = packet_ptr;
    packet_ptr -> nx_packet_length = message_length;

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

    *method_name_pptr = az_span_ptr(request.name);
    *method_name_length_ptr = (USHORT)az_span_size(request.name);
    *context_pptr = (VOID*)az_span_ptr(request.request_id);
    *context_length_ptr =  (USHORT)az_span_size(request.request_id);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_direct_method_message_response(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            UINT status_code, VOID *context_ptr,
                                                            USHORT context_length, const UCHAR *payload,
                                                            UINT payload_length, UINT wait_option)
{
NX_PACKET *packet_ptr;
UINT topic_length;
az_span request_id_span;
UINT status;
az_result core_result;

    if ((hub_client_ptr == NX_NULL) ||
        (context_ptr == NX_NULL) ||
        (context_length == 0))
    {
        LogError(LogLiteralArgs("IoTHub direct method response fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Prepare response packet.  */
    status = nx_azure_iot_hub_transport_publish_packet_get(&(hub_client_ptr -> nx_azure_iot_hub_client_transport),
                                                           &packet_ptr, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("Create response data fail"));
        return(status);
    }

    topic_length = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    request_id_span = az_span_create((UCHAR*)context_ptr, (INT)context_length);
    core_result = az_iot_hub_client_methods_response_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                       request_id_span, (USHORT)status_code,
                                                                       (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                       topic_length, &topic_length);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("Failed to create the method response topic"));
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;

    if ((payload == NX_NULL) || (payload_length == 0))
    {
        payload = (const UCHAR *)NX_AZURE_IOT_HUB_CLIENT_EMPTY_JSON;
        payload_length = sizeof(NX_AZURE_IOT_HUB_CLIENT_EMPTY_JSON) - 1;
    }

    status = nx_azure_iot_hub_transport_publish(&(hub_client_ptr -> nx_azure_iot_hub_client_transport), packet_ptr,
                                                payload, payload_length, NX_AZURE_IOT_MQTT_QOS_0, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client method response fail: PUBLISH FAIL status: %d"), status);
        nx_packet_release(packet_ptr);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}
