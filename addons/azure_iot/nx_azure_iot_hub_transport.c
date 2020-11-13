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

#include "nx_azure_iot_hub_transport.h"

#include "azure/core/az_version.h"


#define NX_AZURE_IOT_HUB_U32_MAX_BUFFER_SIZE     10
#define NX_AZURE_IOT_HUB_EMPTY_JSON              "{}"
#define NX_AZURE_IOT_HUB_THROTTLE_STATUS_CODE    429


extern UINT _nxd_mqtt_process_publish_packet(NX_PACKET *packet_ptr, ULONG *topic_offset_ptr,
                                             USHORT *topic_length_ptr, ULONG *message_offset_ptr,
                                             ULONG *message_length_ptr);
extern UINT _nxd_mqtt_client_sub_unsub(NXD_MQTT_CLIENT *client_ptr, UINT op,
                                       CHAR *topic_name, UINT topic_name_length,
                                       USHORT *packet_id_ptr, UINT QoS);

static VOID nx_azure_iot_hub_transport_sub_ack_notify(NXD_MQTT_CLIENT *client_ptr, UINT type,
                                                      USHORT packet_id, NX_PACKET *transmit_packet_ptr, VOID *context)
{
NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr = (NX_AZURE_IOT_HUB_TRANSPORT *)context;
UINT pending_subscribe_ack = hub_transport_ptr -> nx_azure_iot_hub_transport_message_pending_subscribe_ack;

    NX_PARAMETER_NOT_USED(client_ptr);
    NX_PARAMETER_NOT_USED(transmit_packet_ptr);

    /* Mointor subscribe ack.  */
    if (type == MQTT_CONTROL_PACKET_TYPE_SUBACK)
    {

        if (pending_subscribe_ack == 0)
        {
            return;
        }

        /* Compare the topic.  */
        for (UINT index = 0; index < NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE; index++)
        {
            if ((pending_subscribe_ack & (UINT)(0x1 << index)) &&
                (hub_transport_ptr -> nx_azure_iot_hub_transport_message[index].message_sub_packet_id == packet_id))
            {
                pending_subscribe_ack &= ~((UINT)(0x1 << index));
                break;
            }
        }

        hub_transport_ptr -> nx_azure_iot_hub_transport_message_pending_subscribe_ack = pending_subscribe_ack;
    }
}

static UINT nx_azure_iot_hub_transport_message_subscribe(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr, UINT queue_index)
{
UINT status;

    if ((hub_transport_ptr -> nx_azure_iot_hub_transport_message[queue_index].message_topic_ptr == NX_NULL) ||
        (hub_transport_ptr -> nx_azure_iot_hub_transport_message[queue_index].message_topic_length == 0))
    {
        /* Nothing to subscribe */
        return(NX_AZURE_IOT_SUCCESS);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    hub_transport_ptr -> nx_azure_iot_hub_transport_message_pending_subscribe_ack |= (UINT)(0x1 << queue_index);
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt.nxd_mqtt_ack_receive_notify = nx_azure_iot_hub_transport_sub_ack_notify;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt.nxd_mqtt_ack_receive_context = hub_transport_ptr;

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    status = _nxd_mqtt_client_sub_unsub(&(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt),
                                        (MQTT_CONTROL_PACKET_TYPE_SUBSCRIBE << 4) | 0x02,
                                        (CHAR *)hub_transport_ptr -> nx_azure_iot_hub_transport_message[queue_index].message_topic_ptr,
                                        hub_transport_ptr -> nx_azure_iot_hub_transport_message[queue_index].message_topic_length,
                                        &(hub_transport_ptr -> nx_azure_iot_hub_transport_message[queue_index].message_sub_packet_id),
                                        NX_AZURE_IOT_MQTT_QOS_0);

    if (status)
    {
        tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

        /* Reset the pending subscribe */
        hub_transport_ptr -> nx_azure_iot_hub_transport_message_pending_subscribe_ack &= ~(UINT)(0x1 << queue_index);

        /* Release the mutex.  */
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
    }

    return(status);
}

static UINT nx_azure_iot_hub_transport_messages_enable(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr)
{
UINT status = NX_AZURE_IOT_SUCCESS;
UINT index = 0;

    for (index = 0; index < NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE; index++)
    {
        if (hub_transport_ptr -> nx_azure_iot_hub_transport_message[index].message_topic_ptr != NX_NULL)
        {
            status = nx_azure_iot_hub_transport_message_subscribe(hub_transport_ptr, index);
            if (status)
            {
                LogError(LogLiteralArgs("Failed to enable message type: %d"), index);
                LogError(LogLiteralArgs("Enable status: %d"), status);
                break;
            }
        }
    }

    return(status);
}

static VOID nx_azure_iot_hub_transport_mqtt_receive_callback(NXD_MQTT_CLIENT* client_ptr,
                                                             UINT number_of_messages)
{
NX_AZURE_IOT_RESOURCE *resource = nx_azure_iot_resource_search(client_ptr);
NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr = NX_NULL;
NX_PACKET *packet_ptr;
NX_PACKET *packet_next_ptr;
ULONG topic_offset;
USHORT topic_length;
UINT index = 0;

    /* This function is protected by MQTT mutex.  */

    NX_PARAMETER_NOT_USED(number_of_messages);

    if (resource && (resource -> resource_type == NX_AZURE_IOT_RESOURCE_IOT_HUB))
    {
        hub_transport_ptr = (NX_AZURE_IOT_HUB_TRANSPORT *)resource -> resource_data_ptr;
    }

    if (hub_transport_ptr)
    {
        for (packet_ptr = client_ptr -> message_receive_queue_head;
             packet_ptr;
             packet_ptr = packet_next_ptr)
        {

            /* Store next packet in case current packet is consumed.  */
            packet_next_ptr = packet_ptr -> nx_packet_queue_next;

            /* Adjust packet to simply process logic.  */
            nx_azure_iot_mqtt_packet_adjust(packet_ptr);

            if (nx_azure_iot_hub_transport_process_publish_packet(packet_ptr -> nx_packet_prepend_ptr, &topic_offset,
                                                                  &topic_length))
            {

                /* Message not supported. It will be released.  */
                nx_packet_release(packet_ptr);
                continue;
            }

            if ((topic_offset + topic_length) >
                (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr))
            {

                /* Message with topic spaning multiple packet is not supported. It will be released.  */
                LogDebug(LogLiteralArgs("IoTHub packet receive fail as topic span multiple packet"));
                nx_packet_release(packet_ptr);
                continue;
            }

            for (index = 0; index < NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE; index++)
            {
                if ((hub_transport_ptr -> nx_azure_iot_hub_transport_message[index].message_process != NX_NULL) &&
                    (hub_transport_ptr -> nx_azure_iot_hub_transport_message[index].message_process(hub_transport_ptr,
                                                                                                    packet_ptr, topic_offset,
                                                                                                    topic_length) == NX_AZURE_IOT_SUCCESS))
                {
                    break;
                }
            }

            if (index >= NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE)
            {
                /* Message not supported. It will be released.  */
                nx_packet_release(packet_ptr);
            }
        }

        /* Clear all message from MQTT receive queue.  */
        client_ptr -> message_receive_queue_head = NX_NULL;
        client_ptr -> message_receive_queue_tail = NX_NULL;
        client_ptr -> message_receive_queue_depth = 0;
    }
}

static VOID nx_azure_iot_hub_transport_mqtt_connect_notify(struct NXD_MQTT_CLIENT_STRUCT *client_ptr,
                                                           UINT status, VOID *context)
{
NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr = (NX_AZURE_IOT_HUB_TRANSPORT *)context;


    NX_PARAMETER_NOT_USED(client_ptr);

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Release the mqtt connection resource.  */
    if (hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt_buffer_context)
    {
        nx_azure_iot_buffer_free(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt_buffer_context);
        hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt_buffer_context = NX_NULL;
    }

    /* Update hub client status.  */
    if (status == NXD_MQTT_SUCCESS)
    {
        hub_transport_ptr -> nx_azure_iot_hub_transport_state = NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTED;
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

        status = nx_azure_iot_hub_transport_messages_enable(hub_transport_ptr);

        tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

        if (status)
        {
            hub_transport_ptr -> nx_azure_iot_hub_transport_state = NX_AZURE_IOT_HUB_TRANSPORT_STATUS_NOT_CONNECTED;
            LogError(LogLiteralArgs("IoTHub connect fail: MQTT SUBSCRIBE FAIL status: %d"), status);
        }
    }
    else
    {
        hub_transport_ptr -> nx_azure_iot_hub_transport_state = NX_AZURE_IOT_HUB_TRANSPORT_STATUS_NOT_CONNECTED;
    }

    /* Call connection notify if it is set.  */
    if (hub_transport_ptr -> nx_azure_iot_hub_transport_connection_status_callback)
    {
        hub_transport_ptr -> nx_azure_iot_hub_transport_connection_status_callback(hub_transport_ptr, status,
                                                                                   hub_transport_ptr -> nx_azure_iot_hub_transport_connection_status_callback_arg);
    }

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
}

static VOID nx_azure_iot_hub_transport_mqtt_disconnect_notify(NXD_MQTT_CLIENT *client_ptr)
{
NX_AZURE_IOT_RESOURCE *resource = nx_azure_iot_resource_search(client_ptr);
NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr = NX_NULL;
NX_AZURE_IOT_THREAD *thread_list_ptr;

    /* This function is protected by MQTT mutex.  */

    if (resource && (resource -> resource_type == NX_AZURE_IOT_RESOURCE_IOT_HUB))
    {
        hub_transport_ptr = (NX_AZURE_IOT_HUB_TRANSPORT *)resource -> resource_data_ptr;
    }

    if (hub_transport_ptr == NX_NULL)
    {
        return;
    }

    /* Wake up all threads.  */
    for (thread_list_ptr = hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended;
         thread_list_ptr;
         thread_list_ptr = thread_list_ptr -> thread_next)
    {
        tx_thread_wait_abort(thread_list_ptr -> thread_ptr);
    }

    /* Do not call callback if not connected, as at our layer connected means : mqtt connect + subscribe messages topic.  */
    if (hub_transport_ptr -> nx_azure_iot_hub_transport_state == NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTED)
    {
        hub_transport_ptr -> nx_azure_iot_hub_transport_state = NX_AZURE_IOT_HUB_TRANSPORT_STATUS_NOT_CONNECTED;

        /* Call connection notify if it is set.  */
        if (hub_transport_ptr -> nx_azure_iot_hub_transport_connection_status_callback)
        {
            hub_transport_ptr -> nx_azure_iot_hub_transport_connection_status_callback(hub_transport_ptr,
                                                                                       NX_AZURE_IOT_DISCONNECTED,
                                                                                       hub_transport_ptr -> nx_azure_iot_hub_transport_connection_status_callback_arg);
        }
    }
}

static UINT nx_azure_iot_hub_transport_sas_token_get(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                     ULONG expiry_time_secs, const UCHAR *key, UINT key_len,
                                                     UCHAR *sas_buffer, UINT sas_buffer_len, UINT *sas_length)
{
UCHAR *buffer_ptr;
UINT buffer_size;
VOID *buffer_context;
UINT bytes_used;
UINT status;
UCHAR *output_ptr;
UINT output_len;
az_span span;
az_result core_result;

    status = nx_azure_iot_buffer_allocate(hub_transport_ptr -> nx_azure_iot_ptr, &buffer_ptr, &buffer_size, &buffer_context);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub sas token fail: BUFFER ALLOCATE FAIL"));
        return(status);
    }

    span = az_span_create(sas_buffer, (INT)sas_buffer_len);
    core_result = hub_transport_ptr -> nx_azure_iot_hub_transport_sas_signature(hub_transport_ptr,
                                                                                expiry_time_secs, span, &span);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoTHub failed failed to get signature with error status: %d"), status);
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    bytes_used = (UINT)az_span_size(span);
    status = nx_azure_iot_base64_hmac_sha256_calculate(&(hub_transport_ptr -> nx_azure_iot_hub_transport_resource),
                                                       key, key_len, sas_buffer, bytes_used,
                                                       buffer_ptr, buffer_size, &output_ptr, &output_len);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub failed to encoded hash"));
        nx_azure_iot_buffer_free(buffer_context);
        return(status);
    }

    span = az_span_create(output_ptr, (INT)output_len);
    core_result = hub_transport_ptr -> nx_azure_iot_hub_transport_sas_password(hub_transport_ptr,
                                                                               expiry_time_secs, span,
                                                                               AZ_SPAN_EMPTY,
                                                                               sas_buffer, sas_buffer_len,
                                                                               &bytes_used);
    if (az_result_failed(core_result))
    {
        LogError(LogLiteralArgs("IoTHub failed to generate token with error status: %d"), core_result);
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    *sas_length = bytes_used;
    nx_azure_iot_buffer_free(buffer_context);

    return(NX_AZURE_IOT_SUCCESS);
}

static VOID nx_azure_iot_hub_transport_thread_dequeue(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                      NX_AZURE_IOT_THREAD *thread_list_ptr)
{
NX_AZURE_IOT_THREAD *thread_list_prev = NX_NULL;
NX_AZURE_IOT_THREAD *thread_list_current;

    for (thread_list_current = hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended;
         thread_list_current;
         thread_list_current = thread_list_current -> thread_next)
    {
        if (thread_list_current == thread_list_ptr)
        {

            /* Found the thread to dequeue.  */
            if (thread_list_prev == NX_NULL)
            {
                hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended = thread_list_current -> thread_next;
            }
            else
            {
                thread_list_prev -> thread_next = thread_list_current -> thread_next;
            }
            break;
        }

        thread_list_prev = thread_list_current;
    }
}

static UINT nx_azure_iot_hub_transport_message_receive_internal(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                                UINT message_queue_index, UINT expected_id,
                                                                NX_AZURE_IOT_HUB_TRANSPORT_RECEIVE_MESSAGE *receive_message,
                                                                NX_PACKET **packet_pptr, UINT wait_option)
{
NX_PACKET *packet_ptr = NX_NULL;
UINT old_threshold;
NX_AZURE_IOT_THREAD thread_list;

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    if (receive_message -> message_head)
    {
        packet_ptr = receive_message -> message_head;
        if (receive_message -> message_tail == packet_ptr)
        {
            receive_message -> message_tail = NX_NULL;
        }

        receive_message -> message_head = packet_ptr -> nx_packet_queue_next;
        packet_ptr -> nx_packet_queue_next = NX_NULL;
    }
    else if (wait_option)
    {
        thread_list.thread_message_type = message_queue_index;
        thread_list.thread_ptr = tx_thread_identify();
        thread_list.thread_received_message = NX_NULL;
        thread_list.thread_expected_id = expected_id;
        thread_list.thread_next = hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended;
        hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended = &thread_list;

        /* Disable preemption.  */
        tx_thread_preemption_change(tx_thread_identify(), 0, &old_threshold);

        /* Release the mutex.  */
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

        tx_thread_sleep(wait_option);

        /* Obtain the mutex.  */
        tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

        nx_azure_iot_hub_transport_thread_dequeue(hub_transport_ptr, &thread_list);

        /* Restore preemption.  */
        tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
        packet_ptr = thread_list.thread_received_message;
    }

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    if (packet_ptr == NX_NULL)
    {
        if (hub_transport_ptr -> nx_azure_iot_hub_transport_state != NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTED)
        {
            LogError(LogLiteralArgs("IoTHub transport message receive fail:  IoTHub client not connected"));
            return(NX_AZURE_IOT_DISCONNECTED);
        }

        return(NX_AZURE_IOT_NO_PACKET);
    }

    *packet_pptr = packet_ptr;

    return(NX_AZURE_IOT_SUCCESS);
}

static VOID nx_azure_iot_hub_transport_received_message_cleanup(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr)
{
NX_PACKET *current_ptr;
NX_PACKET *next_ptr;
NX_AZURE_IOT_HUB_TRANSPORT_RECEIVE_MESSAGE *message_queue_ptr;

    for (UINT index = 0; index < NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE; index++)
    {
        message_queue_ptr = &(hub_transport_ptr -> nx_azure_iot_hub_transport_message[index]);
        for (current_ptr = message_queue_ptr -> message_head; current_ptr; current_ptr = next_ptr)
        {

            /* Get next packet in queue.  */
            next_ptr = current_ptr -> nx_packet_queue_next;

            /* Release current packet.  */
            current_ptr -> nx_packet_queue_next = NX_NULL;
            nx_packet_release(current_ptr);
        }

        /* Reset received messages.  */
        message_queue_ptr -> message_head = NX_NULL;
        message_queue_ptr -> message_tail = NX_NULL;
    }

}

UINT nx_azure_iot_hub_transport_initialize(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                           NX_AZURE_IOT *nx_azure_iot_ptr,
                                           const UCHAR *host_name, UINT host_name_length,
                                           const NX_AZURE_IOT_HUB_TRANSPORT_CLIENT_ID_GET_FN client_id_get,
                                           const NX_AZURE_IOT_HUB_TRANSPORT_USERNAME_GET_FN username_get,
                                           const NX_CRYPTO_METHOD **crypto_array, UINT crypto_array_size,
                                           const NX_CRYPTO_CIPHERSUITE **cipher_map, UINT cipher_map_size,
                                           UCHAR *metadata_memory, UINT memory_size,
                                           NX_SECURE_X509_CERT *trusted_certificate,
                                           VOID *client_context)
{
UINT status;
NX_AZURE_IOT_RESOURCE *resource_ptr;

    if ((nx_azure_iot_ptr == NX_NULL) || (hub_transport_ptr == NX_NULL) || (host_name == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub initialization fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    memset(hub_transport_ptr, 0, sizeof(NX_AZURE_IOT_HUB_TRANSPORT));

    hub_transport_ptr -> nx_azure_iot_ptr = nx_azure_iot_ptr;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_crypto_array = crypto_array;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_crypto_array_size = crypto_array_size;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_cipher_map = cipher_map;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_cipher_map_size = cipher_map_size;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_metadata_ptr = metadata_memory;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_metadata_size = memory_size;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_trusted_certificate = trusted_certificate;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_hostname = host_name;
    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_hostname_length = host_name_length;
    hub_transport_ptr -> nx_azure_iot_hub_transport_client_context = client_context;
    hub_transport_ptr -> nx_azure_iot_hub_transport_client_id_get = client_id_get;
    hub_transport_ptr -> nx_azure_iot_hub_transport_username_get = username_get;

    /* Set resource pointer.  */
    resource_ptr = &(hub_transport_ptr -> nx_azure_iot_hub_transport_resource);

    /* Create MQTT client.  */
    status = _nxd_mqtt_client_cloud_create(&(resource_ptr -> resource_mqtt),
                                           (CHAR *)nx_azure_iot_ptr -> nx_azure_iot_name,
                                           "", 0,
                                           nx_azure_iot_ptr -> nx_azure_iot_ip_ptr,
                                           nx_azure_iot_ptr -> nx_azure_iot_pool_ptr,
                                           &nx_azure_iot_ptr -> nx_azure_iot_cloud);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub initialization fail: MQTT CLIENT CREATE FAIL status: %d"), status);
        return(status);
    }

    /* Set mqtt receive notify.  */
    status = nxd_mqtt_client_receive_notify_set(&(resource_ptr -> resource_mqtt),
                                                nx_azure_iot_hub_transport_mqtt_receive_callback);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub set message callback status: %d"), status);
        nxd_mqtt_client_delete(&(resource_ptr -> resource_mqtt));
        return(status);
    }

    /* Obtain the mutex.   */
    tx_mutex_get(nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Link the resource.  */
    resource_ptr -> resource_data_ptr = (VOID *)hub_transport_ptr;
    resource_ptr -> resource_type = NX_AZURE_IOT_RESOURCE_IOT_HUB;
    nx_azure_iot_resource_add(nx_azure_iot_ptr, resource_ptr);

    /* Release the mutex.  */
    tx_mutex_put(nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_deinitialize(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr)
{
UINT status;

    /* Check for invalid input pointers.  */
    if ((hub_transport_ptr == NX_NULL) || (hub_transport_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub deinitialize fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    nx_azure_iot_hub_transport_disconnect(hub_transport_ptr);

    status = nxd_mqtt_client_delete(&(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt));
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub client delete fail status: %d"), status);
        return(status);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Remove resource from list.  */
    status = nx_azure_iot_resource_remove(hub_transport_ptr -> nx_azure_iot_ptr,
                                          &(hub_transport_ptr -> nx_azure_iot_hub_transport_resource));
    if (status)
    {

        /* Release the mutex.  */
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        LogError(LogLiteralArgs("IoTHub client handle not found"));
        return(status);
    }

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_device_cert_set(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                NX_SECURE_X509_CERT *device_certificate)
{
    if ((hub_transport_ptr == NX_NULL) ||
        (hub_transport_ptr -> nx_azure_iot_ptr == NX_NULL) ||
        (device_certificate == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub device certificate set fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_device_certificate = device_certificate;

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_symmetric_key_auth_set(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                       const NX_AZURE_IOT_HUB_TRANSPORT_SIGNATURE_GET_FN sas_signature_get,
                                                       const NX_AZURE_IOT_HUB_TRANSPORT_PASSWORD_GET_FN sas_password_get,
                                                       const UCHAR *symmetric_key, UINT symmetric_key_length)
{
    if ((hub_transport_ptr == NX_NULL)  || (hub_transport_ptr -> nx_azure_iot_ptr == NX_NULL) ||
        (symmetric_key == NX_NULL) || (symmetric_key_length == 0))
    {
        LogError(LogLiteralArgs("IoTHub symmetric key fail: Invalid argument"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    hub_transport_ptr -> nx_azure_iot_hub_transport_symmetric_key = symmetric_key;
    hub_transport_ptr -> nx_azure_iot_hub_transport_symmetric_key_length = symmetric_key_length;
    hub_transport_ptr -> nx_azure_iot_hub_transport_sas_signature = sas_signature_get;
    hub_transport_ptr -> nx_azure_iot_hub_transport_sas_password = sas_password_get;
    hub_transport_ptr -> nx_azure_iot_hub_transport_token_refresh = nx_azure_iot_hub_transport_sas_token_get;

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_connection_callback_set(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                        NX_AZURE_IOT_HUB_TRANSPORT_CONNECTION_STATUS_CB connection_cb,
                                                        NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg)
{
    if ((hub_transport_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub set connection cb fail: Invalid argument"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Set callback function for disconnection.  */
    nxd_mqtt_client_disconnect_notify_set(&(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt),
                                          nx_azure_iot_hub_transport_mqtt_disconnect_notify);

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    hub_transport_ptr -> nx_azure_iot_hub_transport_connection_status_callback = connection_cb;
    hub_transport_ptr -> nx_azure_iot_hub_transport_connection_status_callback_arg = arg;

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_connect(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                        UINT clean_session, UINT wait_option)
{
UINT            status;
NXD_ADDRESS     server_address;
NX_AZURE_IOT_RESOURCE *resource_ptr;
NXD_MQTT_CLIENT *mqtt_client_ptr;
UCHAR           *buffer_ptr;
UINT            buffer_size;
VOID            *buffer_context;
UINT            buffer_length;
ULONG           expiry_time_secs;
az_result       core_result;

    /* Check for invalid input pointers.  */
    if ((hub_transport_ptr == NX_NULL) || (hub_transport_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub connect fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Check for status.  */
    if (hub_transport_ptr -> nx_azure_iot_hub_transport_state == NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTED)
    {
        LogError(LogLiteralArgs("IoTHub already connected"));
        return(NX_AZURE_IOT_ALREADY_CONNECTED);
    }
    else if (hub_transport_ptr -> nx_azure_iot_hub_transport_state == NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTING)
    {
        LogError(LogLiteralArgs("IoTHub is connecting"));
        return(NX_AZURE_IOT_CONNECTING);
    }

    /* Resolve the host name.  */
    /* Note: always using default dns timeout.  */
    status = nxd_dns_host_by_name_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_dns_ptr,
                                      (UCHAR *)hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_hostname,
                                      &server_address, NX_AZURE_IOT_HUB_TRANSPORT_DNS_TIMEOUT, NX_IP_VERSION_V4);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub connect fail: DNS RESOLVE FAIL status: %d"), status);
        return(status);
    }

    /* Allocate buffer for client id, username and sas token.  */
    status = nx_azure_iot_buffer_allocate(hub_transport_ptr -> nx_azure_iot_ptr,
                                          &buffer_ptr, &buffer_size, &buffer_context);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub failed initialization: BUFFER ALLOCATE FAIL"));
        return(status);
    }

    /* Obtain the mutex.   */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Set resource pointer and buffer context.  */
    resource_ptr = &(hub_transport_ptr -> nx_azure_iot_hub_transport_resource);

    /* Build client id.  */
    buffer_length = buffer_size;
    core_result = hub_transport_ptr -> nx_azure_iot_hub_transport_client_id_get(hub_transport_ptr,
                                                                                buffer_ptr, buffer_length,
                                                                                &buffer_length);
    if (az_result_failed(core_result))
    {
        /* Release the mutex.  */
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    resource_ptr -> resource_mqtt_client_id = buffer_ptr;
    resource_ptr -> resource_mqtt_client_id_length = buffer_length;

    /* Update buffer for user name.  */
    buffer_ptr += resource_ptr -> resource_mqtt_client_id_length;
    buffer_size -= resource_ptr -> resource_mqtt_client_id_length;

    /* Build user name.  */
    buffer_length = buffer_size;
    core_result = hub_transport_ptr -> nx_azure_iot_hub_transport_username_get(hub_transport_ptr,
                                                                               buffer_ptr, buffer_length,
                                                                               &buffer_length);
    if (az_result_failed(core_result))
    {

        /* Release the mutex.  */
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    resource_ptr -> resource_mqtt_user_name = buffer_ptr;
    resource_ptr -> resource_mqtt_user_name_length = buffer_length;

    /* Build sas token.  */
    resource_ptr -> resource_mqtt_sas_token = buffer_ptr + buffer_length;
    resource_ptr -> resource_mqtt_sas_token_length = buffer_size - buffer_length;

    /* Check if token refersh is setup.  */
    if (hub_transport_ptr -> nx_azure_iot_hub_transport_token_refresh)
    {
        status = nx_azure_iot_unix_time_get(hub_transport_ptr -> nx_azure_iot_ptr, &expiry_time_secs);
        if (status)
        {

            /* Release the mutex.  */
            tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
            nx_azure_iot_buffer_free(buffer_context);
            LogError(LogLiteralArgs("IoTHub connect fail: unixtime get failed status: %d"), status);
            return(status);
        }

        expiry_time_secs += NX_AZURE_IOT_HUB_TRANSPORT_TOKEN_EXPIRY;
        if ((status = hub_transport_ptr -> nx_azure_iot_hub_transport_token_refresh(hub_transport_ptr,
                                                                                    expiry_time_secs,
                                                                                    hub_transport_ptr -> nx_azure_iot_hub_transport_symmetric_key,
                                                                                    hub_transport_ptr -> nx_azure_iot_hub_transport_symmetric_key_length,
                                                                                    resource_ptr -> resource_mqtt_sas_token,
                                                                                    resource_ptr -> resource_mqtt_sas_token_length,
                                                                                    &(resource_ptr -> resource_mqtt_sas_token_length))))
        {

            /* Release the mutex.  */
            tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
            nx_azure_iot_buffer_free(buffer_context);
            LogError(LogLiteralArgs("IoTHub connect fail: Token generation failed status: %d"), status);
            return(status);
        }
    }
    else
    {
        resource_ptr ->  resource_mqtt_sas_token_length = 0;
    }

    mqtt_client_ptr = &(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt);

    /* Update client id.  */
    mqtt_client_ptr -> nxd_mqtt_client_id = (CHAR *)resource_ptr -> resource_mqtt_client_id;
    mqtt_client_ptr -> nxd_mqtt_client_id_length = resource_ptr -> resource_mqtt_client_id_length;

    /* Set login info.  */
    status = nxd_mqtt_client_login_set(&(resource_ptr -> resource_mqtt),
                                       (CHAR *)resource_ptr -> resource_mqtt_user_name,
                                       resource_ptr -> resource_mqtt_user_name_length,
                                       (CHAR *)resource_ptr -> resource_mqtt_sas_token,
                                       resource_ptr -> resource_mqtt_sas_token_length);
    if (status)
    {

        /* Release the mutex.  */
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        nx_azure_iot_buffer_free(buffer_context);
        LogError(LogLiteralArgs("IoTHub connect fail: MQTT CLIENT LOGIN SET FAIL status: %d"), status);
        return(status);
    }

    /* Set connect notify for non-blocking mode.  */
    if (wait_option == 0)
    {
        mqtt_client_ptr -> nxd_mqtt_connect_notify = nx_azure_iot_hub_transport_mqtt_connect_notify;
        mqtt_client_ptr -> nxd_mqtt_connect_context = hub_transport_ptr;
    }

    /* Save the resource buffer.  */
    resource_ptr -> resource_mqtt_buffer_context = buffer_context;
    resource_ptr -> resource_mqtt_buffer_size = buffer_size;

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    /* Start MQTT connection.  */
    status = nxd_mqtt_client_secure_connect(mqtt_client_ptr, &server_address, NXD_MQTT_TLS_PORT,
                                            nx_azure_iot_mqtt_tls_setup, NX_AZURE_IOT_MQTT_KEEP_ALIVE,
                                            clean_session, wait_option);

    /* Check status for non-blocking mode.  */
    if ((wait_option == 0) && (status == NX_IN_PROGRESS))
    {

        /* Obtain the mutex.  */
        tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

        hub_transport_ptr -> nx_azure_iot_hub_transport_state = NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTING;

        /* Release the mutex.  */
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

        /* Return in-progress completion status.  */
        return(NX_AZURE_IOT_CONNECTING);
    }

    /* Call notify in synchronous way */
    nx_azure_iot_hub_transport_mqtt_connect_notify(mqtt_client_ptr, status, (VOID *)hub_transport_ptr);

    return(status);
}

UINT nx_azure_iot_hub_transport_disconnect(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr)
{
UINT status;
NX_AZURE_IOT_THREAD *thread_list_ptr;

    /* Check for invalid input pointers.  */
    if ((hub_transport_ptr == NX_NULL) || (hub_transport_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub client disconnect fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Disconnect.  */
    status = nxd_mqtt_client_disconnect(&(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt));
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub disconnect fail status: %d"), status);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Release the mqtt connection resource.  */
    if (hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt_buffer_context)
    {
        nx_azure_iot_buffer_free(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt_buffer_context);
        hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt_buffer_context = NX_NULL;
    }

    /* Wakeup all suspend threads.  */
    for (thread_list_ptr = hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended;
         thread_list_ptr;
         thread_list_ptr = thread_list_ptr -> thread_next)
    {
        tx_thread_wait_abort(thread_list_ptr -> thread_ptr);
    }

    hub_transport_ptr -> nx_azure_iot_hub_transport_state = NX_AZURE_IOT_HUB_TRANSPORT_STATUS_NOT_CONNECTED;

    /* cleanup all the queues */
    nx_azure_iot_hub_transport_received_message_cleanup(hub_transport_ptr);

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(status);
}

UINT nx_azure_iot_hub_transport_receive_message_enable(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr, UINT message_queue_index,
                                                       const UCHAR *message_topic_ptr, UINT message_topic_length,
                                                       NX_AZURE_IOT_HUB_TRANSPORT_MESSAGE_PROCESS_FN message_process)
{
UINT status;

    if ((hub_transport_ptr == NX_NULL) ||
        (message_queue_index >= NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE))
    {
        LogError(LogLiteralArgs("IoTHub transport receive message process fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_topic_ptr = message_topic_ptr;
    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_topic_length = message_topic_length;
    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_process = message_process;
    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_control_flag |= NZ_AZURE_IOT_HUB_TRANSPORT_MESSAGE_ENABLE;

    /* Register callbacks even if not connect and when connect complete subscribe for topics.  */
    if (hub_transport_ptr -> nx_azure_iot_hub_transport_state != NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTED)
    {
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        return(NX_AZURE_IOT_SUCCESS);
    }

    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    status = nx_azure_iot_hub_transport_message_subscribe(hub_transport_ptr, message_queue_index);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub transport receive subscribe fail: %d"), status);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_receive_message_disable(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                        UINT message_queue_index)
{
UINT status;

    if ((hub_transport_ptr == NX_NULL) ||
        (message_queue_index >= NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE))
    {
        LogError(LogLiteralArgs("IoTHub transport receive message process fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if (hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_topic_ptr == NX_NULL)
    {
        return(NX_AZURE_IOT_SUCCESS);
    }

    status = nxd_mqtt_client_unsubscribe(&(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt),
                                         (CHAR *)hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_topic_ptr,
                                         hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_topic_length);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub transport receive topic unsubscribe fail status: %d"), status);
        return(status);
    }

    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_sub_packet_id = 0;
    hub_transport_ptr -> nx_azure_iot_hub_transport_message_pending_subscribe_ack &= ~(UINT)(0x1 << message_queue_index);
    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_topic_ptr = NX_NULL;
    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_topic_length = 0;
    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_process = NX_NULL;
    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_control_flag &= (USHORT)(~NZ_AZURE_IOT_HUB_TRANSPORT_MESSAGE_ENABLE);

    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_receive_message_callback_set(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr, UINT message_queue_index,
                                                             NX_AZURE_IOT_HUB_TRANSPORT_MESSAGE_CB_FN message_callback,
                                                             NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg1, VOID *arg2)
{
    if ((hub_transport_ptr == NX_NULL) ||
        (message_queue_index >= NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE) ||
        (hub_transport_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub transport receive message set callback fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_callback = message_callback;
    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_callback_arg1 = arg1;
    hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_callback_arg2 = arg2;

    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_receive_message_is_subscribed(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                              UINT message_queue_index, UINT wait_option)
{
   if ((hub_transport_ptr == NX_NULL) ||
        (message_queue_index >= NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE))
    {
        LogError(LogLiteralArgs("IoTHub transport receive message is subscribed fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Wait for subscribe ack.  */
    while (1)
    {
        tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

        if (!(hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_control_flag &
              NZ_AZURE_IOT_HUB_TRANSPORT_MESSAGE_ENABLE))
        {
            LogError(LogLiteralArgs("IoTHub transport receive message is subscribed fail: not enabled"));
            return(NX_AZURE_IOT_NOT_ENABLED);
        }

        /* Check if it is still in connected status.  */
        if (hub_transport_ptr -> nx_azure_iot_hub_transport_state != NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTED)
        {

            /* Clean ack receive notify.  */
            hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt.nxd_mqtt_ack_receive_notify = NX_NULL;
            tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
            return(NX_AZURE_IOT_DISCONNECTED);
        }

        if (hub_transport_ptr -> nx_azure_iot_hub_transport_message_pending_subscribe_ack == 0)
        {
            /* Clean ack receive notify.  */
            hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt.nxd_mqtt_ack_receive_notify = NX_NULL;
            tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
            break;
        }

        /* Check if receive the subscribe ack.  */
        if ((hub_transport_ptr -> nx_azure_iot_hub_transport_message_pending_subscribe_ack & (UINT)(0x1 << message_queue_index)) == 0)
        {
            tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
            break;
        }

        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

        /* Update wait time.  */
        if (wait_option != NX_WAIT_FOREVER)
        {
            if (wait_option > 0)
            {
                wait_option--;
            }
            else
            {
                return(NX_AZURE_IOT_NO_SUBSCRIBE_ACK);
            }
        }

        tx_thread_sleep(1);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_message_receive(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                UINT message_queue_index, UINT expected_id,
                                                NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;

    if ((hub_transport_ptr == NX_NULL) ||
        (packet_pptr == NX_NULL) ||
        (message_queue_index >= NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE))
    {
        LogError(LogLiteralArgs("IoTHub transport argument: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if ((hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index].message_control_flag &
         NZ_AZURE_IOT_HUB_TRANSPORT_MESSAGE_ENABLE))
    {
        status = nx_azure_iot_hub_transport_message_receive_internal(hub_transport_ptr, message_queue_index, expected_id,
                                                                     &(hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index]),
                                                                     packet_pptr, wait_option);
    }
    else
    {
        LogError(LogLiteralArgs("IoTHub transport receive queue not enabled for message_queue_index : %d"), message_queue_index);
        status = NX_AZURE_IOT_NOT_ENABLED;
    }

    return(status);
}

UINT nx_azure_iot_hub_transport_receive_notify(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                               NX_PACKET *packet_ptr, UINT message_queue_index,
                                               UINT correlation_id)
{
NX_AZURE_IOT_THREAD *thread_list_prev = NX_NULL;
NX_AZURE_IOT_THREAD *thread_list_ptr;
NX_AZURE_IOT_HUB_TRANSPORT_RECEIVE_MESSAGE *receive_message = NX_NULL;

    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Search thread waiting for message type.  */
    for (thread_list_ptr = hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended;
         thread_list_ptr;
         thread_list_ptr = thread_list_ptr -> thread_next)
    {

        /* Each queue point to messages of particular type */
        if ((thread_list_ptr -> thread_message_type == message_queue_index) &&
            (correlation_id == thread_list_ptr -> thread_expected_id))
        {

            /* Found a thread waiting for message type.  */
            if (thread_list_prev == NX_NULL)
            {
                hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended = thread_list_ptr -> thread_next;
            }
            else
            {
                thread_list_prev -> thread_next = thread_list_ptr -> thread_next;
            }

            thread_list_ptr -> thread_received_message = packet_ptr;
            tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
            tx_thread_wait_abort(thread_list_ptr -> thread_ptr);

            return(NX_AZURE_IOT_SUCCESS);
        }

        thread_list_prev = thread_list_ptr;
    }

    /* Check if queue exist for this message type and then notify using callback if present */
    if (message_queue_index < NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE)
    {
        receive_message = &(hub_transport_ptr -> nx_azure_iot_hub_transport_message[message_queue_index]);

        if (receive_message -> message_tail)
        {
            receive_message -> message_tail -> nx_packet_queue_next = packet_ptr;
        }
        else
        {
            receive_message -> message_head = packet_ptr;
        }
        receive_message -> message_tail = packet_ptr;

        /* Check for user callback function.  */
        if (receive_message -> message_callback)
        {
            receive_message -> message_callback(hub_transport_ptr,
                                                receive_message -> message_callback_arg1,
                                                receive_message -> message_callback_arg2);
        }

        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

        return(NX_AZURE_IOT_SUCCESS);
    }

    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_NOT_FOUND);
}

UINT nx_azure_iot_hub_transport_request_response(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                 UINT request_id, NX_PACKET *packet_ptr, ULONG topic_length,
                                                 const UCHAR *message_buffer, UINT message_length, UINT response_queue_index,
                                                 NX_PACKET **response_packet_pptr, UINT wait_option)
{
NX_AZURE_IOT_THREAD thread_list;
UINT status;

    if ((hub_transport_ptr == NX_NULL) ||
        (response_queue_index >= NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE))
    {
        LogError(LogLiteralArgs("IoTHub transport request response argument: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if (!(hub_transport_ptr -> nx_azure_iot_hub_transport_message[response_queue_index].message_control_flag &
          NZ_AZURE_IOT_HUB_TRANSPORT_MESSAGE_ENABLE))
    {
        LogError(LogLiteralArgs("IoTHub transport receive queue not enabled for response_queue_index : %d"), response_queue_index);
        return(NX_AZURE_IOT_NOT_ENABLED);
    }

    if ((message_buffer != NX_NULL) && (message_length != 0))
    {

        /* Append payload.  */
        status = nx_packet_data_append(packet_ptr, (VOID *)message_buffer, message_length,
                                       packet_ptr -> nx_packet_pool_owner,
                                       wait_option);
        if (status)
        {
            LogError(LogLiteralArgs("IoTHub client reported state send fail: append failed"));
            return(status);
        }
    }
    

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    thread_list.thread_message_type = response_queue_index;
    thread_list.thread_ptr = tx_thread_identify();
    thread_list.thread_expected_id = request_id;
    thread_list.thread_received_message = NX_NULL;
    thread_list.thread_next = hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended;
    hub_transport_ptr -> nx_azure_iot_hub_transport_thread_suspended = &thread_list;

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    status = nx_azure_iot_publish_mqtt_packet(&(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt),
                                              packet_ptr, topic_length, NX_NULL, NX_AZURE_IOT_MQTT_QOS_0,
                                              wait_option);

    if (status)
    {
        /* remove thread from waiting suspend queue.  */
        tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);
        nx_azure_iot_hub_transport_thread_dequeue(hub_transport_ptr, &thread_list);
        tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

        LogError(LogLiteralArgs("IoTHub transport send: PUBLISH FAIL status: %d"), status);
        return(status);
    }

    if ((thread_list.thread_received_message) == NX_NULL && wait_option)
    {
        tx_thread_sleep(wait_option);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    nx_azure_iot_hub_transport_thread_dequeue(hub_transport_ptr, &thread_list);
    *response_packet_pptr = thread_list.thread_received_message;

    /* Release the mutex.  */
    tx_mutex_put(hub_transport_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_publish(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr, NX_PACKET *packet_ptr,
                                        const UCHAR *data, UINT data_size, UINT qos, UINT wait_option)
{
UINT status;
UINT topic_len;
UCHAR packet_id[2];

    if ((hub_transport_ptr == NX_NULL) || (packet_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub transport publish fail: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    topic_len = packet_ptr -> nx_packet_length;

    if (qos != 0)
    {
        status = nx_azure_iot_mqtt_packet_id_get(&(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt),
                                                 packet_id, wait_option);

        if (status)
        {
            LogError(LogLiteralArgs("Failed to get packet id"));
            return(status);
        }

        /* Append packet identifier.  */
        status = nx_packet_data_append(packet_ptr, packet_id, sizeof(packet_id),
                                       packet_ptr -> nx_packet_pool_owner,
                                       wait_option);
        if (status)
        {
            LogError(LogLiteralArgs("packet id append fail"));
            return(status);
        }
    }

    if (data && (data_size != 0))
    {

        /* Append payload.  */
        status = nx_packet_data_append(packet_ptr, (VOID *)data, data_size,
                                       packet_ptr -> nx_packet_pool_owner,
                                       wait_option);
        if (status)
        {
            LogError(LogLiteralArgs("data append fail"));
            return(status);
        }
    }

    status = nx_azure_iot_publish_mqtt_packet(&(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt),
                                              packet_ptr, topic_len, packet_id, qos, wait_option);
    if (status)
    {
        LogError(LogLiteralArgs("IoTHub transport send fail: PUBLISH FAIL status: %d"), status);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_process_publish_packet(UCHAR *start_ptr, ULONG *topic_offset_ptr,
                                                       USHORT *topic_length_ptr)
{
UCHAR *byte = start_ptr;
UINT byte_count = 0;
UINT multiplier = 1;
UINT remaining_length = 0;
UINT topic_length;

    /* Validate packet start contains fixed header.  */
    do
    {
        if (byte_count >= 4)
        {
            LogError(LogLiteralArgs("Invalid mqtt packet start position"));
            return(NX_AZURE_IOT_INVALID_PACKET);
        }

        byte++;
        remaining_length += (((*byte) & 0x7F) * multiplier);
        multiplier = multiplier << 7;
        byte_count++;
    } while ((*byte) & 0x80);

    if (remaining_length < 2)
    {
        return(NX_AZURE_IOT_INVALID_PACKET);
    }

    /* Retrieve topic length.  */
    byte++;
    topic_length = (UINT)(*(byte) << 8) | (*(byte + 1));

    if (topic_length > remaining_length - 2u)
    {
        return(NX_AZURE_IOT_INVALID_PACKET);
    }

    *topic_offset_ptr = (ULONG)((byte + 2) - start_ptr);
    *topic_length_ptr = (USHORT)topic_length;

    /* Return.  */
    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_adjust_payload(NX_PACKET *packet_ptr)
{
UINT status;
ULONG topic_offset;
USHORT topic_length;
ULONG message_offset;
ULONG message_length;

    status = _nxd_mqtt_process_publish_packet(packet_ptr, &topic_offset,
                                              &topic_length, &message_offset,
                                              &message_length);
    if (status)
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

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

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_transport_publish_packet_get(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                   NX_PACKET **packet_pptr, UINT wait_option)
{
    if ((hub_transport_ptr == NX_NULL) ||
        (hub_transport_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError(LogLiteralArgs("IoTHub transport publish packet get: INVALID POINTER"));
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_publish_packet_get(hub_transport_ptr -> nx_azure_iot_ptr,
                                           &(hub_transport_ptr -> nx_azure_iot_hub_transport_resource.resource_mqtt),
                                           packet_pptr, wait_option));
}
