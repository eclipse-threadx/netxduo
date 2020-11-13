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

/**
 * @file nx_azure_iot_hub_transport.h
 *
 *
 */

#ifndef NX_AZURE_IOT_HUB_TRANSPORT_H
#define NX_AZURE_IOT_HUB_TRANSPORT_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "azure/core/az_result.h"
#include "azure/core/az_span.h"
#include "nx_azure_iot.h"
#include "nx_api.h"
#include "nx_cloud.h"
#include "nxd_dns.h"
#include "nxd_mqtt_client.h"

#define NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE                       5

/* Set the default timeout for DNS query.  */
#ifndef NX_AZURE_IOT_HUB_TRANSPORT_DNS_TIMEOUT
#ifndef NX_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT
#define NX_AZURE_IOT_HUB_TRANSPORT_DNS_TIMEOUT                                  (5 * NX_IP_PERIODIC_RATE)
#else
#define NX_AZURE_IOT_HUB_TRANSPORT_DNS_TIMEOUT                                  NX_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT
#endif /* NX_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT */
#endif /* NX_AZURE_IOT_HUB_TRANSPORT_DNS_TIMEOUT */


/* Set the default token expiry in secs.  */
#ifndef NX_AZURE_IOT_HUB_TRANSPORT_TOKEN_EXPIRY
#ifndef NX_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY
#define NX_AZURE_IOT_HUB_TRANSPORT_TOKEN_EXPIRY                                 (3600)
#else
#define NX_AZURE_IOT_HUB_TRANSPORT_TOKEN_EXPIRY                                 NX_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY
#endif /* NX_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY */
#endif /* NX_AZURE_IOT_HUB_TRANSPORT_TOKEN_EXPIRY */

/* Define AZ IoT Hub Client state.  */
/**< The client is not connected */
#define NX_AZURE_IOT_HUB_TRANSPORT_STATUS_NOT_CONNECTED                         0

/**< The client is connecting */
#define NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTING                            1

/**< The client is connected */
#define NX_AZURE_IOT_HUB_TRANSPORT_STATUS_CONNECTED                             2

/* Default TELEMETRY QoS is QoS1 */
#ifndef NX_AZURE_IOT_HUB_TRANSPORT_TELEMETRY_QOS
#define NX_AZURE_IOT_HUB_TRANSPORT_TELEMETRY_QOS                                NX_AZURE_IOT_MQTT_QOS_1
#endif /* NX_AZURE_IOT_HUB_TRANSPORT_TELEMETRY_QOS */

#define NZ_AZURE_IOT_HUB_TRANSPORT_MESSAGE_ENABLE                               (0x0001)

/* Forward declaration */
struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT;

typedef VOID (*NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN)(VOID);
typedef VOID (*NX_AZURE_IOT_HUB_TRANSPORT_CONNECTION_STATUS_CB)(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                                UINT status, NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg);
typedef az_result (*NX_AZURE_IOT_HUB_TRANSPORT_CLIENT_ID_GET_FN)(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                                 UCHAR *buffer, UINT buffer_len, UINT *bytes_copied);
typedef az_result (*NX_AZURE_IOT_HUB_TRANSPORT_USERNAME_GET_FN)(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                                UCHAR *buffer, UINT buffer_len, UINT *bytes_copied);
typedef az_result (*NX_AZURE_IOT_HUB_TRANSPORT_SIGNATURE_GET_FN)(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                                 ULONG expiry_time_secs, az_span buffer, az_span *out_buffer);
typedef az_result (*NX_AZURE_IOT_HUB_TRANSPORT_PASSWORD_GET_FN)(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                                ULONG expiry_time_secs, az_span hash_buffer, az_span key_name,
                                                                UCHAR *out_buffer, UINT out_buffer_len, UINT *bytes_copied);

typedef VOID (*NX_AZURE_IOT_HUB_TRANSPORT_MESSAGE_CB_FN)(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                         NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg1,
                                                         VOID *arg2);
typedef UINT (*NX_AZURE_IOT_HUB_TRANSPORT_MESSAGE_PROCESS_FN)(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                              NX_PACKET *packet_ptr, ULONG topic_offset, USHORT topic_length);
typedef UINT (*NX_AZURE_IOT_HUB_TRANSPORT_MESSAGE_ENABLE_FN)(struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr);

typedef struct NX_AZURE_IOT_HUB_TRANSPORT_RECEIVE_MESSAGE_STRUCT
{
    NX_PACKET                                           *message_head;
    NX_PACKET                                           *message_tail;
    NX_AZURE_IOT_HUB_TRANSPORT_MESSAGE_CB_FN             message_callback;
    NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN                message_callback_arg1;
    VOID                                                *message_callback_arg2;
    const UCHAR                                         *message_topic_ptr;
    UINT                                                 message_topic_length;
    NX_AZURE_IOT_HUB_TRANSPORT_MESSAGE_PROCESS_FN        message_process;
    USHORT                                               message_sub_packet_id;
    USHORT                                               message_control_flag;
} NX_AZURE_IOT_HUB_TRANSPORT_RECEIVE_MESSAGE;

/**
 * @brief Azure IoT Hub transport struct
 *
 */
typedef struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT
{
    NX_AZURE_IOT                                        *nx_azure_iot_ptr;

    UINT                                                 nx_azure_iot_hub_transport_state;

    UINT                                                 nx_azure_iot_hub_transport_request_id;
    const UCHAR                                         *nx_azure_iot_hub_transport_symmetric_key;
    UINT                                                 nx_azure_iot_hub_transport_symmetric_key_length;
    NX_AZURE_IOT_RESOURCE                                nx_azure_iot_hub_transport_resource;

    VOID                                                *nx_azure_iot_hub_transport_client_context;

    NX_AZURE_IOT_HUB_TRANSPORT_CONNECTION_STATUS_CB      nx_azure_iot_hub_transport_connection_status_callback;
    NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN                nx_azure_iot_hub_transport_connection_status_callback_arg;
    UINT                                                (*nx_azure_iot_hub_transport_token_refresh)(
                                                         struct NX_AZURE_IOT_HUB_TRANSPORT_STRUCT *hub_trans_ptr,
                                                         ULONG expiry_time_secs, const UCHAR *key, UINT key_len,
                                                         UCHAR *sas_buffer, UINT sas_buffer_len, UINT *sas_length);

    NX_AZURE_IOT_HUB_TRANSPORT_CLIENT_ID_GET_FN          nx_azure_iot_hub_transport_client_id_get;
    NX_AZURE_IOT_HUB_TRANSPORT_USERNAME_GET_FN           nx_azure_iot_hub_transport_username_get;
    NX_AZURE_IOT_HUB_TRANSPORT_SIGNATURE_GET_FN          nx_azure_iot_hub_transport_sas_signature;
    NX_AZURE_IOT_HUB_TRANSPORT_PASSWORD_GET_FN           nx_azure_iot_hub_transport_sas_password;


    NX_AZURE_IOT_THREAD                                 *nx_azure_iot_hub_transport_thread_suspended;
    NX_AZURE_IOT_HUB_TRANSPORT_RECEIVE_MESSAGE           nx_azure_iot_hub_transport_message[NX_AZURE_IOT_HUB_TRANSPORT_MAX_NUM_RECEIVE_QUEUE];
    volatile UINT                                        nx_azure_iot_hub_transport_message_pending_subscribe_ack;
} NX_AZURE_IOT_HUB_TRANSPORT;


UINT nx_azure_iot_hub_transport_initialize(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                           NX_AZURE_IOT *nx_azure_iot_ptr,
                                           const UCHAR *host_name, UINT host_name_length,
                                           const NX_AZURE_IOT_HUB_TRANSPORT_CLIENT_ID_GET_FN client_id_get,
                                           const NX_AZURE_IOT_HUB_TRANSPORT_USERNAME_GET_FN username_get,
                                           const NX_CRYPTO_METHOD **crypto_array, UINT crypto_array_size,
                                           const NX_CRYPTO_CIPHERSUITE **cipher_map, UINT cipher_map_size,
                                           UCHAR *metadata_memory, UINT memory_size,
                                           NX_SECURE_X509_CERT *trusted_certificate,
                                           VOID *client_context);

UINT nx_azure_iot_hub_transport_deinitialize(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr);

UINT nx_azure_iot_hub_transport_device_cert_set(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                NX_SECURE_X509_CERT *device_certificate);

UINT nx_azure_iot_hub_transport_symmetric_key_auth_set(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                       const NX_AZURE_IOT_HUB_TRANSPORT_SIGNATURE_GET_FN sas_signature_get,
                                                       const NX_AZURE_IOT_HUB_TRANSPORT_PASSWORD_GET_FN sas_password_get,
                                                       const UCHAR *symmetric_key, UINT symmetric_key_length);

UINT nx_azure_iot_hub_transport_connection_callback_set(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                        NX_AZURE_IOT_HUB_TRANSPORT_CONNECTION_STATUS_CB connection_cb,
                                                        NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg);

UINT nx_azure_iot_hub_transport_connect(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                        UINT clean_session, UINT wait_option);

UINT nx_azure_iot_hub_transport_disconnect(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr);

UINT nx_azure_iot_hub_transport_receive_message_enable(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr, UINT message_queue_index,
                                                       const UCHAR *message_topic_ptr, UINT message_topic_length,
                                                       NX_AZURE_IOT_HUB_TRANSPORT_MESSAGE_PROCESS_FN message_process);

UINT nx_azure_iot_hub_transport_receive_message_disable(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                        UINT message_queue_index);

UINT nx_azure_iot_hub_transport_receive_message_callback_set(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr, UINT message_queue_index,
                                                             NX_AZURE_IOT_HUB_TRANSPORT_MESSAGE_CB_FN message_callback,
                                                             NX_AZURE_IOT_HUB_TRANSPORT_GENERIC_FN arg1, VOID *arg2);

UINT nx_azure_iot_hub_transport_receive_message_is_subscribed(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                              UINT message_queue_index, UINT wait_option);

UINT nx_azure_iot_hub_transport_message_receive(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                UINT message_queue_index, UINT expected_id,
                                                NX_PACKET **packet_pptr, UINT wait_option);

UINT nx_azure_iot_hub_transport_receive_notify(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                               NX_PACKET *packet_ptr, UINT message_queue_index,
                                               UINT correlation_id);

UINT nx_azure_iot_hub_transport_request_response(NX_AZURE_IOT_HUB_TRANSPORT *hub_transport_ptr,
                                                 UINT request_id, NX_PACKET *packet_ptr, ULONG topic_length,
                                                 const UCHAR *message_buffer, UINT message_length, UINT response_queue_index,
                                                 NX_PACKET **response_packet_pptr, UINT wait_option);

UINT nx_azure_iot_hub_transport_publish(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr, NX_PACKET *packet_ptr,
                                        const UCHAR *data, UINT data_size, UINT qos, UINT wait_option);

UINT nx_azure_iot_hub_transport_process_publish_packet(UCHAR *start_ptr, ULONG *topic_offset_ptr,
                                                       USHORT *topic_length_ptr);

UINT nx_azure_iot_hub_transport_adjust_payload(NX_PACKET *packet_ptr);

UINT nx_azure_iot_hub_transport_publish_packet_get(NX_AZURE_IOT_HUB_TRANSPORT *hub_trans_ptr,
                                                   NX_PACKET **packet_pptr, UINT wait_option);
#ifdef __cplusplus
}
#endif
#endif /* NX_AZURE_IOT_HUB_TRANSPORT_H */
