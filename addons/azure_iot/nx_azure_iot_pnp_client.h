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
 * @file nx_azure_iot_pnp_client.h
 *
 * @brief Definition for the Azure IoT PnP client.
 *
 */

#ifndef NX_AZURE_IOT_PNP_CLIENT_H
#define NX_AZURE_IOT_PNP_CLIENT_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "azure/iot/az_iot_pnp_client.h"
#include "nx_azure_iot_hub_transport.h"
#include "nx_azure_iot.h"
#include "nx_azure_iot_json_reader.h"
#include "nx_azure_iot_json_writer.h"
#include "nx_api.h"
#include "nx_cloud.h"

/**< Value denoting a message is of "None" type */
#define NX_AZURE_IOT_PNP_NONE                                       0x00000000

/**< Value denoting a message is of "all" type */
#define NX_AZURE_IOT_PNP_ALL_MESSAGE                                0xFFFFFFFF

/**< Value denoting a message is a command */
#define NX_AZURE_IOT_PNP_COMMAND                                    0x00000002

/**< Value denoting a message is a all properties message */
#define NX_AZURE_IOT_PNP_PROPERTIES                                 0x00000004

/**< Value denoting a message is a desired properties message */
#define NX_AZURE_IOT_PNP_DESIRED_PROPERTIES                         0x00000008

/**< Value denoting a message is a reported properties response */
#define NX_AZURE_IOT_PNP_REPORTED_PROPERTIES_RESPONSE               0x00000010

#ifndef NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_IN_SEC
#define NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_IN_SEC                  (10 * 60)
#endif /* NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_IN_SEC */

#ifndef NX_AZURE_IOT_PNP_CLIENT_INITIAL_BACKOFF_IN_SEC
#define NX_AZURE_IOT_PNP_CLIENT_INITIAL_BACKOFF_IN_SEC              (3)
#endif /* NX_AZURE_IOT_PNP_CLIENT_INITIAL_BACKOFF_IN_SEC */

#ifndef NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_JITTER_PERCENT
#define NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_JITTER_PERCENT          (60)
#endif /* NX_AZURE_IOT_PNP_CLIENT_MAX_BACKOFF_JITTER_PERCENT */

#ifndef NX_AZURE_IOT_PNP_CLIENT_MAX_PNP_COMPONENT_LIST
#define NX_AZURE_IOT_PNP_CLIENT_MAX_PNP_COMPONENT_LIST              (4)
#endif /* NX_AZURE_IOT_PNP_CLIENT_MAX_PNP_COMPONENT_LIST */

/* Default TELEMETRY QoS is QoS1 */
#ifndef NX_AZURE_IOT_PNP_CLIENT_TELEMETRY_QOS
#define NX_AZURE_IOT_PNP_CLIENT_TELEMETRY_QOS                       NX_AZURE_IOT_MQTT_QOS_1
#endif /* NX_AZURE_IOT_PNP_CLIENT_TELEMETRY_QOS */

/**
 * @brief Azure IoT PnP Client struct
 *
 */
typedef struct NX_AZURE_IOT_PNP_CLIENT_STRUCT
{
    NX_AZURE_IOT_HUB_TRANSPORT              nx_azure_iot_pnp_client_transport;

    UINT                                    nx_azure_iot_pnp_client_request_id;

    az_iot_pnp_client                       iot_pnp_client_core;
    az_span                                 nx_azure_iot_pnp_client_component_list[NX_AZURE_IOT_PNP_CLIENT_MAX_PNP_COMPONENT_LIST];
    UINT                                    nx_azure_iot_pnp_client_throttle_count;
    ULONG                                   nx_azure_iot_pnp_client_throttle_end_time;
} NX_AZURE_IOT_PNP_CLIENT;

/**
 * @brief Initialize Azure IoT PnP instance
 *
 * @param pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param nx_azure_iot_ptr A pointer to a #NX_AZURE_IOT.
 * @param host_name A `UCHAR` pointer to IoTHub hostname. Must be `NULL` terminated.
 * @param[in] host_name_length Length of `host_name`. Does not include the `NULL` terminator.
 * @param[in] device_id A `UCHAR` pointer to the device ID.
 * @param[in] device_id_length Length of the `device_id`. Does not include the `NULL` terminator.
 * @param[in] module_id A `UCHAR` pointer to the module ID.
 * @param[in] module_id_length Length of the `module_id`. Does not include the `NULL` terminator.
 * @param[in] model_id A `UCHAR` pointer to the model ID.
 * @param[in] model_id_length Length of the `model_id`. Does not include the `NULL` terminator.
 * @param[in] crypto_array A pointer to an array of `NX_CRYPTO_METHOD`.
 * @param[in] crypto_array_size Size of `crypto_array`.
 * @param[in] cipher_map A pointer to an array of `NX_CRYPTO_CIPHERSUITE`.
 * @param[in] cipher_map_size Size of `cipher_map`.
 * @param[in] metadata_memory A `UCHAR` pointer to metadata memory buffer.
 * @param[in] memory_size Size of `metadata_memory`.
 * @param[in] trusted_certificate A pointer to `NX_SECURE_X509_CERT`, which are the server side certs.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successfully initialized the Azure IoT PnP client.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to initialize the Azure IoT PnP client due to invalid parameter.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail to initialize the Azure IoT PnP client due to SDK core error.
 */
UINT nx_azure_iot_pnp_client_initialize(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                        NX_AZURE_IOT *nx_azure_iot_ptr,
                                        const UCHAR *host_name, UINT host_name_length,
                                        const UCHAR *device_id, UINT device_id_length,
                                        const UCHAR *module_id, UINT module_id_length,
                                        const UCHAR *model_id, UINT model_id_length,
                                        const NX_CRYPTO_METHOD **crypto_array, UINT crypto_array_size,
                                        const NX_CRYPTO_CIPHERSUITE **cipher_map, UINT cipher_map_size,
                                        UCHAR *metadata_memory, UINT memory_size,
                                        NX_SECURE_X509_CERT *trusted_certificate);

/**
 * @brief Deinitialize the Azure IoT PnP instance.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successfully de-initialized the Azure IoT PnP client.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to deinitialize the Azure IoT PnP client due to invalid parameter.
 */
UINT nx_azure_iot_pnp_client_deinitialize(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr);


/**
 * @brief Add component name to IoT PnP client.
 * @note This routine should be called for all the component in the PnP model.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] component_name_ptr A pointer to component, that is part of PnP model.
 * @param[in] component_name_length Length of the `component_name_ptr`.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successfully add the component name to the PnP client.
 *   @retval #NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail to add the component name due to out of memory.
 */
UINT nx_azure_iot_pnp_client_component_add(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                           const UCHAR *component_name_ptr,
                                           UINT component_name_length);

/**
 * @brief Set the client certificate in the IoT PnP client.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] device_certificate A pointer to a `NX_SECURE_X509_CERT`, which is the device certificate.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successfully set device certificate to AZ IoT PnP Instance.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to set device certificate to AZ IoT PnP Instance due to invalid parameter.
 */
UINT nx_azure_iot_pnp_client_device_cert_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                             NX_SECURE_X509_CERT *device_certificate);

/**
 * @brief Set symmetric key in the IoT PnP client.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] symmetric_key A pointer to a symmetric key.
 * @param[in] symmetric_key_length Length of `symmetric_key`.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successfully set symmetric key to IoT PnP client.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to set symmetric key to IoT PnP client due to invalid parameter.
 */
UINT nx_azure_iot_pnp_client_symmetric_key_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                               const UCHAR *symmetric_key, UINT symmetric_key_length);

/**
 * @brief Connect to IoT Hub.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] clean_session Can be set to `0` to re-use current session, or `1` to start new session
 * @param[in] wait_option Number of ticks to wait for internal resources to be available.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if connected to Azure IoT Hub.
 *   @retval #NX_AZURE_IOT_CONNECTING Successfully started connection but not yet completed.
 *   @retval #NX_AZURE_IOT_ALREADY_CONNECTED Already connected to Azure IoT Hub.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to connect to Azure IoT Hub due to invalid parameter.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail to connect to Azure IoT Hub due to SDK core error.
 *   @retval #NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail to connect to Azure IoT Hub due to buffer size is too small.
 *   @retval NX_DNS_QUERY_FAILED Fail to connect to Azure IoT Hub due to hostname can not be resolved.
 *   @retval NX_NO_PACKET Fail to connect to Azure IoT Hub due to no available packet in pool.
 *   @retval NX_INVALID_PARAMETERS Fail to connect to Azure IoT Hub due to invalid parameters.
 *   @retval NX_SECURE_TLS_INSUFFICIENT_METADATA_SPACE Fail to connect to Azure IoT Hub due to insufficient metadata space.
 *   @retval NX_SECURE_TLS_UNSUPPORTED_CIPHER Fail to connect to Azure IoT Hub due to unsupported cipher.
 *   @retval NXD_MQTT_ALREADY_CONNECTED Fail to connect to Azure IoT Hub due to MQTT session is not disconnected.
 *   @retval NXD_MQTT_CONNECT_FAILURE Fail to connect to Azure IoT Hub due to TCP/TLS connect error.
 *   @retval NXD_MQTT_COMMUNICATION_FAILURE Fail to connect to Azure IoT Hub due to MQTT connect error.
 *   @retval NXD_MQTT_ERROR_SERVER_UNAVAILABLE Fail to connect to Azure IoT Hub due to server unavailable.
 *   @retval NXD_MQTT_ERROR_NOT_AUTHORIZED Fail to connect to Azure IoT Hub due to authentication error.
 */
UINT nx_azure_iot_pnp_client_connect(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                     UINT clean_session, UINT wait_option);

/**
 * @brief Disconnect from IoT Hub.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if client disconnects.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to disconnect due to invalid parameter.
 */
UINT nx_azure_iot_pnp_client_disconnect(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr);

/**
 * @brief Sets connection status callback function
 * @details This routine sets the connection status callback. This callback function is
 *          invoked when PnP client status is changed, such as when the client is connected to IoT Hub.
 *          The different statuses include:
 *
 *          - #NX_AZURE_IOT_SUCCESS
 *          - NX_SECURE_TLS_ALERT_RECEIVED
 *          - NX_SECURE_TLS_NO_SUPPORTED_CIPHERS
 *          - NX_SECURE_X509_CHAIN_VERIFY_FAILURE
 *          - NXD_MQTT_CONNECT_FAILURE
 *          - NXD_MQTT_ERROR_SERVER_UNAVAILABLE
 *          - NXD_MQTT_ERROR_NOT_AUTHORIZED
 *          - NX_AZURE_IOT_DISCONNECTED
 *
 *          Setting the callback function to `NULL` disables the callback function.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] connection_status_cb Pointer to a callback function invoked on connection status is changed.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if connection status callback is set.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to set connection status callback due to invalid parameter.
 */
UINT nx_azure_iot_pnp_client_connection_status_callback_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                            VOID (*connection_status_cb)(
                                                                  struct NX_AZURE_IOT_PNP_CLIENT_STRUCT *pnp_client_ptr,
                                                                  UINT status));

/**
 * @brief Sets receive callback function
 * @details This routine sets the IoT PnP receive callback function. This callback
 *          function is invoked when a message is received from Azure IoT hub. Setting the
 *          callback function to `NULL` disables the callback function. Message types can be:
 *
 *          - #NX_AZURE_IOT_PNP_COMMAND
 *          - #NX_AZURE_IOT_PNP_PROPERTIES
 *          - #NX_AZURE_IOT_PNP_DESIRED_PROPERTIES
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] message_type Message type of callback function.
 * @param[in] callback_ptr Pointer to a callback function invoked if the specified message type is received.
 * @param[in] callback_args Pointer to an argument passed to callback function.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if callback function is set.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to set receive callback due to invalid parameter.
 *   @retval #NX_AZURE_IOT_NOT_SUPPORTED Fail to set receive callback due to message_type not supported.
 */
UINT nx_azure_iot_pnp_client_receive_callback_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                  UINT message_type,
                                                  VOID (*callback_ptr)(
                                                        NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        VOID *args),
                                                  VOID *callback_args);

/**
 * @brief Creates PnP telemetry message.
 * @details This routine prepares a packet for sending telemetry data. After the packet is properly created,
 *          application owns the `NX_PACKET` and can add additional user-defined properties before sending out.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] component_name_ptr A pointer to a component name.
 * @param[in] component_name_length Length of `component_name_ptr`. Does not include the `NULL` terminator.
 * @param[out] packet_pptr Returned allocated `NX_PACKET` on success. Caller owns the `NX_PACKET` memory.
 * @param[in] wait_option Ticks to wait if no packet is available.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if a packet is allocated.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to allocate telemetry message due to invalid parameter.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail to allocate telemetry message due to SDK core error.
 *   @retval NX_NO_PACKET Fail to allocate telemetry message due to no available packet in pool.
 */
UINT nx_azure_iot_pnp_client_telemetry_message_create(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      const UCHAR *component_name_ptr,
                                                      UINT component_name_length,
                                                      NX_PACKET **packet_pptr,
                                                      UINT wait_option);

/**
 * @brief Deletes PnP telemetry message
 *
 * @param[in] packet_ptr The `NX_PACKET` to release.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if a packet is deallocated.
 */
UINT nx_azure_iot_pnp_client_telemetry_message_delete(NX_PACKET *packet_ptr);

/**
 * @brief Add property to telemetry message
 * @details This routine allows an application to add user-defined properties to a telemetry message
 *          before it is being sent. This routine can be called multiple times to add all the properties to
 *          the message. The properties are stored in the sequence which the routine is being called.
 *          The property must be added after a telemetry packet is created, and before the telemetry
 *          message is being sent.
 *
 * @param[in] packet_ptr A pointer to telemetry property packet.
 * @param[in] property_name Pointer to property name.
 * @param[in] property_name_length Length of property name.
 * @param[in] property_value Pointer to property value.
 * @param[in] property_value_length Length of property value.
 * @param[in] wait_option Ticks to wait if packet needs to be expanded.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if property is added.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to add property due to invalid parameter.
 *   @retval NX_NO_PACKET Fail to add property due to no available packet in pool.
 */
UINT nx_azure_iot_pnp_client_telemetry_property_add(NX_PACKET *packet_ptr,
                                                    const UCHAR *property_name,
                                                    USHORT property_name_length,
                                                    const UCHAR *property_value,
                                                    USHORT property_value_length,
                                                    UINT wait_option);

/**
 * @brief Sends PnP telemetry message to IoTHub.
 * @details This routine sends PnP telemetry to IoTHub, with `packet_ptr` containing all the properties.
 *          On successful return of this function, ownership of `NX_PACKET` is released.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] packet_ptr A pointer to telemetry property packet.
 * @param[in] telemetry_data Pointer to telemetry data.
 * @param[in] data_size Size of telemetry data.
 * @param[in] wait_option Ticks to wait for message to be sent.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if telemetry message is sent out.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to send telemetry message due to invalid parameter.
 *   @retval #NX_AZURE_IOT_INVALID_PACKET Fail to send telemetry message due to packet is invalid.
 *   @retval NXD_MQTT_PACKET_POOL_FAILURE Fail to send telemetry message due to no available packet in pool.
 *   @retval NXD_MQTT_COMMUNICATION_FAILURE Fail to send telemetry message due to TCP/TLS error.
 *   @retval NX_NO_PACKET Fail to send telemetry message due to no available packet in pool.
 */
UINT nx_azure_iot_pnp_client_telemetry_send(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                            NX_PACKET *packet_ptr,
                                            const UCHAR *telemetry_data,
                                            UINT data_size, UINT wait_option);

/**
 * @brief Receives receiving PnP command message from IoTHub
 * @details This routine receives PnP command message from IoT Hub. If there are no
 *          messages in the receive queue, this routine can block. The amount of time it waits for a
 *          message is determined by the `wait_option` parameter.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[out] component_name_pptr Return a pointer to PnP component name on success.
 * @param[out] component_name_length_ptr Return length of `*component_name_pptr` on success.
 * @param[out] pnp_command_name_pptr Return a pointer to PnP command name on success.
 * @param[out] pnp_command_name_length_ptr Return length of `*pnp_command_name_pptr` on success.
 * @param[out] context_pptr Return a pointer to the context pointer on success.
 * @param[out] context_length_ptr Return length of `context` on success.
 * @param[out] reader_ptr Return `NX_AZURE_IOT_JSON_READER` containing the method payload on success.
 * @param[in] wait_option Ticks to wait for message to arrive.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if PnP command message is received.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to receive PnP command message due to invalid parameter.
 *   @retval #NX_AZURE_IOT_NOT_ENABLED Fail to receive PnP command message due to it is not enabled.
 *   @retval #NX_AZURE_IOT_NO_PACKET Fail to receive PnP command message due to timeout.
 *   @retval #NX_AZURE_IOT_INVALID_PACKET Fail to receive PnP command message due to invalid packet.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail to receive PnP command message due to SDK core error.
 *   @retval #NX_AZURE_IOT_DISCONNECTED Fail to receive PnP command message due to disconnect.
 */
UINT nx_azure_iot_pnp_client_command_receive(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                             const UCHAR **component_name_pptr, UINT *component_name_length_ptr,
                                             const UCHAR **pnp_command_name_pptr, UINT *pnp_command_name_length_ptr,
                                             VOID **context_pptr, USHORT *context_length_ptr,
                                             NX_AZURE_IOT_JSON_READER *reader_ptr, UINT wait_option);

/**
 * @brief Return response to PnP command message from IoTHub
 * @details This routine returns response to the PnP command message from IoT Hub.
 * @note request_id ties the correlation between PnP command message receive and response.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] status_code Status code for PnP command.
 * @param[in] context_ptr Pointer to context return from nx_azure_iot_pnp_client_command_receive().
 * @param[in] context_length Length of context.
 * @param[in] payload  Pointer to `UCHAR` containing the payload for the PnP command response. Payload is in JSON format.
 * @param[in] payload_length Length of `payload`
 * @param[in] wait_option Ticks to wait for message to send.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if PnP command response is send.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to send PnP command response due to invalid parameter.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail to send PnP command response due to SDK core error.
 *   @retval NX_NO_PACKET Fail send PnP command response due to no available packet in pool.
 */
UINT nx_azure_iot_pnp_client_command_message_response(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      UINT status_code, VOID *context_ptr,
                                                      USHORT context_length, const UCHAR *payload_ptr,
                                                      UINT payload_length, UINT wait_option);

/**
 * @brief Creates PnP reported property message writer.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT
 * @param[out] writer_ptr A pointer to a #NX_AZURE_IOT_JSON_WRITER
 * @param[in] wait_option Ticks to wait for writer creation
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if a message writer is created.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to create message writer due to invalid parameter.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail to create message writer due to SDK core error.
 *   @retval NX_NO_PACKET Fail to create message writer due to no available packet in pool.
 */
UINT nx_azure_iot_pnp_client_reported_properties_create(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                        UINT wait_option);

/**
 * @brief Append the necessary characters to a reported property JSON payload belonging to a
 * subcomponent.
 *
 * The payload will be of the form:
 *
 * @code
 * "reported": {
 *     "<component_name>": {
 *         "__t": "c",
 *         "temperature": 23
 *     }
 * }
 * @endcode
 *
 * @note This API should be used in conjunction with
 * nx_azure_iot_pnp_client_reported_property_component_end().
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT
 * @param[in] writer_ptr A pointer to a #NX_AZURE_IOT_JSON_WRITER
 * @param[in] component_name_ptr A pointer to a component name
 * @param[in] component_name_length Length of `component_name_ptr`
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if JSON payload was prefixed successfully.
 */
UINT nx_azure_iot_pnp_client_reported_property_component_begin(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                               NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                               const UCHAR *component_name_ptr,
                                                               UINT component_name_length);

/**
 * @brief Append the necessary characters to end a reported property JSON payload belonging to a
 * subcomponent.
 *
 * @note This API should be used in conjunction with
 * nx_azure_iot_pnp_client_reported_property_component_begin().
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT
 * @param[in] writer_ptr A pointer to a #NX_AZURE_IOT_JSON_WRITER
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS The JSON payload was suffixed successfully.
 */
UINT nx_azure_iot_pnp_client_reported_property_component_end(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                             NX_AZURE_IOT_JSON_WRITER *writer_ptr);

/**
 * @brief Begin a property response payload with confirmation status.
 *
 * This API should be used in response to an incoming desired property. More details can be found
 * here:
 *
 * https://docs.microsoft.com/en-us/azure/iot-pnp/concepts-convention#writable-properties
 *
 * The payload will be of the form:
 *
 * **Without component**
 * @code
 * //{
 * //  "<property_name>":{
 * //    "ac": <ack_code>,
 * //    "av": <ack_version>,
 * //    "ad": "<ack_description>",
 * //    "value": <user_value>
 * //  }
 * //}
 * @endcode
 *
 * To send a status for a property belonging to a component, first call the
 * nx_azure_iot_pnp_client_reported_property_status_begin() API to prefix the payload with the
 * necessary identification. The API call flow would look like the following with the listed JSON
 * payload being generated.
 *
 * **With component**
 * @code
 *
 * nx_azure_iot_pnp_client_reported_property_component_begin()
 * nx_azure_iot_pnp_client_reported_property_status_begin()
 * // Append user value here (<user_value>)
 * nx_azure_iot_pnp_client_reported_property_status_end()
 * nx_azure_iot_pnp_client_reported_property_component_end()
 *
 * //{
 * //  "<component_name>": {
 * //    "__t": "c",
 * //    "<property_name>": {
 * //      "ac": <ack_code>,
 * //      "av": <ack_version>,
 * //      "ad": "<ack_description>",
 * //      "value": <user_value>
 * //    }
 * //  }
 * //}
 * @endcode
 *
 * @note This API should be used in conjunction with
 * nx_azure_iot_pnp_client_reported_property_status_end().
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] writer_ptr A pointer to a #NX_AZURE_IOT_JSON_WRITER
 * @param[in] property_name_ptr A pointer to property name.
 * @param[in] property_name_length Length of `property_name_ptr`.
 * @param[in] ack_code The HTTP-like status code to respond with.
 * @param[in] ack_version The version of the property the application is acknowledging.
 * @param[in] ack_description_ptr An optional pointer to description detailing the context or any details about
 *            the acknowledgement. This can be empty string.
 * @param[in] ack_description_length Length of ack_description_ptr
 *
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful appended JSON prefix.
 */
UINT nx_azure_iot_pnp_client_reported_property_status_begin(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                            NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                            const UCHAR *property_name_ptr, UINT property_name_length,
                                                            UINT ack_code, ULONG ack_version,
                                                            const UCHAR *ack_description_ptr, UINT ack_description_length);

/**
 * @brief End a property response payload with confirmation status.
 *
 * @note This API should be used in conjunction with
 * nx_azure_iot_pnp_client_reported_property_status_begin().
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] writer_ptr A pointer to a #NX_AZURE_IOT_JSON_WRITER
 *
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful appended JSON suffix.
 */
UINT nx_azure_iot_pnp_client_reported_property_status_end(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                          NX_AZURE_IOT_JSON_WRITER *writer_ptr);

/**
 * @brief Sets reported properties response callback function
 * @details This routine sets the reponse receive callback function for reported properties. This callback
 *          function is invoked when a response is received from Azure IoT hub for reported properties and no
 *          thread is waiting for response. Setting the callback function to `NULL` disables the callback
 *          function.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] callback_ptr Pointer to a callback function invoked.
 * @param[in] callback_args Pointer to an argument passed to callback function.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if callback function is set.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to set callback due to invalid parameter.
 */
UINT nx_azure_iot_pnp_client_report_properties_response_callback_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                                     VOID (*callback_ptr)(
                                                                           NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                                           UINT request_id,
                                                                           UINT response_status,
                                                                           ULONG version,
                                                                           VOID *args),
                                                                     VOID *callback_args);

/**
 * @brief Sends PnP reported properties message to IoTHub.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] writer_ptr A pointer to a #NX_AZURE_IOT_JSON_WRITER
 * @param[out] request_id_ptr Request Id assigned to the request.
 * @param[out] response_status_ptr Status return for successful send of reported properties.
 * @param[out] version_ptr Version return for successful send of reported properties.
 * @param[in] wait_option Ticks to wait for message to send.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if reported properties is sent.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to send reported properties due to invalid parameter.
 *   @retval #NX_AZURE_IOT_NOT_ENABLED Fail to send reported properties due to device twin is not enabled.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail to send reported properties due to SDK core error.
 *   @retval #NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail to send reported properties due to buffer size is too small.
 *   @retval #NX_AZURE_IOT_NO_PACKET Fail to send reported properties due to no packet available.
 *   @retval NX_NO_PACKET Fail to send reported properties due to no packet available.
 *   @retval #NX_AZURE_IOT_DISCONNECTED Fail to send reported properties due to disconnect.
 */
UINT nx_azure_iot_pnp_client_reported_properties_send(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      NX_AZURE_IOT_JSON_WRITER *reported_property_message,
                                                      UINT *request_id_ptr, UINT *response_status_ptr,
                                                      ULONG *version_ptr, UINT wait_option);

/**
 * @brief Request complete to get all properties
 * @details This routine requests all properties.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] wait_option Ticks to wait for request to send.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if request get all properties is sent.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to request get all properties due to invalid parameter.
 *   @retval #NX_AZURE_IOT_NO_SUBSCRIBE_ACK Fail to request get all properties due to no subscribe ack.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail to request get all properties due to SDK core error.
 *   @retval #NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail to request get all properties due to buffer size is too small.
 *   @retval #NX_AZURE_IOT_NO_PACKET Fail to request get all properties due to no packet available.
 *   @retval NX_NO_PACKET Fail to request get all properties due to no packet available.
 */
UINT nx_azure_iot_pnp_client_properties_request(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                UINT wait_option);

/**
 * @brief Receive all the properties
 * @details This routine receives all the properties.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[out] reader_ptr A pointer to a #NX_AZURE_IOT_JSON_READER containing all the properties
 * @param[out] desired_properties_version_ptr A pointer to `ULONG`, containing version of desired properties
 * @param[in] wait_option Ticks to wait for message to receive.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if all properties is received.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to receive all properties due to invalid parameter.
 *   @retval #NX_AZURE_IOT_NOT_ENABLED Fail to receive all properties due to it is not enabled.
 *   @retval #NX_AZURE_IOT_NO_PACKET Fail to receive all properties due to timeout.
 *   @retval #NX_AZURE_IOT_INVALID_PACKET Fail to receive all properties due to invalid packet.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail to receive all properties due to SDK core error.
 *   @retval #NX_AZURE_IOT_SERVER_RESPONSE_ERROR Response code from server is not 2xx.
 *   @retval #NX_AZURE_IOT_DISCONNECTED Fail to receive all properties due to disconnect.
 */
UINT nx_azure_iot_pnp_client_properties_receive(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                NX_AZURE_IOT_JSON_READER *reader_ptr,
                                                ULONG *desired_properties_version_ptr,
                                                UINT wait_option);

/**
 * @brief Receive desired properties form IoTHub
 * @details This routine receives desired properties from IoTHub.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[out] reader_ptr A pointer to a #NX_AZURE_IOT_JSON_READER containing desired properties
 * @param[out] desired_properties_version_ptr A pointer to `ULONG`, containing version of properties
 * @param[in] wait_option Ticks to wait for message to receive.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if desired properties is received.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail to receive desired properties due to invalid parameter.
 *   @retval #NX_AZURE_IOT_NOT_ENABLED Fail to receive desired properties due to it is not enabled.
 *   @retval #NX_AZURE_IOT_NO_PACKET Fail to receive desired properties due to timeout.
 *   @retval #NX_AZURE_IOT_INVALID_PACKET Fail to receive desired properties due to invalid packet.
 *   @retval #NX_AZURE_IOT_DISCONNECTED Fail to receive desired properties due to disconnect.
 */
UINT nx_azure_iot_pnp_client_desired_properties_receive(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        NX_AZURE_IOT_JSON_READER *reader_ptr,
                                                        ULONG *properties_version_ptr,
                                                        UINT wait_option);

/**
 * @brief Return the next desired property in the property document passed.
 *
 * @param[in] pnp_client_ptr A pointer to a #NX_AZURE_IOT_PNP_CLIENT.
 * @param[in] reader_ptr A pointer to a #NX_AZURE_IOT_JSON_READER containing properties document
 * @param[in] message_type Type of document, only valid value are NX_AZURE_IOT_PNP_DESIRED_PROPERTIES or NX_AZURE_IOT_PNP_PROPERTIES
 * @param[out] component_pptr A pointer to component name for the property returned using name_value_reader_ptr
 * @param[out] component_len_ptr Length of the component name
 * @param[out] name_value_reader_ptr A pointer to a #NX_AZURE_IOT_JSON_READER containing property name and value
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if next desired property is found.
 */
UINT nx_azure_iot_pnp_client_desired_component_property_value_next(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                                   NX_AZURE_IOT_JSON_READER *reader_ptr, UINT message_type,
                                                                   const UCHAR **component_pptr, UINT *component_len_ptr,
                                                                   NX_AZURE_IOT_JSON_READER *name_value_reader_ptr);
#ifdef __cplusplus
}
#endif
#endif /* NX_AZURE_IOT_PNP_CLIENT_H */
