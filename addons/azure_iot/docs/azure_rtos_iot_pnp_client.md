# Azure IoT PnP Client

**nx_azure_iot_pnp_client_initialize**
***
<div style="text-align: right"> Initialize Azure IoT PnP instance </div>

**Prototype**
```c
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
```
**Description**

<p>This routine initializes the IoT PnP client.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| nx_azure_iot_ptr [in]      | A pointer to a `NX_AZURE_IOT`.|
| host_name [in] | A pointer to IoTHub hostname. Must be NULL terminated string.   |
| host_name_length [in] | Length of the IoTHub hostname.  |
| device_id [in]  | A pointer to device ID.     |
| device_id_length [in] | Length of the device ID. |
| module_id [in]  | A pointer to module ID.     |
| module_id_length [in] | Length of the module ID. |
| model_id [in]  | A pointer to the model ID.     |
| model_id_length [in] | Length of the model ID. |
| crypto_array [in] | A pointer to `NX_CRYPTO_METHOD`    |
| crypto_array_size [in] | Size of crypto method array   |
| cipher_map [in] | A pointer to `NX_CRYPTO_CIPHERSUITE`    |
| cipher_map_size [in] | Size of cipher map    |
| metadata_memory [in] | A pointer to metadata memory buffer. |
| memory_size [in]  | Size of metadata buffer     |
| trusted_certificate [in] | A pointer to `NX_SECURE_X509_CERT`, which is server side certs |

**Return Values**
* NX_AZURE_IOT_SUCCESS Successfully initialized the Azure IoT PnP client.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to initialize the Azure IoT PnP client due to invalid parameter.
* NX_AZURE_IOT_SDK_CORE_ERROR Fail to initialize the Azure IoT PnP client due to SDK core error.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_deinitialize**
***
<div style="text-align: right"> Cleanup the Azure IoT PnP</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_deinitialize(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr);
```
**Description**

<p>The routine deinitializes the IoT PnP client</p>

**Parameters**
|               |               |
| ------------- |:-------------|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT` |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successfully de-initialized the Azure IoT PnP client.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to deinitialize the Azure IoT PnP client due to invalid parameter.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_component_add**
***
<div style="text-align: right"> Add component name to IoT PnP client </div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_component_add(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                           const UCHAR *component_name_ptr,
                                           UINT component_name_length);
```
**Description**

<p>This routine should be called for all the component in the PnP model.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT` |
| component_name_ptr [in]    | A pointer to component, that is part of PnP model. |
| component_name_length [in]    | Length of the `component_name_ptr`. |

**Return Values**
* NX_AZURE_IOT_SUCCESS Successfully set device certificate to AZ IoT PnP Instance.
* NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail to add the component name due to out of memory.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_device_cert_set**
***
<div style="text-align: right"> Set client certificate </div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_device_cert_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                             NX_SECURE_X509_CERT *device_certificate);
```
**Description**

<p>This routine sets the device certificate.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT` |
| device_certificate [in]    | A pointer to a `NX_SECURE_X509_CERT` |

**Return Values**
* NX_AZURE_IOT_SUCCESS Successfully set device certificate to AZ IoT PnP Instance.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to set device certificate to AZ IoT PnP Instance due to invalid parameter.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_symmetric_key_set**
***
<div style="text-align: right"> Set symmetric key </div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_symmetric_key_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                               const UCHAR *symmetric_key, UINT symmetric_key_length);
```
**Description**

<p>This routine sets the symmetric key.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT` |
| symmetric_key [in]    | A pointer to a symmetric key. |
| symmetric_key_length [in]    | Length of symmetric key |

**Return Values**
* NX_AZURE_IOT_SUCCESS Successfully set symmetric key to IoT PnP client.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to set symmetric key to IoT PnP client due to invalid parameter.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_connect**
***
<div style="text-align: right"> Connects to IoT Hub</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_connect(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                     UINT clean_session, UINT wait_option);
```
**Description**

<p>This routine connects to the Azure IoT Hub.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT` |
| clean_session [in]    | 0 re-use current session, or 1 to start new session |
| wait_option [in]    | Number of ticks to wait for internal resources to be available. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if connected to Azure IoT Hub.
* NX_AZURE_IOT_CONNECTING Successfully started connection but not yet completed.
* NX_AZURE_IOT_ALREADY_CONNECTED Already connected to Azure IoT Hub.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to connect to Azure IoT Hub due to invalid parameter.
* NX_AZURE_IOT_SDK_CORE_ERROR Fail to connect to Azure IoT Hub due to SDK core error.
* NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail to connect to Azure IoT Hub due to buffer size is too small.
* NX_DNS_QUERY_FAILED Fail to connect to Azure IoT Hub due to hostname can not be resolved.
* NX_NO_PACKET Fail to connect to Azure IoT Hub due to no available packet in pool.
* NX_INVALID_PARAMETERS Fail to connect to Azure IoT Hub due to invalid parameters.
* NX_SECURE_TLS_INSUFFICIENT_METADATA_SPACE Fail to connect to Azure IoT Hub due to insufficient metadata space.
* NX_SECURE_TLS_UNSUPPORTED_CIPHER Fail to connect to Azure IoT Hub due to unsupported cipher.
* NXD_MQTT_ALREADY_CONNECTED Fail to connect to Azure IoT Hub due to MQTT session is not disconnected.
* NXD_MQTT_CONNECT_FAILURE Fail to connect to Azure IoT Hub due to TCP/TLS connect error.
* NXD_MQTT_COMMUNICATION_FAILURE Fail to connect to Azure IoT Hub due to MQTT connect error.
* NXD_MQTT_ERROR_SERVER_UNAVAILABLE Fail to connect to Azure IoT Hub due to server unavailable.
* NXD_MQTT_ERROR_NOT_AUTHORIZED Fail to connect to Azure IoT Hub due to authentication error.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_disconnect**
***
<div style="text-align: right"> Disconnects the client</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_disconnect(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr);
```
**Description**

<p>This routine disconnects the client.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT` |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if client disconnects.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to disconnect due to invalid parameter.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_connection_status_callback_set**
***
<div style="text-align: right"> Sets connection status callback function</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_connection_status_callback_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                            VOID (*connection_status_cb)(
                                                                  struct NX_AZURE_IOT_PNP_CLIENT_STRUCT *pnp_client_ptr,
                                                                  UINT status));
```
**Description**

<p>This routine sets the connection status callback. This callback function is invoked when PnP client status is changed, such as when the client is connected to IoT Hub. Setting the callback function to NULL disables the callback function. The different statuses include:</p>

* NX_SECURE_TLS_ALERT_RECEIVED
* NX_SECURE_TLS_NO_SUPPORTED_CIPHERS
* NX_SECURE_X509_CHAIN_VERIFY_FAILURE
* NXD_MQTT_CONNECT_FAILURE
* NXD_MQTT_ERROR_SERVER_UNAVAILABLE
* NXD_MQTT_ERROR_NOT_AUTHORIZED
* NX_AZURE_IOT_DISCONNECTED

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT` |
| connection_status_cb [in]    | Pointer to a callback function invoked once connection status is changed. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if connection status callback is set.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to set connection status callback due to invalid parameter.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_receive_callback_set**
***
<div style="text-align: right"> Sets receive callback function</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_receive_callback_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                  UINT message_type,
                                                  VOID (*callback_ptr)(
                                                        NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        VOID *args),
                                                  VOID *callback_args);
```
**Description**

<p>This routine sets the IoT PnP receive callback function. This callback function is invoked when a message is received from Azure IoT hub. Setting the callback function to `NULL` disables the callback function. Message types can be: </p>

* NX_AZURE_IOT_PNP_COMMAND
* NX_AZURE_IOT_PNP_PROPERTIES
* NX_AZURE_IOT_PNP_DESIRED_PROPERTIES

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| message_type [in]    | Message type of callback function. |
| callback_ptr [in]    | Pointer to a callback function invoked on specified message type is received. |
| callback_args [in]    | Pointer to an argument passed to callback function. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if callback function is set.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to set receive callback due to invalid parameter.
* NX_AZURE_IOT_NOT_SUPPORTED Fail to set receive callback due to message_type not supported.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_telemetry_message_create**
***
<div style="text-align: right"> Creates telemetry message</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_telemetry_message_create(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      const UCHAR *component_name_ptr,
                                                      UINT component_name_length,
                                                      NX_PACKET **packet_pptr,
                                                      UINT wait_option);
```
**Description**

<p>This routine prepares a packet for sending telemetry data. After the packet is properly created, application owns the `NX_PACKET` and can add additional user-defined properties before sending out.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| component_name_ptr [in]    | A pointer to a component name. |
| component_name_length [in]    | Length of `component_name_ptr`. Does not include the `NULL` terminator. |
| packet_pptr [out]    | Return allocated packet on success. Caller owns the `NX_PACKET` memory. |
| wait_option [in]    | Ticks to wait if no packet is available. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if a packet is allocated.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to allocate telemetry message due to invalid parameter.
* NX_AZURE_IOT_SDK_CORE_ERROR Fail to allocate telemetry message due to SDK core error.
* NX_NO_PACKET Fail to allocate telemetry message due to no available packet in pool.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_telemetry_message_delete**
***
<div style="text-align: right"> Deletes telemetry message</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_telemetry_message_delete(NX_PACKET *packet_ptr)
```
**Description**

<p>This routine deletes the telemetry message.</p>

**Parameters**

| Name | Description |
| - |:-|
| packet_ptr [in]    | Release the `NX_PACKET` on success. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if a packet is deallocated.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_telemetry_property_add**
***
<div style="text-align: right"> Adds property to telemetry message</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_telemetry_property_add(NX_PACKET *packet_ptr,
                                                    const UCHAR *property_name,
                                                    USHORT property_name_length,
                                                    const UCHAR *property_value,
                                                    USHORT property_value_length,
                                                    UINT wait_option));
```
**Description**

<p>This routine allows an application to add user-defined properties to a telemetry message before it is being sent. This routine can be called multiple times to add all the properties to the message. The properties are stored in the sequence which the routine is called. The property must be added after a telemetry packet is created, and before the telemetry message is being sent.</p>

**Parameters**

| Name | Description |
| - |:-|
| packet_ptr [in]    | A pointer to telemetry property packet. |
| property_name [in]    | Pointer to property name. |
| property_name_length [in]    | Length of property name. |
| property_value [in]    | Pointer to property value. |
| property_value_length [in]    | Length of property value. |
| wait_option [in]    | Ticks to wait if packet needs to be expanded. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if property is added.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to add property due to invalid parameter.
* NX_NO_PACKET Fail to add property due to no available packet in pool.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_telemetry_send**
***
<div style="text-align: right"> Sends telemetry message to IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_telemetry_send(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                            NX_PACKET *packet_ptr,
                                            const UCHAR *telemetry_data,
                                            UINT data_size, UINT wait_option);
```
**Description**

<p>This routine sends telemetry to IoTHub, with packet_ptr containing all the properties. On successful return of this function, ownership of `NX_PACKET` is released.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| packet_ptr [in]    | A pointer to telemetry property packet. |
| telemetry_data [in]    | Pointer to telemetry data. |
| data_size [in]    | Size of telemetry data. |
| wait_option [in]    | Ticks to wait for message to be sent. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if telemetry message is sent out.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to send telemetry message due to invalid parameter.
* NX_AZURE_IOT_INVALID_PACKET Fail to send telemetry message due to packet is invalid.
* NXD_MQTT_PACKET_POOL_FAILURE Fail to send telemetry message due to no available packet in pool.
* NXD_MQTT_COMMUNICATION_FAILURE Fail to send telemetry message due to TCP/TLS error.
* NX_NO_PACKET Fail to send telemetry message due to no available packet in pool.

**Allowed From**

Threads

**Example**

**See Also**

**nx_azure_iot_pnp_client_command_receive**
***
<div style="text-align: right"> Receives PnP command message from IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_command_receive(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                             const UCHAR **component_name_pptr, UINT *component_name_length_ptr,
                                             const UCHAR **pnp_command_name_pptr, UINT *pnp_command_name_length_ptr,
                                             VOID **context_pptr, USHORT *context_length_ptr,
                                             NX_AZURE_IOT_JSON_READER *reader_ptr, UINT wait_option);
```
**Description**

<p>This routine receives PnP command message from IoT Hub. If there are no messages in the receive queue, this routine can block.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| component_name_pptr [out]    | Return a pointer to PnP component name on success. |
| component_name_length_ptr [out]    | Return length of `*component_name_pptr` on success. |
| pnp_command_name_pptr [out]    | Return a pointer to PnP command name on success. |
| pnp_command_name_length_ptr [out]    | Return length of `*pnp_command_name_pptr` on success. |
| context_pptr [out]    | Return a pointer to context pointer on success. |
| context_length_ptr [out]    | Return length of context on success. |
| reader_ptr [out]    | Return `NX_AZURE_IOT_JSON_READER` containing the method payload on success. |
| wait_option [in]    | Ticks to wait for message to arrive. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if PnP command message is received.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to receive PnP command message due to invalid parameter.
* NX_AZURE_IOT_NOT_ENABLED Fail to receive PnP command message due to it is not enabled.
* NX_AZURE_IOT_NO_PACKET Fail to receive PnP command message due to timeout.
* NX_AZURE_IOT_INVALID_PACKET Fail to receive PnP command message due to invalid packet.
* NX_AZURE_IOT_SDK_CORE_ERROR Fail to receive PnP command message due to SDK core error.
* NX_AZURE_IOT_DISCONNECTED Fail to receive PnP command message due to disconnect.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_command_message_response**
***
<div style="text-align: right"> Return response to PnP command message from IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_command_message_response(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      UINT status_code, VOID *context_ptr,
                                                      USHORT context_length, const UCHAR *payload_ptr,
                                                      UINT payload_length, UINT wait_option);
```
**Description**

<p>This routine returns response to the PnP command message from IoT Hub. Note: request_id ties the correlation between direct method receive and response.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| status_code [in]    | Status code for pnp command message. |
| context_ptr [in]    | Pointer to context return from nx_azure_iot_pnp_client_command_receive. |
| context_length [in]    | Length of context. |
| payload [in]    | Pointer to `UCHAR` containing the payload for the PnP command response. Payload is in JSON format. |
| payload_length [in]    | Length of the payload |
| wait_option [in]    | Ticks to wait for message to send. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if PnP command response is send.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to send PnP command response due to invalid parameter.
* NX_AZURE_IOT_SDK_CORE_ERROR Fail to send PnP command response due to SDK core error.
* NX_NO_PACKET Fail send PnP command response due to no available packet in pool.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_reported_properties_create**
***
<div style="text-align: right">Creates PnP reported property message writer.</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_reported_properties_create(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                        UINT wait_option)
```
**Description**

<p>This routine creates a PnP property message writer.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| writer_ptr [out]    | A pointer to a NX_AZURE_IOT_JSON_WRITER. |
| wait_option [in]    | Ticks to wait for writer creation. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if a message writer is created.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to create message writer due to invalid parameter.
* NX_AZURE_IOT_SDK_CORE_ERROR Fail to create message writer due to SDK core error.
* NX_NO_PACKET Fail to create message writer due to no available packet in pool.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_reported_property_component_begin**
***
<div style="text-align: right">Append the necessary characters to a reported property JSON payload belonging to a subcomponent.</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_reported_property_component_begin(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                               NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                               const UCHAR *component_name_ptr,
                                                               UINT component_name_length);
```
**Description**

<p>This routine append the necessary characters to a reported property JSON payload belonging to a subcomponent. The payload will be of the form: </p>

```c   
"reported": {
    "<component_name>": {
        "__t": "c",
        "temperature": 23
    }
}
```

**Note** This API should be used in conjunction with
```c
nx_azure_iot_pnp_client_reported_property_component_end()
```

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| writer_ptr [in]    | A pointer to a #NX_AZURE_IOT_JSON_WRITER. |
| component_name_ptr [in]    | A pointer to a component name. |
| component_name_length [in]    | Length of `component_name_ptr`. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if JSON payload was prefixed successfully.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_reported_property_component_end**
***
<div style="text-align: right">Append the necessary characters to end a reported property JSON payload belonging to a subcomponent.</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_reported_property_component_end(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                             NX_AZURE_IOT_JSON_WRITER *writer_ptr);
```
**Description**

<p>This routine append the necessary characters to end a reported property JSON payload</p>

**Note** This API should be used in conjunction with

```c
nx_azure_iot_pnp_client_reported_property_component_begin()
```


**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| writer_ptr [in]    | A pointer to a #NX_AZURE_IOT_JSON_WRITER. |


**Return Values**
* NX_AZURE_IOT_SUCCESS The JSON payload was suffixed successfully.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_reported_property_status_begin**
***
<div style="text-align: right"> Begin a property response payload with confirmation status.</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_reported_property_status_begin(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                            NX_AZURE_IOT_JSON_WRITER *writer_ptr,
                                                            const UCHAR *property_name_ptr, UINT property_name_length,
                                                            UINT ack_code, ULONG ack_version,
                                                            const UCHAR *ack_description_ptr, UINT ack_description_length);
```
**Description**

<p>This API should be used in response to an incoming desired property. More details can be found
here:

https://docs.microsoft.com/en-us/azure/iot-pnp/concepts-convention#writable-properties

The payload will be of the form:
<p>
**Without component**

```c
//{
//  "<property_name>":{
//    "ac": <ack_code>,
//    "av": <ack_version>,
//    "ad": "<ack_description>",
//    "value": <user_value>
//  }
//}
```

<p>To send a status for a property belonging to a component, first call the
nx_azure_iot_pnp_client_reported_property_status_begin() API to prefix the payload with the
necessary identification. The API call flow would look like the following with the listed JSON
payload being generated.<p>

**With component**

```c
nx_azure_iot_pnp_client_reported_property_component_begin()
nx_azure_iot_pnp_client_reported_property_status_begin()
// Append user value here (<user_value>)
nx_azure_iot_pnp_client_reported_property_status_end()
nx_azure_iot_pnp_client_reported_property_component_end()

//{
//  "<component_name>": {
//    "__t": "c",
//    "<property_name>": {
//      "ac": <ack_code>,
//      "av": <ack_version>,
//      "ad": "<ack_description>",
//      "value": <user_value>
//    }
//  }
//}
```

**Note** This API should be used in conjunction with
```c
nx_azure_iot_pnp_client_reported_property_status_end()
```

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| writer_ptr [in]    | A pointer to a #NX_AZURE_IOT_JSON_WRITER. |
| property_name_ptr [in]    | A pointer to property name. |
| property_name_length [in]    |  Length of `property_name_ptr`. |
| ack_code [in]    | The HTTP-like status code to respond with. |
| ack_version [in]    | The version of the property the application is acknowledging. |
| ack_description_ptr [in]    | An optional pointer to description detailing the context or any details about the acknowledgement. This can be empty string. |
| ack_description_length [in]    | Length of ack_description_ptr. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful appended JSON prefix.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_reported_property_status_end**
***
<div style="text-align: right">End a property response payload with confirmation status.</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_reported_property_status_end(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                          NX_AZURE_IOT_JSON_WRITER *writer_ptr);
```
**Description**

<p>This routine ends the property response payload.</p>

**Note** This API should be used in conjunction with
```c
nx_azure_iot_pnp_client_reported_property_status_begin()
```

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| writer_ptr [in]    | A pointer to a #NX_AZURE_IOT_JSON_WRITER. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful appended JSON suffix.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_report_properties_response_callback_set**
***
<div style="text-align: right">Sets reported properties response callback function</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_report_properties_response_callback_set(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                                     VOID (*callback_ptr)(
                                                                           NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                                           UINT request_id,
                                                                           UINT response_status,
                                                                           ULONG version,
                                                                           VOID *args),
                                                                     VOID *callback_args);
```
**Description**

<p>This routine sets the reponse receive callback function for reported properties. This callback
 function is invoked when a response is received from Azure IoT hub for reported properties and no
 thread is waiting for response. Setting the callback function to `NULL` disables the callback
 function.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| callback_ptr [in]    | Pointer to a callback function invoked. |
| callback_args [in]    | Pointer to an argument passed to callback function. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if callback function is set.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to set callback due to invalid parameter.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_reported_properties_send**
***
<div style="text-align: right">Sends PnP reported properties message to IoTHub.</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_reported_properties_send(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                      NX_AZURE_IOT_JSON_WRITER *reported_property_message,
                                                      UINT *request_id_ptr, UINT *response_status_ptr,
                                                      ULONG *version_ptr, UINT wait_option);
```
**Description**

<p>This routine sends the reported property contain in the JSON Writer .</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| writer_ptr [in]    | A pointer to a #NX_AZURE_IOT_JSON_WRITER. |
| request_id_ptr [out]    | Request Id assigned to the request. |
| response_status_ptr [out]    | Status return for successful send of reported properties. |
| version_ptr [out]    | Version return for successful send of reported properties. |
| wait_option [in]    | Ticks to wait for message to send. |


**Return Values**
 * NX_AZURE_IOT_SUCCESS Successful if reported properties is sent.
 * NX_AZURE_IOT_INVALID_PARAMETER Fail to send reported properties due to invalid parameter.
 * NX_AZURE_IOT_NOT_ENABLED Fail to send reported properties due to device twin is not enabled.
 * NX_AZURE_IOT_SDK_CORE_ERROR Fail to send reported properties due to SDK core error.
 * NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail to send reported properties due to buffer size is too small.
 * NX_AZURE_IOT_NO_PACKET Fail to send reported properties due to no packet available.
 * NX_NO_PACKET Fail to send reported properties due to no packet available.
 * NX_AZURE_IOT_DISCONNECTED Fail to send reported properties due to disconnect.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_properties_request**
***
<div style="text-align: right">Request complete to get all properties</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_properties_request(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                UINT wait_option);
```
**Description**

<p>This routine requests all properties.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| wait_option [in]    | Ticks to wait for to wait for sending request. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if request get all properties is sent..
* NX_AZURE_IOT_INVALID_PARAMETER Fail to request get all properties due to invalid parameter.
* NX_AZURE_IOT_NO_SUBSCRIBE_ACK Fail to request get all properties due to no subscribe ack.
* NX_AZURE_IOT_SDK_CORE_ERROR Fail to request get all properties due to SDK core error.
* NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail to request get all properties due to buffer size is too small.
* NX_AZURE_IOT_NO_PACKET Fail to request get all properties due to no packet available.
* NX_NO_PACKET Fail to request get all properties due to no packet available.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_properties_receive**
***
<div style="text-align: right">Receive all the properties</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_properties_receive(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                NX_AZURE_IOT_JSON_READER *reader_ptr,
                                                ULONG *desired_properties_version_ptr,
                                                UINT wait_option);
```
**Description**

<p>This routine receives all the properties.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| reader_ptr [out]    | A pointer to a #NX_AZURE_IOT_JSON_READER containing all the properties. |
| desired_properties_version_ptr [out]    | A pointer to `ULONG`, containing version of desired properties. |
| wait_option [in]    | Ticks to wait for message to receive. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if all properties is received.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to receive all properties due to invalid parameter.
* NX_AZURE_IOT_NOT_ENABLED Fail to receive all properties due to it is not enabled.
* NX_AZURE_IOT_NO_PACKET Fail to receive all properties due to timeout.
* NX_AZURE_IOT_INVALID_PACKET Fail to receive all properties due to invalid packet.
* NX_AZURE_IOT_SDK_CORE_ERROR Fail to receive all properties due to SDK core error.
* NX_AZURE_IOT_SERVER_RESPONSE_ERROR Response code from server is not 2xx.
* NX_AZURE_IOT_DISCONNECTED Fail to receive all properties due to disconnect.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_desired_properties_receive**
***
<div style="text-align: right">Receive desired properties form IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_desired_properties_receive(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                        NX_AZURE_IOT_JSON_READER *reader_ptr,
                                                        ULONG *properties_version_ptr,
                                                        UINT wait_option);
```
**Description**

<p>This routine receives desired properties from IoTHub.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| reader_ptr [out]    | A pointer to a #NX_AZURE_IOT_JSON_READER containing desired properties. |
| desired_properties_version_ptr [out]    | A pointer to `ULONG`, containing version of properties. |
| wait_option [in]    | Ticks to wait for message to receive. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if desired properties is received.
* NX_AZURE_IOT_INVALID_PARAMETER Fail to receive desired properties due to invalid parameter.
* NX_AZURE_IOT_NOT_ENABLED Fail to receive desired properties due to it is not enabled.
* NX_AZURE_IOT_NO_PACKET Fail to receive desired properties due to timeout.
* NX_AZURE_IOT_INVALID_PACKET Fail to receive desired properties due to invalid packet.
* NX_AZURE_IOT_DISCONNECTED Fail to receive desired properties due to disconnect.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_pnp_client_desired_component_property_value_next**
***
<div style="text-align: right">Return the next desired property in the property document passed.</div>

**Prototype**
```c
UINT nx_azure_iot_pnp_client_desired_component_property_value_next(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                                                   NX_AZURE_IOT_JSON_READER *reader_ptr, UINT message_type,
                                                                   const UCHAR **component_pptr, UINT *component_len_ptr,
                                                                   NX_AZURE_IOT_JSON_READER *name_value_reader_ptr);
```
**Description**

<p>This routine gets the next desired property in the property document passed.</p>

**Parameters**

| Name | Description |
| - |:-|
| pnp_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PNP_CLIENT`. |
| reader_ptr [in]    | A pointer to a #NX_AZURE_IOT_JSON_READER containing properties document. |
| message_type [in]    | Type of document, only valid value are NX_AZURE_IOT_PNP_DESIRED_PROPERTIES or NX_AZURE_IOT_PNP_PROPERTIES. |
| component_pptr [out]    | A pointer to component name for the property returned using name_value_reader_ptr. |
| component_len_ptr [out]    | Length of the component name. |
| name_value_reader_ptr [out]    | A pointer to a #NX_AZURE_IOT_JSON_READER containing property name and value. |


**Return Values**
* NX_AZURE_IOT_SUCCESS Successful if next desired property is found.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>
