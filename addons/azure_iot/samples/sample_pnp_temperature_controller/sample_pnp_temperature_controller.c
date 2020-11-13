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
#include "nx_azure_iot_pnp_client.h"
#include "nx_azure_iot_provisioning_client.h"

/* These are sample files, user can build their own certificate and ciphersuites.  */
#include "nx_azure_iot_cert.h"
#include "nx_azure_iot_ciphersuites.h"
#include "sample_config.h"
#include "sample_pnp_deviceinfo_component.h"
#include "sample_pnp_thermostat_component.h"

#ifndef SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC
#define SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC                           (10 * 60)
#endif /* SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC */

#ifndef SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC
#define SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC                       (3)
#endif /* SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC */

#ifndef SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT
#define SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT                   (60)
#endif /* SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT */

#ifndef SAMPLE_WAIT_OPTION
#define SAMPLE_WAIT_OPTION                                              (NX_NO_WAIT)
#endif /* SAMPLE_WAIT_OPTION */

/* Sample events.  */
#define SAMPLE_ALL_EVENTS                                               ((ULONG)0xFFFFFFFF)
#define SAMPLE_CONNECT_EVENT                                            ((ULONG)0x00000001)
#define SAMPLE_INITIALIZATION_EVENT                                     ((ULONG)0x00000002)
#define SAMPLE_COMMAND_MESSAGE_EVENT                                    ((ULONG)0x00000004)
#define SAMPLE_DEVICE_PROPERTIES_GET_EVENT                              ((ULONG)0x00000008)
#define SAMPLE_DEVICE_DESIRED_PROPERTIES_EVENT                          ((ULONG)0x00000010)
#define SAMPLE_TELEMETRY_SEND_EVENT                                     ((ULONG)0x00000020)
#define SAMPLE_DEVICE_REPORTED_PROPERTIES_EVENT                         ((ULONG)0x00000040)
#define SAMPLE_DISCONNECT_EVENT                                         ((ULONG)0x00000080)
#define SAMPLE_RECONNECT_EVENT                                          ((ULONG)0x00000100)
#define SAMPLE_CONNECTED_EVENT                                          ((ULONG)0x00000200)

/* Sample states.  */
#define SAMPLE_STATE_NONE                                               (0)
#define SAMPLE_STATE_INIT                                               (1)
#define SAMPLE_STATE_CONNECTING                                         (2)
#define SAMPLE_STATE_CONNECT                                            (3)
#define SAMPLE_STATE_CONNECTED                                          (4)
#define SAMPLE_STATE_DISCONNECTED                                       (5)

#define SAMPLE_DEFAULT_START_TEMP_CELSIUS                               (22)
#define DOUBLE_DECIMAL_PLACE_DIGITS                                     (2)
#define SAMPLE_COMMAND_SUCCESS_STATUS                                   (200)
#define SAMPLE_COMMAND_ERROR_STATUS                                     (500)
#define SAMPLE_COMMAND_NOT_FOUND_STATUS                                 (404)

#define SAMPLE_PNP_MODEL_ID                                             "dtmi:com:example:TemperatureController;1"
#define SAMPLE_PNP_DPS_PAYLOAD                                          "{\"modelId\":\"" SAMPLE_PNP_MODEL_ID "\"}"

/* Define Sample context.  */
typedef struct SAMPLE_CONTEXT_STRUCT
{
    UINT                                state;
    UINT                                action_result;
    ULONG                               last_periodic_action_tick;

    TX_EVENT_FLAGS_GROUP                sample_events;

    /* Generally, IoTHub Client and DPS Client do not run at the same time, user can use union as below to
       share the memory between IoTHub Client and DPS Client.

       NOTE: If user can not make sure sharing memory is safe, IoTHub Client and DPS Client must be defined seperately.  */
    union SAMPLE_CLIENT_UNION
    {
        NX_AZURE_IOT_PNP_CLIENT             iotpnp_client;
#ifdef ENABLE_DPS_SAMPLE
        NX_AZURE_IOT_PROVISIONING_CLIENT    prov_client;
#endif /* ENABLE_DPS_SAMPLE */
    } client;

#define iotpnp_client client.iotpnp_client
#ifdef ENABLE_DPS_SAMPLE
#define prov_client client.prov_client
#endif /* ENABLE_DPS_SAMPLE */

} SAMPLE_CONTEXT;

VOID sample_entry(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time));

#ifdef ENABLE_DPS_SAMPLE
static UINT sample_dps_entry(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                             UCHAR **iothub_hostname, UINT *iothub_hostname_length,
                             UCHAR **iothub_device_id, UINT *iothub_device_id_length);
#endif /* ENABLE_DPS_SAMPLE */

/* Define Azure RTOS TLS info.  */
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR nx_azure_iot_tls_metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG nx_azure_iot_thread_stack[NX_AZURE_IOT_STACK_SIZE / sizeof(ULONG)];

/* Using X509 certificate authenticate to connect to IoT Hub,
   set the device certificate as your device.  */
#if (USE_DEVICE_CERTIFICATE == 1)
extern const UCHAR sample_device_cert_ptr[];
extern const UINT sample_device_cert_len;
extern const UCHAR sample_device_private_key_ptr[];
extern const UINT sample_device_private_key_len;
NX_SECURE_X509_CERT device_certificate;
#endif /* USE_DEVICE_CERTIFICATE */

/* Define buffer for IoTHub info.  */
#ifdef ENABLE_DPS_SAMPLE
static UCHAR sample_iothub_hostname[SAMPLE_MAX_BUFFER];
static UCHAR sample_iothub_device_id[SAMPLE_MAX_BUFFER];
#endif /* ENABLE_DPS_SAMPLE */

/* Define the prototypes for AZ IoT.  */
static NX_AZURE_IOT nx_azure_iot;

static SAMPLE_CONTEXT sample_context;
static volatile UINT sample_connection_status = NX_NOT_CONNECTED;
static UINT exponential_retry_count;

/* PNP model id.  */
static SAMPLE_PNP_THERMOSTAT_COMPONENT sample_thermostat_1;
static const CHAR sample_thermostat_1_component[] = "thermostat1";
static double sample_thermostat_1_last_device_max_temp_reported;
static SAMPLE_PNP_THERMOSTAT_COMPONENT sample_thermostat_2;
static const CHAR sample_thermostat_2_component[] = "thermostat2";
static double sample_thermostat_2_last_device_max_tem_reported;
static const CHAR sample_device_info_component[] = "deviceInformation";
static UINT sample_device_info_sent;
static UINT sample_device_serial_info_sent;

/* Name of the serial number property as defined in this component's DTML.  */
static const CHAR sample_serial_number_property_name[] = "serialNumber";

/* Value of the serial number.  NOTE: This must be a legal JSON string which requires value to be in "..."  */
static const CHAR sample_serial_number_property_value[] = "serial-no-123-abc";

static const CHAR working_set[] = "workingSet";

/* PnP command supported.  */
static const CHAR rebootCommand[] = "reboot";

static const INT working_set_minimum = 1000;
static const INT working_set_random_modulo = 500;

static UCHAR scratch_buffer[256];

static UINT sample_pnp_temp_controller_reboot_command(NX_AZURE_IOT_JSON_READER *json_reader_ptr,
                                                      NX_AZURE_IOT_JSON_WRITER *out_json_builder_ptr)
{
INT delay;

    NX_PARAMETER_NOT_USED(out_json_builder_ptr);

    if (nx_azure_iot_json_reader_next_token(json_reader_ptr) ||
        nx_azure_iot_json_reader_token_int32_get(json_reader_ptr, (int32_t *)&delay))
    {
        return(NX_NOT_SUCCESSFUL);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT sample_pnp_temp_controller_telemetry_send(NX_AZURE_IOT_PNP_CLIENT *iotpnp_client_ptr)
{
UINT status;
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_WRITER json_writer;
UINT buffer_length;
INT working_set_value;

    working_set_value = working_set_minimum + (rand() % working_set_random_modulo);

    /* Create a telemetry message packet.  */
    if ((status = nx_azure_iot_pnp_client_telemetry_message_create(iotpnp_client_ptr, NX_NULL, 0,
                                                                   &packet_ptr, NX_WAIT_FOREVER)))
    {
        printf("Telemetry message create failed!: error code = 0x%08x\r\n", status);
        return(status);
    }

    /* Build telemetry JSON payload.  */
    if (nx_azure_iot_json_writer_with_buffer_init(&json_writer, scratch_buffer, sizeof(scratch_buffer)))
    {
        printf("Telemetry message failed to build message\r\n");
        nx_azure_iot_pnp_client_telemetry_message_delete(packet_ptr);
        return(NX_NOT_SUCCESSFUL);
    }

    if(nx_azure_iot_json_writer_append_begin_object(&json_writer) ||
       nx_azure_iot_json_writer_append_property_with_int32_value(&json_writer,
                                                                 (UCHAR *)working_set,
                                                                 sizeof(working_set) - 1,
                                                                 working_set_value) ||
        nx_azure_iot_json_writer_append_end_object(&json_writer))
    {
        printf("Telemetry message failed to build message\r\n");
        nx_azure_iot_json_writer_deinit(&json_writer);
        nx_azure_iot_pnp_client_telemetry_message_delete(packet_ptr);
        return(NX_NOT_SUCCESSFUL);
    }

    buffer_length = nx_azure_iot_json_writer_get_bytes_used(&json_writer);
    if ((status = nx_azure_iot_pnp_client_telemetry_send(iotpnp_client_ptr, packet_ptr,
                                                         (UCHAR *)scratch_buffer, buffer_length, NX_WAIT_FOREVER)))
    {
        printf("Telemetry message send failed!: error code = 0x%08x\r\n", status);
        nx_azure_iot_json_writer_deinit(&json_writer);
        nx_azure_iot_pnp_client_telemetry_message_delete(packet_ptr);
        return(status);
    }

    nx_azure_iot_json_writer_deinit(&json_writer);
    printf("Temp Controller Telemetry message send: %.*s.\r\n", buffer_length, scratch_buffer);

    return(status);
}

static UINT sample_pnp_temp_controller_process_command(const UCHAR *component_name_ptr, UINT component_name_length,
                                                       const UCHAR *pnp_command_name_ptr, UINT pnp_command_name_length,
                                                       NX_AZURE_IOT_JSON_READER *json_reader_ptr,
                                                       NX_AZURE_IOT_JSON_WRITER *json_response_ptr, UINT *status_code)
{
UINT dm_status;

    if (component_name_ptr != NX_NULL || component_name_length != 0)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (pnp_command_name_length != (sizeof(rebootCommand) - 1) ||
        strncmp((CHAR *)pnp_command_name_ptr, (CHAR *)rebootCommand, pnp_command_name_length) != 0)
    {
        printf("PnP command=%.*s is not supported on thermostat component",
               pnp_command_name_length, pnp_command_name_ptr);
        dm_status = SAMPLE_COMMAND_NOT_FOUND_STATUS;
    }
    else
    {
        if (sample_pnp_temp_controller_reboot_command(json_reader_ptr, json_response_ptr))
        {
            dm_status = SAMPLE_COMMAND_ERROR_STATUS;
        }
        else
        {
            dm_status = SAMPLE_COMMAND_SUCCESS_STATUS;
        }
    }

    *status_code = dm_status;

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT sample_pnp_temp_controller_report_serial_number_property(NX_AZURE_IOT_PNP_CLIENT *iotpnp_client_ptr)
{
UINT status;
UINT response_status = 0;
NX_AZURE_IOT_JSON_WRITER json_writer;

    if ((status = nx_azure_iot_pnp_client_reported_properties_create(iotpnp_client_ptr,
                                                                     &json_writer, NX_WAIT_FOREVER)))
    {
        printf("Failed create reported properties: error code = 0x%08x\r\n", status);
        return(status);
    }

    if ((status = nx_azure_iot_json_writer_append_property_with_string_value(&json_writer,
                                                                             (UCHAR *)sample_serial_number_property_name,
                                                                             sizeof(sample_serial_number_property_name) - 1,
                                                                             (UCHAR *)sample_serial_number_property_value,
                                                                             sizeof(sample_serial_number_property_value) - 1)))
    {
        printf("Failed to build reported property!: error code = 0x%08x\r\n", status);
        nx_azure_iot_json_writer_deinit(&json_writer);
        return(status);
    }

    if ((status = nx_azure_iot_pnp_client_reported_properties_send(iotpnp_client_ptr,
                                                                   &json_writer,
                                                                   NX_NULL, &response_status,
                                                                   NX_NULL,
                                                                   (5 * NX_IP_PERIODIC_RATE))))
    {
        printf("Reported properties send failed!: error code = 0x%08x\r\n", status);
        nx_azure_iot_json_writer_deinit(&json_writer);
        return(status);
    }

    nx_azure_iot_json_writer_deinit(&json_writer);

    if ((response_status < 200) || (response_status >= 300))
    {
        printf("Reported properties send failed with code : %d\r\n", response_status);
        return(NX_NOT_SUCCESSFUL);
    }

    return(status);
}

static UINT exponential_backoff_with_jitter()
{
double jitter_percent = (SAMPLE_MAX_EXPONENTIAL_BACKOFF_JITTER_PERCENT / 100.0) * (rand() / ((double)RAND_MAX));
UINT base_delay = SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC;
uint64_t delay;

    if (exponential_retry_count < (sizeof(UINT) * 8))
    {
        delay = (uint64_t)((1 << exponential_retry_count) * SAMPLE_INITIAL_EXPONENTIAL_BACKOFF_IN_SEC);
        if (delay <= (UINT)(-1))
        {
            base_delay = (UINT)delay;
        }
    }

    if (base_delay > SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC)
    {
        base_delay = SAMPLE_MAX_EXPONENTIAL_BACKOFF_IN_SEC;
    }
    else
    {
        exponential_retry_count++;
    }

    return((UINT)(base_delay * (1 + jitter_percent)) * NX_IP_PERIODIC_RATE) ;
}

static VOID exponential_backoff_reset()
{
    exponential_retry_count = 0;
}

static VOID connection_status_callback(NX_AZURE_IOT_PNP_CLIENT *hub_client_ptr, UINT status)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);

    sample_connection_status = status;

    if (status)
    {
        printf("Disconnected from IoTHub!: error code = 0x%08x\r\n", status);
        tx_event_flags_set(&(sample_context.sample_events), SAMPLE_DISCONNECT_EVENT, TX_OR);
    }
    else
    {
        printf("Connected to IoTHub.\r\n");
        tx_event_flags_set(&(sample_context.sample_events), SAMPLE_CONNECTED_EVENT, TX_OR);
        exponential_backoff_reset();
    }
}

static VOID message_receive_callback_properties(NX_AZURE_IOT_PNP_CLIENT *hub_client_ptr, VOID *context)
{
SAMPLE_CONTEXT *sample_ctx = (SAMPLE_CONTEXT *)context;

    NX_PARAMETER_NOT_USED(hub_client_ptr);
    tx_event_flags_set(&(sample_ctx -> sample_events),
                       SAMPLE_DEVICE_PROPERTIES_GET_EVENT, TX_OR);
}

static VOID message_receive_callback_command(NX_AZURE_IOT_PNP_CLIENT *hub_client_ptr, VOID *context)
{
SAMPLE_CONTEXT *sample_ctx = (SAMPLE_CONTEXT *)context;

    NX_PARAMETER_NOT_USED(hub_client_ptr);
    tx_event_flags_set(&(sample_ctx -> sample_events),
                       SAMPLE_COMMAND_MESSAGE_EVENT, TX_OR);
}

static VOID message_receive_callback_desired_property(NX_AZURE_IOT_PNP_CLIENT *hub_client_ptr, VOID *context)
{
SAMPLE_CONTEXT *sample_ctx = (SAMPLE_CONTEXT *)context;

    NX_PARAMETER_NOT_USED(hub_client_ptr);
    tx_event_flags_set(&(sample_ctx -> sample_events),
                       SAMPLE_DEVICE_DESIRED_PROPERTIES_EVENT, TX_OR);
}

static VOID sample_connect_action(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_CONNECT)
    {
        return;
    }

    context -> action_result = nx_azure_iot_pnp_client_connect(&(context -> iotpnp_client),
                                                               NX_FALSE, SAMPLE_WAIT_OPTION);

    if (context -> action_result == NX_AZURE_IOT_CONNECTING)
    {
        context -> state = SAMPLE_STATE_CONNECTING;
    }
    else if (context -> action_result != NX_SUCCESS)
    {
        sample_connection_status = context -> action_result;
        context -> state = SAMPLE_STATE_DISCONNECTED;
    }
    else
    {
        context -> state = SAMPLE_STATE_CONNECTED;

        context -> action_result =
            nx_azure_iot_pnp_client_properties_request(&(context -> iotpnp_client), NX_WAIT_FOREVER);
    }
}

static VOID sample_disconnect_action(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_CONNECTED &&
        context -> state != SAMPLE_STATE_CONNECTING)
    {
        return;
    }

    context -> action_result = nx_azure_iot_pnp_client_disconnect(&(context -> iotpnp_client));
    context -> state = SAMPLE_STATE_DISCONNECTED;
}

static VOID sample_connected_action(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_CONNECTING)
    {
        return;
    }

    context -> state = SAMPLE_STATE_CONNECTED;

    context -> action_result =
        nx_azure_iot_pnp_client_properties_request(&(context -> iotpnp_client), NX_WAIT_FOREVER);
}

static VOID sample_initialize_iothub(SAMPLE_CONTEXT *context)
{
UINT status;
#ifdef ENABLE_DPS_SAMPLE
UCHAR *iothub_hostname = NX_NULL;
UCHAR *iothub_device_id = NX_NULL;
UINT iothub_hostname_length = 0;
UINT iothub_device_id_length = 0;
#else
UCHAR *iothub_hostname = (UCHAR *)HOST_NAME;
UCHAR *iothub_device_id = (UCHAR *)DEVICE_ID;
UINT iothub_hostname_length = sizeof(HOST_NAME) - 1;
UINT iothub_device_id_length = sizeof(DEVICE_ID) - 1;
#endif /* ENABLE_DPS_SAMPLE */
NX_AZURE_IOT_PNP_CLIENT *iotpnp_client_ptr = &(context -> iotpnp_client);

    if (context -> state != SAMPLE_STATE_INIT)
    {
        return;
    }

#ifdef ENABLE_DPS_SAMPLE

    /* Run DPS.  */
    if ((status = sample_dps_entry(&(context -> prov_client), &iothub_hostname, &iothub_hostname_length,
                                   &iothub_device_id, &iothub_device_id_length)))
    {
        printf("Failed on sample_dps_entry!: error code = 0x%08x\r\n", status);
        context -> action_result = status;
        return;
    }
#endif /* ENABLE_DPS_SAMPLE */

    printf("IoTHub Host Name: %.*s; Device ID: %.*s.\r\n",
           iothub_hostname_length, iothub_hostname, iothub_device_id_length, iothub_device_id);

    /* Initialize IoTHub client.  */
    if ((status = nx_azure_iot_pnp_client_initialize(iotpnp_client_ptr, &nx_azure_iot,
                                                     iothub_hostname, iothub_hostname_length,
                                                     iothub_device_id, iothub_device_id_length,
                                                     (const UCHAR *)MODULE_ID, sizeof(MODULE_ID) - 1,
                                                     (const UCHAR *)SAMPLE_PNP_MODEL_ID, sizeof(SAMPLE_PNP_MODEL_ID) - 1,
                                                     _nx_azure_iot_tls_supported_crypto,
                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                     nx_azure_iot_tls_metadata_buffer,
                                                     sizeof(nx_azure_iot_tls_metadata_buffer),
                                                     &root_ca_cert)))
    {
        printf("Failed on nx_azure_iot_pnp_client_initialize!: error code = 0x%08x\r\n", status);
        context -> action_result = status;
        return;
    }

#if (USE_DEVICE_CERTIFICATE == 1)

    /* Initialize the device certificate.  */
    if ((status = nx_secure_x509_certificate_initialize(&device_certificate,
                                                        (UCHAR *)sample_device_cert_ptr, (USHORT)sample_device_cert_len,
                                                        NX_NULL, 0,
                                                        (UCHAR *)sample_device_private_key_ptr, (USHORT)sample_device_private_key_len,
                                                        DEVICE_KEY_TYPE)))
    {
        printf("Failed on nx_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
    }

    /* Set device certificate.  */
    else if ((status = nx_azure_iot_pnp_client_device_cert_set(iotpnp_client_ptr, &device_certificate)))
    {
        printf("Failed on nx_azure_iot_pnp_client_device_cert_set!: error code = 0x%08x\r\n", status);
    }
#else

    /* Set symmetric key.  */
    if ((status = nx_azure_iot_pnp_client_symmetric_key_set(iotpnp_client_ptr,
                                                            (UCHAR *)DEVICE_SYMMETRIC_KEY,
                                                            sizeof(DEVICE_SYMMETRIC_KEY) - 1)))
    {
        printf("Failed on nx_azure_iot_pnp_client_symmetric_key_set! error: 0x%08x\r\n", status);
    }
#endif /* USE_DEVICE_CERTIFICATE */

    /* Set connection status callback.  */
    else if ((status = nx_azure_iot_pnp_client_connection_status_callback_set(iotpnp_client_ptr,
                                                                              connection_status_callback)))
    {
        printf("Failed on connection_status_callback!\r\n");
    }
    else if ((status = nx_azure_iot_pnp_client_receive_callback_set(iotpnp_client_ptr,
                                                                    NX_AZURE_IOT_PNP_PROPERTIES,
                                                                    message_receive_callback_properties,
                                                                    (VOID *)context)))
    {
        printf("device properties callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_pnp_client_receive_callback_set(iotpnp_client_ptr,
                                                                    NX_AZURE_IOT_PNP_COMMAND,
                                                                    message_receive_callback_command,
                                                                    (VOID *)context)))
    {
        printf("device command callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_pnp_client_receive_callback_set(iotpnp_client_ptr,
                                                                    NX_AZURE_IOT_PNP_DESIRED_PROPERTIES,
                                                                    message_receive_callback_desired_property,
                                                                    (VOID *)context)))
    {
        printf("device desired property callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_pnp_client_component_add(iotpnp_client_ptr,
                                                             (const UCHAR *)sample_thermostat_1_component,
                                                             sizeof(sample_thermostat_1_component) - 1)) ||
             (status = nx_azure_iot_pnp_client_component_add(iotpnp_client_ptr,
                                                             (const UCHAR *)sample_thermostat_2_component,
                                                             sizeof(sample_thermostat_2_component) - 1)) ||
             (status = nx_azure_iot_pnp_client_component_add(iotpnp_client_ptr,
                                                             (const UCHAR *)sample_device_info_component,
                                                             sizeof(sample_device_info_component) - 1)))
    {
        printf("Failed to add component to pnp client!: error code = 0x%08x\r\n", status);
    }

    if (status)
    {
        nx_azure_iot_pnp_client_deinitialize(iotpnp_client_ptr);
    }

    context -> action_result = status;

    if (status == NX_AZURE_IOT_SUCCESS)
    {
        context -> state = SAMPLE_STATE_CONNECT;
    }
}

static VOID sample_connection_error_recover(SAMPLE_CONTEXT *context)
{
    if (context -> state != SAMPLE_STATE_DISCONNECTED)
    {
        return;
    }

    switch (sample_connection_status)
    {
        case NX_AZURE_IOT_SUCCESS:
        {
            printf("already connected\r\n");
        }
        break;

        /* Something bad has happened with client state, we need to re-initialize it.  */
        case NX_DNS_QUERY_FAILED :
        case NXD_MQTT_ERROR_BAD_USERNAME_PASSWORD :
        case NXD_MQTT_ERROR_NOT_AUTHORIZED :
        {
            printf("re-initializing iothub connection, after backoff\r\n");

            tx_thread_sleep(exponential_backoff_with_jitter());
            nx_azure_iot_pnp_client_deinitialize(&(context -> iotpnp_client));
            context -> state = SAMPLE_STATE_INIT;
        }
        break;

        default :
        {
            printf("reconnecting iothub, after backoff\r\n");

            tx_thread_sleep(exponential_backoff_with_jitter());
            context -> state = SAMPLE_STATE_CONNECT;
        }
        break;
    }
}

static VOID sample_trigger_action(SAMPLE_CONTEXT *context)
{
    switch (context -> state)
    {
        case SAMPLE_STATE_INIT:
        {
            tx_event_flags_set(&(context -> sample_events), SAMPLE_INITIALIZATION_EVENT, TX_OR);
        }
        break;

        case SAMPLE_STATE_CONNECT:
        {
            tx_event_flags_set(&(context -> sample_events), SAMPLE_CONNECT_EVENT, TX_OR);
        }
        break;

        case SAMPLE_STATE_CONNECTED:
        {
            if ((tx_time_get() - context -> last_periodic_action_tick) >= (5 * NX_IP_PERIODIC_RATE))
            {
                context -> last_periodic_action_tick = tx_time_get();
                tx_event_flags_set(&(context -> sample_events), SAMPLE_TELEMETRY_SEND_EVENT, TX_OR);
                tx_event_flags_set(&(context -> sample_events), SAMPLE_DEVICE_REPORTED_PROPERTIES_EVENT, TX_OR);
            }
        }
        break;

        case SAMPLE_STATE_DISCONNECTED:
        {
            tx_event_flags_set(&(context -> sample_events), SAMPLE_RECONNECT_EVENT, TX_OR);
        }
        break;
    }
}

static VOID sample_command_action(SAMPLE_CONTEXT *sample_context_ptr)
{
UINT status;
USHORT context_length;
VOID *context_ptr;
UINT component_name_length;
const UCHAR *component_name_ptr;
UINT pnp_command_name_length;
const UCHAR *pnp_command_name_ptr;
NX_AZURE_IOT_JSON_WRITER json_writer;
NX_AZURE_IOT_JSON_READER json_reader;
UINT status_code;
UINT response_length;

    if (sample_context_ptr -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = nx_azure_iot_pnp_client_command_receive(&(sample_context_ptr -> iotpnp_client),
                                                          &component_name_ptr, &component_name_length,
                                                          &pnp_command_name_ptr, &pnp_command_name_length,
                                                          &context_ptr, &context_length,
                                                          &json_reader, NX_WAIT_FOREVER)))
    {
        printf("Command receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    if (component_name_ptr != NX_NULL)
    {
        printf("Received component: %.*s ", component_name_length, component_name_ptr);
    }
    else
    {
        printf("Received component: root component ");
    }

    printf("command: %.*s", pnp_command_name_length, (CHAR *)pnp_command_name_ptr);
    printf("\r\n");

    if ((status = nx_azure_iot_json_writer_with_buffer_init(&json_writer,
                                                            scratch_buffer,
                                                            sizeof(scratch_buffer))))
    {
        printf("Failed to initialize json builder response \r\n");
        nx_azure_iot_json_reader_deinit(&json_reader);
        return;
    }

    if ((status = sample_pnp_thermostat_process_command(&sample_thermostat_1, component_name_ptr,
                                                        component_name_length, pnp_command_name_ptr,
                                                        pnp_command_name_length, &json_reader,
                                                        &json_writer, &status_code)) == NX_AZURE_IOT_SUCCESS)
    {
        printf("Successfully executed command %.*s on thermostat 1\r\n", pnp_command_name_length, pnp_command_name_ptr);
        response_length = nx_azure_iot_json_writer_get_bytes_used(&json_writer);
    }
    else if ((status = sample_pnp_thermostat_process_command(&sample_thermostat_2, component_name_ptr,
                                                             component_name_length, pnp_command_name_ptr,
                                                             pnp_command_name_length, &json_reader,
                                                             &json_writer, &status_code)) == NX_AZURE_IOT_SUCCESS)
    {
        printf("Successfully executed command %.*s on thermostat 2\r\n", pnp_command_name_length, pnp_command_name_ptr);
        response_length = nx_azure_iot_json_writer_get_bytes_used(&json_writer);
    }
    else if((status = sample_pnp_temp_controller_process_command(component_name_ptr, component_name_length,
                                                                 pnp_command_name_ptr, pnp_command_name_length,
                                                                 &json_reader, &json_writer,
                                                                 &status_code)) == NX_AZURE_IOT_SUCCESS)
    {
        printf("Successfully executed command %.*s  controller \r\n", pnp_command_name_length, pnp_command_name_ptr);
        response_length = nx_azure_iot_json_writer_get_bytes_used(&json_writer);
    }
    else
    {
        printf("Failed to find any handler for command %.*s\r\n", pnp_command_name_length, pnp_command_name_ptr);
        status_code = SAMPLE_COMMAND_NOT_FOUND_STATUS;
        response_length = 0;
    }

    nx_azure_iot_json_reader_deinit(&json_reader);

    if ((status = nx_azure_iot_pnp_client_command_message_response(&(sample_context_ptr -> iotpnp_client), status_code,
                                                                   context_ptr, context_length, scratch_buffer,
                                                                   response_length, NX_WAIT_FOREVER)))
    {
        printf("Command response failed!: error code = 0x%08x\r\n", status);
    }

    nx_azure_iot_json_writer_deinit(&json_writer);
}

static VOID sample_desired_properties_parse(NX_AZURE_IOT_PNP_CLIENT *pnp_client_ptr,
                                            NX_AZURE_IOT_JSON_READER *json_reader_ptr,
                                            UINT message_type, ULONG version)
{
const UCHAR *component_ptr = NX_NULL;
UINT component_len = 0;
NX_AZURE_IOT_JSON_READER name_value_reader;

    while (nx_azure_iot_pnp_client_desired_component_property_value_next(pnp_client_ptr,
                                                                         json_reader_ptr, message_type,
                                                                         &component_ptr, &component_len,
                                                                         &name_value_reader) == NX_AZURE_IOT_SUCCESS)
    {
        if (sample_pnp_thermostat_process_property_update(&sample_thermostat_1,
                                                          pnp_client_ptr,
                                                          component_ptr, component_len,
                                                          &name_value_reader, version) == NX_AZURE_IOT_SUCCESS)
        {
            printf("property updated of thermostat 1\r\n");
        }
        else if (sample_pnp_thermostat_process_property_update(&sample_thermostat_2,
                                                               pnp_client_ptr,
                                                               component_ptr, component_len,
                                                               &name_value_reader, version) == NX_AZURE_IOT_SUCCESS)
        {
            printf("property updated of thermostat 2\r\n");
        }
        else
        {
            if (component_ptr)
            {
                printf("Component=%.*s is not implemented by the Controller\r\n", component_len, component_ptr);
            }
            else
            {
                printf("Root component is not implemented by the Controller\r\n");
            }
        }
    }
}

static VOID sample_device_desired_property_action(SAMPLE_CONTEXT *context)
{

UINT status = 0;
NX_AZURE_IOT_JSON_READER json_reader;
ULONG desired_properties_version;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = nx_azure_iot_pnp_client_desired_properties_receive(&(context -> iotpnp_client),
                                                                     &json_reader,
                                                                     &desired_properties_version,
                                                                     NX_WAIT_FOREVER)))
    {
        printf("desired properties receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf("Received desired property");
    printf("\r\n");

    sample_desired_properties_parse(&(context -> iotpnp_client), &json_reader,
                                    NX_AZURE_IOT_PNP_DESIRED_PROPERTIES,
                                    desired_properties_version);

    nx_azure_iot_json_reader_deinit(&json_reader);
}

static VOID sample_device_reported_property_action(SAMPLE_CONTEXT *context)
{
UINT status;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    /* Only report once.  */
    if (sample_device_serial_info_sent == 0)
    {
        if ((status = sample_pnp_temp_controller_report_serial_number_property(&(context -> iotpnp_client))))
        {
            printf("Failed sample_pnp_temp_controller_report_serial_number_property: error code = 0x%08x\r\n", status);
        }
        else
        {
            sample_device_serial_info_sent = 1;
        }
    }

    /* Only report once.  */
    if (sample_device_info_sent == 0)
    {
        if ((status = sample_pnp_deviceinfo_report_all_properties((UCHAR *)sample_device_info_component,
                                                                  sizeof(sample_device_info_component) - 1,
                                                                  &(context -> iotpnp_client))))
        {
            printf("Failed sample_pnp_deviceinfo_report_all_properties: error code = 0x%08x\r\n", status);
        }
        else
        {
            sample_device_info_sent = 1;
        }
    }

    /* Only report when changed.  */
    if (!(((sample_thermostat_1_last_device_max_temp_reported - 0.01) < sample_thermostat_1.maxTemperature) &&
          ((sample_thermostat_1_last_device_max_temp_reported + 0.01) > sample_thermostat_1.maxTemperature)))
    {
        if ((status = sample_pnp_thermostat_report_max_temp_since_last_reboot_property(&sample_thermostat_1,
                                                                                       &(context -> iotpnp_client))))
        {
            printf("Failed sample_pnp_thermostat_report_max_temp_since_last_reboot_property: error code = 0x%08x\r\n", status);
        }
        else
        {
            sample_thermostat_1_last_device_max_temp_reported = sample_thermostat_1.maxTemperature;
        }
    }

    /* Only report when changed.  */
    if (!(((sample_thermostat_2_last_device_max_tem_reported - 0.01) < sample_thermostat_2.maxTemperature) &&
          ((sample_thermostat_2_last_device_max_tem_reported + 0.01) > sample_thermostat_2.maxTemperature)))
    {
        if ((status = sample_pnp_thermostat_report_max_temp_since_last_reboot_property(&sample_thermostat_2,
                                                                                       &(context -> iotpnp_client))))
        {
            printf("Failed sample_pnp_thermostat_report_max_temp_since_last_reboot_property: error code = 0x%08x\r\n", status);
        }
        else
        {
            sample_thermostat_2_last_device_max_tem_reported = sample_thermostat_2.maxTemperature;
        }
    }
}

static VOID sample_device_properties_get_action(SAMPLE_CONTEXT *context)
{
UINT status = 0;
NX_AZURE_IOT_JSON_READER json_reader;
ULONG desired_properties_version;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = nx_azure_iot_pnp_client_properties_receive(&(context -> iotpnp_client),
                                                             &json_reader,
                                                             &desired_properties_version,
                                                             NX_WAIT_FOREVER)))
    {
        printf("Get all properties receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf("Received all properties");
    printf("\r\n");

    sample_desired_properties_parse(&(context -> iotpnp_client), &json_reader,
                                    NX_AZURE_IOT_PNP_PROPERTIES,
                                    desired_properties_version);

    nx_azure_iot_json_reader_deinit(&json_reader);
}

static VOID sample_telemetry_action(SAMPLE_CONTEXT *context)
{
UINT status;

    if (context -> state != SAMPLE_STATE_CONNECTED)
    {
        return;
    }

    if ((status = sample_pnp_temp_controller_telemetry_send(&(context -> iotpnp_client))) != NX_AZURE_IOT_SUCCESS)
    {
        printf("Failed to send sample_pnp__telemetry_send, error: %d", status);
    }

    if ((status = sample_pnp_thermostat_telemetry_send(&sample_thermostat_1,
                                                       &(context -> iotpnp_client))) != NX_AZURE_IOT_SUCCESS)
    {
        printf("Failed to send sample_pnp_thermostat_telemetry_send, error: %d", status);
    }

    if ((status = sample_pnp_thermostat_telemetry_send(&sample_thermostat_2,
                                                       &(context -> iotpnp_client))) != NX_AZURE_IOT_SUCCESS)
    {
        printf("Failed to send sample_pnp_thermostat_telemetry_send, error: %d", status);
    }
}

#ifdef ENABLE_DPS_SAMPLE
static UINT sample_dps_entry(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                             UCHAR **iothub_hostname, UINT *iothub_hostname_length,
                             UCHAR **iothub_device_id, UINT *iothub_device_id_length)
{
UINT status;

    printf("Start Provisioning Client...\r\n");

    /* Initialize IoT provisioning client.  */
    if ((status = nx_azure_iot_provisioning_client_initialize(prov_client_ptr, &nx_azure_iot,
                                                              (UCHAR *)ENDPOINT, sizeof(ENDPOINT) - 1,
                                                              (UCHAR *)ID_SCOPE, sizeof(ID_SCOPE) - 1,
                                                              (UCHAR *)REGISTRATION_ID, sizeof(REGISTRATION_ID) - 1,
                                                              _nx_azure_iot_tls_supported_crypto,
                                                              _nx_azure_iot_tls_supported_crypto_size,
                                                              _nx_azure_iot_tls_ciphersuite_map,
                                                              _nx_azure_iot_tls_ciphersuite_map_size,
                                                              nx_azure_iot_tls_metadata_buffer,
                                                              sizeof(nx_azure_iot_tls_metadata_buffer),
                                                              &root_ca_cert)))
    {
        printf("Failed on nx_azure_iot_provisioning_client_initialize!: error code = 0x%08x\r\n", status);
        return(status);
    }

    /* Initialize length of hostname and device ID.  */
    *iothub_hostname_length = sizeof(sample_iothub_hostname);
    *iothub_device_id_length = sizeof(sample_iothub_device_id);

#if (USE_DEVICE_CERTIFICATE == 1)

    /* Initialize the device certificate.  */
    if ((status = nx_secure_x509_certificate_initialize(&device_certificate, (UCHAR *)sample_device_cert_ptr, (USHORT)sample_device_cert_len, NX_NULL, 0,
                                                        (UCHAR *)sample_device_private_key_ptr, (USHORT)sample_device_private_key_len, DEVICE_KEY_TYPE)))
    {
        printf("Failed on nx_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
    }

    /* Set device certificate.  */
    else if ((status = nx_azure_iot_provisioning_client_device_cert_set(prov_client_ptr, &device_certificate)))
    {
        printf("Failed on nx_azure_iot_provisioning_client_device_cert_set!: error code = 0x%08x\r\n", status);
    }
#else

    /* Set symmetric key.  */
    if ((status = nx_azure_iot_provisioning_client_symmetric_key_set(prov_client_ptr, (UCHAR *)DEVICE_SYMMETRIC_KEY,
                                                                     sizeof(DEVICE_SYMMETRIC_KEY) - 1)))
    {
        printf("Failed on nx_azure_iot_pnp_client_symmetric_key_set!: error code = 0x%08x\r\n", status);
    }
#endif /* USE_DEVICE_CERTIFICATE */
    else if ((status = nx_azure_iot_provisioning_client_registration_payload_set(prov_client_ptr, (UCHAR *)SAMPLE_PNP_DPS_PAYLOAD,
                                                                                 sizeof(SAMPLE_PNP_DPS_PAYLOAD) - 1)))
    {
        printf("Failed on nx_azure_iot_provisioning_client_registration_payload_set!: error code = 0x%08x\r\n", status);
    }

    /* Register device */
    else if ((status = nx_azure_iot_provisioning_client_register(prov_client_ptr, NX_WAIT_FOREVER)))
    {
        printf("Failed on nx_azure_iot_provisioning_client_register!: error code = 0x%08x\r\n", status);
    }

    /* Get Device info */
    else if ((status = nx_azure_iot_provisioning_client_iothub_device_info_get(prov_client_ptr,
                                                                               sample_iothub_hostname, iothub_hostname_length,
                                                                               sample_iothub_device_id, iothub_device_id_length)))
    {
        printf("Failed on nx_azure_iot_provisioning_client_iothub_device_info_get!: error code = 0x%08x\r\n", status);
    }
    else
    {
        *iothub_hostname = sample_iothub_hostname;
        *iothub_device_id = sample_iothub_device_id;
        printf("Registered Device Successfully.\r\n");
    }

    /* Destroy Provisioning Client.  */
    nx_azure_iot_provisioning_client_deinitialize(prov_client_ptr);

    return(status);
}
#endif /* ENABLE_DPS_SAMPLE */

/**
 *
 * Sample Event loop
 *
 *
 *       +--------------+           +--------------+      +--------------+       +--------------+
 *       |              |  INIT     |              |      |              |       |              |
 *       |              | SUCCESS   |              |      |              |       |              +--------+
 *       |    INIT      |           |    CONNECT   |      |  CONNECTING  |       |   CONNECTED  |        | (TELEMETRY |
 *       |              +----------->              +----->+              +------->              |        |  COMMAND |
 *       |              |           |              |      |              |       |              <--------+  PROPERTIES)
 *       |              |           |              |      |              |       |              |
 *       +-----+--------+           +----+---+-----+      +------+-------+       +--------+-----+
 *             ^                         ^   |                   |                        |
 *             |                         |   |                   |                        |
 *             |                         |   |                   |                        |
 *             |                         |   | CONNECT           | CONNECTING             |
 *             |                         |   |  FAIL             |   FAIL                 |
 * REINITIALIZE|                RECONNECT|   |                   |                        |
 *             |                         |   |                   v                        |  DISCONNECT
 *             |                         |   |        +----------+-+                      |
 *             |                         |   |        |            |                      |
 *             |                         |   +------->+            |                      |
 *             |                         |            | DISCONNECT |                      |
 *             |                         |            |            +<---------------------+
 *             |                         +------------+            |
 *             +--------------------------------------+            |
 *                                                    +------------+
 *
 *
 *
 */
static VOID sample_event_loop(SAMPLE_CONTEXT *context)
{
ULONG app_events;
UINT loop = NX_TRUE;

    while (loop)
    {

        /* Pickup IP event flags.  */
        if (tx_event_flags_get(&(context -> sample_events), SAMPLE_ALL_EVENTS, TX_OR_CLEAR, &app_events, 5 * NX_IP_PERIODIC_RATE))
        {
            if (context -> state == SAMPLE_STATE_CONNECTED)
            {
                sample_trigger_action(context);
            }

            continue;
        }

        if (app_events & SAMPLE_CONNECT_EVENT)
        {
            sample_connect_action(context);
        }

        if (app_events & SAMPLE_INITIALIZATION_EVENT)
        {
            sample_initialize_iothub(context);
        }

        if (app_events & SAMPLE_DEVICE_PROPERTIES_GET_EVENT)
        {
            sample_device_properties_get_action(context);
        }

        if (app_events & SAMPLE_COMMAND_MESSAGE_EVENT)
        {
            sample_command_action(context);
        }

        if (app_events & SAMPLE_DEVICE_DESIRED_PROPERTIES_EVENT)
        {
            sample_device_desired_property_action(context);
        }

        if (app_events & SAMPLE_TELEMETRY_SEND_EVENT)
        {
            sample_telemetry_action(context);
        }

        if (app_events & SAMPLE_DEVICE_REPORTED_PROPERTIES_EVENT)
        {
            sample_device_reported_property_action(context);
        }

        if (app_events & SAMPLE_DISCONNECT_EVENT)
        {
            sample_disconnect_action(context);
        }

        if (app_events & SAMPLE_CONNECTED_EVENT)
        {
            sample_connected_action(context);
        }

        if (app_events & SAMPLE_RECONNECT_EVENT)
        {
            sample_connection_error_recover(context);
        }

        sample_trigger_action(context);
    }
}

static VOID sample_context_init(SAMPLE_CONTEXT *context)
{
    memset(context, 0, sizeof(SAMPLE_CONTEXT));
    tx_event_flags_create(&(context->sample_events), (CHAR*)"sample_app");
}

static VOID log_callback(az_log_classification classification, UCHAR *msg, UINT msg_len)
{
    if (classification == AZ_LOG_IOT_AZURERTOS)
    {
        printf("%.*s", msg_len, (CHAR *)msg);
    }
}

static UINT sample_components_init()
{
UINT status;

    if ((status = sample_pnp_thermostat_init(&sample_thermostat_1,
                                             (UCHAR *)sample_thermostat_1_component,
                                             sizeof(sample_thermostat_1_component) - 1,
                                             SAMPLE_DEFAULT_START_TEMP_CELSIUS)))
    {
        printf("Failed to initialize %s: error code = 0x%08x\r\n",
               sample_thermostat_1_component, status);
    }
    else if ((status = sample_pnp_thermostat_init(&sample_thermostat_2,
                                                  (UCHAR *)sample_thermostat_2_component,
                                                  sizeof(sample_thermostat_2_component) - 1,
                                                  SAMPLE_DEFAULT_START_TEMP_CELSIUS)))
    {
        printf("Failed to initialize %s: error code = 0x%08x\r\n",
               sample_thermostat_2_component, status);
    }

    sample_thermostat_1_last_device_max_temp_reported = 0;
    sample_thermostat_2_last_device_max_tem_reported = 0;
    sample_device_info_sent = 0;
    sample_device_serial_info_sent = 0;

    return(status);
}

VOID sample_entry(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
UINT status;

    nx_azure_iot_log_init(log_callback);

    if ((status = sample_components_init()))
    {
        printf("Failed on initialize sample components!: error code = 0x%08x\r\n", status);
        return;
    }

    /* Create Azure IoT handler.  */
    if ((status = nx_azure_iot_create(&nx_azure_iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr,
                                      nx_azure_iot_thread_stack, sizeof(nx_azure_iot_thread_stack),
                                      NX_AZURE_IOT_THREAD_PRIORITY, unix_time_callback)))
    {
        printf("Failed on nx_azure_iot_create!: error code = 0x%08x\r\n", status);
        return;
    }

    /* Initialize CA certificate.  */
    if ((status = nx_secure_x509_certificate_initialize(&root_ca_cert, (UCHAR *)_nx_azure_iot_root_cert,
                                                        (USHORT)_nx_azure_iot_root_cert_size,
                                                        NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE)))
    {
        printf("Failed to initialize ROOT CA certificate!: error code = 0x%08x\r\n", status);
        nx_azure_iot_delete(&nx_azure_iot);
        return;
    }

    sample_context_init(&sample_context);

    sample_context.state = SAMPLE_STATE_INIT;
    tx_event_flags_set(&(sample_context.sample_events), SAMPLE_INITIALIZATION_EVENT, TX_OR);

    /* Handle event loop.  */
    sample_event_loop(&sample_context);

    nx_azure_iot_delete(&nx_azure_iot);
}
