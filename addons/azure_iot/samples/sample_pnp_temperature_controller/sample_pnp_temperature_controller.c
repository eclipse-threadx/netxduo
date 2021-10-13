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
#include "nx_azure_iot_hub_client.h"
#include "nx_azure_iot_hub_client_properties.h"
#include "nx_azure_iot_provisioning_client.h"

/* These are sample files, user can build their own certificate and ciphersuites.  */
#include "nx_azure_iot_cert.h"
#include "nx_azure_iot_ciphersuites.h"
#include "sample_config.h"
#include "sample_pnp_deviceinfo_component.h"
#include "sample_pnp_thermostat_component.h"

#ifndef SAMPLE_WAIT_OPTION
#define SAMPLE_WAIT_OPTION                                              (NX_NO_WAIT)
#endif /* SAMPLE_WAIT_OPTION */

/* Sample events.  */
#define SAMPLE_ALL_EVENTS                                               ((ULONG)0xFFFFFFFF)
#define SAMPLE_CONNECTED_EVENT                                          ((ULONG)0x00000001)
#define SAMPLE_DISCONNECT_EVENT                                         ((ULONG)0x00000002)
#define SAMPLE_PERIODIC_EVENT                                           ((ULONG)0x00000004)
#define SAMPLE_TELEMETRY_SEND_EVENT                                     ((ULONG)0x00000008)
#define SAMPLE_COMMAND_RECEIVE_EVENT                                    ((ULONG)0x00000010)
#define SAMPLE_PROPERTIES_RECEIVE_EVENT                                 ((ULONG)0x00000020)
#define SAMPLE_WRITABLE_PROPERTIES_RECEIVE_EVENT                        ((ULONG)0x00000040)
#define SAMPLE_REPORTED_PROPERTIES_SEND_EVENT                           ((ULONG)0x00000080)

#define SAMPLE_DEFAULT_START_TEMP_CELSIUS                               (22)
#define DOUBLE_DECIMAL_PLACE_DIGITS                                     (2)
#define SAMPLE_COMMAND_SUCCESS_STATUS                                   (200)
#define SAMPLE_COMMAND_ERROR_STATUS                                     (500)
#define SAMPLE_COMMAND_NOT_FOUND_STATUS                                 (404)

#define SAMPLE_PNP_MODEL_ID                                             "dtmi:com:example:TemperatureController;1"
#define SAMPLE_PNP_DPS_PAYLOAD                                          "{\"modelId\":\"" SAMPLE_PNP_MODEL_ID "\"}"

/* Generally, IoTHub Client and DPS Client do not run at the same time, user can use union as below to
   share the memory between IoTHub Client and DPS Client.

   NOTE: If user can not make sure sharing memory is safe, IoTHub Client and DPS Client must be defined seperately.  */
typedef union SAMPLE_CLIENT_UNION
{
    NX_AZURE_IOT_HUB_CLIENT                         iothub_client;

#ifdef ENABLE_DPS_SAMPLE
    NX_AZURE_IOT_PROVISIONING_CLIENT                prov_client;
#endif /* ENABLE_DPS_SAMPLE */

} SAMPLE_CLIENT;

static SAMPLE_CLIENT                                client;

#define iothub_client client.iothub_client
#ifdef ENABLE_DPS_SAMPLE
#define prov_client client.prov_client
#endif /* ENABLE_DPS_SAMPLE */

VOID sample_entry(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time));

#ifdef ENABLE_DPS_SAMPLE
static UINT sample_dps_entry(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                             UCHAR **iothub_hostname, UINT *iothub_hostname_length,
                             UCHAR **iothub_device_id, UINT *iothub_device_id_length);
#endif /* ENABLE_DPS_SAMPLE */

/* Define Azure RTOS TLS info.  */
static NX_SECURE_X509_CERT root_ca_cert;
static NX_SECURE_X509_CERT root_ca_cert_2;
static NX_SECURE_X509_CERT root_ca_cert_3;
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

static TX_EVENT_FLAGS_GROUP sample_events;
static TX_TIMER sample_timer;
static volatile UINT sample_connection_status = NX_AZURE_IOT_NOT_INITIALIZED;
static volatile ULONG sample_periodic_counter = 0;

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

/* Include the connection monitor function from sample_azure_iot_embedded_sdk_connect.c.  */
extern VOID sample_connection_monitor(NX_IP *ip_ptr, NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr, UINT connection_status,
                                      UINT (*iothub_init)(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr));

static UINT sample_pnp_temp_controller_reboot_command(NX_AZURE_IOT_JSON_READER *json_reader_ptr,
                                                      NX_AZURE_IOT_JSON_WRITER *out_json_writer_ptr)
{
INT delay;

    NX_PARAMETER_NOT_USED(out_json_writer_ptr);

    if (nx_azure_iot_json_reader_next_token(json_reader_ptr) ||
        nx_azure_iot_json_reader_token_int32_get(json_reader_ptr, (int32_t *)&delay))
    {
        return(NX_NOT_SUCCESSFUL);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT sample_pnp_temp_controller_telemetry_send(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
UINT status;
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_WRITER json_writer;
UINT buffer_length;
INT working_set_value;

    working_set_value = working_set_minimum + (rand() % working_set_random_modulo);

    /* Create a telemetry message packet.  */
    if ((status = nx_azure_iot_hub_client_telemetry_message_create(iothub_client_ptr,
                                                                   &packet_ptr, NX_WAIT_FOREVER)))
    {
        printf("Telemetry message create failed!: error code = 0x%08x\r\n", status);
        return(status);
    }

    /* Build telemetry JSON payload.  */
    if (nx_azure_iot_json_writer_with_buffer_init(&json_writer, scratch_buffer, sizeof(scratch_buffer)))
    {
        printf("Telemetry message failed to build message\r\n");
        nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
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
        nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
        return(NX_NOT_SUCCESSFUL);
    }

    buffer_length = nx_azure_iot_json_writer_get_bytes_used(&json_writer);
    if ((status = nx_azure_iot_hub_client_telemetry_send(iothub_client_ptr, packet_ptr,
                                                         (UCHAR *)scratch_buffer, buffer_length, NX_WAIT_FOREVER)))
    {
        printf("Telemetry message send failed!: error code = 0x%08x\r\n", status);
        nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
        return(status);
    }

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

static UINT sample_pnp_temp_controller_report_serial_number_property(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
UINT status;
UINT response_status = 0;
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_WRITER json_writer;

    if ((status = nx_azure_iot_hub_client_reported_properties_create(iothub_client_ptr,
                                                                     &packet_ptr, NX_WAIT_FOREVER)))
    {
        printf("Failed create reported properties: error code = 0x%08x\r\n", status);
        return(status);
    }

    if ((status = nx_azure_iot_json_writer_init(&json_writer, packet_ptr, NX_WAIT_FOREVER)))
    {
        printf("Failed init json writer: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return(status);
    }

    if ((status = nx_azure_iot_json_writer_append_begin_object(&json_writer)) ||
        (status = nx_azure_iot_json_writer_append_property_with_string_value(&json_writer,
                                                                             (UCHAR *)sample_serial_number_property_name,
                                                                             sizeof(sample_serial_number_property_name) - 1,
                                                                             (UCHAR *)sample_serial_number_property_value,
                                                                             sizeof(sample_serial_number_property_value) - 1)) ||
        (status = nx_azure_iot_json_writer_append_end_object(&json_writer)))
    {
        printf("Failed to build reported property!: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return(status);
    }

    if ((status = nx_azure_iot_hub_client_reported_properties_send(iothub_client_ptr,
                                                                   packet_ptr,
                                                                   NX_NULL, &response_status,
                                                                   NX_NULL,
                                                                   (5 * NX_IP_PERIODIC_RATE))))
    {
        printf("Reported properties send failed!: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return(status);
    }

    if ((response_status < 200) || (response_status >= 300))
    {
        printf("Reported properties send failed with code : %d\r\n", response_status);
        return(NX_NOT_SUCCESSFUL);
    }

    return(status);
}

static VOID connection_status_callback(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, UINT status)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);
    if (status)
    {
        printf("Disconnected from IoTHub!: error code = 0x%08x\r\n", status);
        tx_event_flags_set(&sample_events, SAMPLE_DISCONNECT_EVENT, TX_OR);
    }
    else
    {
        printf("Connected to IoTHub.\r\n");
        tx_event_flags_set(&sample_events, SAMPLE_CONNECTED_EVENT, TX_OR);
    }

    sample_connection_status = status;
}

static VOID message_receive_callback_properties(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *context)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);
    NX_PARAMETER_NOT_USED(context);
    tx_event_flags_set(&sample_events, SAMPLE_PROPERTIES_RECEIVE_EVENT, TX_OR);
}

static VOID message_receive_callback_command(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *context)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);
    NX_PARAMETER_NOT_USED(context);
    tx_event_flags_set(&(sample_events), SAMPLE_COMMAND_RECEIVE_EVENT, TX_OR);
}

static VOID message_receive_callback_writable_properties(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *context)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);
    NX_PARAMETER_NOT_USED(context);
    tx_event_flags_set(&(sample_events), SAMPLE_WRITABLE_PROPERTIES_RECEIVE_EVENT, TX_OR);
}

static VOID sample_connected_action(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;

    /* Request all properties.  */
    if ((status = nx_azure_iot_hub_client_properties_request(hub_client_ptr, NX_WAIT_FOREVER)))
    {
        printf("Properties request failed!: error code = 0x%08x\r\n", status);
    }
    else
    {
        printf("Sent properties request.\r\n");
    }
}

static UINT sample_initialize_iothub(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
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

#ifdef ENABLE_DPS_SAMPLE

    /* Run DPS.  */
    if ((status = sample_dps_entry(&prov_client, &iothub_hostname, &iothub_hostname_length,
                                   &iothub_device_id, &iothub_device_id_length)))
    {
        printf("Failed on sample_dps_entry!: error code = 0x%08x\r\n", status);
        return(status);
    }
#endif /* ENABLE_DPS_SAMPLE */

    printf("IoTHub Host Name: %.*s; Device ID: %.*s.\r\n",
           iothub_hostname_length, iothub_hostname, iothub_device_id_length, iothub_device_id);

    /* Initialize IoTHub client.  */
    if ((status = nx_azure_iot_hub_client_initialize(iothub_client_ptr, &nx_azure_iot,
                                                     iothub_hostname, iothub_hostname_length,
                                                     iothub_device_id, iothub_device_id_length,
                                                     (const UCHAR *)MODULE_ID, sizeof(MODULE_ID) - 1,
                                                     _nx_azure_iot_tls_supported_crypto,
                                                     _nx_azure_iot_tls_supported_crypto_size,
                                                     _nx_azure_iot_tls_ciphersuite_map,
                                                     _nx_azure_iot_tls_ciphersuite_map_size,
                                                     nx_azure_iot_tls_metadata_buffer,
                                                     sizeof(nx_azure_iot_tls_metadata_buffer),
                                                     &root_ca_cert)))
    {
        printf("Failed on nx_azure_iot_hub_client_initialize!: error code = 0x%08x\r\n", status);
        return(status);
    }

    /* Set the model id.  */
    if ((status = nx_azure_iot_hub_client_model_id_set(iothub_client_ptr,
                                                       (const UCHAR *)SAMPLE_PNP_MODEL_ID,
                                                       sizeof(SAMPLE_PNP_MODEL_ID) - 1)))
    {
        printf("Failed on nx_azure_iot_hub_client_model_id_set!: error code = 0x%08x\r\n", status);
    }

    /* Add more CA certificates.  */
    else if ((status = nx_azure_iot_hub_client_trusted_cert_add(iothub_client_ptr, &root_ca_cert_2)))
    {
        printf("Failed on nx_azure_iot_hub_client_trusted_cert_add!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_trusted_cert_add(iothub_client_ptr, &root_ca_cert_3)))
    {
        printf("Failed on nx_azure_iot_hub_client_trusted_cert_add!: error code = 0x%08x\r\n", status);
    }

#if (USE_DEVICE_CERTIFICATE == 1)

    /* Initialize the device certificate.  */
    else if ((status = nx_secure_x509_certificate_initialize(&device_certificate,
                                                             (UCHAR *)sample_device_cert_ptr, (USHORT)sample_device_cert_len,
                                                             NX_NULL, 0,
                                                             (UCHAR *)sample_device_private_key_ptr, (USHORT)sample_device_private_key_len,
                                                             DEVICE_KEY_TYPE)))
    {
        printf("Failed on nx_secure_x509_certificate_initialize!: error code = 0x%08x\r\n", status);
    }

    /* Set device certificate.  */
    else if ((status = nx_azure_iot_hub_client_device_cert_set(iothub_client_ptr, &device_certificate)))
    {
        printf("Failed on nx_azure_iot_hub_client_device_cert_set!: error code = 0x%08x\r\n", status);
    }
#else

    /* Set symmetric key.  */
    else if ((status = nx_azure_iot_hub_client_symmetric_key_set(iothub_client_ptr,
                                                                 (UCHAR *)DEVICE_SYMMETRIC_KEY,
                                                                 sizeof(DEVICE_SYMMETRIC_KEY) - 1)))
    {
        printf("Failed on nx_azure_iot_hub_client_symmetric_key_set! error: 0x%08x\r\n", status);
    }
#endif /* USE_DEVICE_CERTIFICATE */

    /* Enable command and properties features.  */
    else if ((status = nx_azure_iot_hub_client_command_enable(iothub_client_ptr)))
    {
        printf("Failed on nx_azure_iot_hub_client_command_enable!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_properties_enable(iothub_client_ptr)))
    {
        printf("Failed on nx_azure_iot_hub_client_properties_enable!: error code = 0x%08x\r\n", status);
    }

    /* Set connection status callback.  */
    else if ((status = nx_azure_iot_hub_client_connection_status_callback_set(iothub_client_ptr,
                                                                              connection_status_callback)))
    {
        printf("Failed on connection_status_callback!\r\n");
    }
    else if ((status = nx_azure_iot_hub_client_receive_callback_set(iothub_client_ptr,
                                                                    NX_AZURE_IOT_HUB_COMMAND,
                                                                    message_receive_callback_command,
                                                                    NX_NULL)))
    {
        printf("device command callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_receive_callback_set(iothub_client_ptr,
                                                                    NX_AZURE_IOT_HUB_PROPERTIES,
                                                                    message_receive_callback_properties,
                                                                    NX_NULL)))
    {
        printf("device properties callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_receive_callback_set(iothub_client_ptr,
                                                                    NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                    message_receive_callback_writable_properties,
                                                                    NX_NULL)))
    {
        printf("device writable properties callback set!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_hub_client_component_add(iothub_client_ptr,
                                                             (const UCHAR *)sample_thermostat_1_component,
                                                             sizeof(sample_thermostat_1_component) - 1)) ||
             (status = nx_azure_iot_hub_client_component_add(iothub_client_ptr,
                                                             (const UCHAR *)sample_thermostat_2_component,
                                                             sizeof(sample_thermostat_2_component) - 1)) ||
             (status = nx_azure_iot_hub_client_component_add(iothub_client_ptr,
                                                             (const UCHAR *)sample_device_info_component,
                                                             sizeof(sample_device_info_component) - 1)))
    {
        printf("Failed to add component to client!: error code = 0x%08x\r\n", status);
    }

    if (status)
    {
        nx_azure_iot_hub_client_deinitialize(iothub_client_ptr);
    }

    return(status);
}

static VOID sample_command_action(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;
USHORT context_length;
VOID *context_ptr;
USHORT component_name_length;
const UCHAR *component_name_ptr;
USHORT pnp_command_name_length;
const UCHAR *pnp_command_name_ptr;
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_WRITER json_writer;
NX_AZURE_IOT_JSON_READER json_reader;
UINT status_code;
UINT response_length;

    /* Loop to receive command message.  */
    while (1)
    {
        if (sample_connection_status != NX_SUCCESS)
        {
            return;
        }

        if ((status = nx_azure_iot_hub_client_command_message_receive(hub_client_ptr,
                                                                      &component_name_ptr, &component_name_length,
                                                                      &pnp_command_name_ptr, &pnp_command_name_length,
                                                                      &context_ptr, &context_length,
                                                                      &packet_ptr, NX_NO_WAIT)))
        {
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

        if ((status = nx_azure_iot_json_reader_init(&json_reader,
                                                    packet_ptr)))
        {
            printf("Failed to initialize json reader \r\n");
            nx_packet_release(packet_ptr);
            return;
        }

        if ((status = nx_azure_iot_json_writer_with_buffer_init(&json_writer,
                                                                scratch_buffer,
                                                                sizeof(scratch_buffer))))
        {
            printf("Failed to initialize json writer response \r\n");
            nx_packet_release(packet_ptr);
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

        nx_packet_release(packet_ptr);

        if ((status = nx_azure_iot_hub_client_command_message_response(hub_client_ptr, status_code,
                                                                       context_ptr, context_length, scratch_buffer,
                                                                       response_length, NX_WAIT_FOREVER)))
        {
            printf("Command response failed!: error code = 0x%08x\r\n", status);
        }
    }
}

static VOID sample_writable_properties_parse(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                             NX_AZURE_IOT_JSON_READER *json_reader_ptr,
                                             UINT message_type, ULONG version)
{
const UCHAR *component_ptr = NX_NULL;
USHORT component_len = 0;

    while (nx_azure_iot_hub_client_properties_component_property_next_get(iothub_client_ptr,
                                                                          json_reader_ptr,
                                                                          message_type,
                                                                          NX_AZURE_IOT_HUB_CLIENT_PROPERTY_WRITABLE,
                                                                          &component_ptr, &component_len) == NX_AZURE_IOT_SUCCESS)
    {
        if (sample_pnp_thermostat_process_property_update(&sample_thermostat_1,
                                                          iothub_client_ptr,
                                                          component_ptr, component_len,
                                                          json_reader_ptr, version) == NX_AZURE_IOT_SUCCESS)
        {
            printf("property updated of thermostat 1\r\n");
        }
        else if (sample_pnp_thermostat_process_property_update(&sample_thermostat_2,
                                                               iothub_client_ptr,
                                                               component_ptr, component_len,
                                                               json_reader_ptr, version) == NX_AZURE_IOT_SUCCESS)
        {
            printf("property updated of thermostat 2\r\n");
        }
        else
        {

            /* The JSON reader must be advanced regardless of whether the property
               is of interest or not.  */
            nx_azure_iot_json_reader_next_token(json_reader_ptr);
 
            /* Skip children in case the property value is an object.  */
            if (nx_azure_iot_json_reader_token_type(json_reader_ptr) == NX_AZURE_IOT_READER_TOKEN_BEGIN_OBJECT)
            {
                nx_azure_iot_json_reader_skip_children(json_reader_ptr);
            }
            nx_azure_iot_json_reader_next_token(json_reader_ptr);
        }
    }
}

static void sample_writable_properties_receive_action(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{

UINT status = 0;
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER json_reader;
ULONG writable_properties_version;

    if (sample_connection_status != NX_SUCCESS)
    {
        return;
    }

    if ((status = nx_azure_iot_hub_client_writable_properties_receive(hub_client_ptr,
                                                                      &packet_ptr,
                                                                      NX_WAIT_FOREVER)))
    {
        printf("writable properties receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf("Received writable property");
    printf("\r\n");
    
    if ((status = nx_azure_iot_json_reader_init(&json_reader, packet_ptr)))
    {
        printf("Init json reader failed!: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return;
    }

    /* Get the version.  */
    if ((status = nx_azure_iot_hub_client_properties_version_get(hub_client_ptr, &json_reader, 
                                                                 NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                                                 &writable_properties_version)))
    {
        printf("Properties version get failed!: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return;
    }

    if ((status = nx_azure_iot_json_reader_init(&json_reader, packet_ptr)))
    {
        printf("Init json reader failed!: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return;
    }

    sample_writable_properties_parse(hub_client_ptr, &json_reader,
                                    NX_AZURE_IOT_HUB_WRITABLE_PROPERTIES,
                                    writable_properties_version);

    nx_packet_release(packet_ptr);
}

static void sample_reported_properties_send_action(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;

    if (sample_connection_status != NX_SUCCESS)
    {
        return;
    }

    /* Only report once.  */
    if (sample_device_serial_info_sent == 0)
    {
        if ((status = sample_pnp_temp_controller_report_serial_number_property(hub_client_ptr)))
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
                                                                  hub_client_ptr)))
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
                                                                                       hub_client_ptr)))
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
                                                                                       hub_client_ptr)))
        {
            printf("Failed sample_pnp_thermostat_report_max_temp_since_last_reboot_property: error code = 0x%08x\r\n", status);
        }
        else
        {
            sample_thermostat_2_last_device_max_tem_reported = sample_thermostat_2.maxTemperature;
        }
    }
}

static void sample_properties_receive_action(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status = 0;
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_READER json_reader;
ULONG writable_properties_version;

    if (sample_connection_status != NX_SUCCESS)
    {
        return;
    }

    if ((status = nx_azure_iot_hub_client_properties_receive(hub_client_ptr,
                                                             &packet_ptr,
                                                             NX_WAIT_FOREVER)))
    {
        printf("Get all properties receive failed!: error code = 0x%08x\r\n", status);
        return;
    }

    printf("Received all properties");
    printf("\r\n");

    if ((status = nx_azure_iot_json_reader_init(&json_reader, packet_ptr)))
    {
        printf("Init json reader failed!: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return;
    }

    if ((status = nx_azure_iot_hub_client_properties_version_get(hub_client_ptr, &json_reader,
                                                                 NX_AZURE_IOT_HUB_PROPERTIES,
                                                                 &writable_properties_version)))
    {
        printf("Properties version get failed!: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return;
    }

    if ((status = nx_azure_iot_json_reader_init(&json_reader, packet_ptr)))
    {
        printf("Init json reader failed!: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return;
    }

    sample_writable_properties_parse(hub_client_ptr, &json_reader,
                                     NX_AZURE_IOT_HUB_PROPERTIES,
                                     writable_properties_version);

    nx_packet_release(packet_ptr);
}

static void sample_telemetry_action(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;

    if (sample_connection_status != NX_SUCCESS)
    {
        return;
    }

    if ((status = sample_pnp_temp_controller_telemetry_send(hub_client_ptr)) != NX_AZURE_IOT_SUCCESS)
    {
        printf("Failed to send sample_pnp__telemetry_send, error: %d", status);
    }

    if ((status = sample_pnp_thermostat_telemetry_send(&sample_thermostat_1,
                                                       hub_client_ptr)) != NX_AZURE_IOT_SUCCESS)
    {
        printf("Failed to send sample_pnp_thermostat_telemetry_send, error: %d", status);
    }

    if ((status = sample_pnp_thermostat_telemetry_send(&sample_thermostat_2,
                                                       hub_client_ptr)) != NX_AZURE_IOT_SUCCESS)
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

    /* Add more CA certificates.  */
    if ((status = nx_azure_iot_provisioning_client_trusted_cert_add(prov_client_ptr, &root_ca_cert_2)))
    {
        printf("Failed on nx_azure_iot_provisioning_client_trusted_cert_add!: error code = 0x%08x\r\n", status);
    }
    else if ((status = nx_azure_iot_provisioning_client_trusted_cert_add(prov_client_ptr, &root_ca_cert_3)))
    {
        printf("Failed on nx_azure_iot_provisioning_client_trusted_cert_add!: error code = 0x%08x\r\n", status);
    }

#if (USE_DEVICE_CERTIFICATE == 1)

    /* Initialize the device certificate.  */
    else if ((status = nx_secure_x509_certificate_initialize(&device_certificate, (UCHAR *)sample_device_cert_ptr, (USHORT)sample_device_cert_len, NX_NULL, 0,
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
    else if ((status = nx_azure_iot_provisioning_client_symmetric_key_set(prov_client_ptr, (UCHAR *)DEVICE_SYMMETRIC_KEY,
                                                                          sizeof(DEVICE_SYMMETRIC_KEY) - 1)))
    {
        printf("Failed on nx_azure_iot_hub_client_symmetric_key_set!: error code = 0x%08x\r\n", status);
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

static VOID sample_periodic_timer_entry(ULONG context)
{

    NX_PARAMETER_NOT_USED(context);
    tx_event_flags_set(&(sample_events), SAMPLE_PERIODIC_EVENT, TX_OR);
}

static VOID sample_periodic_action(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    NX_PARAMETER_NOT_USED(hub_client_ptr);
    
    if ((sample_periodic_counter % 5) == 0)
    {

        /* Set telemetry send event and reported properties send event.  */
        tx_event_flags_set(&(sample_events), (SAMPLE_TELEMETRY_SEND_EVENT | SAMPLE_REPORTED_PROPERTIES_SEND_EVENT), TX_OR);
    }

    sample_periodic_counter++;
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
UINT loop = NX_TRUE;
ULONG app_events;

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

    /* Initialize CA certificates.  */
    if ((status = nx_secure_x509_certificate_initialize(&root_ca_cert, (UCHAR *)_nx_azure_iot_root_cert,
                                                        (USHORT)_nx_azure_iot_root_cert_size,
                                                        NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE)))
    {
        printf("Failed to initialize ROOT CA certificate!: error code = 0x%08x\r\n", status);
        nx_azure_iot_delete(&nx_azure_iot);
        return;
    }

    if ((status = nx_secure_x509_certificate_initialize(&root_ca_cert_2, (UCHAR *)_nx_azure_iot_root_cert_2,
                                                        (USHORT)_nx_azure_iot_root_cert_size_2,
                                                        NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE)))
    {
        printf("Failed to initialize ROOT CA certificate!: error code = 0x%08x\r\n", status);
        nx_azure_iot_delete(&nx_azure_iot);
        return;
    }

    if ((status = nx_secure_x509_certificate_initialize(&root_ca_cert_3, (UCHAR *)_nx_azure_iot_root_cert_3,
                                                        (USHORT)_nx_azure_iot_root_cert_size_3,
                                                        NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE)))
    {
        printf("Failed to initialize ROOT CA certificate!: error code = 0x%08x\r\n", status);
        nx_azure_iot_delete(&nx_azure_iot);
        return;
    }
    
    tx_timer_create(&(sample_timer), (CHAR*)"sample_app_timer", sample_periodic_timer_entry, 0,
                    NX_IP_PERIODIC_RATE, NX_IP_PERIODIC_RATE, TX_AUTO_ACTIVATE);
    tx_event_flags_create(&sample_events, (CHAR*)"sample_app_event");

    while (loop)
    {

        /* Pickup sample event flags.  */
        tx_event_flags_get(&(sample_events), SAMPLE_ALL_EVENTS, TX_OR_CLEAR, &app_events, NX_WAIT_FOREVER);

        if (app_events & SAMPLE_CONNECTED_EVENT)
        {
            sample_connected_action(&iothub_client);
        }

        if (app_events & SAMPLE_PERIODIC_EVENT)
        {
            sample_periodic_action(&iothub_client);
        }

        if (app_events & SAMPLE_TELEMETRY_SEND_EVENT)
        {
            sample_telemetry_action(&iothub_client);
        }

        if (app_events & SAMPLE_COMMAND_RECEIVE_EVENT)
        {
            sample_command_action(&iothub_client);
        }

        if (app_events & SAMPLE_PROPERTIES_RECEIVE_EVENT)
        {
            sample_properties_receive_action(&iothub_client);
        }

        if (app_events & SAMPLE_WRITABLE_PROPERTIES_RECEIVE_EVENT)
        {
            sample_writable_properties_receive_action(&iothub_client);
        }

        if (app_events & SAMPLE_REPORTED_PROPERTIES_SEND_EVENT)
        {
            sample_reported_properties_send_action(&iothub_client);
        }

        /* Connection monitor.  */
        sample_connection_monitor(ip_ptr, &iothub_client, sample_connection_status, sample_initialize_iothub);
    }

    /* Cleanup.  */
    tx_event_flags_delete(&sample_events);
    tx_timer_delete(&sample_timer);
    nx_azure_iot_hub_client_deinitialize(&iothub_client);
    nx_azure_iot_delete(&nx_azure_iot);
}
