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

#include "sample_pnp_thermostat_component.h"

#define SAMPLE_DEAFULT_START_TEMP_CELSIUS                               (22)
#define DOUBLE_DECIMAL_PLACE_DIGITS                                     (2)
#define SAMPLE_COMMAND_SUCCESS_STATUS                                   (200)
#define SAMPLE_COMMAND_ERROR_STATUS                                     (500)

/* Telemetry key */
static const CHAR telemetry_name[] = "temperature";

/* Pnp command supported */
static const CHAR get_max_min_report[] = "getMaxMinReport";

/* Names of properties for writable/reporting */
static const CHAR reported_max_temp_since_last_reboot[] = "maxTempSinceLastReboot";
static const CHAR report_max_temp_name[] = "maxTemp";
static const CHAR report_min_temp_name[] = "minTemp";
static const CHAR report_avg_temp_name[] = "avgTemp";
static const CHAR report_start_time_name[] = "startTime";
static const CHAR report_end_time_name[] = "endTime";
static const CHAR target_temp_property_name[] = "targetTemperature";
static const CHAR temp_response_description_success[] = "success";
static const CHAR temp_response_description_failed[] = "failed";

/* Fake device data */
static const CHAR fake_start_report_time[] = "2020-01-10T10:00:00Z";
static const CHAR fake_end_report_time[] = "2023-01-10T10:00:00Z";

static UCHAR scratch_buffer[256];

/* sample direct method implementation */
static UINT sample_get_maxmin_report(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                     NX_AZURE_IOT_JSON_READER *json_reader_ptr,
                                     NX_AZURE_IOT_JSON_WRITER *out_json_writer_ptr)
{
UINT status;
UCHAR *start_time = (UCHAR *)fake_start_report_time;
UINT start_time_len = sizeof(fake_start_report_time) - 1;
UCHAR time_buf[32];

    /* Check for start time if present  */
    if ((status = nx_azure_iot_json_reader_next_token(json_reader_ptr)) == NX_AZURE_IOT_SUCCESS)
    {
        if (nx_azure_iot_json_reader_token_string_get(json_reader_ptr, time_buf,
                                                      sizeof(time_buf), &start_time_len))
        {
            return(NX_NOT_SUCCESSFUL);
        }

        start_time = time_buf;
    }
    else
    {
        if (status != NX_AZURE_IOT_EMPTY_JSON)
        {
            return(NX_NOT_SUCCESSFUL);
        }
    }

    /* Build the method response payload */
    if (nx_azure_iot_json_writer_append_begin_object(out_json_writer_ptr) ||
        nx_azure_iot_json_writer_append_property_with_double_value(out_json_writer_ptr,
                                                                   (UCHAR *)report_max_temp_name,
                                                                   sizeof(report_max_temp_name) - 1,
                                                                   handle -> maxTemperature,
                                                                   DOUBLE_DECIMAL_PLACE_DIGITS) ||
        nx_azure_iot_json_writer_append_property_with_double_value(out_json_writer_ptr,
                                                                   (UCHAR *)report_min_temp_name,
                                                                   sizeof(report_min_temp_name) - 1,
                                                                   handle -> minTemperature,
                                                                   DOUBLE_DECIMAL_PLACE_DIGITS) ||
        nx_azure_iot_json_writer_append_property_with_double_value(out_json_writer_ptr,
                                                                   (UCHAR *)report_avg_temp_name,
                                                                   sizeof(report_avg_temp_name) - 1,
                                                                   handle -> avgTemperature,
                                                                   DOUBLE_DECIMAL_PLACE_DIGITS) ||
        nx_azure_iot_json_writer_append_property_with_string_value(out_json_writer_ptr,
                                                                   (UCHAR *)report_start_time_name,
                                                                   sizeof(report_start_time_name) - 1,
                                                                   (UCHAR *)start_time, start_time_len) ||
        nx_azure_iot_json_writer_append_property_with_string_value(out_json_writer_ptr,
                                                                   (UCHAR *)report_end_time_name,
                                                                   sizeof(report_end_time_name) - 1,
                                                                   (UCHAR *)fake_end_report_time,
                                                                   sizeof(fake_end_report_time) - 1) ||
        nx_azure_iot_json_writer_append_end_object(out_json_writer_ptr))
    {
        status = NX_NOT_SUCCESSFUL;
    }
    else
    {
        status = NX_AZURE_IOT_SUCCESS;
    }

    return(status);
}

static VOID sample_send_target_temperature_report(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                                  NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr, double temp,
                                                  UINT status_code, ULONG version, const CHAR *description)
{
UINT response_status;
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_WRITER json_writer;

    if (nx_azure_iot_hub_client_reported_properties_create(iothub_client_ptr,
                                                           &packet_ptr, NX_WAIT_FOREVER))
    {
        printf("Failed to build reported response\r\n");
        return;
    }

    if (nx_azure_iot_json_writer_init(&json_writer, packet_ptr, NX_WAIT_FOREVER))
    {
        printf("Failed init json writer\r\n");
        nx_packet_release(packet_ptr);
        return;
    }

    if (nx_azure_iot_json_writer_append_begin_object(&json_writer) ||
        nx_azure_iot_hub_client_reported_properties_component_begin(iothub_client_ptr, &json_writer,
                                                                    handle ->component_name_ptr,
                                                                    handle -> component_name_length) ||
        nx_azure_iot_hub_client_reported_properties_status_begin(iothub_client_ptr,
                                                                 &json_writer, (UCHAR *)target_temp_property_name,
                                                                 sizeof(target_temp_property_name) - 1,
                                                                 status_code, version,
                                                                 (const UCHAR *)description, strlen(description)) ||
        nx_azure_iot_json_writer_append_double(&json_writer,
                                               temp, DOUBLE_DECIMAL_PLACE_DIGITS) ||
        nx_azure_iot_hub_client_reported_properties_status_end(iothub_client_ptr, &json_writer) ||
        nx_azure_iot_hub_client_reported_properties_component_end(iothub_client_ptr, &json_writer) ||
        nx_azure_iot_json_writer_append_end_object(&json_writer))
    {
        printf("Failed to build reported response\r\n");
        nx_packet_release(packet_ptr);
    }
    else
    {
        if (nx_azure_iot_hub_client_reported_properties_send(iothub_client_ptr,
                                                             packet_ptr, NX_NULL,
                                                             &response_status, NX_NULL,
                                                             (5 * NX_IP_PERIODIC_RATE)))
        {
            printf("Failed to send reported response\r\n");
            nx_packet_release(packet_ptr);
        }
    }
}

UINT sample_pnp_thermostat_init(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                UCHAR *component_name_ptr, USHORT component_name_length,
                                double default_temp)
{
    if (handle == NX_NULL)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    handle -> component_name_ptr = component_name_ptr;
    handle -> component_name_length = component_name_length;
    handle -> currentTemperature = default_temp;
    handle -> minTemperature = default_temp;
    handle -> maxTemperature = default_temp;
    handle -> allTemperatures = default_temp;
    handle -> numTemperatureUpdates = 1;
    handle -> avgTemperature = default_temp;

    return(NX_AZURE_IOT_SUCCESS);
}

UINT sample_pnp_thermostat_process_command(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                           const UCHAR *component_name_ptr, USHORT component_name_length,
                                           const UCHAR *pnp_command_name_ptr, USHORT pnp_command_name_length,
                                           NX_AZURE_IOT_JSON_READER *json_reader_ptr,
                                           NX_AZURE_IOT_JSON_WRITER *json_response_ptr, UINT *status_code)
{
UINT dm_status;

    if (handle == NX_NULL)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (handle -> component_name_length != component_name_length ||
        strncmp((CHAR *)handle -> component_name_ptr, (CHAR *)component_name_ptr, component_name_length) != 0)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (pnp_command_name_length != (sizeof(get_max_min_report) - 1) ||
        strncmp((CHAR *)pnp_command_name_ptr, (CHAR *)get_max_min_report, pnp_command_name_length) != 0)
    {
        printf("PnP command=%.*s is not supported on thermostat component\r\n", pnp_command_name_length, pnp_command_name_ptr);
        dm_status = 404;
    }
    else
    {
        if (sample_get_maxmin_report(handle, json_reader_ptr, json_response_ptr))
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

UINT sample_pnp_thermostat_telemetry_send(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                          NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
UINT status;
NX_PACKET *packet_ptr;
NX_AZURE_IOT_JSON_WRITER json_writer;
UINT buffer_length;

    if (handle == NX_NULL)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    /* Create a telemetry message packet. */
    if ((status = nx_azure_iot_hub_client_telemetry_message_create(iothub_client_ptr,
                                                                   &packet_ptr, NX_WAIT_FOREVER)))
    {
        printf("Telemetry message create failed!: error code = 0x%08x\r\n", status);
        return(status);
    }

    /* Add component name.  */
    if ((status = nx_azure_iot_hub_client_telemetry_component_set(packet_ptr, 
                                                                  handle -> component_name_ptr,
                                                                  (USHORT)handle -> component_name_length,
                                                                  NX_WAIT_FOREVER)))
    {
        printf("Telemetry message failed to set component\r\n");
        nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
        return(NX_NOT_SUCCESSFUL);
    }

    /* Build telemetry JSON payload */
    if (nx_azure_iot_json_writer_with_buffer_init(&json_writer, scratch_buffer, sizeof(scratch_buffer)))
    {
        printf("Telemetry message failed to build message\r\n");
        nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
        return(NX_NOT_SUCCESSFUL);
    }

    if(nx_azure_iot_json_writer_append_begin_object(&json_writer) ||
       nx_azure_iot_json_writer_append_property_with_double_value(&json_writer,
                                                                  (UCHAR *)telemetry_name,
                                                                  sizeof(telemetry_name) - 1,
                                                                  handle -> currentTemperature,
                                                                  DOUBLE_DECIMAL_PLACE_DIGITS) ||
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

    printf("Thermostat %.*s Telemetry message send: %.*s.\r\n", handle -> component_name_length,
           handle -> component_name_ptr, buffer_length, scratch_buffer);

    return(status);
}

UINT sample_pnp_thermostat_report_max_temp_since_last_reboot_property(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                                                      NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
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
        (status = nx_azure_iot_hub_client_reported_properties_component_begin(iothub_client_ptr,
                                                                              &json_writer,
                                                                              handle -> component_name_ptr,
                                                                              handle -> component_name_length)) ||
        (status = nx_azure_iot_json_writer_append_property_with_double_value(&json_writer,
                                                                             (const UCHAR *)reported_max_temp_since_last_reboot,
                                                                             sizeof(reported_max_temp_since_last_reboot) - 1,
                                                                             handle -> maxTemperature,
                                                                             DOUBLE_DECIMAL_PLACE_DIGITS)) ||
        (status = nx_azure_iot_hub_client_reported_properties_component_end(iothub_client_ptr,
                                                                            &json_writer)) ||
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
        printf("Device twin reported properties failed!: error code = 0x%08x\r\n", status);
        nx_packet_release(packet_ptr);
        return(status);
    }

    if ((response_status < 200) || (response_status >= 300))
    {
        printf("device twin report properties failed with code : %d\r\n", response_status);
        return(NX_NOT_SUCCESSFUL);
    }

    return(status);
}

UINT sample_pnp_thermostat_process_property_update(SAMPLE_PNP_THERMOSTAT_COMPONENT *handle,
                                                   NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                                   const UCHAR *component_name_ptr, USHORT component_name_length,
                                                   NX_AZURE_IOT_JSON_READER *name_value_reader_ptr, UINT version)
{
double parsed_value = 0;
UINT status_code;
const CHAR *description;

    if (handle == NX_NULL)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (handle -> component_name_length != component_name_length ||
        strncmp((CHAR *)handle -> component_name_ptr, (CHAR *)component_name_ptr, component_name_length) != 0)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (nx_azure_iot_json_reader_token_is_text_equal(name_value_reader_ptr,
                                                     (UCHAR *)target_temp_property_name,
                                                     sizeof(target_temp_property_name) - 1) == NX_FALSE)
    {
        printf("Unknown property for component %.*s received\r\n", component_name_length, component_name_ptr);
        status_code = 404;
        description = temp_response_description_failed;
    }
    else if (nx_azure_iot_json_reader_next_token(name_value_reader_ptr) ||
             nx_azure_iot_json_reader_token_double_get(name_value_reader_ptr, &parsed_value))
    {
        status_code = 401;
        description = temp_response_description_failed;
    }
    else
    {
        status_code = 200;
        description = temp_response_description_success;

        handle -> currentTemperature = parsed_value;
        if (handle -> currentTemperature > handle -> maxTemperature)
        {
            handle -> maxTemperature = handle -> currentTemperature;
        }

        if (handle -> currentTemperature < handle -> minTemperature)
        {
            handle -> minTemperature = handle -> currentTemperature;
        }

        /* Increment the avg count, add the new temp to the total, and calculate the new avg */
        handle -> numTemperatureUpdates++;
        handle -> allTemperatures += handle -> currentTemperature;
        handle -> avgTemperature = handle -> allTemperatures / handle -> numTemperatureUpdates;
    }

    sample_send_target_temperature_report(handle, iothub_client_ptr, parsed_value,
                                          status_code, version, description);
    
    nx_azure_iot_json_reader_next_token(name_value_reader_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}
