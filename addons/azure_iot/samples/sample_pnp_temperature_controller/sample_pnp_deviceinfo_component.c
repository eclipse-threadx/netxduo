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

#include "sample_pnp_deviceinfo_component.h"

#include "nx_azure_iot_pnp_helpers.h"

#define DOUBLE_DECIMAL_PLACE_DIGITS                                     (2)

/* Reported property keys and values.  */
static const CHAR sample_pnp_device_info_software_version_property_name[] = "swVersion";
static const CHAR sample_pnp_device_info_software_version_property_value[] = "1.0.0.0";
static const CHAR sample_pnp_device_info_manufacturer_property_name[] = "manufacturer";
static const CHAR sample_pnp_device_info_manufacturer_property_value[] = "Sample-Manufacturer";
static const CHAR sample_pnp_device_info_model_property_name[] = "model";
static const CHAR sample_pnp_device_info_model_property_value[] = "pnp-sample-Model-123";
static const CHAR sample_pnp_device_info_os_name_property_name[] = "osName";
static const CHAR sample_pnp_device_info_os_name_property_value[] = "AzureRTOS";
static const CHAR sample_pnp_device_info_processor_architecture_property_name[] = "processorArchitecture";
static const CHAR sample_pnp_device_info_processor_architecture_property_value[] = "Contoso-Arch-64bit";
static const CHAR sample_pnp_device_info_processor_manufacturer_property_name[] = "processorManufacturer";
static const CHAR sample_pnp_device_info_processor_manufacturer_property_value[] = "Processor Manufacturer(TM)";
static const CHAR sample_pnp_device_info_total_storage_property_name[] = "totalStorage";
static const double sample_pnp_device_info_total_storage_property_value = 1024.0;
static const CHAR sample_pnp_device_info_total_memory_property_name[] = "totalMemory";
static const double sample_pnp_device_info_total_memory_property_value = 128;

static UCHAR scratch_buffer[512];

static UINT append_properties(NX_AZURE_IOT_JSON_WRITER *json_writer, VOID *context)
{
UINT status;

    NX_PARAMETER_NOT_USED(context);

    if (nx_azure_iot_json_writer_append_property_with_string_value(json_writer,
                                                                   (UCHAR *)sample_pnp_device_info_manufacturer_property_name,
                                                                   sizeof(sample_pnp_device_info_manufacturer_property_name) - 1,
                                                                   (UCHAR *)sample_pnp_device_info_manufacturer_property_value,
                                                                   sizeof(sample_pnp_device_info_manufacturer_property_value) - 1) ||
        nx_azure_iot_json_writer_append_property_with_string_value(json_writer,
                                                                   (UCHAR *)sample_pnp_device_info_model_property_name,
                                                                   sizeof(sample_pnp_device_info_model_property_name) - 1,
                                                                   (UCHAR *)sample_pnp_device_info_model_property_value,
                                                                   sizeof(sample_pnp_device_info_model_property_value) - 1) ||
        nx_azure_iot_json_writer_append_property_with_string_value(json_writer,
                                                                   (UCHAR *)sample_pnp_device_info_software_version_property_name,
                                                                   sizeof(sample_pnp_device_info_software_version_property_name) - 1,
                                                                   (UCHAR *)sample_pnp_device_info_software_version_property_value,
                                                                   sizeof(sample_pnp_device_info_software_version_property_value) - 1) ||
        nx_azure_iot_json_writer_append_property_with_string_value(json_writer,
                                                                   (UCHAR *)sample_pnp_device_info_os_name_property_name,
                                                                   sizeof(sample_pnp_device_info_os_name_property_name) - 1,
                                                                   (UCHAR *)sample_pnp_device_info_os_name_property_value,
                                                                   sizeof(sample_pnp_device_info_os_name_property_value) - 1) ||
        nx_azure_iot_json_writer_append_property_with_string_value(json_writer,
                                                                   (UCHAR *)sample_pnp_device_info_processor_architecture_property_name,
                                                                   sizeof(sample_pnp_device_info_processor_architecture_property_name) - 1,
                                                                   (UCHAR *)sample_pnp_device_info_processor_architecture_property_value,
                                                                   sizeof(sample_pnp_device_info_processor_architecture_property_value) - 1) ||
        nx_azure_iot_json_writer_append_property_with_string_value(json_writer,
                                                                   (UCHAR *)sample_pnp_device_info_processor_manufacturer_property_name,
                                                                   sizeof(sample_pnp_device_info_processor_manufacturer_property_name) - 1,
                                                                   (UCHAR *)sample_pnp_device_info_processor_manufacturer_property_value,
                                                                   sizeof(sample_pnp_device_info_processor_manufacturer_property_value) - 1) ||
        nx_azure_iot_json_writer_append_property_with_double_value(json_writer,
                                                                   (UCHAR *)sample_pnp_device_info_total_storage_property_name,
                                                                   sizeof(sample_pnp_device_info_total_storage_property_name) - 1,
                                                                   sample_pnp_device_info_total_storage_property_value,
                                                                   DOUBLE_DECIMAL_PLACE_DIGITS) ||
        nx_azure_iot_json_writer_append_property_with_double_value(json_writer,
                                                                   (UCHAR *)sample_pnp_device_info_total_memory_property_name,
                                                                   sizeof(sample_pnp_device_info_total_memory_property_name) - 1,
                                                                   sample_pnp_device_info_total_memory_property_value, DOUBLE_DECIMAL_PLACE_DIGITS))
    {
        status = NX_NOT_SUCCESSFUL;
    }
    else
    {
        status = NX_AZURE_IOT_SUCCESS;
    }

    return(status);
}

UINT sample_pnp_deviceinfo_report_all_properties(UCHAR *component_name_ptr, UINT component_name_len,
                                                 NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
UINT reported_properties_length;
UINT status;
UINT response_status;
UINT request_id;
NX_AZURE_IOT_JSON_WRITER json_builder;
ULONG reported_property_version;

    if ((status = nx_azure_iot_json_writer_with_buffer_init(&json_builder,
                                                            scratch_buffer,
                                                            sizeof(scratch_buffer))))
    {
        printf("Failed to initialize json writer\r\n");
        return(NX_NOT_SUCCESSFUL);
    }

    if ((status = nx_azure_iot_pnp_helper_build_reported_property(component_name_ptr, component_name_len,
                                                                  append_properties, NX_NULL,
                                                                  &json_builder)))
    {
        printf("Failed to build reported property!: error code = 0x%08x\r\n", status);
        nx_azure_iot_json_writer_deinit(&json_builder);
        return(status);
    }

    reported_properties_length = nx_azure_iot_json_writer_get_bytes_used(&json_builder);
    if ((status = nx_azure_iot_hub_client_device_twin_reported_properties_send(iothub_client_ptr,
                                                                               scratch_buffer,
                                                                               reported_properties_length,
                                                                               &request_id, &response_status,
                                                                               &reported_property_version,
                                                                               (5 * NX_IP_PERIODIC_RATE))))
    {
        printf("Device twin reported properties failed!: error code = 0x%08x\r\n", status);
        nx_azure_iot_json_writer_deinit(&json_builder);
        return(status);
    }

    nx_azure_iot_json_writer_deinit(&json_builder);

    if ((response_status < 200) || (response_status >= 300))
    {
        printf("device twin report properties failed with code : %d\r\n", response_status);
        return(NX_NOT_SUCCESSFUL);
    }

    return(status);
}
