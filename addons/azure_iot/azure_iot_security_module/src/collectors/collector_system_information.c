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

#include "nx_api.h"
#include "tx_api.h"

#include "asc_security_core/logger.h"
#include "asc_security_core/serializer.h"
#include "asc_security_core/utils/notifier.h"

#include "asc_security_core/collectors/system_information.h"

#undef STR_AUX
#undef STR
#define STR_AUX(x) #x
#define STR(x) STR_AUX(x)
#define OS_NAME "Azure RTOS "
#define OS_INFO OS_NAME STR(THREADX_MAJOR_VERSION) "." STR(THREADX_MINOR_VERSION)

static void _collector_system_information_deinit(collector_internal_t *collector_internal_ptr);
static asc_result_t _collector_system_information_serialize_events(collector_internal_t *collector_internal_ptr, serializer_t *serializer);
static asc_result_t _collect_operation_system_information(collector_internal_t *collector_internal_ptr, system_information_t *data_ptr);

asc_result_t collector_system_information_init(collector_internal_t *collector_internal_ptr)
{
    if (collector_internal_ptr == NULL)
    {
        log_error("Could not initialize collector_system_information, bad argument");
        return ASC_RESULT_BAD_ARGUMENT;
    }
    memset(collector_internal_ptr, 0, sizeof(*collector_internal_ptr));
    collector_internal_ptr->type = COLLECTOR_TYPE_SYSTEM_INFORMATION;
    collector_internal_ptr->priority = COLLECTOR_PRIORITY_LOW;
    collector_internal_ptr->collect_function = _collector_system_information_serialize_events;
    collector_internal_ptr->deinit_function = _collector_system_information_deinit;

    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, collector_internal_ptr);

    return ASC_RESULT_OK;
}

static void _collector_system_information_deinit(collector_internal_t *collector_internal_ptr)
{
    if (collector_internal_ptr == NULL)
    {
        log_error("Could not deinitialize collector_system_information, bad argument");
        return;
    }

    memset(collector_internal_ptr, 0, sizeof(*collector_internal_ptr));
}

static asc_result_t _collector_system_information_serialize_events(collector_internal_t *collector_internal_ptr, serializer_t *serializer)
{
    asc_result_t result = ASC_RESULT_OK;
    system_information_t system_information;
    uint32_t current_time;
    uint32_t collection_interval;
    
    memset(&system_information, 0, sizeof(system_information_t));

    log_debug("Start _collector_system_information_serialize_events");

    result = _collect_operation_system_information(collector_internal_ptr, &system_information);
    if (result != ASC_RESULT_OK)
    {
        log_error("Failed to collect Operation System information, result=[%d]", result);
        goto cleanup;
    }

    current_time = itime_time(NULL);
    collection_interval = g_collector_collections_intervals[collector_internal_ptr->priority];

    result = serializer_event_add_system_information(serializer, current_time, collection_interval, &system_information);

cleanup:
    if (result != ASC_RESULT_OK)
    {
        log_error("failed to collect events");
    }

    log_debug("Done _collector_system_information_serialize_events, result=[%d]", result);
    return result;
}

static asc_result_t _collect_operation_system_information(collector_internal_t *collector_internal_ptr, system_information_t *data_ptr)
{
    log_debug("Start _collect_operation_system_information");
    data_ptr->os_info = OS_INFO;

    log_debug("Done _collect_operation_system_information");

    return ASC_RESULT_OK;
}
