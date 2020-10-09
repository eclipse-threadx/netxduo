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

#include "asc_security_core/collector_collection.h"
#include "asc_security_core/collector_collection_internal.h"
#include "asc_security_core/collectors_headers.h"
#include "asc_security_core/logger.h"
#include "asc_security_core/utils/collection/linked_list.h"
#include "asc_security_core/utils/irand.h"
#include "asc_security_core/utils/itime.h"

const char *g_collector_names[COLLECTOR_TYPE_COUNT] = {
#ifdef COLLECTOR_SYSTEM_INFORMATION_ENABLED
    COLLECTOR_NAME_SYSTEM_INFORMATION,
#endif
#ifdef COLLECTOR_NETWORK_ACTIVITY_ENABLED
    COLLECTOR_NAME_NETWORK_ACTIVITY,
#endif
#ifdef COLLECTOR_LISTENING_PORTS_ENABLED
    COLLECTOR_NAME_LISTENING_PORTS,
#endif
#ifdef COLLECTOR_HEARTBEAT_ENABLED
    COLLECTOR_NAME_HEARTBEAT,
#endif
#ifdef COLLECTOR_BASELINE_ENABLED
    COLLECTOR_NAME_BASELINE,
#endif
};

const uint32_t g_collector_collections_intervals[COLLECTOR_PRIORITY_COUNT] = {
    ASC_HIGH_PRIORITY_INTERVAL,
    ASC_MEDIUM_PRIORITY_INTERVAL,
    ASC_LOW_PRIORITY_INTERVAL
};

static asc_result_t collector_collection_internal_set_random_collected_time(priority_collectors_t *priority_collector_ptr);

asc_result_t collector_collection_internal_init_startup_time(collector_collection_t *collector_collection_ptr)
{
    asc_result_t result = ASC_RESULT_OK;

    priority_collectors_t *priority_collector_ptr = collector_collection_get_head_priority(collector_collection_ptr);

    while (priority_collector_ptr != NULL) {
        result = collector_collection_internal_set_random_collected_time(priority_collector_ptr);
        if (result != ASC_RESULT_OK) {
            log_error("Failed to set random collected time to collectors, collector_priority=[%d], result=[%d]", priority_collectors_get_priority(priority_collector_ptr), result);
            goto cleanup;
        }

        priority_collector_ptr = collector_collection_get_next_priority(collector_collection_ptr, priority_collector_ptr);
    }

cleanup:
    if (result != ASC_RESULT_OK) {
        log_error("Failed to init collector collection init startup time, result=[%d]", result);
    }

    return result;
}

static asc_result_t collector_collection_internal_set_random_collected_time(priority_collectors_t *priority_collector_ptr)
{
    linked_list_collector_t_handle priority_collector_list = priority_collectors_get_list(priority_collector_ptr);
    uint32_t collector_interval = priority_collectors_get_interval(priority_collector_ptr);
    collector_t *collector_ptr = linked_list_collector_t_get_first(priority_collector_list);
    uint32_t current_time = itime_time(NULL);
    uint32_t last_collected_timestamp;

#ifdef ASC_FIRST_FORCE_COLLECTION_INTERVAL
    last_collected_timestamp = current_time - collector_interval + ASC_FIRST_FORCE_COLLECTION_INTERVAL;
#else
    collector_priority_t priority = priority_collectors_get_priority(priority_collector_ptr);
    uint32_t interval = (uint32_t)((priority+1) * ASC_FIRST_COLLECTION_INTERVAL);
    uint32_t delta = (uint32_t)(irand_int() % (2 * interval) + interval);
    last_collected_timestamp = current_time - collector_interval + delta;
#endif

    while (collector_ptr != NULL) {
        collector_set_last_collected_timestamp(collector_ptr, last_collected_timestamp);
        collector_ptr = collector_ptr->next;
    }

    return ASC_RESULT_OK;
}