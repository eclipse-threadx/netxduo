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

#include <string.h>

#include "asc_security_core/collectors/heartbeat.h"
#include "asc_security_core/logger.h"
#include "asc_security_core/collector_enums.h"
#include "asc_security_core/object_pool.h"
#include "asc_security_core/utils/itime.h"
#include "asc_security_core/utils/notifier.h"

static void _collector_heartbeat_deinit(collector_internal_t *collector_internal_ptr);
static asc_result_t _collector_heartbeat_get_events(collector_internal_t *collector_internal_ptr, serializer_t *serializer);

asc_result_t collector_heartbeat_init(collector_internal_t *collector_internal_ptr)
{
    if (collector_internal_ptr == NULL) {
        log_error("Could not initialize collector_heartbeat, bad argument");
        return ASC_RESULT_BAD_ARGUMENT;
    }

    memset(collector_internal_ptr, 0, sizeof(*collector_internal_ptr));

    collector_internal_ptr->type = COLLECTOR_TYPE_HEARTBEAT;
    collector_internal_ptr->priority = COLLECTOR_PRIORITY_LOW;
    collector_internal_ptr->collect_function = _collector_heartbeat_get_events;
    collector_internal_ptr->deinit_function = _collector_heartbeat_deinit;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, collector_internal_ptr);

    return ASC_RESULT_OK;
}

static void _collector_heartbeat_deinit(collector_internal_t *collector_internal_ptr)
{
    memset(collector_internal_ptr, 0, sizeof(*collector_internal_ptr));
}

static asc_result_t _collector_heartbeat_get_events(collector_internal_t *collector_internal_ptr, serializer_t *serializer)
{
    uint32_t timestamp = itime_time(NULL);
    return serializer_event_add_heartbeat(serializer, timestamp, g_collector_collections_intervals[collector_internal_ptr->priority]);
}
