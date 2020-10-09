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
#include <string.h>

#include "asc_security_core/logger.h"
#include "asc_security_core/object_pool.h"
#include "asc_security_core/collectors_info.h"
#include "asc_security_core/collector_enums.h"
#include "asc_security_core/collector.h"
#include "asc_security_core/utils/containerof.h"
#include "asc_security_core/utils/notifier.h"

typedef struct notifier_container_t {
    COLLECTION_INTERFACE(struct notifier_container_t);

    notifier_t notifier;
    collector_info_t info[COLLECTORS_INFO_SIZE];
} notifier_container_t;

OBJECT_POOL_DECLARATIONS(notifier_container_t)
OBJECT_POOL_DEFINITIONS(notifier_container_t, 1)

static void _collector_info_cb(notifier_t *notifier, int message_num, void *payload)
{
    notifier_container_t *container = containerof(notifier, notifier_container_t, notifier);
    collector_info_t *info = container->info;
    collector_internal_t *collector_internal_ptr = payload;

    if (collector_internal_ptr == NULL) {
        log_error("Wrong (NULL) data was recieved");
        return;
    }

    if (collector_internal_ptr->type >= COLLECTORS_INFO_SIZE ||
        collector_internal_ptr->priority >= COLLECTOR_PRIORITY_COUNT) {
        log_error("Wrong collector type=[%d] or priority=[%d]", collector_internal_ptr->type, collector_internal_ptr->priority);
    } else {
        info[collector_internal_ptr->type].interval = g_collector_collections_intervals[collector_internal_ptr->priority];
        log_debug("Updated configuration for collector=[%s] with interval=[%u]\n",
            g_collector_names[collector_internal_ptr->type],
            info[collector_internal_ptr->type].interval);
    }
}

collectors_info_t *collectors_info_init()
{
    notifier_container_t *container = object_pool_get(notifier_container_t);

    if (container == NULL) {
        log_error("Failed to allocate notifier container object");
        return 0;
    }
    memset(container, 0, sizeof(notifier_container_t));
    container->notifier.notify = _collector_info_cb;
    notifier_subscribe(NOTIFY_TOPIC_SYSTEM, &container->notifier);
    return (collectors_info_t *)container;
}

void collectors_info_deinit(collectors_info_t *collectors_info)
{
    notifier_container_t *container = (notifier_container_t *)collectors_info;

    if (container == NULL) {
        log_error("collectors_info_t *is NULL");
        return;
    }
    notifier_unsubscribe(NOTIFY_TOPIC_SYSTEM, &container->notifier);
    object_pool_free(notifier_container_t, container);
}

collector_info_t *collectors_info_get(collectors_info_t *collectors_info, uint32_t *size)
{
    notifier_container_t *container = (notifier_container_t *)collectors_info;

    if (container == NULL) {
        log_error("collectors_info_t *is NULL");
        return NULL;
    }
    *size = COLLECTORS_INFO_SIZE;
    return container->info;
}