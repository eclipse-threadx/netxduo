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

#include <stdlib.h>
#include <string.h>

#include "asc_security_core/logger.h"
#include "asc_security_core/collector_collection.h"
#include "asc_security_core/object_pool.h"
#include "asc_security_core/collector_collection_internal.h"
#include "asc_security_core/collector_collection_factory.h"
#include "asc_security_core/collectors_headers.h"

#define COLLECTOR_COLLECTION_OBJECT_POOL_COUNT 1

struct priority_collectors {
    uint32_t interval;
    collector_priority_t priority;
    collector_t *current_collector_ptr;

    linked_list_collector_t collector_list;
};

struct collector_collection {
    COLLECTION_INTERFACE(struct collector_collection);

    priority_collectors_t collector_array[COLLECTOR_PRIORITY_COUNT];
};

OBJECT_POOL_DECLARATIONS(collector_collection_t)
OBJECT_POOL_DEFINITIONS(collector_collection_t, COLLECTOR_COLLECTION_OBJECT_POOL_COUNT)

static asc_result_t _collector_collection_init_collector_lists(collector_collection_t *collector_collection_ptr, collector_init_function_t *collector_init_array, uint32_t array_size);
static void _collector_collection_deinit_collector_lists(linked_list_collector_t_handle collector_list_ptr);
static bool _collector_collection_type_match_function(collector_t *collector_ptr, void *match_context);


collector_collection_t *collector_collection_init()
{
    log_debug("Init collector collection");
    asc_result_t result = ASC_RESULT_OK;
    collector_collection_t *collector_collection_ptr = NULL;
    collector_init_function_t *collector_init_array = NULL;
    uint32_t collector_init_array_size = 0;

    collector_collection_ptr = object_pool_get(collector_collection_t);
    if (collector_collection_ptr == NULL) {
        log_error("Failed to initialized collector collection");
        result = ASC_RESULT_MEMORY_EXCEPTION;
        goto cleanup;
    }

    memset(collector_collection_ptr, 0, sizeof(collector_collection_t));

    result = collector_collection_factory_get_initialization_array(&collector_init_array, &collector_init_array_size);
    if (result != ASC_RESULT_OK) {
        log_error("Collector collection array is not being initialized properly");
        goto cleanup;
    }

    result = _collector_collection_init_collector_lists(collector_collection_ptr, collector_init_array, collector_init_array_size);
    if (result != ASC_RESULT_OK) {
        log_error("Collector collection failed to initialize collector lists, result=[%d]", result);
        goto cleanup;
    }

    result = collector_collection_internal_init_startup_time(collector_collection_ptr);
    if (result != ASC_RESULT_OK) {
        log_error("Collector collection failed to init collectors startup time, result=[%d]", result);
        goto cleanup;
    }


cleanup:
    if (result != ASC_RESULT_OK) {
        log_error("Failed to initialize collector collection, result=[%d]", result);
        collector_collection_ptr = NULL;
    }

    return collector_collection_ptr;
}


void collector_collection_deinit(collector_collection_t *collector_collection_ptr)
{
    if (collector_collection_ptr == NULL) {
        return;
    }

    for (int priority=0; priority < COLLECTOR_PRIORITY_COUNT; priority++) {
        _collector_collection_deinit_collector_lists(&(collector_collection_ptr->collector_array[priority].collector_list));
        collector_collection_ptr->collector_array[priority].current_collector_ptr = NULL;
    }

    object_pool_free(collector_collection_t, collector_collection_ptr);
    collector_collection_ptr = NULL;
}


priority_collectors_t *collector_collection_get_head_priority(collector_collection_t *collector_collection_ptr)
{
    return &(collector_collection_ptr->collector_array[COLLECTOR_PRIORITY_HIGH]);
}


priority_collectors_t *collector_collection_get_next_priority(collector_collection_t *collector_collection_ptr, priority_collectors_t *priority_collectors_ptr)
{
    uint32_t current_priority = (uint32_t)priority_collectors_ptr->priority + 1;
    if (current_priority == COLLECTOR_PRIORITY_COUNT) {
        return NULL;
    }

    return &(collector_collection_ptr->collector_array[current_priority]);
}


priority_collectors_t *collector_collection_get_by_priority(collector_collection_t *collector_collection_ptr, collector_priority_t collector_priority)
{
    if (collector_priority >= COLLECTOR_PRIORITY_COUNT) {
        return NULL;
    }

    return &(collector_collection_ptr->collector_array[collector_priority]);
}


static bool _collector_collection_type_match_function(collector_t *collector_ptr, void *match_context)
{
    return collector_ptr == NULL ? false : collector_ptr->internal.type == *((collector_type_t *)match_context);
}


collector_t *collector_collection_get_collector_by_priority(collector_collection_t *collector_collection_ptr, collector_type_t type)
{
    collector_t *collector_ptr = NULL;
    priority_collectors_t *priority_collector_ptr = collector_collection_get_head_priority(collector_collection_ptr);

    while (priority_collector_ptr != NULL) {
        linked_list_collector_t_handle collector_list = priority_collectors_get_list(priority_collector_ptr);

        collector_ptr = linked_list_collector_t_find(collector_list, _collector_collection_type_match_function, &type);
        if (collector_ptr != NULL) {
            goto cleanup;
        }

        priority_collector_ptr = collector_collection_get_next_priority(collector_collection_ptr, priority_collector_ptr);
    }

cleanup:
    return collector_ptr;
}


void collector_collection_foreach(collector_collection_t *collector_collection_ptr, linked_list_collector_t_action action_function, void *context)
{
    for (priority_collectors_t *prioritized_collectors = collector_collection_get_head_priority(collector_collection_ptr) ; prioritized_collectors != NULL; prioritized_collectors = collector_collection_get_next_priority(collector_collection_ptr, prioritized_collectors)) {
        linked_list_collector_t_foreach(priority_collectors_get_list(prioritized_collectors), action_function, context);
    }
}


uint32_t priority_collectors_get_interval(priority_collectors_t *priority_collectors_ptr)
{
    return priority_collectors_ptr->interval;
}


asc_result_t priority_collectors_set_interval(priority_collectors_t *priority_collectors_ptr, uint32_t interval)
{
    asc_result_t result = ASC_RESULT_OK;

    if (priority_collectors_ptr == NULL)
    {
        result = ASC_RESULT_BAD_ARGUMENT;
    }
    else
    {
        priority_collectors_ptr->interval = interval;
    }

    return result;
}


collector_priority_t priority_collectors_get_priority(priority_collectors_t *priority_collectors_ptr)
{
    return priority_collectors_ptr->priority;
}


linked_list_collector_t_handle priority_collectors_get_list(priority_collectors_t *priority_collectors_ptr)
{
    return &(priority_collectors_ptr->collector_list);
}


asc_result_t _collector_collection_init_collector_lists(collector_collection_t *collector_collection_ptr, collector_init_function_t *collector_init_array, uint32_t collector_init_array_size)
{
    asc_result_t result = ASC_RESULT_OK;

    for (unsigned int priority=0; priority < COLLECTOR_PRIORITY_COUNT; priority++) {
        linked_list_collector_t_init(&(collector_collection_ptr->collector_array[priority].collector_list), NULL);
        collector_collection_ptr->collector_array[priority].interval = g_collector_collections_intervals[priority];
        collector_collection_ptr->collector_array[priority].current_collector_ptr = NULL;
        collector_collection_ptr->collector_array[priority].priority = (collector_priority_t)priority;
    }

    uint32_t collector_count = collector_init_array_size;
    for (unsigned int i=0; i < collector_count; i++){
        collector_t *collector_ptr = collector_init(collector_init_array[i]);

        if (collector_ptr == NULL) {
            result = ASC_RESULT_MEMORY_EXCEPTION;
            goto cleanup;
        }

        collector_priority_t priority = collector_get_priority(collector_ptr);

        linked_list_collector_t_handle current_collector_list_handle = &(collector_collection_ptr->collector_array[priority].collector_list);

        if (linked_list_collector_t_add_last(current_collector_list_handle, collector_ptr) == NULL){
            log_error("Could not append collector type=[%d] to collector list", collector_ptr->internal.type);
            result = ASC_RESULT_EXCEPTION;
            goto cleanup;
        }
        collector_collection_ptr->collector_array[priority].current_collector_ptr = linked_list_collector_t_get_first(current_collector_list_handle);
    }

cleanup:

    return result;
}


collector_t *priority_collectors_get_current_collector(priority_collectors_t *priority_collectors_ptr)
{
    return priority_collectors_ptr->current_collector_ptr;
}


void priority_collectors_set_current_collector(priority_collectors_t *priority_collectors_ptr, collector_t *current_item)
{
    priority_collectors_ptr->current_collector_ptr = current_item;
}


collector_t *priority_collectors_get_next_cyclic_collector(priority_collectors_t *priority_collectors_ptr)
{
    collector_t *current_item = priority_collectors_ptr->current_collector_ptr;

    if (current_item == NULL) {
        return NULL;
    }

    if (current_item->next == NULL) {
        current_item = linked_list_collector_t_get_first(&(priority_collectors_ptr->collector_list));
    } else {
        current_item = current_item->next;
    }

    return current_item;
}


static void _collector_collection_deinit_collector_lists(linked_list_collector_t_handle collector_list_ptr)
{
    collector_t *collector_ptr = linked_list_collector_t_get_first(collector_list_ptr);
    while (collector_ptr != NULL) {
        linked_list_collector_t_remove(collector_list_ptr, collector_ptr);

        if (collector_ptr != NULL) {
            collector_deinit(collector_ptr);
        }

        collector_ptr = linked_list_collector_t_get_first(collector_list_ptr);
    }

}