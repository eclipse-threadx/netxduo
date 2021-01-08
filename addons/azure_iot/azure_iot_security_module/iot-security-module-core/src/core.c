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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "asc_security_core/collector_collection.h"
#include "asc_security_core/configuration.h"
#include "asc_security_core/logger.h"
#include "asc_security_core/collector.h"
#include "asc_security_core/object_pool.h"
#include "asc_security_core/serializer.h"
#include "asc_security_core/utils/itime.h"
#include "asc_security_core/utils/os_utils.h"

#include "asc_security_core/core.h"

#define CORE_OBJECT_POOL_COUNT 1

OBJECT_POOL_DECLARATIONS(core_t)
OBJECT_POOL_DEFINITIONS(core_t, CORE_OBJECT_POOL_COUNT)

core_t *core_init()
{
    asc_result_t result = ASC_RESULT_OK;
    core_t *core_ptr = NULL;

    core_ptr = object_pool_get(core_t);
    if (core_ptr == NULL) {
        log_error("Failed to init core");
        result = ASC_RESULT_MEMORY_EXCEPTION;
        goto cleanup;
    }
    memset(core_ptr, 0, sizeof(core_t));

    core_ptr->security_module_id = os_utils_get_security_module_id();
    if (core_ptr->security_module_id == NULL) {
        log_error("Failed to retrieve security module id");
        result = ASC_RESULT_EXCEPTION;
        goto cleanup;
    }

    core_ptr->security_module_version = SECURITY_MODULE_VERSION;

    core_ptr->collector_collection_ptr = collector_collection_init();
    if (core_ptr->collector_collection_ptr == NULL) {
        log_error("Failed to init core collectors");
        result = ASC_RESULT_MEMORY_EXCEPTION;
        goto cleanup;
    }

    core_ptr->serializer = serializer_init();
    if (core_ptr->serializer == NULL) {
        log_error("Failed to init serializer");
        result = ASC_RESULT_MEMORY_EXCEPTION;
        goto cleanup;
    }

    result = serializer_message_begin(core_ptr->serializer, core_ptr->security_module_id, core_ptr->security_module_version);

#ifdef DYNAMIC_MEMORY_ENABLED
    core_ptr->message_allocated = false;
#endif
    core_ptr->message_empty = true;

cleanup:
    if (result != ASC_RESULT_OK) {
        log_error("Failed to init client core_t");
        core_deinit(core_ptr);
        core_ptr = NULL;
    }

    return core_ptr;
}

void core_deinit(core_t *core_ptr)
{
    if (core_ptr != NULL) {
        if (core_ptr->collector_collection_ptr != NULL) {
            collector_collection_deinit(core_ptr->collector_collection_ptr);
        }

#ifdef DYNAMIC_MEMORY_ENABLED
        if (core_ptr->message_allocated) {
            free(core_ptr->message_buffer);
            core_ptr->message_buffer = NULL;
        }
#endif
        serializer_deinit(core_ptr->serializer);

        core_ptr->security_module_id = NULL;
        core_ptr->collector_collection_ptr = NULL;

        object_pool_free(core_t, core_ptr);
        core_ptr = NULL;
    }
}

asc_result_t core_collect(core_t *core_ptr)
{
    asc_result_t result = ASC_RESULT_OK;
    uint32_t current_snapshot = itime_time(NULL);
    bool at_least_one_success = false;
    bool time_passed = false;

    for (priority_collectors_t *prioritized_collectors = collector_collection_get_head_priority(core_ptr->collector_collection_ptr);
            prioritized_collectors != NULL;
            prioritized_collectors = collector_collection_get_next_priority(core_ptr->collector_collection_ptr, prioritized_collectors)
        ) {
        linked_list_collector_t_handle collector_list = priority_collectors_get_list(prioritized_collectors);

        for (collector_t *current_collector=linked_list_collector_t_get_first(collector_list);
                current_collector!=NULL;
                current_collector=current_collector->next
            ) {
            uint32_t last_collected = collector_get_last_collected_timestamp(current_collector);
            uint32_t interval = priority_collectors_get_interval(prioritized_collectors);

            if (current_snapshot - last_collected >= interval) {
                time_passed = true;
                result = collector_serialize_events(current_collector, core_ptr->serializer);
                if (result == ASC_RESULT_EMPTY) {
                    log_debug("empty, collector type=[%d]", current_collector->internal.type);
                    continue;
                } else if (result != ASC_RESULT_OK) {
                    log_error("failed to collect, collector type=[%d]", current_collector->internal.type);
                    goto error;
                }
                at_least_one_success = true;
                core_ptr->message_empty = false;
            }
        }
    }

    return (!time_passed || at_least_one_success) ? ASC_RESULT_OK : result;

error:
    // In case of serializer failure, it is unsafe to keep building the message
    core_message_deinit(core_ptr);

    return ASC_RESULT_EXCEPTION;
}


asc_result_t core_message_get(core_t* core_ptr, security_message_t* security_message_ptr) {
    asc_result_t result = ASC_RESULT_OK;

    if (core_ptr == NULL || security_message_ptr == NULL) {
        result = ASC_RESULT_BAD_ARGUMENT;
        log_error("bad argument");
        goto cleanup;
    }

    if (core_ptr->message_empty) {
        result = ASC_RESULT_EMPTY;
        log_debug("message empty");
        goto cleanup;
    }

    if (serializer_get_state(core_ptr->serializer) == SERIALIZER_STATE_MESSAGE_PROCESSING &&
        serializer_message_end(core_ptr->serializer) != ASC_RESULT_OK) {
        result = ASC_RESULT_EXCEPTION;
        log_error("failed to end message");
        goto cleanup;
    }

    if (core_ptr->message_buffer == NULL) {
        result = serializer_buffer_get(core_ptr->serializer, &core_ptr->message_buffer, &core_ptr->message_buffer_size);
        if (result != ASC_RESULT_OK && result != ASC_RESULT_IMPOSSIBLE) {
            log_error("failed in serializer_buffer_get");
            goto cleanup;
        }

        if (result == ASC_RESULT_IMPOSSIBLE) {
#ifndef DYNAMIC_MEMORY_ENABLED
            log_error("failed in serializer_buffer_get, message too big");
            result = ASC_RESULT_EXCEPTION;
            goto cleanup;
#else /* DYNAMIC_MEMORY_ENABLED */
            result = ASC_RESULT_OK;
            log_debug("failed in serializer_buffer_get on first attempt, re-allocating buffer...");
            if (serializer_buffer_get_size(core_ptr->serializer, &core_ptr->message_buffer_size) != ASC_RESULT_OK) {
                result = ASC_RESULT_EXCEPTION;
                log_error("failed in serializer_buffer_get_size");
                goto cleanup;
            }

            core_ptr->message_buffer = (uint8_t*)malloc(core_ptr->message_buffer_size);
            if (core_ptr->message_buffer == NULL) {
                result = ASC_RESULT_MEMORY_EXCEPTION;
                log_error("failed to allocate message buffer");
                goto cleanup;
            }

            core_ptr->message_allocated = true;

            if (serializer_buffer_get_copy(core_ptr->serializer, core_ptr->message_buffer, core_ptr->message_buffer_size) != ASC_RESULT_OK) {
                result = ASC_RESULT_EXCEPTION;
                log_error("failed in serializer_buffer_get_copy");
                goto cleanup;
            }
            log_debug("re-allocating buffer done successfully");
#endif /* DYNAMIC_MEMORY_ENABLED */
        }
    }

    // set security message properties
    security_message_ptr->data = core_ptr->message_buffer;
    security_message_ptr->size = core_ptr->message_buffer_size;

cleanup:
    if (result == ASC_RESULT_EXCEPTION || result == ASC_RESULT_MEMORY_EXCEPTION) {
        core_message_deinit(core_ptr);
    }

    return result;
}

asc_result_t core_message_deinit(core_t *core_ptr)
{
    if (core_ptr == NULL) {
        log_error("bad argument");
        return ASC_RESULT_BAD_ARGUMENT;
    }

#ifdef DYNAMIC_MEMORY_ENABLED
    if (core_ptr->message_allocated) {
        free(core_ptr->message_buffer);
        core_ptr->message_allocated = false;
    }
#endif

    if (serializer_reset(core_ptr->serializer) != ASC_RESULT_OK) {
        log_error("failed in serializer_reset");
        return ASC_RESULT_EXCEPTION;
    }

    if (serializer_message_begin(core_ptr->serializer, core_ptr->security_module_id, core_ptr->security_module_version) != ASC_RESULT_OK) {
        log_error("failed in serializer_message_begin");
        return ASC_RESULT_EXCEPTION;
    }

    core_ptr->message_buffer = NULL;
    core_ptr->message_buffer_size = 0;
    core_ptr->message_empty = true;

    return ASC_RESULT_OK;
}
