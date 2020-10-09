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

#ifndef COLLECTOR_H
#define COLLECTOR_H

#include <assert.h>
#include <stdbool.h>

#include "asc_security_core/utils/itime.h"
#include "asc_security_core/asc_result.h"
#include "asc_security_core/collector_enums.h"
#include "asc_security_core/object_pool.h"
#include "asc_security_core/serializer.h"
#include "asc_security_core/utils/collection/linked_list.h"

#ifndef EXTRA_COLLECTORS_OBJECT_POOL_COUNT
#define COLLECTOR_OBJECT_POOL_COUNT COLLECTOR_TYPE_COUNT
#else
#define COLLECTOR_OBJECT_POOL_COUNT (COLLECTOR_TYPE_COUNT + EXTRA_COLLECTORS_OBJECT_POOL_COUNT)
#endif

typedef struct collector_internal_t collector_internal_t;

/**
 * @brief Initialize the collector internal
 *
 * @param collector_internal_ptr   A handle to the collector internal to initialize.
 *
 * @return ASC_RESULT_OK on success
 */
typedef asc_result_t (*collector_init_function_t)(collector_internal_t *collector_internal_ptr);

/**
 * @brief Serialize events from the collector
 *
 * @param collector_internal_ptr    A handle to the collector internal.
 * @param serializer                The serializer the collector should use.
 *
 * @return  ASC_RESULT_OK on success
 *          ASC_RESULT_EMPTY when there are no events to serialize. In that case, serializer remains unchanged.
 *          ASC_RESULT_EXCEPTION otherwise
 */
typedef asc_result_t (*collector_serialize_function_t)(collector_internal_t *collector_internal_ptr, serializer_t *serializer);

/**
 * @brief Function which used in order to free a specific collector.
 *
 * @param collector_internal_ptr   A handle to the collector internal to deinitialize.
 */
typedef void (*collector_deinit_function_t)(collector_internal_t *collector_internal_ptr);

struct collector_internal_t {
    collector_type_t type;
    collector_priority_t priority;

    collector_serialize_function_t collect_function;
    collector_deinit_function_t deinit_function;

    void *state;
};

typedef enum {
    COLLECTOR_STATUS_OK,
    COLLECTOR_STATUS_EXCEPTION
} collector_status_t;

/**
 * @struct collector_t
 * @brief collector struct
 *        base class for all collectors
 *
 */
typedef struct collector_t {
    COLLECTION_INTERFACE(struct collector_t);

    /*@{*/
    bool enabled; /**< Indicates if the collector is enabled. */
    collector_status_t status;
    unsigned int failure_count;
    /*@}*/

    /**
    * @name Timestamps
    */
    /*@{*/
    uint32_t last_collected_timestamp;
    uint32_t last_sent_timestamp;
    /*@}*/

    collector_internal_t internal;
} collector_t;

OBJECT_POOL_DECLARATIONS(collector_t)
LINKED_LIST_DECLARATIONS(collector_t)


/**
 * @brief Initialize a Collector
 *
 * @param init_function      The initialization function of the collector internal
 *
 * @return collector ptr
 */
collector_t *collector_init(collector_init_function_t init_function);


/**
 * @brief Deinitialize Collector
 *
 * @param collector_ptr  collector ptr
 */
void collector_deinit(collector_t *collector_ptr);


/**
 * @brief Collector priority getter
 *
 * @param collector_ptr  collector ptr
 *
 * @return Collector priority
 */
collector_priority_t collector_get_priority(collector_t *collector_ptr);


/**
 * @brief Collector last collected timestamp getter
 *
 * @param collector_ptr  collector ptr
 *
 * @return Collector last collected timestamp
 */
uint32_t collector_get_last_collected_timestamp(collector_t *collector_ptr);


/**
 * @brief Collector last collected timestamp setter
 *
 * @param collector_ptr             collector_t*
 * @param last_collected_timestamp  the timestamp
 *
 * @return ASC_RESULT_OK on success, ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t collector_set_last_collected_timestamp(collector_t *collector_ptr, uint32_t last_collected_timestamp);


/**
 * @brief Serialize the events in the collector
 *
 * @param collector_ptr     The collector handle
 * @param serializer        The serializer to use
 *
 * @return  ASC_RESULT_OK on success
 *          ASC_RESULT_EMPTY when there are no events. In that case, serializer will be unchanged.
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t collector_serialize_events(collector_t *collector, serializer_t *serializer);


#endif /* COLLECTOR_H */
