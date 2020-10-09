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

#ifndef CORE_H
#define CORE_H

#include "asc_security_core/asc_result.h"
#include "asc_security_core/collector_collection.h"
#include "asc_security_core/model/security_message.h"



/**
 * @struct core_t
 *
 */
typedef struct core {
    COLLECTION_INTERFACE(struct core);

    const char *security_module_id;
    uint32_t security_module_version;
    collector_collection_t *collector_collection_ptr;

    uint8_t *message_buffer;
    size_t message_buffer_size;
#ifdef DYNAMIC_MEMORY_ENABLED
    bool message_allocated;
#endif
    bool message_empty;

    serializer_t *serializer;
} core_t;


/**
 * @brief Initialize a new core
 *
 * @return A new core
 */
core_t *core_init();

/**
 * @brief Deinitialize a core
 *
 * @param core_ptr The core to deinit
 */
void core_deinit(core_t *core_ptr);

/**
 * @brief Collect events from all of the registered collectors.
 *
 * @param core_ptr the core ptr
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_EMPTY when there are no events to send,
 *          ASC_RESULT_EXCEPTION otherwise.
 */
asc_result_t core_collect(core_t *core_ptr);

/**
 * @brief Get a security message from the core.
 *
 * @param core_ptr              The core ptr
 * @param security_message_ptr  The message buffer to write into
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_EMPTY when there are no events to send, in that case message_ptr remains unchanged,
 *          ASC_RESULT_EXCEPTION otherwise.
 */
asc_result_t core_message_get(core_t* core_ptr, security_message_t* security_message_ptr);


/**
 * @brief Deinit the last security message.
 *
 * @param core_ptr          the core ptr
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_EXCEPTION otherwise.
 */
asc_result_t core_message_deinit(core_t *core_ptr);

#endif /* CORE_H */