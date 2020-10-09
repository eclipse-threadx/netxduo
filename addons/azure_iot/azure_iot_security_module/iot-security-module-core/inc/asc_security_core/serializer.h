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

#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <stddef.h>
#include <stdint.h>

#include "asc_security_core/configuration.h"
#include "asc_security_core/asc_result.h"
#include "asc_security_core/model/objects/objects.h"

typedef enum {
    SERIALIZER_STATE_UNINITIALIZED      = 0,
    SERIALIZER_STATE_INITIALIZED        = 1,
    SERIALIZER_STATE_MESSAGE_EMPTY      = 2,
    SERIALIZER_STATE_MESSAGE_PROCESSING = 3,
    SERIALIZER_STATE_MESSAGE_READY      = 4,
    SERIALIZER_STATE_EXCEPTION          = 5,
} serializer_state_t;

/**
 * @page serializer
 *
 * The Serializer is implemented as the following state machine.
 * Notes:
 *   -   Calling serializer_reset, at any state (after initialization), will
 *       reset the serializer back to "initialized" state.
 *   -   The serializer_get_buffer function is callable only in "message ready"
 *       state. The resulting buffer is owned by the serializer and will be
 *       INVALID after the next call to serializer_reset or serializer_deinit.
 *
 *                                                Start
 *                                                  +
 *                                                  |
 *                                                  |
 *                                           serializer_init
 *                                                  |
 *                                                  |
 *                                                  v
 *                                          +-------+-------+
 *                                          |               |
 *                                          |               |
 *               +---- serializer_reset --->+ Initialized   +<-- serializer_reset --+
 *               |                          |               |                       |
 *               |                          |               |                       |
 *               |                          +-------+-------+                       |
 *               |                                  |                               |
 *               |                                  |                               |
 *               |                      serializer_message_begin                    |
 *               |                                  |                               |
 *               |                                  |                               |
 *               |                                  v                        +------+------+
 *               |                                 / \                       |             |
 *               |                                +   +-------failure------->+  Exception  |
 *               |                                 \ /                       |             |
 *               |                                  +                        +------+------+
 *               |                                  |                               ^
 *               |                                  |                               |
 *               |                               success                            |
 *               |                                  |                               |
 *               |                                  |                               |
 *               |                                  v                               |
 *               |                          +-------+-------+                       |
 *               |                          |               |                       |
 *               +<-------------------------+    Message    |                       |
 *               |                          |     Empty     |                       |
 *               |                          |               |                       |
 *               |                          +-------+-------+                       |
 *               |                                  |                               |
 *               |                                  |                               |
 *               |                        serializer_event_add_*                    |
 *               |                                  |                               |
 *               |                                  |                               |
 *               |                                  v                               |
 *               |                                 / \                              |
 *               |             +----------------->+   +-----------failure---------->+
 *               |             |                   \ /                              |
 *               |             |                    +                               |
 *               |             |                    |                               |
 *               |             |                    |                               |
 *               |             |                 success                            |
 *               |   serializer_event_add_*         |                               |
 *               |             |                    |                               |
 *               |             |                    v                               |
 *               |             |            +-------+-------+                       |
 *               |             |            |               |                       |
 *               |             +------------+    Message    |                       |
 *               |                          |               |                       |
 *               +<-------------------------+   Processing  |                       |
 *               |                          |               |                       |
 *               |                          +-------+-------+                       |
 *               |                                  |                               |
 *               |                                  |                               |
 *               |                       serializer_message_end                     |
 *               |                                  |                               |
 *               |   +---------------+              |                               |
 *               |   |               |              v                               |
 *               |   |    Message    |             / \                              |
 *               +---+     Ready     +<--success--+   +-----------failure-----------+
 *                   |               |             \ /
 *                   +---------------+              +
 */
typedef struct serializer serializer_t;

/**
 * @brief   Initialize a serializer
 *          On success sets state to: SERIALIZER_STATE_INITIALIZED
 * @return  A new serializer
 */
serializer_t *serializer_init();

/**
 * @brief   Deinitialize a serializer
 *
 * @param serializer    The serializer to deinit
 */
void serializer_deinit(serializer_t *serializer);

/**
 * @brief   Get the serializer current state.
 *
 * @param serializer    The serializer to query
 *
 * @return  The serializer state.
 */
serializer_state_t serializer_get_state(serializer_t *serializer);

/**
 * @brief   Begin a new message.
 *          Callable from states: SERIALIZER_STATE_INITIALIZED
 *          On success sets state to: SERIALIZER_STATE_MESSAGE_EMPTY
 *
 * @param serializer                The serializer
 * @param security_module_id        The security module ID
 * @param security_module_version   The security module version
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer is NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_message_begin(serializer_t *serializer, const char *security_module_id, uint32_t security_module_version);

/**
 * @brief   End current message.
 *          Callable from states: SERIALIZER_STATE_MESSAGE_PROCESSING
 *          On success sets state to: SERIALIZER_STATE_MESSAGE_READY
 *
 * @param serializer    The serializer
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer is NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_message_end(serializer_t *serializer);

#ifdef COLLECTOR_NETWORK_ACTIVITY_ENABLED
/**
 * @brief   Adds a network activity event to current message.
 *          Callable from states:   SERIALIZER_STATE_INITIALIZED, SERIALIZER_STATE_MESSAGE_PROCESSING
 *          On success sets state to: SERIALIZER_STATE_MESSAGE_PROCESSING
 *
 * @param serializer            The serializer
 * @param timestamp             The event timestamp
 * @param collection_interval   The collection interval
 * @param ipv4_payload          A list of IPv4 network activity objects
 * @param ipv6_payload          A list of IPv6 network activity objects
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer is NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_event_add_network_activity(serializer_t *serializer, uint32_t timestamp, uint32_t collection_interval,
                                                   network_activity_ipv4_t *ipv4_payload, network_activity_ipv6_t *ipv6_payload);
#endif


#ifdef COLLECTOR_SYSTEM_INFORMATION_ENABLED
/**
 * @brief   Adds a system information event to current message.
 *          Callable from states:   SERIALIZER_STATE_INITIALIZED, SERIALIZER_STATE_MESSAGE_PROCESSING
 *          On success sets state to: SERIALIZER_STATE_MESSAGE_PROCESSING
 *
 * @param serializer            The serializer
 * @param timestamp             The event timestamp
 * @param collection_interval   The collection interval
 * @param payload               The system information payload object
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer is NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_event_add_system_information(serializer_t *serializer, uint32_t timestamp, uint32_t collection_interval,
                                                     system_information_t *payload);
#endif


#ifdef COLLECTOR_HEARTBEAT_ENABLED
/**
 * @brief   Adds a heartbeat event to current message.
 *          Callable from states:   SERIALIZER_STATE_MESSAGE_READY
 *
 * @param serializer            The serializer
 * @param timestamp             The event timestamp
 * @param collection_interval   The collection interval
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer is NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_event_add_heartbeat(serializer_t *serializer, uint32_t timestamp, uint32_t collection_interval);
#endif


#ifdef COLLECTOR_LISTENING_PORTS_ENABLED
/**
 * @brief   Adds a listening ports event to current message.
 *          Callable from states:   SERIALIZER_STATE_INITIALIZED, SERIALIZER_STATE_MESSAGE_PROCESSING
 *          On success sets state to: SERIALIZER_STATE_MESSAGE_PROCESSING
 *
 * @param serializer            The serializer
 * @param timestamp             The event timestamp
 * @param collection_interval   The collection interval
 * @param ipv4_payload          A list of IPv4 listening ports objects
 * @param ipv6_payload          A list of IPv6 listening ports objects
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer is NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_event_add_listening_ports(serializer_t *serializer, uint32_t timestamp, uint32_t collection_interval,
                                                  listening_ports_ipv4_t *ipv4_payload, listening_ports_ipv6_t *ipv6_payload);
#endif

#ifdef COLLECTOR_BASELINE_ENABLED
/**
 * @brief   Adds a Baseline event to current message.
 *          Callable from states:   SERIALIZER_STATE_INITIALIZED, SERIALIZER_STATE_MESSAGE_PROCESSING
 *          On success sets state to: SERIALIZER_STATE_MESSAGE_PROCESSING
 *
 * @param serializer            The serializer
 * @param timestamp             The event timestamp
 * @param collection_interval   The collection interval
 * @param report_list_iter      The baseline report list iterator
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer is NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_event_add_baseline(serializer_t *serializer, uint32_t timestamp, uint32_t collection_interval, linked_list_iterator_baseline_report_t *report_list_iter);
#endif

/**
 * @brief   Retrieve the finished message buffer from the serializer.
 *          Callable from states:   SERIALIZER_STATE_MESSAGE_READY
 * @warning The buffer resides in internal state, and will be invalidated upon serializer state changes (e.g. @b serializer_reset ).
 *
 * @param serializer    The serializer
 * @param buffer        Out param. The buffer pointer.
 * @param size          Out param. The buffer size.
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer and/or @a buffer and/or @a size are NULL
 *          AS_RESULT_IMPOSSIBLE if the buffer is too big to retrieve without copying, requiring a call to @b serializer_buffer_get_copy
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_buffer_get(serializer_t *serializer, uint8_t **buffer, size_t *size);


/**
 * @brief   Get the size of the finished buffer.
 *          Callable from states:   SERIALIZER_STATE_MESSAGE_READY
 *
 * @param serializer    The serializer
 * @param size          Out param. The buffer size
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer and/or @a size are NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_buffer_get_size(serializer_t *serializer, size_t *size);


/**
 * @brief   Copy the finished message buffer from the serializer to the supplied target buffer.
 *          Callable from states:   SERIALIZER_STATE_MESSAGE_READY
 *
 * @param serializer    The serializer
 * @param buffer        The target buffer
 * @param size          The target buffer's size
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer and/or @a buffer are NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_buffer_get_copy(serializer_t *serializer, uint8_t *buffer, size_t size);


/**
 * @brief   Resets the serializer state.
 *          Callable from states:   All except SERIALIZER_STATE_UNINITIALIZED
 *          On success sets state to: SERIALIZER_STATE_INITIALIZED
 *
 * @param serializer    The serializer
 *
 * @return  ASC_RESULT_OK on success,
 *          ASC_RESULT_BAD_ARGUMENT if @a serializer is NULL
 *          ASC_RESULT_EXCEPTION otherwise
 */
asc_result_t serializer_reset(serializer_t *serializer);


#endif /* SERIALIZER_H */
