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

#ifndef _EVENT_BE_H_
#define _EVENT_BE_H_

#include "asc_security_core/utils/ievent_loop.h"
#include "asc_security_core/collector_enums.h"

#ifndef EXTRA_BE_TIMERS_OBJECT_POOL_ENTRIES
#define OBJECT_POOL_BE_EVENT_LOOP_TIMERS_COUNT (COLLECTOR_TYPE_COUNT + 1)
#else
#define OBJECT_POOL_BE_EVENT_LOOP_TIMERS_COUNT ((COLLECTOR_TYPE_COUNT + 1) + EXTRA_BE_TIMERS_OBJECT_POOL_ENTRIES)
#endif


/**
 * @brief   Attach specific best effort event loop implementation.
 *
 * @return  @c ievent_loop_t structure represents event loop based on base effort
 */
ievent_loop_t *event_loop_be_instance_attach();

#endif //_EVENT_BE_H_