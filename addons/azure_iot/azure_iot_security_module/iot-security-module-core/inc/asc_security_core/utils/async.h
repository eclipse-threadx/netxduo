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

#ifndef _ASYNC_H_
#define _ASYNC_H_

#include <stdbool.h>

#include "asc_security_core/utils/collection/collection.h"
#include "asc_security_core/utils/ievent_loop.h"

#define ASYNC_ERROR_LEN 50

typedef enum {
    // must be first
    ASYNC_PENDING = 0,
    ASYNC_IN_PROGRESS,
    ASYNC_FAIL
} async_status_t;

/** @brief  A callback function called when asynchronous operation is done */
typedef void (*event_loop_done_cb_t)(void *ctx);

typedef struct async_t{
    COLLECTION_INTERFACE(struct async_t);

    event_loop_timer_cb_t func;
    event_loop_timer_handler timer;
    event_loop_done_cb_t done_callback;
    uint8_t retry;
    async_status_t status;
    char err[ASYNC_ERROR_LEN];

    void *ctx;
} async_t;

#endif /* _ASYNC_H_ */
