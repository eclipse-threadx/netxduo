
/*******************************************************************************/
/*                                                                             */
/* Copyright (c) Microsoft Corporation. All rights reserved.                   */
/*                                                                             */
/* This software is licensed under the Microsoft Software License              */
/* Terms for Microsoft Azure Defender for IoT. Full text of the license can be */
/* found in the LICENSE file at https://aka.ms/AzureDefenderForIoT_EULA        */
/* and in the root directory of this software.                                 */
/*                                                                             */
/*******************************************************************************/
#include <asc_config.h>

#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "asc_security_core/logger.h"
#include "asc_security_core/object_pool.h"
#include "asc_security_core/utils/collection/linked_list.h"
#include "asc_security_core/utils/itime.h"

#include "asc_security_core/utils/event_loop_be.h"

/** @brief An opaque structure representing a timer. */
typedef struct event_timer event_timer_t;

/** @brief Flag to know if we are in timer callback to avoid inserting to another timer callbacks that where created
*          in current loop.
*/
static bool _in_timer_cb;

struct event_timer {
    COLLECTION_INTERFACE(struct event_timer);
    time_t delay;
    time_t repeat;
    event_loop_timer_cb_t cb;
    event_timer_t **self;
    void *ctx;
    bool added_in_cb;
};

OBJECT_POOL_DECLARATIONS(event_timer_t)
OBJECT_POOL_DEFINITIONS(event_timer_t, OBJECT_POOL_BE_EVENT_LOOP_TIMERS_COUNT)
LINKED_LIST_DECLARATIONS(event_timer_t)
LINKED_LIST_DEFINITIONS(event_timer_t)

static linked_list_event_timer_t _event_timer_linked_list;
static linked_list_event_timer_t_handle _event_timer_linked_list_handler = &_event_timer_linked_list;
static int _event_loop_initialized;
static int _event_loop_is_stop;

// #define DEBUG_BE 1
#if (DEBUG_BE) && (ASC_LOG_LEVEL == LOG_LEVEL_DEBUG)
static void _timers_list_debug_print(void)
{
    event_timer_t *iter = NULL;

    log_error("Timers total number %u", linked_list_event_timer_t_get_size(_event_timer_linked_list_handler));
        
    linked_list_iterator_event_timer_t event_timer_iter = {0};   
    linked_list_iterator_event_timer_t_init(&event_timer_iter, _event_timer_linked_list_handler);

    while ((iter = linked_list_iterator_event_timer_t_next(&event_timer_iter)) != NULL) {
        log_debug("timer=[%p] with delay=[%lu]", (void *)iter, iter->delay);
           
    }
}
#else
#define _timers_list_debug_print()
#endif

static int _init(void)
{
    _event_loop_initialized = true;
    _event_loop_is_stop = false;
    /* Default deinit function is not set, because in case of periodic timer we will want to remove timer without free. */
    linked_list_event_timer_t_init(_event_timer_linked_list_handler, NULL);
    return 0;
}

static int _deinit(void)
{
    return (_event_loop_initialized = 0);
}

static void _reset_added_in_run_cb(event_timer_t *t, void *ctx)
{
    t->added_in_cb = false;
}

static void _timers_reset_added_in_run()
{
    linked_list_event_timer_t_foreach(_event_timer_linked_list_handler, _reset_added_in_run_cb, NULL);
}

static void _timer_del(event_timer_t *t)
{
    log_debug("deleting timer=[%p]", (void *)t);
    if (t) {
        event_timer_t **self = t->self;

        log_debug("deleting timer=[%p] delay=[%lu] repeat=[%lu] ", (void *)t, t->delay, t->repeat);

        linked_list_event_timer_t_remove(_event_timer_linked_list_handler, t);
        object_pool_event_timer_t_free(t);

        if (self) {
            *self = NULL;
        }
    }
    _timers_list_debug_print();
}

static event_timer_t *_timer_add(event_timer_t *t, event_loop_timer_cb_t cb, void *ctx, time_t delay, time_t repeat, event_timer_t **self)
{
    event_timer_t *iter = NULL, *new;
    bool is_periodic = !!t;
    time_t current_time = itime_time(NULL);
    linked_list_iterator_event_timer_t event_timer_iter = {0};

    log_debug("is_periodic=[%d]", is_periodic);
    
    if (is_periodic) {
        new = t;
    } else {
        if (!(new = object_pool_event_timer_t_get())) {
            log_error("Failed to allocate timer struct.");
            goto cleanup;
        }
    }
    new->delay = delay + current_time;
    new->repeat = repeat;
    new->ctx = ctx;
    new->self = self;
    new->cb = cb;
    new->added_in_cb = _in_timer_cb;

    linked_list_iterator_event_timer_t_init(&event_timer_iter, _event_timer_linked_list_handler);

    while ((iter = linked_list_iterator_event_timer_t_next(&event_timer_iter)) != NULL) {
        if (new->delay < iter->delay) {
            break;
        }
    }

    if (linked_list_event_timer_t_insert(_event_timer_linked_list_handler, iter, new) != new) {
        log_error("Failed to insert timer to queue.");
        _timer_del(new);
        new = NULL;
        goto cleanup;
    }
    log_debug("added timer=[%p] delay=[%lu] offset=[%lu] repeat=[%lu] from preiodic=[%d]", (void *)new, delay, new->delay, new->repeat, is_periodic);
    _timers_list_debug_print();

cleanup:
    return new;
}

static void _be_timer_wrapper(event_timer_t *t)
{
    time_t repeat = t->repeat;

    linked_list_event_timer_t_remove(_event_timer_linked_list_handler, t);

    // Add timer to next period so in parameter 'delay' we will set 'repeat' value
    if (repeat) {
        _timer_add(t, t->cb, t->ctx, t->repeat, t->repeat, t->self);
    }
    log_debug("calling timer=[%p] delay=[%lu] repeat=[%lu] ", (void *)t, t->delay, t->repeat);

    t->cb((event_loop_timer_handler)t, t->ctx);
}

static bool _run_once(void)
{
    event_timer_t *t;
    time_t current_time = itime_time(NULL);

    log_debug("calling timers total count=[%d]", linked_list_event_timer_t_get_size(_event_timer_linked_list_handler));
    _timers_list_debug_print();

    /* stop() might be called in one of callbacks, so need to check it on each iteration.
     * _event_timer_linked_list might change on each call, so always get first.
     */
    _in_timer_cb = true;
    while(!_event_loop_is_stop && (t = linked_list_event_timer_t_get_first(_event_timer_linked_list_handler))) {
        // we are adding timer to the end of same sorted sequence so if we met t->added_in_cb = true we can break
        if (!t->added_in_cb && t->delay <= current_time) {
            _be_timer_wrapper(t);
        } else {
            break;
        }
    }
    _in_timer_cb = false;
    _timers_reset_added_in_run();
    _timers_list_debug_print();

    return !_event_loop_is_stop;
}

static bool _run_until(int max_count)
{
    int cnt = 0;
    while (cnt++ < max_count) {
        _run_once();
        if (!linked_list_event_timer_t_get_size(_event_timer_linked_list_handler)) {
            return true;
        }
    }
    return false;
}

static void _stop(void)
{
    event_timer_t *iter;

    _timers_list_debug_print();

    _event_loop_is_stop = true;
    while((iter = linked_list_event_timer_t_get_first(_event_timer_linked_list_handler))) {
        _timer_del(iter);
    }
}

static event_loop_timer_handler _timer_create(event_loop_timer_cb_t cb, void *ctx, time_t delay, time_t repeat, event_loop_timer_handler *self)
{
    if (!_event_loop_initialized) {
        return (event_loop_timer_handler)NULL;
    }
    return (event_loop_timer_handler)_timer_add(NULL, cb, ctx, delay, repeat, (event_timer_t **)self);
}

static void _timer_delete(event_loop_timer_handler handler)
{
    if (handler) {
        _timer_del((event_timer_t *)handler);
    }
}

ievent_loop_t *event_loop_be_instance_attach(void)
{
    static ievent_loop_t event_loop = {
        .init = _init,
        .deinit = _deinit,
        .run = NULL,
        .run_once = _run_once,
        .run_until = _run_until,
        .stop = _stop,
        .signal_create = NULL,
        .signal_delete = NULL,
        .timer_create = _timer_create,
        .timer_delete = _timer_delete,
    };

    return &event_loop;
}
