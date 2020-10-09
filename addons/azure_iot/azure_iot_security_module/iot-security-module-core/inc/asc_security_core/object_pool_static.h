
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

#ifndef OBJECT_POOL_STATIC_H
#define OBJECT_POOL_STATIC_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "asc_security_core/logger.h"

#define OBJECT_POOL_DEFINITIONS(type, pool_size)\
STACK_DEFINITIONS(type)\
static bool _##type##_is_pool_initialized = false;\
static type _##type##_pool[pool_size];\
static stack_##type _stack_##type = {0};\
static stack_##type##_handle _stack_##type##_handle;\
static uint32_t _##type##_pool_size = pool_size;\
static uint32_t _##type##_current_pool_size = 0;\
static uint32_t _##type##_failures = 0;\
void object_pool_##type##_init() \
{\
    if (_##type##_is_pool_initialized) {\
        return;\
    }\
\
    _stack_##type##_handle = &(_stack_##type);\
    stack_##type##_init(_stack_##type##_handle);\
    for (uint32_t i=0; i<pool_size; i++) {\
        type *obj = _##type##_pool + i;\
        stack_##type##_push(_stack_##type##_handle, obj);\
  }\
\
    _##type##_is_pool_initialized = true;\
}\
type *object_pool_##type##_get() \
{\
    object_pool_##type##_init();\
    if ((_##type##_current_pool_size) >= (_##type##_pool_size)) {\
        (_##type##_failures)++;\
        if ((_##type##_failures) % (_##type##_pool_size) == 0) {\
            log_debug("Pool exceeded objects [%d/%d] failures=[%d]", _##type##_current_pool_size, _##type##_pool_size, _##type##_failures); \
        }\
        return NULL;\
    }\
    (_##type##_current_pool_size)++;\
    return stack_##type##_pop(_stack_##type##_handle);\
}\
void object_pool_##type##_free(type *obj) \
{\
    if (obj) { \
        if (_##type##_current_pool_size == 0) { \
            log_fatal("Invalid memory free"); \
        } else { \
            (_##type##_current_pool_size)--; \
            stack_##type##_push(_stack_##type##_handle, obj);\
        } \
    } \
}\

#define OBJECT_POOL_DECLARATIONS(type)\
STACK_DECLARATIONS(type)\
void object_pool_##type##_init();\
type *object_pool_##type##_get();\
void object_pool_##type##_free(type *obj);\

#endif /* OBJECT_POOL_STATIC_H */