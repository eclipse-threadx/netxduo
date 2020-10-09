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

#ifndef OBJECT_POOL_DYNAMIC_H
#define OBJECT_POOL_DYNAMIC_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "asc_security_core/logger.h"

#define OBJECT_POOL_DECLARATIONS(type)\
type *object_pool_##type##_get();\
void object_pool_##type##_free(type *object);\

#define OBJECT_POOL_DEFINITIONS(type, pool_size)\
static uint32_t _##type##_pool_size = pool_size;\
static uint32_t _##type##_current_pool_size = 0;\
type *object_pool_##type##_get() \
{\
    if ((_##type##_current_pool_size) >= (_##type##_pool_size)) {\
        log_debug("Pool exceeded objects count %d size %d", _##type##_current_pool_size, _##type##_pool_size); \
        return NULL;\
    }\
    (_##type##_current_pool_size)++;\
    return (type*)malloc(sizeof(type));\
}\
void object_pool_##type##_free(type *obj) \
{\
    if (obj) { \
        if (_##type##_current_pool_size == 0) { \
            log_fatal("Invalid memory free"); \
        } else { \
            free(obj);\
            (_##type##_current_pool_size)--; \
        } \
    } \
}\

#endif /* OBJECT_POOL_DYNAMIC_H */