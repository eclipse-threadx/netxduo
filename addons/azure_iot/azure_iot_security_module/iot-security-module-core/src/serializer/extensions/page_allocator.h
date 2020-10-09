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

#ifndef PAGE_ALLOCATOR_H
#define PAGE_ALLOCATOR_H

#include <stddef.h>

#include "asc_security_core/configuration.h"

#define MAX_MESSAGE_SIZE (500 + \
    ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV4_OBJECTS_IN_CACHE * 36 + \
    ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE * 60)

#define MIN_PAGE_SIZE (MAX_MESSAGE_SIZE * 2)
#define PAGE_MULTIPLE 64
#define FLATCC_EMITTER_PAGE_SIZE ((MIN_PAGE_SIZE + (PAGE_MULTIPLE) - 1) & ~(2 * (PAGE_MULTIPLE) - 1))

void *serializer_page_alloc(size_t size);
void serializer_page_free(void *page);

#endif /* PAGE_ALLOCATOR_H */
