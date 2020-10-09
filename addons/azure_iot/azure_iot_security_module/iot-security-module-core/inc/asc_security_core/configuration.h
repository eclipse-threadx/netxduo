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

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include "asc_security_core/version.h"

#ifndef DISABLE_ASC_PORT
#include "asc_port.h"
#else
#include "asc_security_core/no_platform/asc_port.h"
#endif /* DISABLE_ASC_PORT */

// Security Module ID - A unique identifier of the device
#ifndef ASC_SECURITY_MODULE_ID
#define ASC_SECURITY_MODULE_ID "iot_security_module"
#endif

// First collection interval in seconds
#ifndef ASC_FIRST_COLLECTION_INTERVAL
#define ASC_FIRST_COLLECTION_INTERVAL 10
#endif

// Collection interval for high priority events, in seconds
#ifndef ASC_HIGH_PRIORITY_INTERVAL
#define ASC_HIGH_PRIORITY_INTERVAL 10
#endif

// Collection interval for medium priority events, in seconds
#ifndef ASC_MEDIUM_PRIORITY_INTERVAL
#define ASC_MEDIUM_PRIORITY_INTERVAL 30
#endif

// Collection interval for low priority events, in seconds
#ifndef ASC_LOW_PRIORITY_INTERVAL
#define ASC_LOW_PRIORITY_INTERVAL 60
#endif

// The maximum number of IPv4 network events to store in memory
#ifndef ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV4_OBJECTS_IN_CACHE
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV4_OBJECTS_IN_CACHE 64
#endif

// The maximum number of IPv6 network events to store in memory
#ifndef ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE 64
#endif

// Send empty Network Activity events
// #define ASC_COLLECTOR_NETWORK_ACTIVITY_SEND_EMPTY_EVENTS

// The size of flatcc emitter page cache, when using custom allocator
#ifndef EMITTER_PAGE_CACHE_SIZE
#define EMITTER_PAGE_CACHE_SIZE 1
#endif

#endif /* CONFIGURATION_H */
