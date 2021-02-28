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


#ifdef __cplusplus
extern "C" {
#endif

/* Distribution RTOS_BASE */
#ifndef __ASC_CONFIG_H__
#define __ASC_CONFIG_H__

/********************
* Core configuration
*********************/

/* ID and version */
#define ASC_SECURITY_MODULE_ID "defender-iot-micro-agent"
#define SECURITY_MODULE_VERSION_MAJOR 3
#define SECURITY_MODULE_VERSION_MINOR 2
#define SECURITY_MODULE_VERSION_PATCH 1
#ifndef SECURITY_MODULE_VERSION_MAJOR
#define SECURITY_MODULE_VERSION_MAJOR 3
#endif
#ifndef SECURITY_MODULE_VERSION_MINOR
#define SECURITY_MODULE_VERSION_MINOR 2
#endif
#ifndef SECURITY_MODULE_VERSION_PATCH
#define SECURITY_MODULE_VERSION_PATCH 0
#endif

/* Collectors definitions */
#define ASC_COLLECTOR_HEARTBEAT_ENABLED

/* #undef ASC_COLLECTOR_BASELINE_ENABLED */
/* #undef ASC_BASELINE_REPORT_POOL_ENTRIES */

#define ASC_COLLECTOR_NETWORK_ACTIVITY_ENABLED
/* #undef ASC_COLLECTOR_NETWORK_ACTIVITY_SEND_EMPTY_EVENTS */
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV4_OBJECTS_IN_CACHE 64
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE 64
#ifndef ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV4_OBJECTS_IN_CACHE
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV4_OBJECTS_IN_CACHE 0
#endif
#ifndef ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE 0
#endif

/* #undef ASC_COLLECTOR_PROCESS_ENABLED */
/* #undef ASC_COLLECTOR_PROCESS_SEND_EMPTY_EVENTS */
/* #undef ASC_COLLECTOR_PROCESS_MODE_AGGREGATED_DISABLE */
/* #undef ASC_COLLECTOR_PROCESS_IN_CACHE */
#ifndef ASC_COLLECTOR_PROCESS_IN_CACHE
#define ASC_COLLECTOR_PROCESS_IN_CACHE 0
#endif

#define ASC_COLLECTOR_SYSTEM_INFORMATION_ENABLED

/* #undef ASC_COLLECTOR_LISTENING_PORTS_ENABLED */

/* Components definitions */
/* #undef ASC_COMPONENT_COMMAND_EXECUTOR */
/* #undef ASC_OPERATIONS_POOL_ENTRIES */

/* #undef ASC_COMPONENT_CONFIGURATION */
/* #undef ASC_COMPONENT_CONFIGURATION_PLAT */

#define ASC_COMPONENT_SECURITY_MODULE

/* Collection definitions */
#define ASC_FIRST_COLLECTION_INTERVAL 30
#define ASC_HIGH_PRIORITY_INTERVAL 10
#define ASC_MEDIUM_PRIORITY_INTERVAL 30
#define ASC_LOW_PRIORITY_INTERVAL 60

/* Dynamic/Static memory */
/* #undef ASC_DYNAMIC_MEMORY_ENABLED */

/* ROM reduce */
/* #undef ASC_COMPONENT_CORE_SUPPORTS_RESTART */
/* #undef ASC_COLLECTORS_INFO_SUPPORT */

/* Notifier definitions */
#define ASC_NOTIFIERS_OBJECT_POOL_ENTRIES 2

/* Event loop best effort */
#define ASC_BEST_EFFORT_EVENT_LOOP

/* Flat buffer serializer */
#define ASC_SERIALIZER_USE_CUSTOM_ALLOCATOR
/* #undef ASC_FLATCC_JSON_PRINTER_OVERWRITE */
#define ASC_EMITTER_PAGE_CACHE_SIZE 1
#define FLATCC_NO_ASSERT
#define FLATCC_USE_GENERIC_ALIGNED_ALLOC
/* #undef FLATCC_EMITTER_PAGE_SIZE */

/* Tests definitions */
// Highest compiled log level
/* #undef ASC_LOG_LEVEL */
// Set ASC_FIRST_FORCE_COLLECTION_INTERVAL to '-1' to force immediatly collecting
/* #undef ASC_FIRST_FORCE_COLLECTION_INTERVAL */
/* #undef ASC_EXTRA_BE_TIMERS_OBJECT_POOL_ENTRIES */
/* #undef ASC_EXTRA_NOTIFIERS_OBJECT_POOL_ENTRIES */
/* #undef ASC_EXTRA_COMPONENTS_COUNT */
/* #undef ASC_EXTRA_COLLECTORS_COUNT */

/************************
* Platform configuration
*************************/
#ifndef __ASC_CONFIG_EXCLUDE_PORT__H__
#include "tx_port.h"
#include "nx_port.h"
#endif /* __ASC_CONFIG_EXCLUDE_PORT__H__ */

/* Security Module pending time, in seconds */
#define ASC_SECURITY_MODULE_PENDING_TIME 60*5
#define ASC_SECURITY_MODULE_SEND_MESSAGE_RETRY_TIME 3
/* #undef ASC_SECURITY_MODULE_MAX_HUB_DEVICES */
#ifndef ASC_SECURITY_MODULE_MAX_HUB_DEVICES
#define ASC_SECURITY_MODULE_MAX_HUB_DEVICES 64
#endif

/* Collector network activity. */
/* #undef ASC_COLLECTOR_NETWORK_ACTIVITY_TCP_DISABLED */
/* #undef ASC_COLLECTOR_NETWORK_ACTIVITY_UDP_DISABLED */
/* #undef ASC_COLLECTOR_NETWORK_ACTIVITY_ICMP_DISABLED */
#define ASC_COLLECTOR_NETWORK_ACTIVITY_CAPTURE_UNICAST_ONLY

/* The maximum number of IPv4 network events to store in memory. */
#ifdef NX_DISABLE_IPV6
#undef ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE 0
#endif

#endif /* __ASC_CONFIG_H__ */

#ifdef __cplusplus
}
#endif
