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

#ifndef ASC_PORT_H
#define ASC_PORT_H

#include "nx_api.h"
#include "asc_security_core/version.h"

/* Security Module ID - A unique identifier of the device. */
#ifndef ASC_SECURITY_MODULE_ID
#define ASC_SECURITY_MODULE_ID "iot_security_module"
#endif

/* Security Module pending time, in seconds */
#ifndef ASC_SECURITY_MODULE_PENDING_TIME
#define ASC_SECURITY_MODULE_PENDING_TIME (60 * 5)
#endif

/* Collection intervals, in seconds. */
#ifndef ASC_HIGH_PRIORITY_INTERVAL
#define ASC_HIGH_PRIORITY_INTERVAL 10
#endif
#ifndef ASC_MEDIUM_PRIORITY_INTERVAL
#define ASC_MEDIUM_PRIORITY_INTERVAL 30
#endif
#ifndef ASC_LOW_PRIORITY_INTERVAL
#define ASC_LOW_PRIORITY_INTERVAL 60
#endif

/* Enable Collectors */
#define COLLECTOR_HEARTBEAT_ENABLED
#define COLLECTOR_SYSTEM_INFORMATION_ENABLED
#define COLLECTOR_NETWORK_ACTIVITY_ENABLED

/* Collector network activity. */
/* #define ASC_COLLECTOR_NETWORK_ACTIVITY_TCP_DISABLED */
/* #define ASC_COLLECTOR_NETWORK_ACTIVITY_UDP_DISABLED */
/* #define ASC_COLLECTOR_NETWORK_ACTIVITY_ICMP_DISABLED */
#define ASC_COLLECTOR_NETWORK_ACTIVITY_CAPTURE_UNICAST_ONLY

/* The maximum number of IPv4 network events to store in memory. */
#ifndef ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV4_OBJECTS_IN_CACHE
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV4_OBJECTS_IN_CACHE 4
#endif
/* The maximum number of IPv6 network events to store in memory. */
#ifndef ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE
#ifdef NX_DISABLE_IPV6
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE 0
#else
#define ASC_COLLECTOR_NETWORK_ACTIVITY_MAX_IPV6_OBJECTS_IN_CACHE 4
#endif /* NX_DISABLE_IPV6 */
#endif


/* Serializer custom allocator uses static memory instead of heap memory. Desired behaviour in Azure RTOS devices. */
#ifndef ASC_SERIALIZER_USE_CUSTOM_ALLOCATOR
#define ASC_SERIALIZER_USE_CUSTOM_ALLOCATOR
#endif

#endif /* ASC_PORT_H */
