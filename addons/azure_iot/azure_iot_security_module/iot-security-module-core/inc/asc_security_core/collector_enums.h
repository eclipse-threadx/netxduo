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

#ifndef _COLLECTOR_ENUMS_H_
#define _COLLECTOR_ENUMS_H_

#include <stdint.h>

#include "asc_security_core/configuration.h"

#define COLLECTOR_NAME_SYSTEM_INFORMATION "SystemInformation"
#define COLLECTOR_NAME_NETWORK_ACTIVITY "NetworkActivity"
#define COLLECTOR_NAME_LISTENING_PORTS "ListeningPorts"
#define COLLECTOR_NAME_HEARTBEAT "Heartbeat"
#define COLLECTOR_NAME_BASELINE "Baseline"

typedef enum {
#ifdef COLLECTOR_SYSTEM_INFORMATION_ENABLED
    COLLECTOR_TYPE_SYSTEM_INFORMATION,
#endif
#ifdef COLLECTOR_NETWORK_ACTIVITY_ENABLED
    COLLECTOR_TYPE_NETWORK_ACTIVITY,
#endif
#ifdef COLLECTOR_LISTENING_PORTS_ENABLED
    COLLECTOR_TYPE_LISTENING_PORTS,
#endif
#ifdef COLLECTOR_HEARTBEAT_ENABLED
    COLLECTOR_TYPE_HEARTBEAT,
#endif
#ifdef COLLECTOR_BASELINE_ENABLED
    COLLECTOR_TYPE_BASELINE,
#endif
    COLLECTOR_TYPE_COUNT
} collector_type_t;

extern const char *g_collector_names[COLLECTOR_TYPE_COUNT];

typedef enum {
    COLLECTOR_PRIORITY_HIGH = 0,
    COLLECTOR_PRIORITY_MEDIUM = 1,
    COLLECTOR_PRIORITY_LOW = 2,
    COLLECTOR_PRIORITY_COUNT = 3
} collector_priority_t;

extern const uint32_t g_collector_collections_intervals[COLLECTOR_PRIORITY_COUNT];

#endif /* _COLLECTOR_ENUMS_H_ */