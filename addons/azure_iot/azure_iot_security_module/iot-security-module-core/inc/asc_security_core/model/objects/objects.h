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

#ifndef OBJECTS_H
#define OBJECTS_H

#include "asc_security_core/configuration.h"

#ifdef COLLECTOR_SYSTEM_INFORMATION_ENABLED
#include "asc_security_core/model/objects/system_information.h"
#endif

#ifdef COLLECTOR_LISTENING_PORTS_ENABLED
#include "asc_security_core/model/objects/listening_ports.h"
#endif

#ifdef COLLECTOR_NETWORK_ACTIVITY_ENABLED
#include "asc_security_core/model/objects/network_activity.h"
#endif

#ifdef COLLECTOR_BASELINE_ENABLED
#include "asc_security_core/model/objects/baseline.h"
#include "asc_security_core/model/objects/object_baseline_ext.h"
#endif

#endif /* OBJECTS_H */
