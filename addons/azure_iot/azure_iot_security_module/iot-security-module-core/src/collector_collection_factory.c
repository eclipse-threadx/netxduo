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

#include <stdlib.h>
#include "asc_security_core/utils/itime.h"
#include "asc_security_core/logger.h"

#include "asc_security_core/collector_collection_factory.h"
#include "asc_security_core/collectors_headers.h"

static collector_init_function_t collector_init_array[] = {
#ifdef COLLECTOR_SYSTEM_INFORMATION_ENABLED
    collector_system_information_init,
#endif
#ifdef COLLECTOR_LISTENING_PORTS_ENABLED
    collector_listening_ports_init,
#endif
#ifdef COLLECTOR_NETWORK_ACTIVITY_ENABLED
    collector_network_activity_init,
#endif
#ifdef COLLECTOR_HEARTBEAT_ENABLED
    collector_heartbeat_init,
#endif
#ifdef COLLECTOR_BASELINE_ENABLED
    collector_baseline_init,
#endif
};


asc_result_t collector_collection_factory_get_initialization_array(collector_init_function_t **init_array, uint32_t *init_array_size)
{
    asc_result_t result = ASC_RESULT_OK;

    if (init_array == NULL) {
        log_error("Collector collection array cannot be initialize due to bad arguments");
        result = ASC_RESULT_BAD_ARGUMENT;
        goto cleanup;
    }

    if (collector_init_array == NULL) {
        log_error("Collector collection array cannot be initialize due to collector_init_array=[NULL]");
        result = ASC_RESULT_UNINITIALIZED;
        goto cleanup;
    }

    *init_array = collector_init_array;
    *init_array_size = sizeof(collector_init_array) / sizeof(collector_init_function_t);

cleanup:
    if (result != ASC_RESULT_OK) {
        log_error("Failed to retrieve collector collection initialization array");
    }

    return result;
}