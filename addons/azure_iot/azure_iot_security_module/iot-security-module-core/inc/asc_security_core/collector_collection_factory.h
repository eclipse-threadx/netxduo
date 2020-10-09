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

#ifndef IOTSECURITY_COLLECTOR_COLLECTION_FACTORY_H
#define IOTSECURITY_COLLECTOR_COLLECTION_FACTORY_H


#include <stdint.h>
#include "asc_security_core/collector_collection.h"
#include "asc_security_core/asc_result.h"

/**
 * @brief Initialize an collector_init_function_t array with init functions of enabled collectors
 *
 * @param init_array                out param -given array to populate
 * @param init_array_size           array size
 *
 * @return An @c asc_result_t indicating the status of the call.
 */
asc_result_t collector_collection_factory_get_initialization_array(collector_init_function_t **init_array, uint32_t *init_array_size);

#endif /* IOTSECURITY_COLLECTOR_COLLECTION_FACTORY_H */