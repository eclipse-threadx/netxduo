/*******************************************************************************/
/*                                                                             */
/* Copyright (c) Microsoft Corporation. All rights reserved.                   */
/*                                                                             */
/* This software is licensed under the Microsoft Software License              */
/* Terms for Microsoft Azure Defender for IoT. Full text of the license can be */
/* found in the LICENSE file at https://aka.ms/AzureDefenderForIoT_EULA        */
/* and in the root directory of this software.                                 */
/*                                                                             */
/*******************************************************************************/

#ifndef __COMPONENTS_FACTORY__TYPE_H__
#define __COMPONENTS_FACTORY__TYPE_H__
#include <asc_config.h>

#include "asc_security_core/asc_result.h"
#include "asc_security_core/component_info.h"

/**
 * @brief Factory load the component function prototype
 */
typedef asc_result_t (*component_load_function_t)(void);

/**
 * @brief Struct of factory entry.
 */
typedef struct {
    component_t component;
} components_factory_t;

/**
 * @brief Factory global array.
 */
extern components_factory_t g_component_factory[];

/**
 * @brief Get array of component load functions
 *
 * @return An @c component_load_function_t array of component load functions.
 */
component_load_function_t **components_factory_get_load_array(void);

/**
 * @brief Factory unload - clean built-in components data from @c g_component_factory .
 */
void components_factory_unload(void);

#endif
