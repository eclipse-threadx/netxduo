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

#ifndef __COMPONENTS_FACTORY_H__
#define __COMPONENTS_FACTORY_H__
#include <asc_config.h>

#include <stdint.h>
#include <string.h>


#include "asc_security_core/logger.h"
#include "asc_security_core/utils/string_utils.h"
#include "asc_security_core/components_factory_type.h"
#include "asc_security_core/component_id.h"

/**
 * @brief Macros for generating load and get_id functions for built-in components.
 *
 * @param _component Component generated name from @c component_enum_t and @c collector_enum_t
 */
/* Add this declaration in inc/asc_security_core/components_factory_enum.h. */
#define COMPONENTS_FACTORY_DECLARATION(_component) \
extern component_load_function_t components_factory_##_component##_load_ptr;

#define COMPONENTS_FACTORY_DEFINITION(_component, _ops) \
asc_result_t components_factory_##_component##_load(void);\
asc_result_t components_factory_##_component##_load(void) { \
    if ((char *)#_component == NULL || str_str(#_component, "_")){ log_fatal("Component name is NULL or has '_'"); return ASC_RESULT_BAD_ARGUMENT; } \
    g_component_factory[_component].component.info.state = COMPONENT_LOADED; \
    g_component_factory[_component].component.info.last_result = ASC_RESULT_OK; \
    g_component_factory[_component].component.info.log_level = ASC_LOG_LEVEL; \
    g_component_factory[_component].component.ops = _ops; \
    g_component_factory[_component].component.info.id = (component_id_t)(&g_component_factory[_component].component); \
    g_component_factory[_component].component.info.name = #_component; \
    g_component_factory[_component].component.info.enumerator = _component; \
    bit_vector_clean(component_owners_t, &g_component_factory[_component].component.info.owners); \
    __auto_generated_self_id = g_component_factory[_component].component.info.id; \
    return ASC_RESULT_OK; \
} \
component_load_function_t components_factory_##_component##_load_ptr = components_factory_##_component##_load;


/* Add this macro in src/components_factory.c */
#define COMPONENTS_FACTORY_LOAD(_component) &components_factory_##_component##_load_ptr

#endif // __COMPONENTS_FACTORY_H__