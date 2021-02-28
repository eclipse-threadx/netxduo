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
#include <asc_config.h>

#include <stdlib.h>

#include "asc_security_core/components_factory_declarations.h"

#define COMPONENTS_FACTORY_UNLOAD(_component) do { \
    g_component_factory[_component].component.ops = NULL; \
    g_component_factory[_component].component.info.state = COMPONENT_UNLOADED; \
    g_component_factory[_component].component.info.id = 0; \
    g_component_factory[_component].component.info.name = NULL; \
    g_component_factory[_component].component.info.enumerator = COMPONENTS_COUNT; \
    g_component_factory[_component].component.info.log_level = ASC_LOG_LEVEL; \
    bit_vector_clean(component_owners_t, &g_component_factory[_component].component.info.owners); \
} while (0)

components_factory_t g_component_factory[COMPONENTS_COUNT];

static component_load_function_t *component_load_function_array[] = {
    COMPONENTS_FACTORY_LOAD(ManagerCore),
    COMPONENTS_FACTORY_LOAD(Logger),
#ifdef ASC_COMPONENT_SECURITY_MODULE
    COMPONENTS_FACTORY_LOAD(SecurityModule),
#endif
    COMPONENTS_FACTORY_LOAD(CollectorsCore),
#ifdef ASC_COMPONENT_CONFIGURATION
    COMPONENTS_FACTORY_LOAD(Configuration),
#endif
#ifdef ASC_COMPONENT_CONFIGURATION_PLAT
    COMPONENTS_FACTORY_LOAD(ConfigurationPlatform),
#endif
#ifdef ASC_COMPONENT_COMMAND_EXECUTOR_PLAT
    COMPONENTS_FACTORY_LOAD(CommandExecutorPlatform),
#endif
#ifdef ASC_COLLECTOR_HEARTBEAT_ENABLED
    COMPONENTS_FACTORY_LOAD(Heartbeat),
#endif
#ifdef ASC_COLLECTOR_BASELINE_ENABLED
    COMPONENTS_FACTORY_LOAD(Baseline),
#endif
#ifdef ASC_COMPONENT_BASELINE_PLAT
    COMPONENTS_FACTORY_LOAD(BaselinePlatform),
#endif
#ifdef ASC_COMPONENT_IPC_PLAT
    COMPONENTS_FACTORY_LOAD(IpcPlatform),
#endif
#ifdef ASC_COMPONENT_CLI_PLAT
    #ifdef ASC_COMPONENT_DEMO_CLI_PLAT
        COMPONENTS_FACTORY_LOAD(CliDemoPlatform),
    #endif
    COMPONENTS_FACTORY_LOAD(CliPlatform),
#endif
#ifdef ASC_COLLECTOR_SYSTEM_INFORMATION_ENABLED
    COMPONENTS_FACTORY_LOAD(SystemInformation),
#endif
#ifdef ASC_COLLECTOR_NETWORK_ACTIVITY_ENABLED
    COMPONENTS_FACTORY_LOAD(NetworkActivity),
#endif
#ifdef ASC_COLLECTOR_LISTENING_PORTS_ENABLED
    COMPONENTS_FACTORY_LOAD(ListeningPorts),
#endif
#ifdef ASC_COLLECTOR_PROCESS_ENABLED
    COMPONENTS_FACTORY_LOAD(Process),
#endif
    NULL
};

component_load_function_t **components_factory_get_load_array(void)
{
    return component_load_function_array;
}

void components_factory_unload(void)
{
    int index;

    for (index = 0; index < COMPONENTS_COUNT; index++) {
        COMPONENTS_FACTORY_UNLOAD(index);
    }
}
