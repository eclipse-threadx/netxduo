cmake_minimum_required(VERSION 3.13)

set(TARGET_NAME "asc_security_core")
project(${TARGET_NAME})


set(build_pedantic ON CACHE BOOL "use -Wpedantic flag in compilation")

# Include the common build rules for the security module core
include(cmake-modules/asc_security_coreBuild.cmake)
include(cmake-modules/asc_security_core_build_rules.cmake)

# the following variables are project-wide and can be used with cmake-gui
set(run_unittests OFF CACHE BOOL "set run_unittests to ON to run unittests (default is OFF)")
set(run_coverage OFF CACHE BOOL "set run_coverage to ON to gather coverage info (default is OFF)")
set(use_dynamic_memory OFF CACHE BOOL "use the stack memory instead of using heap memory")
set(disable_asc_port OFF CACHE BOOL "explicitly disable ASC_PORT include")
set(serializer_custom_allocator OFF CACHE BOOL "Use custom allocator for flatcc")
set(build_json_printer OFF CACHE BOOL "Build the json printer")

# collector options
set(collector_force_first_interval 0 CACHE STRING "Force first collector interval")
set(collector_heartbeat_enabled ON CACHE BOOL "Enable the heartbeat collector")
set(collector_network_activity_enabled OFF CACHE BOOL "Enable the network activity collector")
set(collector_system_information_enabled OFF CACHE BOOL "Enable the system information collector")
set(collector_listening_ports_enabled OFF CACHE BOOL "Enable the listening ports collector")
set(collector_baseline_enabled OFF CACHE BOOL "Enable the baseline collector")
set(build_as_32 OFF CACHE BOOL "build as 32 bit")

# components options
set(component_command_executor_enabled OFF CACHE BOOL "Enable the command executor component")
set(best_effort_event_loop_enabled OFF CACHE BOOL "Compile best effort event loop")

# reslove logger log level
set(LOG_LEVELS NOTSET DEBUG INFO WARNING ERROR FATAL)
set(log_level NOTSET CACHE STRING "log_level: ${log_level} (default is NOTSET)")
set_property(CACHE log_level PROPERTY STRINGS NOTSET DEBUG INFO WARNING ERROR FATAL)
list(FIND LOG_LEVELS ${log_level} log_level_index)
if(log_level_index EQUAL -1)
    message(FATAL_ERROR "log_level must be one of ${LOG_LEVELS}")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules")

if(${collector_force_first_interval})
    message("Forcing first collection interval to ${collector_force_first_interval}")
    add_definitions(
        -DASC_FIRST_FORCE_COLLECTION_INTERVAL=${collector_force_first_interval}
    )
endif()

if(${run_unittests})
    FILE(REMOVE ${CMAKE_BINARY_DIR}/valgrind_targets.lst)

    set(disable_asc_port ON)
    set(collector_heartbeat_enabled ON)
    set(component_command_executor_enabled ON)
    set(best_effort_event_loop_enabled ON)

    if (${run_coverage})
        include(asc_security_coreCodeCoverage)
        include(asc_security_coreCreateCodeCoverageTargets)
        include(asc_security_coreCheckAndIncludeCodeCov)
    endif ()
endif()

add_library(${TARGET_NAME} STATIC
    # componets
    $<$<BOOL:${component_command_executor_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/command_executor.c>

    $<$<BOOL:${collector_heartbeat_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/collectors/collector_heartbeat.c>
    $<$<BOOL:${collector_baseline_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/collectors/baseline.c>
    $<$<BOOL:${collector_baseline_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/serializer/baseline.c>
    $<$<BOOL:${collector_baseline_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/model/objects/object_baseline_ext.c>
    $<$<BOOL:${collector_heartbeat_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/serializer/heartbeat.c>
    $<$<BOOL:${collector_listening_ports_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/serializer/listening_ports.c>
    $<$<BOOL:${collector_network_activity_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/serializer/network_activity.c>
    $<$<BOOL:${collector_system_information_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/serializer/system_information.c>

    $<$<BOOL:${serializer_custom_allocator}>:${CMAKE_CURRENT_SOURCE_DIR}/src/serializer/extensions/custom_builder_allocator.c>
    $<$<BOOL:${serializer_custom_allocator}>:${CMAKE_CURRENT_SOURCE_DIR}/src/serializer/extensions/page_allocator.c>

    src/collector_collection_factory.c
    src/collector_collection_internal.c
    src/collector_collection.c
    src/collectors_info.c
    src/core.c
    src/logger.c
    src/model/collector.c
    src/model/security_message.c
    src/serializer/serializer_private.c
    src/serializer/serializer.c
    src/utils/notifier.c
    $<$<BOOL:${best_effort_event_loop_enabled}>:${CMAKE_CURRENT_SOURCE_DIR}/src/utils/event_loop_be.c>
    src/utils/string_utils.c
)

target_compile_definitions(${TARGET_NAME} PUBLIC
    LOG_LEVEL=${log_level_index}

    $<$<BOOL:${disable_asc_port}>:DISABLE_ASC_PORT>
    $<$<BOOL:${use_dynamic_memory}>:DYNAMIC_MEMORY_ENABLED>
    $<$<BOOL:${serializer_custom_allocator}>:ASC_SERIALIZER_USE_CUSTOM_ALLOCATOR>

    $<$<BOOL:${component_command_executor_enabled}>:CONFIG_COMPONENT_COMMAND_EXECUTOR>
)

target_include_directories(${TARGET_NAME} PUBLIC inc)

add_subdirectory(deps)
target_link_libraries(${TARGET_NAME} PRIVATE
    flatccrt
)
target_include_directories(flatccrt PRIVATE inc)

if(${serializer_custom_allocator})
    target_link_libraries(flatccrt PRIVATE asc_security_core)
    target_sources(flatccrt PRIVATE src/serializer/extensions/custom_emitter.c)
    target_include_directories(flatccrt PRIVATE deps/flatcc/src/runtime)
endif()

if (${run_unittests})
    enable_testing()
    include(CTest)

    add_definitions(
        -DEXTRA_BE_TIMERS_OBJECT_POOL_ENTRIES=10
        -DEXTRA_NOTIFIERS_OBJECT_POOL_ENTRIES=1
        # we have 7 test collectors
        -DEXTRA_COLLECTORS_OBJECT_POOL_COUNT=7
    )

    add_subdirectory(tests)

endif ()

setTargetCompileOptions(${TARGET_NAME})
compileTargetAsC99(${TARGET_NAME})
