cmake_minimum_required(VERSION 3.13)
cmake_policy(SET CMP0079 NEW)

set(PROJECT_NAME "iot_security_module")
project(${PROJECT_NAME})

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# reslove logger log level
set(LOG_LEVELS NOTSET DEBUG INFO WARNING ERROR FATAL)
set(log_level NOTSET CACHE STRING "log_level: ${log_level} (default is NOTSET)")
set_property(CACHE log_level PROPERTY STRINGS NOTSET DEBUG INFO WARNING ERROR FATAL)
list(FIND LOG_LEVELS ${log_level} log_level_index)
if(log_level_index EQUAL -1)
    message(FATAL_ERROR "log_level must be one of ${LOG_LEVELS}")
else()
    add_definitions(-DLOG_LEVEL=${log_level_index})
endif()

# collector options
set(collector_heartbeat_enabled ON CACHE BOOL "Enable the heartbeat collector")
set(collector_network_activity_enabled ON CACHE BOOL "Enable the network activity collector")
set(collector_system_information_enabled ON CACHE BOOL "Enable the system information collector")

# Azure IoT Security Module core
if(UNIX)
    set(build_as_32 ON CACHE BOOL "build as 32 bit")
endif()
set(serializer_custom_allocator ON CACHE BOOL "")
set(run_unittests OFF)
set(run_coverage OFF)
add_subdirectory(iot-security-module-core)
# FlatBUffers
target_include_directories(flatccrt
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/inc
)

# Define our target library and an alias for consumers
add_library(${PROJECT_NAME}
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot_security_module.c

    $<$<BOOL:${collector_network_activity_enabled}>:${CMAKE_CURRENT_LIST_DIR}/src/collectors/collector_network_activity.c>
    $<$<BOOL:${collector_system_information_enabled}>:${CMAKE_CURRENT_LIST_DIR}/src/collectors/collector_system_information.c>
    ${CMAKE_CURRENT_LIST_DIR}/src/model/objects/object_network_activity_ext.c
    ${CMAKE_CURRENT_LIST_DIR}/src/utils/irand.c
    ${CMAKE_CURRENT_LIST_DIR}/src/utils/itime.c
    ${CMAKE_CURRENT_LIST_DIR}/src/utils/iuuid.c
    ${CMAKE_CURRENT_LIST_DIR}/src/utils/os_utils.c
)
add_library("azrtos::${PROJECT_NAME}" ALIAS ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${AZURE_IOT_SECURITY_MODULE}
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/inc
)


target_link_libraries(${PROJECT_NAME}
    PUBLIC
        asc_security_core
        az::core
        netxduo
)
target_link_libraries(asc_security_core
    PUBLIC
        netxduo
)

target_include_directories(asc_security_core
    PRIVATE
        inc
)

# Define any required dependencies between this library and others
target_link_libraries(asc_security_core
    PRIVATE
        ${PROJECT_NAME}
)

setTargetCompileOptions(${PROJECT_NAME})
compileTargetAsC99(${PROJECT_NAME})

set_target_properties(asc_security_core PROPERTIES FOLDER "azure_iot_security_module")
set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "azure_iot_security_module")
set_target_properties(flatccrt PROPERTIES FOLDER "azure_iot_security_module")
