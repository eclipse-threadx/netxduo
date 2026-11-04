cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

# Win64 MSVC simulation: no assembly sources; compiler probe must not use
# executables (cross-like environment under the VS developer shell).
if(THREADX_ARCH STREQUAL "win64")
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    project(netxduo LANGUAGES C)
else()
    # Set up the project
    project(netxduo
        LANGUAGES C ASM
    )
endif()

option(NXD_ENABLE_FILE_SERVERS "Includes a dependency on FileX to support 'server' protocol handlers" ON)
option(NXD_ENABLE_AZURE_IOT "Enable Azure IoT" OFF)
option(NXD_ENABLE_ADDONS "Build NetX Duo add-on modules" ON)
option(NXD_ENABLE_NX_SECURE "Build NetX Secure when packet chaining is enabled" ON)
option(NXD_DISABLE_PACKET_CHAIN "Build without packet chaining" OFF)

set(CUSTOM_INC_DIR ${CMAKE_CURRENT_BINARY_DIR}/custom_inc)
if(NOT NX_USER_FILE)
    message(STATUS "Using default nx_user.h file")
    set(NX_USER_FILE ${CMAKE_CURRENT_LIST_DIR}/common/inc/nx_user_sample.h)
else()
    message(STATUS "Using custom nx_user.h file from ${NX_USER_FILE}")
endif()
configure_file(${NX_USER_FILE} ${CUSTOM_INC_DIR}/nx_user.h COPYONLY)

include(CheckCSourceCompiles)
set(NXD_SAVED_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES})
set(CMAKE_REQUIRED_INCLUDES ${CUSTOM_INC_DIR})
unset(NXD_USER_DISABLE_PACKET_CHAIN CACHE)
check_c_source_compiles("#include \"nx_user.h\"
#ifndef NX_DISABLE_PACKET_CHAIN
#error Packet chaining is enabled
#endif
int main(void) { return 0; }" NXD_USER_DISABLE_PACKET_CHAIN)
set(CMAKE_REQUIRED_INCLUDES ${NXD_SAVED_REQUIRED_INCLUDES})

if(NXD_DISABLE_PACKET_CHAIN OR NXD_USER_DISABLE_PACKET_CHAIN)
    set(NXD_NO_PACKET_CHAIN ON)
endif()

if(NOT DEFINED THREADX_ARCH)
    message(FATAL_ERROR "Error: THREADX_ARCH not defined")
endif()
if(NOT DEFINED THREADX_TOOLCHAIN)
    message(FATAL_ERROR "Error: THREADX_TOOLCHAIN not defined")
endif()

# Define our target library and an alias for consumers
add_library(${PROJECT_NAME})
add_library("azrtos::${PROJECT_NAME}" ALIAS ${PROJECT_NAME})

if(NXD_NO_PACKET_CHAIN)
    target_compile_definitions(${PROJECT_NAME} PUBLIC NX_DISABLE_FRAGMENTATION)
    if(NXD_DISABLE_PACKET_CHAIN AND NOT NXD_USER_DISABLE_PACKET_CHAIN)
        target_compile_definitions(${PROJECT_NAME} PUBLIC NX_DISABLE_PACKET_CHAIN)
    endif()
endif()

# Define any required dependencies between this library and others
target_link_libraries(${PROJECT_NAME} PUBLIC "azrtos::threadx")

if(NXD_ENABLE_ADDONS AND NXD_ENABLE_FILE_SERVERS)
    message(STATUS "NXD_ENABLE_FILE_SERVERS - defined")
    target_link_libraries(${PROJECT_NAME} PUBLIC "azrtos::filex")
endif()

if(NXD_ENABLE_ADDONS AND NXD_ENABLE_AZURE_IOT)
    message(STATUS "NXD_ENABLE_AZURE_IOT - defined")
    target_link_libraries(${PROJECT_NAME} PUBLIC az_iot_hub az_iot_provisioning)
endif()

# Pick up the port specific stuff first
if(DEFINED NETXDUO_CUSTOM_PORT)
    add_subdirectory(${NETXDUO_CUSTOM_PORT} netxduo_port)
else()
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/ports/${THREADX_ARCH}/${THREADX_TOOLCHAIN})
endif()

# Then the common files
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/common)

# Pick up the apps directory containing the protocol and app-layer components
if(NXD_ENABLE_ADDONS)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/addons)
endif()

# Network security and crypto components
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/crypto_libraries)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/nx_secure)

# Utility components
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/utility)

# Link layer
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tsn)

target_include_directories(${PROJECT_NAME} 
    PUBLIC 
    ${CUSTOM_INC_DIR}
)
target_compile_definitions(${PROJECT_NAME} PUBLIC "NX_INCLUDE_USER_DEFINE_FILE" )

# Enable a build target that produces a ZIP file of all sources
set(CPACK_SOURCE_GENERATOR "ZIP")
set(CPACK_SOURCE_IGNORE_FILES
  \\.git/
  \\.github/
  _build/
  \\.git
  \\.gitattributes
  \\.gitignore
  ".*~$"
)
set(CPACK_VERBATIM_VARIABLES YES)
include(CPack)
# Portions of this file were generated with AI assistance.
