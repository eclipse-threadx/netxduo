cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

if(NOT DEFINED THREADX_ARCH)
  if(WIN32)
    set(CMAKE_TOOLCHAIN_FILE
        "configs/win32.cmake"
        CACHE STRING "")
  elseif(UNIX)
    set(CMAKE_TOOLCHAIN_FILE
        "configs/linux.cmake"
        CACHE STRING "")
  else()
    message(FATAL_ERROR "Error: Architecture not supported")
  endif()
endif()

# Project
project(AzureIoTMiddleware LANGUAGES C ASM)

# Set build configurations
if(NOT WIN32)
set(BUILD_CONFIGURATIONS
    default_build_coverage disable_precondition_build disable_security_module_build)
set(CMAKE_CONFIGURATION_TYPES
    ${BUILD_CONFIGURATIONS}
    CACHE STRING "list of supported configuration types" FORCE)
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                                              ${CMAKE_CONFIGURATION_TYPES})
list(GET CMAKE_CONFIGURATION_TYPES 0 BUILD_TYPE)
if((NOT CMAKE_BUILD_TYPE) OR (NOT ("${CMAKE_BUILD_TYPE}" IN_LIST
                                    CMAKE_CONFIGURATION_TYPES)))
  set(CMAKE_BUILD_TYPE
      "${BUILD_TYPE}"
      CACHE STRING "Build Type of the project" FORCE)
endif()
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}.")

set(default_build_coverage)
set(disable_precondition_build -DAZ_NO_PRECONDITION_CHECKING -DAZ_NO_LOGGING -DNX_DISABLE_IPV6)

# Set property for folder
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(DISABLE_TEST
    OFF
    CACHE BOOL "Disable test projects (default is OFF)")

# CFLAGS
if(WIN32)
  set(ADDITIONAL_C_FLAGS $ENV{CFLAGS} "/MP -DWIN32 -D_CRT_SECURE_NO_WARNINGS")
else()
  if(THREADX_ARCH STREQUAL "linux")
    set(ADDITIONAL_C_FLAGS
        "$ENV{CFLAGS} -O0 -g3 -ggdb -m32 -gdwarf-2 -fdiagnostics-color -fprofile-arcs -ftest-coverage -Wno-error=misleading-indentation")
  endif()
  set(ADDITIONAL_C_FLAGS_AZURE_SERVICES
      "-std=c99 -Werror -Wall -Wextra -pedantic -fmessage-length=0 -fsigned-char -ffunction-sections -fdata-sections -Wunused -Wuninitialized -Wmissing-declarations -Wconversion -Wpointer-arith -Wshadow -Wlogical-op -Wfloat-equal -fprofile-arcs -ftest-coverage -Wjump-misses-init -Wno-error=misleading-indentation"
  )
endif()

# Add definitions
add_definitions(
  ${ADDITIONAL_C_FLAGS}
  ${DRIVER_FLAG}
  -DNX_PCAP_SOURCE_NAME=\"${PCAP_NAME}\"
  -DNX_ENABLE_EXTENDED_NOTIFY_SUPPORT
  -DNX_SECURE_ENABLE
  -DNX_DNS_CLIENT_USER_CREATE_PACKET_POOL
  -DNX_DNS_CLIENT_CLEAR_QUEUE
  -DNXD_MQTT_CLOUD_ENABLE
  -DNX_SNTP_CLIENT_MAX_ROOT_DISPERSION=0
  -DNX_SNTP_CLIENT_MIN_SERVER_STRATUM=3
  -DNX_ENABLE_IP_PACKET_FILTER
  -DNX_SECURE_TLS_DISABLE_TLS_1_1
  -DNXD_MQTT_PING_TIMEOUT_DELAY=500
  -DNXD_MQTT_SOCKET_TIMEOUT=0
  -DNXD_MQTT_OVER_WEBSOCKET
  -DNX_AZURE_IOT_ADU_AGENT_PROXY_UPDATE_COUNT=1
  ${${CMAKE_BUILD_TYPE}})

# Include azure rtos cmake
include(configs/azure_rtos_src.cmake)

# Link libraries
if(THREADX_ARCH STREQUAL "linux")
  add_link_options(-m32 -fprofile-arcs -ftest-coverage)
endif()

if((NOT DISABLE_TEST) AND UNIX)
  # Include tests cmake
  include(configs/azure_rtos_tests.cmake)
endif()
