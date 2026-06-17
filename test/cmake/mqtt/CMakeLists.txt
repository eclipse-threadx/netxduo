cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

if((DEFINED THREADX_ARCH) AND (THREADX_ARCH STREQUAL "win64"))
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
endif()

project(mqtt_test LANGUAGES C)

# Set build configurations
set(BUILD_CONFIGURATIONS
    default_build_coverage secure_build_coverage require_secure_build queue_depth_build
    cloud_default_build_coverage cloud_secure_build_coverage
    cloud_require_secure_build cloud_queue_depth_build
    websocket_secure_build)
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

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}.")

set(SECURE -DNX_SECURE_ENABLE)
set(REQUIRE_TLS -DNXD_MQTT_REQUIRE_TLS)
set(QUEUE_DEPTH -DNXD_MQTT_MAXIMUM_TRANSMIT_QUEUE_DEPTH=20)
set(CLOUD -DNXD_MQTT_CLOUD_ENABLE)
set(WEBSOCKET -DNXD_MQTT_OVER_WEBSOCKET)

set(default_build_coverage)
set(secure_build_coverage ${SECURE})
set(require_secure_build ${SECURE} ${REQUIRE_TLS})
set(queue_depth_build ${QUEUE_DEPTH})

set(cloud_default_build_coverage ${CLOUD})
set(cloud_secure_build_coverage ${SECURE} ${CLOUD})
set(cloud_require_secure_build ${SECURE} ${REQUIRE_TLS} ${CLOUD})
set(cloud_queue_depth_build ${CLOUD} ${QUEUE_DEPTH})

set(websocket_secure_build ${WEBSOCKET} ${SECURE} -DNX_ENABLE_EXTENDED_NOTIFY_SUPPORT)

if(MSVC)
  add_compile_options(/W3 /Zi
                      -DTX_INCLUDE_USER_DEFINE_FILE
                      ${${CMAKE_BUILD_TYPE}})
  add_link_options(/DEBUG /INCREMENTAL:NO)
  message(STATUS "Building for Win64 (MSVC)")
else()
  add_compile_options(
    -m32
    -ggdb
    -g3
    -gdwarf-2
    -fdiagnostics-color
    -DTX_INCLUDE_USER_DEFINE_FILE
    ${${CMAKE_BUILD_TYPE}})
  add_link_options(-m32)
  message(STATUS "Building for 32bit")
endif()

enable_testing()

# On Windows, build ThreadX and FileX from source before netxduo is configured.
if(MSVC)
  if(NOT DEFINED THREADX_SOURCE_DIR)
    message(FATAL_ERROR
      "THREADX_SOURCE_DIR must point to a ThreadX source tree. "
      "Pass -DTHREADX_SOURCE_DIR=<path> or use build_mqtt.ps1.")
  endif()
  if(NOT DEFINED FILEX_SOURCE_DIR)
    message(FATAL_ERROR
      "FILEX_SOURCE_DIR must point to a FileX source tree. "
      "Pass -DFILEX_SOURCE_DIR=<path> or use build_mqtt.ps1.")
  endif()
  add_subdirectory(${THREADX_SOURCE_DIR} threadx_build)
  add_subdirectory(${FILEX_SOURCE_DIR} filex_build)
endif()

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../.. netxduo)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/regression regression)

# Coverage instrumentation (GCC/Clang only — not supported by MSVC)
if(NOT MSVC AND CMAKE_BUILD_TYPE MATCHES ".*_coverage")
  target_compile_options(netxduo PRIVATE -fprofile-arcs -ftest-coverage)
  target_link_options(netxduo PRIVATE -fprofile-arcs -ftest-coverage)
endif()

# Build ThreadX and FileX shared libraries (Linux only)
if(NOT MSVC)
  execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run.sh build_libs)
  add_custom_target(build_libs ALL COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run.sh
                                           build_libs)
  add_dependencies(netxduo build_libs)
  target_include_directories(netxduo PUBLIC ${CMAKE_BINARY_DIR}/../libs/inc)
  add_library(threadx SHARED IMPORTED GLOBAL)
  add_library("azrtos::threadx" ALIAS threadx)
  set_target_properties(
    threadx PROPERTIES IMPORTED_LOCATION
                       ${CMAKE_BINARY_DIR}/../libs/threadx/libthreadx.so)
  add_library(filex SHARED IMPORTED GLOBAL)
  add_library("azrtos::filex" ALIAS filex)
  set_target_properties(
    filex PROPERTIES IMPORTED_LOCATION
                     ${CMAKE_BINARY_DIR}/../libs/filex/libfilex.so)
  target_link_libraries(netxduo PUBLIC filex)
endif()

if(MSVC)
  target_compile_options(netxduo PRIVATE /W3)
else()
  target_compile_options(
    netxduo
    PRIVATE -Werror
            -std=c99
            -Wall
            -Wextra
            -pedantic
            -fmessage-length=0
            -fsigned-char
            -ffunction-sections
            -fdata-sections
            -Wunused
            -Wuninitialized
            -Wmissing-declarations
            -Wconversion
            -Wpointer-arith
            -Wshadow
            -Wlogical-op
            -Waggregate-return
            -Wfloat-equal)
endif()
