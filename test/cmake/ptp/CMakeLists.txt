cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

if((DEFINED THREADX_ARCH) AND (THREADX_ARCH STREQUAL "win64"))
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
endif()

project(web_test LANGUAGES C)

# Set build configurations
set(BUILD_CONFIGURATIONS default_build_coverage
                         gptp_slave_build
                         gptp_master_build)
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

if(NOT PRODUCT)
  set(PRODUCT netxduo)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}.")

set(SECURE -DNX_WEB_HTTPS_ENABLE -DNX_TCPSERVER_ENABLE_TLS -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY)
set(MULTIPART -DNX_WEB_HTTP_MULTIPART_ENABLE)
set(DIGEST -DNX_WEB_HTTP_DIGEST_ENABLE)

set(GPTP -DNX_ENABLE_GPTP -DNX_PTP_CLIENT_TRANSPORT_UDP=0 -DNX_PTP_CLIENT_TRANSPORT_ETHERNET=1)
set(VLAN -DNX_ENABLE_VLAN)
set(gptp_slave_build ${GPTP} ${VLAN})
set(gptp_master_build ${GPTP} ${VLAN} -DNX_PTP_ENABLE_MASTER)

if(MSVC)
  add_compile_options(/W3 /Zi
                      -std=c99
                      -DTX_INCLUDE_USER_DEFINE_FILE
                      ${${CMAKE_BUILD_TYPE}})
  add_link_options(/DEBUG /INCREMENTAL:NO)
  message(STATUS "Building for Win64 (MSVC)")
else()
  add_compile_options(
    -m32
    -std=c99
    -ggdb
    -g3
    -gdwarf-2
    -fdiagnostics-color
    -Werror
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
      "Pass -DTHREADX_SOURCE_DIR=<path> or use build_ptp.ps1.")
  endif()
  if(NOT DEFINED FILEX_SOURCE_DIR)
    message(FATAL_ERROR
      "FILEX_SOURCE_DIR must point to a FileX source tree. "
      "Pass -DFILEX_SOURCE_DIR=<path> or use build_ptp.ps1.")
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
