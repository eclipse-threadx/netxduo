cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

project(crypto_test LANGUAGES C)

set(CPU_ARCH "linux")
set(COMPILER "gnu")

# Set build configurations
set(BUILD_CONFIGURATIONS default_build_coverage fips_build_coverage
                         standalone_build curve25519_448_build)
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

set(default_build_coverage "")
set(fips_build_coverage -DNX_CRYPTO_SELF_TEST)
set(standalone_build -DNX_CRYPTO_STANDALONE_ENABLE -DNX_CRYPTO_SELF_TEST)
set(curve25519_448_build -DNX_CRYPTO_ENABLE_CURVE25519_448)

add_compile_options(
  -std=c99
  -ggdb
  -g3
  -gdwarf-2
  -fdiagnostics-color
  -Werror
  ${${CMAKE_BUILD_TYPE}})

if($ENV{ENABLE_64})
  message(STATUS "Building for 64bit")
else()
  add_compile_options(-m32)
  add_link_options(-m32)
  message(STATUS "Building for 32bit")
endif()

enable_testing()

set(NXD_ENABLE_FILE_SERVERS
    OFF
    CACHE BOOL
          "Includes a dependency on FileX to support 'server' protocol handlers"
          FORCE)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../.. netxduo)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/regression regression)


# Coverage
if(CMAKE_BUILD_TYPE MATCHES ".*_coverage")
  target_compile_options(netxduo PRIVATE -fprofile-arcs -ftest-coverage)
  target_link_options(netxduo PRIVATE -fprofile-arcs -ftest-coverage)
endif()

# Build ThreadX library once
if(NOT ("${CMAKE_BUILD_TYPE}" STREQUAL "standalone_build"))
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
endif()

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

# Leave files from crypto_libraries only
get_target_property(SOURCES_LIST netxduo SOURCES)
set(NEW_SOURCES_LIST "")
foreach(SOURCE ${SOURCES_LIST})
  if(("${SOURCE}" MATCHES ".*crypto_libraries/.*")
     AND NOT (("${SOURCE}" MATCHES ".*nx_crypto_module_start.*")
              OR (("${SOURCE}" MATCHES ".*nx_crypto_generic_ciphersuites.*")
                  AND ("${CMAKE_BUILD_TYPE}" STREQUAL "standalone_build"))))
    list(APPEND NEW_SOURCES_LIST ${SOURCE})
  endif()
endforeach()
set_target_properties(netxduo PROPERTIES SOURCES "${NEW_SOURCES_LIST}")

if("${CMAKE_BUILD_TYPE}" STREQUAL "standalone_build")
  set_target_properties(netxduo PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/../../../crypto_libraries/inc")
  target_include_directories(netxduo PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}/../../../crypto_libraries/ports/${CPU_ARCH}/${COMPILER}/inc")
  set_target_properties(netxduo PROPERTIES LINK_LIBRARIES "")
  set_target_properties(netxduo PROPERTIES INTERFACE_LINK_LIBRARIES "")
endif()
