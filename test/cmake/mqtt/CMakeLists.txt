cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

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

add_compile_options(
  -m32
  -ggdb
  -g3
  -gdwarf-2
  -fdiagnostics-color
  -DTX_INCLUDE_USER_DEFINE_FILE
  ${${CMAKE_BUILD_TYPE}})
add_link_options(-m32)

enable_testing()

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../.. netxduo)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/regression regression)

# Coverage
#
# The gate here used to be the build type alone, and only 32 of the 110 build
# configurations across the ten suites have a name matching "*_coverage" -- 4
# of netxduo's 43, and none of netxduo_fast's. So 78 configurations built and
# ran every test and their coverage was thrown away. That is not redundancy
# discarded: each configuration selects a different set of NX_ feature macros,
# so the code the others compile is *absent from the denominator* rather than
# reported as uncovered, and thirteen files of common/src were absent from
# every report because no instrumented configuration compiled them at all.
#
# TX_COVERAGE instruments a build regardless of its name. It defaults to OFF
# and the build-type match is kept, exactly as threadx does it: the pinned
# cmake_bootstrap.sh collects coverage on that same name match as well as on
# TX_COVERAGE, and that file is threadx's rather than ours. Dropping the match
# here would leave a by-hand run of a *_coverage configuration building
# uninstrumented while the runner still called coverage.sh on it, which now
# fails on an empty report. The two switches are reconciled where it matters
# instead: coverage_merge.sh refuses to publish a figure unless every
# configuration of every contributing suite is present in the merge set, so a
# partial set cannot be read as the component's number.
option(TX_COVERAGE "Instrument this build for coverage regardless of build type" OFF)
if(TX_COVERAGE OR CMAKE_BUILD_TYPE MATCHES ".*_coverage")
  target_compile_options(netxduo PRIVATE -fprofile-arcs -ftest-coverage)
  target_link_options(netxduo PRIVATE -fprofile-arcs -ftest-coverage)
endif()

# Build ThreadX library once
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
