cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

project(web_test LANGUAGES C)

# Set build configurations
set(BUILD_CONFIGURATIONS default_build_coverage no_tls_build_coverage
                         digest_authenticate_build)
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

set(SECURE -DNX_WEB_HTTPS_ENABLE -DNX_TCPSERVER_ENABLE_TLS -DNX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY)
set(MULTIPART -DNX_WEB_HTTP_MULTIPART_ENABLE)
set(DIGEST -DNX_WEB_HTTP_DIGEST_ENABLE)

set(default_build_coverage ${SECURE} ${MULTIPART} -DNX_ENABLE_EXTENDED_NOTIFY_SUPPORT)
set(no_tls_build_coverage ${MULTIPART})
set(digest_authenticate_build ${SECURE} ${MULTIPART} ${DIGEST})

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
