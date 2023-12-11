cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

project(netx_test LANGUAGES C)

set(NX_USER_FILE ${CMAKE_CURRENT_SOURCE_DIR}/nx_user.h)
include(${CMAKE_CURRENT_SOURCE_DIR}/../netxduo/CMakeLists.txt)

# Set build configurations
set(BUILD_CONFIGURATIONS v6_full_build)