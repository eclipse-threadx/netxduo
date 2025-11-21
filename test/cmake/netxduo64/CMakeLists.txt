cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

project(netx_test LANGUAGES C)

set(NX_USER_FILE ${CMAKE_CURRENT_SOURCE_DIR}/nx_user.h)
include(${CMAKE_CURRENT_SOURCE_DIR}/../netxduo/CMakeLists.txt)

# Set build configurations
set(BUILD_CONFIGURATIONS default_build_coverage)

get_target_property(SOURCES_LIST netxduo SOURCES)
get_target_property(SOURCE_DIR netxduo SOURCE_DIR)
# Remove files not needed from netxduo
foreach(
  EXCLUDE_DIR
  nx_secure/src
  crypto_libraries/src
  addons/auto_ip
  addons/cloud
  addons/ftp
  addons/http
  addons/mdns
  addons/mqtt
  addons/nat
  addons/pop3
  addons/ppp
  addons/pppoe
  addons/ptp
  addons/rtp
  addons/rtsp
  addons/smtp
  addons/snmp
  addons/sntp
  addons/telnet
  addons/tftp
  addons/web
  addons/websocket
  utility/iperf)
  aux_source_directory(${SOURCE_DIR}/${EXCLUDE_DIR} EXCLUDE_SOURCES)
  list(REMOVE_ITEM SOURCES_LIST ${EXCLUDE_SOURCES})
endforeach()
# list(REMOVE_ITEM SOURCES_LIST ${SOURCE_DIR}/addons/dhcp/nxd_dhcpv6_client.c
#      ${SOURCE_DIR}/addons/dhcp/nxd_dhcpv6_server.c)
set_target_properties(netxduo PROPERTIES SOURCES "${SOURCES_LIST}")
