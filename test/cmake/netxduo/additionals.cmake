cmake_minimum_required(VERSION 3.13.0 FATAL_ERROR)

# See https://cmake.org/cmake/help/latest/policy/CMP0079.html for more info
cmake_policy(SET CMP0079 NEW)

target_include_directories(netxduo PUBLIC ${SOURCE_DIR})

get_target_property(SOURCES_LIST netxduo SOURCES)
get_target_property(SOURCE_DIR netxduo SOURCE_DIR)

if("-DNX_DISABLE_PACKET_CHAIN" IN_LIST ${CMAKE_BUILD_TYPE})
  # Remove nx_secure from build
  aux_source_directory(${SOURCE_DIR}/nx_secure/src SECURE_SOURCES)
  list(REMOVE_ITEM SOURCES_LIST ${SECURE_SOURCES})
  # Remove MQTT from build
  list(REMOVE_ITEM SOURCES_LIST ${SOURCE_DIR}/addons/mqtt/nxd_mqtt_client.c)
  # Remove WebSocket from build
  list(REMOVE_ITEM SOURCES_LIST ${SOURCE_DIR}/addons/websocket/nx_websocket_client.c)
  # Remove RTP from build
  list(REMOVE_ITEM SOURCES_LIST ${SOURCE_DIR}/addons/rtp/nx_rtp_sender.c)
endif()
set_target_properties(netxduo PROPERTIES SOURCES "${SOURCES_LIST}")
