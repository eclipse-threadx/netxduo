cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
cmake_policy(SET CMP0057 NEW)

project(samples LANGUAGES C)

set(SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../samples)

set(sample_files
    ${SOURCE_DIR}/demo_netxduo_dns.c
    ${SOURCE_DIR}/demo_netxduo_ftp.c
    ${SOURCE_DIR}/demo_netxduo_http.c
    ${SOURCE_DIR}/demo_netxduo_snmp.c
    ${SOURCE_DIR}/demo_netxduo_sntp_client.c
    ${SOURCE_DIR}/demo_netxduo_telnet.c
    ${SOURCE_DIR}/demo_netxduo_tftp.c
    ${SOURCE_DIR}/demo_netx_duo_tcp.c
    ${SOURCE_DIR}/demo_netx_duo_udp.c)

if("-DNX_BSD_ENABLE" IN_LIST ${CMAKE_BUILD_TYPE})
  list(APPEND sample_files ${SOURCE_DIR}/demo_bsd_raw.c
       ${SOURCE_DIR}/demo_bsd_tcp.c ${SOURCE_DIR}/demo_bsd_udp.c)
endif()
if("-DNX_MAX_PHYSICAL_INTERFACES" IN_LIST ${CMAKE_BUILD_TYPE})
  list(APPEND sample_files ${SOURCE_DIR}/demo_netx_duo_multihome_tcp.c
       ${SOURCE_DIR}/demo_netx_duo_multihome_udp.c)
endif()
if(("-DNX_PPP_PPPOE_ENABLE" IN_LIST ${CMAKE_BUILD_TYPE})
   AND NOT ("-DNX_PPPOE_CLIENT_INITIALIZE_DRIVER_ENABLE" IN_LIST
            ${CMAKE_BUILD_TYPE}))
  list(APPEND sample_files ${SOURCE_DIR}/demo_netx_pppoe_client.c
       ${SOURCE_DIR}/demo_netx_pppoe_server.c)
endif()
if(NOT ("-DNX_DISABLE_IPV6" IN_LIST ${CMAKE_BUILD_TYPE}))
  list(APPEND sample_files ${SOURCE_DIR}/demo_netxduo_dhcpv6_client.c)
endif()
if(NOT "-DNX_DISABLE_IPV4" IN_LIST ${CMAKE_BUILD_TYPE})
  list(
    APPEND
    sample_files
    ${SOURCE_DIR}/demo_netxduo_smtp_client.c
    ${SOURCE_DIR}/demo_netxduo_multihome_dhcp_client.c
    ${SOURCE_DIR}/demo_netx_ppp.c
    ${SOURCE_DIR}/demo_netx_duo_ptp_client.c
    ${SOURCE_DIR}/demo_netxduo_dhcp.c
    ${SOURCE_DIR}/demo_netxduo_pop3_client.c
    ${SOURCE_DIR}/demo_netx_auto_ip.c)
endif()
if((NOT "-DNX_DISABLE_IPV4" IN_LIST ${CMAKE_BUILD_TYPE})
    AND NOT ("-DNX_DISABLE_PACKET_CHAIN" IN_LIST ${CMAKE_BUILD_TYPE}))
  list(APPEND sample_files ${SOURCE_DIR}/demo_netx_secure_tls.c)
endif()

if("-DNX_BSD_RAW_SUPPORT" IN_LIST ${CMAKE_BUILD_TYPE})
  set(sample_files "")
endif()

foreach(sample_file ${sample_files})
  get_filename_component(sample_file_name ${sample_file} NAME_WE)
  add_executable(${sample_file_name} ${sample_file})
  target_link_libraries(${sample_file_name} PRIVATE azrtos::${PRODUCT})
endforeach()
