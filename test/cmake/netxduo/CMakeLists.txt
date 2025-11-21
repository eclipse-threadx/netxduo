cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
cmake_policy(SET CMP0054 NEW)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0077 NEW)

project(netxduo_test LANGUAGES C)

# Set build configurations
set(BUILD_CONFIGURATIONS
    default_build_coverage
    dhcp_default_build_coverage
    dns_default_build_coverage
    tsn_build_coverage
    v4_build
    v4_dns_cache_build
    v4_no_checksum_build
    v4_physical_48_build
    v4_small_build
    v4_packet_pad_build
    v4_full_build
    v4_no_frag_build
    v4_no_check_build
    v4_no_reset_disconn_build
    v4_dual_pool_build
    v4_no_chain_build
    v4_link_cap_build
    v4_address_check_build
    v6_build
    v6_only_build
    v6_only_link_cap_build
    v6_no_checksum_build
    v6_dual_pool_build
    v6_packet_pad_build
    v6_physical_48_build
    v6_small_nd_cache_build
    v6_small_build
    v6_full_build
    v6_no_frag_build
    v6_pmtu_no_frag_build
    v6_no_chain_build
    v6_no_dad_build
    v6_no_check_build
    v6_no_icmpv6_error_build
    v6_no_reset_disconn_build
    v6_link_cap_build
    v6_address_change_build
    v6_multicast_build
    v6_no_rs_build
    v6_dhcp_tahi_build
    v6_bsd_raw_build
    v6_full_secure_build
    optimize_build)
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

message(STATUS "Build for ${PRODUCT}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}.")

set(IPV4 -DNX_DISABLE_IPV6)
set(DISABLE_RX_CHECKSUM
    -DNX_DISABLE_ICMPV4_RX_CHECKSUM -DNX_DISABLE_ICMPV6_RX_CHECKSUM
    -DNX_DISABLE_IP_RX_CHECKSUM -DNX_DISABLE_TCP_RX_CHECKSUM
    -DNX_DISABLE_UDP_RX_CHECKSUM)
set(DISABLE_TX_CHECKSUM
    -DNX_DISABLE_ICMPV4_TX_CHECKSUM -DNX_DISABLE_ICMPV6_TX_CHECKSUM
    -DNX_DISABLE_IP_TX_CHECKSUM -DNX_DISABLE_TCP_TX_CHECKSUM
    -DNX_DISABLE_UDP_TX_CHECKSUM)
set(PHY_HEADER -DNX_PHYSICAL_HEADER=48)
set(NO_INFO
    -DNX_DISABLE_ARP_INFO
    -DNX_DISABLE_IP_INFO
    -DNX_DISABLE_ICMP_INFO
    -DNX_DISABLE_PACKET_INFO
    -DNX_DISABLE_RARP_INFO
    -DNX_DISABLE_TCP_INFO
    -DNX_DISABLE_UDP_INFO)
set(NO_FRAG -DNX_DISABLE_FRAGMENTATION)
set(NO_CHECK -DTX_DISABLE_ERROR_CHECKING -DNX_DISABLE_ERROR_CHECKING)
set(NO_RESET_DISCONNECT -DNX_DISABLE_RESET_DISCONNECT)
set(NO_AUTO_ARP_ENTRY -DNX_DISABLE_ARP_AUTO_ENTRY)
set(IMME_ACK -DNX_TCP_ACK_EVERY_N_PACKETS=1)
set(NO_LOOPBACK -DNX_DISABLE_LOOPBACK_INTERFACE)
set(NO_RX_SIZE_CHECK -DNX_DISABLE_RX_SIZE_CHECKING)
set(NO_IGMPV2 -DNX_DISABLE_IGMPV2)
set(TCP_KEEPALIVE -DNX_ENABLE_TCP_KEEPALIVE -DNX_TCP_KEEPALIVE_INITIAL=60
                  -DTCP_KEEPALIVE_RETRY -DNX_TCP_KEEPALIVE_RETRY=10)
set(TCP_WINDOW -DNX_ENABLE_TCP_WINDOW_SCALING)
set(IP_STATIC_ROUTING -DNX_ENABLE_IP_STATIC_ROUTING)
set(PACKET_ALIGNMENT -DNX_PACKET_ALIGNMENT=64)
set(MULTI_INTERFACE -DNX_MAX_PHYSICAL_INTERFACES=4
                    -DNX_DHCP_CLIENT_MAX_RECORDS=2)
set(IMME_FRAG_ASSEMBLY -DNX_FRAGMENT_IMMEDIATE_ASSEMBLY)
set(MSS_CHECK -DNX_ENABLE_TCP_MSS_CHECK -DNX_TCP_MSS_MINIMUM=32)
set(TCP_QUEUE_NOTIFY -DNX_ENABLE_TCP_QUEUE_DEPTH_UPDATE_NOTIFY)
set(ARP_EXPIRATION_RATE -DNX_ARP_EXPIRATION_RATE=5)
set(NAT -DNX_NAT_ENABLE)
set(IP_PACKET_FILTER -DNX_ENABLE_IP_PACKET_FILTER)
set(TRACE -DTX_ENABLE_EVENT_TRACE)
set(BSD
    -D__suseconds_t_defined
    -D_STRUCT_TIMEVAL
    -D_SYS_SELECT_H
    -DNX_ENABLE_EXTENDED_NOTIFY_SUPPORT
    -DNX_BSD_SOCKET_QUEUE_MAX=20
    -DNX_BSD_ENABLE
    -DNX_IPV6_NEIGHBOR_CACHE_SIZE=32
    -DNX_IPV6_DESTINATION_TABLE_SIZE=32
    -DNX_BSD_ENABLE_DNS
    -DNX_DNS_ENABLE_EXTENDED_RR_TYPES)
set(TAHI -DNX_TAHI_ENABLE)
set(IPV6 -DFEATURE_NX_IPV6)
set(IPV6_PMTU_DISCOVERY -DNX_ENABLE_IPV6_PATH_MTU_DISCOVERY)
set(NO_DAD -DNX_DISABLE_IPV6_DAD)
set(NO_ICMPV6_ERROR -DNX_DISABLE_ICMPV6_ERROR_MESSAGE)
set(NO_CHAIN -DNX_DISABLE_PACKET_CHAIN -DNX_DISABLE_FRAGMENTATION)
set(LINK_CAP -DNX_ENABLE_INTERFACE_CAPABILITY)
set(ADDRESS_CHANGE_NOTIFY -DNX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY)
set(ADDRESS_CHECK -DNX_ENABLE_SOURCE_ADDRESS_CHECK
                  -DNX_ENABLE_ICMP_ADDRESS_CHECK)
set(MULTICAST -DNX_ENABLE_IPV6_MULTICAST)
set(LOW_WATERMARK -DNX_ENABLE_LOW_WATERMARK)
if(PRODUCT STREQUAL netxduo)
  set(BSD_RAW ${BSD} -DNX_BSD_RAW_SUPPORT -DNX_ENABLE_IP_RAW_PACKET_FILTER
              -DNX_BSD_RAW_PPPOE_SUPPORT -DNX_ENABLE_IP_RAW_PACKET_FILTER)
  list(REMOVE_ITEM BSD_RAW -DNX_BSD_RAW_PPPOE_SUPPORT)
  set(RAW_FILTER -DNX_ENABLE_IP_RAW_PACKET_FILTER)
  set(RAW_ALL_STACK -DNX_ENABLE_IP_RAW_PACKET_ALL_STACK)
endif()
set(NO_REDIRECT_PROCESS -DNX_DISABLE_ICMPV6_REDIRECT_PROCESS)
set(NO_RA_PROCESS -DNX_DISABLE_ICMPV6_ROUTER_ADVERTISEMENT_PROCESS)
set(NO_RS -DNX_DISABLE_ICMPV6_ROUTER_SOLICITATION)
set(STATELESS_AC -DNX_IPV6_STATELESS_AUTOCONFIG_CONTROL)
set(NO_PURGE_UNUSED_CACHE -DNX_DISABLE_IPV6_PURGE_UNUSED_CACHE_ENTRIES)
set(PACKET_PAD -DNX_PACKET_HEADER_PAD=4)
set(MSS_CHECK -DNX_ENABLE_TCP_MSS_CHECK -DNX_TCP_MSS_MINIMUM=32)
set(DUAL_POOL -DNX_ENABLE_DUAL_PACKET_POOL)
set(DHCPV6_TAHI -DNX_DHCPV6_TAHI_ENABLE)
set(MULTIPART -DNX_HTTP_MULTIPART_ENABLE)
set(PACKET_DEBUG -DNX_ENABLE_PACKET_DEBUG_INFO)
set(TCP_RX_LIMIT -DNX_TCP_MAX_OUT_OF_ORDER_PACKETS=8)
set(TELNET_MAX_CLIENTS -DNX_TELNET_MAX_CLIENTS=2)
set(TELNET_ACTIVITY_TIMEOUT -DNX_TELNET_ACTIVITY_TIMEOUT=10)
set(TELNET_TIMEOUT_PERIOD -DNX_TELNET_TIMEOUT_PERIOD=2)
set(CREATE_TELNET_PACKET_POOL -DNX_TELNET_SERVER_USER_CREATE_PACKET_POOL)
set(LCP_PROTOCOL_RETRIES -DNX_PPP_MAX_LCP_PROTOCOL_RETRIES=5)
set(IPCP_PROTOCOL_RETRIES -DNX_PPP_MAX_IPCP_PROTOCOL_RETRIES=5)
set(PREFIX_LIMIT -DNX_IPV6_PREFIX_LIST_TABLE_SIZE=4)
set(LARGE_DEST_TABLE -DNX_IPV6_DESTINATION_TABLE_SIZE=32)
set(ND_CACHE_LIMIT -DNX_IPV6_NEIGHBOR_CACHE_SIZE=8)
set(TX_RX_INTERFACE_CAPABILITY
    -DNX_INTERFACE_CAPABILITY=NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM|NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM|NX_INTERFACE_CAPABILITY_UDP_TX_CHECKSUM|NX_INTERFACE_CAPABILITY_ICMPV4_TX_CHECKSUM|NX_INTERFACE_CAPABILITY_ICMPV6_TX_CHECKSUM|NX_INTERFACE_CAPABILITY_IGMP_TX_CHECKSUM|NX_INTERFACE_CAPABILITY_IPV4_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_TCP_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_UDP_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_ICMPV4_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_ICMPV6_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_IGMP_RX_CHECKSUM
)
set(RX_INTERFACE_CAPABILITY
    -DNX_INTERFACE_CAPABILITY=NX_INTERFACE_CAPABILITY_IPV4_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_TCP_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_UDP_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_ICMPV4_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_ICMPV6_RX_CHECKSUM|NX_INTERFACE_CAPABILITY_IGMP_RX_CHECKSUM
)
set(NO_INTERFACE_CAPABILITY -DNX_INTERFACE_CAPABILITY=0)
set(DHCP_ARP_PROBE -DNX_DHCP_CLIENT_SEND_ARP_PROBE)
set(NO_ASSERT -DNX_DISABLE_ASSERT)
set(NO_IPV4 -DNX_DISABLE_IPV4)
set(MDNS_IPV6 -DNX_MDNS_ENABLE_IPV6 -DFEATURE_NX_IPV6
              -DNX_ENABLE_IPV6_MULTICAST -DNX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY)
set(MDNS_NO_CLIENT -DNX_MDNS_DISABLE_CLIENT)
set(MDNS_NO_SERVER -DNX_MDNS_DISABLE_SERVER)
set(PPPOE -DNX_PPP_PPPOE_ENABLE -DNX_PPPOE_SERVER_INITIALIZE_DRIVER_ENABLE
          -DNX_PPPOE_CLIENT_INITIALIZE_DRIVER_ENABLE)
set(PPPOE_CONTROL -DNX_PPPOE_SERVER_SESSION_CONTROL_ENABLE)
set(HTTP_DIGEST -DNX_HTTP_DIGEST_ENABLE)
set(DHCP_RESTORE -DNX_DHCP_CLIENT_RESTORE_STATE)
set(DNS_CACHE -DNX_DNS_CACHE_ENABLE)
set(TCPIP_OFFLOAD -DNX_ENABLE_TCPIP_OFFLOAD ${LINK_CAP})
set(ARP -DNX_ARP_DEFEND_BY_REPLY)
set(HTTP_PROXY -DNX_ENABLE_HTTP_PROXY)
set(RAND_ID -DNX_ENABLE_IP_ID_RANDOMIZATION)
set(PPP_COMPRESSION -DNX_PPP_COMPRESSION_ENABLE)

set(v4_build ${IPV4} ${PACKET_DEBUG})
set(v4_dns_cache_build ${IPV4} ${DNS_CACHE})
set(v4_no_checksum_build ${IPV4} ${DISABLE_TX_CHECKSUM} ${DISABLE_RX_CHECKSUM})
set(v4_physical_48_build ${IPV4} ${PHY_HEADER} ${MDNS_NO_CLIENT} ${PPPOE} ${MULTI_INTERFACE})
set(v4_small_build
    ${IPV4}
    ${NO_INFO}
    ${NO_FRAG}
    ${NO_CHECK}
    ${NO_RESET_DISCONNECT}
    ${NO_AUTO_ARP_ENTRY}
    ${IMME_ACK}
    ${NO_LOOPBACK}
    ${NO_RX_SIZE_CHECK}
    ${NO_IGMPV2}
    ${RAND_ID})
set(v4_packet_pad_build ${IPV4} ${PACKET_ALIGNMENT})
set(v4_full_build
    ${IPV4}
    ${TCP_KEEPALIVE}
    ${TCP_WINDOW}
    ${IP_STATIC_ROUTING}
    ${BSD}
    ${MULTI_INTERFACE}
    ${IMME_FRAG_ASSEMBLY}
    ${MSS_CHECK}
    ${TCP_QUEUE_NOTIFY}
    ${RAW_FILTER}
    ${ARP_EXPIRATION_RATE}
    ${MULTIPART}
    ${NAT}
    ${PACKET_DEBUG}
    ${DUAL_POOL}
    ${IP_PACKET_FILTER}
    ${CREATE_TELNET_PACKET_POOL}
    ${TELNET_MAX_CLIENTS}
    ${TELNET_ACTIVITY_TIMEOUT}
    ${TELNET_TIMEOUT_PERIOD}
    ${LCP_PROTOCOL_RETRIES}
    ${IPCP_PROTOCOL_RETRIES}
    ${DHCP_ARP_PROBE}
    ${TRACE}
    ${DHCP_RESTORE}
    ${DNS_CACHE}
    ${ARP}
    ${HTTP_PROXY}
    ${PPP_COMPRESSION})
set(v4_no_frag_build ${IPV4} ${NO_FRAG})
set(v4_no_check_build ${IPV4} ${NO_CHECK})
set(v4_no_reset_disconn_build ${IPV4} ${NO_RESET_DISCONNECT})

# netxduo only
set(v4_dual_pool_build ${IPV4} ${DUAL_POOL})
set(v4_no_chain_build ${IPV4} ${NO_CHAIN} ${MDNS_NO_SERVER})
set(v4_link_cap_build ${IPV4} ${LINK_CAP} ${RX_INTERFACE_CAPABILITY}
                      ${MULTI_INTERFACE} ${TCPIP_OFFLOAD})
set(v4_address_check_build ${IPV4} ${ADDRESS_CHECK})
set(v6_build ${IPV6})
set(v6_only_build ${IPV6} ${NO_IPV4} ${TRACE} ${MDNS_NO_CLIENT})
set(v6_only_link_cap_build ${IPV6} ${NO_IPV4} ${LINK_CAP})
set(v6_no_checksum_build ${IPV6} ${DISABLE_TX_CHECKSUM} ${DISABLE_RX_CHECKSUM})
set(v6_dual_pool_build ${IPV6} ${DUAL_POOL})
set(v6_packet_pad_build ${IPV6} ${PACKET_PAD})
set(v6_physical_48_build ${IPV6} ${PHY_HEADER} ${MDNS_NO_SERVER} ${PPPOE} ${PPPOE_CONTROL})
set(v6_small_nd_cache_build ${IPV6} ${MULTI_INTERFACE} ${ND_CACHE_LIMIT}
                            ${NO_PURGE_UNUSED_CACHE} ${LARGE_DEST_TABLE})
set(v6_small_build
    ${IPV6}
    ${NO_INFO}
    ${NO_FRAG}
    ${NO_DAD}
    ${NO_CHECK}
    ${NO_ICMPV6_ERROR}
    ${NO_RESET_DISCONNECT}
    ${NO_REDIRECT_PROCESS}
    ${NO_RA_PROCESS}
    ${NO_RS}
    ${NO_PURGE_UNUSED_CACHE}
    ${IMME_ACK}
    ${NO_LOOPBACK}
    ${NO_RX_SIZE_CHECK}
    ${PACKET_ALIGNMENT}
    ${PREFIX_LIMIT}
    ${MDNS_NO_SERVER}
    ${RAND_ID})
set(v6_full_build
    ${IPV6}
    ${IPV6_PMTU_DISCOVERY}
    ${TCP_KEEPALIVE}
    ${TCP_KEEPALIVE_INITIAL}
    ${TCP_KEEPALIVE_RETRY}
    ${TCP_KEEPALIVE_RETRIES}
    ${TCP_WINDOW}
    ${IP_STATIC_ROUTING}
    ${TAHI}
    ${BSD}
    ${MULTI_INTERFACE}
    ${STATELESS_AC}
    ${IMME_FRAG_ASSEMBLY}
    ${MSS_CHECK}
    ${TCP_QUEUE_NOTIFY}
    ${RAW_FILTER}
    ${RAW_ALL_STACK}
    ${ADDRESS_CHANGE_NOTIFY}
    ${MULTIPART}
    ${NAT}
    ${PACKET_DEBUG}
    ${DUAL_POOL}
    ${IP_PACKET_FILTER}
    ${DHCP_ARP_PROBE}
    ${MDNS_IPV6}
    ${HTTP_DIGEST}
    ${DHCP_RESTORE}
    ${DNS_CACHE}
    ${TCPIP_OFFLOAD}
    ${ARP}
    ${HTTP_PROXY}
    ${PPP_COMPRESSION})
set(v6_full_secure_build
    ${v6_full_build}
    -DNX_SECURE_ENABLE)
set(v6_no_frag_build ${IPV6} ${NO_FRAG})
set(v6_pmtu_no_frag_build ${v6_no_frag_build} ${IPV6_PMTU_DISCOVERY})
set(v6_no_chain_build ${IPV6} ${NO_CHAIN} ${MDNS_NO_CLIENT})
set(v6_no_dad_build ${IPV6} ${NO_DAD})
set(v6_no_check_build ${IPV6} ${NO_CHECK} ${TAHI} ${IPV6_PMTU_DISCOVERY})
set(v6_no_icmpv6_error_build ${IPV6} ${NO_ICMPV6_ERROR})
set(v6_no_reset_disconn_build ${IPV6} ${NO_RESET_DISCONNECT} ${TAHI}
                              ${IPV6_PMTU_DISCOVERY})
set(v6_link_cap_build ${IPV6} ${LINK_CAP} ${TX_RX_INTERFACE_CAPABILITY}
                      ${MULTI_INTERFACE})
set(v6_address_change_build ${IPV6} ${ADDRESS_CHANGE_NOTIFY} ${MDNS_NO_SERVER})
set(v6_multicast_build ${IPV6} ${MULTICAST} ${MULTI_INTERFACE})
set(v6_no_rs_build ${IPV6} ${STATELESS_AC} ${NO_RS})
set(v6_dhcp_tahi_build ${IPV6} ${ADDRESS_CHANGE_NOTIFY} ${DHCPV6_TAHI} ${TAHI}
                       ${IPV6_PMTU_DISCOVERY})
set(v6_bsd_raw_build ${IPV6} ${BSD_RAW} ${MULTI_INTERFACE} ${RAW_ALL_STACK})
set(default_build_coverage -DNX_TAHI_ENABLE -DNX_MAX_PHYSICAL_INTERFACES=4 -DNX_ENABLE_IPV6_PATH_MTU_DISCOVERY)
set(optimize_build ${default_build_coverage} -O3)
set(dhcp_default_build_coverage ${default_build_coverage} -DNX_DHCP_CLIENT_USER_CREATE_PACKET_POOL -DNX_DISABLE_ASSERT)
set(dns_default_build_coverage ${default_build_coverage}  -DNX_DNS_CLIENT_USER_CREATE_PACKET_POOL -DNX_DNS_CLIENT_CLEAR_QUEUE)
set(tsn_build_coverage ${default_build_coverage} ${PHY_HEADER} -DNX_ENABLE_VLAN)

if($ENV{ENABLE_64})
  message(STATUS "Building for 64bit")
  set(NXD_ENABLE_FILE_SERVERS OFF)
else()
  add_compile_options(-m32)
  add_link_options(-m32)
  message(STATUS "Building for 32bit")
  set(NXD_ENABLE_FILE_SERVERS ON)
endif()
add_compile_options(
  -std=c99
  -ggdb
  -g3
  -gdwarf-2
  -fdiagnostics-color
  # -Werror
  -DTX_INCLUDE_USER_DEFINE_FILE
  ${${CMAKE_BUILD_TYPE}})

enable_testing()

if("-DNX_BSD_ENABLE" IN_LIST ${CMAKE_BUILD_TYPE})
  set(NXD_ENABLE_BSD ON)
endif()
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../.. ${PRODUCT})
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/regression regression)
if(NOT "$ENV{ENABLE_64}")
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/samples samples)
  if(PRODUCT STREQUAL netxduo)
    include(additionals.cmake)
  endif()
endif()

# Coverage
if(CMAKE_BUILD_TYPE MATCHES ".*_coverage")
  target_compile_options(${PRODUCT} PRIVATE -fprofile-arcs -ftest-coverage)
  target_link_options(${PRODUCT} PRIVATE -fprofile-arcs -ftest-coverage)
endif()

# Build ThreadX library once
execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run.sh build_libs)
add_custom_target(build_libs ALL COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run.sh
                                         build_libs)
add_dependencies(${PRODUCT} build_libs)
target_include_directories(${PRODUCT} PUBLIC ${CMAKE_BINARY_DIR}/../libs/inc)
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
target_link_libraries(${PRODUCT} PUBLIC filex)

target_compile_options(
  ${PRODUCT}
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
