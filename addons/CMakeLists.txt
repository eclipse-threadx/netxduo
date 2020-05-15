# Each protocol handler is listed below. If you want
# to disable some / all of these, comment out the block(s) in question

set(SOURCES 
    # {{BEGIN_TARGET_SOURCES}}
    ${CMAKE_CURRENT_LIST_DIR}/auto_ip/nx_auto_ip.c
    # ${CMAKE_CURRENT_LIST_DIR}/BSD/nxd_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/dhcp/nxd_dhcpv6_client.c
    ${CMAKE_CURRENT_LIST_DIR}/dhcp/nxd_dhcpv6_server.c
    ${CMAKE_CURRENT_LIST_DIR}/dhcp/nxd_dhcp_client.c
    ${CMAKE_CURRENT_LIST_DIR}/dhcp/nxd_dhcp_server.c
    ${CMAKE_CURRENT_LIST_DIR}/dns/nxd_dns.c
    ${CMAKE_CURRENT_LIST_DIR}/ftp/nxd_ftp_client.c
    ${CMAKE_CURRENT_LIST_DIR}/ftp/nxd_ftp_server.c
    ${CMAKE_CURRENT_LIST_DIR}/http/nxd_http_client.c
    ${CMAKE_CURRENT_LIST_DIR}/http/nxd_http_server.c
    ${CMAKE_CURRENT_LIST_DIR}/mdns/nxd_mdns.c
    ${CMAKE_CURRENT_LIST_DIR}/mqtt/nxd_mqtt_client.c
    ${CMAKE_CURRENT_LIST_DIR}/nat/nx_nat.c
    ${CMAKE_CURRENT_LIST_DIR}/pop3/nxd_pop3_client.c
    ${CMAKE_CURRENT_LIST_DIR}/ppp/nx_ppp.c
    ${CMAKE_CURRENT_LIST_DIR}/pppoe/nx_pppoe_client.c
    ${CMAKE_CURRENT_LIST_DIR}/pppoe/nx_pppoe_server.c
    ${CMAKE_CURRENT_LIST_DIR}/smtp/nxd_smtp_client.c
    ${CMAKE_CURRENT_LIST_DIR}/snmp/nxd_snmp.c
    ${CMAKE_CURRENT_LIST_DIR}/snmp/nx_des.c
    ${CMAKE_CURRENT_LIST_DIR}/snmp/nx_sha1.c
    ${CMAKE_CURRENT_LIST_DIR}/sntp/nxd_sntp_client.c
    ${CMAKE_CURRENT_LIST_DIR}/telnet/nxd_telnet_client.c
    ${CMAKE_CURRENT_LIST_DIR}/telnet/nxd_telnet_server.c
    ${CMAKE_CURRENT_LIST_DIR}/tftp/nxd_tftp_client.c
    ${CMAKE_CURRENT_LIST_DIR}/tftp/nxd_tftp_server.c
    ${CMAKE_CURRENT_LIST_DIR}/web/nx_tcpserver.c
    ${CMAKE_CURRENT_LIST_DIR}/web/nx_web_http_client.c
    ${CMAKE_CURRENT_LIST_DIR}/web/nx_web_http_server.c
    # {{END_TARGET_SOURCES}}
)

# Remove the file server files if the user doesn't want them
if(NOT NXD_ENABLE_FILE_SERVERS)
    list(REMOVE_ITEM SOURCES     
        "${CMAKE_CURRENT_LIST_DIR}/web/nx_web_http_server.c"
        "${CMAKE_CURRENT_LIST_DIR}/http/nxd_http_server.c"
        "${CMAKE_CURRENT_LIST_DIR}/ftp/nxd_ftp_server.c"
        "${CMAKE_CURRENT_LIST_DIR}/tftp/nxd_tftp_server.c"
    )
endif()

target_sources(${PROJECT_NAME} PRIVATE ${SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/auto_ip
    ${CMAKE_CURRENT_LIST_DIR}/BSD
    ${CMAKE_CURRENT_LIST_DIR}/dhcp
    ${CMAKE_CURRENT_LIST_DIR}/dns
    ${CMAKE_CURRENT_LIST_DIR}/ftp
    ${CMAKE_CURRENT_LIST_DIR}/http
    ${CMAKE_CURRENT_LIST_DIR}/mdns
    ${CMAKE_CURRENT_LIST_DIR}/mqtt
    ${CMAKE_CURRENT_LIST_DIR}/nat
    ${CMAKE_CURRENT_LIST_DIR}/pop3
    ${CMAKE_CURRENT_LIST_DIR}/ppp
    ${CMAKE_CURRENT_LIST_DIR}/pppoe
    ${CMAKE_CURRENT_LIST_DIR}/smtp
    ${CMAKE_CURRENT_LIST_DIR}/snmp
    ${CMAKE_CURRENT_LIST_DIR}/sntp
    ${CMAKE_CURRENT_LIST_DIR}/telnet
    ${CMAKE_CURRENT_LIST_DIR}/tftp
    ${CMAKE_CURRENT_LIST_DIR}/web
)
