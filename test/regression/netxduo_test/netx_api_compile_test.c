/* This NetX test concentrates on compiling all APIs for NetXDuo.  */

#include   "nx_api.h"

extern void    test_control_return(UINT status);
#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__)
#define     DEMO_STACK_SIZE         2048
#include   "nx_ip.h"
#include   "nx_ipv6.h"
#include   "nx_packet.h"
#include   "nx_tcp.h"

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static NX_PACKET_POOL          pool_0;
static ULONG                   error_counter = 0;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_api_compile_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT     status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;
}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
NX_PACKET *pkt_ptr = NX_NULL;

    /* Print out test information banner.  */
    printf("NetX Test:   API Compile Test..........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* APIs for ARP. */
    nx_arp_dynamic_entries_invalidate(0);
    nx_arp_dynamic_entry_set(0, 0, 0, 0);
    nx_arp_enable(0, 0 , 0);
    nx_arp_entry_delete(0, 0);
    nx_arp_gratuitous_send(0, 0);
    nx_arp_hardware_address_find(0, 0, 0, 0);
    nx_arp_info_get(0, 0, 0, 0, 0, 0, 0, 0, 0);
    nx_arp_ip_address_find(0, 0, 0, 0);
    nx_arp_static_entries_delete(0);
    nx_arp_static_entry_create(0, 0, 0, 0);
    nx_arp_static_entry_delete(0, 0, 0, 0);

    /* APIs for ICMP */
    nx_icmp_enable(0);
    nx_icmp_info_get(0, 0, 0, 0, 0, 0, 0);
    nx_icmp_ping(0, 0, 0, 0, 0, 0);
    nxd_icmp_enable(0);
    nxd_icmp_ping(0, 0, 0, 0, 0, 0);
    nxd_icmp_source_ping(0, 0, 0, 0, 0, 0, 0);
    nxd_icmpv6_ra_flag_callback_set(0, 0);

    /* APIs for IGMP */
    nx_igmp_enable(0);
    nx_igmp_info_get(0, 0, 0, 0, 0);
    nx_igmp_loopback_disable(0);
    nx_igmp_loopback_enable(0);
    nx_igmp_multicast_interface_join(0, 0, 0);
    nx_igmp_multicast_interface_leave(0, 0, 0);
    nx_igmp_multicast_join(0, 0);
    nx_igmp_multicast_leave(0, 0);

    /* APIs for IP */
    nx_ip_address_change_notify(0, 0, 0);
    nx_ip_address_get(0, 0, 0);
    nx_ip_address_set(0, 0, 0);
    nx_ip_auxiliary_packet_pool_set(0, 0);
#ifndef NX_ENABLE_DUAL_PACKET_POOL
    _nx_ip_auxiliary_packet_pool_set(0, 0);
#endif
    nx_ip_create(0, 0, 0, 0, 0, 0, 0, 0, 0);
    nx_ip_delete(0);
    nx_ip_driver_direct_command(0, 0, 0);
    nx_ip_driver_interface_direct_command(0, 0, 0, 0);
    nx_ip_forwarding_disable(0);
    nx_ip_forwarding_enable(0);
    nx_ip_fragment_disable(0);
    nx_ip_fragment_enable(0);
    nx_ip_gateway_address_clear(0);
    nx_ip_gateway_address_get(0, 0);
    nx_ip_gateway_address_set(0, 0);
    nx_ip_info_get(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    nx_ip_interface_address_get(0, 0, 0, 0);
    nx_ip_interface_address_mapping_configure(0, 0, 0);
    nx_ip_interface_address_set(0, 0, 0, 0);
    nx_ip_interface_attach(0, 0, 0, 0, 0);
    nx_ip_interface_capability_get(0, 0, 0);
    nx_ip_interface_capability_set(0, 0, 0);
#ifndef NX_ENABLE_INTERFACE_CAPABILITY
    _nx_ip_interface_capability_get(0, 0, 0);
    _nx_ip_interface_capability_set(0, 0, 0);
#endif
    nx_ip_interface_detach(0, 0);
    nx_ip_interface_info_get(0, 0, 0, 0, 0, 0, 0, 0);
    nx_ip_interface_mtu_set(0, 0, 0);
    nx_ip_interface_physical_address_get(0, 0, 0, 0);
    nx_ip_interface_physical_address_set(0, 0, 0, 0, 0);
    nx_ip_interface_status_check(0, 0, 0, 0, 0);
    nx_ip_link_status_change_notify_set(0, 0);
    nx_ip_max_payload_size_find(0, 0, 0, 0, 0, 0, 0, 0);
    nx_ip_status_check(0, 0, 0, 0);
    nx_ip_static_route_add(0, 0, 0, 0);
    nx_ip_static_route_delete(0, 0, 0);
#ifndef NX_ENABLE_IP_STATIC_ROUTING
    _nx_ip_static_route_add(0, 0, 0, 0);
    _nx_ip_static_route_delete(0, 0, 0);
#endif
    nx_ipv4_multicast_interface_join(0, 0, 0);
    nx_ipv4_multicast_interface_leave(0, 0, 0);
    nxd_ipv6_address_change_notify(0, 0);
#ifndef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
    _nxd_ipv6_address_change_notify(0, 0);
#endif
    nxd_ipv6_address_delete(0, 0);
    nxd_ipv6_address_get(0, 0, 0, 0, 0);
    nxd_ipv6_address_set(0, 0, 0, 0, 0);
    nxd_ipv6_default_router_add(0, 0, 0, 0);
    nxd_ipv6_default_router_delete(0, 0);
    nxd_ipv6_default_router_entry_get(0, 0, 0, 0, 0, 0, 0);
    nxd_ipv6_default_router_get(0, 0, 0, 0, 0);
    nxd_ipv6_default_router_number_of_entries_get(0, 0, 0);
    nxd_ipv6_disable(0);
    nxd_ipv6_enable(0);
    nxd_ipv6_multicast_interface_join(0, 0, 0);
    nxd_ipv6_multicast_interface_leave(0, 0, 0);
#ifndef NX_ENABLE_IPV6_MULTICAST
    _nxd_ipv6_multicast_interface_join(0, 0, 0);
    _nxd_ipv6_multicast_interface_leave(0, 0, 0);
#endif
    nxd_ipv6_stateless_address_autoconfig_disable(0, 0);
    nxd_ipv6_stateless_address_autoconfig_enable(0, 0);
#ifndef NX_IPV6_STATELESS_AUTOCONFIG_CONTROL
    _nxd_ipv6_stateless_address_autoconfig_disable(0, 0);
    _nxd_ipv6_stateless_address_autoconfig_enable(0, 0);
#endif

    /* APIs for RAW service. */
    nx_ip_raw_packet_disable(0);
    nx_ip_raw_packet_enable(0);
    nx_ip_raw_packet_filter_set(0, 0);
#ifndef NX_ENABLE_IP_RAW_PACKET_FILTER
    _nx_ip_raw_packet_filter_set(0, 0);
#endif
    nx_ip_raw_packet_receive(0, 0, 0);
    nx_ip_raw_packet_send(0, pkt_ptr, 0, 0);
    nx_ip_raw_packet_source_send(0, pkt_ptr, 0, 0, 0);
    nx_ip_raw_receive_queue_max_set(0, 0);
    nxd_ip_raw_packet_send(0, pkt_ptr, 0, 0, 0, 0);
    nxd_ip_raw_packet_source_send(0, 0, 0, 0, 0, 0, 0);

    /* APIs for ND cache. */
    nxd_nd_cache_entry_set(0, 0, 0, 0);
    nxd_nd_cache_entry_delete(0, 0);
    nxd_nd_cache_hardware_address_find(0, 0, 0, 0, 0);
    nxd_nd_cache_invalidate(0);
    nxd_nd_cache_ip_address_find(0, 0, 0, 0, 0);

    /* APIs for packet pool. */
    nx_packet_allocate(0, 0, 0, 0);
    nx_packet_copy(0, 0, 0, 0);
    nx_packet_data_append(0, 0, 0, 0, 0);
    nx_packet_data_extract_offset(0, 0, 0, 0, 0);
    nx_packet_data_retrieve(0, 0, 0);
    nx_packet_length_get(0, 0);
    nx_packet_pool_create(0, 0, 0, 0, 0);
    nx_packet_pool_delete(0);
    nx_packet_pool_info_get(0, 0, 0, 0, 0, 0);
    nx_packet_pool_low_watermark_set(0, 0);
#ifndef NX_ENABLE_LOW_WATERMARK
    _nx_packet_pool_low_watermark_set(0, 0);
#endif
    nx_packet_release(pkt_ptr);
    nx_packet_transmit_release(pkt_ptr);

    /* APIs for RARP. */
    nx_rarp_disable(0);
    nx_rarp_enable(0);
    nx_rarp_info_get(0, 0, 0, 0);

    /* APIs for TCP. */
    nx_tcp_client_socket_bind(0, 0, 0);
    nx_tcp_client_socket_connect(0, 0, 0, 0);
    nx_tcp_client_socket_port_get(0, 0);
    nx_tcp_client_socket_unbind(0);
    nx_tcp_enable(0);
    nx_tcp_free_port_find(0, 0, 0);
    nx_tcp_info_get(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    nx_tcp_server_socket_accept(0, 0);
    nx_tcp_server_socket_listen(0, 0, 0, 0, 0);
    nx_tcp_server_socket_relisten(0, 0, 0);
    nx_tcp_server_socket_unaccept(0);
    nx_tcp_server_socket_unlisten(0, 0);
    nx_tcp_socket_bytes_available(0, 0);
    nx_tcp_socket_create(0, 0, 0, 0, 0, 0, 0, 0, 0);
    nx_tcp_socket_delete(0);
    nx_tcp_socket_disconnect(0, 0);
    nx_tcp_socket_disconnect_complete_notify(0, 0);
    nx_tcp_socket_establish_notify(0, 0);
#ifdef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
    _nx_tcp_socket_disconnect_complete_notify(0, 0);
    _nx_tcp_socket_establish_notify(0, 0);
#endif
    nx_tcp_socket_info_get(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    nx_tcp_socket_mss_get(0, 0);
    nx_tcp_socket_mss_peer_get(0, 0);
    nx_tcp_socket_mss_set(0, 0);
    nx_tcp_socket_peer_info_get(0, 0, 0);
    nx_tcp_socket_queue_depth_notify_set(0, 0);
#ifndef NX_ENABLE_TCP_QUEUE_DEPTH_UPDATE_NOTIFY
    _nx_tcp_socket_queue_depth_notify_set(0, 0);
#endif
    nx_tcp_socket_receive(0, 0, 0);
    nx_tcp_socket_receive_notify(0, 0);
    nx_tcp_socket_receive_queue_max_set(0, 0);
#ifndef NX_ENABLE_LOW_WATERMARK
    _nx_tcp_socket_receive_queue_max_set(0, 0);
#endif
    nx_tcp_socket_send(0, pkt_ptr, 0);
    nx_tcp_socket_state_wait(0, 0, 0);
    nx_tcp_socket_timed_wait_callback(0, 0);
#ifdef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
    _nx_tcp_socket_timed_wait_callback(0, 0);
#endif
    nx_tcp_socket_transmit_configure(0, 0, 0, 0, 0);
    nx_tcp_socket_window_update_notify_set(0, 0);
    nxd_tcp_client_socket_connect(0, 0, 0, 0);
    nxd_tcp_socket_peer_info_get(0, 0, 0);

    /* APIs for UDP */
    nx_udp_enable(0);
    nx_udp_free_port_find(0, 0, 0);
    nx_udp_info_get(0, 0, 0, 0, 0, 0, 0, 0);
    nx_udp_packet_info_extract(0, 0, 0, 0, 0);
    nx_udp_socket_bind(0, 0, 0);
    nx_udp_socket_bytes_available(0, 0);
    nx_udp_socket_checksum_disable(0);
    nx_udp_socket_checksum_enable(0);
    nx_udp_socket_create(0, 0, 0, 0, 0, 0, 0);
    nx_udp_socket_delete(0);
    nx_udp_socket_info_get(0, 0, 0, 0, 0, 0, 0, 0);
    nx_udp_socket_port_get(0, 0);
    nx_udp_socket_receive(0, 0, 0);
    nx_udp_socket_receive_notify(0, 0);
    nx_udp_socket_send(0, pkt_ptr, 0, 0);
    nx_udp_socket_source_send(0, pkt_ptr, 0, 0, 0);
    nx_udp_socket_unbind(0);
    nx_udp_source_extract(0, 0, 0);
    nxd_udp_packet_info_extract(0, 0, 0, 0, 0);
    nxd_udp_socket_send(0, pkt_ptr, 0, 0);
    nxd_udp_socket_source_send(0, pkt_ptr, 0, 0, 0);
    nxd_udp_source_extract(0, 0, 0);

    /* APIs for others. */
    nx_system_initialize();
#ifndef NX_DRIVER_DEFERRED_PROCESSING
UINT status;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &pkt_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    _nx_ip_driver_deferred_enable(0, 0);
    _nx_ip_driver_deferred_receive(0, pkt_ptr);
#endif

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_api_compile_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   API Compile Test..........................................N/A\n");
    test_control_return(3);  
}
#endif
