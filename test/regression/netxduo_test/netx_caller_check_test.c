/* This NetX test concentrates on caller check for error checking functions. */

#include "nx_api.h"
#include "tx_thread.h"
#include "tx_timer.h"
#include "nx_udp.h"
#include "nx_tcp.h"
#include "nx_rarp.h"
#include "nx_ip.h"
#include "nx_icmp.h"
#include "nx_igmp.h"
#include "nx_arp.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__) && defined(__linux__)  && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   test_ip;
static NX_TCP_SOCKET           tcp_socket;
static NX_UDP_SOCKET           udp_socket;
static NXD_ADDRESS address = {NX_IP_VERSION_V6, };
static TX_TIMER                timer_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;
static ULONG                   expected_system_state;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    link_status_change_notify(NX_IP *ip_ptr, UINT interface_index, UINT link_up);
static void    tcp_receive_notify(NX_TCP_SOCKET *socket_ptr);
static VOID    tcp_socket_window_update_notify(NX_TCP_SOCKET *socket_ptr);
VOID test_process(ULONG id);
VOID test_process_1(ULONG id);
VOID test_process_2(ULONG id);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_caller_check_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
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

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;
                                   
    /* Enable UDP processing for IP instance.  */
    status =  nx_udp_enable(&ip_0);

    /* Check UDP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for IP instance.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    /* Enable IGMP for IP instance. */
    status =  nx_igmp_enable(&ip_0);

    /* Check IGMP enable status.  */
    if (status)
        error_counter++;

    /* Enable ICMP processing for IP instance.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

}

VOID test_process(ULONG id)
{
UINT        uint_value;
ULONG       ulong_value;
NX_PACKET_POOL
            test_pool;
ULONG       ipv6_addr[4];
UINT        old_state = _tx_thread_system_state;


    _tx_thread_system_state = expected_system_state;

    if (nx_ip_raw_packet_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_raw_packet_disable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_raw_receive_queue_max_set(&ip_0, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_fragment_disable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_rarp_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_gateway_address_clear(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL,
                       NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_link_status_change_notify_set(&ip_0, link_status_change_notify) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_address_change_notify(&ip_0, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_rarp_disable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_fragment_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_rarp_queue_process = _nx_rarp_queue_process;
    if (nx_rarp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_arp_static_entries_delete(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_icmp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_igmp_loopback_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_igmp_loopback_disable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_driver_direct_command(&ip_0, 0xFFFFFFFF, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_driver_interface_direct_command(&ip_0, 0xFFFFFFFF, 0, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_interface_physical_address_set(&ip_0, 0, 0, 0, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL,
                        NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_igmp_info_get(&ip_0, 0, 0, 0, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_interface_mtu_set(&ip_0, 0, 1500) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_gateway_address_set(&ip_0, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_arp_entry_delete(&ip_0, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_arp_allocate = NX_NULL;
    if (nx_arp_enable(&ip_0, (VOID *)0x20000000, 1024) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_arp_allocate = _nx_arp_entry_allocate;
    if (nx_tcp_socket_mss_set(&tcp_socket, 1460) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_mss_get(&tcp_socket, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_window_update_notify_set(&tcp_socket, tcp_socket_window_update_notify) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_gateway_address_get(&ip_0, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_icmp_packet_receive = NX_NULL;
    if (nx_icmp_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_icmp_packet_receive = _nx_icmp_packet_receive;
    if (nx_tcp_socket_info_get(&tcp_socket, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL,
                               NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_igmp_packet_receive = NX_NULL;
    if (nx_igmp_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;
    if (nx_ip_interface_address_mapping_configure(&ip_0, 0, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_interface_info_get(&ip_0, 0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_address_set(&ip_0, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_address_get(&ip_0, &ulong_value, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_interface_address_set(&ip_0, 0, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_interface_physical_address_get(&ip_0, 0, &ulong_value, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_transmit_configure(&tcp_socket, 1, 1, 1, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_receive_notify(&tcp_socket, tcp_receive_notify) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_packet_pool_create(&test_pool, "Invalid pool", 256, (VOID *)0x20000000, 1024) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_interface_address_get(&ip_0, 0, &ulong_value, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_create(&test_ip, "test ip", 0, 0, &pool_0, _nx_ram_network_driver_256,
                     (VOID *)0x20000000, 1024, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_arp_static_entry_create(&ip_0, 1, 1, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    address.nxd_ip_version = NX_IP_VERSION_V6;
    if (nx_ip_max_payload_size_find(&ip_0, &address, 0, 1, 1, NX_PROTOCOL_TCP, &ulong_value, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_create(&ip_0, &udp_socket, "UDP socket", 0, 0, 0, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_create(&ip_0, &tcp_socket, "TCP socket", 0, 0, 0, 0, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
#if (NX_MAX_PHYSICAL_INTERFACES>1)
    if (nx_ip_interface_detach(&ip_0, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_interface_attach(&ip_0, "Second interface", 1, 0, _nx_ram_network_driver_256) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
#endif /* (NX_MAX_PHYSICAL_INTERFACES>1) */
#ifdef FEATURE_NX_IPV6
    if (nxd_ipv6_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_ipv6_disable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_ipv6_default_router_delete(&ip_0, &address) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_ipv6_default_router_entry_get(&ip_0, 0, 0, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_ipv6_default_router_number_of_entries_get(&ip_0, 0, &uint_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_icmpv6_ra_flag_callback_set(&ip_0, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_icmp_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_ipv6_address_delete(&ip_0, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_nd_cache_entry_delete(&ip_0, ipv6_addr) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_nd_cache_entry_set(&ip_0, ipv6_addr, 0, "") != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_ipv6_address_get(&ip_0, 0, &address, &ulong_value, &uint_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    address.nxd_ip_version = NX_IP_VERSION_V6;
    if (nxd_ipv6_default_router_add(&ip_0, &address, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
#endif /* FEATURE_NX_IPV6 */

    _tx_thread_system_state = old_state;

    /* Deactivate current timer. */
    tx_timer_deactivate(&timer_0);
}

VOID test_process_1(ULONG id)
{
NX_PACKET  *packet_ptr;
ULONG       ulong_value;
UINT        uint_value;
ULONG       ipv6_addr[4];
UINT        old_state = _tx_thread_system_state;
TX_THREAD  *old_thread = _tx_thread_current_ptr;


    nx_packet_allocate(&pool_0, &packet_ptr, 0, 0);
    packet_ptr -> nx_packet_ip_version = 0;

    _tx_thread_system_state = expected_system_state;

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nxd_udp_packet_info_extract(packet_ptr, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_packet_info_extract(packet_ptr, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_bytes_available(&udp_socket, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_port_get(&udp_socket, &uint_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_raw_ip_processing = _nx_ip_raw_packet_processing;
    if (nx_ip_raw_packet_receive(&ip_0, &packet_ptr, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_receive(&udp_socket, &packet_ptr, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_allocate(&pool_0, &packet_ptr, 0, 0);
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr;

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nxd_udp_source_extract(packet_ptr, &address, &uint_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_delete(&udp_socket) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_unbind(&udp_socket) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_free_port_find(&ip_0, 1, &uint_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_delete(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ipv4_multicast_interface_leave(&ip_0, IP_ADDRESS(224, 0, 0, 1), 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_packet_pool_delete(&pool_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_arp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_arp_dynamic_entries_invalidate(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_disconnect(&tcp_socket, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_client_socket_unbind(&tcp_socket) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_delete(&tcp_socket) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_server_socket_accept(&tcp_socket, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_server_socket_unaccept(&tcp_socket) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_state_wait(&tcp_socket, NX_TCP_CLOSED, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ipv4_multicast_interface_join(&ip_0, IP_ADDRESS(224, 0, 0, 1), 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_allocate(&pool_0, &packet_ptr, sizeof(NX_IPV4_HEADER), 0);
    address.nxd_ip_version = NX_IP_VERSION_V4;
    address.nxd_ip_address.v4 = 1;

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nxd_ip_raw_packet_send(&ip_0, packet_ptr, &address, 0, 0, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_raw_packet_source_send(&ip_0, packet_ptr, 1, 0, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_raw_packet_send(&ip_0, packet_ptr, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_release(packet_ptr);

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224, 0, 0, 1), 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224, 0, 0, 1), 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &ulong_value, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_bind(&udp_socket, 10, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_mss_peer_get(&tcp_socket, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_client_socket_bind(&tcp_socket, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_bytes_available(&tcp_socket, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_receive(&tcp_socket, &packet_ptr, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_client_socket_port_get(&tcp_socket, &uint_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, 0);

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nx_udp_socket_send(&udp_socket, packet_ptr, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_release(packet_ptr);

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nx_arp_ip_address_find(&ip_0, ipv6_addr, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_free_port_find(&ip_0, 1, &uint_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224, 0, 0, 1)) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224, 0, 0, 1)) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_icmp_ping(&ip_0, 1, "", 0, &packet_ptr, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_socket_peer_info_get(&tcp_socket, &ulong_value, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_arp_static_entry_delete(&ip_0, 1, 1, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_server_socket_unlisten(&ip_0, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_tcp_socket_peer_info_get(&tcp_socket, &address, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_tcp_client_socket_connect(&tcp_socket, &address, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_client_socket_connect(&tcp_socket, 1, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, 0);

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nx_udp_socket_source_send(&udp_socket, packet_ptr, 1, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_release(packet_ptr);

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nx_ip_interface_status_check(&ip_0, 0, NX_IP_INITIALIZE_DONE, &ulong_value, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_arp_hardware_address_find(&ip_0, 1, &ulong_value, &ulong_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_arp_dynamic_entry_set(&ip_0, 1, 1, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_arp_gratuitous_send(&ip_0, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nx_tcp_socket_send(&tcp_socket, packet_ptr, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_udp_socket_source_send(&udp_socket, packet_ptr, &address, 1, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_udp_socket_send(&udp_socket, packet_ptr, &address, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_ip_raw_packet_source_send(&ip_0, packet_ptr, &address, 0, 0, 0, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_release(packet_ptr);

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nx_tcp_server_socket_relisten(&ip_0, 1, &tcp_socket) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_tcp_server_socket_listen(&ip_0, 1, &tcp_socket, 1, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_icmp_ping(&ip_0, &address, "", 0, &packet_ptr, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
#ifdef FEATURE_NX_IPV6
    if (nxd_nd_cache_invalidate(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_nd_cache_ip_address_find(&ip_0, &address, 1, 1, &uint_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nxd_icmp_source_ping(&ip_0, &address, 0, "", 0, &packet_ptr, 0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    address.nxd_ip_version = NX_IP_VERSION_V6;
    if (nxd_nd_cache_hardware_address_find(&ip_0, &address, &ulong_value, &ulong_value, &uint_value) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
#endif /* FEATURE_NX_IPV6 */

    _tx_thread_system_state = old_state;

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    /* Deactivate current timer. */
    tx_timer_deactivate(&timer_0);
}

VOID test_process_2(ULONG id)
{
NX_PACKET  *packet_ptr;
NX_PACKET  *test_packet_ptr;
ULONG       ulong_value;
UINT        old_state = _tx_thread_system_state;
TX_THREAD  *old_thread = _tx_thread_current_ptr;

    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);

    _tx_thread_system_state = expected_system_state;

    if (id == 1)
        _tx_thread_current_ptr = TX_NULL;

    if (nx_packet_allocate(&pool_0, &test_packet_ptr, 0, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_packet_copy(packet_ptr, &packet_ptr, &pool_0, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_packet_data_append(packet_ptr, "", 1, &pool_0, 1) != NX_CALLER_ERROR)
    {
        error_counter++;
    }

    _tx_thread_system_state = old_state;

    if (id == 1)
        _tx_thread_current_ptr = old_thread;

    nx_packet_release(packet_ptr);
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
TX_INTERRUPT_SAVE_AREA
UINT        i;
UINT        old_state;
TX_THREAD  *old_thread;
NX_PACKET  *packet_ptr;
ULONG       ulong_value;
UINT        uint_value;
ULONG       ipv6_addr[4];
struct sched_param sp;

    /* Print out some test information banners.  */
    printf("NetX Test:   Caller Check Test.........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Modify the thread priority so it will pass the check as not a user thread. */
    sp.sched_priority = 1;
    pthread_setschedparam(_tx_thread_current_ptr -> tx_thread_linux_thread_id, SCHED_FIFO, &sp);

    /* Create a UDP socket.  */
    nx_udp_socket_create(&ip_0, &udp_socket, "UDP Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Create a TCP socket. */
    nx_tcp_socket_create(&ip_0, &tcp_socket, "TCP Socket", 
                         NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                         NX_NULL, NX_NULL);

    TX_DISABLE
    old_state = _tx_thread_system_state;
    old_thread = _tx_thread_current_ptr;

    /* 1. NX_INIT_AND_THREADS_CALLER_CHECKING checking. */

    /* 1.1 _tx_thread_system_state = 1, _tx_thread_current_ptr != _tx_timer_thread */
    expected_system_state = 1;
    test_process(0);

#ifndef TX_TIMER_PROCESS_IN_ISR
    /* Restore. */
    _tx_thread_current_ptr = old_thread;
    _tx_thread_system_state = old_state;

    /* 1.2 _tx_thread_system_state = 0xF0F0F0F0UL, _tx_thread_current_ptr = _tx_timer_thread */
    expected_system_state = 0xF0F0F0F0UL;
    tx_timer_create(&timer_0, "TIMER 0", test_process, 0, 1, 1, TX_AUTO_ACTIVATE);
    /* Invoke functions in timer thread. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    tx_timer_delete(&timer_0);
#endif /* TX_TIMER_PROCESS_IN_ISR */

    /* Restore. */
    _tx_thread_current_ptr = old_thread;
    _tx_thread_system_state = old_state;

    /* 1.3 _tx_thread_current_ptr = &_tx_timer_thread, _tx_thread_system_state = 0. */
    expected_system_state = 0;
    tx_timer_create(&timer_0, "TIMER 1", test_process, 0, 1, 1, TX_AUTO_ACTIVATE);
    /* Invoke functions in timer thread. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    tx_timer_delete(&timer_0);

    /* Restore. */
    _tx_thread_current_ptr = old_thread;
    _tx_thread_system_state = old_state;


    /* 2. NX_NOT_ISR_CALLER_CHECKING checking. */
    /* 2.1 _tx_thread_system_state = 0 */
    _tx_thread_system_state = 0;
    if (nx_udp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_info_get(&udp_socket, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_udp_packet_receive = NX_NULL;
    if (nx_udp_enable(&ip_0) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_udp_packet_receive = _nx_udp_packet_receive;
    if (nx_udp_socket_checksum_disable(&udp_socket) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_checksum_enable(&udp_socket) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_packet_pool_info_get(&pool_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_forwarding_enable(&ip_0) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_forwarding_disable(&ip_0) == NX_CALLER_ERROR)
    {
        error_counter++;
    }

    /* 2.2 _tx_thread_system_state = 1 */
    _tx_thread_system_state = 1;
    if (nx_udp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_info_get(&udp_socket, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_udp_packet_receive = NX_NULL;
    if (nx_udp_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_udp_packet_receive = _nx_udp_packet_receive;
    if (nx_udp_socket_checksum_disable(&udp_socket) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_checksum_enable(&udp_socket) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_packet_pool_info_get(&pool_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_forwarding_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_forwarding_disable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_tcp_packet_receive = NX_NULL;
    if (nx_tcp_enable(&ip_0) != NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

    /* 2.3 _tx_thread_system_state = 0xF0F0F0F0UL */
    _tx_thread_system_state = 0xF0F0F0F0UL;
    if (nx_udp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_info_get(&udp_socket, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_udp_packet_receive = NX_NULL;
    if (nx_udp_enable(&ip_0) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_udp_packet_receive = _nx_udp_packet_receive;
    if (nx_udp_socket_checksum_disable(&udp_socket) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_udp_socket_checksum_enable(&udp_socket) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_packet_pool_info_get(&pool_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_forwarding_enable(&ip_0) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    if (nx_ip_forwarding_disable(&ip_0) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_tcp_packet_receive = NX_NULL;
    if (nx_tcp_enable(&ip_0) == NX_CALLER_ERROR)
    {
        error_counter++;
    }
    ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

    /* Restore. */
    _tx_thread_current_ptr = old_thread;
    _tx_thread_system_state = old_state;


    /* 3. NX_THREADS_ONLY_CALLER_CHECKING checking. */
    /* 3.1 _tx_thread_system_state = 1 */
    expected_system_state = 1;
    test_process_1(0);

    /* Restore. */
    _tx_thread_current_ptr = old_thread;
    _tx_thread_system_state = old_state;

    /* 3.2 _tx_thread_current_ptr = &_tx_timer_thread, _tx_thread_system_state = 0. */
    expected_system_state = 0;
    tx_timer_create(&timer_0, "TIMER 2", test_process_1, 0, 1, 1, TX_AUTO_ACTIVATE);
    /* Invoke functions in timer thread. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    tx_timer_delete(&timer_0);

    /* Restore. */
    _tx_thread_current_ptr = old_thread;
    _tx_thread_system_state = old_state;

    /* 3.3 _tx_thread_current_ptr = TX_NULL, _tx_thread_system_state = 0. */
    expected_system_state = 0;
    test_process_1(1);

    /* Restore. */
    _tx_thread_current_ptr = old_thread;
    _tx_thread_system_state = old_state;

    /* 4. NX_THREAD_WAIT_CALLER_CHECKING checking. */
    /* 4.1 _tx_thread_system_state = 1. */
    expected_system_state = 1;
    test_process_2(0);

    /* 4.2 _tx_thread_current_ptr = TX_NULL, _tx_thread_system_state = 0. */
    expected_system_state = 0;
    test_process_2(1);

    /* 4.3 _tx_thread_current_ptr = &_tx_timer_thread, _tx_thread_system_state = 0. */
    expected_system_state = 0;
    tx_timer_create(&timer_0, "TIMER 3", test_process_2, 0, 1, 1, TX_AUTO_ACTIVATE);
    /* Invoke functions in timer thread. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    tx_timer_delete(&timer_0);

    /* Restore. */
    _tx_thread_current_ptr = old_thread;
    _tx_thread_system_state = old_state;
    TX_RESTORE

    /* Check status.  */
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

static void    link_status_change_notify(NX_IP *ip_ptr, UINT interface_index, UINT link_up)
{
}

static void    tcp_receive_notify(NX_TCP_SOCKET *socket_ptr)
{
}

static VOID    tcp_socket_window_update_notify(NX_TCP_SOCKET *socket_ptr)
{
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_caller_check_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Caller Check Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
