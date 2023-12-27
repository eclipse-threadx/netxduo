/* This is the test control routine the NetX TCP/IP stack.  All tests are dispatched from this routine.  */

#include "tx_api.h"
#include "fx_api.h"
#include "nx_api.h"
#include <stdio.h>
#include <stdlib.h>
#include "nx_ram_network_driver_test_1500.h"
#if defined(__linux__) && defined(USE_FORK)
#undef __suseconds_t_defined
#undef _STRUCT_TIMEVAL
#undef _SYS_SELECT_H
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/poll.h>

void fork_child();
#endif 

/* Version definitions check. */
#if defined(__PRODUCT_NETXDUO__)

#if defined(EXPECTED_MAJOR_VERSION) && ( !defined(__NETXDUO_MAJOR_VERSION__) || __NETXDUO_MAJOR_VERSION__ != EXPECTED_MAJOR_VERSION)
#error "__NETXDUO_MAJOR_VERSION__"
#endif /* Check __NETXDUO_MAJOR_VERSION__ */

#if defined(EXPECTED_MINOR_VERSION) && ( !defined(__NETXDUO_MINOR_VERSION__) || EXPECTED_MINOR_VERSION != __NETXDUO_MINOR_VERSION__) 
#error "__NETXDUO_MINOR_VERSION__"
#endif /* Check __NETXDUO_MINOR_VERSION__ */

#elif defined(__PRODUCT_NETX__)

#if defined(EXPECTED_MAJOR_VERSION) && (!defined(__NETX_MAJOR_VERSION__) || __NETX_MAJOR_VERSION__ != EXPECTED_MAJOR_VERSION)
#error "__NETX_MAJOR_VERSION__"
#endif /* Check __NETX_MAJOR_VERSION__ */

#if defined(EXPECTED_MINOR_VERSION) && ( !defined(__NETX_MINOR_VERSION__) || EXPECTED_MINOR_VERSION != __NETX_MINOR_VERSION__)
#error "__NETX_MINOR_VERSION__"
#endif /* Check __NETX_MINOR_VERSION__ */

#else /* ! __PRODUCT_NETXDUO__ and !__PRODUCT_NETX__ */
#error "__PRODUCT_XXX__ not found."
#endif /* ! __PRODUCT_NETXDUO__ and !__PRODUCT_NETX__ */

/*
#define NETXTEST_TIMEOUT_DISABLE
*/

 FILE *stream; 

#define TEST_STACK_SIZE         4096

/* 1 minute. */
#define TEST_TIMEOUT_LOW        (60 * NX_IP_PERIODIC_RATE)
/* 15 minutes. */
#define TEST_TIMEOUT_MID        (900 * NX_IP_PERIODIC_RATE)
/* 120 minutes. */
#define TEST_TIMEOUT_HIGH       (7200 * NX_IP_PERIODIC_RATE)

/* Define the test control ThreadX objects...  */

TX_THREAD       test_control_thread;
#ifndef NETXTEST_TIMEOUT_DISABLE
TX_SEMAPHORE    test_control_sema;
#endif

/* Define the test control global variables.   */

ULONG           test_control_return_status;
ULONG           test_control_successful_tests;
ULONG           test_control_failed_tests;
ULONG           test_control_warning_tests;
ULONG           test_control_na_tests;

/* Remember the start of free memory.  */

UCHAR           *test_free_memory_ptr;

extern volatile UINT   _tx_thread_preempt_disable;

/* Define test entry pointer type.  */

typedef  struct TEST_ENTRY_STRUCT
{
    VOID        (*test_entry)(void *);
    UINT        timeout;
} TEST_ENTRY;


/* Define the prototypes for the test entry points.  */
void    netx_api_compile_test_application_define(void*);
void    netx_caller_check_test_application_define(void*);
void    netx_packet_payload_size_test_application_define(void *);
void    netx_checksum_test_application_define(void *);
void    netx_netx_ramdriver_callback_application_define(void *);
void    netx_old_api_application_define(void *);
void    netx_utility_test_application_define(void *);

void    netx_arp_basic_test_application_define(void *);
void    netx_arp_conflict_test_application_define(void *);
void    netx_arp_dynamic_entry_test_application_define(void *);  
void    netx_arp_dynamic_entry_test2_application_define(void *);
void    netx_arp_dynamic_entry_test3_application_define(void *);
void    netx_arp_dynamic_entry_set_test_application_define(void *); 
void    netx_arp_dynamic_entry_fail_test_application_define(void *); 
void    netx_arp_dynamic_entry_timeout_test_application_define(void *); 
void    netx_arp_dynamic_invalidate_test_application_define(void *);
void    netx_arp_gratuitous_test_application_define(void *);
void    netx_arp_static_entries_delete_test_application_define(void *);
void    netx_arp_static_entry_create_test_application_define(void *);     
void    netx_arp_static_entry_test_application_define(void *);     
void    netx_arp_static_entry_pollute_test_application_define(void *);     
void    netx_arp_entry_cache_test_application_define(void *); 
void    netx_arp_entry_abnormal_operation_test_application_define(void *); 
void    netx_arp_queue_depth_test_application_define(void *); 
void    netx_arp_nxe_api_test_application_define(void *);  
void    netx_arp_dual_pool_test_application_define(void *);  
void    netx_arp_invalid_type_test_application_define(void *);  
void    netx_arp_auto_entry_test_application_define(void *);  
void    netx_arp_no_duplicate_entry_application_define(void *);  
void    netx_arp_packet_allocate_test_application_define(void *);
void    netx_arp_branch_test_application_define(void*);  

void    netx_icmp_ping_test_application_define(void *);
void    netx_icmp_ping_fragment_test_application_define(void *);
void    netx_icmp_ping6_test_application_define(void *);
void    netx_icmp_ping6_data_append_test_application_define(void *);      
void    netx_icmp_ping6_fragment_test_application_define(void *);
void    netx_icmp_interface2_ping_test_application_define(void *);
void    netx_icmp_interface2_ping6_test_application_define(void *);
void    netx_icmp_invalid_source_test_application_define(void *); 
void    netx_icmp_cleanup_test_application_define(void *);
void    netx_icmp_packet_receive_function_test_application_define(void *);       
void    netx_icmp_multiple_ping_test1_application_define(void *);
void    netx_icmp_multiple_ping_test2_application_define(void *);
void    netx_icmp_multiple_ping6_test1_application_define(void *);
void    netx_icmp_multiple_ping6_test2_application_define(void *);
void    netx_icmp_nxe_api_test_application_define(void *);  
void    netx_icmp_send_error_message_test_application_define(void *);  
void    netx_icmp_send_error_message_test_1_application_define(void *);  
void    netx_icmp_loopback_test_application_define(void *);  
void    netx_icmp_loopback_test2_application_define(void *);  
void    netx_icmp_loopback_fail_test_application_define(void *);  
void    netx_icmp_invalid_echo_reply_test_application_define(void *);  
void    netx_icmp_ping_multicast_test_application_define(void *);  
void    netx_icmp_branch_test_application_define(void *); 
void    netx_icmp_broadcast_ping_test_application_define(void *);

void    netx_icmpv6_error_test_application_define(void *first_unused_memory);
void    netx_icmpv6_error_small_packet_test_application_define(void *first_unused_memory);
void    netx_icmpv6_DAD_test_application_define(void *);
void    netx_icmpv6_echo_request_test_application_define(void *);
void    netx_icmpv6_echo_reply_test_application_define(void *);
void    netx_icmpv6_redirect_test_application_define(void *first_unused_memory);
void    netx_icmpv6_ra_flag_callback_test_application_define(void *first_unused_memory);
void    netx_icmpv6_solicitated_ra_test_application_define(void *first_unused_memory);
void    netx_icmpv6_abnormal_mtu_in_ra_test_application_define(void *first_unused_memory);
void    netx_icmpv6_invalid_length_test_application_define(void *first_unused_memory);
void    netx_icmpv6_invalid_length_test2_application_define(void *first_unused_memory);
void    netx_icmpv6_invalid_ra_dest_test_application_define(void *first_unused_memory);
void    netx_icmpv6_ra_lifetime_test_application_define(void *first_unused_memory);
void    netx_icmpv6_router_solicitation_test_application_define(void *first_unused_memory);
void    netx_icmpv6_invalid_na_application_define(void *first_unused_memory);
void    netx_icmpv6_na_test_application_define(void *first_unused_memory);
void    netx_icmpv6_na_tlla_changed_test_application_define(void *first_unused_memory);
void    netx_icmpv6_na_buffer_overwrite_test_application_define(void *first_unused_memory);
void    netx_icmpv6_redirect_nd_full_test_application_define(void *first_unused_memory);
void    netx_icmpv6_redirect_buffer_overwrite_test_application_define(void *first_unused_memory);
void    netx_icmpv6_destination_table_periodic_test_application_define(void *first_unused_memory);
void    netx_icmpv6_mtu_option_test_application_define(void *first_unused_memory);
void    netx_icmpv6_branch_test_application_define(void *);
void    netx_icmpv6_ra_address_full_test_application_define(void *first_unused_memory);
void    netx_icmpv6_ra_slla_changed_test_application_define(void *first_unused_memory);
void    netx_icmpv6_ra_router_full_test_application_define(void *first_unused_memory);
void    netx_icmpv6_invalid_message_test_application_define(void *);
void    netx_icmpv6_ra_invalid_length_test_application_define(void *);
void    netx_icmpv6_ra_buffer_overwrite_test_application_define(void *);
void    netx_icmpv6_ns_with_small_packet_test_application_define(void *);
void    netx_icmpv6_ns_buffer_overwrite_test_application_define(void *first_unused_memory);
void    netx_icmpv6_invalid_ra_option_test_application_define(void *);
void    netx_icmpv6_too_big_buffer_overwrite_test_application_define(void *);

void    netx_igmp_basic_test_application_define(void *);
void    netx_igmp_multicast_basic_test_application_define(void *);
void    netx_igmp_loopback_test_application_define(void *);   
void    netx_igmp_packet_receive_function_test_application_define(void *);  
void    netx_igmp_router_query_test_application_define(void *);  
void    netx_igmp_nxe_api_test_application_define(void *);   
void    netx_igmp_leave_test_application_define(void *);   
void    netx_igmp_join_fail_test_application_define(void *);   
void    netx_igmp_checksum_computation_test_application_define(void *);
void    netx_igmp_branch_test_application_define(void *);
void    netx_igmp_interface_indirect_report_send_test_application_define(void *);
        

void    netx_nd_cache_api_test_application_define(void *); 
void    netx_nd_cache_under_interface_detach_test_application_define(void *); 
void    netx_nd_cache_with_own_address_test_application_define(void *); 
void    netx_nd_cache_add_test_application_define(void *); 
void    netx_nd_cache_nxe_api_test_application_define(void *); 
void    netx_nd_cache_branch_test_application_define(void *); 
void    netx_dest_table_add_fail_test_application_define(void *); 

void    netx_ip_basic_test_application_define(void *);
void    netx_ip_link_status_test_application_define(void *);
void    netx_ip_create_test_application_define(void *);
void    netx_ip_delete_test_application_define(void *);
void    netx_ip_status_check_test_application_define(void*);
void    netx_ip_fragmentation_order_test_application_define(void *);
void    netx_ip_fragmentation_test_application_define(void *);
void    netx_ip_fragmentation_disable_test_application_define(void *);
void    netx_ip_fragmentation_timeout_check_test_application_define(void *);
void    netx_ip_fragmentation_timeout_check_test_2_application_define(void *);
void    netx_ip_fragmentation_time_exceeded_message_test_application_define(void *);
void    netx_ip_fragmentation_duplicate_test_application_define(void *);
void    netx_ip_fragmentation_dispatch_fail_test_application_define(void *);
void    netx_ip_fragmentation_packet_copy_test_application_define(void *); 
void    netx_ip_fragmentation_packet_delay_test_application_define(void *);
void    netx_ip_fragmentation_packet_drop_test_application_define(void *);
void    netx_ip_fragmentation_wrong_destination_address_test_application_define(void *);
void    netx_ip_fragmentation_wrong_protocol_field_test_application_define(void *);
void    netx_ip_fragmentation_wrong_protocol_field_test2_application_define(void *);
void    netx_ip_interface_attachment_test_application_define(void*);
void    netx_ip_interface_detachment_test_application_define(void*);
void    netx_ip_interface_detachment_tcp_connection_test_application_define(void*);
void    netx_ip_interface_detachment_arp_table_test_application_define(void*);
void    netx_ip_interface_detachment_gateway_test_application_define(void*);
void    netx_ip_interface_status_check_fail_test_application_define(void*);
void    netx_ip_interface_status_check_test_application_define(void*);
void    netx_ip_interface_address_get_test_application_define(void*);
void    netx_ip_interface_address_set_test_application_define(void*);
void    netx_ip_interface_info_get_test_application_define(void*);
void    netx_ip_interface_capability_test_application_define(void *);
void    netx_ip_interface_physical_address_set_fail_test_application_define(void *);
void    netx_ip_interface_physical_address_test_application_define(void *);
void    netx_ip_max_payload_size_find_test_application_define(void*);
void    netx_ip_address_get_test_application_define(void*);
void    netx_ip_address_set_test_application_define(void*);
void    netx_ip_address_change_notify_test_application_define(void*);
void    netx_ip_address_conflict_callback_test_application_define(void*);
void    netx_ip_address_conflict_detection_test_application_define(void*);
void    netx_ip_auxiliary_packet_pool_set_test_application_define(void*);
void    netx_ip_multicast_interface_detach_test_application_define(void *); 
void    netx_ip_gateway_address_test_application_define(void*);
void    netx_ip_static_route_add_test_application_define(void*);
void    netx_ip_static_route_delete_test_application_define(void*);
void    netx_ip_static_route_find_test_application_define(void*);
void    netx_ip_invalid_packet_receive_test_application_define(void*);
void    netx_ip_chain_packet_process_test_application_define(void*);
void    netx_ip_nxe_api_test_application_define(void *);  
void    netx_ip_abnormal_packet_test_application_define(void *);
void    netx_ip_link_local_address_test_application_define(void *);
void    netx_ip_route_reachable_test_application_define(void *);
void    netx_ip_packet_filter_test_application_define(void *);
void    netx_ip_packet_filter_extended_test_application_define(void *);
void    netx_ip_driver_deferred_test_application_define(void *);
void    netx_ip_loopback_multihome_test_application_define(void *);
void    netx_ip_branch_test_application_define(void *);
void    netx_ip_malformed_packet_test_application_define(void *);
void    netx_ip_idle_scan_test_application_define(void *);

void    netx_ipv4_option_process_test_application_define(void *);  

void    netx_ip_raw_packet_test_application_define(void *);
void    netx_raw_special_test_application_define(void *);
void    netx_raw_nxe_api_test_application_define(void *);
void    netx_ip_raw_packet_filter_test_application_define(void *);
void    netx_ip_raw_packet_queue_test_application_define(void *); 
void    netx_ipv6_raw_packet_test_application_define(void *);
void    netx_ip_raw_loopback_test_application_define(void *);

/* Forward function.  */
void    netx_forward_icmp_ping_test_application_define(void *);
void    netx_forward_icmp_ttl_test_application_define(void *);
void    netx_forward_icmp_small_header_test_application_define(void *);
void    netx_forward_icmp_small_header_test2_application_define(void *);
void    netx_forward_icmp_small_header_test3_application_define(void *);
void    netx_forward_multicast_test_application_define(void *);
void    netx_forward_udp_test_application_define(void *);     
void    netx_forward_udp_fragment_test_application_define(void *);
void    netx_forward_udp_fragment_test2_application_define(void *);
void    netx_forward_udp_fragment_test3_application_define(void *);
void    netx_forward_udp_fragment_test4_application_define(void *);
void    netx_forward_tcp_test_1_application_define(void *);
void    netx_forward_tcp_test_2_application_define(void *);
void    netx_forward_tcp_test_3_application_define(void *);
void    netx_forward_tcp_test_4_application_define(void *);
void    netx_forward_tcp_test_5_application_define(void *);
void    netx_forward_link_local_address_test_application_define(void *);
                                                              
void    netx_ipv6_disable_test_application_define(void *);
void    netx_ipv6_fragmentation_test_application_define(void *);
void    netx_ipv6_fragmentation_error_test1_application_define(void *);
void    netx_ipv6_fragmentation_error_test2_application_define(void *);
void    netx_ipv6_default_router_api_test_application_define(void *);
void    netx_ipv6_address_delete_application_define(void *);
void    netx_ipv6_address_get_test_application_define(void *);
void    netx_ipv6_address_set_test_application_define(void *);
void    netx_ipv6_search_onlink_test_application_define(void *); 
void    netx_ipv6_multicast_basic_test_application_define(void *); 
void    netx_ipv6_multicast_ping_test_application_define(void *); 
void    netx_ipv6_multicast_ping_test1_application_define(void *); 
void    netx_ipv6_multicast_interface_detach_test_application_define(void *); 
void    netx_ipv6_stateless_address_autoconfig_application_define(void *);
void    netx_ipv6_prefix_test_application_define(void *);
void    netx_ipv6_hop_by_hop_option_error_test_application_define(void *);
void    netx_ipv6_hop_by_hop_fragment_test_application_define(void *);
void    netx_ipv6_util_api_test_application_define(void *);   
void    netx_ipv6_nxe_api_test_application_define(void *);   
void    netx_ipv6_send_fail_test_application_define(void *);   
void    netx_ipv6_default_router_test_application_define(void *); 
void    netx_ipv6_invalid_packet_receive_test_application_define(void *);
void    netx_ipv6_packet_chain_test_application_define(void *);
void    netx_ipv6_fragment_fail_test_application_define(void *);
void    netx_ipv6_pmtu_test_application_define(void *);
void    netx_ipv6_interface_detachment_router_test_application_define(void *);
void    netx_ipv6_branch_test_application_define(void *);

void    netx_packet_basic_test_application_define(void *);
void    netx_packet_data_append_test_application_define(void *);
void    netx_packet_debug_info_test_application_define(void *);
void    netx_packet_suspension_test_application_define(void *);  
void    netx_packet_nxe_api_test_application_define(void *);
void    netx_packet_branch_test_application_define(void *);

void    netx_low_watermark_test_application_define(void *);
void    netx_low_watermark_zero_window_test_application_define(void *);
void    netx_low_watermark_fragment_test_application_define(void *);

void    netx_rarp_basic_processing_test_application_define(void *);  
void    netx_rarp_packet_allocate_fail_test_application_define(void *);  
void    netx_rarp_nxe_api_test_application_define(void *);  
void    netx_rarp_multiple_interfaces_test_application_define(void *); 
void    netx_rarp_branch_test_application_define(void*);   

void    netx_tcp_duplicate_accept_test_application_define(void *);
void    netx_tcp_ack_check_for_syn_message_test_application_define(void *);
void    netx_tcp_ack_check_issue_test_application_define(void *);
void    netx_tcp_basic_processing_test_application_define(void *);
void    netx_tcp_zero_window_test_application_define(void *);
void    netx_tcp_zero_window_probe_test_application_define(void *);
void    netx_tcp_zero_window_probe_test_2_application_define(void *);
void    netx_tcp_zero_window_probe_test_3_application_define(void *);
void    netx_tcp_fin_wait_recv_test_application_define(void *);
void    netx_tcp_window_update_application_define(void *);
void    netx_tcp_retransmit_test_application_define(void *);
void    netx_tcp_retransmit_test_1_application_define(void *);
void    netx_tcp_send_fail_test_application_define(void *);
void    netx_tcp_send_fail_test2_application_define(void *);
void    netx_tcp_send_fail_test3_application_define(void *);
void    netx_tcp_listen_test_application_define(void *);
void    netx_tcp_listen_packet_leak_test_application_define(void *);
void    netx_tcp_socket_available_bytes_test_application_define(void *);
void    netx_tcp_socket_delete_test_application_define(void *);
void    netx_tcp_socket_unbind_test_application_define(void *);
void    netx_tcp_socket_unbind_test2_application_define(void *);
void    netx_tcp_socket_unaccept_test_application_define(void *);
void    netx_tcp_socket_unlisten_test_application_define(void *);
void    netx_tcp_socket_relisten_test_application_define(void *);
void    netx_tcp_socket_relisten_test2_application_define(void *);
void    netx_tcp_socket_listen_test_application_define(void *);
void    netx_tcp_socket_listen_queue_test_application_define(void *);
void    netx_tcp_server_socket_accept_test_application_define(void *);
void    netx_tcp_connection_reset_test_application_define(void *);
void    netx_tcp_fast_retransmit_test_application_define(void *);
void    netx_tcp_data_transfer_test_application_define(void *);
void    netx_tcp_data_trim_test_application_define(void *);
void    netx_tcp_dropped_packet_test_application_define(void *);
void    netx_tcp_dropped_packet_test2_application_define(void *);
void    netx_tcp_fast_disconnect_test_application_define(void *);
void    netx_tcp_loopback_test_application_define(void *);
void    netx_tcp_out_of_order_packet_test_application_define(void *);
void    netx_tcp_out_of_order_ack_test_application_define(void *);
void    netx_tcp_out_of_order_packet_max_test_application_define(void *);
void    netx_tcp_small_window_preempt_test_application_define(void *);
void    netx_tcp_small_window_test_application_define(void *);
void    netx_tcp_ipv4_interface2_mss_test_application_define(void *); 
void    netx_tcp_ipv6_basic_processing_test_application_define(void *);
void    netx_tcp_ipv6_interface2_mss_test_application_define(void *);
void    netx_tcp_ipv6_window_scale_test_application_define(void *);
void    netx_tcp_wrapping_sequence_test_application_define(void *);
void    netx_tcp_wrapping_sequence_test2_application_define(void *);
void    netx_tcp_wrapping_sequence_test3_application_define(void *);
void    netx_tcp_wrapping_sequence_test4_application_define(void *);
void    netx_tcp_queue_depth_nofity_application_define(void *);  
void    netx_tcp_client_bind_cleanup_test_application_define(void *); 
void    netx_tcp_transmit_cleanup_test_application_define(void *);  
void    netx_tcp_receive_cleanup_test_application_define(void *); 
void    netx_tcp_packet_receive_function_test_application_define(void *);
void    netx_tcp_error_operation_check_test_application_define(void *);
void    netx_tcp_socket_send_internal_test_application_define(void *);
void    netx_tcp_socket_state_wait_test_application_define(void *);
void    netx_tcp_keepalive_test_application_define(void *);
void    netx_tcp_client_socket_port_get_test_application_define(void *); 
void    netx_tcp_client_socket_bind_test_application_define(void *); 
void    netx_tcp_client_packet_leak_test_application_define(void *); 
void    netx_tcp_client_socket_unbind_test_application_define(void *); 
void    netx_tcp_transmit_under_interface_detach_test_application_define(void *); 
void    netx_tcp_receive_under_interface_detach_test_application_define(void *); 
void    netx_tcp_receive_under_interface_detach_test2_application_define(void *); 
void    netx_tcp_max_window_scale_test_application_define(void *);
void    netx_tcp_mss_option_test_application_define(void *);
void    netx_tcp_socket_mss_test_application_define(void *);
void    netx_tcp_fin_wait1_to_time_wait_test_application_define(void *);
void    netx_tcp_time_wait_to_close_test_application_define(void *);
void    netx_tcp_invalid_option_test_application_define(void *);
void    netx_tcp_invalid_option_test2_application_define(void *);
void    netx_tcp_out_of_window_control_packet_test_application_define(void *);
void    netx_tcp_new_reno_algorithm_test1_application_define(void *); 
void    netx_tcp_new_reno_algorithm_test2_application_define(void *); 
void    netx_tcp_new_reno_algorithm_test3_application_define(void *);   
void    netx_tcp_new_reno_algorithm_test4_application_define(void *);   
void    netx_tcp_new_reno_algorithm_test5_application_define(void *);   
void    netx_tcp_nxe_api_test_application_define(void *);  
void    netx_tcp_large_mtu_test_application_define(void *);  
void    netx_tcp_large_mtu_test_2_application_define(void *);  
void    netx_tcp_simultaneous_test_application_define(void *);  
void    netx_tcp_send_disconnect_test_application_define(void *);  
void    netx_tcp_not_enabled_test_application_define(void *);  
void    netx_tcp_tx_queue_exceed_test_application_define(void *);  
void    netx_tcp_transmit_not_done_test_application_define(void *);  
void    netx_tcp_4_duplicate_ack_test_application_define(void *);  
void    netx_tcp_cwnd_test_application_define(void *);  
void    netx_tcp_urgent_packet_test_application_define(void *);  
void    netx_tcp_multiple_send_test_application_define(void *);  
void    netx_tcp_multiple_send_test2_application_define(void *);  
void    netx_tcp_reset_during_send_test_application_define(void *);  
void    netx_tcp_delayed_retransmission_test_application_define(void *);  
void    netx_tcp_delayed_retransmission_test_2_application_define(void *);  
void    netx_tcp_ipv6_delayed_retransmission_test_application_define(void *);  
void    netx_tcp_odd_window_test_application_define(void *);  
void    netx_tcp_chained_packet_test_application_define(void *); 
void    netx_tcp_branch_test_application_define(void *);
void    netx_tcp_packet_leak_test_application_define(void *);
void    netx_tcp_udp_random_port_test_application_define(void *);
void    netx_tcp_invalid_length_test_application_define(void *);
void    netx_tcp_large_data_transfer_test_application_define(void *);
void    netx_tcp_small_packet_test_application_define(void *);
void    netx_tcp_advertised_window_update_test_application_define(void *);
void    netx_tcp_race_condition_test_application_define(void *);
void    netx_tcp_race_condition_test2_application_define(void *);
void    netx_tcp_socket_receive_rst_test_application_define(void *);
void    netx_tcp_invalid_packet_chain_test_application_define(void *);
 
void    netx_udp_basic_processing_test_application_define(void *);
void    netx_udp_socket_bind_test_application_define(void *);
void    netx_udp_socket_delete_test_application_define(void *);
void    netx_udp_socket_unbind_receive_test_application_define(void *);
void    netx_udp_socket_unbind_test_application_define(void *);
void    netx_udp_free_port_find_test_application_define(void *);
void    netx_udp_source_send_test_application_define(void *);
void    netx_udp_packet_receive_test_application_define(void *);
void    netx_udp_fragment_test_application_define(void *);
void    netx_udp_fragmentation_processing_test_application_define(void *);
void    netx_nxd_udp_socket_send_special_test_application_define(void *);
void    netx_udp_multiple_ports_test_application_define(void *);  
void    netx_udp_bind_cleanup_test_application_define(void *);  
void    netx_udp_packet_type_test_application_define(void *);    
void    netx_udp_nxe_api_test_application_define(void *);  
void    netx_udp_checksum_zero_test_application_define(void *);  
void    netx_udp_ipv4_interface2_test_1_test_application_define(void *);
void    netx_udp_ipv6_interface2_test_1_test_application_define(void *);
void    netx_udp_loopback_test_application_define(void *);
void    netx_udp_port_unreachable_test_application_define(void *);
void    netx_udp_port_table_update_test_application_define(void *);
void    netx_udp_branch_test_application_define(void *);

void    netx_icmp_ping_tunnel_ipv4_ipv4_test_application_define(void *);
void    netx_udp_tunnel_ipv4_ipv4_basic_test_application_define(void *);
void    netx_tcp_tunnel_ipv4_ipv4_basic_test_application_define(void *);
void    netx_udp_tunnel_ipv6_ipv4_basic_test_application_define(void *);
void    netx_udp_tunnel_ipv4_ipv6_basic_test_application_define(void *);
void    netx_udp_tunnel_ipv6_ipv6_basic_test_application_define(void *);
void    netx_tcp_tunnel_ipv6_ipv4_basic_test_application_define(void *);
void    netx_tcp_tunnel_ipv4_ipv6_basic_test_application_define(void *);
void    netx_tcp_tunnel_ipv6_ipv6_basic_test_application_define(void *);
void    netx_tcp_tunnel_ipv4_ipv6_address_test_application_define(void *);
void    netx_icmp_ping_tunnel_ipv4_ipv6_test_application_define(void *);
void    netx_icmp_ping6_tunnel_ipv6_ipv6_test_application_define(void *);
void    netx_icmp_ping6_tunnel_ipv6_ipv4_test_application_define(void *);
void    netx_tcp_tunnel_ipv4_ipv6_samll_windows_application_define(void *);
void    netx_tcp_tunnel_ipv4_ipv6_big_packet_test_application_define(void *);
void    netx_tcp_overlapping_packet_test_application_define(void *);
void    netx_tcp_overlapping_packet_test_2_application_define(void *);
void    netx_tcp_overlapping_packet_test_3_application_define(void *);
void    netx_tcp_overlapping_packet_test_4_application_define(void *);
void    netx_tcp_overlapping_packet_test_5_application_define(void *);
void    netx_tcp_overlapping_packet_test_6_application_define(void *);
void    netx_tcp_overlapping_packet_test_7_application_define(void *);
void    netx_tcp_overlapping_packet_test_8_application_define(void *);
void    netx_tcp_overlapping_packet_test_9_application_define(void *);
void    netx_tcp_overlapping_packet_test_10_application_define(void *);
void    netx_tcp_overlapping_packet_test_11_application_define(void *);
void    netx_tcp_overlapping_packet_test_12_application_define(void *);
void    netx_tcp_overlapping_packet_test_13_application_define(void *);
void    netx_tcp_overlapping_packet_test_14_application_define(void *);
void    netx_tcp_overlapping_packet_test_15_application_define(void *);
void    netx_tcp_overlapping_packet_test_16_application_define(void *);
void    netx_tcp_overlapping_packet_test_17_application_define(void *);
void    netx_tcp_overlapping_packet_test_18_application_define(void *);

/* TCP tests*/
void    netx_1_01_application_define(void *);
void    netx_1_02_application_define(void *);
void    netx_1_03_application_define(void *);
void    netx_1_04_application_define(void *);
void    netx_1_04_ipv6_application_define(void *);
void    netx_1_05_application_define(void *);
void    netx_1_17_application_define(void *);
void    netx_1_18_application_define(void *);
void    netx_1_19_01_application_define(void *);
void    netx_1_19_02_application_define(void *);
void    netx_1_19_03_application_define(void *);
void    netx_1_20_application_define(void *);
void    netx_1_21_01_application_define(void *);
void    netx_1_21_02_application_define(void *);
void    netx_1_26_01_application_define(void *);
void    netx_1_26_02_application_define(void *);
void    netx_1_27_01_application_define(void *);
void    netx_1_27_02_application_define(void *);
void    netx_1_27_03_application_define(void *);
void    netx_1_27_04_application_define(void *);
void    netx_2_01_application_define(void *);
void    netx_2_02_application_define(void *);
void    netx_2_17_application_define(void *);
void    netx_2_20_application_define(void *);
void    netx_3_01_application_define(void *);
void    netx_3_02_application_define(void *);
void    netx_3_03_application_define(void *);
void    netx_3_04_application_define(void *);
void    netx_3_06_application_define(void *);
void    netx_3_07_application_define(void *);
void    netx_3_08_application_define(void *);
void    netx_3_17_application_define(void *);
void    netx_3_18_application_define(void *);
void    netx_3_19_application_define(void *);
void    netx_3_20_application_define(void *);
void    netx_3_21_application_define(void *);
void    netx_3_23_application_define(void *);
void    netx_4_01_application_define(void *);
void    netx_4_17_application_define(void *);
void    netx_4_21_application_define(void *);
void    netx_4_23_application_define(void *);
void    netx_4_24_application_define(void *);
void    netx_4_25_application_define(void *);
void    netx_4_26_application_define(void *);
void    netx_4_27_application_define(void *);
void    netx_4_28_application_define(void *);
void    netx_4_29_application_define(void *);
void    netx_5_18_application_define(void *);
void    netx_5_19_application_define(void *);
void    netx_5_20_application_define(void *);
void    netx_5_21_application_define(void *);
void    netx_5_22_application_define(void *);
void    netx_5_23_application_define(void *);
void    netx_5_24_application_define(void *);
void    netx_5_25_application_define(void *);
void    netx_6_17_application_define(void *);
void    netx_6_18_application_define(void *);
void    netx_6_20_application_define(void *);
void    netx_6_22_01_application_define(void *);
void    netx_6_22_02_application_define(void *);
void    netx_6_23_application_define(void *);
void    netx_6_24_application_define(void *);
void    netx_6_25_application_define(void *);
void    netx_6_27_application_define(void *);
void    netx_6_28_application_define(void *);
void    netx_6_29_application_define(void *);
void    netx_6_32_application_define(void *);
void    netx_8_01_application_define(void *);
void    netx_8_02_application_define(void *);
void    netx_8_17_application_define(void *);
void    netx_8_18_application_define(void *);
void    netx_8_19_application_define(void *);
void    netx_8_20_application_define(void *);
void    netx_8_21_application_define(void *);
void    netx_8_29_01_application_define(void *);
void    netx_8_29_02_application_define(void *);
void    netx_8_29_03_application_define(void *);
void    netx_8_29_04_application_define(void *);
void    netx_9_17_application_define(void *);
void    netx_9_18_application_define(void *);
void    netx_9_19_01_application_define(void *);
void    netx_9_19_02_application_define(void *);
void    netx_9_20_application_define(void *);
void    netx_9_21_01_application_define(void *);
void    netx_9_21_02_application_define(void *);
void    netx_9_22_application_define(void *);
void    netx_9_27_application_define(void *);
void    netx_10_23_01_application_define(void *);
void    netx_10_23_02_application_define(void *);
void    netx_10_24_01_application_define(void *);
void    netx_10_24_02_application_define(void *);
void    netx_10_24_03_application_define(void *);
void    netx_10_25_application_define(void *);
void    netx_10_26_application_define(void *);
void    netx_11_18_application_define(void *);
void    netx_11_19_application_define(void *);
void    netx_11_24_application_define(void *);
void    netx_11_25_application_define(void *);
void    netx_11_26_application_define(void *);
void    netx_11_27_application_define(void *);
void    netx_11_28_application_define(void *);
void    netx_11_29_application_define(void *);
void    netx_12_01_application_define(void *);
void    netx_12_02_application_define(void *);
void    netx_12_03_application_define(void *);
void    netx_12_04_application_define(void *);
void    netx_12_17_application_define(void *);
void    netx_12_18_application_define(void *);
void    netx_12_19_application_define(void *);
void    netx_12_20_application_define(void *);
void    netx_12_21_application_define(void *);
void    netx_12_23_application_define(void *);
void    netx_12_24_application_define(void *);
void    netx_12_25_application_define(void *);
void    netx_12_26_application_define(void *);
void    netx_12_27_application_define(void *);
void    netx_12_30_application_define(void *);
void    netx_12_31_application_define(void *);
void    netx_13_01_application_define(void *);
void    netx_13_02_application_define(void *);
void    netx_13_04_application_define(void *);
void    netx_13_05_application_define(void *);
void    netx_13_17_application_define(void *);
void    netx_14_19_application_define(void *);
void    netx_14_20_application_define(void *);
void    netx_15_03_application_define(void *);
void    netx_15_20_application_define(void *);
void    netx_15_21_application_define(void *);
void    netx_15_24_application_define(void *);
void    netx_15_25_application_define(void *);
void    netx_15_26_application_define(void *);
void    netx_16_02_application_define(void *);
void    netx_16_17_application_define(void *);
void    netx_16_19_application_define(void *);
void    netx_16_21_application_define(void *);
void    netx_16_22_application_define(void *);
void    netx_17_17_application_define(void *);
void    netx_23_02_01_application_define(void *);
void    netx_23_02_02_application_define(void *);
void    netx_23_02_03_application_define(void *);
void    netx_23_02_04_application_define(void *);
void    netx_101_17_application_define(void *);
void    netx_101_18_application_define(void *);
void    netx_102_18_application_define(void *);
void    netx_102_19_application_define(void *);
void    netx_102_20_application_define(void *);
void    netx_102_21_application_define(void *);
void    netx_102_22_application_define(void *);
void    netx_102_23_application_define(void *);
void    netx_102_24_application_define(void *);
void    netx_102_25_application_define(void *);
void    netx_103_17_application_define(void *);
void    netx_104_17_application_define(void *);
void    netx_106_17_application_define(void *);


/* Applications.  */

/* Application tests do not support for 64-bit mode yet.  */
#ifndef XWARE_64

/* AUTO IP.  */
void    netx_auto_ip_basic_test_application_define(void *);
void    netx_auto_ip_address_check_test_application_define(void *);
void    netx_auto_ip_announce_num_test_application_define(void *);
void    netx_auto_ip_arp_dest_addr_test_application_define(void *);
void    netx_auto_ip_max_conflicts_test_application_define(void *);


/* WebSocket. */
void    netx_websocket_fin_test_application_define(void *);
void    netx_websocket_opcode_test_application_define(void *);
void    netx_websocket_connect_test_application_define(void *);
void    netx_websocket_disconnect_test_application_define(void *);
void    netx_websocket_mask_test_application_define(void *);
void    netx_websocket_one_frame_in_packets_test_application_define(void *);
void    netx_websocket_one_packet_with_multi_frames_test_application_define(void *);
void    netx_websocket_16_bit_payload_length_test_application_define(void *);
void    netx_websocket_delete_test_application_define(void *);
void    netx_websocket_multi_instance_test_application_define(void *);
void    netx_websocket_non_block_test_application_define(void *);
void    netx_websocket_send_chain_packets_test_application_define(void *);


/* HTTP.  */
void    netx_http_basic_test_application_define(void *);
void    netx_http_if_modified_since_test_application_define(void *);
void    netx_http_head_basic_test_application_define(void *);
void    netx_http_post_basic_test_application_define(void *);
void    netx_http_delete_basic_test_application_define(void *);
void    netx_http_basic_authenticate_test_application_define(void *);
void    netx_http_status_404_test_application_define(void *);
void    netx_http_multipart_fragment_test_application_define(void *);
void    netx_http_multipart_underflow_test_application_define(void *);
void    netx_http_get_content_length_test_application_define(void *);
void    netx_http_get_contentlength_packetleak_test_application_define(void *);
void    netx_http_client_change_connect_port_test_application_define(void *);
void    netx_http_get_put_referred_URI_test_application_define(void *);
void    netx_http_request_in_multiple_packets_test_application_define(void *);
void    netx_http_digest_authenticate_test_application_define(void *);
void    netx_http_server_type_retrieve_test_application_define(void *);
void    netx_http_digest_authenticate_timeout_test_application_define(void *);

/*HTTP Proxy. */
void    netx_http_proxy_basic_test_application_define(void *);
void    netx_http_proxy_non_block_test_application_define(void *);
void    netx_http_proxy_multiple_response_test_application_define(void *);
void    netx_http_proxy_error_response_test_application_define(void *);
void    netx_http_proxy_disconnect_test_application_define(void *);
void    netx_http_proxy_data_fin_test_application_define(void *);


/* FTP.  */
void    netx_ftp_basic_test_application_define(void *);
void    netx_ftp_access_control_commands_01_test_application_define(void *);
void    netx_ftp_access_control_commands_02_test_application_define(void *);
void    netx_ftp_access_control_commands_03_test_application_define(void *);
void    netx_ftp_access_control_commands_04_test_application_define(void *);
void    netx_ftp_commands_characters_test_application_define(void *);
void    netx_ftp_commands_replys_test_application_define(void *);
void    netx_ftp_control_connection_test_application_define(void *);
void    netx_ftp_data_connection_test_application_define(void *);
void    netx_ftp_establish_data_connection_03_test_application_define(void *);
void    netx_ftp_establish_data_connection_05_test_application_define(void *);
void    netx_ftp_establish_data_connection_06_test_application_define(void *);
void    netx_ftp_establish_data_connection_08_test_application_define(void *);
void    netx_ftp_service_commands_nlist_test_application_define(void *);
void    netx_ftp_service_commands_rename_test_application_define(void *);
void    netx_ftp_service_commands_RETR_STOR_test_application_define(void *);
void    netx_ftp_user_data_type_application_define(void *);
void    netx_ftp_service_commands_file_write_test_application_define(void *);
void    netx_ftp_client_pasv_denied_test_application_define(void *);
void    netx_ftp_client_pasv_file_read_test_application_define(void *);
void    netx_ftp_client_pasv_file_write_test_application_define(void *);
void    netx_ftp_client_invalid_username_password_length_test_application_define(void *first_unused_memory); 
void    netx_ftp_client_multiple_connection_response_test_application_define(void*);
void    netx_ftp_client_packet_leak_test_application_define(void *first_unused_memory); 
void    netx_ftp_client_buffer_overflow_test_application_define(void *first_unused_memory); 
void    netx_ftp_client_file_write_fail_test_application_define(void *);
void    netx_ftp_server_invalid_month_crash_test_application_define(void *first_unused_memory); 
void    netx_ftp_server_mss_too_small_test_application_define(void *first_unused_memory); 
void    netx_ftp_rst_test_application_define(void *first_unused_memory); 
void    netx_ftp_two_listen_test_application_define(void *first_unused_memory); 
void    netx_ftp_parse_ipv6_address_test_application_define(void *);
void    netx_ftp_server_abnormal_packet_test_application_define(void *);
void    netx_ftp_server_list_command_test_application_define(void *);
void    netx_ftp_server_dangling_pinter_test_application_define(void *);
void    netx_ftp_pasv_twice_test_application_define(void *);
void    netx_ftp_disconnection_event_test_application_define(void *);
void    netx_ftp_ipv6_epsv_test_application_define(void *);
void    netx_ftp_pasv_port_test_application_define(void *);
void    netx_ftp_pasv_stor_test_application_define(void *);


/* PPP test.  */
void    netx_ppp_IPCP_timeout_test_application_define(void *);
void    netx_ppp_LCP_timeout_test_application_define(void *);
void    netx_ppp_chap_bad_secret_failed_retry_test_application_define(void *);
void    netx_ppp_chap_bad_secret_passed_on_retry_test_application_define(void *);
void    netx_ppp_check_boundary_test_application_define(void *);
void    netx_ppp_request_dns_server_test_application_define(void *);
void    netx_ppp_PAP_bad_password_test_application_define(void *);
void    netx_ppp_PAP_bad_username_test_application_define(void *);
void    netx_ppp_pap_null_name_password_test_application_define(void *);
void    netx_ppp_LCP_invalid_packet_test_application_define(void *);
void    netx_ppp_IPCP_abnormal_packet_test_application_define(void *);
void    netx_ppp_IPCP_nak_test_application_define(void *);
void    netx_ppp_IPCP_retransmit_test_application_define(void *);
void    netx_ppp_pap_basic_test_application_define(void *);
void    netx_ppp_pfc_option_test_application_define(void *);
void    netx_ppp_acfc_option_test_application_define(void *);


/* PPPoE test.  */
void    netx_pppoe_basic_test_application_define(void *);
void    netx_pppoe_api_test_application_define(void *);
void    netx_pppoe_api_extended_test_application_define(void *);
void    netx_pppoe_ac_name_test_application_define(void *);
void    netx_pppoe_session_control_test_application_define(void *);

/* RTP test. */
void    netx_rtp_multi_interfaces_test_application_define(void *first_unused_memory);
void    netx_rtp_session_packet_send_test_application_define(void *first_unused_memory);
void    netx_rtp_session_jpeg_send_test_application_define(void *first_unused_memory);
void    netx_rtp_session_h264_send_test_application_define(void *first_unused_memory);
void    netx_rtp_session_aac_send_test_application_define(void *first_unused_memory);
void    netx_rtp_free_udp_port_find_test_application_define(void *first_unused_memory);
void    netx_rtp_multi_clients_test_application_define(void *first_unused_memory);
void    netx_rtp_multicast_test_application_define(void *first_unused_memory);
void    netx_rtp_basic_test_application_define(void *first_unused_memory);
void    netx_rtp_api_test_application_define(void *first_unused_memory);
void    netx_rtcp_abnormal_packet_test_application_define(void *first_unused_memory);
void    netx_rtcp_packet_process_test_application_define(void *first_unused_memory);
void    netx_rtcp_packet_send_test_application_define(void *first_unused_memory);
void    netx_rtcp_basic_test_application_define(void *first_unused_memory);

/* RTSP test. */
void    netx_rtsp_api_test_application_define(void *);
void    netx_rtsp_rtp_basic_test_application_define(void *);
void    netx_rtsp_rtp_ipv6_basic_test_application_define(void *);
void    netx_rtsp_rtp_multicast_test_application_define(void *);
void    netx_rtsp_rtp_ipv6_multicast_test_application_define(void *);
void    netx_rtsp_multiple_request_test_application_define(void *);
void    netx_rtsp_multiple_clients_test_application_define(void *);
void    netx_rtsp_client_timeout_test_application_define(void *);
void    netx_rtsp_error_response_test_application_define(void *);
void    netx_rtsp_delete_beforehand_test_application_define(void *);

/* TFTP.  */
void    netx_tftp_basic_test_application_define(void *);  
#ifdef FEATURE_NX_IPV6 
void    netx_tftp_ipv6_basic_test_application_define(void *);
#endif   
void    netx_tftp_read_interaction_test_application_define(void *);
void    netx_tftp_write_interaction_test_application_define(void *);  
void    netx_tftp_error_destination_port_test_application_define(void *);   
void    netx_tftp_error_file_name_test_application_define(void *);  
void    netx_tftp_large_data_test_application_define(void *);  
void    netx_tftp_malformed_packet_test_application_define(void *);


/* TELNET.  */
void    netx_telnet_create_packet_pool_test_application_define(void *);
void    netx_telnet_max_connections_test_application_define(void *);
void    netx_telnet_activity_timeout_test_application_define(void *);
void    netx_telnet_server_options_negotiate_test_application_define(void *);
void    netx_telnet_server_bad_option_reply_test_application_define(void *);
void    netx_telnet_rst_test_application_define(void *);
void    netx_telnet_two_listen_test_application_define(void *);


/* SNTP.  */
void    netx_sntp_client_unicast_basic_test_application_define(void *);
void    netx_sntp_client_broadcast_basic_test_application_define(void *);
void    netx_sntp_client_ipv6_unicast_basic_test_application_define(void *);
void    netx_sntp_client_ipv6_broadcast_basic_test_application_define(void *);
void    netx_sntp_request_unicast_test_application_define(void *);
void    netx_sntp_forward_unicast_update_test_application_define(void *);
void    netx_sntp_client_unicast_display_date_test_application_define(void *);
void    netx_sntp_client_seconds_to_date_test_application_define(void *);
void    netx_sntp_client_kod_test_application_define(void *);
void    netx_sntp_client_packet_chain_test_application_define(void *);


/* SNMP Agent */
void    netx_snmp_v1_buffer_overwrite_test_application_define(void *);
void    netx_snmp_v1_object_id_buffer_overwrite_test_application_define(void *);
void    netx_snmp_v1_packet_double_release_test_application_define(void *);
void    netx_snmp_basic_v2_test_application_define(void*);
void    netx_snmp_v2_get_bulk_request_test_application_define(void *);
void    netx_snmp_v2_unknown_oid_test_application_define(void*);
void    netx_snmp_v2_send_trap_test_application_define(void*);
void    netx_snmp_v2_buffer_overwrite_test_application_define(void *);
void    netx_snmp_v3_nosec_traplist_test_application_define(void *);
void    netx_snmp_v3_md5_failed_security_test_application_define(void *);
void    netx_snmp_v3_no_security_application_define(void*);
void    netx_snmp_v3_md5_security_test_application_define(void *);
void    netx_snmp_v3_md5_security_extended_test_application_define(void *);
void    netx_snmp_v3_buffer_overwrite_test_application_define(void *);
void    netx_snmp_v3_decrypt_pdu_buffer_overwrite_test_application_define(void *);
void    netx_snmp_v3_encrypt_pdu_buffer_overwrite_test_application_define(void *);
void    netx_snmp_v3_encrypt_pdu_padding_buffer_overwrite_test_application_define(void *);
void    netx_snmp_v3_object_id_buffer_overwrite_test_application_define(void *);

void    netx_snmp_setget_integers_test_application_define(void *);
void    netx_snmp_setget_octet_strings_test_application_define(void *);
void    netx_snmp_setget_ip_address_test_application_define(void *);
void    netx_snmp_setget_misc_test_application_define(void *);
void    netx_snmp_abnormal_packet_test_application_define(void *);
#endif /* XWARE_64 */


/* DHCP.  */
void    netx_dhcp_basic_test_application_define(void *);
void    netx_dhcp_basic_restore_test_application_define(void *);
void    netx_dhcp_unicast_test_application_define(void *);
void    netx_dhcp_user_option_add_test_application_define(void *);
void    netx_dhcp_server_improper_term_test_application_define(void *);
void    netx_dhcp_03_01_01_test_application_define(void *);
void    netx_dhcp_03_02_01_test_application_define(void *);
void    netx_dhcp_03_02_02_test_application_define(void *);
void    netx_dhcp_03_02_03_test_application_define(void *);
void    netx_dhcp_03_05_01_test_application_define(void *);
void    netx_dhcp_04_01_01_test_application_define(void *);
void    netx_dhcp_04_03_02_01_test_application_define(void *);
void    netx_dhcp_04_03_02_02_test_application_define(void *);
void    netx_dhcp_04_03_02_03_test_application_define(void *);
void    netx_dhcp_04_03_05_01_test_application_define(void *);
void    netx_dhcp_04_04_01_01_test_application_define(void *);
void    netx_dhcp_04_04_01_02_test_application_define(void *);
void    netx_dhcp_packet_process_test_application_define(void*);
void    netx_dhcp_client_send_with_zero_source_address_test_application_define(void*);
void    netx_dhcp_multiple_instances_test_application_define(void*);
void    netx_dhcp_send_request_internal_test_application_define(void*);
void    netx_dhcp_extract_information_test_application_define(void*);
void    netx_dhcp_get_option_value_test_application_define(void *);
void    netx_dhcp_delete_test_application_define(void*);
void    netx_dhcp_stop_test_application_define(void *);
void    netx_dhcp_enable_test_application_define(void *);
void    netx_dhcp_start_test_application_define(void *);
void    netx_dhcp_release_test_application_define(void *);
void    netx_dhcp_reinitialize_test_application_define(void *);
void    netx_dhcp_client_activate_interfaces_test_application_define(void *);
void    netx_dhcp_client_secondary_interface_test_application_define(void *);
void    netx_dhcp_client_interface_order_test_application_define(void *);
void    netx_dhcp_client_ip_mutex_test_application_define(void *);
void    netx_dhcp_client_server_source_port_test_application_define(void *);
void    netx_dhcp_client_parameter_request_test_application_define(void *);
void    netx_dhcp_client_ntp_option_test_application_define(void *);
void    netx_dhcp_skip_discover_test_application_define(void *);
void    netx_dhcp_coverage_test_applicaiton_define(void*);
void    netx_dhcp_client_nxe_api_test_application_define(void*);
void    netx_dhcp_server_test_application_define(void *);
void    netx_dhcp_server_second_interface_test_application_define(void *);
void    netx_dhcp_server_options_test_application_define(void *);
void    netx_dhcp_server_small_packet_payload_test_application_define(void *);

void    netx_dhcpv6_basic_test_application_define(void *);
void    netx_dhcpv6_extended_api_test_application_define(void *);
void    netx_dhcpv6_packet_loss_test_application_define(void *); 
void    netx_dhcpv6_client_process_server_duid_test_application_define(void *);
void    netx_dhcpv6_server_ia_options_test_application_define(void *);
void    netx_dhcpv6_server_iana_test_application_define(void *);
void    netx_dhcpv6_server_process_repeated_msgs_test_application_define(void *);
void    netx_dhcpv6_user_option_add_test_application_define(void *);

#ifndef XWARE_64

void    netx_dhcpv4_relay_test_define(void *);  

#ifdef FEATURE_NX_IPV6
void    netx_dhcpv6_relay_test_define(void *);
#endif


/* SMTP Client */
void    netx_smtp_basic_function_test_application_define(void *);
void    netx_smtp_two_packet_ehlo_message_test_application_define(void *);
void    netx_smtp_auth_logon_function_test_application_define(void *);
void    netx_smtp_auth_none_test_application_define(void *);
void    netx_smtp_missing_last_250_EHLO_message_test_application_define(void *);
void    netx_smtp_two_packet_EHLO_auth_last_message_test_application_define(void *);
void    netx_smtp_auth_no_type_test_application_define(void *);
void    netx_smtp_abnormal_packet_test_application_define(void *);
void    netx_smtp_invalid_release_test_application_define(void *);


/* POP3 client */
void    netx_pop3_mail_receive_test_application_define(void *);
void    netx_pop3_two_mails_received_test_application_define(void *_);
void    netx_pop3_packet_with_endmarker_test_application_define(void *);
void    netx_pop3_abnormal_packet_test_application_define(void *);


/* NAT  */
void    netx_nat_icmp_test_application_define(void *);  
void    netx_nat_udp_test_application_define(void *);  
void    netx_nat_udp_port_test_application_define(void *);    
void    netx_nat_udp_fragment_test_application_define(void *);  
void    netx_nat_tcp_test1_application_define(void *);  
void    netx_nat_tcp_test2_application_define(void *);  
void    netx_nat_tcp_port_test_application_define(void *);  
void    netx_nat_tcp_port_test2_application_define(void *);  
void    netx_nat_tcp_fragment_test_application_define(void *);
void    netx_nat_invalid_header_test_application_define(void *);  

#endif /* !XWARE_64 */

/* DNS Test*/
void    netx_dns_coverage_test_application_define(void *);
void    netx_dns_function_test_application_define(void *);
void    netx_dns_nxe_api_test_application_define(void *);
void    netx_dns_request_a_response_cname_a_smtp_live_com_test_application_define(void *);
void    netx_dns_invalid_name_unencode_test_application_define(void *);
void    netx_dns_invalid_resource_get_test_application_define(void *);
void    netx_dns_abnormal_packet_test_application_define(void *);
void    netx_dns_source_port_test_application_define(void *);
void    netx_dns_non_blocking_a_test_application_define(void *);
void    netx_dns_fake_response_test_application_define(void *);
void    netx_dns_packet_double_release_test_application_define(void *);

#ifndef XWARE_64

/* mDNS Test.  */
void    netx_mdns_internal_function_test(void *first_unused_memory); 
void    netx_mdns_create_delete_test(void *first_unused_memory); 
void    netx_mdns_one_shot_query_test(void *first_unused_memory);
void    netx_mdns_local_cache_continuous_query_test(void *first_unused_memory); 
void    netx_mdns_local_cache_one_shot_query_test(void *first_unused_memory);
void    netx_mdns_service_lookup_test(void *first_unused_memory);
void    netx_mdns_service_add_delete_test(void *first_unused_memory);
void    netx_mdns_announcement_repeat_test(void *first_unused_memory);
void    netx_mdns_multiple_answers_test(void *first_unused_memory);
void    netx_mdns_responder_cooperating_test(void *first_unused_memory);
void    netx_mdns_response_with_question_test(void *first_unused_memory); 
void    netx_mdns_source_address_test(void *first_unused_memory);
void    netx_mdns_source_port_test(void *first_unused_memory);
void    netx_mdns_two_buffer_test(void *first_unused_memory);
void    netx_mdns_buffer_size_test(void *first_unused_memory);
void    netx_mdns_ttl_test(void *first_unused_memory);
void    netx_mdns_txt_test(void *first_unused_memory);
void    netx_mdns_txt_notation_test(void *first_unused_memory); 
void    netx_mdns_name_test(void *first_unused_memory);
void    netx_mdns_domain_name_test(void *first_unused_memory); 
void    netx_mdns_interface_test(void *first_unused_memory);
void    netx_mdns_second_interface_test(void *first_unused_memory);
void    netx_mdns_peer_service_change_notify_test(void *first_unused_memory);
void    netx_mdns_ipv6_string_test(void *first_unused_memory); 
void    netx_mdns_bad_packet_test(void *first_unused_memory);
void    netx_mdns_read_overflow_test(void *);
#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_IPV4
void    netx_mdns_ram_test_define(void *first_unused_memory);
#endif /* __PRODUCT_NETXDUO__ && !NX_DISABLE_IPV4  */


/* BSD Test */
#ifdef NX_BSD_ENABLE
void    netx_bsd_getaddrinfo_test_application_define(void *);
void    netx_bsd_raw_pppoe_test_application_define(void *first_unused_memory);
void    netx_bsd_tcp_ioctl_nonblocking_test_application_define(void *);
void    netx_bsd_tcp_two_blocking_test_application_define(void *);
void    netx_bsd_tcp_multiple_accept_test_application_define(void *);
void    netx_bsd_tcp_basic_blocking_test_application_define(void *);
void    netx_bsd_tcp_basic_nonblocking_test_application_define(void *);
void    netx_bsd_udp_basic_blocking_test_application_define(void*);
void    netx_bsd_udp_basic_nonblocking_test_application_define(void*);
void    netx_bsd_raw_basic_blocking_test_application_define(void*);
void    netx_bsd_raw_basic_nonblocking_test_application_define(void*);
void    netx_bsd_raw_basic_rx_nohdr_blocking_test_application_define(void*);
void    netx_bsd_raw_basic_rx_nohdr_nonblocking_test_application_define(void*);
void    netx_bsd_multicast_test_application_define(void*);
void    netx_bsd_udp_bind_test_application_define(void*);
void    netx_bsd_tcp_bind_test_application_define(void*);
void    netx_bsd_udp_connect_test_application_define(void*);
void    netx_bsd_tcp_disconnect_test_application_define(void*);
void    netx_bsd_tcp_sendto_test_application_define(void*);
void    netx_bsd_tcp_2nd_bind_test_application_define(void*);
void    netx_bsd_udp_blocking_bidirection_test_application_define(void *);
void    netx_bsd_tcp_blocking_bidirection_test_application_define(void *);
void    netx_bsd_udp_bind_connect_test_application_define(void *);
void    netx_bsd_raw_tx_test_application_define(void *);
void    netx_bsd_raw_bind_connect_test_application_define(void*);
void    netx_bsd_raw_rx_hdrinclude_test_application_define(void*);
void    netx_bsd_raw_rx_nohdr_basic_blocking_test_application_define(void*);
void    netx_bsd_raw_rx_nohdr_basic_nonblocking_test_application_define(void*);
void    netx_bsd_raw_basic_rx_nohdr_blocking_test_application_define(void*);
void    netx_bsd_raw_basic_rx_nohdr_basic_blocking_test_application(void*);
void    netx_bsd_raw_rx_nohdr_basic_blocking_test_application_define(void*);
void    netx_bsd_raw_ping_test_application_define(void*);
void    netx_bsd_tcp_accept_nonblocking_timeout_test_application_define(void *);
void    netx_bsd_tcp_accept_blocking_test_application_define(void *);
void    netx_bsd_tcp_accept_nonblocking_test_application_define(void *);
void    netx_bsd_tcp_accept_blocking_test_application_define(void *);
void    netx_bsd_tcp_accept_nonblocking_test_application_define(void *);
void    netx_bsd_tcp_accept_blocking_timeout_test_application_define(void *);
void    netx_bsd_tcp_accept_noselect_test_application_define(void *);
void    netx_bsd_tcp_udp_select_test_application_define(void *);
void    netx_bsd_aton_test_application_define(void *);
void    netx_bsd_ntoa_test_application_define(void *);
void    netx_bsd_ntop_test_application_define(void *);
void    netx_bsd_pton_test_application_define(void *);
void    netx_bsd_inet_addr_pton_test_application_define(void *);
void    netx_bsd_tcp_servers_share_port_test_application_define(void *);
void    netx_bsd_tcp_clients_share_port_test_application_define(void *);
void    netx_bsd_tcp_rcvbuf_test_application_define(void *);
void    netx_bsd_tcp_getsockname_without_bind_test_application_define(void *);
void    netx_bsd_udp_checksum_corrupt_test_application_define(void*);
void    netx_bsd_tcp_fionread_test_application_define(void *);
#endif /* NX_BSD_ENABLE */


/* Cloud Test  */
void    netx_cloud_basic_test_application_define(void*);
void    netx_cloud_api_test_application_define(void*);
void    netx_cloud_module_register_deregister_test_application_define(void*);
void    netx_cloud_module_event_test_application_define(void*);

#endif /* XWARE_64  */

#if defined(NX_TAHI_ENABLE) && defined(FEATURE_NX_IPV6) 

#ifdef NX_ENABLE_IPV6_PATH_MTU_DISCOVERY
/* IPv6 TAHI test*/
void    netx_tahi_test_1_define(void *);
void    netx_tahi_test_2_1_define(void *);
void    netx_tahi_test_2_2_define(void *);
void    netx_tahi_test_2_3_define(void *);
void    netx_tahi_test_2_4_define(void *);
void    netx_tahi_test_2_5_define(void *);
void    netx_tahi_test_2_6_define(void *);
void    netx_tahi_test_2_7_define(void *);
void    netx_tahi_test_2_8_define(void *);
void    netx_tahi_test_2_9_define(void *);
void    netx_tahi_test_2_10_define(void *);
void    netx_tahi_test_2_11_define(void *);
void    netx_tahi_test_3_1_define(void *);
void    netx_tahi_test_3_2_define(void *);
void    netx_tahi_test_3_3_define(void *);
void    netx_tahi_test_3_4_define(void *);
void    netx_tahi_test_3_5_define(void *);
void    netx_tahi_test_3_6_define(void *);
void    netx_tahi_test_3_7_define(void *);
void    netx_tahi_test_3_8_define(void *);
void    netx_tahi_test_3_9_define(void *);
void    netx_tahi_test_3_10_define(void *);
void    netx_tahi_test_3_11_define(void *);
void    netx_tahi_test_3_12_define(void *);
void    netx_tahi_test_3_13_define(void *);
void    netx_tahi_test_3_14_define(void *);
void    netx_tahi_test_3_15_define(void *);
void    netx_tahi_test_3_16_define(void *);
void    netx_tahi_test_3_17_define(void *);
void    netx_tahi_test_3_18_define(void *);
void    netx_tahi_test_3_19_define(void *);
void    netx_tahi_test_3_20_define(void *);
void    netx_tahi_test_3_21_define(void *);
void    netx_tahi_test_3_22_define(void *);
void    netx_tahi_test_3_23_define(void *);
void    netx_tahi_test_3_24_define(void *);
void    netx_tahi_test_3_25_define(void *);
void    netx_tahi_test_3_26_define(void *);
void    netx_tahi_test_3_27_define(void *);
void    netx_tahi_test_3_28_define(void *);
void    netx_tahi_test_3_29_define(void *);
void    netx_tahi_test_3_30_define(void *);
void    netx_tahi_test_3_31_define(void *);
void    netx_tahi_test_3_32_define(void *);
void    netx_tahi_test_3_33_define(void *);
void    netx_tahi_test_3_34_define(void *);
void    netx_tahi_test_3_35_define(void *);
void    netx_tahi_test_3_36_define(void *);
void    netx_tahi_test_3_37_define(void *);
void    netx_tahi_test_3_38_define(void *);
void    netx_tahi_test_3_39_define(void *);
void    netx_tahi_test_3_40_define(void *);
void    netx_tahi_test_3_41_define(void *);
void    netx_tahi_test_3_42_define(void *);
void    netx_tahi_test_3_43_define(void *);
void    netx_tahi_test_3_44_define(void *);
void    netx_tahi_test_3_45_define(void *);

void    netx_tahi_test_4_2_define(void *);
void    netx_tahi_test_4_3_define(void *);
void    netx_tahi_test_4_4_define(void *);
void    netx_tahi_test_4_5_define(void *);
void    netx_tahi_test_4_6_define(void *);
void    netx_tahi_test_4_7_define(void *);
void    netx_tahi_test_4_8_define(void *);
void    netx_tahi_test_4_9_define(void *);
void    netx_tahi_test_4_10_define(void *);
void    netx_tahi_test_4_11_define(void *);
void    netx_tahi_test_4_12_define(void *);
void    netx_tahi_test_4_13_define(void *);
void    netx_tahi_test_4_14_define(void *);
void    netx_tahi_test_4_15_define(void *);
void    netx_tahi_test_4_16_define(void *);

void    netx_tahi_test_5_define(void *);
#endif /* NX_ENABLE_IPV6_PATH_MTU_DISCOVERY */
#endif /* NX_TAHI_ENABLE */

#ifdef NX_DHCPV6_TAHI_ENABLE
void netx_tahi_dhcpv6_test_01_002_define(void * );
void netx_tahi_dhcpv6_test_01_003_define(void * );
void netx_tahi_dhcpv6_test_01_004_define(void * );
void netx_tahi_dhcpv6_test_01_005_define(void * );
void netx_tahi_dhcpv6_test_01_006_define(void * );
void netx_tahi_dhcpv6_test_01_007_define(void * );
void netx_tahi_dhcpv6_test_01_008_define(void * );
void netx_tahi_dhcpv6_test_01_009_define(void * );
void netx_tahi_dhcpv6_test_01_010_define(void * );
void netx_tahi_dhcpv6_test_01_011_define(void * );
void netx_tahi_dhcpv6_test_01_012_define(void * );
void netx_tahi_dhcpv6_test_01_013_define(void * );
void netx_tahi_dhcpv6_test_01_014_define(void * );

void netx_tahi_dhcpv6_test_01_019_define(void * );
void netx_tahi_dhcpv6_test_01_020_define(void * );
void netx_tahi_dhcpv6_test_01_021_define(void * );
void netx_tahi_dhcpv6_test_01_022_define(void * );
void netx_tahi_dhcpv6_test_01_023_define(void * );
void netx_tahi_dhcpv6_test_01_024_define(void * );
void netx_tahi_dhcpv6_test_01_025_define(void * );
void netx_tahi_dhcpv6_test_01_026_define(void * );
void netx_tahi_dhcpv6_test_01_027_define(void * );
void netx_tahi_dhcpv6_test_01_028_define(void * );
void netx_tahi_dhcpv6_test_01_029_define(void * );
void netx_tahi_dhcpv6_test_01_030_define(void * );
void netx_tahi_dhcpv6_test_01_031_define(void * );
void netx_tahi_dhcpv6_test_01_032_define(void * );
void netx_tahi_dhcpv6_test_01_033_define(void * );
void netx_tahi_dhcpv6_test_01_034_define(void * );
void netx_tahi_dhcpv6_test_01_035_define(void * );
void netx_tahi_dhcpv6_test_01_036_define(void * );
void netx_tahi_dhcpv6_test_01_037_define(void * );
void netx_tahi_dhcpv6_test_01_038_define(void * );
void netx_tahi_dhcpv6_test_01_039_define(void * );
void netx_tahi_dhcpv6_test_01_040_define(void * );
void netx_tahi_dhcpv6_test_01_041_define(void * );
void netx_tahi_dhcpv6_test_01_042_define(void * );
void netx_tahi_dhcpv6_test_01_043_define(void * );
void netx_tahi_dhcpv6_test_01_044_define(void * );
void netx_tahi_dhcpv6_test_01_045_define(void * );
void netx_tahi_dhcpv6_test_01_046_define(void * );
void netx_tahi_dhcpv6_test_01_047_define(void * );
void netx_tahi_dhcpv6_test_01_048_define(void * );
void netx_tahi_dhcpv6_test_01_049_define(void * );
void netx_tahi_dhcpv6_test_01_050_define(void * );
void netx_tahi_dhcpv6_test_01_051_define(void * );
void netx_tahi_dhcpv6_test_01_052_define(void * );
void netx_tahi_dhcpv6_test_01_053_define(void * );
void netx_tahi_dhcpv6_test_01_054_define(void * );
void netx_tahi_dhcpv6_test_01_055_define(void * );
void netx_tahi_dhcpv6_test_01_056_define(void * );
void netx_tahi_dhcpv6_test_01_057_define(void * );
void netx_tahi_dhcpv6_test_01_058_define(void * );
void netx_tahi_dhcpv6_test_01_059_define(void * );
void netx_tahi_dhcpv6_test_01_060_define(void * );
void netx_tahi_dhcpv6_test_01_061_define(void * );
void netx_tahi_dhcpv6_test_01_062_define(void * );
void netx_tahi_dhcpv6_test_01_063_define(void * );
void netx_tahi_dhcpv6_test_01_064_define(void * );
void netx_tahi_dhcpv6_test_01_065_define(void * );
void netx_tahi_dhcpv6_test_01_066_define(void * );
void netx_tahi_dhcpv6_test_01_067_define(void * );
void netx_tahi_dhcpv6_test_01_068_define(void * );
void netx_tahi_dhcpv6_test_01_069_define(void * );
void netx_tahi_dhcpv6_test_01_070_define(void * );
void netx_tahi_dhcpv6_test_01_071_define(void * );
void netx_tahi_dhcpv6_test_01_072_define(void * );
void netx_tahi_dhcpv6_test_01_073_define(void * );
void netx_tahi_dhcpv6_test_01_074_define(void * );
void netx_tahi_dhcpv6_test_01_075_define(void * );
void netx_tahi_dhcpv6_test_01_076_define(void * );
void netx_tahi_dhcpv6_test_01_077_define(void * );
void netx_tahi_dhcpv6_test_01_078_define(void * );
void netx_tahi_dhcpv6_test_01_079_define(void * );
void netx_tahi_dhcpv6_test_01_080_define(void * );
void netx_tahi_dhcpv6_test_01_081_define(void * );
void netx_tahi_dhcpv6_test_01_082_define(void * );
void netx_tahi_dhcpv6_test_01_083_define(void * );
void netx_tahi_dhcpv6_test_01_084_define(void * );
void netx_tahi_dhcpv6_test_01_085_define(void * );
void netx_tahi_dhcpv6_test_01_086_define(void * );
void netx_tahi_dhcpv6_test_01_087_define(void * );
void netx_tahi_dhcpv6_test_01_088_define(void * );
void netx_tahi_dhcpv6_test_01_089_define(void * );
void netx_tahi_dhcpv6_test_01_090_define(void * );
void netx_tahi_dhcpv6_test_01_091_define(void * );
void netx_tahi_dhcpv6_test_01_092_define(void * );
void netx_tahi_dhcpv6_test_01_093_define(void * );
void netx_tahi_dhcpv6_test_01_094_define(void * );
void netx_tahi_dhcpv6_test_01_095_define(void * );
void netx_tahi_dhcpv6_test_01_096_define(void * );
void netx_tahi_dhcpv6_test_01_097_define(void * );
void netx_tahi_dhcpv6_test_01_098_define(void * );
void netx_tahi_dhcpv6_test_01_099_define(void * );



void netx_tahi_dhcpv6_test_04_002_define(void * );
void netx_tahi_dhcpv6_test_04_003_define(void * );
void netx_tahi_dhcpv6_test_04_004_define(void * );
void netx_tahi_dhcpv6_test_04_005_define(void * );
void netx_tahi_dhcpv6_test_04_006_define(void * );
void netx_tahi_dhcpv6_test_04_007_define(void * );
void netx_tahi_dhcpv6_test_04_008_define(void * );
void netx_tahi_dhcpv6_test_04_009_define(void * );
void netx_tahi_dhcpv6_test_04_010_define(void * );
void netx_tahi_dhcpv6_test_04_011_define(void * );
void netx_tahi_dhcpv6_test_04_012_define(void * );
void netx_tahi_dhcpv6_test_04_013_define(void * );
void netx_tahi_dhcpv6_test_04_014_define(void * );
void netx_tahi_dhcpv6_test_04_015_define(void * );
void netx_tahi_dhcpv6_test_04_016_define(void * );
void netx_tahi_dhcpv6_test_04_017_define(void * );
void netx_tahi_dhcpv6_test_04_018_define(void * );
void netx_tahi_dhcpv6_test_04_019_define(void * );
void netx_tahi_dhcpv6_test_04_020_define(void * );
void netx_tahi_dhcpv6_test_04_021_define(void * );
void netx_tahi_dhcpv6_test_04_022_define(void * );
void netx_tahi_dhcpv6_test_04_023_define(void * );
void netx_tahi_dhcpv6_test_04_024_define(void * );
void netx_tahi_dhcpv6_test_04_025_define(void * );
void netx_tahi_dhcpv6_test_04_026_define(void * );
void netx_tahi_dhcpv6_test_04_027_define(void * );
void netx_tahi_dhcpv6_test_04_028_define(void * );
void netx_tahi_dhcpv6_test_04_029_define(void * );
void netx_tahi_dhcpv6_test_04_030_define(void * );
void netx_tahi_dhcpv6_test_04_031_define(void * );

void netx_tahi_dhcpv6_test_07_002_define(void * );
void netx_tahi_dhcpv6_test_07_003_define(void * );
void netx_tahi_dhcpv6_test_07_004_define(void * );
void netx_tahi_dhcpv6_test_07_005_define(void * );
void netx_tahi_dhcpv6_test_07_006_define(void * );
void netx_tahi_dhcpv6_test_07_007_define(void * );
void netx_tahi_dhcpv6_test_07_008_define(void * );
void netx_tahi_dhcpv6_test_07_009_define(void * );
void netx_tahi_dhcpv6_test_07_010_define(void * );
void netx_tahi_dhcpv6_test_07_011_define(void * );
void netx_tahi_dhcpv6_test_07_012_define(void * );
void netx_tahi_dhcpv6_test_07_013_define(void * );
void netx_tahi_dhcpv6_test_07_014_define(void * );
void netx_tahi_dhcpv6_test_07_015_define(void * );
void netx_tahi_dhcpv6_test_07_016_define(void * );
void netx_tahi_dhcpv6_test_07_017_define(void * );
void netx_tahi_dhcpv6_test_07_018_define(void * );
void netx_tahi_dhcpv6_test_07_019_define(void * );
void netx_tahi_dhcpv6_test_07_020_define(void * );
void netx_tahi_dhcpv6_test_07_021_define(void * );
void netx_tahi_dhcpv6_test_07_022_define(void * );
void netx_tahi_dhcpv6_test_07_023_define(void * );
void netx_tahi_dhcpv6_test_07_024_define(void * );
void netx_tahi_dhcpv6_test_07_025_define(void * );
void netx_tahi_dhcpv6_test_07_026_define(void * );
void netx_tahi_dhcpv6_test_07_027_define(void * );
#endif /* NX_DHCPV6_TAHI_ENABLE*/

#ifdef NX_ENABLE_VLAN
    /* TSN related tests.  */
void netx_ip_link_status_test2_application_define(void *);
void netx_shaper_cbs_test_application_define(void *);
void netx_shaper_tas_test_application_define(void *);
void netx_mrp_state_machine_test_application_define(void *);
#endif /* NX_ENABLE_VLAN */

void test_application_define(void * );


/* Define the array of test entry points.  */

TEST_ENTRY  test_control_tests[] = 
{

#ifdef CTEST
    {test_application_define, TEST_TIMEOUT_HIGH},
#else /* CTEST */

#ifndef SNMP_ONLY
    {netx_caller_check_test_application_define, TEST_TIMEOUT_LOW},
    {netx_api_compile_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_status_check_test_application_define, TEST_TIMEOUT_LOW},
    {netx_utility_test_application_define, TEST_TIMEOUT_LOW},

    /* Checksum test. */
    {netx_checksum_test_application_define, TEST_TIMEOUT_LOW},

    /* Pakcet payload size test. */
    {netx_packet_payload_size_test_application_define, TEST_TIMEOUT_LOW},

    /* RAMDriver test */
    {netx_netx_ramdriver_callback_application_define, TEST_TIMEOUT_LOW},

    /* Old API test*/
    {netx_old_api_application_define, TEST_TIMEOUT_LOW},
    
    /* ARP test */
    {netx_arp_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_conflict_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_dynamic_entry_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_arp_dynamic_entry_test2_application_define, TEST_TIMEOUT_MID},
    {netx_arp_dynamic_entry_test3_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_dynamic_entry_set_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_dynamic_entry_fail_test_application_define, TEST_TIMEOUT_MID},
    {netx_arp_dynamic_entry_timeout_test_application_define, TEST_TIMEOUT_MID},
    {netx_arp_dynamic_invalidate_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_gratuitous_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_static_entries_delete_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_static_entry_create_test_application_define, TEST_TIMEOUT_LOW},       
    {netx_arp_static_entry_test_application_define, TEST_TIMEOUT_LOW},       
    {netx_arp_static_entry_pollute_test_application_define, TEST_TIMEOUT_LOW},       
    {netx_arp_entry_cache_test_application_define, TEST_TIMEOUT_LOW},     
    {netx_arp_entry_abnormal_operation_test_application_define, TEST_TIMEOUT_LOW},     
    {netx_arp_queue_depth_test_application_define, TEST_TIMEOUT_LOW},     
    {netx_arp_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_dual_pool_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_invalid_type_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_auto_entry_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_no_duplicate_entry_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_packet_allocate_test_application_define, TEST_TIMEOUT_LOW},
    {netx_arp_branch_test_application_define, TEST_TIMEOUT_LOW},

    /* RARP test */
    {netx_rarp_basic_processing_test_application_define, TEST_TIMEOUT_LOW},    
    {netx_rarp_packet_allocate_fail_test_application_define, TEST_TIMEOUT_LOW},    
    {netx_rarp_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rarp_multiple_interfaces_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rarp_branch_test_application_define, TEST_TIMEOUT_LOW},

    /* ICMP test */
    {netx_icmp_ping_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_ping_fragment_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_ping6_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_ping6_data_append_test_application_define, TEST_TIMEOUT_LOW},    
    {netx_icmp_ping6_fragment_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_interface2_ping_test_application_define, TEST_TIMEOUT_LOW},    
    {netx_icmp_interface2_ping6_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_invalid_source_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmp_cleanup_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_packet_receive_function_test_application_define, TEST_TIMEOUT_LOW},       
    {netx_icmp_multiple_ping_test1_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_multiple_ping_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_multiple_ping6_test1_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_multiple_ping6_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_send_error_message_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_send_error_message_test_1_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_loopback_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_loopback_test2_application_define, TEST_TIMEOUT_MID},
    {netx_icmp_loopback_fail_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_invalid_echo_reply_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_ping_multicast_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_branch_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmp_broadcast_ping_test_application_define, TEST_TIMEOUT_LOW},
  
    /* ICMPv6 test*/
    {netx_icmpv6_error_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_error_small_packet_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_DAD_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_echo_request_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_echo_reply_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_redirect_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_ra_flag_callback_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_ra_address_full_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_ra_slla_changed_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_ra_router_full_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_solicitated_ra_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_abnormal_mtu_in_ra_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_invalid_length_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_invalid_length_test2_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_invalid_ra_dest_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_ra_lifetime_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_router_solicitation_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_invalid_na_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_na_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_na_tlla_changed_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_na_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_redirect_nd_full_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_redirect_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_icmpv6_destination_table_periodic_test_application_define, TEST_TIMEOUT_MID},
    {netx_icmpv6_mtu_option_test_application_define, TEST_TIMEOUT_MID},
    {netx_icmpv6_invalid_message_test_application_define, TEST_TIMEOUT_MID},
    {netx_icmpv6_ra_invalid_length_test_application_define, TEST_TIMEOUT_MID},
    {netx_icmpv6_ra_buffer_overwrite_test_application_define, TEST_TIMEOUT_MID},
    {netx_icmpv6_branch_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmpv6_ns_with_small_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmpv6_ns_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmpv6_invalid_ra_option_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmpv6_too_big_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},

    /* IGMP test */
    {netx_igmp_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_igmp_multicast_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_igmp_loopback_test_application_define, TEST_TIMEOUT_LOW},         
    {netx_igmp_packet_receive_function_test_application_define, TEST_TIMEOUT_LOW},
    {netx_igmp_router_query_test_application_define, TEST_TIMEOUT_LOW},
    {netx_igmp_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_igmp_leave_test_application_define, TEST_TIMEOUT_LOW},
    {netx_igmp_join_fail_test_application_define, TEST_TIMEOUT_LOW},
    {netx_igmp_checksum_computation_test_application_define, TEST_TIMEOUT_LOW},
    {netx_igmp_branch_test_application_define, TEST_TIMEOUT_LOW},
    {netx_igmp_interface_indirect_report_send_test_application_define, TEST_TIMEOUT_LOW},

    /* IPv4 test */
    {netx_ip_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_link_status_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_create_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_delete_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_fragmentation_order_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_fragmentation_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_fragmentation_disable_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_fragmentation_timeout_check_test_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_timeout_check_test_2_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_time_exceeded_message_test_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_duplicate_test_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_dispatch_fail_test_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_packet_copy_test_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_packet_delay_test_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_packet_drop_test_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_wrong_destination_address_test_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_wrong_protocol_field_test_application_define, TEST_TIMEOUT_MID},
    {netx_ip_fragmentation_wrong_protocol_field_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_attachment_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_detachment_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_detachment_tcp_connection_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_detachment_arp_table_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_detachment_gateway_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_address_get_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_address_set_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_info_get_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_capability_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_physical_address_set_fail_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_physical_address_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_address_set_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_address_get_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_address_change_notify_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_address_conflict_callback_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_address_conflict_detection_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_auxiliary_packet_pool_set_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_status_check_fail_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_interface_status_check_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_max_payload_size_find_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_gateway_address_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_static_route_add_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_static_route_delete_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_static_route_find_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_invalid_packet_receive_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_chain_packet_process_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_abnormal_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_link_local_address_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_route_reachable_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_packet_filter_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_packet_filter_extended_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_driver_deferred_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_loopback_multihome_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_branch_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_malformed_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_idle_scan_test_application_define, TEST_TIMEOUT_LOW},
    
    {netx_ipv4_option_process_test_application_define, TEST_TIMEOUT_LOW},    
    
    {netx_ip_raw_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_raw_special_test_application_define, TEST_TIMEOUT_LOW},
    {netx_raw_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_raw_packet_queue_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_raw_packet_filter_test_application_define, TEST_TIMEOUT_LOW},                                                                                  
    {netx_ip_multicast_interface_detach_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_ipv6_raw_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ip_raw_loopback_test_application_define, TEST_TIMEOUT_LOW},

    /* IPv6 test */
    {netx_ipv6_disable_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_search_onlink_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_address_delete_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_address_get_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_address_set_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_default_router_api_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_ipv6_fragmentation_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_ipv6_fragmentation_error_test1_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_fragmentation_error_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_multicast_basic_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_ipv6_multicast_ping_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_ipv6_multicast_ping_test1_application_define, TEST_TIMEOUT_LOW},  
    {netx_ipv6_multicast_interface_detach_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_ipv6_stateless_address_autoconfig_application_define, TEST_TIMEOUT_MID},     
    {netx_ipv6_prefix_test_application_define, TEST_TIMEOUT_LOW},     
    {netx_ipv6_hop_by_hop_option_error_test_application_define, TEST_TIMEOUT_LOW},     
    {netx_ipv6_hop_by_hop_fragment_test_application_define, TEST_TIMEOUT_MID},
    {netx_ipv6_util_api_test_application_define, TEST_TIMEOUT_LOW},     
    {netx_ipv6_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_send_fail_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_default_router_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_invalid_packet_receive_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_packet_chain_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_fragment_fail_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_pmtu_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_interface_detachment_router_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ipv6_branch_test_application_define, TEST_TIMEOUT_LOW},

    /* ND Cache test */                               
    {netx_nd_cache_api_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_nd_cache_under_interface_detach_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_nd_cache_with_own_address_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_nd_cache_add_test_application_define, TEST_TIMEOUT_LOW},  
    {netx_nd_cache_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_nd_cache_branch_test_application_define, TEST_TIMEOUT_LOW},

    /* Dest table test*/
    {netx_dest_table_add_fail_test_application_define, TEST_TIMEOUT_LOW},  

    /* Packet test */
    {netx_packet_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_packet_data_append_test_application_define, TEST_TIMEOUT_LOW},
    {netx_packet_debug_info_test_application_define, TEST_TIMEOUT_LOW},
    {netx_packet_suspension_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_packet_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_packet_branch_test_application_define, TEST_TIMEOUT_LOW},
    {netx_low_watermark_test_application_define, TEST_TIMEOUT_LOW},
    {netx_low_watermark_zero_window_test_application_define, TEST_TIMEOUT_LOW},
    {netx_low_watermark_fragment_test_application_define, TEST_TIMEOUT_LOW},

    /* TCP test */
    {netx_tcp_duplicate_accept_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_ack_check_for_syn_message_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_ack_check_issue_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_basic_processing_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_zero_window_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_zero_window_probe_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_zero_window_probe_test_2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_zero_window_probe_test_3_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_fin_wait_recv_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_window_update_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_retransmit_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_retransmit_test_1_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_send_fail_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_send_fail_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_send_fail_test3_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_listen_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_listen_packet_leak_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_available_bytes_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_delete_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_unbind_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_unbind_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_unaccept_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_unlisten_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_relisten_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_relisten_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_listen_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_listen_queue_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_server_socket_accept_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_connection_reset_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_fast_retransmit_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_tcp_overlapping_packet_test_2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_3_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_4_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_5_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_6_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_7_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_8_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_9_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_10_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_11_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_12_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_13_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_14_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_15_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_16_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_17_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_overlapping_packet_test_18_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_data_transfer_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_data_trim_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_dropped_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_dropped_packet_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_fast_disconnect_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_loopback_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_out_of_order_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_out_of_order_ack_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_out_of_order_packet_max_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_small_window_preempt_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_small_window_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_ipv4_interface2_mss_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_tcp_ipv6_basic_processing_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_tcp_ipv6_interface2_mss_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_ipv6_window_scale_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_wrapping_sequence_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_wrapping_sequence_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_wrapping_sequence_test3_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_wrapping_sequence_test4_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_queue_depth_nofity_application_define, TEST_TIMEOUT_LOW},  
    {netx_tcp_client_bind_cleanup_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_transmit_cleanup_test_application_define, TEST_TIMEOUT_LOW},     
    {netx_tcp_receive_cleanup_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_packet_receive_function_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_error_operation_check_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_send_internal_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_state_wait_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_keepalive_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_client_socket_port_get_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_client_socket_unbind_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_client_socket_bind_test_application_define, TEST_TIMEOUT_HIGH},
    {netx_tcp_client_packet_leak_test_application_define, TEST_TIMEOUT_HIGH},
    {netx_tcp_transmit_under_interface_detach_test_application_define, TEST_TIMEOUT_LOW},     
    {netx_tcp_receive_under_interface_detach_test_application_define, TEST_TIMEOUT_LOW},     
    {netx_tcp_receive_under_interface_detach_test2_application_define, TEST_TIMEOUT_LOW},     
    {netx_tcp_max_window_scale_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_mss_option_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_mss_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_fin_wait1_to_time_wait_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_time_wait_to_close_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_invalid_option_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_invalid_option_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_out_of_window_control_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_new_reno_algorithm_test1_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_new_reno_algorithm_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_new_reno_algorithm_test3_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_new_reno_algorithm_test4_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_new_reno_algorithm_test5_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_large_mtu_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_large_mtu_test_2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_simultaneous_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_send_disconnect_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_not_enabled_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_tx_queue_exceed_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_transmit_not_done_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_4_duplicate_ack_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_cwnd_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_urgent_packet_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_multiple_send_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_multiple_send_test2_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_reset_during_send_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_delayed_retransmission_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_delayed_retransmission_test_2_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_ipv6_delayed_retransmission_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_odd_window_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_chained_packet_test_application_define, TEST_TIMEOUT_MID},
    {netx_tcp_branch_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_packet_leak_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_udp_random_port_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_invalid_length_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_large_data_transfer_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_small_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_advertised_window_update_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_race_condition_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_race_condition_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_socket_receive_rst_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_invalid_packet_chain_test_application_define, TEST_TIMEOUT_LOW},

    /* UDP test*/
    {netx_udp_basic_processing_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_socket_unbind_receive_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_socket_unbind_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_free_port_find_test_application_define, TEST_TIMEOUT_HIGH},
    {netx_udp_source_send_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_packet_receive_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_fragment_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_fragmentation_processing_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_multiple_ports_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_ipv4_interface2_test_1_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_ipv6_interface2_test_1_test_application_define, TEST_TIMEOUT_LOW},   
    {netx_udp_socket_bind_test_application_define, TEST_TIMEOUT_HIGH},  
    {netx_udp_socket_delete_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_bind_cleanup_test_application_define, TEST_TIMEOUT_LOW},    
    {netx_udp_packet_type_test_application_define, TEST_TIMEOUT_LOW},    
    {netx_udp_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_checksum_zero_test_application_define, TEST_TIMEOUT_LOW},
    {netx_nxd_udp_socket_send_special_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_loopback_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_port_unreachable_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_port_table_update_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_branch_test_application_define, TEST_TIMEOUT_LOW},

    /* Add Forward test.  */
    {netx_forward_icmp_ping_test_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_icmp_ttl_test_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_icmp_small_header_test_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_icmp_small_header_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_icmp_small_header_test3_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_multicast_test_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_udp_test_application_define, TEST_TIMEOUT_LOW},      
    {netx_forward_udp_fragment_test_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_udp_fragment_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_udp_fragment_test3_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_udp_fragment_test4_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_tcp_test_1_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_tcp_test_2_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_tcp_test_3_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_tcp_test_4_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_tcp_test_5_application_define, TEST_TIMEOUT_LOW},
    {netx_forward_link_local_address_test_application_define, TEST_TIMEOUT_LOW},

    
    {netx_icmp_ping_tunnel_ipv4_ipv4_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_tunnel_ipv4_ipv4_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_tunnel_ipv4_ipv4_basic_test_application_define, TEST_TIMEOUT_LOW},
    
    {netx_icmp_ping6_tunnel_ipv6_ipv6_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_ping6_tunnel_ipv6_ipv4_test_application_define, TEST_TIMEOUT_LOW},
    {netx_icmp_ping_tunnel_ipv4_ipv6_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_tunnel_ipv6_ipv4_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_tunnel_ipv4_ipv6_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_udp_tunnel_ipv6_ipv6_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_tunnel_ipv6_ipv4_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_tunnel_ipv4_ipv6_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_tunnel_ipv6_ipv6_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_tunnel_ipv4_ipv6_address_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_tunnel_ipv4_ipv6_samll_windows_application_define, TEST_TIMEOUT_LOW},
    {netx_tcp_tunnel_ipv4_ipv6_big_packet_test_application_define, TEST_TIMEOUT_LOW},
    
    /*TCP tests*/
    {netx_1_01_application_define, TEST_TIMEOUT_LOW},
    {netx_1_02_application_define, TEST_TIMEOUT_LOW},
    {netx_1_03_application_define, TEST_TIMEOUT_LOW},
    {netx_1_04_application_define, TEST_TIMEOUT_LOW},
    {netx_1_04_ipv6_application_define, TEST_TIMEOUT_LOW},
    {netx_1_05_application_define, TEST_TIMEOUT_LOW}, 
    {netx_1_17_application_define, TEST_TIMEOUT_LOW},
    {netx_1_18_application_define, TEST_TIMEOUT_LOW},
    {netx_1_19_01_application_define, TEST_TIMEOUT_LOW},
    {netx_1_19_02_application_define, TEST_TIMEOUT_LOW},
    {netx_1_19_03_application_define, TEST_TIMEOUT_LOW},
    {netx_1_20_application_define, TEST_TIMEOUT_LOW},
    {netx_1_21_01_application_define, TEST_TIMEOUT_LOW},
    {netx_1_21_02_application_define, TEST_TIMEOUT_LOW},
    {netx_1_26_01_application_define, TEST_TIMEOUT_LOW},
    {netx_1_26_02_application_define, TEST_TIMEOUT_LOW},
    {netx_1_27_01_application_define, TEST_TIMEOUT_LOW},
    {netx_1_27_02_application_define, TEST_TIMEOUT_LOW},
    {netx_1_27_03_application_define, TEST_TIMEOUT_LOW},
    {netx_1_27_04_application_define, TEST_TIMEOUT_LOW},
    {netx_2_01_application_define, TEST_TIMEOUT_LOW},
    {netx_2_02_application_define, TEST_TIMEOUT_LOW},
    {netx_2_17_application_define, TEST_TIMEOUT_LOW},
    {netx_2_20_application_define, TEST_TIMEOUT_LOW},
    {netx_3_01_application_define, TEST_TIMEOUT_LOW},
    {netx_3_02_application_define, TEST_TIMEOUT_LOW},
    {netx_3_03_application_define, TEST_TIMEOUT_LOW},
    {netx_3_04_application_define, TEST_TIMEOUT_LOW},
    {netx_3_06_application_define, TEST_TIMEOUT_LOW},
    {netx_3_07_application_define, TEST_TIMEOUT_LOW},
    {netx_3_08_application_define, TEST_TIMEOUT_LOW},
    {netx_3_17_application_define, TEST_TIMEOUT_LOW},
    {netx_3_18_application_define, TEST_TIMEOUT_LOW},
    {netx_3_19_application_define, TEST_TIMEOUT_LOW},
    {netx_3_20_application_define, TEST_TIMEOUT_LOW},
    {netx_3_21_application_define, TEST_TIMEOUT_LOW},
    {netx_3_23_application_define, TEST_TIMEOUT_LOW},
    {netx_4_01_application_define, TEST_TIMEOUT_LOW},
    {netx_4_17_application_define, TEST_TIMEOUT_LOW},
    {netx_4_21_application_define, TEST_TIMEOUT_LOW},
    {netx_4_23_application_define, TEST_TIMEOUT_LOW},
    {netx_4_24_application_define, TEST_TIMEOUT_LOW},
    {netx_4_25_application_define, TEST_TIMEOUT_LOW},
    {netx_4_26_application_define, TEST_TIMEOUT_LOW},
    {netx_4_27_application_define, TEST_TIMEOUT_LOW},
    {netx_4_28_application_define, TEST_TIMEOUT_LOW},
    {netx_4_29_application_define, TEST_TIMEOUT_LOW},
    {netx_5_18_application_define, TEST_TIMEOUT_LOW},
    {netx_5_19_application_define, TEST_TIMEOUT_LOW},
    {netx_5_20_application_define, TEST_TIMEOUT_LOW},
    {netx_5_21_application_define, TEST_TIMEOUT_LOW},
    {netx_5_22_application_define, TEST_TIMEOUT_LOW},
    {netx_5_23_application_define, TEST_TIMEOUT_LOW},
    {netx_5_24_application_define, TEST_TIMEOUT_LOW},
    {netx_5_25_application_define, TEST_TIMEOUT_LOW},
    {netx_6_17_application_define, TEST_TIMEOUT_LOW},
    {netx_6_18_application_define, TEST_TIMEOUT_LOW},
    {netx_6_20_application_define, TEST_TIMEOUT_LOW},
    {netx_6_22_01_application_define, TEST_TIMEOUT_LOW},
    {netx_6_22_02_application_define, TEST_TIMEOUT_LOW},
    {netx_6_23_application_define, TEST_TIMEOUT_LOW},
    {netx_6_24_application_define, TEST_TIMEOUT_LOW},
    {netx_6_25_application_define, TEST_TIMEOUT_LOW},
    {netx_6_27_application_define, TEST_TIMEOUT_LOW},
    {netx_6_28_application_define, TEST_TIMEOUT_LOW},
    {netx_6_29_application_define, TEST_TIMEOUT_LOW},
    {netx_6_32_application_define, TEST_TIMEOUT_LOW},
    {netx_8_01_application_define, TEST_TIMEOUT_LOW},
    {netx_8_02_application_define, TEST_TIMEOUT_LOW},
    {netx_8_17_application_define, TEST_TIMEOUT_LOW},
    {netx_8_18_application_define, TEST_TIMEOUT_LOW},
    {netx_8_19_application_define, TEST_TIMEOUT_LOW},
    {netx_8_20_application_define, TEST_TIMEOUT_LOW},
    {netx_8_21_application_define, TEST_TIMEOUT_LOW},
    {netx_8_29_01_application_define, TEST_TIMEOUT_LOW},
    {netx_8_29_02_application_define, TEST_TIMEOUT_LOW},
    {netx_8_29_03_application_define, TEST_TIMEOUT_LOW},
    {netx_8_29_04_application_define, TEST_TIMEOUT_LOW},
    {netx_9_17_application_define, TEST_TIMEOUT_LOW},
    {netx_9_18_application_define, TEST_TIMEOUT_LOW},
    {netx_9_19_01_application_define, TEST_TIMEOUT_LOW},
    {netx_9_19_02_application_define, TEST_TIMEOUT_LOW},
    {netx_9_20_application_define, TEST_TIMEOUT_LOW},
    {netx_9_21_01_application_define, TEST_TIMEOUT_LOW},
    {netx_9_21_02_application_define, TEST_TIMEOUT_LOW},
    {netx_9_22_application_define, TEST_TIMEOUT_LOW},
    {netx_9_27_application_define, TEST_TIMEOUT_LOW},
    {netx_10_23_01_application_define, TEST_TIMEOUT_LOW},
    {netx_10_23_02_application_define, TEST_TIMEOUT_LOW},
    {netx_10_24_01_application_define, TEST_TIMEOUT_LOW},
    {netx_10_24_02_application_define, TEST_TIMEOUT_LOW},
    {netx_10_24_03_application_define, TEST_TIMEOUT_LOW},
    {netx_10_25_application_define, TEST_TIMEOUT_LOW},
    {netx_10_26_application_define, TEST_TIMEOUT_LOW},
    {netx_11_18_application_define, TEST_TIMEOUT_LOW},
    {netx_11_19_application_define, TEST_TIMEOUT_LOW},
    {netx_11_24_application_define, TEST_TIMEOUT_LOW},
    {netx_11_25_application_define, TEST_TIMEOUT_LOW},
    {netx_11_26_application_define, TEST_TIMEOUT_LOW},
    {netx_11_27_application_define, TEST_TIMEOUT_LOW},
    {netx_11_28_application_define, TEST_TIMEOUT_LOW},
    {netx_11_29_application_define, TEST_TIMEOUT_LOW},
    {netx_12_01_application_define, TEST_TIMEOUT_LOW},
    {netx_12_02_application_define, TEST_TIMEOUT_LOW},
    {netx_12_03_application_define, TEST_TIMEOUT_LOW},
    {netx_12_04_application_define, TEST_TIMEOUT_LOW},
    {netx_12_17_application_define, TEST_TIMEOUT_LOW},
    {netx_12_18_application_define, TEST_TIMEOUT_LOW},
    {netx_12_19_application_define, TEST_TIMEOUT_LOW},
    {netx_12_20_application_define, TEST_TIMEOUT_LOW},
    {netx_12_21_application_define, TEST_TIMEOUT_LOW},
    {netx_12_23_application_define, TEST_TIMEOUT_LOW},
    {netx_12_24_application_define, TEST_TIMEOUT_LOW},
    {netx_12_25_application_define, TEST_TIMEOUT_LOW},
    {netx_12_26_application_define, TEST_TIMEOUT_LOW},
    {netx_12_27_application_define, TEST_TIMEOUT_LOW}, 
    {netx_12_30_application_define, TEST_TIMEOUT_LOW},
    {netx_12_31_application_define, TEST_TIMEOUT_LOW},
    {netx_13_01_application_define, TEST_TIMEOUT_LOW},
    {netx_13_02_application_define, TEST_TIMEOUT_LOW},
    {netx_13_04_application_define, TEST_TIMEOUT_LOW},
    {netx_13_05_application_define, TEST_TIMEOUT_LOW},
    {netx_13_17_application_define, TEST_TIMEOUT_LOW},
    {netx_14_19_application_define, TEST_TIMEOUT_LOW},
    {netx_14_20_application_define, TEST_TIMEOUT_LOW},
    {netx_15_03_application_define, TEST_TIMEOUT_LOW},
    {netx_15_20_application_define, TEST_TIMEOUT_LOW},
    {netx_15_21_application_define, TEST_TIMEOUT_LOW},
    {netx_15_24_application_define, TEST_TIMEOUT_LOW},
    {netx_15_25_application_define, TEST_TIMEOUT_LOW},
    {netx_15_26_application_define, TEST_TIMEOUT_LOW},
    {netx_16_02_application_define, TEST_TIMEOUT_LOW},
    {netx_16_17_application_define, TEST_TIMEOUT_LOW},
    {netx_16_19_application_define, TEST_TIMEOUT_LOW},
    {netx_16_21_application_define, TEST_TIMEOUT_LOW},
    {netx_16_22_application_define, TEST_TIMEOUT_LOW},
    {netx_17_17_application_define, TEST_TIMEOUT_LOW},
    {netx_23_02_01_application_define, TEST_TIMEOUT_LOW},
    {netx_23_02_02_application_define, TEST_TIMEOUT_LOW},
    {netx_23_02_03_application_define, TEST_TIMEOUT_LOW},
    {netx_23_02_04_application_define, TEST_TIMEOUT_LOW},
    {netx_101_17_application_define, TEST_TIMEOUT_LOW},
    {netx_101_18_application_define, TEST_TIMEOUT_LOW},
    {netx_102_18_application_define, TEST_TIMEOUT_LOW},
    {netx_102_19_application_define, TEST_TIMEOUT_LOW},
    {netx_102_20_application_define, TEST_TIMEOUT_LOW},
    {netx_102_21_application_define, TEST_TIMEOUT_LOW},
    {netx_102_22_application_define, TEST_TIMEOUT_LOW},
    {netx_102_23_application_define, TEST_TIMEOUT_LOW},
    {netx_102_24_application_define, TEST_TIMEOUT_LOW},
    {netx_102_25_application_define, TEST_TIMEOUT_LOW},
    {netx_103_17_application_define, TEST_TIMEOUT_LOW},
    {netx_104_17_application_define, TEST_TIMEOUT_LOW},
    {netx_106_17_application_define, TEST_TIMEOUT_LOW},
#endif /* SNMP_ONLY  */

#ifdef NX_ENABLE_VLAN
    /* TSN related tests.  */
    {netx_ip_link_status_test2_application_define, TEST_TIMEOUT_LOW},
    {netx_shaper_cbs_test_application_define, TEST_TIMEOUT_LOW},
    {netx_shaper_tas_test_application_define, TEST_TIMEOUT_LOW},
    {netx_mrp_state_machine_test_application_define, TEST_TIMEOUT_LOW},
#endif /* NX_ENABLE_VLAN */

#if !defined CERT_BUILD && !defined (SNMP_ONLY) 

    /* Application tests do not support for 64-bit mode yet.  */
#ifndef XWARE_64
    /* Auto_ip test. */
    {netx_auto_ip_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_auto_ip_address_check_test_application_define, TEST_TIMEOUT_LOW},
    {netx_auto_ip_announce_num_test_application_define, TEST_TIMEOUT_LOW},
    {netx_auto_ip_arp_dest_addr_test_application_define, TEST_TIMEOUT_LOW},
    {netx_auto_ip_max_conflicts_test_application_define, TEST_TIMEOUT_MID},

    /* Websocket test. */
    {netx_websocket_fin_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_opcode_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_connect_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_disconnect_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_mask_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_one_frame_in_packets_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_one_packet_with_multi_frames_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_16_bit_payload_length_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_delete_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_multi_instance_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_non_block_test_application_define, TEST_TIMEOUT_LOW},
    {netx_websocket_send_chain_packets_test_application_define, TEST_TIMEOUT_LOW},

    /* Http test. */
    {netx_http_if_modified_since_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_status_404_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_basic_authenticate_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_delete_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_post_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_head_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_multipart_fragment_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_multipart_underflow_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_get_contentlength_packetleak_test_application_define, TEST_TIMEOUT_MID},
    {netx_http_get_put_referred_URI_test_application_define, TEST_TIMEOUT_MID},
    {netx_http_client_change_connect_port_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_request_in_multiple_packets_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_digest_authenticate_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_server_type_retrieve_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_digest_authenticate_timeout_test_application_define, TEST_TIMEOUT_LOW},

    /*HTTP Proxy test. */
    {netx_http_proxy_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_proxy_non_block_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_proxy_multiple_response_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_proxy_error_response_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_proxy_disconnect_test_application_define, TEST_TIMEOUT_LOW},
    {netx_http_proxy_data_fin_test_application_define, TEST_TIMEOUT_LOW},

    /* Ftp test. */
    {netx_ftp_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_establish_data_connection_05_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_user_data_type_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_service_commands_RETR_STOR_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_service_commands_rename_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_service_commands_nlist_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_service_commands_file_write_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_establish_data_connection_08_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_establish_data_connection_06_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_establish_data_connection_03_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_data_connection_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_control_connection_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_commands_replys_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_commands_characters_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_access_control_commands_04_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_access_control_commands_03_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_access_control_commands_02_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_access_control_commands_01_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_client_pasv_denied_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_client_pasv_file_read_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_client_pasv_file_write_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_client_invalid_username_password_length_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_client_multiple_connection_response_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_client_packet_leak_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_client_buffer_overflow_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_client_file_write_fail_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_server_invalid_month_crash_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_server_mss_too_small_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_rst_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_two_listen_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_parse_ipv6_address_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_server_abnormal_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_server_list_command_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_server_dangling_pinter_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_pasv_twice_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_disconnection_event_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_ipv6_epsv_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_pasv_port_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ftp_pasv_stor_test_application_define, TEST_TIMEOUT_LOW},

    /* PPP test.  */
    {netx_ppp_PAP_bad_username_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_PAP_bad_password_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_chap_bad_secret_failed_retry_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_chap_bad_secret_passed_on_retry_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_LCP_timeout_test_application_define, TEST_TIMEOUT_MID},
    {netx_ppp_IPCP_timeout_test_application_define, TEST_TIMEOUT_MID},
    {netx_ppp_check_boundary_test_application_define, TEST_TIMEOUT_MID},
    {netx_ppp_request_dns_server_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_pap_null_name_password_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_LCP_invalid_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_IPCP_abnormal_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_IPCP_nak_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_IPCP_retransmit_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_pap_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_pfc_option_test_application_define, TEST_TIMEOUT_LOW},
    {netx_ppp_acfc_option_test_application_define, TEST_TIMEOUT_LOW},

    /* PPPoE test.  */
    {netx_pppoe_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_pppoe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_pppoe_api_extended_test_application_define, TEST_TIMEOUT_LOW},
    {netx_pppoe_ac_name_test_application_define, TEST_TIMEOUT_LOW},
    {netx_pppoe_session_control_test_application_define, TEST_TIMEOUT_LOW},

    /* RTP test.  */
    {netx_rtp_multi_interfaces_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtp_session_packet_send_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtp_session_jpeg_send_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtp_session_h264_send_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtp_session_aac_send_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtp_free_udp_port_find_test_application_define, TEST_TIMEOUT_MID},
    {netx_rtp_multi_clients_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtp_multicast_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtp_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtp_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtcp_abnormal_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtcp_packet_process_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtcp_packet_send_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtcp_basic_test_application_define, TEST_TIMEOUT_LOW},

    /* RTSP test.  */
    {netx_rtsp_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtsp_rtp_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtsp_rtp_ipv6_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtsp_rtp_multicast_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtsp_rtp_ipv6_multicast_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtsp_multiple_request_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtsp_multiple_clients_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtsp_client_timeout_test_application_define, TEST_TIMEOUT_MID},
    {netx_rtsp_error_response_test_application_define, TEST_TIMEOUT_LOW},
    {netx_rtsp_delete_beforehand_test_application_define, TEST_TIMEOUT_LOW},

    /* Tftp test. */                
    {netx_tftp_basic_test_application_define, TEST_TIMEOUT_LOW},   
#ifdef FEATURE_NX_IPV6
    {netx_tftp_ipv6_basic_test_application_define, TEST_TIMEOUT_LOW},
#endif
    {netx_tftp_read_interaction_test_application_define, TEST_TIMEOUT_LOW},                   
    {netx_tftp_write_interaction_test_application_define, TEST_TIMEOUT_LOW},   
    {netx_tftp_error_destination_port_test_application_define, TEST_TIMEOUT_LOW},
    {netx_tftp_error_file_name_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_tftp_large_data_test_application_define, TEST_TIMEOUT_HIGH}, 
    {netx_tftp_malformed_packet_test_application_define, TEST_TIMEOUT_LOW},

    /* Sntp test.  */
    {netx_sntp_client_ipv6_broadcast_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_sntp_client_ipv6_unicast_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_sntp_client_broadcast_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_sntp_client_unicast_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_sntp_request_unicast_test_application_define, TEST_TIMEOUT_LOW},
    {netx_sntp_forward_unicast_update_test_application_define, TEST_TIMEOUT_LOW},
    {netx_sntp_client_unicast_display_date_test_application_define, TEST_TIMEOUT_LOW},
    {netx_sntp_client_seconds_to_date_test_application_define, TEST_TIMEOUT_LOW},

    /* Telnet test. */
    {netx_telnet_create_packet_pool_test_application_define, TEST_TIMEOUT_LOW},
    {netx_telnet_max_connections_test_application_define, TEST_TIMEOUT_LOW},
    {netx_telnet_activity_timeout_test_application_define, TEST_TIMEOUT_MID},
    {netx_telnet_server_options_negotiate_test_application_define, TEST_TIMEOUT_LOW},
    {netx_telnet_server_bad_option_reply_test_application_define, TEST_TIMEOUT_LOW},
    {netx_telnet_rst_test_application_define, TEST_TIMEOUT_LOW},
    {netx_telnet_two_listen_test_application_define, TEST_TIMEOUT_LOW},
    {netx_sntp_client_kod_test_application_define, TEST_TIMEOUT_LOW},
    {netx_sntp_client_packet_chain_test_application_define, TEST_TIMEOUT_LOW},
    
#endif /* !XWARE_64 */

    /* DHCP test. */
    {netx_dhcp_basic_test_application_define, TEST_TIMEOUT_MID},
    {netx_dhcp_basic_restore_test_application_define, TEST_TIMEOUT_MID},
    {netx_dhcp_unicast_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_user_option_add_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_server_improper_term_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_coverage_test_applicaiton_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_client_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_04_04_01_02_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_04_04_01_01_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_04_03_05_01_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_04_03_02_03_test_application_define, TEST_TIMEOUT_MID},
    {netx_dhcp_04_03_02_02_test_application_define, TEST_TIMEOUT_MID},
    {netx_dhcp_04_03_02_01_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_04_01_01_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_03_05_01_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_03_02_03_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_03_02_02_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_03_02_01_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_03_01_01_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_packet_process_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_client_send_with_zero_source_address_test_application_define, TEST_TIMEOUT_LOW},
    { netx_dhcp_multiple_instances_test_application_define, TEST_TIMEOUT_LOW },
    {netx_dhcp_send_request_internal_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_extract_information_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_get_option_value_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_delete_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_stop_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_enable_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_start_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_release_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_reinitialize_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_client_activate_interfaces_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_client_secondary_interface_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_client_interface_order_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_client_ip_mutex_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_client_server_source_port_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_client_parameter_request_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_client_ntp_option_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_server_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_server_second_interface_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_server_options_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcp_server_small_packet_payload_test_application_define, TEST_TIMEOUT_LOW},
    
    {netx_dhcpv6_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcpv6_extended_api_test_application_define, TEST_TIMEOUT_LOW},        
    {netx_dhcpv6_packet_loss_test_application_define, TEST_TIMEOUT_LOW}, 
    {netx_dhcpv6_client_process_server_duid_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcpv6_server_ia_options_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcpv6_server_iana_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcpv6_server_process_repeated_msgs_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dhcpv6_user_option_add_test_application_define, TEST_TIMEOUT_LOW},
            
#ifndef XWARE_64
            
#ifdef NX_DHCP_RELAY_ENABLE
    /* DHCPv4 Relay test.  */
    {netx_dhcpv4_relay_test_define, TEST_TIMEOUT_MID},    
                
#ifdef FEATURE_NX_IPV6
    /* DHCPv6 Relay test.  */
    {netx_dhcpv6_relay_test_define, TEST_TIMEOUT_MID},
#endif
#endif /* NX_DHCP_RELAY_ENABLE */

    /* SMTP test.  */
    {netx_smtp_basic_function_test_application_define, TEST_TIMEOUT_LOW},
    {netx_smtp_two_packet_ehlo_message_test_application_define, TEST_TIMEOUT_MID},
    {netx_smtp_auth_logon_function_test_application_define, TEST_TIMEOUT_LOW},
    {netx_smtp_auth_none_test_application_define, TEST_TIMEOUT_LOW},
    {netx_smtp_missing_last_250_EHLO_message_test_application_define, TEST_TIMEOUT_MID}, 
    {netx_smtp_two_packet_EHLO_auth_last_message_test_application_define, TEST_TIMEOUT_LOW},
    {netx_smtp_auth_no_type_test_application_define, TEST_TIMEOUT_LOW},
    {netx_smtp_abnormal_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_smtp_invalid_release_test_application_define, TEST_TIMEOUT_LOW},

    /* PoP3 test.  */
    {netx_pop3_mail_receive_test_application_define, TEST_TIMEOUT_LOW},
    {netx_pop3_two_mails_received_test_application_define, TEST_TIMEOUT_LOW},
    {netx_pop3_packet_with_endmarker_test_application_define, TEST_TIMEOUT_LOW},
    {netx_pop3_abnormal_packet_test_application_define, TEST_TIMEOUT_LOW},

    /* NAT test.  */
    {netx_nat_icmp_test_application_define, TEST_TIMEOUT_MID},
    {netx_nat_udp_test_application_define, TEST_TIMEOUT_MID},
    {netx_nat_udp_port_test_application_define, TEST_TIMEOUT_MID}, 
    {netx_nat_udp_fragment_test_application_define, TEST_TIMEOUT_MID},
    {netx_nat_tcp_test1_application_define, TEST_TIMEOUT_MID},
    {netx_nat_tcp_test2_application_define, TEST_TIMEOUT_MID},
    {netx_nat_tcp_port_test_application_define, TEST_TIMEOUT_MID},
    {netx_nat_tcp_port_test2_application_define, TEST_TIMEOUT_MID},
    {netx_nat_tcp_fragment_test_application_define, TEST_TIMEOUT_MID},
    {netx_nat_invalid_header_test_application_define, TEST_TIMEOUT_MID},
    
#endif /* !XWARE_64 */

    /* DNS Test.  */
    {netx_dns_coverage_test_application_define, TEST_TIMEOUT_MID},
    {netx_dns_function_test_application_define, TEST_TIMEOUT_MID},
    {netx_dns_request_a_response_cname_a_smtp_live_com_test_application_define, TEST_TIMEOUT_MID},
    {netx_dns_invalid_name_unencode_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dns_invalid_resource_get_test_application_define, TEST_TIMEOUT_MID},
    {netx_dns_abnormal_packet_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dns_source_port_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dns_non_blocking_a_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dns_fake_response_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dns_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_dns_packet_double_release_test_application_define, TEST_TIMEOUT_LOW},

#ifndef XWARE_64
    /* mDNS Test.  */
    {netx_mdns_internal_function_test, TEST_TIMEOUT_LOW},
    {netx_mdns_create_delete_test, TEST_TIMEOUT_LOW},
    {netx_mdns_one_shot_query_test, TEST_TIMEOUT_LOW},
    {netx_mdns_local_cache_continuous_query_test, TEST_TIMEOUT_LOW},
    {netx_mdns_local_cache_one_shot_query_test, TEST_TIMEOUT_MID},
    {netx_mdns_service_lookup_test, TEST_TIMEOUT_LOW},
    {netx_mdns_service_add_delete_test, TEST_TIMEOUT_LOW},
    {netx_mdns_announcement_repeat_test, TEST_TIMEOUT_MID},
    {netx_mdns_multiple_answers_test, TEST_TIMEOUT_LOW},
    {netx_mdns_responder_cooperating_test, TEST_TIMEOUT_LOW},
    {netx_mdns_response_with_question_test, TEST_TIMEOUT_LOW},
    {netx_mdns_source_address_test, TEST_TIMEOUT_LOW},
    {netx_mdns_source_port_test, TEST_TIMEOUT_LOW},
    {netx_mdns_two_buffer_test, TEST_TIMEOUT_LOW},
    {netx_mdns_buffer_size_test, TEST_TIMEOUT_MID},
    {netx_mdns_ttl_test, TEST_TIMEOUT_LOW},
    {netx_mdns_txt_test, TEST_TIMEOUT_LOW},
    {netx_mdns_txt_notation_test, TEST_TIMEOUT_LOW},
    {netx_mdns_name_test, TEST_TIMEOUT_LOW},
    {netx_mdns_domain_name_test, TEST_TIMEOUT_LOW},
    {netx_mdns_interface_test, TEST_TIMEOUT_LOW},
    {netx_mdns_second_interface_test, TEST_TIMEOUT_LOW},
    {netx_mdns_peer_service_change_notify_test, TEST_TIMEOUT_LOW},
    {netx_mdns_ipv6_string_test, TEST_TIMEOUT_LOW},
    {netx_mdns_bad_packet_test, TEST_TIMEOUT_LOW},
    {netx_mdns_read_overflow_test, TEST_TIMEOUT_LOW},
#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_IPV4
    {netx_mdns_ram_test_define, TEST_TIMEOUT_MID},
#endif /* __PRODUCT_NETXDUO__ && !NX_DISABLE_IPV4  */

/* BSD Test */
#ifdef NX_BSD_ENABLE
    {netx_bsd_getaddrinfo_test_application_define, TEST_TIMEOUT_MID}, 
    {netx_bsd_raw_pppoe_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_tcp_ioctl_nonblocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_two_blocking_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_tcp_basic_blocking_test_application_define, TEST_TIMEOUT_MID}, 
    {netx_bsd_tcp_basic_nonblocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_accept_blocking_timeout_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_accept_nonblocking_timeout_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_accept_nonblocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_accept_blocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_sendto_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_udp_select_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_accept_noselect_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_bind_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_disconnect_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_multiple_accept_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_udp_bind_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_multicast_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_udp_blocking_bidirection_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_udp_basic_blocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_udp_basic_nonblocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_tcp_2nd_bind_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_bind_connect_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_basic_blocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_basic_nonblocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_basic_rx_nohdr_blocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_rx_nohdr_basic_blocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_basic_rx_nohdr_nonblocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_rx_nohdr_basic_blocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_basic_rx_nohdr_blocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_ping_test_application_define, TEST_TIMEOUT_MID},
    //{netx_bsd_raw_rx_nohdr_basic_nonblocking_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_udp_bind_connect_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_udp_checksum_corrupt_test_application_define, TEST_TIMEOUT_MID},

    {netx_bsd_udp_connect_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_raw_tx_test_application_define, TEST_TIMEOUT_MID},
    {netx_bsd_aton_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_ntoa_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_ntop_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_pton_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_inet_addr_pton_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_tcp_servers_share_port_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_tcp_clients_share_port_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_tcp_getsockname_without_bind_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_tcp_rcvbuf_test_application_define, TEST_TIMEOUT_LOW},
    {netx_bsd_tcp_fionread_test_application_define, TEST_TIMEOUT_LOW},

#endif /* NX_BSD_ENABLE */

	/* Cloud Test.  */
    {netx_cloud_basic_test_application_define, TEST_TIMEOUT_LOW},
    {netx_cloud_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_cloud_module_register_deregister_test_application_define, TEST_TIMEOUT_LOW},
    {netx_cloud_module_event_test_application_define, TEST_TIMEOUT_LOW},

#endif /* XWARE_64  */

#endif /* !CERT_BUILD && !SNMP_ONLY */

#ifndef CERT_BUILD
#ifndef XWARE_64
    /* SNMP Agent  */
    {netx_snmp_v1_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_v1_object_id_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_v1_packet_double_release_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_basic_v2_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_v2_get_bulk_request_test_application_define, TEST_TIMEOUT_MID},
    {netx_snmp_v2_send_trap_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_v2_unknown_oid_test_application_define, TEST_TIMEOUT_MID},
    {netx_snmp_v2_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_v3_nosec_traplist_test_application_define, TEST_TIMEOUT_MID},
    {netx_snmp_v3_md5_failed_security_test_application_define, TEST_TIMEOUT_MID},
    {netx_snmp_v3_no_security_application_define, TEST_TIMEOUT_MID},
    {netx_snmp_v3_md5_security_test_application_define, TEST_TIMEOUT_MID},
    {netx_snmp_v3_md5_security_extended_test_application_define, TEST_TIMEOUT_MID},
    {netx_snmp_v3_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_v3_decrypt_pdu_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_v3_encrypt_pdu_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_v3_encrypt_pdu_padding_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_v3_object_id_buffer_overwrite_test_application_define, TEST_TIMEOUT_LOW},

    {netx_snmp_setget_integers_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_setget_octet_strings_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_setget_ip_address_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_setget_misc_test_application_define, TEST_TIMEOUT_LOW},
    {netx_snmp_abnormal_packet_test_application_define, TEST_TIMEOUT_LOW},
#endif /* XWARE_64  */
#endif /* CERT_BUILD */

#if !defined CERT_BUILD && !defined (SNMP_ONLY) 

#if defined(NX_TAHI_ENABLE) && defined(FEATURE_NX_IPV6)

#ifdef NX_ENABLE_IPV6_PATH_MTU_DISCOVERY
    /* IPv6 TAHI test*/
    {netx_tahi_test_1_define, TEST_TIMEOUT_HIGH},

    {netx_tahi_test_2_1_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_2_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_3_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_4_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_5_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_6_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_7_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_8_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_9_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_10_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_2_11_define, TEST_TIMEOUT_HIGH},

    {netx_tahi_test_3_1_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_2_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_3_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_4_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_5_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_6_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_7_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_8_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_9_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_10_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_11_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_12_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_13_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_14_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_15_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_16_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_17_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_18_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_19_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_20_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_21_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_22_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_23_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_24_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_25_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_26_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_27_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_28_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_29_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_30_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_31_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_32_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_33_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_34_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_35_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_36_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_37_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_38_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_39_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_40_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_41_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_3_42_define, TEST_TIMEOUT_HIGH},    
    {netx_tahi_test_4_2_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_3_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_4_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_5_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_6_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_7_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_8_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_9_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_10_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_11_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_12_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_13_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_14_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_15_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_test_4_16_define, TEST_TIMEOUT_HIGH},

    {netx_tahi_test_5_define, TEST_TIMEOUT_HIGH},
#endif /* NX_ENABLE_IPV6_PATH_MTU_DISCOVERY */
#endif /* NX_TAHI_ENABLE*/

#ifdef NX_DHCPV6_TAHI_ENABLE

    /* Section 1: RFC3315 - Address Assignment for Client.  */
    {netx_tahi_dhcpv6_test_01_002_define, TEST_TIMEOUT_HIGH}, 
    {netx_tahi_dhcpv6_test_01_003_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_004_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_005_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_006_define, TEST_TIMEOUT_HIGH}, 
    {netx_tahi_dhcpv6_test_01_007_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_008_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_009_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_010_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_011_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_012_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_013_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_014_define, TEST_TIMEOUT_HIGH},
                                                             
    {netx_tahi_dhcpv6_test_01_019_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_020_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_021_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_022_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_023_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_024_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_025_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_026_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_027_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_028_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_029_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_030_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_031_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_032_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_033_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_034_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_035_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_036_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_037_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_038_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_039_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_040_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_041_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_042_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_043_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_044_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_045_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_046_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_047_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_048_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_049_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_050_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_051_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_052_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_053_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_054_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_055_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_056_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_057_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_058_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_059_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_060_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_061_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_062_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_063_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_064_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_065_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_066_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_067_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_068_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_069_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_070_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_071_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_072_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_073_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_074_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_075_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_076_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_077_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_078_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_079_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_080_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_081_define, TEST_TIMEOUT_HIGH}, 
    {netx_tahi_dhcpv6_test_01_082_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_083_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_084_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_085_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_086_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_087_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_088_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_089_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_090_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_091_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_092_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_093_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_094_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_095_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_096_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_097_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_098_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_01_099_define, TEST_TIMEOUT_HIGH},


    /* Section 4: RFC3646 - DNS configuration in parallel with Address Assignment for Client.  */
    {netx_tahi_dhcpv6_test_04_002_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_003_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_004_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_005_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_006_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_007_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_008_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_009_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_010_define, TEST_TIMEOUT_HIGH},

    {netx_tahi_dhcpv6_test_04_012_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_013_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_014_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_015_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_016_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_017_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_018_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_019_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_020_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_021_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_022_define, TEST_TIMEOUT_HIGH},

    {netx_tahi_dhcpv6_test_04_026_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_04_027_define, TEST_TIMEOUT_HIGH},


    /* Section 7: RFC3736 - Stateless DHCPv6 for DNS configuration for Client.  */
    {netx_tahi_dhcpv6_test_07_002_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_003_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_004_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_005_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_006_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_007_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_008_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_009_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_010_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_011_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_012_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_013_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_014_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_015_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_016_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_017_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_018_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_019_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_020_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_021_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_022_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_023_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_024_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_025_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_026_define, TEST_TIMEOUT_HIGH},
    {netx_tahi_dhcpv6_test_07_027_define, TEST_TIMEOUT_HIGH},

#endif /* NX_DHCPV6_TAHI_ENABLE*/
#endif /* !CERT_BUILD && !SNMP_ONLY */
#endif /* CTEST */
    {TX_NULL, TEST_TIMEOUT_LOW},
};

/* Define thread prototypes.  */

void  test_control_thread_entry(ULONG thread_input);
void  test_control_return(UINT status);
void  test_control_cleanup(void);
void  _nx_ram_network_driver_reset(void);

/* Define necessary external references.  */

#ifdef __ghs
extern TX_MUTEX                 __ghLockMutex;
#endif

extern TX_TIMER                 *_tx_timer_created_ptr;
extern ULONG                    _tx_timer_created_count;
#ifndef TX_TIMER_PROCESS_IN_ISR
extern TX_THREAD                _tx_timer_thread;
#endif
extern TX_THREAD                *_tx_thread_created_ptr;
extern ULONG                    _tx_thread_created_count;
extern TX_SEMAPHORE             *_tx_semaphore_created_ptr;
extern ULONG                    _tx_semaphore_created_count;
extern TX_QUEUE                 *_tx_queue_created_ptr;
extern ULONG                    _tx_queue_created_count;
extern TX_MUTEX                 *_tx_mutex_created_ptr;
extern ULONG                    _tx_mutex_created_count;
extern TX_EVENT_FLAGS_GROUP     *_tx_event_flags_created_ptr;
extern ULONG                    _tx_event_flags_created_count;
extern TX_BYTE_POOL             *_tx_byte_pool_created_ptr;
extern ULONG                    _tx_byte_pool_created_count;
extern TX_BLOCK_POOL            *_tx_block_pool_created_ptr;
extern ULONG                    _tx_block_pool_created_count;

extern NX_PACKET_POOL *         _nx_packet_pool_created_ptr;
extern ULONG                    _nx_packet_pool_created_count;
extern NX_IP *                  _nx_ip_created_ptr;
extern ULONG                    _nx_ip_created_count; 

/* Define main entry point.  */

int main()
{
#if 0
    /* Reassign "stdout" to "freopen.out": */
    stream = freopen( "test_result.txt", "w", stdout );
#endif
    /* Print out some test information banners.  */
    printf("%s\n", _nx_version_id);
#ifdef FEATURE_NX_IPV6
    printf("IPv6 is built-in.\n");
#else
    printf("IPv6 is not built-in.\n");
#endif

#ifdef NX_TUNNEL_ENABLE
    printf("Tunnel is built-in.\n");
#else
    printf("Tunnel is not built-in.\n");
#endif

    printf("IP structure size: %d\n", (UINT)sizeof(NX_IP));
    printf("TCP control block size: %d\n", (UINT)sizeof(NX_TCP_SOCKET));
#if defined(__PRODUCT_NETXDUO__)
#ifndef NX_DISABLE_IPV4
    printf("ARP table entry size: %d, ARP table size %d\n", 
        (UINT)sizeof(NX_ARP), (UINT)(sizeof(NX_ARP) * NX_ARP_TABLE_SIZE));
#endif /* NX_DISABLE_IPV4 */
#elif defined(__PRODUCT_NETX__)
    printf("ARP table entry size: %d, ARP table size %d\n", 
        (UINT)sizeof(NX_ARP), (UINT)(sizeof(NX_ARP) * NX_ROUTE_TABLE_SIZE));
#else
#error "Not NetX nor NetX Duo"
#endif
    printf("Packet structure size: %d\n", (UINT)sizeof(NX_PACKET));
    fflush(stdout);

#if defined(__linux__) && defined(USE_FORK)
    fork_child();
#else
    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
#endif

    return 0;
}

#if defined(__linux__) && defined(USE_FORK)
static pid_t child_pid = -1;
static UINT test_index = 0;
static int result_fd[2];

void kill_child(int sig)
{
CHAR data[4]={0, 1, 0, 0};

    printf("ERROR! - TIMEOUT\n");
    fflush(stdout);
    write(result_fd[1], data, sizeof(data));
    exit(1);
}

void fork_child()
{
INT status;
CHAR data[4];
struct pollfd fds;

    while (test_control_tests[test_index].test_entry != TX_NULL)
    {

        /* Create pipe for communicating. */
        pipe(result_fd);
        fds.fd = result_fd[0];
        fds.events=POLLIN | POLLOUT | POLLERR;


        /* Fork test process. */
        child_pid = fork();
        if (child_pid > 0)
        {
            wait(&status);
            poll(&fds, 1, 0);
            if (fds.revents & POLLIN)
            {
                read(result_fd[0], data, sizeof(data));
                test_control_successful_tests += (ULONG)data[0];
                test_control_failed_tests += (ULONG)data[1];
                test_control_warning_tests += (ULONG)data[2];
                test_control_na_tests += (ULONG)data[3];
            }
            else
            {

                /* The child process crashes. */
                printf("ERROR! CRASH\n");
                test_control_failed_tests++;
            }

            fflush(stdout);

            test_index++;
        }
        else
        {

            /* Setup SIGALRM callback function. */
            signal(SIGALRM, (void (*)(int))kill_child);

            /* Initialize the results. */
            test_control_successful_tests = 0;
            test_control_failed_tests = 0;
            test_control_warning_tests = 0;
            test_control_na_tests = 0;

            /* Setup timeout alarm. */
            alarm(test_control_tests[test_index].timeout / NX_IP_PERIODIC_RATE);

            /* Enter the ThreadX kernel.  */
            tx_kernel_enter();
            return;
        }
    }

    /* Finished with all tests, print results and return!  */
    printf("**** Testing Complete ****\n");
    printf("**** Test Summary:  Tests Passed:  %d   Tests Warning:  %d   Tests Failed:  %d\n", (UINT)test_control_successful_tests, (UINT)test_control_warning_tests, (UINT)test_control_failed_tests);
#ifdef BATCH_TEST
    exit(test_control_failed_tests);
#endif
}

/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{

    fx_system_initialize();

    /* Dispatch the test.  */
    (test_control_tests[test_index].test_entry)(first_unused_memory);
}

void  test_control_return(UINT status)
{
UINT    old_posture = TX_INT_ENABLE;
INT     exit_code = status;
CHAR    data[4];

    fflush(stdout);

    /* Initialize result through pipe. */
    data[0] = (CHAR)test_control_successful_tests;
    data[1] = (CHAR)test_control_failed_tests;
    data[2] = (CHAR)test_control_warning_tests;
    data[3] = (CHAR)test_control_na_tests;

    /* Save the status in a global.  */
    test_control_return_status = status;

    /* Ensure interrupts are enabled.  */
    old_posture = tx_interrupt_control(TX_INT_ENABLE);

    /* Determine if it was successful or not.  */
    if((status == 1) || (_tx_thread_preempt_disable) || (old_posture == TX_INT_DISABLE))       
    {
        data[1]++;
        exit_code = 1;
    }
    else if(status == 2)
    {
        data[2]++;
        exit_code = 2;
    }
    else if(status == 0)
    {
        data[0]++;
        exit_code = 0;
    }
    else if(status == 3)
    {
        data[3]++;
        exit_code = 3;
    }

    /* Send result through pipe. */
    write(result_fd[1], data, sizeof(data));
    exit(exit_code);
}

#else
/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{
    UCHAR    *pointer;

    /* Setup a pointer to the first unused memory.  */
    pointer = (UCHAR *)   first_unused_memory; 

    fx_system_initialize();

#ifdef CTEST

    test_application_define(pointer);

#else

    /* Create the test control thread.  */
    tx_thread_create(&test_control_thread, "test control thread", test_control_thread_entry, 0,  
        pointer, TEST_STACK_SIZE, 
        0, 0, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + TEST_STACK_SIZE;
    
#ifndef NETXTEST_TIMEOUT_DISABLE
    /* Create the test control semaphore.  */
    tx_semaphore_create(&test_control_sema, "Test control semaphore", 0);
#endif

    /* Remember the free memory pointer.  */
    test_free_memory_ptr = pointer;

#endif /* CTEST */
}

/* Define the test control thread.  This thread is responsible for dispatching all of the 
tests in the ThreadX test suite.  */

void  test_control_thread_entry(ULONG thread_input)
{
    UINT    i;

    /* Loop to process all tests...  */
    i = 0;
    while (test_control_tests[i].test_entry != TX_NULL)
    {

        /* Dispatch the test.  */
        (test_control_tests[i++].test_entry)(test_free_memory_ptr);

        if (test_control_return_status != 3)
        {

#ifdef NETXTEST_TIMEOUT_DISABLE
            /* Suspend control test to allow test to run.  */
            tx_thread_suspend(&test_control_thread);
#else
            if(tx_semaphore_get(&test_control_sema, test_control_tests[i - 1].timeout))
            {

                /* Test case timeouts. */
                printf("ERROR!\n");
                test_control_failed_tests++;

            }
#endif
        }
        else
            test_control_return_status = 0;    

        /* Test finished, cleanup in preparation for the next test.  */
        test_control_cleanup();
        fflush(stdout);
    }

    /* Finished with all tests, print results and return!  */
    printf("**** Testing Complete ****\n");
    printf("**** Test Summary:  Tests Passed:  %d   Tests Warning:  %d   Tests Failed:  %d\n", (UINT)test_control_successful_tests, (UINT)test_control_warning_tests, (UINT)test_control_failed_tests);
#if 0
    fclose(stream);
#endif
#ifdef BATCH_TEST
    exit(test_control_failed_tests);
#endif


}

void  test_control_return(UINT status)
{
    UINT    old_posture = TX_INT_ENABLE;

    /* Save the status in a global.  */
    test_control_return_status = status;

    /* Ensure interrupts are enabled.  */
    old_posture = tx_interrupt_control(TX_INT_ENABLE);

    /* Determine if it was successful or not.  */
    if((status == 1) || (_tx_thread_preempt_disable) || (old_posture == TX_INT_DISABLE))       
        test_control_failed_tests++;
    else if(status == 2)
        test_control_warning_tests++;
    else if(status == 0)
        test_control_successful_tests++;
    else if(status == 3)
        test_control_na_tests++;


#ifdef CTEST

    exit(test_control_failed_tests);

#else

#ifdef NETXTEST_TIMEOUT_DISABLE
    /* Resume the control thread to fully exit the test.  */
    tx_thread_resume(&test_control_thread);
#else
    if(test_control_return_status != 3)
        tx_semaphore_put(&test_control_sema);
#endif

#endif /* CTEST */
}

void  test_control_cleanup(void)
{
    TX_MUTEX        *mutex_ptr;
    TX_THREAD       *thread_ptr;

    /* Clean timer used by RAM driver. */
    _nx_ram_network_driver_timer_clean();

    /* Delete all IP instances.   */
    while (_nx_ip_created_ptr)
    {

        /* Delete all UDP sockets.  */
        while (_nx_ip_created_ptr -> nx_ip_udp_created_sockets_ptr)
        {

            /* Make sure the UDP socket is unbound.  */
            nx_udp_socket_unbind(_nx_ip_created_ptr -> nx_ip_udp_created_sockets_ptr);

            /* Delete the UDP socket.  */
            nx_udp_socket_delete(_nx_ip_created_ptr -> nx_ip_udp_created_sockets_ptr);
        }

        /* Delete all TCP sockets.  */
        while (_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr)
        {

            /* Disconnect.  */
            nx_tcp_socket_disconnect(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr, NX_NO_WAIT);

            /* Make sure the TCP client socket is unbound.  */
            nx_tcp_client_socket_unbind(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr);

            /* Make sure the TCP server socket is unaccepted.  */
            nx_tcp_server_socket_unaccept(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr);

            /* Delete the TCP socket.  */
            nx_tcp_socket_delete(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr);
        }

        /* Clear all listen requests.  */
        while (_nx_ip_created_ptr -> nx_ip_tcp_active_listen_requests)
        {

            /* Make sure the TCP server socket is unlistened.  */
            nx_tcp_server_socket_unlisten(_nx_ip_created_ptr, (_nx_ip_created_ptr -> nx_ip_tcp_active_listen_requests) -> nx_tcp_listen_port);
        }

        /* Delete the IP instance.  */
        nx_ip_delete(_nx_ip_created_ptr);
    }

    /* Delete all the packet pools.  */
    while (_nx_packet_pool_created_ptr)
    {
        nx_packet_pool_delete(_nx_packet_pool_created_ptr);
    }

    /* Reset the RAM driver.  */
    _nx_ram_network_driver_reset();

    /* Delete all queues.  */
    while(_tx_queue_created_ptr)
    {

        /* Delete queue.  */
        tx_queue_delete(_tx_queue_created_ptr);
    }

    /* Delete all semaphores.  */
    while(_tx_semaphore_created_ptr)
    {
#ifndef NETXTEST_TIMEOUT_DISABLE
        if(_tx_semaphore_created_ptr != &test_control_sema)
        {

            /* Delete semaphore.  */
            tx_semaphore_delete(_tx_semaphore_created_ptr);
        }
        else if(_tx_semaphore_created_count == 1)
            break;
        else
        {
            /* Delete semaphore.  */
            tx_semaphore_delete(_tx_semaphore_created_ptr -> tx_semaphore_created_next);
        }
#else
        /* Delete semaphore.  */
        tx_semaphore_delete(_tx_semaphore_created_ptr);
#endif
    }

    /* Delete all event flag groups.  */
    while(_tx_event_flags_created_ptr)
    {

        /* Delete event flag group.  */
        tx_event_flags_delete(_tx_event_flags_created_ptr);
    }

    /* Delete all byte pools.  */
    while(_tx_byte_pool_created_ptr)
    {

        /* Delete byte pool.  */
        tx_byte_pool_delete(_tx_byte_pool_created_ptr);
    }

    /* Delete all block pools.  */
    while(_tx_block_pool_created_ptr)
    {

        /* Delete block pool.  */
        tx_block_pool_delete(_tx_block_pool_created_ptr);
    }

    /* Delete all timers.  */
    while(_tx_timer_created_ptr)
    {

        /* Deactivate timer.  */
        tx_timer_deactivate(_tx_timer_created_ptr);

        /* Delete timer.  */
        tx_timer_delete(_tx_timer_created_ptr);
    }

    /* Delete all mutexes (except for system mutex).  */
    while(_tx_mutex_created_ptr)
    {

        /* Setup working mutex pointer.  */
        mutex_ptr = _tx_mutex_created_ptr;

#ifdef __ghs

        /* Determine if the mutex is the GHS system mutex.  If so, don't delete!  */
        if(mutex_ptr == &__ghLockMutex)
        {

            /* Move to next mutex.  */
            mutex_ptr = mutex_ptr -> tx_mutex_created_next;
        }

        /* Determine if there are no more mutexes to delete.  */
        if(_tx_mutex_created_count == 1)
            break;
#endif

        /* Delete mutex.  */
        tx_mutex_delete(mutex_ptr);
    }

    /* Delete all threads, except for timer thread, and test control thread.  */
    while (_tx_thread_created_ptr)
    {

        /* Setup working pointer.  */
        thread_ptr = _tx_thread_created_ptr;

#ifdef TX_TIMER_PROCESS_IN_ISR

        /* Determine if there are more threads to delete.  */
        if(_tx_thread_created_count == 1)
            break;

        /* Determine if this thread is the test control thread.  */
        if(thread_ptr == &test_control_thread)
        {

            /* Move to the next thread pointer.  */
            thread_ptr = thread_ptr -> tx_thread_created_next;
        }
#else

        /* Determine if there are more threads to delete.  */
        if(_tx_thread_created_count == 2)
            break;

        /* Move to the thread not protected.  */
        while ((thread_ptr == &_tx_timer_thread) || (thread_ptr == &test_control_thread))
        {

            /* Yes, move to the next thread.  */
            thread_ptr = thread_ptr -> tx_thread_created_next;
        }
#endif

        /* First terminate the thread to ensure it is ready for deletion.  */
        tx_thread_terminate(thread_ptr);

        /* Delete the thread.  */
        tx_thread_delete(thread_ptr);
    }

    /* At this point, only the test control thread and the system timer thread and/or mutex should still be
    in the system.  */

#ifdef NX_PCAP_ENABLE
    /* Close the pcap file.  */
    close_pcap_file();
#endif 
}
#endif
