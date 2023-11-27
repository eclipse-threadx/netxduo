/* This NetX test concentrates on the code coverage for IPv6 functions,
 * nx_tcp_connect_cleanup.c
 * nx_tcp_disconnect_cleanup.c
 * nx_udp_bind_cleanup.c */

#include "tx_api.h"
#include "nx_api.h"
extern void    test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6

#include "tx_thread.h"
#include "nx_icmp.h"
#include "nx_ip.h"
#include "nx_icmpv6.h" 

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
#ifndef NX_DISABLE_ASSERT
static TX_THREAD               thread_for_assert;
static UINT                    assert_count = 0;
#endif
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;
static CHAR                    *pointer;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
#ifndef NX_DISABLE_ASSERT
static void    thread_for_assert_entry(ULONG thread_input);
#endif


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_branch_test_application_define(void *first_unused_memory)
#endif
{

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

#if (NX_MAX_PHYSICAL_INTERFACES > 1)
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL,
                                    _nx_ram_network_driver_256);

    if (status)
        error_counter++;
#endif /* (NX_MAX_PHYSICAL_INTERFACES > 1) */

    /* Enable ICMP processing for IP instance.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    /* Enable IPv6 processing for IP instance.  */
    status = nxd_ipv6_enable(&ip_0);

    /* Check IPv6 enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

NX_PACKET  *my_packet[2];
NXD_ADDRESS ipv6_address;
ULONG       prefix_address[4];
ULONG       address_1[4];
ULONG       address_2[4];
ULONG       router_address;
void       *nd_cache_entry;
ND_CACHE_ENTRY
            cache_entry;
NXD_IPV6_ADDRESS
            *nxd_ipv6_address;  
#ifndef NX_DISABLE_FRAGMENTATION
NX_IP_DRIVER
            driver_request;
#endif
UINT        address_index;


    /* Print out some test information banners.  */
    printf("NetX Test:   IPv6 Branch Test..........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }



#ifndef NX_DISABLE_FRAGMENTATION
    /* Hit condition of while (bytes_remaining > 0) and if ((source_pkt == NX_NULL) || (dest_pkt == NX_NULL)) in _nx_ipv6_packet_copy(). */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_allocate(&pool_0, &my_packet[1], 0, NX_NO_WAIT);
    _nx_ipv6_packet_copy(my_packet[0], my_packet[1], 0);
    my_packet[0] -> nx_packet_last = my_packet[1];
    _nx_ipv6_packet_copy(my_packet[0], my_packet[1], 100);
    my_packet[0] -> nx_packet_last = NX_NULL;
    my_packet[1] -> nx_packet_last = my_packet[0];
    _nx_ipv6_packet_copy(my_packet[0], my_packet[1], 100);
    my_packet[0] -> nx_packet_last = NX_NULL;
    my_packet[1] -> nx_packet_last = NX_NULL;
    nx_packet_release(my_packet[0]); 
    nx_packet_release(my_packet[1]);
#endif



    /* Hit false condition of CHECK_IPV6_ADDRESSES_SAME(prefix, current -> nx_ipv6_prefix_entry_network_address) in _nx_ipv6_prefix_list_delete . */
    prefix_address[0] = 0x20010001;
    prefix_address[1] = 0x00000002;
    prefix_address[2] = 0x00000003;
    prefix_address[3] = 0x00000004;
    _nx_ipv6_prefix_list_add_entry(&ip_0, prefix_address, 64, 100);
    _nx_ipv6_prefix_list_delete(&ip_0, prefix_address, 48);
    prefix_address[3] = 0x00000005;
    _nx_ipv6_prefix_list_delete(&ip_0, prefix_address, 64);
    prefix_address[3] = 0x00000004;
    _nx_ipv6_prefix_list_delete(&ip_0, prefix_address, 64);


    /* Hit false condition of if (interface_ipv6_address -> nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_UNKNOWN)  in _nx_ipv6_prefix_list_delete_entry . */    
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[0] = 0x20010001;
    ipv6_address.nxd_ip_address.v6[1] = 0x00000002;
    ipv6_address.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[3] = 0x00000004;
    nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 64, NX_NULL);
    ip_0.nx_ipv6_address[0].nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_UNKNOWN;
    _nx_ipv6_prefix_list_delete_entry(&ip_0, ip_0.nx_ipv6_prefix_list_ptr);
    nxd_ipv6_address_delete(&ip_0, 0);



    /* Hit condition of for (i = 0; i < 4; i++) in _nxd_ipv6_find_max_prefix_length . */
    address_1[0] = 0x20010001;
    address_1[1] = 0x00000002;
    address_1[2] = 0x00000003;
    address_1[3] = 0x00000004;
        
    address_2[0] = 0x20010001;
    address_2[1] = 0x00000002;
    address_2[2] = 0x00000003;
    address_2[3] = 0x00000004;
    _nxd_ipv6_find_max_prefix_length(address_1, address_2, 128);
                  
#ifndef NX_DISABLE_ASSERT
    /* Test _nx_ip_header_add().  */
    /* Hit NX_ASSERT(packet_ptr -> nx_packet_prepend_ptr >= packet_ptr -> nx_packet_data_start);  */

    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Test _nxd_ipv6_destination_table_find_next_hop  */
    /* Hit NX_ASSERT(next_hop != NX_NULL);  */      
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Test _nxd_ipv6_router_lookup  */
    /* Hit NX_ASSERT(routers_checked != NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE);  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Test _nxd_ipv6_router_lookup  */
    /* Hit NX_ASSERT(nd_cache_entry != NX_NULL)  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Test _nxd_ipv6_interface_find  */
    /* Hit NX_ASSERT(ipv6_addr != NX_NULL);  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Test _nxd_ipv6_interface_find  */
    /* Hit NX_ASSERT((*ipv6_addr) -> nxd_ipv6_address_valid);  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);

    
    /* Test _nxd_ipv6_interface_find  */
    /* Hit NX_ASSERT((*ipv6_addr) -> nxd_ipv6_address_valid);  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);
    
    /* Test _nxd_ipv6_interface_find  */
    /* Hit NX_ASSERT((*ipv6_addr) -> nxd_ipv6_address_valid);  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);

    /* Test _nx_ipv6_header_add  */
    /* Hit NX_ASSERT(packet_ptr -> nx_packet_prepend_ptr >= packet_ptr -> nx_packet_data_start);  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);

    /* Test _nx_ipv6_packet_send  */
    /* Hit NX_ASSERT(if_ptr -> nx_interface_link_driver_entry != NX_NULL);  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);
    ip_0.nx_ip_interface[0].nx_interface_link_driver_entry = _nx_ram_network_driver_256;

    /* Test _nx_ipv6_packet_send  */
    /* Hit NX_ASSERT(if_ptr != NX_NULL);  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);

    /* Test _nx_ipv6_packet_send  */
    /* Hit NX_ASSERT(NDCacheEntry -> nx_nd_cache_nd_status != ND_CACHE_STATE_INVALID);  */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);
#else

    /* Set up the IPv6 address. */
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[3] = 0x4;
    ipv6_address.nxd_ip_address.v6[2] = 0x0;
    ipv6_address.nxd_ip_address.v6[1] = 0x0;
    ipv6_address.nxd_ip_address.v6[0] = 0xfe800000;

    /* Add a router.  */
    _nxd_ipv6_default_router_add(&ip_0, &ipv6_address, 1000, 0);

#endif /* NX_DISABLE_ASSERT  */
                          
    /* Hit false condition of for (i = 0; table_size && (i < NX_IPV6_DESTINATION_TABLE_SIZE); i++).  */
    ip_0.nx_ipv6_destination_table_size = NX_IPV6_DESTINATION_TABLE_SIZE + 1; 
    _nxd_ipv6_destination_table_find_next_hop(&ip_0, address_1, address_2);
    ip_0.nx_ipv6_destination_table_size = 0; 

    /* Cover the branches for NDCacheEntry -> nx_nd_cache_nd_status.  */
    cache_entry.nx_nd_cache_nd_status = ND_CACHE_STATE_INVALID;
    ip_0.nx_ipv6_default_router_table[0].nx_ipv6_default_router_entry_neighbor_cache_ptr = &cache_entry;
    _nxd_ipv6_router_lookup(&ip_0, &ip_0.nx_ip_interface[0], &router_address, &nd_cache_entry);
    cache_entry.nx_nd_cache_nd_status = ND_CACHE_STATE_CREATED;
    _nxd_ipv6_router_lookup(&ip_0, &ip_0.nx_ip_interface[0], &router_address, &nd_cache_entry);
    ip_0.nx_ipv6_default_router_table[0].nx_ipv6_default_router_entry_neighbor_cache_ptr = NX_NULL;

#if (NX_MAX_PHYSICAL_INTERFACES > 1)
    /* Hit the branch 
     156 [ +  + ][ +  - ]:        408 :         if ((rt_entry -> nx_ipv6_default_router_entry_flag & NX_IPV6_ROUTE_TYPE_VALID) &&
     157                 :        378 :             (rt_entry -> nx_ipv6_default_router_entry_interface_ptr == if_ptr))
     */
    ip_0.nx_ipv6_default_router_table[0].nx_ipv6_default_router_entry_flag = NX_IPV6_ROUTE_TYPE_VALID;
    _nxd_ipv6_router_lookup(&ip_0, &ip_0.nx_ip_interface[1], &router_address, &nd_cache_entry);
#endif /* (NX_MAX_PHYSICAL_INTERFACES > 1) */

    /* Call nxd_ipv6_default_router_entry_get with NULL pointers.  */
    nxd_ipv6_default_router_entry_get(&ip_0, 0, 0, NX_NULL, NX_NULL, NX_NULL, NX_NULL);

    /* Set linklocal address */
    nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 10, NX_NULL);

    /* Set up the IPv6 address. */
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[3] = 0x3;
    ipv6_address.nxd_ip_address.v6[2] = 0x0;
    ipv6_address.nxd_ip_address.v6[1] = 0x0;
    ipv6_address.nxd_ip_address.v6[0] = 0xFF000000;

    /* Call _nxd_ipv6_interface_find with multicast destination address.  */
    _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &nxd_ipv6_address, NX_NULL);

    /* Set up the IPv6 address. */
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[3] = 0x2;
    ipv6_address.nxd_ip_address.v6[2] = 0x0;
    ipv6_address.nxd_ip_address.v6[1] = 0x0;
    ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;
    ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address[0] = 0xFE000000;

    /* Call _nxd_ipv6_interface_find with link local destination address.  */
    _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &nxd_ipv6_address, NX_NULL);
    ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address[0] = 0xFE800000;

    ipv6_address.nxd_ip_address.v6[0] = 0x20010000;
    ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_DEPRECATED;
    /* Call _nxd_ipv6_interface_find with multicast destination address.  */
    _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &nxd_ipv6_address, NX_NULL);
    ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_VALID;

    /* Call _nxd_ipv6_address_delete with invalid interface address list.  */
    ip_0.nx_ipv6_address[0].nxd_ipv6_address_attached -> nxd_interface_ipv6_address_list_head = NX_NULL;
    _nxd_ipv6_address_delete(&ip_0, 0);
    ip_0.nx_ipv6_address[0].nxd_ipv6_address_attached -> nxd_interface_ipv6_address_list_head = &ip_0.nx_ipv6_address[0];
    
    /* Call _nx_ipv6_header_add with invalid address state and protocol.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;
    _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &my_packet[0] -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
    ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_DEPRECATED;
    _nx_ipv6_header_add(&ip_0, &my_packet[0], NX_PROTOCOL_UDP, 10, 10, NX_NULL, NX_NULL, NX_NULL);
    nx_packet_release(my_packet[0]);
    ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_VALID;


#ifndef NX_DISABLE_FRAGMENTATION
    /* Call _nx_ipv6_fragment_process with a packet with NX_PROTOCOL_NEXT_HEADER_ROUTING.  */
    driver_request.nx_ip_driver_ptr = &ip_0;
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    driver_request.nx_ip_driver_packet = my_packet[0];
    my_packet[0] -> nx_packet_length = 48;
    my_packet[0] ->nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 48;

    *(my_packet[0] -> nx_packet_prepend_ptr + 6) = NX_PROTOCOL_NEXT_HEADER_ROUTING;
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV6_HEADER)) = NX_PROTOCOL_TCP;
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV6_HEADER) + 1) = 0;
    _nx_ipv6_fragment_process(&driver_request, 1400);
#endif


    /* Set up the IPv6 address. */
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[3] = 0x4;
    ipv6_address.nxd_ip_address.v6[2] = 0x0;
    ipv6_address.nxd_ip_address.v6[1] = 0x0;
    ipv6_address.nxd_ip_address.v6[0] = 0xfe800000;

    /* Add a duplicated router.  */
    _nxd_ipv6_default_router_add(&ip_0, &ipv6_address, 1000, 0);

    /* Add a duplicated router but with a different interface.  */
    _nxd_ipv6_default_router_add_internal(&ip_0, ipv6_address.nxd_ip_address.v6, 0xFFFF, &ip_0.nx_ip_interface[1], NX_IPV6_ROUTE_TYPE_STATIC, NX_NULL);

    _nxd_ipv6_prefix_router_timer_tick(&ip_0);

    ip_0.nx_ipv6_default_router_table[0].nx_ipv6_default_router_entry_life_time = 0;
    ip_0.nx_ipv6_destination_table_size = NX_IPV6_DESTINATION_TABLE_SIZE + 1;
    ip_0.nx_ipv6_default_router_table[0].nx_ipv6_default_router_entry_neighbor_cache_ptr = &cache_entry;
    _nxd_ipv6_prefix_router_timer_tick(&ip_0);
    ip_0.nx_ipv6_default_router_table[0].nx_ipv6_default_router_entry_neighbor_cache_ptr = NX_NULL;
    ip_0.nx_ipv6_destination_table_size = 0;

    /* Test _nxd_ipv6_address_set with different interface address.  */
    ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address[1] = 1;
    _nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, &address_index);
    ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address[1] = 0;
    ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address[2] = 0x021122FF;
    _nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, &address_index);

    /* Test _nxd_ipv6_disable with null nx_nd_cache_interface_ptr.  */
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_nd_status = ND_CACHE_STATE_CREATED;
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_interface_ptr = NX_NULL;
    _nxd_ipv6_disable(&ip_0);
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_nd_status = ND_CACHE_STATE_INVALID;
    _nxd_ipv6_enable(&ip_0);

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


#ifndef NX_DISABLE_ASSERT
/* Define the test threads.  */

static void    thread_for_assert_entry(ULONG thread_input)
{
NX_PACKET   *test_packet;
NXD_ADDRESS  destination_ip;
ULONG        ipv6_destination_address[4];
NXD_ADDRESS  ipv6_address;
ULONG        router_address;
void        *nd_cache_entry;
NXD_IPV6_ADDRESS
            *nxd_ipv6_address;
NX_IPV6_DESTINATION_ENTRY 
            *dest_entry_ptr;


    /* Check the count.  */
    if (assert_count == 0)
    {

        /* Update the count.  */
        assert_count ++;

        nx_packet_allocate(&pool_0, &test_packet, 0, NX_NO_WAIT);
        test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr  = NX_NULL;

        /* Call function with NULL interface.  */
        _nxd_ipv6_raw_packet_send_internal(&ip_0, test_packet, &destination_ip, 0);
    }
    else if (assert_count == 1)
    {

        /* Update the count.  */
        assert_count ++;

        /* Call function with NULL next hop.  */
        _nxd_ipv6_destination_table_find_next_hop(&ip_0, ipv6_destination_address, NX_NULL);
    }
    else if (assert_count == 2)
    {

        /* Update the count.  */
        assert_count ++;

        /* Set up the IPv6 address. */
        ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
        ipv6_address.nxd_ip_address.v6[3] = 0x3;
        ipv6_address.nxd_ip_address.v6[2] = 0x0;
        ipv6_address.nxd_ip_address.v6[1] = 0x0;
        ipv6_address.nxd_ip_address.v6[0] = 0xfe800000;
        nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 64, NX_NULL);
        ipv6_address.nxd_ip_address.v6[3] = 0x4;

        _nxd_ipv6_default_router_add(&ip_0, &ipv6_address, 1000, 0);

        /* Hit false condition of for (i = 0; table_size && (i < NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE); i++).  */
        ip_0.nx_ipv6_default_router_table[0].nx_ipv6_default_router_entry_flag = NX_IPV6_ROUTE_TYPE_NOT_ROUTER;
        _nxd_ipv6_router_lookup(&ip_0, &ip_0.nx_ip_interface[0], &router_address, &nd_cache_entry);

    }
    else if (assert_count == 3)
    {

        /* Update the count.  */
        assert_count ++;

        ip_0.nx_ipv6_default_router_table[0].nx_ipv6_default_router_entry_flag = NX_IPV6_ROUTE_TYPE_VALID | NX_IPV6_ROUTE_TYPE_STATIC;

        /* Call function with NULL cache entry pointer.  */
        _nxd_ipv6_router_lookup(&ip_0, &ip_0.nx_ip_interface[0], &router_address, NX_NULL);
    }
    else if (assert_count == 4)
    {

        /* Update the count.  */
        assert_count ++;

        /* Call function with NULL address pointers.  */
        _nxd_ipv6_interface_find(&ip_0, ipv6_destination_address, NX_NULL, NX_NULL);
    }
    else if (assert_count == 5)
    {

        /* Update the count.  */
        assert_count ++;

        /* This test point is useless since the logic of _nxd_ipv6_interface_find is modified. */
#if 0
        /* Set up the IPv6 address. */
        ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
        ipv6_address.nxd_ip_address.v6[3] = 0x3;
        ipv6_address.nxd_ip_address.v6[2] = 0x0;
        ipv6_address.nxd_ip_address.v6[1] = 0x0;
        ipv6_address.nxd_ip_address.v6[0] = 0xFF020000;

        ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address_valid = NX_FALSE;

        /* Call function with invalid address pointers.  */
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &nxd_ipv6_address, NX_NULL);
#else
        tx_thread_suspend(tx_thread_identify());
#endif

    }
    else if (assert_count == 6)
    {

        /* Update the count.  */
        assert_count ++;

        /* This test point is useless since the logic of _nxd_ipv6_interface_find is modified. */
#if 0
        /* Set up the IPv6 address. */
        ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
        ipv6_address.nxd_ip_address.v6[3] = 0x2;
        ipv6_address.nxd_ip_address.v6[2] = 0x0;
        ipv6_address.nxd_ip_address.v6[1] = 0x0;
        ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;

        ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address_valid = NX_FALSE;

        /* Call function with invalid address pointers.  */
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &nxd_ipv6_address, NX_NULL);
#else
        tx_thread_suspend(tx_thread_identify());
#endif

    }
    else if (assert_count == 7)
    {

        /* Update the count.  */
        assert_count ++;

        /* This test point is useless since the logic of _nxd_ipv6_interface_find is modified. */
#if 0
        /* Set up the IPv6 address. */
        ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
        ipv6_address.nxd_ip_address.v6[3] = 0x2;
        ipv6_address.nxd_ip_address.v6[2] = 0x0;
        ipv6_address.nxd_ip_address.v6[1] = 0x0;
        ipv6_address.nxd_ip_address.v6[0] = 0x20010000;
        ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address[0] = 0x20010000;
        ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address_valid = NX_FALSE;

        /* Call function with invalid address pointers.  */
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &nxd_ipv6_address, NX_NULL);
#else
        tx_thread_suspend(tx_thread_identify());
#endif

    }
    else if (assert_count == 8)
    {

        /* Update the count.  */
        assert_count ++;

        /* Call _nx_ipv6_header_add with invalid nx_packet_prepend_ptr.  */
        nx_packet_allocate(&pool_0, &test_packet, 0, NX_NO_WAIT);
        ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
        test_packet -> nx_packet_prepend_ptr = test_packet -> nx_packet_data_start - 1;
        _nx_ipv6_header_add(&ip_0, &test_packet, NX_PROTOCOL_ICMPV6, 10, 10, NX_NULL, NX_NULL, NX_NULL);

    }
    else if (assert_count == 9)
    {

        /* Update the count.  */
        assert_count ++;

        /* Set up the IPv6 address. */
        ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
        ipv6_address.nxd_ip_address.v6[3] = 0x2;
        ipv6_address.nxd_ip_address.v6[2] = 0x0;
        ipv6_address.nxd_ip_address.v6[1] = 0x0;
        ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;

        /* Test _nx_ipv6_packet_send with nx_ipv6_destination_table full for on link destination.  */
        nx_packet_allocate(&pool_0, &test_packet, NX_IPv6_UDP_PACKET, NX_NO_WAIT);
        test_packet -> nx_packet_length = 60;
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + test_packet -> nx_packet_length;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
        ip_0.nx_ipv6_destination_table_size = NX_IPV6_DESTINATION_TABLE_SIZE;
        _nx_ipv6_packet_send(&ip_0, test_packet, NX_PROTOCOL_UDP, test_packet -> nx_packet_length, ip_0.nx_ipv6_hop_limit, ip_0.nx_ipv6_address[0].nxd_ipv6_address, ipv6_address.nxd_ip_address.v6);
        ip_0.nx_ipv6_destination_table_size = 0;

        /* Test _nx_ipv6_packet_send with nx_ipv6_destination_table full for off link destination.  */
        nx_packet_allocate(&pool_0, &test_packet, NX_IPv6_UDP_PACKET, NX_NO_WAIT);
        test_packet -> nx_packet_length = 60;
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + test_packet -> nx_packet_length;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
        ipv6_address.nxd_ip_address.v6[0] = 0x20010000;
        ip_0.nx_ipv6_destination_table_size = NX_IPV6_DESTINATION_TABLE_SIZE;
        _nx_ipv6_packet_send(&ip_0, test_packet, NX_PROTOCOL_UDP, test_packet -> nx_packet_length, ip_0.nx_ipv6_hop_limit, ip_0.nx_ipv6_address[0].nxd_ipv6_address, ipv6_address.nxd_ip_address.v6);
        ip_0.nx_ipv6_destination_table_size = 0;

        /* Call _nx_ipv6_packet_send to add ND cache.  */
        ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;
        nx_packet_allocate(&pool_0, &test_packet, NX_IPv6_UDP_PACKET, NX_NO_WAIT);
        test_packet -> nx_packet_length = 60;
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + test_packet -> nx_packet_length;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
        _nx_ipv6_packet_send(&ip_0, test_packet, NX_PROTOCOL_UDP, test_packet -> nx_packet_length, ip_0.nx_ipv6_hop_limit, ip_0.nx_ipv6_address[0].nxd_ipv6_address, ipv6_address.nxd_ip_address.v6);

        /* Call _nx_ipv6_packet_send to add ND cache.  */
        nx_packet_allocate(&pool_0, &test_packet, NX_IPv6_UDP_PACKET, NX_NO_WAIT);
        test_packet -> nx_packet_length = 60;
        test_packet -> nx_packet_prepend_ptr = test_packet -> nx_packet_data_start + NX_IPv6_UDP_PACKET;
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + test_packet -> nx_packet_length;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
        _nx_ipv6_packet_send(&ip_0, test_packet, NX_PROTOCOL_UDP, test_packet -> nx_packet_length, ip_0.nx_ipv6_hop_limit, ip_0.nx_ipv6_address[0].nxd_ipv6_address, ipv6_address.nxd_ip_address.v6);

        /* Call _nx_ipv6_packet_send with null nx_nd_cache_packet_waiting_head.  */
        nx_packet_allocate(&pool_0, &test_packet, NX_IPv6_UDP_PACKET, NX_NO_WAIT);
        test_packet -> nx_packet_length = 60;
        test_packet -> nx_packet_prepend_ptr = test_packet -> nx_packet_data_start + NX_IPv6_UDP_PACKET;
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + test_packet -> nx_packet_length;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
        ip_0.nx_ipv6_nd_cache[2].nx_nd_cache_packet_waiting_head = NX_NULL;
        ip_0.nx_ipv6_nd_cache[2].nx_nd_cache_packet_waiting_queue_length = NX_ND_MAX_QUEUE_DEPTH + 1;
        _nx_ipv6_packet_send(&ip_0, test_packet, NX_PROTOCOL_UDP, test_packet -> nx_packet_length, ip_0.nx_ipv6_hop_limit, ip_0.nx_ipv6_address[0].nxd_ipv6_address, ipv6_address.nxd_ip_address.v6);

#ifdef NX_ENABLE_IPV6_PATH_MTU_DISCOVERY
        /* Call _nx_ipv6_packet_send with zero nx_ipv6_destination_entry_path_mtu.  */
        nx_packet_allocate(&pool_0, &test_packet, NX_IPv6_UDP_PACKET, NX_NO_WAIT);
        test_packet -> nx_packet_length = 60;
        test_packet -> nx_packet_prepend_ptr = test_packet -> nx_packet_data_start + NX_IPv6_UDP_PACKET;
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + test_packet -> nx_packet_length;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
        ip_0.nx_ipv6_nd_cache[2].nx_nd_cache_nd_status = ND_CACHE_STATE_REACHABLE;
        ip_0.nx_ipv6_destination_table[0].nx_ipv6_destination_entry_path_mtu = 0;
        _nx_ipv6_packet_send(&ip_0, test_packet, NX_PROTOCOL_UDP, test_packet -> nx_packet_length, ip_0.nx_ipv6_hop_limit, ip_0.nx_ipv6_address[0].nxd_ipv6_address, ipv6_address.nxd_ip_address.v6);

        /* Call _nx_ipv6_packet_send with null nx_interface_link_driver_entry.  */
        ip_0.nx_ip_interface[0].nx_interface_link_driver_entry = NX_NULL;
        nx_packet_allocate(&pool_0, &test_packet, NX_IPv6_UDP_PACKET, NX_NO_WAIT);
        test_packet -> nx_packet_length = 60;
        test_packet -> nx_packet_prepend_ptr = test_packet -> nx_packet_data_start + NX_IPv6_UDP_PACKET;
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + test_packet -> nx_packet_length;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
        ip_0.nx_ipv6_destination_table[0].nx_ipv6_destination_entry_path_mtu = 256;
        _nx_ipv6_packet_send(&ip_0, test_packet, NX_PROTOCOL_UDP, test_packet -> nx_packet_length, ip_0.nx_ipv6_hop_limit, ip_0.nx_ipv6_address[0].nxd_ipv6_address, ipv6_address.nxd_ip_address.v6);
#endif

    }
    else if (assert_count == 10)
    {
        NXD_IPV6_ADDRESS ipv6_address2;

        /* Update the count.  */
        assert_count ++;

        /* Set up the IPv6 address. */
        ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
        ipv6_address.nxd_ip_address.v6[3] = 0x2;
        ipv6_address.nxd_ip_address.v6[2] = 0x0;
        ipv6_address.nxd_ip_address.v6[1] = 0x0;
        ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;

        /* Test _nx_ipv6_packet_send with null interface pointer.  */
        nx_packet_allocate(&pool_0, &test_packet, NX_IPv6_UDP_PACKET, NX_NO_WAIT);
        test_packet -> nx_packet_length = 60;
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + test_packet -> nx_packet_length;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);
        ipv6_address2 = *test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr;
        ipv6_address2.nxd_ipv6_address_attached = NX_NULL;
        test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr = &ipv6_address2;
        _nx_ipv6_packet_send(&ip_0, test_packet, NX_PROTOCOL_UDP, test_packet -> nx_packet_length, ip_0.nx_ipv6_hop_limit, ip_0.nx_ipv6_address[0].nxd_ipv6_address, ipv6_address.nxd_ip_address.v6);

    }
    else if (assert_count == 11)
    {

        /* Update the count.  */
        assert_count ++;

        /* Set up the IPv6 address. */
        ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
        ipv6_address.nxd_ip_address.v6[3] = 0x2;
        ipv6_address.nxd_ip_address.v6[2] = 0x0;
        ipv6_address.nxd_ip_address.v6[1] = 0x0;
        ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;
                                    
                                  
        nx_packet_allocate(&pool_0, &test_packet, NX_IPv6_UDP_PACKET, NX_NO_WAIT);
        test_packet -> nx_packet_length = 60;
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + test_packet -> nx_packet_length;
        _nxd_ipv6_interface_find(&ip_0, ipv6_address.nxd_ip_address.v6, &test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr, NX_NULL);

        /* Test _nx_ipv6_packet_send with state of ND cache invalid.  */
        _nx_icmpv6_dest_table_add(&ip_0, ipv6_address.nxd_ip_address.v6, &dest_entry_ptr,
                                  ipv6_address.nxd_ip_address.v6, 1500, NX_WAIT_FOREVER,
                                  test_packet -> nx_packet_address.nx_packet_ipv6_address_ptr);
        dest_entry_ptr -> nx_ipv6_destination_entry_nd_entry -> nx_nd_cache_nd_status = ND_CACHE_STATE_INVALID;

        _nx_ipv6_packet_send(&ip_0, test_packet, NX_PROTOCOL_UDP, test_packet -> nx_packet_length, ip_0.nx_ipv6_hop_limit, ip_0.nx_ipv6_address[0].nxd_ipv6_address, ipv6_address.nxd_ip_address.v6);
    }

}
#endif

#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_branch_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Branch Test..........................................N/A\n");
    
    test_control_return(3);
}
#endif
