/* This NetX test concentrates on the code coverage for IGMP functions,
 * _nx_igmp_packet_receive
 *_nx_igmp_multicast_check
 *_nx_igmp_multicast_interface_join_internal
 *_nx_igmp_multicast_interface_leave_internal
 *_nx_igmp_periodic_processing
 *_nx_igmp_packet_process
 */

#include "nx_api.h"
#include "tx_thread.h"
#include "tx_timer.h"
#include "nx_igmp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;



/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_igmp_branch_test_application_define(void *first_unused_memory)
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
                                      
    /* Enable IGMP processing for IP instance.  */
    status =  nx_igmp_enable(&ip_0);

    /* Check IGMP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

ULONG       system_state;
NX_PACKET  *my_packet[2]; 
#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_ENABLE_INTERFACE_CAPABILITY)
UINT        packet_available;
#endif


    /* Print out some test information banners.  */
    printf("NetX Test:   IGMP Branch Test..........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Hit condition of if ((_tx_thread_system_state) || (&(ip_ptr -> nx_ip_thread) != _tx_thread_current_ptr)) in _nx_igmp_packet_receive().  */
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_data_append(my_packet[0], "abcdefghijklmnopqrstuvwxyz", 26, &pool_0, NX_NO_WAIT);

    system_state = _tx_thread_system_state;
    _tx_thread_system_state = 0;

    _nx_igmp_packet_receive(&ip_0, my_packet[0]);
    ip_0.nx_ip_igmp_queue_head =  NX_NULL;

    _tx_thread_system_state = system_state;
    nx_packet_release(my_packet[0]);

    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_data_append(my_packet[0], "abcdefghijklmnopqrstuvwxyz", 26, &pool_0, NX_NO_WAIT);
    system_state = _tx_thread_system_state;
    _tx_thread_system_state = 1;

    _nx_igmp_packet_receive(&ip_0, my_packet[0]);
    ip_0.nx_ip_igmp_queue_head =  NX_NULL;

    _tx_thread_system_state = system_state;
    nx_packet_release(my_packet[0]);
    tx_mutex_put(&(ip_0.nx_ip_protection));



    /* Hit condition of if ((ip_ptr -> nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_list == group) && (nx_interface == ip_ptr -> nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_interface_list)) in _nx_igmp_multicast_check(). */
    nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224, 0, 0, 2));
    _nx_igmp_multicast_check(&ip_0, IP_ADDRESS(224, 0, 0, 2), &ip_0.nx_ip_interface[0]);
    _nx_igmp_multicast_check(&ip_0, IP_ADDRESS(224, 0, 0, 2), NX_NULL);
    nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224, 0, 0, 2));



#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_ENABLE_INTERFACE_CAPABILITY)
    /* Hit condition of if ((ip_ptr -> nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_list == group) && (nx_interface == ip_ptr -> nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_interface_list)) in _nx_igmp_multicast_interface_join_internal(). */
    /* Attach the 2nd interface to IP instance0 */
    nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver_256);
    nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224, 0, 0, 2), 0);
    _nx_igmp_multicast_interface_join_internal(&ip_0, IP_ADDRESS(224, 0, 0, 2), 0, NX_FALSE);
    _nx_igmp_multicast_interface_join_internal(&ip_0, IP_ADDRESS(224, 0, 0, 2), 1, NX_FALSE);
    _nx_igmp_multicast_interface_join_internal(&ip_0, IP_ADDRESS(224, 0, 0, 3), 1, NX_FALSE);
    _nx_igmp_multicast_interface_join_internal(&ip_0, IP_ADDRESS(224, 0, 0, 3), 0, NX_FALSE);
    nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224, 0, 0, 2));
    nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224, 0, 0, 3));
    nx_ip_interface_detach(&ip_0, 1);



    /* Test _nx_igmp_multicast_interface_leave_internal  */
    /* Hit false condition of if (status == NX_SUCCESS) for _nx_packet_allocate.*/
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 2);
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_count = 1;
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time = 1;
    
    /* Record the packet available count.  */
    packet_available = pool_0.nx_packet_pool_available;

    /* Set the packet available count as 0.  */
    pool_0.nx_packet_pool_available = 0;

    /* Call function.  */
    _nx_igmp_multicast_interface_leave_internal(&ip_0, IP_ADDRESS(224, 0, 0, 2), 0);

    /* Recover the packet available count.  */
    pool_0.nx_packet_pool_available = packet_available;

    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;



    /* Test _nx_igmp_multicast_interface_leave_internal 
     173         [ -  + ]:         42 :                 if (ip_ptr -> nx_ip_igmp_router_version == NX_IGMP_HOST_VERSION_1)
     174                 :            :                 {
     177                 :          0 :                     tx_mutex_put(&(ip_ptr -> nx_ip_protection));
     180                 :          0 :                     return(NX_SUCCESS);
     181                 :            :                 }
    */
    ip_0.nx_ip_igmp_router_version = NX_IGMP_HOST_VERSION_1;
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 2);
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_count = 1;
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time = 1;

    /* Call function.  */
    _nx_igmp_multicast_interface_leave_internal(&ip_0, IP_ADDRESS(224, 0, 0, 2), 0);

    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;

    /* Revert the IGMP version */
    ip_0.nx_ip_igmp_router_version = NX_IGMP_HOST_VERSION_2;



    /* Test _nx_igmp_periodic_processing().  */

    /* Hit false condition of (ip_ptr -> nx_ipv4_multicast_entry[i].nx_ipv4_multicast_update_time != NX_WAIT_FOREVER).  */
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 2);
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time = NX_WAIT_FOREVER;
    _nx_igmp_periodic_processing(&ip_0);

    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;


    /* Hit false condition of if ((sent_count > 0) && (ip_ptr -> nx_ipv4_multicast_entry[i].nx_ipv4_multicast_update_time == 0)).  */
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 2);
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time = 1; 
    ip_0.nx_ipv4_multicast_entry[1].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 3);
    ip_0.nx_ipv4_multicast_entry[1].nx_ipv4_multicast_update_time = 2;
    _nx_igmp_periodic_processing(&ip_0);
    
    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0; 
    ip_0.nx_ipv4_multicast_entry[1].nx_ipv4_multicast_join_list = 0;


    /* Hit false condition of if ((ip_ptr -> nx_ipv4_multicast_entry[i].nx_ipv4_multicast_update_time == 0) && (sent_count == 0)).  */
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 2);
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time = 1; 
    ip_0.nx_ipv4_multicast_entry[1].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 3);
    ip_0.nx_ipv4_multicast_entry[1].nx_ipv4_multicast_update_time = 1;
    _nx_igmp_periodic_processing(&ip_0);
    
    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0; 
    ip_0.nx_ipv4_multicast_entry[1].nx_ipv4_multicast_join_list = 0;


    /* Hit false condition of if (status == NX_SUCCESS) for _nx_packet_allocate.  */
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 2);
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time = 1;
    
    /* Record the packet available count.  */
    packet_available = pool_0.nx_packet_pool_available;

    /* Set the packet available count as 0.  */
    pool_0.nx_packet_pool_available = 0;

    /* Call function.  */
    _nx_igmp_periodic_processing(&ip_0);

    /* Recover the packet available count.  */
    pool_0.nx_packet_pool_available = packet_available;

    /* Recover the multicast.  */
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;



    /* Test _nx_igmp_packet_process().  */

    /* Hit false condition of if (packet_ptr -> nx_packet_last) and if (checksum & NX_CARRY_BIT).  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x00; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0xFF;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0xFF;
    my_packet[0] -> nx_packet_prepend_ptr[8] = 0x2;
    my_packet[0] -> nx_packet_length = 9;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;
    _nx_igmp_packet_process(&ip_0, my_packet[0]);

#ifndef NX_DISABLE_PACKET_CHAIN
    /* Hit true condition
     *      172         [ -  + ]:          6 :             if (packet_ptr -> nx_packet_last) */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x00; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0xFF;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0xFF;
    my_packet[0] -> nx_packet_prepend_ptr[8] = 0x2;
    my_packet[0] -> nx_packet_length = 9;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;
    my_packet[0] -> nx_packet_last = my_packet[0];
    _nx_igmp_packet_process(&ip_0, my_packet[0]);
#endif /* NX_DISABLE_PACKET_CHAIN */

    /* Hit false condition of if ((update_time > max_update_time) || (update_time == 0)).  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x01; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0x1E;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0x04;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0xE0;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0xFB;
    my_packet[0] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;
    _tx_timer_system_clock = 1;
    _nx_igmp_packet_process(&ip_0, my_packet[0]);
                                              
    /* Hit false condition of if ((update_time > max_update_time) || (update_time == 0)).  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x01; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0x1E;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0x04;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0xE0;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0xFB;
    my_packet[0] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;
    _tx_timer_system_clock = 0;
    _nx_igmp_packet_process(&ip_0, my_packet[0]);

    /* Hit false condition of (header_ptr -> nx_igmp_header_word_1 != NX_NULL)) and (ip_ptr -> nx_ipv4_multicast_entry[i].nx_ipv4_multicast_update_time == NX_WAIT_FOREVER).  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x01; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0xFE;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0xFF;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0x00;
    my_packet[0] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;     
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 251);
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    _nx_igmp_packet_process(&ip_0, my_packet[0]);

    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;

    /* Hit true condition of (header_ptr -> nx_igmp_header_word_1 != NX_NULL)) and (ip_ptr -> nx_ipv4_multicast_entry[i].nx_ipv4_multicast_update_time == NX_WAIT_FOREVER).  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x01; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0xFE;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0xFF;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0x00;
    my_packet[0] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;     
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 251); 
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time  = NX_WAIT_FOREVER;
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    _nx_igmp_packet_process(&ip_0, my_packet[0]);

    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;

    /* Hit false condition of (header_ptr -> nx_igmp_header_word_0 & NX_IGMP_TYPE_MASK) == NX_IGMP_HOST_RESPONSE_TYPE).  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x17; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0x08;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0x04;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0xE0;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0xFB;
    my_packet[0] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;     
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 251);
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    _nx_igmp_packet_process(&ip_0, my_packet[0]);

    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;


    /* Hit false condition of for (i = 0; i < NX_MAX_MULTICAST_GROUPS; i++)  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x16; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0x09;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0x04;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0xE0;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0xFB;
    my_packet[0] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;     
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    _nx_igmp_packet_process(&ip_0, my_packet[0]);
    
    /* Hit false condition of for (i = 0; i < NX_MAX_MULTICAST_GROUPS; i++)  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x16; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0x09;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0x04;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0xE0;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0xFB;
    my_packet[0] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;     
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 251);;
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time = NX_WAIT_FOREVER;
    _nx_igmp_packet_process(&ip_0, my_packet[0]);

    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;

    /* Hit false condition :
       else if (((header_ptr -> nx_igmp_header_word_0 & NX_IGMP_TYPE_MASK) == NX_IGMP_HOST_RESPONSE_TYPE)
    */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x14; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0x0b;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0x04;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0xE0;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0xFB;
    my_packet[0] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;     
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 251);;
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time = NX_WAIT_FOREVER;
    _nx_igmp_packet_process(&ip_0, my_packet[0]);

    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;

    /* Hit false condition :
       else if (((header_ptr -> nx_igmp_header_word_0 & NX_IGMP_TYPE_MASK) == NX_IGMP_HOST_RESPONSE_TYPE)
    */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_prepend_ptr[0] = 0x12; 
    my_packet[0] -> nx_packet_prepend_ptr[1] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[2] = 0x0d;
    my_packet[0] -> nx_packet_prepend_ptr[3] = 0x04;
    my_packet[0] -> nx_packet_prepend_ptr[4] = 0xE0;
    my_packet[0] -> nx_packet_prepend_ptr[5] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[6] = 0x00;
    my_packet[0] -> nx_packet_prepend_ptr[7] = 0xFB;
    my_packet[0] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + my_packet[0] -> nx_packet_length;     
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = IP_ADDRESS(224, 0, 0, 251);;
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list = &ip_0.nx_ip_interface[0];
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_update_time = NX_WAIT_FOREVER;
    _nx_igmp_packet_process(&ip_0, my_packet[0]);

    /* Recover the multicast.  */    
    ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list = 0;
#endif /* __PRODUCT_NETXDUO__  */


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
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_igmp_branch_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Branch Test..........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
