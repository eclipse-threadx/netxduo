/* This NetX test concentrates on the code coverage for ICMP functions,
 * _nx_icmp_packet_receive.c
 * _nx_icmp_cleanup.c
 */

#include "nx_icmp.h"
#include "nx_api.h"
#include "tx_thread.h"
#include "nx_ip.h"

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
static VOID    suspend_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_branch_test_application_define(void *first_unused_memory)
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

    /* Enable ICMP processing for IP instance.  */
    status = nx_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

#ifndef NX_ENABLE_ICMP_ADDRESS_CHECK
ULONG           system_state;
#endif /* NX_ENABLE_ICMP_ADDRESS_CHECK */
#if !defined(NX_ENABLE_ICMP_ADDRESS_CHECK) || defined(__PRODUCT_NETXDUO__)
NX_PACKET      *my_packet[2];
#endif /* !defined(NX_ENABLE_ICMP_ADDRESS_CHECK) || defined(__PRODUCT_NETXDUO__) */
#ifdef __PRODUCT_NETXDUO__
NX_IPV4_HEADER *ip_header_ptr;
#endif /* __PRODUCT_NETXDUO__ */

    /* Print out some test information banners.  */
    printf("NetX Test:   ICMP Branch Test..........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }



#ifndef NX_ENABLE_ICMP_ADDRESS_CHECK
    /* Hit condition of if ((_tx_thread_system_state) || (&(ip_ptr -> nx_ip_thread) != _tx_thread_current_ptr)) in _nx_icmp_packet_receive().  */
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_data_append(my_packet[0], "abcdefghijklmnopqrstuvwxyz", 26, &pool_0, NX_NO_WAIT);

    system_state = _tx_thread_system_state;
    _tx_thread_system_state = 0;

    _nx_icmp_packet_receive(&ip_0, my_packet[0]);
    ip_0.nx_ip_icmp_queue_head =  NX_NULL;

    _tx_thread_system_state = system_state;
    nx_packet_release(my_packet[0]);

    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_data_append(my_packet[0], "abcdefghijklmnopqrstuvwxyz", 26, &pool_0, NX_NO_WAIT);
    system_state = _tx_thread_system_state;
    _tx_thread_system_state = 1;

    _nx_icmp_packet_receive(&ip_0, my_packet[0]);
    ip_0.nx_ip_icmp_queue_head =  NX_NULL;

    _tx_thread_system_state = system_state;
    nx_packet_release(my_packet[0]);
    tx_mutex_put(&(ip_0.nx_ip_protection));
#endif /* NX_ENABLE_ICMP_ADDRESS_CHECK */


    /* Test _nx_icmp_cleanup().  */
    /* tx_thread_suspend_control_block is set to NULL. */
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    _nx_icmp_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* tx_thread_suspend_control_block is set to IP but tx_thread_suspend_cleanup is set to NULL. */
    tx_thread_identify() -> tx_thread_suspend_control_block = &ip_0;
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    _nx_icmp_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* tx_thread_suspend_control_block is set to IP and tx_thread_suspend_cleanup is set to suspend_cleanup, but clear the IP ID. */
    tx_thread_identify() -> tx_thread_suspend_control_block = &ip_0;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    ip_0.nx_ip_id = 0;
    _nx_icmp_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    ip_0.nx_ip_id = NX_IP_ID;


#ifdef __PRODUCT_NETXDUO__
    /* Test _nx_icmpv4_send_error_message(). */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr;
    ip_header_ptr = (NX_IPV4_HEADER *)(my_packet[0] -> nx_packet_prepend_ptr);
    ip_header_ptr -> nx_ip_header_destination_ip = IP_ADDRESS(224, 0, 0, 1);
    _nx_icmpv4_send_error_message(&ip_0, my_packet[0], 0, 0);
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &(ip_0.nx_ip_interface[0]);
    ip_header_ptr -> nx_ip_header_word_1 = NX_IP_OFFSET_MASK;
    ip_header_ptr -> nx_ip_header_destination_ip = IP_ADDRESS(2, 2, 3, 0);
    _nx_icmpv4_send_error_message(&ip_0, my_packet[0], 0, 0);
    ip_header_ptr -> nx_ip_header_word_1 = 0;
    ip_header_ptr -> nx_ip_header_destination_ip = IP_ADDRESS(1, 2, 3, 6);
    ip_header_ptr -> nx_ip_header_source_ip = IP_ADDRESS(0, 0, 0, 0);
    _nx_icmpv4_send_error_message(&ip_0, my_packet[0], 0, 0);
    ip_header_ptr -> nx_ip_header_source_ip = IP_ADDRESS(0, 0, 0, 0);
    _nx_icmpv4_send_error_message(&ip_0, my_packet[0], 0, 0);
    ip_header_ptr -> nx_ip_header_source_ip = NX_IP_LOOPBACK_LAST;
    _nx_icmpv4_send_error_message(&ip_0, my_packet[0], 0, 0);
    ip_header_ptr -> nx_ip_header_source_ip = NX_IP_LIMITED_BROADCAST;
    _nx_icmpv4_send_error_message(&ip_0, my_packet[0], 0, 0);
    nx_packet_release(my_packet[0]);
#endif /* __PRODUCT_NETXDUO__ */

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

static VOID    suspend_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER)
{
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_branch_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Branch Test..........................................N/A\n"); 

    test_control_return(3);  
}      
#endif

