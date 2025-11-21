/* This NetX test concentrates on the IP Interface Address Set  operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void  test_control_return(UINT status);

#if (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
VOID    ip_address_change_notify(NX_IP *ip_ptr, VOID *additional_info);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_interface_address_set_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
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

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 14), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 15), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)    

        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       address;
ULONG       mask;
NX_PACKET   *my_packet;
ULONG       pings_sent;
ULONG       ping_timeouts;
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Interface Address Set Test.............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 110), 0xFF000000, _nx_ram_network_driver_1500);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   

#ifdef __PRODUCT_NETXDUO__
    /* Attach the same address to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 110), 0xFF000000, _nx_ram_network_driver_1500);
    if(status != NX_DUPLICATED_ENTRY)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Attach the 2nd interface to IP instance1 */
    status = nx_ip_interface_attach(&ip_1, "2nd interface", IP_ADDRESS(4, 3, 2, 111), 0xFF000000, _nx_ram_network_driver_1500);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Make sure we can ping using the current IP address. */
    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(4, 3, 2, 91), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping an IP address that does exist.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(4, 3, 2, 110), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* It should also be able to ping an IP address that is accessible via the primary interface. */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(1, 2, 3, 14), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Ping via the other direction. */
    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 9), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping an IP address that does exist.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 111), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* It should also be able to ping an IP address that is accessible via the primary interface. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 15), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
    
#ifndef NX_DISABLE_ICMP_INFO

    if ((pings_sent != 3) || (ping_timeouts != 1) || (ping_responses_received != 2) ||(icmp_checksum_errors) || (icmp_unhandled_messages))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (ping_threads_suspended))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_1, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
    
#ifndef NX_DISABLE_ICMP_INFO

    if ((pings_sent != 3) || (ping_timeouts != 1) || (ping_responses_received != 2) ||(icmp_checksum_errors) || (icmp_unhandled_messages))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (ping_threads_suspended))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Reconfigure the interface IP addresses. */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00);
    
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_address_set(&ip_0, 1, IP_ADDRESS(4, 3, 2, 10), 0xFFFFFF00);
    
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nx_ip_interface_address_set(&ip_0, 2, IP_ADDRESS(4, 3, 2, 15), 0xFFFFF000);
    
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING  */

    status = nx_ip_interface_address_set(&ip_1, 0, IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00);
    
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_address_set(&ip_1, 1, IP_ADDRESS(4, 3, 2, 11), 0xFFFFFF00);
    
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nx_ip_interface_address_set(&ip_1, 2, IP_ADDRESS(4, 3, 2, 15), 0xFFFFF000);
    
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING  */

        
    /* Make sure we can ping via the new interface IP address. */
    /* Make sure we can ping using the current IP address. */
    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(4, 3, 2, 91), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping an IP address that does exist.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(4, 3, 2, 10), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* It should also be able to ping an IP address that is accessible via the primary interface. */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Ping via the other direction. */
    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 9), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping an IP address that does exist.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 11), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* It should also be able to ping an IP address that is accessible via the primary interface. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
    
#ifndef NX_DISABLE_ICMP_INFO

    if ((pings_sent != 6) || (ping_timeouts != 2) || (ping_responses_received != 4) ||(icmp_checksum_errors) || (icmp_unhandled_messages))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (ping_threads_suspended))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_1, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
    
#ifndef NX_DISABLE_ICMP_INFO

    if ((pings_sent != 6) || (ping_timeouts != 2) || (ping_responses_received != 4) ||(icmp_checksum_errors) || (icmp_unhandled_messages))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (ping_threads_suspended))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    status = nx_ip_interface_address_get(&ip_0, 0, &address, &mask);

    if((status != NX_SUCCESS) || (address != IP_ADDRESS(1, 2, 3, 4)) || (mask != 0xFFFFFF00))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    status = nx_ip_interface_address_get(&ip_0, 1, &address, &mask);

    if((status != NX_SUCCESS) || (address != IP_ADDRESS(4, 3, 2, 10)) || (mask != 0xFFFFFF00))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nx_ip_interface_address_get(&ip_0, 2, &address, &mask);

    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING  */

    status = nx_ip_interface_address_get(&ip_1, 0, &address, &mask);

    if((status != NX_SUCCESS) || (address != IP_ADDRESS(1, 2, 3, 5)) || (mask != 0xFFFFFF00))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_address_get(&ip_1, 1, &address, &mask);

    if((status != NX_SUCCESS ) || (address != IP_ADDRESS(4, 3, 2, 11)) || (mask != 0xFFFFFF00))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nx_ip_interface_address_get(&ip_1, 2, &address, &mask);

    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING  */

    /* Test the condition for network mask if ((address_change_notify) && ((ip_address != previous_ip_address) || (network_mask != previous_network_mask)) in _nx_ip_interface_address_set.
       Same network mask.  */
    status = nx_ip_address_change_notify(&ip_0, ip_address_change_notify, NX_NULL);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test the condition for network mask if ((address_change_notify) && ((ip_address != previous_ip_address) || (network_mask != previous_network_mask)) in _nx_ip_interface_address_set.
       Different network mask.  */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 2, 3, 4), 0xFFFF0000);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test the condition for network mask if ((address_change_notify) && ((ip_address != previous_ip_address) || (network_mask != previous_network_mask)) in _nx_ip_interface_address_set.
       Same network mask.  */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 2, 3, 39), 0xFFFFFF00);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test the condition for network mask if ((address_change_notify) && ((ip_address != previous_ip_address) || (network_mask != previous_network_mask)) in _nx_ip_interface_address_set.
       Different network mask.  */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 2, 3, 40), 0xFFFF0000);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);

}
    
VOID    ip_address_change_notify(NX_IP *ip_ptr, VOID *additional_info)
{
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_interface_address_set_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Interface Address Set Test.............................N/A\n");
    test_control_return(3);
}
#endif
