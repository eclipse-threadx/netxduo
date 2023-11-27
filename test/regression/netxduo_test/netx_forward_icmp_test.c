/* This NetX test concentrates on the ICMP ping operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_IP                   ip_2;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_icmp_ping_test_application_define(void *first_unused_memory)
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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an forward IP Instance 0.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;    
    if (status)
        error_counter++;

    /* Set the second interface for forward IP Instance 0.  */
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_1500);    
    if (status)
        error_counter++;

    /* Create an IP Instance 1.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 1.  */
    status = nx_ip_gateway_address_set(&ip_1, IP_ADDRESS(1, 2, 3, 4));
    if (status)
        error_counter++;

    /* Create another IP Instance 2.  */
    status = nx_ip_create(&ip_2, "NetX IP Instance 1", IP_ADDRESS(2, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 2.  */
    status = nx_ip_gateway_address_set(&ip_2, IP_ADDRESS(2, 2, 3, 4));
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
    
    /* Enable ARP and supply ARP cache memory for IP Instance 2.  */
    status = nx_arp_enable(&ip_2, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for both IP Instance 0.  */
    status = nx_icmp_enable(&ip_0);
    if (status)
        error_counter++;
    
    /* Enable ICMP processing for both IP Instance 1.  */
    status = nx_icmp_enable(&ip_1);
    if (status)
        error_counter++;
    
    /* Enable ICMP processing for both IP Instance 2.  */
    status = nx_icmp_enable(&ip_2);
    if (status)
        error_counter++;

    /* Enable the forwarding function for IP Instance 0.  */
    status = nx_ip_forwarding_enable(&ip_0);
    if (status)
        error_counter++;

}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
ULONG       pings_sent;
ULONG       ping_timeouts;
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages;

    
    /* Print out test information banner.  */
    printf("NetX Test:   Forward ICMP Processing Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Now ip_0 ping ip_1.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 1) || (ping_responses_received != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    
    /* Now ip_0 ping ip_2.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 2) || (ping_responses_received != 2))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    /* Enable all TX checksum capability. */
    nx_ip_interface_capability_set(&ip_0, 0, NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM | 
                                             NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM |
                                             NX_INTERFACE_CAPABILITY_UDP_TX_CHECKSUM |
                                             NX_INTERFACE_CAPABILITY_ICMPV4_TX_CHECKSUM |
                                             NX_INTERFACE_CAPABILITY_ICMPV6_TX_CHECKSUM |
                                             NX_INTERFACE_CAPABILITY_IGMP_TX_CHECKSUM);
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

    /* Now ip_1 ping an one address of ip_0.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_1, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 1) || (ping_responses_received != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    
    /* Now ip_1 ping an other address of ip_0.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(2, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_1, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 2) || (ping_responses_received != 2))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    
    /* Now ip_1 ping ip_2.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_1, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 3) || (ping_responses_received != 3))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    /* Disable all interface capability. */
    nx_ip_interface_capability_set(&ip_0, 0, 0);
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

    /* Now ip_2 ping an one address of ip_0.  */
    status =  nx_icmp_ping(&ip_2, IP_ADDRESS(2, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_2, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 1) || (ping_responses_received != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    
    /* Now ip_2 ping an other address of ip_0.  */
    status =  nx_icmp_ping(&ip_2, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_2, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 2) || (ping_responses_received != 2))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    
    /* Now ip_2 ping ip_1.  */
    status =  nx_icmp_ping(&ip_2, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_2, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 3) || (ping_responses_received != 3))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
         
    /* Now ip_1 ping the address that does not exist.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(3, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
   
    if (status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }      
        
    /* Determine if the timeout error occurred.  */
    if ((ping_threads_suspended) || (icmp_checksum_errors) || (icmp_unhandled_messages))
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

extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_icmp_ping_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Forward ICMP Processing Test..............................N/A\n");
    test_control_return(3);
}
#endif
