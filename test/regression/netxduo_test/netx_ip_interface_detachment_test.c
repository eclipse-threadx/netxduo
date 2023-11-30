

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

#ifdef FEATURE_NX_IPV6                   
static NXD_ADDRESS             ipv6_address;
static NXD_ADDRESS             router_address;
#endif

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static TX_MUTEX                mutex_0;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_detachment_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main threads.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
            pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
            pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Attach the 2nd interface to IP instance1 */
    status = nx_ip_interface_attach(&ip_1, "2nd interface", IP_ADDRESS(4, 3, 2, 11), 0xFF000000, _nx_ram_network_driver);
    if(status != NX_SUCCESS)
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
                      
#ifdef NX_ENABLE_IP_STATIC_ROUTING
    status = nx_ip_static_route_add(&ip_1, IP_ADDRESS(4, 3, 2, 1), 0xFFFFFF00UL, IP_ADDRESS(4, 3, 2, 10));   

    /* Check status.  */
    if (status)
        error_counter++;

#endif /* NX_ENABLE_IP_STATIC_ROUTING  */

#ifdef FEATURE_NX_IPV6      
    /* Set ipv6 version and address.  */
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[3] = 0x10000001;
                                                          
    /* Set interfaces' address */
    status = nxd_ipv6_address_set(&ip_1, 0, &ipv6_address, 64, NX_NULL);

    if(status)
        error_counter++;

    /* Set ipv6 version and address.  */
    router_address.nxd_ip_version = NX_IP_VERSION_V6;
    router_address.nxd_ip_address.v6[0] = 0x20010000;
    router_address.nxd_ip_address.v6[1] = 0x00000000;
    router_address.nxd_ip_address.v6[2] = 0x00000000;
    router_address.nxd_ip_address.v6[3] = 0x10000002;
    
    /* Add the default router.  */
    status = nxd_ipv6_default_router_add(&ip_1, &router_address, 1500, 0);
    
    /* Check status.  */
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6  */
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
    printf("NetX Test:   IP Interface Detachment Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_mutex_create(&mutex_0, "mutex_0", TX_NO_INHERIT);

    tx_mutex_get(&mutex_0, TX_WAIT_FOREVER);

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

    /* Let ntest_1 detach the 2nd interface(4.3.2.11) from IP instance1. */
    tx_mutex_put(&mutex_0);
    tx_thread_sleep(1);
    tx_mutex_get(&mutex_0, TX_WAIT_FOREVER);

     /* Now ping an IP address that has been detached. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 11), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* It should be able to ping an IP address that is accessible via the primary interface. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let ntest_1 attach the interface(4.3.2.11) removed before, then detach the 1st interface(1.2.3.5) to IP instance1. */
    tx_mutex_put(&mutex_0);
    tx_thread_sleep(1);
    tx_mutex_get(&mutex_0, TX_WAIT_FOREVER);

     /* Now ping an IP address that has been detached. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 11), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
     if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* It should be able to ping an IP address that is accessible via the primary interface. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
   

    tx_mutex_delete(&mutex_0);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);

#ifndef NX_DISABLE_ICMP_INFO

    if ((pings_sent != 7) || (ping_timeouts != 3) || (ping_responses_received != 4) || (icmp_checksum_errors) || (icmp_unhandled_messages))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    if(error_counter)
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

static void    ntest_1_entry(ULONG thread_input)
{

UINT    status;

    tx_mutex_get(&mutex_0, TX_WAIT_FOREVER);

    /* Detach the 2nd interface(4.3.2.11) from IP instance1. */
    status = nx_ip_interface_detach(&ip_1, 1);
    if(status)
        error_counter++;

    tx_mutex_put(&mutex_0);
    tx_thread_sleep(1);
    tx_mutex_get(&mutex_0, TX_WAIT_FOREVER);
    
    /* Attach the 2nd interface(4.3.2.11) removed before to IP instance1. */
    status = nx_ip_interface_attach(&ip_1, "2nd interface", IP_ADDRESS(4, 3, 2, 11), 0xFF000000, _nx_ram_network_driver);

    /* Detach the 1st interface(1.2.3.5)from IP instance1. */
    status += nx_ip_interface_detach(&ip_1, 0);

    if(status)
        error_counter++;

    tx_mutex_put(&mutex_0);
    
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_detachment_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Interface Detachment Test..............................N/A\n");
    test_control_return(3);
}
#endif
