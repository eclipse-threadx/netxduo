/* This NetX test concentrates on route reachable.  */

#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_route_reachable_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

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
    if (status)
        error_counter++;

    /* Enable ICMP processing.  */
    status =  nx_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *packet_ptr;  

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Route Reachable Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Setup gateway. */
    status = nx_ip_gateway_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 1));

    if (status)
        error_counter++;

#ifdef NX_ENABLE_IP_STATIC_ROUTING
    /* Add static routing. */
    status = nx_ip_static_route_add(&ip_0, IP_ADDRESS(3, 2, 3, 0), 0xFFFFFF00, IP_ADDRESS(1, 2, 3, 2));

    if (status)
        error_counter++;
#endif /* NX_ENABLE_IP_STATIC_ROUTING */

    /* Now ping out of network address through gateway without waiting. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 1), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &packet_ptr, NX_NO_WAIT);

    if (status != NX_NO_RESPONSE)
        error_counter++;

#ifdef NX_ENABLE_IP_STATIC_ROUTING
    /* Now ping out of network address through static route without waiting. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(3, 2, 3, 1), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &packet_ptr, NX_NO_WAIT);

    if (status != NX_NO_RESPONSE)
        error_counter++;
#endif /* NX_ENABLE_IP_STATIC_ROUTING */

    /* Now set the address to other network.  */
    status  = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 3, 3, 4), 0xFFFFFF00);

    if (status)
        error_counter++;

    /* Now ping out of network address through gateway without waiting. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 1), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &packet_ptr, NX_NO_WAIT);

    if (status != NX_IP_ADDRESS_ERROR)
        error_counter++;

#ifdef NX_ENABLE_IP_STATIC_ROUTING
    /* Now ping out of network address through static route without waiting. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(3, 2, 3, 1), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &packet_ptr, NX_NO_WAIT);

    if (status != NX_IP_ADDRESS_ERROR)
        error_counter++;
#endif /* NX_ENABLE_IP_STATIC_ROUTING */

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
void    netx_ip_route_reachable_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Route Reachable Test...................................N/A\n");

    test_control_return(3);

}
#endif /* __PRODUCT_NETXDUO__ */
