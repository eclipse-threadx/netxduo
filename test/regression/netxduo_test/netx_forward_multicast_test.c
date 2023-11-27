/* This NetX test concentrates on the multicast forward. 
 * Multicast packet must not be forward. */

#include   "tx_api.h"
#include   "nx_api.h"

#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_ICMP_INFO)

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
void    netx_forward_multicast_test_application_define(void *first_unused_memory)
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
NX_IP_DRIVER  driver_request;

    
    /* Print out test information banner.  */
    printf("NetX Test:   Forward multicast Test....................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register the new multicast group with the underlying driver to
       ensure that there is room for the new group at the hardware level.  */
    driver_request.nx_ip_driver_ptr                  =   &ip_0;
    driver_request.nx_ip_driver_command              =   NX_LINK_MULTICAST_JOIN;
    driver_request.nx_ip_driver_physical_address_msw =   NX_IP_MULTICAST_UPPER;
    driver_request.nx_ip_driver_physical_address_lsw =   NX_IP_MULTICAST_LOWER | (IP_ADDRESS(224, 0, 0, 2) & NX_IP_MULTICAST_MASK);
    driver_request.nx_ip_driver_interface            =   &ip_0.nx_ip_interface[0];
    (ip_0.nx_ip_interface[0].nx_interface_link_driver_entry)(&driver_request);
    
    /* Now ip_1 ping multicast address.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(224, 0, 0, 2), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* No response is expected. */
    if (status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
    if ((status != NX_SUCCESS) || (ping_timeouts != 0) || (pings_sent != 0) || (ping_responses_received != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_icmp_info_get(&ip_1, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
    if ((status != NX_SUCCESS) || (ping_timeouts != 1) || (pings_sent != 1) || (ping_responses_received != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_icmp_info_get(&ip_2, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
    if ((status != NX_SUCCESS) || (ping_timeouts != 0) || (pings_sent != 0) || (ping_responses_received != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else

extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_multicast_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Forward multicast Test....................................N/A\n");
    test_control_return(3);
}
#endif
