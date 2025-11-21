/* This NetX test concentrates on the ICMP ping multicast operation.  */

#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__)  && !defined(NX_ENABLE_ICMP_ADDRESS_CHECK) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
#ifndef NX_DISABLE_FRAGMENTATION
static CHAR                    msg[300];
#endif /* NX_DISABLE_FRAGMENTATION */


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping_multicast_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 10240);
    pointer = pointer + 10240;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
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



static void    ntest_0_entry(ULONG thread_input)
{
UINT        status;
NX_PACKET  *my_packet;  
    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Ping Multicast Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Now send a ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 255), "Test", 4, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Release the packet. */
    nx_packet_release(my_packet);


#ifndef NX_DISABLE_FRAGMENTATION
    /* Now send a large ping with fragment disabled. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 255), msg, sizeof(msg), &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_NO_RESPONSE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               


    /* Enable IP fragment for both IP instances.  */
    status = nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check IP fragment enable status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Now send a large ping with fragment enabled.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 255), msg, sizeof(msg), &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Release the packet. */
    nx_packet_release(my_packet);
#endif /* NX_DISABLE_FRAGMENTATION */

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping_multicast_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   ICMP Ping Fragment Test...................................N/A\n");
    test_control_return(3);
}
#endif 
