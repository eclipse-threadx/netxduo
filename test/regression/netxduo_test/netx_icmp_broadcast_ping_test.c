/* This NetX test concentrates on the ICMP ping operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"

extern void    test_control_return(UINT status);
#if !defined(NX_DISABLE_IPV4)
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
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_broadcast_ping_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 4096);
    pointer = pointer + 4096;

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



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Broadcast Ping Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an subnet-directed broadcast.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 255), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

#ifdef NX_ENABLE_ICMP_ADDRESS_CHECK

    /* Check the status.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#else

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Ping an limited broadcast.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(255, 255, 255, 255), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

#ifdef NX_ENABLE_ICMP_ADDRESS_CHECK

    /* Check the status.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#else

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Enable IGMP feature.  */
    status = nx_igmp_enable(&ip_0);  
    status += nx_igmp_enable(&ip_1);

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Join in multicast group.  */
    status = nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224, 0, 0, 251));
    status += nx_igmp_multicast_join(&ip_1, IP_ADDRESS(224, 0, 0, 251));

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an multicast.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(224, 0, 0, 251), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

#ifdef NX_ENABLE_ICMP_ADDRESS_CHECK

    /* Check the status.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#else

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_broadcast_ping_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Broadcast Ping Test..................................N/A\n");

    test_control_return(3);  
}      
#endif
