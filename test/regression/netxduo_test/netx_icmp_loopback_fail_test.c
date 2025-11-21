/* This NetX test concentrates on the ICMP ping through loopback interface.  */

#include   "nx_api.h"

extern void  test_control_return(UINT status);
#if !defined(NX_DISABLE_LOOPBACK_INTERFACE) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
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
void    netx_icmp_loopback_fail_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 4096);
    pointer = pointer + 4096;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for IP_0.  */
    status =  nx_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *first_packet;  
NX_PACKET  *second_packet;  

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Loopback Fail Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Make sure only two packets are available in the pool. */
    if (pool_0.nx_packet_pool_available != 2)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping IPv4 loopback address.  */
    status =  nx_icmp_ping(&ip_0, NX_IP_LOOPBACK_FIRST + 1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &first_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (first_packet == NX_NULL) || (first_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Make sure only one packet is available in the pool since first_packet is not released. */
    /* Now ping IPv4 loopback address.  */
    status =  nx_icmp_ping(&ip_0, NX_IP_LOOPBACK_FIRST + 1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &second_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_IP_INFO
    if (ip_0.nx_ip_send_packets_dropped != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_IP_INFO */
         
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_loopback_fail_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   ICMP Loopback Fail Test...................................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_LOOPBACK_INTERFACE */
