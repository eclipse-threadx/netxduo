/* This NetX test concentrates on the ICMP ping through loopback interface.  */

#include   "nx_api.h"

extern void  test_control_return(UINT status);
#if !defined(NX_DISABLE_LOOPBACK_INTERFACE) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

static NXD_ADDRESS             address_lo;
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
#endif /* FEATURE_NX_IPV6 */

/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_loopback_test_application_define(void *first_unused_memory)
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

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nxd_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 traffic.  */
    status = nxd_ipv6_enable(&ip_0);

    /* Set global address. */    
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010DB8;
    address_0.nxd_ip_address.v6[1] = 0x00010001;
    address_0.nxd_ip_address.v6[2] = 0x021122FF;
    address_0.nxd_ip_address.v6[3] = 0xFE334456;

    status += nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);

    /* Check for errors.  */
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */

    /* Set loopback address. */    
    address_lo.nxd_ip_version = NX_IP_VERSION_V4;
    address_lo.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;  

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Loopback Test........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping IPv4 loopback address.  */
    status =  nxd_icmp_source_ping(&ip_0, &address_lo, NX_LOOPBACK_INTERFACE, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
         
#ifdef FEATURE_NX_IPV6               
    /* Wait for DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Now ping IPv6 address through loopback interface.  */
    status =  nxd_icmp_source_ping(&ip_0, &address_0, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
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
void    netx_icmp_loopback_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   ICMP Loopback Test........................................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_LOOPBACK_INTERFACE */
