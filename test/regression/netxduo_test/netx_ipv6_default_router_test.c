/* This NetX test concentrates on the IPv6 default router.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV6_DAD)
#include    "nx_ip.h"
#include    "nx_ipv6.h"
#include    "nx_nd_cache.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
static NXD_ADDRESS             ipv6_address_3;
static NXD_ADDRESS             ipv6_address_4;
static NXD_ADDRESS             ipv6_multicast;



/* Define the counters used in the test application...  */
static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_default_router_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, 
                          &pool_0, _nx_ram_network_driver_512, pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Set the second interface.  */
    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 
                                     0xFFFFFF00UL, _nx_ram_network_driver_512);
    if (status)
        error_counter++;

    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_2.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_2.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_2.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[3] = 0x10000002;

    ipv6_address_3.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_3.nxd_ip_address.v6[0] = 0x30010000;
    ipv6_address_3.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_3.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_3.nxd_ip_address.v6[3] = 0x10000003;

    ipv6_address_4.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_4.nxd_ip_address.v6[0] = 0x40010000;
    ipv6_address_4.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_4.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_4.nxd_ip_address.v6[3] = 0x10000003;

    ipv6_multicast.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_multicast.nxd_ip_address.v6[0] = 0xFF020000;
    ipv6_multicast.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_multicast.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_multicast.nxd_ip_address.v6[3] = 0x00000001;

    /* Check ipv6 address set status.  */
    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);

    /* Enable ICMP processing for both IP instances.  */
    status += nxd_icmp_enable(&ip_0);

    /* Check enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT             status = 0;
NX_PACKET       *my_packet;
NXD_IPV6_ADDRESS *ipv6_address;
CHAR             mac_address[6];
ND_CACHE_ENTRY  *nd_cache_entry;

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Default Router Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Set default router to primary interface before setting IPv6 address. */
    status = nxd_ipv6_default_router_add(&ip_0, &ipv6_address_1, 60, 0);

    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set IPv6 address. */
    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_2, 64, NX_NULL);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set multicast address default router to primary interface. */
    status = nxd_ipv6_default_router_add(&ip_0, &ipv6_multicast, 60, 0);

    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set default router to primary interface. */
    status = nxd_ipv6_default_router_add(&ip_0, &ipv6_address_1, 60, 0);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set default router to an address which isn't on link. */
    status = nxd_ipv6_default_router_add(&ip_0, &ipv6_address_3, 60, 0);

    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Try to send a ping. */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_3, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_NO_WAIT);

    /* Since the state of address is tentative, no interface can be found. */
    if(status != NX_NO_INTERFACE_ADDRESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set IPv6 address. */
    status = nxd_ipv6_address_set(&ip_0, 1, &ipv6_address_4, 64, NX_NULL);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let DAD finishes. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Try to send a ping. */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_3, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_NO_WAIT);

    /* Router is found. Since it doesn't wait, the result is no response. */
    if(status != NX_NO_RESPONSE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* The interface index of default router is 0. */
    /* Outgoing interface should be found. */
    status = _nxd_ipv6_interface_find(&ip_0, ipv6_address_3.nxd_ip_address.v6, &ipv6_address,
                                      &ip_0.nx_ip_interface[0]);

    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Outgoing interface should not be found. */
    status = _nxd_ipv6_interface_find(&ip_0, ipv6_address_3.nxd_ip_address.v6, &ipv6_address,
                                      &ip_0.nx_ip_interface[1]);

    if (status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the link. */
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_FALSE;

    /* Try to send a ping. */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_3, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_NO_WAIT);

    /* Since the link is down, no interface can be found. */
    if(status != NX_NO_INTERFACE_ADDRESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the link. */
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;


    /* Added the ND Cache entry.  */
    mac_address[0] = 0x11;
    mac_address[1] = 0x11;
    mac_address[2] = 0x22;
    mac_address[3] = 0x33;
    mac_address[4] = 0x44;
    mac_address[5] = 0x57;

    /* Call the function to added the same entry.  */
    status = _nx_nd_cache_add(&ip_0, &ipv6_address_1.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_REACHABLE, &ip_0.nx_ipv6_address[0], &nd_cache_entry);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Try to send a ping. */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_3, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_NO_WAIT);

    /* Since the link is down, no interface can be found. */
    if(status != NX_NO_RESPONSE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    printf("SUCCESS!\n");
    test_control_return(0);


}
#else 

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_default_router_test_application_define(void *first_unused_memory)
#endif
{   

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Default Router Test..................................N/A\n");

    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
