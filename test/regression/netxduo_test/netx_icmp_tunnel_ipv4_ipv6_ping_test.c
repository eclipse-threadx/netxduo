/* This NetX test concentrates on the ICMP ping operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);
#if defined(FEATURE_NX_IPV6) && defined(NX_TUNNEL_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nx_ipv6.h"
#include   "nx_tunnel.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


NXD_ADDRESS                    ipv6_address_1;
NXD_ADDRESS                    ipv6_address_2;
NXD_ADDRESS                    ipv6_address_3;
NXD_ADDRESS                    ipv6_address_4;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static NX_ADDRESS_SELECTOR     address_selector_0;
static NX_ADDRESS_SELECTOR     address_selector_1;
static NX_TUNNEL               tunnel_0;
static NX_TUNNEL               tunnel_1;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping_tunnel_ipv4_ipv6_test_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status += nx_ip_interface_attach(&ip_0,"Second Interface",IP_ADDRESS(2,2,3,4),0xFFFFFF00UL,  _nx_ram_network_driver_256);
    status += nx_ip_interface_attach(&ip_1,"Second Interface",IP_ADDRESS(2,2,3,5),0xFFFFFF00UL,  _nx_ram_network_driver_256);

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
    ipv6_address_3.nxd_ip_address.v6[3] = 0x20000003;

    ipv6_address_4.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_4.nxd_ip_address.v6[0] = 0x30010000;
    ipv6_address_4.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_4.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_4.nxd_ip_address.v6[3] = 0x20000004;

    status += nxd_ipv6_address_set(&ip_0, 1, &ipv6_address_3, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 1, &ipv6_address_4, 64, NX_NULL);

    if (status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status = nxd_ipv6_enable(&ip_1);

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
    status =  nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    status = nx_tunnel_enable(&ip_0);
    status += nx_tunnel_enable(&ip_1);

    /* Check Tunnel enable status.  */
    if (status)
        error_counter++;

    /* Create ip0 TUNNEL.  */
    address_selector_0.nx_selector_src_address_start.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_0.nx_selector_src_address_start.nxd_ip_address.v4 = 0x01000000;

    address_selector_0.nx_selector_src_address_end.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_0.nx_selector_src_address_end.nxd_ip_address.v4 = 0x02000000;

    address_selector_0.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_0.nx_selector_dst_address_start.nxd_ip_address.v4 = 0x01000000;

    address_selector_0.nx_selector_dst_address_end.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_0.nx_selector_dst_address_end.nxd_ip_address.v4 = 0x02000000;

    /* add tunnel address.  */
    address_selector_0.nx_selector_src_tunnel_address = ipv6_address_3;
    address_selector_0.nx_selector_dst_tunnel_address = ipv6_address_4;

    /* Set up TUNNEL */
    status = _nx_tunnel_create(&ip_0, &tunnel_0,NX_IP_VERSION_V6,address_selector_0);


    /* Create ip1 TUNNEL .  */
    address_selector_1.nx_selector_src_address_start.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_1.nx_selector_src_address_start.nxd_ip_address.v4 = 0x01000000;

    address_selector_1.nx_selector_src_address_end.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_1.nx_selector_src_address_end.nxd_ip_address.v4 = 0x02000000;

    address_selector_1.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_1.nx_selector_dst_address_start.nxd_ip_address.v4 = 0x01000000;

    address_selector_1.nx_selector_dst_address_end.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_1.nx_selector_dst_address_end.nxd_ip_address.v4 = 0x02000000;

    /* add tunnel address.  */
    address_selector_1.nx_selector_src_tunnel_address = ipv6_address_4;
    address_selector_1.nx_selector_dst_tunnel_address = ipv6_address_3;

    /* Set up TUNNEL */
    status = _nx_tunnel_create(&ip_1, &tunnel_1,NX_IP_VERSION_V6,address_selector_1);
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
    printf("NetX Test:   TUNNEL ICMP IPV4_6 Ping Test..................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 7), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping an IP address that does exist.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 1) || (pings_sent != 2) || (ping_responses_received != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28 /* data only */) ||
        (ping_threads_suspended) || (icmp_checksum_errors) || (icmp_unhandled_messages))
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
void    netx_icmp_ping_tunnel_ipv4_ipv6_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TUNNEL ICMP IPV4_6 Ping Test..............................N/A\n");

    test_control_return(3);

}

#endif /* NX_TUNNEL_ENABLE */