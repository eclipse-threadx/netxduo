/* This NetX test concentrates on the IGMP loopback operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IGMP_INFO) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048

#define     TEST_INTERFACE          1


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);

extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_igmp_loopback_test_application_define(void *first_unused_memory)
#endif
{
    
CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

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

    status += nx_ip_interface_attach(&ip_0,"Second Interface",IP_ADDRESS(2,2,3,4),0xFFFFFF00UL,  _nx_ram_network_driver_256);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable IGMP processing for both this IP instance.  */
    status =  nx_igmp_enable(&ip_0);

    /* Check enable status.  */
    if (status)
        error_counter++;

    /* Enable UDP processing for this IP instance.  */
    status =  nx_udp_enable(&ip_0);

    /* Check enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
ULONG       igmp_reports_sent;
ULONG       igmp_queries_received;
ULONG       igmp_checksum_errors;
ULONG       current_groups_joined;
#ifdef __PRODUCT_NETXDUO__
NXD_ADDRESS dest_address;
#endif

    
    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Loopback Operation Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    /* Enable all TX checksum capability. */
    nx_ip_interface_capability_set(&ip_0, TEST_INTERFACE, NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM | 
            NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM |
            NX_INTERFACE_CAPABILITY_UDP_TX_CHECKSUM |
            NX_INTERFACE_CAPABILITY_ICMPV4_TX_CHECKSUM |
            NX_INTERFACE_CAPABILITY_ICMPV6_TX_CHECKSUM |
            NX_INTERFACE_CAPABILITY_IGMP_TX_CHECKSUM);

#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

    /* Enable IGMP loopback.  */
    status =  nx_igmp_loopback_enable(&ip_0);

    /* Perform 7 IGMP join operations.  */
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,1),TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,2),TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,3),TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4),TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,5),TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,6),TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,7),TEST_INTERFACE);

    /* Join one group another 4 times to test the counting operation.  */
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4),TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4),TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4),TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4),TEST_INTERFACE);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Sleep 2 seconds to let IGMP packets be sent. */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Call the IGMP information get routine to see if all the groups are there.  */
    status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);

    /* Check for status.  */
    if ((status) || (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 7))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create and bind two UDP sockets.  */
    status =   nx_udp_socket_create(&ip_0, &socket_0, "Sending Socket", NX_IP_NORMAL, NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 5);
    status +=  nx_udp_socket_create(&ip_0, &socket_1, "Receiving Socket", NX_IP_NORMAL, NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 5);
    status +=  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);
    status +=  nx_udp_socket_bind(&socket_1, 0x89, TX_WAIT_FOREVER);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

#ifdef __PRODUCT_NETXDUO__
    dest_address.nxd_ip_address.v4 =IP_ADDRESS(224, 0, 0, 4);
    dest_address.nxd_ip_version = 4;

    /* Send the UDP packet.  */
    status =  nxd_udp_socket_interface_send(&socket_0, my_packet, &dest_address, 0x89, TEST_INTERFACE);
#else

    /* Send the UDP packet.  */
    status =  nx_udp_socket_interface_send(&socket_0, my_packet, IP_ADDRESS(224, 0, 0, 4), 0x89, TEST_INTERFACE);
#endif

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive the UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the IGMP loopback.  */
    status =  nx_igmp_loopback_disable(&ip_0);

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    /* Disable all interface capability. */
    nx_ip_interface_capability_set(&ip_0, TEST_INTERFACE, 0);
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

    /* Now leave all the groups to make sure that processing works properly.  */
#ifdef __PRODUCT_NETXDUO__
    status =   nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,1), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,2), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,3), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,5), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,6), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,7), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), TEST_INTERFACE);
    status +=  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), TEST_INTERFACE);
#else 

    status =   nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,1));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,2));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,3));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,5));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,6));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,7));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
#endif
    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Call the IGMP information get routine to see if all the groups are there.  */
    status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);

    /* Check for status.  */
    if ((status) || (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined))
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
void    netx_igmp_loopback_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   IGMP Loopback Operation Test..............................N/A\n");
    test_control_return(3);

}
#endif /* NX_DISABLE_IGMP_INFO */
