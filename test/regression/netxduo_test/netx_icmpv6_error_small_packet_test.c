/* This NetX test concentrates on icmpv6 error function.  */
/*
 * 1. IP 0 sends a UDP packet to IP 1.
 * 2. Since IP 1 has no UDP socket binding, it will reply ICMPv6 error.
 * 3. No ICMPv6 error message is sent out since IP 1 payload is too small.
 *
 */


#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined (NX_DISABLE_ICMPV6_ERROR_MESSAGE) && !defined(NX_DISABLE_PACKET_CHAIN)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;

static NX_IP                   ip_0;
static NX_IP                   ip_1;


static NX_UDP_SOCKET           socket_0;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
static NXD_ADDRESS             multicast_addr;
static NXD_ADDRESS             lla_1;
static NXD_ADDRESS             lla_2;

static UCHAR                   pool_area_0[40960];
static UCHAR                   pool_area_1[2048];
static UCHAR                   test_data[128];
static CHAR                    mac[2][6] = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x56}, {0x00, 0x11, 0x22, 0x33, 0x44, 0x57}};
static ULONG                   icmpv6_error_count;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    _nx_ram_network_driver_set_pool(NX_PACKET_POOL *pool_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmpv6_error_small_packet_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    icmpv6_error_count = 0;
    memset(test_data, 255, sizeof(test_data));

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create two packet pools.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pool_area_0, sizeof(pool_area_0));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create two packet pools.  */
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", NX_IPv6_ICMP_PACKET, pool_area_1, sizeof(pool_area_1));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_1, _nx_ram_network_driver_1500,
        pointer, 2048, 2);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
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

    multicast_addr.nxd_ip_version = NX_IP_VERSION_V6;
    multicast_addr.nxd_ip_address.v6[0] = 0xFF020000;
    multicast_addr.nxd_ip_address.v6[1] = 0x00000000;
    multicast_addr.nxd_ip_address.v6[2] = 0x00000000;
    multicast_addr.nxd_ip_address.v6[3] = 0x00000001;

    lla_1.nxd_ip_version = NX_IP_VERSION_V6;
    lla_1.nxd_ip_address.v6[0] = 0xfe800000;
    lla_1.nxd_ip_address.v6[1] = 0x00000000;
    lla_1.nxd_ip_address.v6[2] = 0x00000000;
    lla_1.nxd_ip_address.v6[3] = 0x10000001;

    lla_2.nxd_ip_version = NX_IP_VERSION_V6;
    lla_2.nxd_ip_address.v6[0] = 0xfe800000;
    lla_2.nxd_ip_address.v6[1] = 0x00000000;
    lla_2.nxd_ip_address.v6[2] = 0x00000000;
    lla_2.nxd_ip_address.v6[3] = 0x10000002;

    /* Set interfaces' address */
    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);

    /* Check for IPv6 address set errors.  */
    if (status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Check for IPv6 enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check for ICMP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status += nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;


    /* Print out some test information banners.  */
    printf("NetX Test:   ICMPv6 Error Small Packet Test............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait until DAD finishes. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    advanced_packet_process_callback = my_packet_process;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Let driver use large pool. */
    _nx_ram_network_driver_set_pool(&pool_0);

    /* Test error message with icmp disabled. */
    /* Set nd cache so no NS or NA is needed. */
    nxd_nd_cache_entry_set(&ip_0, ipv6_address_2.nxd_ip_address.v6, 0, mac[1]);
    nxd_nd_cache_entry_set(&ip_1, ipv6_address_1.nxd_ip_address.v6, 0, mac[0]);

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Write data into the packet payload!  */
    status += nx_packet_data_append(my_packet, test_data, sizeof(test_data), &pool_0, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the UDP packet to unbinded peer.  */
    status =  nxd_udp_socket_send(&socket_0, my_packet, &ipv6_address_2, 0x89);

    /* Check status.  */
    if ((status) || (icmpv6_error_count != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
UCHAR *data = packet_ptr -> nx_packet_prepend_ptr;

    /* Check whether it is an icmpv6 packet. */
    if (packet_ptr -> nx_packet_length >= 48)
    {

        /* Is it ICMPv6 packet? */
        if (data[6] == 0x3A)
        {

            /* ICMPv6 error message.  */
            if (data[40] == 0x01)
            {

                /* Yes it is. */
                icmpv6_error_count++;
            }
        }
    }

    return NX_TRUE;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmpv6_error_small_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   ICMPv6 Error Small Packet Test............................N/A\n");

    test_control_return(3);

}
#endif
