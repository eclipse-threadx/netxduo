/* This case tests if compile works with old APIs. */

#include   "nx_api.h"
#include   "tx_api.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static TX_THREAD               ntest_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    ntest_0_entry(ULONG thread_input);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_old_api_application_define(void *first_unused_memory)
#endif
{
UCHAR         *pointer;
UINT           status;


    /* Setup the working pointer.  */
    pointer = (UCHAR *) first_unused_memory;

    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;
    
    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
#if defined(__PRODUCT_NETXDUO__)
NX_PACKET      *packet_ptr;
NX_UDP_SOCKET  udp_socket;
#ifdef FEATURE_NX_IPV6

NXD_ADDRESS             src_address;

    /* Set source and destination address with global address. */    
    src_address.nxd_ip_version = NX_IP_VERSION_V6;
    src_address.nxd_ip_address.v6[0] = 0x20010DB8;
    src_address.nxd_ip_address.v6[1] = 0x00010001;
    src_address.nxd_ip_address.v6[2] = 0x021122FF;
    src_address.nxd_ip_address.v6[3] = 0xFE334456;

    nxd_ipv6_address_set(&ip_0, 0, &src_address, 64, NX_NULL);
#endif

    /* Test old APIs. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_NO_WAIT);
    nx_ip_raw_packet_interface_send(&ip_0, packet_ptr, IP_ADDRESS(1, 2, 3, 5), 0, NX_IP_NORMAL);

    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_NO_WAIT);
    nx_udp_socket_create(&ip_0, &udp_socket, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    nx_udp_socket_bind(&udp_socket, 0x88, TX_WAIT_FOREVER);
    nx_udp_socket_interface_send(&udp_socket, packet_ptr, IP_ADDRESS(1, 2, 3, 5), 87, 0);
    
#ifdef FEATURE_NX_IPV6
    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_NO_WAIT);
    nxd_ip_raw_packet_interface_send(&ip_0, packet_ptr, &src_address, 0, 100, 255, NX_IP_NORMAL);

    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_NO_WAIT);
    nxd_udp_socket_interface_send(&udp_socket, packet_ptr, &src_address, 87, 0);

    nxd_icmp_interface_ping(&ip_0, &src_address, 0, "test", 4, &packet_ptr, TX_NO_WAIT);
#endif

    /* Test new APIs. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_NO_WAIT);
    nx_ip_raw_packet_interface_send(&ip_0, packet_ptr, IP_ADDRESS(1, 2, 3, 5), 0, NX_IP_NORMAL);

    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_NO_WAIT);
    nx_udp_socket_source_send(&udp_socket, packet_ptr, IP_ADDRESS(1, 2, 3, 5), 87, 0);
    
#ifdef FEATURE_NX_IPV6
    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_NO_WAIT);
    nxd_ip_raw_packet_source_send(&ip_0, packet_ptr, &src_address, 0, 100, 255, NX_IP_NORMAL);

    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_NO_WAIT);
    nxd_udp_socket_source_send(&udp_socket, packet_ptr, &src_address, 87, 0);

    nxd_icmp_source_ping(&ip_0, &src_address, 0, "test", 4, &packet_ptr, TX_NO_WAIT);
#endif

    printf("NetX Test:   Old APIs Test.............................................SUCCESS!\n");
    test_control_return(0);
#endif
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_old_api_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Old APIs Test.............................................N/A\n");
    test_control_return(3);
}
#endif
