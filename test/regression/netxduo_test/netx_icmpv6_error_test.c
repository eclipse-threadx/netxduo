/* This NetX test concentrates on icmpv6 error function.  */
/*
 * 1. IP 0 sends a UDP packet to IP 1.
 * 2. Since IP 1 has no UDP socket binding, it will reply ICMPv6 error.
 * 3. During sending ICMPv6 error packet, original data are copied.
 * 4. Since IP 1 has smaller payload pool than IP 0, there was a bug causes memory leak.
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
static UCHAR                   clean_buffer[1024];
static UCHAR                   test_data[1024];
static CHAR                    mac[2][6] = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x56}, {0x00, 0x11, 0x22, 0x33, 0x44, 0x57}};
static ULONG                   dest_unreachable_count;
static ULONG                   parameter_problem_count;
static NX_PACKET              *test_packet[10];

/* Packet to trigger parameter problem message. 
 * src: 2001::1000:1
 * dst: ff02::1 */
static const unsigned char pkt1[] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11, /* 33...... */
0x22, 0x33, 0x44, 0x56, 0x86, 0xdd, 0x60, 0x00, /* "3DV..`. */
0x00, 0x00, 0x00, 0x25, 0x00, 0xff, 0x20, 0x01, /* ...%.. . */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3c, 0x00, /* ......<. */
0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, /* ......,. */
0x87, 0x04, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, /* ......:. */
0x00, 0x01, 0x00, 0x00, 0x00, 0x65, 0x80, 0x00, /* .....e.. */
0x10, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x05                                /* ... */
};

/* Packet to trigger parameter problem message. 
 * src: fe80::1000:1
 * dst: ff02::1 */
static const unsigned char pkt2[] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11, /* 33...... */
0x22, 0x33, 0x44, 0x56, 0x86, 0xdd, 0x60, 0x00, /* "3DV..`. */
0x00, 0x00, 0x00, 0x25, 0x00, 0xff, 0xfe, 0x80, /* ...%.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3c, 0x00, /* ......<. */
0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, /* ......,. */
0x87, 0x04, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, /* ......:. */
0x00, 0x01, 0x00, 0x00, 0x00, 0x65, 0x80, 0x00, /* .....e.. */
0x10, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x05                                /* ... */
};

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
void    netx_icmpv6_error_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    dest_unreachable_count = 0;
    parameter_problem_count = 0;
    memset(clean_buffer, 0, sizeof(clean_buffer));
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
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 544, pool_area_1, sizeof(pool_area_1));

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
UINT        i;


    /* Print out some test information banners.  */
    printf("NetX Test:   ICMPv6 Error Test.........................................");

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
    if ((status) || (dest_unreachable_count != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test error message with icmp enabled. */
    nxd_icmp_enable(&ip_1);

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

    /* Allocate all packets of IP1's default pool. */
    for (i = 0; i < sizeof(test_packet) / sizeof(NX_PACKET *); i++)
    {
        if (nx_packet_allocate(&pool_1, &test_packet[i], 0, NX_NO_WAIT))
            break;
    }

    /* Whether array reaches the bound. */
    if (i == sizeof(test_packet) / sizeof(NX_PACKET *))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the UDP packet to unbinded peer.  */
    status =  nxd_udp_socket_send(&socket_0, my_packet, &ipv6_address_2, 0x89);

    /* No destination unrechable message should received since pool of IP1 is empty. */
    /* Check status.  */
    if ((status) || (dest_unreachable_count != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release all packets. */
    while (i != 0)
    {
        i--;
        nx_packet_release(test_packet[i]);
    }

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
    if ((status) || (dest_unreachable_count != 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Verify all packets are normal. */
    for (i = 0; i < sizeof(test_packet) / sizeof(NX_PACKET *); i++)
    {
        if (nx_packet_allocate(&pool_1, &test_packet[i], 0, NX_NO_WAIT))
            break;
        nx_packet_data_append(test_packet[i], test_data, pool_1.nx_packet_pool_payload_size, &pool_1, NX_NO_WAIT);
    }

    /* Whether array reaches the bound. */
    if (i == sizeof(test_packet) / sizeof(NX_PACKET *))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release all packets. */
    while (i != 0)
    {
        i--;
        nx_packet_release(test_packet[i]);
    }

    /* Verify the clean buffer is not polluted. */
    for (i = 0; i < sizeof(clean_buffer); i++)
    {
        if (clean_buffer[i] != 0)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }


    /* Allocate a packet. */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    my_packet -> nx_packet_length = sizeof(pkt1) - 14;
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    /* Directly receive the packet to let IP 1 send parameter problem packet.  */
    _nx_ip_packet_deferred_receive(&ip_1, my_packet);     

    /* Since IP 1 doesn't have link local address, the ICMPV6 error message can't be sent. */
    if (parameter_problem_count != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Set link local address. */
    nxd_ipv6_address_set(&ip_0, 0, &lla_1, 10, NX_NULL);
    nxd_ipv6_address_set(&ip_1, 0, &lla_2, 10, NX_NULL);

#ifndef NX_DISABLE_IPV6_DAD
    /* Allocate a packet. */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);
    my_packet -> nx_packet_length = sizeof(pkt2) - 14;
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    /* Directly receive the packet to let IP 1 send parameter problem packet. 
     * Since lla_2 is not ready, no ICMPV6 message could be sent from link local address. */
    _nx_ip_packet_deferred_receive(&ip_1, my_packet);     

    if (parameter_problem_count != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Sleep 5 seconds for DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* NX_DISABLE_IPV6_DAD */

    /* Allocate a packet. */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);
    my_packet -> nx_packet_length = sizeof(pkt2) - 14;
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    /* Directly receive the packet to let IP 1 send parameter problem packet.  */
    _nx_ip_packet_deferred_receive(&ip_1, my_packet);     

    if (parameter_problem_count != 1)
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

            /* Is it destination unreachable packet? */
            if (data[40] == 0x01)
            {

                /* Yes it is. */
                dest_unreachable_count++;
            }

            /* Is it parameter problem packet? */
            if (data[40] == 0x04)
            {

                /* Yes it is. */
                parameter_problem_count++;
            }
        }

        /* Is it a framgent packet? */
        else if (data[6] == 0x2C)
        {

            /* Is the offset non-zero? */
            if ((data[42] != 0) || ((data[32] & 0xF8) != 0))
            {

                /* Drop the fragment that is not header. */
                *operation_ptr = NX_RAMDRIVER_OP_DROP;
            }
        }
    }

    return NX_TRUE;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmpv6_error_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   ICMPv6 Error Test.........................................N/A\n");

    test_control_return(3);

}
#endif
