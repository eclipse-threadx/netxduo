/* This NetX test concentrates on the code coverage for TCP functions,
 * _nx_tcp_packet_receive.c
 */

#include "nx_api.h"
#include "tx_thread.h"
#include "nx_tcp.h"
#include "nx_ip.h" 
#include "nx_packet.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_RX_SIZE_CHECKING)

#define     DEMO_STACK_SIZE         2048
#define     ASSERT_THREAD_COUNT     1


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           tcp_socket; 


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;  
static UCHAR                   pool_area[102400];

/* TCP packet. 192.168.100.23:6206 -> 192.168.100.4:80 */
/* Invalid TCP length.  */
static unsigned char pkt1[54] = {
0x00, 0x1e, 0x8f, 0xb1, 0x7a, 0xd4, 0xf4, 0x8e, /* ....z... */
0x38, 0xa3, 0x25, 0xb3, 0x08, 0x00, 0x45, 0x00, /* 8.%...E. */
0x00, 0x28, 0x10, 0x9d, 0x00, 0x00, 0x80, 0x06, /* .(...... */
0xe0, 0xc6, 0xc0, 0xa8, 0x64, 0x17, 0xc0, 0xa8, /* ....d... */
0x64, 0x04, 0x18, 0x3e, 0x00, 0x50, 0x62, 0xf3, /* d..>.Pb. */
0xa5, 0x46, 0x54, 0x7e, 0x0c, 0xe7, 0x40, 0x10, /* .FT~..P. */
0x01, 0x00, 0xf3, 0x3a, 0x00, 0x00              /* ...:.. */
};

/* TCP packet. 192.168.100.23:6206 -> 192.168.100.4:80 */
/* Invalid TCP length.  */
static unsigned char pkt2[54] = {
0x00, 0x1e, 0x8f, 0xb1, 0x7a, 0xd4, 0xf4, 0x8e, /* ....z... */
0x38, 0xa3, 0x25, 0xb3, 0x08, 0x00, 0x45, 0x00, /* 8.%...E. */
0x00, 0x28, 0x10, 0x9d, 0x00, 0x00, 0x80, 0x06, /* .(...... */
0xe0, 0xc6, 0xc0, 0xa8, 0x64, 0x17, 0xc0, 0xa8, /* ....d... */
0x64, 0x04, 0x18, 0x3e, 0x00, 0x50, 0x62, 0xf3, /* d..>.Pb. */
0xa5, 0x46, 0x54, 0x7e, 0x0c, 0xe7, 0x60, 0x10, /* .FT~..P. */
0x01, 0x00, 0xd3, 0x3a, 0x00, 0x00              /* ...:.. */
};


/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_invalid_length_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Invalid Length Test...................................");
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pool_area, sizeof(pool_area));

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for IP instance.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;


    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &tcp_socket, "TCP Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                   NX_NULL, NX_NULL);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&tcp_socket, 80, NX_NO_WAIT);

    /* Check for error.  */  
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    
    nx_ip_address_set(&ip_0, IP_ADDRESS(192,168,100,4), 0xFFFFFF00);
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(192,168,100,4);

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt1) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);  

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt2) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);  

#ifndef NX_DISABLE_TCP_INFO
    if (ip_0.nx_ip_tcp_invalid_packets != 2)
        error_counter++;
#endif /* NX_DISABLE_ICMP_INFO */

    /* Check status.  */
    if (error_counter) 
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
void    netx_tcp_invalid_length_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Invalid Length Test...................................N/A\n"); 

    test_control_return(3);  
}      
#endif
