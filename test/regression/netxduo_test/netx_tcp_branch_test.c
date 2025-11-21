/* This NetX test concentrates on the code coverage for TCP functions,
 * _nx_tcp_connect_cleanup.c
 * _nx_tcp_disconnect_cleanup.c
 * _nx_tcp_client_bind_cleanup.c
 * _nx_tcp_receive_cleanup.c
 * _nx_tcp_transmit_cleanup.c
 * _nx_tcp_socket_thread_resume.c
 * _nx_tcp_packet_receive.c
 * _nx_tcp_server_socket_listen.c
 * _nx_tcp_socket_mss_set.c
 * _nx_tcp_socket_state_fin_wait2.c
 * _nx_tcp_socket_state_data_trim.c 
 * _nx_tcp_client_socket_unbind.c
 * _nx_tcp_socket_disconnect.c
 * _nx_tcp_client_bind_cleanup.c
 */

#include "nx_api.h"
#include "tx_thread.h"
#include "nx_tcp.h"
#include "nx_ip.h" 
#include "nx_packet.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048
#define     ASSERT_THREAD_COUNT     1


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_test1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           tcp_socket; 
static NX_TCP_SOCKET           tcp_socket_2; 
static NX_TCP_SOCKET           test_socket;
static NX_TCP_LISTEN           tcp_listen[2];



/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;  
static UCHAR                   pool_area[102400];
#ifdef __PRODUCT_NETXDUO__
static UINT                    disconnect_flag = NX_FALSE;

#if defined FEATURE_NX_IPV6 && !defined NX_DISABLE_ASSERT
static TX_THREAD               thread_for_assert[ASSERT_THREAD_COUNT];
static UCHAR                   stack_for_assert[ASSERT_THREAD_COUNT][DEMO_STACK_SIZE];
#endif

#if !defined NX_DISABLE_PACKET_CHAIN  && !defined NX_DISABLE_ASSERT 
static TX_THREAD               thread_for_assert_1;
static UCHAR                   stack_for_assert_1[DEMO_STACK_SIZE];
#endif /* __PRODUCT_NETXDUO__  */

#endif
#ifdef FEATURE_NX_IPV6
static UINT                    address_index;
#endif /* FEATURE_NX_IPV6 */

#ifdef __PRODUCT_NETXDUO__
/* TCP packet. 192.168.100.23:6206 -> 192.168.100.4:80 */
static unsigned char pkt1[54] = {
0x00, 0x1e, 0x8f, 0xb1, 0x7a, 0xd4, 0xf4, 0x8e, /* ....z... */
0x38, 0xa3, 0x25, 0xb3, 0x08, 0x00, 0x45, 0x00, /* 8.%...E. */
0x00, 0x28, 0x10, 0x9d, 0x00, 0x00, 0x80, 0x06, /* .(...... */
0xe0, 0xc6, 0xc0, 0xa8, 0x64, 0x17, 0xc0, 0xa8, /* ....d... */
0x64, 0x04, 0x18, 0x3e, 0x00, 0x50, 0x62, 0xf3, /* d..>.Pb. */
0xa5, 0x46, 0x54, 0x7e, 0x0c, 0xe7, 0x50, 0x10, /* .FT~..P. */
0x01, 0x00, 0xe3, 0x3a, 0x00, 0x00              /* ...:.. */
};

#ifdef FEATURE_NX_IPV6
/* TCP packet. [fe80::1]:6206 -> [fe80::211:22ff:fe33:4456]:80 */
static unsigned char pkt2[74] = {
0x00, 0x1e, 0x8f, 0xb1, 0x7a, 0xd4, 0xf4, 0x8e, /* ....z... */
0x38, 0xa3, 0x25, 0xb3, 0x86, 0xdd, 0x60, 0x00, /* 8.%...`. */
0x00, 0x00, 0x00, 0x14, 0x06, 0xff, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x18, 0x3e, /* "..3DV.> */
0x00, 0x50, 0x62, 0xf3, 0xa5, 0x46, 0x54, 0x7e, /* .Pb..FT~ */
0x0c, 0xe7, 0x50, 0x10, 0x01, 0x00, 0xc8, 0x0a, /* ..P..... */
0x00, 0x00                                      /* .. */
};

/* TCP packet with invalid option. SYN bits are set. */
static unsigned char pkt3[78] = {
0x00, 0x1e, 0x8f, 0xb1, 0x7a, 0xd4, 0xf4, 0x8e, /* ....z... */
0x38, 0xa3, 0x25, 0xb3, 0x86, 0xdd, 0x60, 0x00, /* 8.%...`. */
0x00, 0x00, 0x00, 0x18, 0x06, 0xff, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x18, 0x3e, /* "..3DV.> */
0x00, 0x50, 0x62, 0xf3, 0xa5, 0x46, 0x54, 0x7e, /* .Pb..FT~ */
0x0c, 0xe7, 0x60, 0x02, 0x01, 0x00, 0xb6, 0x14, /* ..`..... */
0x00, 0x00, 0x02, 0x00, 0x00, 0x00              /* ...... */
};

/* TCP packet with invalid option. SYN bits are set. */
static unsigned char pkt4[78] = {
0x00, 0x1e, 0x8f, 0xb1, 0x7a, 0xd4, 0xf4, 0x8e, /* ....z... */
0x38, 0xa3, 0x25, 0xb3, 0x86, 0xdd, 0x60, 0x00, /* 8.%...`. */
0x00, 0x00, 0x00, 0x18, 0x06, 0xff, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x18, 0x3e, /* "..3DV.> */
0x00, 0x50, 0x62, 0xf3, 0xa5, 0x46, 0x54, 0x7e, /* .Pb..FT~ */
0x0c, 0xe7, 0x60, 0x00, 0x01, 0x00, 0xb6, 0x16, /* ..`..... */
0x00, 0x00, 0x02, 0x00, 0x00, 0x00              /* ...... */
};
#endif

/* TCP packet. 192.168.100.4:80 -> 192.168.100.4:80 */
static unsigned char pkt5[60] = {
0xf4, 0x8e, 0x38, 0xa3, 0x25, 0xb3, 0x20, 0x0b, /* ..8.%. . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x00, 0x45, 0x10, /* ..E...E. */
0x00, 0x28, 0x02, 0x6b, 0x40, 0x00, 0x3a, 0x06, /* .(.k@.:. */
0xf4, 0xfb, 0xc0, 0xa8, 0x64, 0x04, 0xc0, 0xa8, /* ....d... */
0x64, 0x04, 0x00, 0x50, 0x00, 0x50, 0x9e, 0xc2, /* d..P.P.. */
0x86, 0xc6, 0x18, 0xc8, 0x09, 0x1a, 0x50, 0x00, /* ......P. */
0x01, 0xf9, 0x1c, 0x87, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

/* TCP packet. [fe80::211:22ff:fe33:4456]:6206 -> [fe80::211:22ff:fe33:4456]:80 */
static unsigned char pkt6[78] = {
0x00, 0x1e, 0x8f, 0xb1, 0x7a, 0xd4, 0xf4, 0x8e, /* ....z... */
0x38, 0xa3, 0x25, 0xb3, 0x86, 0xdd, 0x60, 0x00, /* 8.%...`. */
0x00, 0x00, 0x00, 0x18, 0x06, 0xff, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0xff, 0x33, 0x44, 0x56, 0xff, 0x02, /* ...3DV.. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0xff, 0x33, 0x44, 0x56, 0x18, 0x3e, /* ...3DV.> */
0x00, 0x50, 0x62, 0xf3, 0xa5, 0x46, 0x54, 0x7e, /* .Pb..FT~ */
0x0c, 0xe7, 0x60, 0x00, 0x01, 0x00, 0x96, 0x97, /* ..`..... */
0x00, 0x00, 0x01, 0x00, 0x00, 0x00              /* ...... */
};

/* TCP packet. 255.255.255.255:80 -> 192.168.100.4:80 */
static unsigned char pkt7[60] = {
0xf4, 0x8e, 0x38, 0xa3, 0x25, 0xb3, 0x20, 0x0b, /* ..8.%. . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x00, 0x45, 0x10, /* ..E...E. */
0x00, 0x28, 0x02, 0x6b, 0x40, 0x00, 0x3a, 0x06, /* .(.k@.:. */
0x19, 0xa9, 0xff, 0xff, 0xff, 0xff, 0xc0, 0xa8, /* ........ */
0x64, 0x04, 0x00, 0x50, 0x00, 0x50, 0x9e, 0xc2, /* d..P.P.. */
0x86, 0xc6, 0x18, 0xc8, 0x09, 0x1a, 0x50, 0x00, /* ......P. */
0x01, 0xf9, 0x41, 0x34, 0x00, 0x00, 0x00, 0x00, /* ..A4.... */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

/* TCP RST packet. 192.168.100.23:80 -> 192.168.100.4:80 */
static unsigned char pkt8[60] = {
0xf4, 0x8e, 0x38, 0xa3, 0x25, 0xb3, 0x20, 0x0b, /* ..8.%. . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x00, 0x45, 0x10, /* ..E...E. */
0x00, 0x28, 0x02, 0x6b, 0x40, 0x00, 0x3a, 0x06, /* .(.k@.:. */
0xf4, 0xe8, 0xc0, 0xa8, 0x64, 0x17, 0xc0, 0xa8, /* ....d... */
0x64, 0x04, 0x00, 0x50, 0x00, 0x50, 0x9e, 0xc2, /* d..P.P.. */
0x86, 0xc6, 0x18, 0xc8, 0x09, 0x1a, 0x50, 0x04, /* ......P. */
0x01, 0xf9, 0x1c, 0x70, 0x00, 0x00, 0x00, 0x00, /* ...p.... */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

/* TCP packet. 224.0.0.1:80 -> 192.168.100.4:80 */
static unsigned char pkt9[60] = {
0xf4, 0x8e, 0x38, 0xa3, 0x25, 0xb3, 0x20, 0x0b, /* ..8.%. . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x00, 0x45, 0x10, /* ..E...E. */
0x00, 0x28, 0x02, 0x6b, 0x40, 0x00, 0x3a, 0x06, /* .(.k@.:. */
0x39, 0xa7, 0xe0, 0x00, 0x00, 0x01, 0xc0, 0xa8, /* 9....... */
0x64, 0x04, 0x00, 0x50, 0x00, 0x50, 0x9e, 0xc2, /* d..P.P.. */
0x86, 0xc6, 0x18, 0xc8, 0x09, 0x1a, 0x50, 0x04, /* ......P. */
0x01, 0xf9, 0x61, 0x2e, 0x00, 0x00, 0x00, 0x00, /* ..a..... */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

/* TCP SYN packet. 192.168.100.24:80 -> 192.168.100.4:80 */
static unsigned char pkt10[60] = {
0xf4, 0x8e, 0x38, 0xa3, 0x25, 0xb3, 0x20, 0x0b, /* ..8.%. . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x00, 0x45, 0x10, /* ..E...E. */
0x00, 0x28, 0x02, 0x6b, 0x40, 0x00, 0x3a, 0x06, /* .(.k@.:. */
0xf4, 0xe7, 0xc0, 0xa8, 0x64, 0x18, 0xc0, 0xa8, /* ....d... */
0x64, 0x04, 0x00, 0x50, 0x00, 0x50, 0x9e, 0xc2, /* d..P.P.. */
0x86, 0xc6, 0x18, 0xc8, 0x09, 0x1a, 0x50, 0x02, /* ......P. */
0x01, 0xf9, 0x1c, 0x71, 0x00, 0x00, 0x00, 0x00, /* ...q.... */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

/* TCP SYN packet. 192.168.100.23:81 -> 192.168.100.4:80 */
static unsigned char pkt11[60] = {
0xf4, 0x8e, 0x38, 0xa3, 0x25, 0xb3, 0x20, 0x0b, /* ..8.%. . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x00, 0x45, 0x10, /* ..E...E. */
0x00, 0x28, 0x02, 0x6b, 0x40, 0x00, 0x3a, 0x06, /* .(.k@.:. */
0xf4, 0xe8, 0xc0, 0xa8, 0x64, 0x17, 0xc0, 0xa8, /* ....d... */
0x64, 0x04, 0x00, 0x51, 0x00, 0x50, 0x9e, 0xc2, /* d..Q.P.. */
0x86, 0xc6, 0x18, 0xc8, 0x09, 0x1a, 0x50, 0x02, /* ......P. */
0x01, 0xf9, 0x1c, 0x71, 0x00, 0x00, 0x00, 0x00, /* ...q.... */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

/* TCP SYN packet. [fe80::211:22ff:fe33:4456]:6206 -> [fe80::211:22ff:fe33:4456]:80 */
static unsigned char pkt12[78] = {
0x00, 0x1e, 0x8f, 0xb1, 0x7a, 0xd4, 0xf4, 0x8e, /* ....z... */
0x38, 0xa3, 0x25, 0xb3, 0x86, 0xdd, 0x60, 0x00, /* 8.%...`. */
0x00, 0x00, 0x00, 0x18, 0x06, 0xff, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x18, 0x3e, /* "..3DV.> */
0x00, 0x50, 0x62, 0xf3, 0xa5, 0x46, 0x54, 0x7e, /* .Pb..FT~ */
0x0c, 0xe7, 0x60, 0x02, 0x01, 0x00, 0xb7, 0x14, /* ..`..... */
0x00, 0x00, 0x01, 0x00, 0x00, 0x00              /* ...... */
};

/* TCP RST packet. [fe80::211:22ff:fe33:4456]:6207 -> [fe80::211:22ff:fe33:4456]:80 */
static unsigned char pkt13[78] = {
0x00, 0x1e, 0x8f, 0xb1, 0x7a, 0xd4, 0xf4, 0x8e, /* ....z... */
0x38, 0xa3, 0x25, 0xb3, 0x86, 0xdd, 0x60, 0x00, /* 8.%...`. */
0x00, 0x00, 0x00, 0x18, 0x06, 0xff, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x18, 0x3f, /* "..3DV.? */
0x00, 0x50, 0x62, 0xf3, 0xa5, 0x46, 0x54, 0x7e, /* .Pb..FT~ */
0x0c, 0xe7, 0x60, 0x04, 0x01, 0x00, 0xb7, 0x11, /* ..`..... */
0x00, 0x00, 0x01, 0x00, 0x00, 0x00              /* ...... */
};

/* TCP RST packet. 192.168.100.24:80 -> 192.168.100.4:80 */
static unsigned char pkt14[60] = {
0xf4, 0x8e, 0x38, 0xa3, 0x25, 0xb3, 0x20, 0x0b, /* ..8.%. . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x00, 0x45, 0x10, /* ..E...E. */
0x00, 0x28, 0x02, 0x6b, 0x40, 0x00, 0x3a, 0x06, /* .(.k@.:. */
0xf4, 0xe7, 0xc0, 0xa8, 0x64, 0x18, 0xc0, 0xa8, /* ....d... */
0x64, 0x04, 0x00, 0x50, 0x00, 0x50, 0x9e, 0xc2, /* d..P.P.. */
0x86, 0xc6, 0x18, 0xc8, 0x09, 0x1a, 0x50, 0x04, /* ......P. */
0x01, 0xf9, 0x1c, 0x6f, 0x00, 0x00, 0x00, 0x00, /* ...o.... */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

#endif /* __PRODUCT_NETXDUO__ */

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    suspend_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER);
#ifdef __PRODUCT_NETXDUO__
static VOID    tcp_fast_periodic_processing(NX_IP *ip_ptr);
static VOID    my_tcp_queue_process(NX_IP *ip_ptr);
static VOID    ack_check_test();
static VOID    data_check_test();
static VOID    socket_packet_process_test();

#if defined FEATURE_NX_IPV6 && !defined NX_DISABLE_ASSERT
static VOID    thread_for_assert_entry_0(ULONG thread_input);
static VOID  (*thread_for_assert_entry[])(ULONG) = 
{
    thread_for_assert_entry_0,
};
#endif

#if !defined NX_DISABLE_PACKET_CHAIN  && !defined NX_DISABLE_ASSERT  
static VOID    thread_for_assert_entry_1(ULONG thread_input);
#endif

#endif /* __PRODUCT_NETXDUO__  */



/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_branch_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Branch Test...........................................");
    
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

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 processing for IP instance.  */
    status =  nxd_ipv6_enable(&ip_0);

    /* Check IPv6 enable status.  */
    if (status)
        error_counter++;

#endif /* FEATURE_NX_IPV6 */
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       system_state;
ULONG       thread_state;
NX_PACKET  *my_packet[3];
TX_THREAD  *suspension_list;
TX_INTERRUPT_SAVE_AREA

#ifdef __PRODUCT_NETXDUO__
NX_PACKET   *packet_ptr;
NX_TCP_HEADER tcp_header, *tcp_header_ptr;
TX_THREAD  *temp_suspend_thread;
NX_IPV4_HEADER *ipv4_header_ptr;
#ifndef NX_DISABLE_PACKET_CHAIN
UINT        packet_counter;
#endif
#endif /* __PRODUCT_NETXDUO__  */
#if defined FEATURE_NX_IPV6 && !defined NX_DISABLE_ASSERT
UINT        i;
#endif /* NX_DISABLE_ASSERT */


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
    status += nx_tcp_socket_create(&ip_0, &tcp_socket_2, "TCP Socket 2", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                   NX_NULL, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

#ifdef FEATURE_NX_IPV6
    nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, &address_index);
#endif /* FEATURE_NX_IPV6 */
    if (nx_tcp_client_socket_bind(&tcp_socket, 80, 0))
    {
        error_counter++;
    }
    
    /* Test bind again. */
    if (nx_tcp_client_socket_bind(&tcp_socket, 80, 0) != NX_ALREADY_BOUND)
    {
        error_counter++;
    }

    /* Cover true branch of (socket_ptr -> nx_tcp_socket_bind_in_progress). */
    tcp_socket_2.nx_tcp_socket_bind_in_progress = _tx_thread_current_ptr;
    if (nx_tcp_client_socket_bind(&tcp_socket_2, 81, 0) != NX_ALREADY_BOUND)
    {
        error_counter++;
    }
    tcp_socket_2.nx_tcp_socket_bind_in_progress = NX_NULL;
    if (nx_tcp_client_socket_bind(&tcp_socket_2, 81, 0))
    {
        error_counter++;
    }

#if defined FEATURE_NX_IPV6 && !defined NX_DISABLE_ASSERT
    for (i = 0; i < ASSERT_THREAD_COUNT; i++)
    {

        /* Create the assert thread.  */
        tx_thread_create(&thread_for_assert[i], "Assert Test thread", thread_for_assert_entry[i], 0,  
                stack_for_assert[i], DEMO_STACK_SIZE, 
                5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

        /* Let test thread run.  */
        tx_thread_sleep(NX_IP_PERIODIC_RATE);

        /* Terminate the test thread.  */
        tx_thread_terminate(&thread_for_assert[i]);
        tx_thread_delete(&thread_for_assert[i]);
    }
#endif
#ifdef FEATURE_NX_IPV6
    ip_0.nx_ipv6_address[address_index].nxd_ipv6_address_attached = &ip_0.nx_ip_interface[0];
    nxd_ipv6_address_delete(&ip_0, address_index);
#endif /* FEATURE_NX_IPV6 */
    nx_tcp_client_socket_unbind(&tcp_socket);


    /* suspension list is set to NULL. */
    suspension_list = NX_NULL;
    _nx_tcp_socket_thread_resume(&suspension_list, 0);

    /* tx_thread_suspend_control_block is set to NULL. */
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    _nx_tcp_client_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_connect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_transmit_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Test for invalid nx_tcp_socket_id */
    tx_thread_identify() -> tx_thread_suspend_control_block = (VOID*)&tcp_socket;
    tcp_socket.nx_tcp_socket_id = 0;
    _nx_tcp_client_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_connect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_transmit_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;


    TX_DISABLE
    /* Test for Thread state in ISR. */
    tx_thread_identify() -> tx_thread_suspend_control_block = (VOID*)&tcp_socket;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tcp_socket.nx_tcp_socket_connect_suspended_thread = tx_thread_identify();
    tcp_socket.nx_tcp_socket_disconnect_suspended_thread = tx_thread_identify();
    system_state = _tx_thread_system_state;
    _tx_thread_system_state = 1;
    _nx_tcp_client_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_connect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_transmit_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _tx_thread_system_state = 0;
    _tx_thread_system_state = system_state;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    TX_RESTORE
    tx_thread_sleep(1);


    /* tx_thread_suspend_control_block is set to TCP socket but tx_thread_suspend_cleanup is set to NULL. */
    tx_thread_identify() -> tx_thread_suspend_control_block = &tcp_socket;
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    _nx_tcp_client_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_connect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_transmit_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup and tx_thread_suspended_next. */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspended_next = tx_thread_identify();
    tcp_socket.nx_tcp_socket_transmit_suspended_count = 1;
    _nx_tcp_transmit_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspended_next = tx_thread_identify();
    tcp_socket.nx_tcp_socket_receive_suspended_count = 1;
    _nx_tcp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspended_next = tx_thread_identify();
    tcp_socket.nx_tcp_socket_bound_previous = &tcp_socket;
    tcp_socket.nx_tcp_socket_bind_suspended_count = 1;
    _nx_tcp_client_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspended_next = tx_thread_identify();
    _nx_tcp_connect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    
    /* Hit condition of if ((_tx_thread_system_state) || (&(ip_ptr -> nx_ip_thread) != _tx_thread_current_ptr)) in _nx_tcp_packet_receive().  */
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_data_append(my_packet[0], "abcdefghijklmnopqrstuvwxyz", 26, &pool_0, NX_NO_WAIT);

    system_state = _tx_thread_system_state;
    _tx_thread_system_state = 0;

    _nx_tcp_packet_receive(&ip_0, my_packet[0]);
    ip_0.nx_ip_tcp_queue_head =  NX_NULL;
    ip_0.nx_ip_tcp_received_packet_count = 0;

    _tx_thread_system_state = system_state;
    nx_packet_release(my_packet[0]);

    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_data_append(my_packet[0], "abcdefghijklmnopqrstuvwxyz", 26, &pool_0, NX_NO_WAIT);
    system_state = _tx_thread_system_state;
    _tx_thread_system_state = 1;

    _nx_tcp_packet_receive(&ip_0, my_packet[0]);
    ip_0.nx_ip_tcp_queue_head =  NX_NULL;
    ip_0.nx_ip_tcp_received_packet_count = 0;

    _tx_thread_system_state = system_state;
    nx_packet_release(my_packet[0]);
    tx_mutex_put(&(ip_0.nx_ip_protection));


    /* Test _nx_tcp_server_socket_listen()  */
    /* Hit condition:
     143 [ +  - ][ +  + ]:       2428 :     if ((socket_ptr -> nx_tcp_socket_bound_next) ||
     144                 :       2428 :         (socket_ptr -> nx_tcp_socket_bind_in_progress))
    */
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    _nx_tcp_server_socket_listen(&ip_0, 12, &tcp_socket, 5, NX_NULL);
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;


    /* Test _nx_tcp_server_socket_listen()  */
    /* Hit condition:
       144 [ +  + ][ -  + ]:        305 :     if ((socket_ptr -> nx_tcp_socket_bound_next) ||
       145                 :        303 :         (socket_ptr -> nx_tcp_socket_bind_in_progress)).  */
    tcp_socket.nx_tcp_socket_bind_in_progress = tx_thread_identify();
    _nx_tcp_server_socket_listen(&ip_0, 12, &tcp_socket, 5, NX_NULL);
    tcp_socket.nx_tcp_socket_bind_in_progress = NX_NULL;

    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;
    tcp_socket.nx_tcp_socket_bind_in_progress = tx_thread_identify();
    _nx_tcp_server_socket_listen(&ip_0, 12, &tcp_socket, 5, NX_NULL);
    tcp_socket.nx_tcp_socket_bind_in_progress = NX_NULL;


    /* Hit condition of if ((mss > ((if_mtu - ip_header_size) - sizeof(NX_TCP_HEADER))) || (mss == 0)) in _nx_tcp_socket_mss_set.  */
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
#ifdef __PRODUCT_NETXDUO__
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
#endif
    _nx_tcp_socket_mss_set(&tcp_socket, 5);
    _nx_tcp_socket_mss_set(&tcp_socket, 0);


#ifdef __PRODUCT_NETXDUO__
    /* Hit condition of if (socket_ptr -> nx_tcp_socket_disconnect_suspended_thread) in _nx_tcp_socket_state_fin_wait2.  */
    tcp_socket.nx_tcp_socket_fin_received = NX_TRUE;
    tcp_socket.nx_tcp_socket_fin_sequence = tcp_socket.nx_tcp_socket_rx_sequence;
    temp_suspend_thread = tcp_socket.nx_tcp_socket_disconnect_suspended_thread;
    tcp_socket.nx_tcp_socket_disconnect_suspended_thread = NX_NULL;
    _nx_tcp_socket_state_fin_wait2(&tcp_socket);
    tcp_socket.nx_tcp_socket_disconnect_suspended_thread = temp_suspend_thread;


    /* Hit condition of if (amount >= packet_ptr -> nx_packet_length) in _nx_tcp_socket_state_data_trim.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    _nx_tcp_socket_state_data_trim(my_packet[0], 1); 
    _nx_tcp_socket_state_data_trim_front(my_packet[0], 0);
    my_packet[0] -> nx_packet_length = 1;
    _nx_tcp_socket_state_data_trim_front(my_packet[0], 0);
    my_packet[0] -> nx_packet_length = 0;
    _nx_tcp_socket_state_data_trim_front(my_packet[0], 1);
    nx_packet_release(my_packet[0]);
#endif

    /* Test _nx_tcp_connect_cleanup */
    tcp_socket.nx_tcp_socket_id = 1;
    _nx_tcp_connect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);


    /* Test _nx_tcp_disconnect_cleanup().  */
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = &tcp_socket;
    tcp_socket.nx_tcp_socket_id = 0;
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    tcp_socket.nx_tcp_socket_id = 0;
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = &tcp_socket;
    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = &tcp_socket;
    tcp_socket.nx_tcp_socket_id = 0;
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    tcp_socket.nx_tcp_socket_id = 0;
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = &tcp_socket;
    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;
    system_state = _tx_thread_system_state;
    _tx_thread_system_state = 0;
    _nx_tcp_connect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT); 
    _tx_thread_system_state = system_state;

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = &tcp_socket;
    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;
    thread_state = tx_thread_identify() -> tx_thread_state;
    tx_thread_identify() -> tx_thread_state = 0;
    _nx_tcp_disconnect_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT); 
    tx_thread_identify() -> tx_thread_state = thread_state;



    /* Test _nx_tcp_client_socket_unbind().  */
    /* Hit false condition of if (socket_ptr -> nx_tcp_socket_state != NX_TCP_CLOSED)  */
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    _nx_tcp_client_socket_unbind(&tcp_socket);


    /* Test _nx_tcp_socket_disconnect  */
    /* Hit false condition of if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED) &&
                                  (socket_ptr -> nx_tcp_socket_connect_interface != NX_NULL))  */
    tcp_socket.nx_tcp_socket_state = NX_TCP_SYN_SENT;
    tcp_socket.nx_tcp_socket_client_type = NX_FALSE;
    _nx_tcp_socket_disconnect(&tcp_socket, 1);

    /* Hit false condition of (wait_option) && (_tx_thread_current_ptr != &(ip_ptr -> nx_ip_thread)  */
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_receive_suspension_list = &thread_test1;  
    tcp_socket.nx_tcp_socket_receive_suspended_count ++;
    thread_test1.tx_thread_suspend_cleanup = suspend_cleanup;
    thread_test1.tx_thread_suspend_control_block = &tcp_socket; 
    thread_test1.tx_thread_suspended_next = &thread_test1;
    _nx_tcp_socket_disconnect(&tcp_socket, 0);

    /* Recover.  */
    tcp_socket.nx_tcp_socket_receive_suspension_list = NX_NULL;


#ifdef __PRODUCT_NETXDUO__
    /* Hit false condition of (_tx_thread_current_ptr != &(ip_ptr -> nx_ip_thread) in _nx_tcp_socket_disconnect()  */
    ip_0.nx_ip_tcp_fast_periodic_processing = tcp_fast_periodic_processing; 

    /* Let trigger TCP fast periodic notify function.  s*/
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Check the flag.  */
    if (disconnect_flag != NX_TRUE) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif


    /* Test _nx_tcp_server_socket_unaccept()  */
    /* Hit false condition of (socket_ptr -> nx_tcp_socket_state == NX_TCP_CLOSED) && (socket_ptr -> nx_tcp_socket_bound_next))  */
    tcp_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;
    _nx_tcp_server_socket_unaccept(&tcp_socket);

    /* Hit false condition of (ip_ptr -> nx_ip_tcp_port_table[index] == socket_ptr)  */
    tcp_socket.nx_tcp_socket_state = NX_TCP_LISTEN_STATE;
    tcp_socket.nx_tcp_socket_bound_next = &test_socket;
    tcp_socket.nx_tcp_socket_bound_previous = &test_socket; 
    test_socket.nx_tcp_socket_bound_next  = NX_NULL;
    test_socket.nx_tcp_socket_bound_previous  = NX_NULL;
    _nx_tcp_server_socket_unaccept(&tcp_socket);

    /* Hit false condition of if (listen_ptr)  */
    tcp_socket.nx_tcp_socket_state = NX_TCP_LISTEN_STATE;
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;
    tcp_socket.nx_tcp_socket_bound_previous = NX_NULL; 
    _nx_tcp_server_socket_unaccept(&tcp_socket);

    /* Hit false condition of if (listen_ptr -> nx_tcp_listen_socket_ptr == socket_ptr)  */
    tcp_socket.nx_tcp_socket_state = NX_TCP_LISTEN_STATE;
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;
    tcp_socket.nx_tcp_socket_bound_previous = NX_NULL;
    ip_0.nx_ip_tcp_active_listen_requests = &tcp_listen[0];
    tcp_listen[0].nx_tcp_listen_next = &tcp_listen[1];
    tcp_listen[1].nx_tcp_listen_next = &tcp_listen[0];
    _nx_tcp_server_socket_unaccept(&tcp_socket);

    /* Hit condition:
       130 [ +  + ][ +  + ]:       2314 :     if ((socket_ptr -> nx_tcp_socket_state >= NX_TCP_CLOSE_WAIT) ||
       131         [ -  + ]:         54 :         ((socket_ptr -> nx_tcp_socket_state == NX_TCP_CLOSED) && (socket_ptr -> nx_tcp_socket_bound_next)))
     */
    tcp_socket.nx_tcp_socket_state = NX_TCP_CLOSED;     
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    _nx_tcp_server_socket_unaccept(&tcp_socket);

    /* Hit condition
       201         [ +  - ]:          5 :         if (ip_ptr -> nx_ip_tcp_port_table[index] == socket_ptr)
    */
    tcp_socket.nx_tcp_socket_state = NX_TCP_CLOSED;     
    tcp_socket.nx_tcp_socket_bound_next = &test_socket;
    tcp_socket.nx_tcp_socket_bound_previous = &test_socket; 
    test_socket.nx_tcp_socket_bound_next  = NX_NULL;
    test_socket.nx_tcp_socket_bound_previous  = NX_NULL;
    _nx_tcp_server_socket_unaccept(&tcp_socket);
    ip_0.nx_ip_tcp_active_listen_requests = NX_NULL;

#ifdef __PRODUCT_NETXDUO__
    /* Test _nx_tcp_socket_state_syn_received */
    /* Test line: 
     140 [ +  - ][ +  + ]:       2278 :     if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) &&
     141                 :       2278 :         (tcp_header_ptr -> nx_tcp_acknowledgment_number == socket_ptr -> nx_tcp_socket_tx_sequence))
    */                          
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    tcp_socket.nx_tcp_socket_tx_sequence = 10;
    tcp_header.nx_tcp_acknowledgment_number = 9;
    tcp_header.nx_tcp_header_word_3 = 0;
    _nx_tcp_socket_state_syn_received(&tcp_socket, &tcp_header);

    /* Test line:
     235 [ +  - ][ +  - ]:          1 :     else if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) &&
     236                 :          1 :              (tcp_header_ptr -> nx_tcp_acknowledgment_number != socket_ptr -> nx_tcp_socket_tx_sequence))
    */
    tcp_socket.nx_tcp_socket_tx_sequence = 10;
    tcp_header.nx_tcp_acknowledgment_number = 9;
    tcp_header.nx_tcp_header_word_3 = 0;
    _nx_tcp_socket_state_syn_received(&tcp_socket, &tcp_header);

    tcp_socket.nx_tcp_socket_tx_sequence = 10;
    tcp_header.nx_tcp_acknowledgment_number = 9;
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    _nx_tcp_socket_state_syn_received(&tcp_socket, &tcp_header);
    

    /* Test nx_tcp_socket_state_syn_sent.c */
    /* Test line:
     158 [ +  + ][ +  + ]:       2296 :     else if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) &&
     159         [ +  - ]:       2281 :              (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) &&
     160                 :       2281 :              (tcp_header_ptr -> nx_tcp_acknowledgment_number == socket_ptr -> nx_tcp_socket_tx_sequence))

     262 [ +  + ][ +  - ]:         15 :     else if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) &&
     263                 :          3 :              (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)))

    */
    tcp_header.nx_tcp_header_word_3 = NX_TCP_SYN_BIT | NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = 10;
    tcp_socket.nx_tcp_socket_tx_sequence = 9;
    _nx_tcp_socket_state_syn_sent(&tcp_socket, &tcp_header, my_packet[0]);
    
    
    /* Test line:
     310 [ +  - ][ +  + ]:         12 :     else if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) &&
     311                 :         12 :              (tcp_header_ptr -> nx_tcp_acknowledgment_number != socket_ptr -> nx_tcp_socket_tx_sequence))
    */
    tcp_header.nx_tcp_header_word_3 = 0;
    tcp_header.nx_tcp_acknowledgment_number = 10;
    tcp_socket.nx_tcp_socket_rx_sequence = 9;
    _nx_tcp_socket_state_syn_sent(&tcp_socket, &tcp_header, my_packet[0]);    


    /* Test nx_tcp_socket_state_last_ack.c
     117         [ +  - ]:       1188 :     if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)       
    */
    tcp_header.nx_tcp_header_word_3 = 0;
    _nx_tcp_socket_state_last_ack(&tcp_socket, &tcp_header);

    /* 
     121 [ +  + ][ +  - ]:       1188 :         if ((tcp_header_ptr -> nx_tcp_acknowledgment_number == socket_ptr -> nx_tcp_socket_tx_sequence) &&
     122                 :       1187 :             (tcp_header_ptr -> nx_tcp_sequence_number == socket_ptr -> nx_tcp_socket_rx_sequence))
    */

    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = 10;
    tcp_socket.nx_tcp_socket_tx_sequence = 10;
    tcp_header.nx_tcp_sequence_number = 9;
    tcp_socket.nx_tcp_socket_rx_sequence = 8;
    _nx_tcp_socket_state_last_ack(&tcp_socket, &tcp_header);

    /*
     129         [ +  - ]:       1187 :             if (socket_ptr -> nx_tcp_socket_disconnect_suspended_thread)
    */

    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = 10;
    tcp_socket.nx_tcp_socket_tx_sequence = 10;
    tcp_header.nx_tcp_sequence_number = 9;
    tcp_socket.nx_tcp_socket_rx_sequence = 9;
    tcp_socket.nx_tcp_socket_disconnect_suspended_thread = NULL; 
    _nx_tcp_socket_state_last_ack(&tcp_socket, &tcp_header);





    /* Test nx_tcp_socket_receive.c:
     168 [ +  + ][ +  + ]:     116763 :         if ((socket_ptr -> nx_tcp_socket_state < NX_TCP_SYN_SENT)   ||
     169         [ -  + ]:     116749 :             (socket_ptr -> nx_tcp_socket_state == NX_TCP_CLOSE_WAIT) ||
     170                 :     116749 :             (socket_ptr -> nx_tcp_socket_state >= NX_TCP_CLOSING))
    */
    tcp_socket.nx_tcp_socket_state = NX_TCP_CLOSING;
    tcp_socket.nx_tcp_socket_bound_next = &test_socket;
    tcp_socket.nx_tcp_socket_receive_queue_head = NX_NULL;
    _nx_tcp_socket_receive(&tcp_socket, &packet_ptr, 0);
    
    /* Test nx_tcp_server_socket_relisten() 
     174 [ +  + ][ -  + ]:       2078 :     if ((socket_ptr -> nx_tcp_socket_bound_next) ||
     175                 :       2076 :         (socket_ptr -> nx_tcp_socket_bind_in_progress))
    */
    tcp_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    tcp_socket.nx_tcp_socket_bound_next = 0;
    tcp_socket.nx_tcp_socket_bind_in_progress = _tx_thread_current_ptr;
    _nx_tcp_server_socket_relisten(&ip_0, 80, &tcp_socket);

    /* Test nx_tcp_server_socket_accept():
     142 [ +  + ][ +  - ]:       2302 :     if ((socket_ptr -> nx_tcp_socket_state != NX_TCP_LISTEN_STATE) && (socket_ptr -> nx_tcp_socket_state != NX_TCP_SYN_RECEIVED))
    */
    tcp_socket.nx_tcp_socket_state = NX_TCP_SYN_RECEIVED;
    _nx_tcp_server_socket_accept(&tcp_socket, 1);


    /* Test nx_tcp_socket_state_fin_wait1.c:
     132 [ +  + ][ +  - ]:         12 :     else if ((socket_ptr -> nx_tcp_socket_fin_acked) &&
     133         [ +  - ]:          1 :              (socket_ptr -> nx_tcp_socket_fin_received) &&
     134                 :          1 :              (socket_ptr -> nx_tcp_socket_fin_sequence == socket_ptr -> nx_tcp_socket_rx_sequence))       
    */


    tcp_socket.nx_tcp_socket_fin_acked = NX_TRUE;
    tcp_socket.nx_tcp_socket_fin_received = NX_TRUE;
    tcp_socket.nx_tcp_socket_fin_sequence = tcp_socket.nx_tcp_socket_rx_sequence + 1;
    _nx_tcp_socket_state_fin_wait1(&tcp_socket);


    /*
     159         [ +  - ]:          1 :         if (socket_ptr -> nx_tcp_socket_disconnect_suspended_thread)
     168         [ +  - ]:          2 :         if (socket_ptr -> nx_tcp_disconnect_callback)
    */

    tcp_socket.nx_tcp_socket_fin_acked = NX_TRUE;
    tcp_socket.nx_tcp_socket_fin_received = NX_TRUE;
    tcp_socket.nx_tcp_socket_fin_sequence = tcp_socket.nx_tcp_socket_rx_sequence;
    tcp_socket.nx_tcp_socket_disconnect_suspended_thread = NX_NULL;
    tcp_socket.nx_tcp_disconnect_callback = NX_NULL;
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    _nx_tcp_socket_state_fin_wait1(&tcp_socket);

    /*
     197 [ +  + ][ +  - ]:         11 :     else if ((socket_ptr -> nx_tcp_socket_fin_received) &&
     198                 :          1 :              (socket_ptr -> nx_tcp_socket_fin_sequence == socket_ptr -> nx_tcp_socket_rx_sequence))
    */

    tcp_socket.nx_tcp_socket_fin_acked = NX_FALSE;
    tcp_socket.nx_tcp_socket_fin_received = NX_TRUE;
    tcp_socket.nx_tcp_socket_fin_sequence = tcp_socket.nx_tcp_socket_rx_sequence + 1;
    _nx_tcp_socket_state_fin_wait1(&tcp_socket);

    /* Test nx_tcp_socket_state_closing.c 
    118         [ +  - ]:          1 :     if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)
    */
    tcp_header.nx_tcp_header_word_3 = 0;
    _nx_tcp_socket_state_closing(&tcp_socket, &tcp_header);

    /*
    122 [ +  - ][ +  - ]:          1 :         if ((tcp_header_ptr -> nx_tcp_acknowledgment_number == socket_ptr -> nx_tcp_socket_tx_sequence) &&
    123                 :          1 :             (tcp_header_ptr -> nx_tcp_sequence_number == socket_ptr -> nx_tcp_socket_rx_sequence))
    */
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = tcp_socket.nx_tcp_socket_tx_sequence;
    tcp_header.nx_tcp_sequence_number = tcp_socket.nx_tcp_socket_rx_sequence + 1;
    _nx_tcp_socket_state_closing(&tcp_socket, &tcp_header);

    tcp_header.nx_tcp_acknowledgment_number = tcp_socket.nx_tcp_socket_tx_sequence + 1;
    tcp_header.nx_tcp_sequence_number = tcp_socket.nx_tcp_socket_rx_sequence;
    _nx_tcp_socket_state_closing(&tcp_socket, &tcp_header);    

    /*
     140         [ +  - ]:          1 :             if (socket_ptr -> nx_tcp_socket_disconnect_suspended_thread)
     149         [ +  - ]:          1 :             if (socket_ptr -> nx_tcp_disconnect_callback)
    */
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = tcp_socket.nx_tcp_socket_tx_sequence;
    tcp_header.nx_tcp_sequence_number = tcp_socket.nx_tcp_socket_rx_sequence;
    tcp_socket.nx_tcp_socket_disconnect_suspended_thread = NX_NULL;
    tcp_socket.nx_tcp_disconnect_callback = NX_NULL;
    _nx_tcp_socket_state_closing(&tcp_socket, &tcp_header);    

    /* Test nx_tcp_socket_delete.c:
     136 [ +  + ][ +  - ]:       2482 :     if ((socket_ptr -> nx_tcp_socket_bound_next) ||
     137         [ -  + ]:       2477 :         (socket_ptr -> nx_tcp_socket_bind_in_progress) ||
     138                 :       2477 :         (socket_ptr -> nx_tcp_socket_state != NX_TCP_CLOSED))
    */
    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;
    tcp_socket.nx_tcp_socket_bound_next = 0;
    tcp_socket.nx_tcp_socket_bind_in_progress = NX_FALSE;
    tcp_socket.nx_tcp_socket_state = NX_TCP_LISTEN_STATE;
    _nx_tcp_socket_delete(&tcp_socket);

    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;
    tcp_socket.nx_tcp_socket_bound_next = 0;
    tcp_socket.nx_tcp_socket_bind_in_progress = tx_thread_identify();
    tcp_socket.nx_tcp_socket_state = NX_TCP_LISTEN_STATE;
    _nx_tcp_socket_delete(&tcp_socket); 
    tcp_socket.nx_tcp_socket_bind_in_progress = TX_NULL;
    
    /* Test nx_tcp_fast_periodic_processing.c 
     216 [ +  + ][ +  + ]:       2559 :             else if (socket_ptr -> nx_tcp_socket_transmit_sent_head ||
     217         [ +  - ]:        137 :                      ((socket_ptr -> nx_tcp_socket_tx_window_advertised == 0) &&
     218                 :        137 :                       (socket_ptr -> nx_tcp_socket_state <= NX_TCP_CLOSE_WAIT)))
    */
    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;
    tcp_socket.nx_tcp_socket_timeout = _nx_tcp_fast_timer_rate;
    tcp_socket.nx_tcp_socket_state = NX_TCP_FIN_WAIT_2;
    _nx_tcp_fast_periodic_processing(&ip_0);
    
    /* Test nx_tcp_fast_periodic_processing.c 
     231 [ +  + ][ +  + ]:       2374 :             else if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_1) ||
     232         [ -  + ]:       2371 :                      (socket_ptr -> nx_tcp_socket_state == NX_TCP_CLOSING)    ||
     233                 :       2371 :                      (socket_ptr -> nx_tcp_socket_state == NX_TCP_LAST_ACK))
    */
    ip_0.nx_ip_tcp_active_listen_requests = NX_NULL;
    tcp_socket.nx_tcp_socket_timeout = _nx_tcp_fast_timer_rate;
    tcp_socket.nx_tcp_socket_state = NX_TCP_LAST_ACK;
    _nx_tcp_fast_periodic_processing(&ip_0);
    
    /* Test nx_tcp_fast_periodic_processing.c 
     187 [ +  + ][ +  + ]:       2857 :             else if (((socket_ptr -> nx_tcp_socket_timeout_retries >= socket_ptr -> nx_tcp_socket_timeout_max_retries) &&
     188         [ +  + ]:       2856 :                       (socket_ptr -> nx_tcp_socket_zero_window_probe_has_data == NX_FALSE)) ||
     189         [ +  - ]:          4 :                      ((socket_ptr -> nx_tcp_socket_zero_window_probe_failure >= socket_ptr -> nx_tcp_socket_timeout_max_retries) &&
     190                 :          4 :                       (socket_ptr -> nx_tcp_socket_zero_window_probe_has_data == NX_TRUE))
    */
    tcp_socket.nx_tcp_socket_timeout = _nx_tcp_fast_timer_rate;
    tcp_socket.nx_tcp_socket_zero_window_probe_failure = tcp_socket.nx_tcp_socket_timeout_max_retries;
    _nx_tcp_fast_periodic_processing(&ip_0);
    tcp_socket.nx_tcp_socket_zero_window_probe_failure = 0;

    
    /* Test nx_tcp_no_connection_reset.c
     227         [ +  - ]:          9 :         if (tcp_header_ptr -> nx_tcp_header_word_3 & (NX_TCP_SYN_BIT | NX_TCP_FIN_BIT))
     */
    tcp_header.nx_tcp_header_word_3 = 0;
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_ip_version = NX_IP_VERSION_V4;
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    _nx_tcp_no_connection_reset(&ip_0, my_packet[0], &tcp_header);


    /* Test nx_tcp_packet_process.c 
     402         [ +  - ]:    2261852 :                 if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == packet_ptr -> nx_packet_ip_version)
     */
    tcp_socket.nx_tcp_socket_id = NX_TCP_ID;
    tcp_socket.nx_tcp_socket_port = 80;
    tcp_socket.nx_tcp_socket_connect_port = 6206;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V6;
    ip_0.nx_ip_tcp_port_table[80 & NX_TCP_PORT_TABLE_MASK] = &tcp_socket;
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    nx_ip_address_set(&ip_0, IP_ADDRESS(192,168,100,4), 0xFFFFFF00);

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt1) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Test nx_tcp_packet_process.c 
     409         [ +  - ]:    2261688 :                         if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v4 == *source_ip)
     */
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(192,168,100,20);

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt1) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


#ifdef FEATURE_NX_IPV6
    /* Test nx_tcp_packet_process.c 
     415         [ +  - ]:        164 :                     else if (CHECK_IPV6_ADDRESSES_SAME(socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v6, source_ip))
     */
    nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V6;
    tcp_socket.nx_tcp_socket_ipv6_addr = &ip_0.nx_ipv6_address[0];

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt2) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Test nx_tcp_packet_process.c
     442 [ +  - ][ +  - ]:          1 :                             if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) ||
     443                 :          1 :                                 (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT))
     */
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v6[0] = 0xFE800000;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v6[1] = 0;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v6[2] = 0;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v6[3] = 1;

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt3[14], sizeof(pkt3) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt3) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    tcp_socket.nx_tcp_socket_port = 80;
    tcp_socket.nx_tcp_socket_connect_port = 6206;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V6;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v6[0] = 0xFE800000;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v6[1] = 0;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v6[2] = 0;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v6[3] = 1;

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt4[14], sizeof(pkt4) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt4) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     
#endif /* FEATURE_NX_IPV6 */

    ip_0.nx_ip_tcp_port_table[80 & NX_TCP_PORT_TABLE_MASK] = NX_NULL;


    /* Test nx_tcp_packet_process.c
    562 [ +  + ][ +  + ]:       2342 :         if (((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4) && (*source_ip == *dest_ip) && (source_port == port))
                [ +  - ]
    563                 :            : #ifdef FEATURE_NX_IPV6
    564 [ +  + ][ +  + ]:       2342 :             || ((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6) && (CHECK_IPV6_ADDRESSES_SAME(source_ip, dest_ip)) && (source_port == port))
                [ +  - ]
    565                 :            : #endif
    566                 :            :            )
    */
    ip_0.nx_ip_tcp_active_listen_requests = ip_0.nx_ip_tcp_available_listen_requests;

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt5[14], sizeof(pkt5) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt5) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt6[14], sizeof(pkt6) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt6) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Test nx_tcp_packet_process.c
     589         [ +  - ]:       2300 :                 ((*source_ip & NX_IP_CLASS_D_MASK) == NX_IP_CLASS_D_TYPE) ||
     591         [ +  + ]:       2295 :                 (((*source_ip & interface_ptr -> nx_interface_ip_network_mask) == interface_ptr -> nx_interface_ip_network) &&
     592         [ +  + ]:       2299 :                  ((*source_ip & ~(interface_ptr -> nx_interface_ip_network_mask)) == ~(interface_ptr -> nx_interface_ip_network_mask))) ||
     594         [ -  + ]:       2298 :                 (*source_ip == interface_ptr -> nx_interface_ip_network)  ||
     596                 :       2298 :                 (*source_ip == NX_IP_LIMITED_BROADCAST)
    */

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt7[14], sizeof(pkt7) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt7) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt9[14], sizeof(pkt9) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt9) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Test nx_tcp_packet_process.c
     900 [ +  - ][ +  - ]:          6 :                             if ((*queued_source_ip == *source_ip) && (queued_source_port == source_port)) 
    */
    ip_0.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_port = 80;
    ip_0.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_queue_current = 0;
    ip_0.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_socket_ptr = NX_NULL;
    ip_0.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_queue_maximum = 5;

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt10[14], sizeof(pkt10) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt10) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt11[14], sizeof(pkt11) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt11) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Test nx_tcp_packet_process.c
     677 [ +  + ][ +  - ]:       2335 :                 if ((listen_ptr -> nx_tcp_listen_socket_ptr) &&
     678                 :       2284 :                     ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT) == NX_NULL))
    */
    ip_0.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_port = 80;
    ip_0.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_socket_ptr = &tcp_socket;

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt8[14], sizeof(pkt8) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt8) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Test nx_tcp_packet_process.c
     983         [ +  - ]:          7 :                             if (queued_ptr == listen_ptr -> nx_tcp_listen_queue_tail)
    */
    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt14[14], sizeof(pkt14) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt14) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Test nx_tcp_packet_process.c
     934 [ +  + ][ +  - ]:         52 :                             if ((CHECK_IPV6_ADDRESSES_SAME(queued_source_ip, source_ip)) && (queued_source_port == source_port))
    */
    ip_0.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_socket_ptr = NX_NULL;

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt12[14], sizeof(pkt12) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt12) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt13[14], sizeof(pkt13) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt13) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Test nx_tcp_no_connection_reset:
     227         [ +  - ]:          9 :         if (tcp_header_ptr -> nx_tcp_header_word_3 & (NX_TCP_SYN_BIT | NX_TCP_FIN_BIT))
    */
    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt8[14], sizeof(pkt8) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt8) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr;
    packet_ptr -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    tcp_header.nx_tcp_header_word_3 = 0;
    _nx_tcp_no_connection_reset(&ip_0, packet_ptr, &tcp_header);
    /* Do not release this packet. We will reuse it in the next test case. */

    /* Test nx_tcp_server_socket_relisten.c:
     187                 :       2076 :     listen_ptr =  ip_ptr -> nx_ip_tcp_active_listen_requests;
     188         [ +  - ]:       2076 :     if (listen_ptr)
    */
    tcp_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;
    tcp_socket.nx_tcp_socket_bind_in_progress = 0;
    ip_0.nx_ip_tcp_active_listen_requests = NX_NULL;
    _nx_tcp_server_socket_relisten(&ip_0, 80, &tcp_socket);

    /*
     246         [ +  - ]:          9 :                     if (packet_ptr == listen_ptr -> nx_tcp_listen_queue_tail)
    */

    ip_0.nx_ip_tcp_active_listen_requests = &tcp_listen[0];
    tcp_listen[0].nx_tcp_listen_next = NX_NULL;
    tcp_listen[0].nx_tcp_listen_port = 80;
    tcp_listen[0].nx_tcp_listen_socket_ptr = NX_NULL;
    tcp_listen[0].nx_tcp_listen_queue_current = 1;
    tcp_listen[0].nx_tcp_listen_queue_head = packet_ptr;
    tcp_listen[0].nx_tcp_listen_queue_tail = NX_NULL;
    tcp_listen[0].nx_tcp_listen_callback = NX_NULL;
    packet_ptr -> nx_packet_queue_next = NX_NULL;
    tcp_header_ptr = (NX_TCP_HEADER*)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_3  = 0;
    _nx_tcp_server_socket_relisten(&ip_0, 80, &tcp_socket);

    /* 262         [ +  - ]:          9 :                         if (option_words > 0) */

    /* Inject TCP packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt8[14], sizeof(pkt8) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt8) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr;
    packet_ptr -> nx_packet_address.nx_packet_interface_ptr = NX_NULL;
    tcp_header.nx_tcp_header_word_3 = 0;    
    
    ip_0.nx_ip_tcp_active_listen_requests = &tcp_listen[0];
    tcp_listen[0].nx_tcp_listen_next = NX_NULL;
    tcp_listen[0].nx_tcp_listen_port = 80;
    tcp_listen[0].nx_tcp_listen_socket_ptr = NX_NULL;
    tcp_listen[0].nx_tcp_listen_queue_current = 1;
    tcp_listen[0].nx_tcp_listen_queue_head = packet_ptr;
    tcp_listen[0].nx_tcp_listen_queue_tail = NX_NULL;
    tcp_listen[0].nx_tcp_listen_callback = NX_NULL;
    packet_ptr -> nx_packet_queue_next = NX_NULL;
    tcp_header_ptr = (NX_TCP_HEADER*)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_3  = NX_TCP_SYN_BIT | (5 << 28);
    _nx_tcp_server_socket_relisten(&ip_0, 80, &tcp_socket);

    ip_0.nx_ip_tcp_active_listen_requests = NX_NULL;


    /* Test _nx_tcp_socket_state_transmit_check()  */
    /* Hit condition:  
       169 [ +  + ][ +  - ]:        332 :         if ((tx_window_current) &&
       170                 :        262 :             (socket_ptr -> nx_tcp_socket_transmit_sent_count < socket_ptr -> nx_tcp_socket_transmit_queue_maximum))  */
    /* suspension list is set to NULL. */               
    tcp_socket.nx_tcp_socket_transmit_suspension_list = &thread_test1;
    tcp_socket.nx_tcp_socket_tx_window_advertised = 100;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 100;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 10;
    tcp_socket.nx_tcp_socket_transmit_queue_maximum = 5;
    _nx_tcp_socket_state_transmit_check(&tcp_socket);  
    tcp_socket.nx_tcp_socket_transmit_suspension_list = TX_NULL;  
    tcp_socket.nx_tcp_socket_tx_window_advertised = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 0;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 0;
    tcp_socket.nx_tcp_socket_transmit_queue_maximum = 0x14;

    /* Test _nx_tcp_socket_state_transmit_check() */
    /* Hit condition of if (socket_ptr -> nx_tcp_socket_duplicated_ack_received == 2) */
    tcp_socket.nx_tcp_socket_transmit_suspension_list = &thread_test1;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 100;
    tcp_socket.nx_tcp_socket_tx_window_advertised = tcp_socket.nx_tcp_socket_tx_window_congestion + 10;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 2;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 10;
    tcp_socket.nx_tcp_socket_transmit_queue_maximum = 5;
    _nx_tcp_socket_state_transmit_check(&tcp_socket);
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 0;
    _nx_tcp_socket_state_transmit_check(&tcp_socket);
    tcp_socket.nx_tcp_socket_transmit_suspension_list = TX_NULL;  
    tcp_socket.nx_tcp_socket_tx_window_advertised = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 0;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 0;
    tcp_socket.nx_tcp_socket_transmit_queue_maximum = 0x14;


    /* Test nx_tcp_server_socket_accept():
       222 [ +  + ][ +  - ]:       2302 :     if ((wait_option) && (_tx_thread_current_ptr != &(ip_ptr -> nx_ip_thread)))
    */
    ip_0.nx_ip_tcp_queue_process = my_tcp_queue_process;

    /* Wakeup IP thread for processing one or more messages in the TCP queue.  */
    tx_event_flags_set(&(ip_0.nx_ip_events), NX_IP_TCP_EVENT, TX_OR);

    /* Let IP thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    ip_0.nx_ip_tcp_queue_process = _nx_tcp_queue_process;



    /* Test _nx_tcp_server_socket_relisten():
       262         [ +  - ]:          9 :                         if (option_words > 0)
    */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    /* Skip ipv4 header.  */
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr;
    ipv4_header_ptr = (NX_IPV4_HEADER *)my_packet[0] -> nx_packet_ip_header;
    ipv4_header_ptr -> nx_ip_header_source_ip = 0x01020305; 
    ipv4_header_ptr -> nx_ip_header_destination_ip = 0x01020304;
    my_packet[0] -> nx_packet_prepend_ptr += 20;
    my_packet[0] -> nx_packet_ip_version = NX_IP_VERSION_V4;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 20;
    my_packet[0] -> nx_packet_length = 20; 
    tcp_header_ptr = (NX_TCP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_0 = (0x1235 << NX_SHIFT_BY_16) | 0x1234;
    tcp_header_ptr -> nx_tcp_acknowledgment_number = 1;
    tcp_header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_SYN_BIT | tcp_socket.nx_tcp_socket_rx_window_current;
    tcp_header_ptr -> nx_tcp_header_word_4 =        0;
    tcp_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;
    tcp_listen[0].nx_tcp_listen_port = 0x1234;
    tcp_listen[0].nx_tcp_listen_socket_ptr = NX_NULL;
    tcp_listen[0].nx_tcp_listen_queue_current = 1;  
    tcp_listen[0].nx_tcp_listen_queue_head  = my_packet[0];
    tcp_listen[0].nx_tcp_listen_queue_tail = my_packet[0];
    ip_0.nx_ip_tcp_active_listen_requests = &tcp_listen[0];
    _nx_tcp_server_socket_relisten(&ip_0, 0x1234, &tcp_socket);
    ip_0.nx_ip_tcp_active_listen_requests = NX_NULL;
    ip_0.nx_ip_tcp_port_table[6] = NX_NULL;
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;
    tcp_socket.nx_tcp_socket_bound_previous = NX_NULL;
    ip_0.nx_ip_tcp_active_listen_requests = NX_NULL;


    /* Test _nx_tcp_socket_retransmit()  */
    /* Hit condition:
       212 [ +  - ][ +  - ]:        159 :     while (packet_ptr && (packet_ptr -> nx_packet_queue_next == (NX_PACKET *)NX_DRIVER_TX_DONE))
    */
    tcp_socket.nx_tcp_socket_tx_window_advertised = 65535;
    tcp_socket.nx_tcp_socket_transmit_sent_head = NX_NULL;
    _nx_tcp_socket_retransmit(&ip_0, &tcp_socket, NX_FALSE);

    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);        
    tcp_socket.nx_tcp_socket_tx_window_advertised = 65535;
    tcp_socket.nx_tcp_socket_transmit_sent_head = my_packet[0];
    my_packet[0] -> nx_packet_queue_next = NX_NULL;
    _nx_tcp_socket_retransmit(&ip_0, &tcp_socket, NX_FALSE);
    nx_packet_release(my_packet[0]);

    /* Hit condition:
       315 [ +  + ][ +  - ]:        158 :         if ((header_ptr -> nx_tcp_acknowledgment_number == original_acknowledgment_number) &&
       316         [ +  + ]:        152 :             (header_ptr -> nx_tcp_header_word_3 == original_header_word_3) &&
       317                 :        152 :             (header_ptr -> nx_tcp_header_word_4 == original_header_word_4))
    */   
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 20;
    my_packet[0] -> nx_packet_length = 20; 
    tcp_header_ptr = (NX_TCP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_0 = (0x1235 << NX_SHIFT_BY_16) | 0x1234;
    tcp_header_ptr -> nx_tcp_acknowledgment_number = tcp_socket.nx_tcp_socket_rx_sequence;
    tcp_header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_SYN_BIT | tcp_socket.nx_tcp_socket_rx_window_current;
    tcp_header_ptr -> nx_tcp_header_word_4 =        0;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_0); 
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
    tcp_socket.nx_tcp_socket_tx_window_advertised = 65535;
    tcp_socket.nx_tcp_socket_transmit_sent_head = my_packet[0];
    my_packet[0] -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    my_packet[0] -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    _nx_tcp_socket_retransmit(&ip_0, &tcp_socket, NX_FALSE);            
    my_packet[0] -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *) NX_PACKET_ALLOCATED;
    nx_packet_release(my_packet[0]);

    /* Hit condition:
       355 [ +  + ][ +  + ]:        488 :         if ((header_ptr -> nx_tcp_acknowledgment_number == original_acknowledgment_number) &&
       356         [ +  - ]:        462 :             (header_ptr -> nx_tcp_header_word_3 == original_header_word_3) &&
       357                 :        462 :             (header_ptr -> nx_tcp_header_word_4 == original_header_word_4))
    */   
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 20;
    my_packet[0] -> nx_packet_length = 20; 
    tcp_header_ptr = (NX_TCP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_0 = (0x1235 << NX_SHIFT_BY_16) | 0x1234;
    tcp_header_ptr -> nx_tcp_acknowledgment_number = tcp_socket.nx_tcp_socket_rx_sequence;
    tcp_header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | NX_TCP_PSH_BIT | tcp_socket.nx_tcp_socket_rx_window_current;
    tcp_header_ptr -> nx_tcp_header_word_4 =        0xFFFF0000;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_0); 
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
    tcp_socket.nx_tcp_socket_tx_window_advertised = 65535;
    tcp_socket.nx_tcp_socket_transmit_sent_head = my_packet[0];
    my_packet[0] -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    my_packet[0] -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    _nx_tcp_socket_retransmit(&ip_0, &tcp_socket, NX_FALSE);            
    my_packet[0] -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *) NX_PACKET_ALLOCATED;
    nx_packet_release(my_packet[0]);



    /* Test _nx_tcp_socket_receive() */
    /* Hit condition:
       262 [ +  + ][ +  + ]:      19398 :         if (((socket_ptr -> nx_tcp_socket_rx_window_current - socket_ptr -> nx_tcp_socket_rx_window_last_sent) >= (socket_ptr -> nx_tcp_socket_rx_window_default / 2)) &&
       263 [ +  - ][ -  + ]:          3 :             ((socket_ptr -> nx_tcp_socket_state == NX_TCP_ESTABLISHED) || (socket_ptr -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_1) || (socket_ptr -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_2)))
    */                                      
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_queue_next = ((NX_PACKET *)NX_PACKET_READY);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 20;
    my_packet[0] -> nx_packet_length = 20; 
    tcp_header_ptr = (NX_TCP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_0 = (0x1235 << NX_SHIFT_BY_16) | 0x1234;
    tcp_header_ptr -> nx_tcp_acknowledgment_number = tcp_socket.nx_tcp_socket_rx_sequence;
    tcp_header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_SYN_BIT | tcp_socket.nx_tcp_socket_rx_window_current;
    tcp_header_ptr -> nx_tcp_header_word_4 =        0;
    tcp_socket.nx_tcp_socket_state = NX_TCP_FIN_WAIT_1;
    tcp_socket.nx_tcp_socket_receive_queue_head = my_packet[0];
    tcp_socket.nx_tcp_socket_bound_next = &test_socket;
    tcp_socket.nx_tcp_socket_receive_queue_count ++;
    tcp_socket.nx_tcp_socket_rx_window_last_sent = 0;
    _nx_tcp_socket_receive(&tcp_socket, &packet_ptr, NX_NO_WAIT);
    nx_packet_release(packet_ptr);
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;

    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_queue_next = ((NX_PACKET *)NX_PACKET_READY);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 20;
    my_packet[0] -> nx_packet_length = 20; 
    tcp_header_ptr = (NX_TCP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_0 = (0x1235 << NX_SHIFT_BY_16) | 0x1234;
    tcp_header_ptr -> nx_tcp_acknowledgment_number = tcp_socket.nx_tcp_socket_rx_sequence;
    tcp_header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_SYN_BIT | tcp_socket.nx_tcp_socket_rx_window_current;
    tcp_header_ptr -> nx_tcp_header_word_4 =        0;
    tcp_socket.nx_tcp_socket_state = NX_TCP_FIN_WAIT_2;
    tcp_socket.nx_tcp_socket_receive_queue_head = my_packet[0];
    tcp_socket.nx_tcp_socket_bound_next = &test_socket;
    tcp_socket.nx_tcp_socket_receive_queue_count ++;
    tcp_socket.nx_tcp_socket_rx_window_last_sent = 0;
    _nx_tcp_socket_receive(&tcp_socket, &packet_ptr, NX_NO_WAIT);
    nx_packet_release(packet_ptr);
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;



    /* Test _nx_tcp_socket_send_internal()  */

#ifndef NX_DISABLE_PACKET_CHAIN
    /* Hit condition:       
       377 [ +  + ][ +  + ]:     125717 :             else if ((packet_ptr -> nx_packet_next != NX_NULL) &&
       378         [ +  - ]:       6631 :                      ((packet_ptr -> nx_packet_length + data_offset) < pool_ptr -> nx_packet_pool_payload_size) &&
       379                 :       6631 :                      (pool_ptr -> nx_packet_pool_available > 0))
    */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_TCP_PACKET, NX_NO_WAIT); 
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 20;
    my_packet[0] -> nx_packet_length = 40; 
    nx_packet_allocate(&pool_0, &my_packet[1], NX_TCP_PACKET, NX_NO_WAIT);
    my_packet[1] -> nx_packet_append_ptr = my_packet[1] -> nx_packet_prepend_ptr + 20;
    my_packet[1] -> nx_packet_length = 20;
    my_packet[0] -> nx_packet_next = my_packet[1];
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    packet_counter = pool_0.nx_packet_pool_available;
    pool_0.nx_packet_pool_available = 0;
    tcp_socket.nx_tcp_socket_transmit_sent_head = NX_NULL;
    _nx_tcp_socket_send_internal(&tcp_socket, my_packet[0], 1);
    pool_0.nx_packet_pool_available = packet_counter;

    
    /* Hit condition:       
       391 [ +  - ][ +  + ]:          5 :                 while ((current_packet != NX_NULL) && (current_packet -> nx_packet_prepend_ptr == current_packet -> nx_packet_append_ptr))

       399         [ -  + ]:          2 :                 NX_ASSERT(current_packet != NX_NULL);
    */                   

#ifndef NX_DISABLE_ASSERT
    /* Create the assert thread.  */
    tx_thread_create(&thread_for_assert_1, "Assert Test thread", thread_for_assert_entry_1, 0,
                     stack_for_assert_1, DEMO_STACK_SIZE,
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert_1);
    tx_thread_delete(&thread_for_assert_1);
#endif /* NX_DISABLE_ASSERT  */


    /* Hit condition: 
       454         [ +  - ]:          1 :                     if (preempted == NX_TRUE)
    */                                                   
    nx_packet_allocate(&pool_0, &my_packet[0], NX_TCP_PACKET, NX_NO_WAIT); 
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 20;
    my_packet[0] -> nx_packet_length = 40;
    tcp_socket.nx_tcp_socket_tx_window_advertised = tcp_socket.nx_tcp_socket_tx_outstanding_bytes + 30; 
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    packet_counter = pool_0.nx_packet_pool_available;
    tcp_socket.nx_tcp_socket_transmit_sent_head = NX_NULL;
    packet_counter = pool_0.nx_packet_pool_available;
    pool_0.nx_packet_pool_available = 0;
    _nx_tcp_socket_send_internal(&tcp_socket, my_packet[0], 1);
    pool_0.nx_packet_pool_available = packet_counter;
    tcp_socket.nx_tcp_socket_tx_window_advertised = 65535;

    /* Hit condition: 
       490         [ +  - ]:          2 :                     if (preempted == NX_TRUE)
    */                                                   
    nx_packet_allocate(&pool_0, &my_packet[0], NX_TCP_PACKET, NX_NO_WAIT);                  
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr;
    my_packet[0] -> nx_packet_length = 40; 
    tcp_socket.nx_tcp_socket_tx_window_advertised = tcp_socket.nx_tcp_socket_tx_outstanding_bytes + 30; 
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    packet_counter = pool_0.nx_packet_pool_available;
    tcp_socket.nx_tcp_socket_transmit_sent_head = NX_NULL;
    _nx_tcp_socket_send_internal(&tcp_socket, my_packet[0], 0);
    tcp_socket.nx_tcp_socket_tx_window_advertised = 65535;

    /* Hit condition: 
       550         [ +  - ]:          1 :                             if (preempted == NX_TRUE)
    */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_TCP_PACKET, NX_NO_WAIT);                  
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr;
    my_packet[0] -> nx_packet_length = 400;  
    nx_packet_allocate(&pool_0, &my_packet[1], NX_TCP_PACKET, NX_NO_WAIT);
    my_packet[1] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_data_end;
    my_packet[1] -> nx_packet_length = 200;
    my_packet[0] -> nx_packet_next = my_packet[1];
    nx_packet_allocate(&pool_0, &my_packet[2], NX_TCP_PACKET, NX_NO_WAIT);
    my_packet[2] -> nx_packet_append_ptr = my_packet[2] -> nx_packet_data_end;
    my_packet[2] -> nx_packet_length = 200;
    my_packet[1] -> nx_packet_next = my_packet[2];
    tcp_socket.nx_tcp_socket_tx_window_advertised = tcp_socket.nx_tcp_socket_tx_outstanding_bytes + 300; 
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    packet_counter = pool_0.nx_packet_pool_available;
    pool_0.nx_packet_pool_available = 1;
    tcp_socket.nx_tcp_socket_transmit_sent_head = NX_NULL;
    tcp_socket.nx_tcp_socket_connect_mss = 536;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 536;
    _nx_tcp_socket_send_internal(&tcp_socket, my_packet[0], 0);
    pool_0.nx_packet_pool_available = packet_counter;
    tcp_socket.nx_tcp_socket_tx_window_advertised = 65535;  
    tcp_socket.nx_tcp_socket_connect_mss = 216;
#endif /* NX_DISABLE_PACKET_CHAIN  */

    /* Hit condition:
       344 [ -  + ]:         10 :                 if (tx_window_current > socket_ptr -> nx_tcp_socket_tx_window_advertised)
    */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_TCP_PACKET, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 20;
    my_packet[0] -> nx_packet_length = 20;
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 100;
    tcp_socket.nx_tcp_socket_tx_window_advertised = 200;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 2;
    tcp_socket.nx_tcp_socket_connect_mss = 0x218;
    tcp_socket.nx_tcp_socket_transmit_sent_head = NX_NULL;
    _nx_tcp_socket_send_internal(&tcp_socket, my_packet[0], 1);
    tcp_socket.nx_tcp_socket_tx_window_congestion = 0x218;
    tcp_socket.nx_tcp_socket_tx_window_advertised = 0xffff;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 0;
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;

    /* Test nx_tcp_socket_state_ack_check.c */
    ack_check_test();

    /* Test nx_tcp_socket_state_data_check.c */
    data_check_test();

    /* Test nx_tcp_socket_packet_process.c */
    socket_packet_process_test();
#endif


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

static VOID    suspend_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER)
{
}

#ifdef __PRODUCT_NETXDUO__
static VOID    tcp_fast_periodic_processing(NX_IP *ip_ptr)
{
NXD_ADDRESS server_ip;
UINT        status;

    /* Check the flag.  */
    if (disconnect_flag == NX_FALSE)
    {

        /* Update the flag.  */
        disconnect_flag = NX_TRUE;

        /* Set the condition.  */
        tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
        tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4; 
        tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
        tcp_socket.nx_tcp_socket_next_hop_address = IP_ADDRESS(1, 2, 3, 5);
        _nx_tcp_socket_disconnect(&tcp_socket, 1);    

        /* Recover.  */
        ip_0.nx_ip_tcp_fast_periodic_processing = _nx_tcp_fast_periodic_processing;

        /* Connect to addrss not reachable. */
        server_ip.nxd_ip_version = NX_IP_VERSION_V4;
        server_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 6);
        status = nxd_tcp_client_socket_connect(&tcp_socket_2, &server_ip, 80, 1);
        if (status != NX_IN_PROGRESS)
        {
            error_counter++;
        }
    }
}

static VOID    my_tcp_queue_process(NX_IP *ip_ptr)
{
NX_PACKET   *packet_ptr;

    /* Test nx_tcp_server_socket_accept():
       222 [ +  + ][ +  - ]:       2302 :     if ((wait_option) && (_tx_thread_current_ptr != &(ip_ptr -> nx_ip_thread)))
       */
    tcp_socket.nx_tcp_socket_state = NX_TCP_SYN_RECEIVED;
    _nx_tcp_server_socket_accept(&tcp_socket, 1);


    /* Test _nx_tcp_socket_receive() */
    /*
    283 [ +  + ][ +  - ]:     118586 :     else if ((wait_option) && (_tx_thread_current_ptr != &(ip_ptr -> nx_ip_thread)))
    */                 
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_receive_queue_head = NX_NULL;
    tcp_socket.nx_tcp_socket_bound_next = &test_socket;
    _nx_tcp_socket_receive(&tcp_socket, &packet_ptr, 1);
    tcp_socket.nx_tcp_socket_bound_next = NX_NULL;


    /* Test _nx_tcp_socket_send_internal()  */
    /* Hit condition:  
       867 [ +  + ][ +  - ]:        281 :         else if ((wait_option) && (_tx_thread_current_ptr != &(ip_ptr -> nx_ip_thread)))
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);                  
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + 20;
    packet_ptr -> nx_packet_length = 20;  
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    tcp_socket.nx_tcp_socket_transmit_sent_head = NX_NULL;
    _nx_tcp_socket_send_internal(&tcp_socket, packet_ptr, 1);
    tcp_socket.nx_tcp_socket_connect_mss = 216;
    nx_packet_release(packet_ptr);
}


static VOID    ack_check_test()
{
NX_TCP_HEADER   tcp_header;
NX_TCP_HEADER  *tcp_header_ptr;
NX_PACKET      *packet_ptr;

    /* Test nx_tcp_socket_state_ack_check.c
     283 [ +  - ][ +  - ]:         14 :                         else if ((socket_ptr -> nx_tcp_socket_tx_window_congestion > socket_ptr -> nx_tcp_socket_connect_mss) &&
     284                 :         28 :                                  ((INT)(tcp_header_ptr -> nx_tcp_acknowledgment_number - (socket_ptr -> nx_tcp_socket_previous_highest_ack +
     285                 :         14 :                                                                                           (socket_ptr -> nx_tcp_socket_connect_mss << 2))) < 0))
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr - 20;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = 0;
    tcp_socket.nx_tcp_socket_tx_sequence = 1;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 2;
    tcp_socket.nx_tcp_socket_tx_sequence_recover = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 1000;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_transmit_sent_head = packet_ptr;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 1;
    tcp_socket.nx_tcp_socket_tx_sequence = 20;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 20;
    _nx_tcp_socket_state_ack_check(&tcp_socket, &tcp_header);

    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr - 20;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = 0;
    tcp_socket.nx_tcp_socket_tx_sequence = 1;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 2;
    tcp_socket.nx_tcp_socket_tx_sequence_recover = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 1500;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_transmit_sent_head = packet_ptr;
    tcp_socket.nx_tcp_socket_previous_highest_ack = 0xFFFF0000;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 1;
    tcp_socket.nx_tcp_socket_tx_sequence = 20;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 20;
    _nx_tcp_socket_state_ack_check(&tcp_socket, &tcp_header);

    /* Test nx_tcp_socket_state_ack_check.c
     295 [ +  + ][ +  - ]:         38 :                     else if ((socket_ptr -> nx_tcp_socket_duplicated_ack_received > 3) &&
     296                 :          1 :                              (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE))
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr - 20;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = 0;
    tcp_socket.nx_tcp_socket_tx_sequence = 1;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 4;
    tcp_socket.nx_tcp_socket_tx_sequence_recover = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 1000;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_transmit_sent_head = packet_ptr;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 1;
    tcp_socket.nx_tcp_socket_fast_recovery = NX_FALSE;
    tcp_socket.nx_tcp_socket_tx_sequence = 20;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 20;
    _nx_tcp_socket_state_ack_check(&tcp_socket, &tcp_header);

    /* Test nx_tcp_socket_state_ack_check.c
     295 [ +  + ][ -  + ]:         38 :                     else if ((socket_ptr -> nx_tcp_socket_duplicated_ack_received > 3) &&
     296                 :          1 :                              (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE))
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr - 20;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = 0;
    tcp_socket.nx_tcp_socket_tx_sequence = 1;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 4;
    tcp_socket.nx_tcp_socket_tx_sequence_recover = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 1000;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_transmit_sent_head = packet_ptr;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 1;
    tcp_socket.nx_tcp_socket_fast_recovery = NX_TRUE;
    tcp_socket.nx_tcp_socket_tx_sequence = 20;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 20;
    _nx_tcp_socket_state_ack_check(&tcp_socket, &tcp_header);


    /* Test nx_tcp_socket_state_ack_check.c
     727 [ +  + ][ +  - ]:      44949 :             if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_1) ||
     728         [ +  + ]:      44892 :                 (socket_ptr -> nx_tcp_socket_state == NX_TCP_CLOSING)    ||
     729                 :      44892 :                 (socket_ptr -> nx_tcp_socket_state == NX_TCP_LAST_ACK))
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr - 20;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_acknowledgment_number = 0;
    tcp_socket.nx_tcp_socket_tx_sequence = 0;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 4;
    tcp_socket.nx_tcp_socket_tx_sequence_recover = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 1000;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_transmit_sent_head = packet_ptr;
    tcp_socket.nx_tcp_socket_transmit_sent_tail = packet_ptr;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 1;
    tcp_socket.nx_tcp_socket_state = NX_TCP_CLOSING;
    _nx_tcp_socket_state_ack_check(&tcp_socket, &tcp_header);

    /* Test nx_tcp_socket_state_ack_check.c
     479         [ -  + ]:         12 :                             if (tcp_header_ptr -> nx_tcp_acknowledgment_number < ending_packet_sequence)
     480                 :            :                             {
     481                 :            : 
     482                 :            :                                 / * ACK does not cover the search packet. Break out of the loop.  * /
     483                 :          0 :                                 break;
     484                 :            :                             }
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr - 20;
    packet_ptr -> nx_packet_length = 20;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_sequence_number = 0xEEEEEEEE;
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_sequence_number = 0;
    tcp_header.nx_tcp_acknowledgment_number = 0;
    tcp_socket.nx_tcp_socket_tx_sequence = 4;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 0;
    tcp_socket.nx_tcp_socket_tx_sequence_recover = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 1000;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_transmit_sent_head = packet_ptr;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 1;
    tcp_socket.nx_tcp_socket_fast_recovery = NX_FALSE;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 20;
    _nx_tcp_socket_state_ack_check(&tcp_socket, &tcp_header);

    /* Test nx_tcp_socket_state_ack_check.c
     500         [ +  - ]:          9 :                         if (tcp_header_ptr -> nx_tcp_acknowledgment_number >= starting_tx_sequence)
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr - 20;
    packet_ptr -> nx_packet_length = 10;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_sequence_number = 0xFFFFFFF0;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_sequence_number = 0;
    tcp_header.nx_tcp_acknowledgment_number = 0;
    tcp_socket.nx_tcp_socket_tx_sequence = 4;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 0;
    tcp_socket.nx_tcp_socket_tx_sequence_recover = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 1000;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_transmit_sent_head = packet_ptr;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 1;
    tcp_socket.nx_tcp_socket_fast_recovery = NX_FALSE;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 20;
    _nx_tcp_socket_state_ack_check(&tcp_socket, &tcp_header);

    /* Test nx_tcp_socket_state_ack_check.c
     679 [ +  + ][ -  + ]:     164665 :         if ((((INT)tcp_header_ptr -> nx_tcp_acknowledgment_number - (INT)starting_tx_sequence > 0) &&
     680         [ +  + ]:     125179 :              ((INT)tcp_header_ptr -> nx_tcp_acknowledgment_number - (INT)ending_tx_sequence <= 0)) ||
     681         [ +  + ]:     118418 :             ((INT)tcp_header_ptr -> nx_tcp_sequence_number - (INT)ending_rx_sequence > 0) ||
     682         [ +  + ]:     112183 :             (((INT)tcp_header_ptr -> nx_tcp_sequence_number == (INT)ending_rx_sequence) &&
     683                 :     112183 :              ((INT)tcp_header_ptr -> nx_tcp_acknowledgment_number - (INT)starting_tx_sequence >= 0)))
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr - 20;
    packet_ptr -> nx_packet_length = 10;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_sequence_number = 0;
    tcp_header.nx_tcp_acknowledgment_number = 20;
    tcp_socket.nx_tcp_socket_tx_sequence = 4;
    tcp_socket.nx_tcp_socket_duplicated_ack_received = 0;
    tcp_socket.nx_tcp_socket_tx_sequence_recover = 0;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 1000;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_transmit_sent_head = packet_ptr;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 1;
    tcp_socket.nx_tcp_socket_fast_recovery = NX_FALSE;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 20;
    _nx_tcp_socket_state_ack_check(&tcp_socket, &tcp_header);

    /* Test nx_tcp_socket_state_ack_check.c
     [+ -] 114 if (search_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_queue_next = (NX_PACKET *)NX_DRIVER_TX_DONE;
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_ip_version = 0;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr - 20;
    packet_ptr -> nx_packet_length = 10;
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;
    tcp_header.nx_tcp_sequence_number = 0;
    tcp_header.nx_tcp_acknowledgment_number = 0;
    tcp_socket.nx_tcp_socket_tx_sequence = 4;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 0;
    tcp_socket.nx_tcp_socket_receive_queue_tail = packet_ptr;
    _nx_tcp_socket_state_ack_check(&tcp_socket, &tcp_header);
}

static VOID    data_check_test()
{
NX_TCP_HEADER  *tcp_header_ptr;
NX_PACKET      *packet_ptr;

    /* Test nx_tcp_socket_state_data_check.c
     729         [ +  - ]:        185 :         while (search_ptr)
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next = NX_NULL;
    packet_ptr -> nx_packet_length = 30;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_3 = 0x50000000;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    tcp_socket.nx_tcp_socket_receive_queue_head = packet_ptr;
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_length = 30;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_3 = 0x50000000;
    tcp_header_ptr -> nx_tcp_sequence_number = 20;
    tcp_socket.nx_tcp_socket_rx_sequence = 0;
    _nx_tcp_socket_state_data_check(&tcp_socket, packet_ptr);

}

static VOID    socket_packet_process_test()
{
NX_TCP_HEADER  *tcp_header_ptr;
NX_PACKET      *packet_ptr;

    /* Test nx_tcp_socket_packet_process.c
     210 [ +  + ][ +  + ]:          3 :                 else if ((tcp_header_copy.nx_tcp_header_word_3 & NX_TCP_RST_BIT) ||
     211         [ +  - ]:          1 :                          (tcp_header_copy.nx_tcp_header_word_3 & NX_TCP_URG_BIT) ||
     212                 :          1 :                          ((tcp_header_copy.nx_tcp_header_word_3 & NX_TCP_CONTROL_MASK) == NX_TCP_ACK_BIT))
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_length = 20;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_3 = 0x50000000;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    tcp_socket.nx_tcp_socket_rx_window_current = 0;
    tcp_socket.nx_tcp_socket_rx_sequence = 1;
    tcp_socket.nx_tcp_socket_state = NX_TCP_TIMED_WAIT;
    _nx_tcp_socket_packet_process(&tcp_socket, packet_ptr);


    /* Test nx_tcp_socket_packet_process.c
     229 [ +  + ][ +  + ]:     136515 :             if ((rx_window > 0) &&
     230         [ -  + ]:     136280 :                 ((((INT)packet_sequence - (INT)rx_sequence >= 0) &&
     231         [ +  + ]:        134 :                   ((INT)rx_sequence + (INT)rx_window - (INT)packet_sequence > 0)) ||
     232         [ +  - ]:         10 :                  (((INT)packet_sequence + ((INT)packet_data_length - 1) - (INT)rx_sequence >= 0) &&
     233                 :         10 :                  ((INT)rx_sequence + 1 + ((INT)rx_window - (INT)packet_sequence) - (INT)packet_data_length > 0))))
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_length = 30;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_3 = 0x50000000;
    tcp_header_ptr -> nx_tcp_sequence_number = 2;
    tcp_socket.nx_tcp_socket_rx_window_current = 1;
    tcp_socket.nx_tcp_socket_rx_sequence = 1;
    tcp_socket.nx_tcp_socket_state = NX_TCP_TIMED_WAIT;
    _nx_tcp_socket_packet_process(&tcp_socket, packet_ptr);

    /* Test nx_tcp_socket_packet_process.c
     452         [ +  - ]:          1 :         if (urgent_callback)
    */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    packet_ptr -> nx_packet_length = 20;
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_3 = 0x50000000 | NX_TCP_URG_BIT | NX_TCP_ACK_BIT;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    tcp_socket.nx_tcp_socket_rx_window_current = 0;
    tcp_socket.nx_tcp_socket_rx_sequence = 0;
    tcp_socket.nx_tcp_socket_state = NX_TCP_TIMED_WAIT;
    tcp_socket.nx_tcp_socket_receive_queue_tail = NX_NULL;
    _nx_tcp_socket_packet_process(&tcp_socket, packet_ptr);
}

#if defined FEATURE_NX_IPV6 && !defined NX_DISABLE_ASSERT
static VOID    thread_for_assert_entry_0(ULONG thread_input)
{
NXD_ADDRESS server_ip;
UINT        status;

    /* Connect to addrss not reachable. */
    server_ip.nxd_ip_version = NX_IP_VERSION_V6;
    server_ip.nxd_ip_address.v6[0] = 0xFE800000;
    server_ip.nxd_ip_address.v6[1] = 0;
    server_ip.nxd_ip_address.v6[2] = 0;
    server_ip.nxd_ip_address.v6[3] = 0x1;
    ip_0.nx_ipv6_address[address_index].nxd_ipv6_address_attached = NX_NULL;
    status = nxd_tcp_client_socket_connect(&tcp_socket, &server_ip, 80, 0);
    if (status != NX_INVALID_INTERFACE)
    {
        error_counter++;
    }
}
#endif /* NX_DISABLE_ASSERT */

#if !defined NX_DISABLE_PACKET_CHAIN  && !defined NX_DISABLE_ASSERT 
static VOID    thread_for_assert_entry_1(ULONG thread_input)
{
NX_PACKET   *test_packet;

    /* Hit condition:       
       391 [ +  - ][ +  + ]:          5 :                 while ((current_packet != NX_NULL) && (current_packet -> nx_packet_prepend_ptr == current_packet -> nx_packet_append_ptr))

       399         [ -  + ]:          2 :                 NX_ASSERT(current_packet != NX_NULL);
    */
    nx_packet_allocate(&pool_0, &test_packet, NX_TCP_PACKET, NX_NO_WAIT);
    if (nx_tcp_socket_send(&tcp_socket, test_packet, 0) != NX_INVALID_PACKET)
    {
        error_counter++;
    }

    test_packet -> nx_packet_length = 10;
    nx_tcp_socket_send(&tcp_socket, test_packet, 0);
}
#endif

#endif /* __PRODUCT_NETXDUO__  */
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_branch_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Branch Test...........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
