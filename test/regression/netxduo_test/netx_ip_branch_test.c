/* This NetX test concentrates on the code coverage for IP functions,
 * _nx_ip_deferred_link_status_process.c
 * _nx_ip_interface_detach.c
 * _nx_ip_max_payload_size_find.c
 * _nx_ip_packet_receive.c 
 */

#include "nx_ip.h"
#include "nx_api.h"
#include "tx_thread.h"
#include "nx_icmp.h"
#include "nx_arp.h"    
#include "nx_rarp.h"  
#ifdef __PRODUCT_NETXDUO__ 
#include "nx_udp.h"
#endif

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_test1;
static TX_THREAD               thread_test2;
#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_ASSERT
static TX_THREAD               thread_for_assert;
static UINT                    assert_count = 0;
#endif
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;



/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;
static CHAR                    *pointer;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    suspend_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER);
static VOID    link_status_change_callback(NX_IP *ip_ptr, UINT interface_index, UINT link_status); 
#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_ASSERT
static void    thread_for_assert_entry(ULONG thread_input);
#endif                                                            
#ifdef FEATURE_NX_IPV6
static UINT  my_raw_packet_processing(NX_IP *ip_ptr, ULONG protocol, NX_PACKET *packet_ptr);
#endif

#ifdef __PRODUCT_NETXDUO__
static char pkt1[590] = {
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x58, 0x08, 0x00, 0x45, 0x00, /* "3DX..E. */
0x02, 0x40, 0x00, 0x01, 0x40, 0x00, 0x80, 0x11, /* .@..@... */
0xf8, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x44, 0x00, 0x43, 0x02, 0x2c, /* ...D.C., */
0xd7, 0x45, 0x01, 0x01, 0x06, 0x00, 0x22, 0x33, /* .E...."3 */
0x44, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, /* D`...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x58, 0x00, 0x00, 0x00, 0x00, /* "3DX.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, /* ......c. */
0x53, 0x63, 0x35, 0x01, 0x01, 0x33, 0x04, 0xff, /* Sc5..3.. */
0xff, 0xff, 0xff, 0x0c, 0x0b, 0x64, 0x68, 0x63, /* .....dhc */
0x70, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, /* p_client */
0x37, 0x03, 0x01, 0x03, 0x06, 0xff, 0x00, 0x00, /* 7....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

/* Frame (342 bytes) */
static char pkt2[342] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x58, 0x00, 0x50, /* .."3DX.P */
0x56, 0x39, 0xf6, 0x3d, 0x08, 0x00, 0x45, 0x10, /* V9.=..E. */
0x01, 0x48, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, /* .H...... */
0x25, 0x7d, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, /* %}...... */
0x00, 0x18, 0x00, 0x3c, 0x00, 0x44, 0x01, 0x34, /* ...<.D.4 */
0xdb, 0x3c, 0x02, 0x01, 0x06, 0x00, 0x22, 0x33, /* .<...."3 */
0x44, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, /* D`...... */
0x00, 0x00, 0x0a, 0x00, 0x00, 0x18, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x58, 0x00, 0x00, 0x00, 0x00, /* "3DX.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, /* ......c. */
0x53, 0x63, 0x35, 0x01, 0x02, 0x36, 0x04, 0x0a, /* Sc5..6.. */
0x00, 0x00, 0x01, 0x33, 0x04, 0x00, 0x00, 0x01, /* ...3.... */
0x2c, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, /* ,....... */
0x04, 0x0a, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};


/* Frame (342 bytes) */
static char pkt3[342] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x58, 0x00, 0x50, /* .."3DX.P */
0x56, 0x39, 0xf6, 0x3d, 0x08, 0x00, 0x45, 0x10, /* V9.=..E. */
0x01, 0x48, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, /* .H...... */
0x25, 0x7d, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, /* %}...... */
0x00, 0x18, 0x00, 0x43, 0x00, 0x46, 0x01, 0x34, /* ...C.F.4 */
0xd8, 0x32, 0x02, 0x01, 0x06, 0x00, 0x22, 0x33, /* .2...."3 */
0x44, 0x60, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, /* D`...... */
0x00, 0x00, 0x0a, 0x00, 0x00, 0x18, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x58, 0x00, 0x00, 0x00, 0x00, /* "3DX.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, /* ......c. */
0x53, 0x63, 0x35, 0x01, 0x05, 0x36, 0x04, 0x0a, /* Sc5..6.. */
0x00, 0x00, 0x01, 0x33, 0x04, 0x00, 0x00, 0x01, /* ...3.... */
0x2c, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, /* ,....... */
0x04, 0x0a, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};


/* Frame (342 bytes) */
static const unsigned char pkt4[342] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x58, 0x00, 0x50, /* .."3DX.P */
0x56, 0x39, 0xf6, 0x3d, 0x08, 0x00, 0x45, 0x10, /* V9.=..E. */
0x01, 0x48, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, /* .H...... */
0x25, 0x7d, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, /* %}...... */
0x00, 0x18, 0x00, 0x43, 0x00, 0x44, 0x01, 0x34, /* ...C.D.4 */
0xd8, 0x34, 0x02, 0x01, 0x06, 0x00, 0x22, 0x33, /* .4...."3 */
0x44, 0x60, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, /* D`...... */
0x00, 0x00, 0x0a, 0x00, 0x00, 0x18, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x58, 0x00, 0x00, 0x00, 0x00, /* "3DX.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, /* ......c. */
0x53, 0x63, 0x35, 0x01, 0x05, 0x36, 0x04, 0x0a, /* Sc5..6.. */
0x00, 0x00, 0x01, 0x33, 0x04, 0x00, 0x00, 0x01, /* ...3.... */
0x2c, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, /* ,....... */
0x04, 0x0a, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};


#ifdef FEATURE_NX_IPV6
static const unsigned char pkt5[78] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x18, 0x00, 0xff, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x3a, 0x00, /* "..3DV:. */
0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, /* ........ */
0x09, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x05, 0x06, 0x07, 0x08              /* ...... */
};
#endif /* FEATURE_NX_IPV6  */
#endif



/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_branch_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;

    
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 800, pointer, 8192);
    pointer = pointer + 8192;

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

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 processing for IP instance.  */
    status = nxd_ipv6_enable(&ip_0);

    /* Check IPv6 enable status.  */
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

ULONG       thread_state;
NX_PACKET  *my_packet[2];

#ifdef __PRODUCT_NETXDUO__ 
NXD_ADDRESS dest_address;
ULONG       src_ip_addr = 0x01020304;
ULONG       dest_ip_addr = 0x01020305;
NX_IPV4_HEADER *ip_header_ptr;
NX_ARP      *temp_arp;
#endif /* __PRODUCT_NETXDUO__ */
NX_INTERFACE
            *if_ptr = NX_NULL;
ULONG       next_hop_address;
#ifndef NX_DISABLE_LOOPBACK_INTERFACE
UINT        i;
#endif
#ifdef FEATURE_NX_IPV6
NX_IPV6_HEADER   *ipv6_header_ptr;
#endif /* FEATURE_NX_IPV6  */


    /* Print out some test information banners.  */
    printf("NetX Test:   IP Branch Test............................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Hit false condition of ip_ptr -> nx_ip_interface[i].nx_interface_link_status_change in _nx_ip_deferred_link_status_process().  */
    ip_0.nx_ip_link_status_change_callback = link_status_change_callback;
    ip_0.nx_ip_interface[0].nx_interface_link_status_change = NX_FALSE;
    _nx_ip_deferred_link_status_process(&ip_0);
    ip_0.nx_ip_interface[0].nx_interface_link_status_change = NX_TRUE;
    _nx_ip_deferred_link_status_process(&ip_0);

    /* Recover.  */
    ip_0.nx_ip_link_status_change_callback = NX_NULL;


#ifdef __PRODUCT_NETXDUO__
    /* Hit condition of if (interface_ptr -> nx_interface_valid == NX_FALSE) in _nx_ip_max_payload_size_find().  */
    dest_address.nxd_ip_version = NX_IP_VERSION_V4;
    _nx_ip_max_payload_size_find(&ip_0, &dest_address, 0, 0, 0, NX_PROTOCOL_TCP, NX_NULL, NX_NULL);
    _nx_ip_max_payload_size_find(&ip_0, &dest_address, NX_MAX_PHYSICAL_INTERFACES, 0, 0, NX_PROTOCOL_TCP, NX_NULL, NX_NULL); 
    _nx_ip_max_payload_size_find(&ip_0, &dest_address, 0, 0, 0, NX_PROTOCOL_ICMP, NX_NULL, NX_NULL);


#if (NX_MAX_PHYSICAL_INTERFACES >= 2)
    /* Hit condition of if (interface_ptr -> nx_interface_valid == NX_FALSE) in _nx_ip_interface_detach().  */
    _nx_ip_interface_detach(&ip_0, 1);
    nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver_256);
    _nx_ip_interface_detach(&ip_0, 1);
#endif

#endif /* __PRODUCT_NETXDUO__  */



    /* Test _nx_ip_raw_packet_cleanup().  */
    /* tx_thread_suspend_control_block is set to NULL. */
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    _nx_ip_raw_packet_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* tx_thread_suspend_control_block is set to IP but tx_thread_suspend_cleanup is set to NULL. */
    tx_thread_identify() -> tx_thread_suspend_control_block = &ip_0;
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    _nx_ip_raw_packet_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* tx_thread_suspend_control_block is set to IP and tx_thread_suspend_cleanup is set to suspend_cleanup, but clear the IP ID. */
    tx_thread_identify() -> tx_thread_suspend_control_block = &ip_0;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    ip_0.nx_ip_id = 0;
    _nx_ip_raw_packet_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    ip_0.nx_ip_id = NX_IP_ID;
    
    ip_0.nx_ip_raw_packet_suspended_count ++;
    tx_thread_identify() -> tx_thread_suspended_next = tx_thread_identify();
    thread_state = tx_thread_identify() -> tx_thread_state;
    tx_thread_identify() -> tx_thread_state = 0;
    _nx_ip_raw_packet_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    tx_thread_identify() -> tx_thread_state = thread_state;


    /* Setup tx_thread_suspend_cleanup, control block.  */ 
    ip_0.nx_ip_raw_packet_suspended_count ++;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = &ip_0; 
    tx_thread_identify() -> tx_thread_suspended_next = &thread_test1;
    tx_thread_identify() -> tx_thread_suspended_previous = &thread_test2;
    thread_state = tx_thread_identify() -> tx_thread_state;
    tx_thread_identify() -> tx_thread_state = 0;
    _nx_ip_raw_packet_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT); 
    tx_thread_identify() -> tx_thread_state = thread_state;


#ifdef FEATURE_NX_IPV6 
    /* Hit condition of if (ip_version == NX_IP_VERSION_V4 && ip_ptr -> nx_ipv4_packet_receive) and if (ip_version == NX_IP_VERSION_V6 && ip_ptr -> nx_ipv6_packet_receive) in _nx_ip_packet_receive().  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    *(my_packet[0] -> nx_packet_prepend_ptr) = NX_IP_VERSION_V4 << 4;
    ip_0.nx_ipv4_packet_receive = NX_NULL;
    _nx_ip_packet_receive(&ip_0, my_packet[0]);
    *(my_packet[0] -> nx_packet_prepend_ptr) = NX_IP_VERSION_V6 << 4;
    ip_0.nx_ipv6_packet_receive = NX_NULL;
    _nx_ip_packet_receive(&ip_0, my_packet[0]); 
    ip_0.nx_ipv4_packet_receive = _nx_ipv4_packet_receive;
    ip_0.nx_ipv6_packet_receive = _nx_ipv6_packet_receive;
    nx_packet_release(my_packet[0]);
#endif /* FEATURE_NX_IPV6 */

    /* Test nx_ip_route_find with a down interface for multicast address.  */
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_FALSE;
    if_ptr = &ip_0.nx_ip_interface[0];
    _nx_ip_route_find(&ip_0, IP_ADDRESS(224, 2, 3, 2), &if_ptr, &next_hop_address);
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;

    /* Hit the condition that (*ip_interface_ptr != interface_ptr).  */
    if_ptr = &ip_0.nx_ip_interface[4];
    _nx_ip_route_find(&ip_0, IP_ADDRESS(1, 2, 3, 4), &if_ptr, &next_hop_address);

    /* Test nx_ip_route_find with a down interface for link local address.  */
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_FALSE;
    if_ptr = &ip_0.nx_ip_interface[0];
    _nx_ip_route_find(&ip_0, IP_ADDRESS(169, 254, 3, 2), &if_ptr, &next_hop_address);
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;

    /* Test nx_ip_route_find with a invalid interface for link local address.  */
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_FALSE;
    if_ptr = &ip_0.nx_ip_interface[0];
    _nx_ip_route_find(&ip_0, IP_ADDRESS(169, 254, 3, 2), &if_ptr, &next_hop_address);
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_TRUE;


    /* Test nx_ip_route_find with a null interface for link local address.  */
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_FALSE;
    ip_0.nx_ip_interface[4].nx_interface_valid = NX_FALSE;
    if_ptr = NX_NULL;
    _nx_ip_route_find(&ip_0, IP_ADDRESS(169, 254, 3, 2), &if_ptr, &next_hop_address);
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;
    ip_0.nx_ip_interface[4].nx_interface_valid = NX_TRUE;

    /* Test nx_ip_route_find with a invalid gateway interface.  */
    ip_0.nx_ip_gateway_address = IP_ADDRESS(1, 2, 3, 5);
    if_ptr = &ip_0.nx_ip_interface[0];
    _nx_ip_route_find(&ip_0, IP_ADDRESS(2, 3, 4, 5), &if_ptr, &next_hop_address);
    ip_0.nx_ip_gateway_interface = &ip_0.nx_ip_interface[4];
    ip_0.nx_ip_interface[4].nx_interface_link_up = NX_FALSE;
    _nx_ip_route_find(&ip_0, IP_ADDRESS(2, 3, 4, 5), &if_ptr, &next_hop_address);
    ip_0.nx_ip_interface[4].nx_interface_link_up = NX_TRUE;
    ip_0.nx_ip_gateway_interface = NX_NULL;
    ip_0.nx_ip_gateway_address = 0;

#ifdef FEATURE_NX_IPV6 
    /* Test _nx_ipv4_option_process with invalid options.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    *(my_packet[0] -> nx_packet_prepend_ptr + 3) = NX_IP_VERSION_V4 << 4 | 15;
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER)) = NX_IP_OPTION_INTERNET_TIMESTAMP;
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER) + 1) = 40;
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER) + 2) = 6;
    _nx_ipv4_option_process(&ip_0, my_packet[0]);
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER) + 1) = 39;
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER) + 2) = 5;
    _nx_ipv4_option_process(&ip_0, my_packet[0]);
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER) + 1) = 41;
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER) + 2) = 5;
    _nx_ipv4_option_process(&ip_0, my_packet[0]);
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER) + 1) = 40;
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER) + 3) = 1;
    _nx_ipv4_option_process(&ip_0, my_packet[0]);
    *(my_packet[0] -> nx_packet_prepend_ptr + sizeof(NX_IPV4_HEADER) + 3) = 3;
    _nx_ipv4_option_process(&ip_0, my_packet[0]);
    nx_packet_release(my_packet[0]);
#endif

#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_ASSERT
    /* Test _nx_ip_header_add().  */
    /* Hit NX_ASSERT(packet_ptr -> nx_packet_prepend_ptr >= packet_ptr -> nx_packet_data_start);  */

    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Test _nx_ip_checksum_compute().  */
    /* Hit condition: src_ip_addr == NX_NULL;
       152 [ +  - ][ -  + ]: NX_ASSERT((src_ip_addr != NX_NULL) && (dest_ip_addr != NX_NULL));  */

    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);

    /* Hit condition: dest_ip_addr == NX_NULL;
       152 [ +  - ][ -  + ]: NX_ASSERT((src_ip_addr != NX_NULL) && (dest_ip_addr != NX_NULL));  */

    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);
#endif /* NX_DISABLE_ASSERT  */

                                      
#ifdef __PRODUCT_NETXDUO__ 
    /* Test _nx_ip_checksum_compute.*/
    /* Hit condition: 208         [ +  - ]:  while (current_packet)  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 9;
    my_packet[0] -> nx_packet_length = 9;
    _nx_ip_checksum_compute(my_packet[0], NX_PROTOCOL_UDP, 9, &src_ip_addr, &dest_ip_addr); 
    nx_packet_release(my_packet[0]);



#ifndef NX_DISABLE_PACKET_CHAIN
    /* Test _nx_ipv4_packet_receive.  */
    /* Hit condition: 268         [ +  - ]:  while (delta)  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_allocate(&pool_0, &my_packet[1], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 30;
    my_packet[0] -> nx_packet_length = 30;  
    my_packet[0] -> nx_packet_next = my_packet[1];
    my_packet[0] -> nx_packet_last = my_packet[1];
    ip_header_ptr = (NX_IPV4_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    ip_header_ptr -> nx_ip_header_word_0 = (NX_IP_VERSION | NX_IP_NORMAL | (0xFFFF & 22));
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);
    my_packet[1] -> nx_packet_append_ptr = my_packet[1] -> nx_packet_prepend_ptr + 8;
    my_packet[1] -> nx_packet_length = 8;
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr; 
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    _nx_ipv4_packet_receive(&ip_0, my_packet[0]);
#endif


    /* Hit true condition: (ip_header_ptr -> nx_ip_header_destination_ip == 0)  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    memcpy(my_packet[0] ->nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + sizeof(pkt1) - 14;
    my_packet[0] -> nx_packet_length = sizeof(pkt1) - 14;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr;
    _nx_ipv4_packet_receive(&ip_0, my_packet[0]);


    /* Hit true condition: src_port = 70;
     755 [ +  - ][ +  - ]: if ((src_port == 67) && (dest_port == 68)) */
    ip_0.nx_ip_interface[0].nx_interface_ip_address = 0;
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    memcpy(my_packet[0] ->nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + sizeof(pkt2) - 14;
    my_packet[0] -> nx_packet_length = sizeof(pkt2) - 14;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr;
    _nx_ipv4_packet_receive(&ip_0, my_packet[0]);
    ip_0.nx_ip_interface[0].nx_interface_ip_address = IP_ADDRESS(1, 2, 3, 4); 


    /* Hit true condition: dest_port = 70;
      755 [ +  - ][ +  - ]: if ((src_port == 67) && (dest_port == 68)) */
    ip_0.nx_ip_interface[0].nx_interface_ip_address = 0;
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    memcpy(my_packet[0] ->nx_packet_prepend_ptr, &pkt3[14], sizeof(pkt3) - 14);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + sizeof(pkt3) - 14;
    my_packet[0] -> nx_packet_length = sizeof(pkt3) - 14;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr;
    _nx_ipv4_packet_receive(&ip_0, my_packet[0]);
    ip_0.nx_ip_interface[0].nx_interface_ip_address = IP_ADDRESS(1, 2, 3, 4);
                                          
    /* Hit true condition:
       757 [ +  - ]: if (ip_ptr -> nx_ip_udp_packet_receive) */
    ip_0.nx_ip_interface[0].nx_interface_ip_address = 0;
    ip_0.nx_ip_udp_packet_receive = NX_NULL;
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    memcpy(my_packet[0] ->nx_packet_prepend_ptr, &pkt4[14], sizeof(pkt4) - 14);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + sizeof(pkt4) - 14;
    my_packet[0] -> nx_packet_length = sizeof(pkt4) - 14;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr;
    _nx_ipv4_packet_receive(&ip_0, my_packet[0]);
    ip_0.nx_ip_interface[0].nx_interface_ip_address = IP_ADDRESS(1, 2, 3, 4);
    ip_0.nx_ip_udp_packet_receive = _nx_udp_packet_receive;
#endif


    /* Test _nx_ip_delete.  */
    nx_ip_fragment_enable(&ip_0);
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_allocate(&pool_0, &my_packet[1], 0, NX_NO_WAIT);
    ip_0.nx_ip_deferred_received_packet_head = my_packet[0];
    ip_0.nx_ip_deferred_received_packet_tail = my_packet[0]; 
    ip_0.nx_ip_raw_packet_suspension_list = &thread_test1;  
    ip_0.nx_ip_raw_packet_suspended_count ++;
    thread_test1.tx_thread_suspend_cleanup = suspend_cleanup;
    thread_test1.tx_thread_suspend_control_block = &ip_0; 
    thread_test1.tx_thread_suspended_next = &thread_test1;
    _nx_ip_delete(&ip_0);



    /* Test _nx_ip_thread_entry()  */
    /*  Hit condition: if ((ip_ptr -> nx_ip_interface[i].nx_interface_valid) && (ip_ptr -> nx_ip_interface[i].nx_interface_link_driver_entry))  */
    /* Create an IP instance.  */
    _nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, NX_NULL,
                 pointer, 2048, 1);
    pointer =  pointer + 2048;
    ip_0.nx_ip_interface[0].nx_interface_link_driver_entry = _nx_ram_network_driver_256;
    _nx_ip_delete(&ip_0);


    /* Create an IP instance.  */
    nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                 pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Hit condition: 394 [ +  - ]: if (!ip_events)  */
    /* Enable TCP.  */
    nx_tcp_enable(&ip_0);

    /* Wakeup IP thread for processing one or more messages in the TCP queue.  */
    tx_event_flags_set(&(ip_0.nx_ip_events), NX_IP_TCP_EVENT, TX_OR);

    /* Let IP thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Wakeup IP thread for processing one or more messages in the TCP queue.  */
    tx_event_flags_set(&(ip_0.nx_ip_events), NX_IP_TCP_EVENT | NX_IP_ARP_REC_EVENT, TX_OR);

    /* Let IP thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);


    /* Hit condition: 546 [ +  + ][ +  - ]: if ((ip_events & NX_IP_ARP_REC_EVENT) && (ip_ptr -> nx_ip_arp_queue_process))  */
    ip_0.nx_ip_arp_queue_process = NX_NULL;

    /* Set NX_IP_ARP_REC_EVENT.  */
    tx_event_flags_set(&(ip_0.nx_ip_events), NX_IP_ARP_REC_EVENT, TX_OR);

    /* Let IP thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    ip_0.nx_ip_arp_queue_process = _nx_arp_queue_process;


    /* Hit condition: 554 [ +  + ][ +  - ]: if ((ip_events & NX_IP_RARP_REC_EVENT) && (ip_ptr -> nx_ip_rarp_queue_process))  */
    ip_0.nx_ip_rarp_queue_process = NX_NULL;

    /* Set NX_IP_RARP_REC_EVENT.  */
    tx_event_flags_set(&(ip_0.nx_ip_events), NX_IP_RARP_REC_EVENT, TX_OR);

    /* Let IP thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    ip_0.nx_ip_arp_queue_process = _nx_rarp_queue_process; 

                               
#ifndef NX_DISABLE_LOOPBACK_INTERFACE
    /* Hit condition: 627 [ +  + ][ +  - ]: while ((ip_ptr -> nx_ip_interface[index].nx_interface_valid) && (index < NX_MAX_PHYSICAL_INTERFACES))  */
    /* Set the all interface as valid.  */
    for (i = 1; i < NX_MAX_IP_INTERFACES; i++)
    {
        /* Set all interface as valid.  */
        ip_0.nx_ip_interface[i].nx_interface_valid = 1;
        ip_0.nx_ip_interface[i].nx_interface_link_driver_entry = _nx_ram_network_driver_256;
    }    
    
    /* Set NX_IP_DRIVER_DEFERRED_EVENT.  */
    tx_event_flags_set(&(ip_0.nx_ip_events), NX_IP_DRIVER_DEFERRED_EVENT, TX_OR);

    /* Let IP thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Clear the valid flag except interface 0.  */
    for (i = 1; i < NX_MAX_IP_INTERFACES; i++)
    {
        /* Set all interface as valid.  */
        ip_0.nx_ip_interface[i].nx_interface_valid = 0;
        ip_0.nx_ip_interface[i].nx_interface_link_driver_entry = NX_NULL;
    }
#endif


                                      
#ifdef __PRODUCT_NETXDUO__ 
    /* Test _nx_ip_forward_packet_process()  */
    /* Hit condition:
      147 [ +  + ][ -  + ]:         46 :     if (((ip_header_ptr -> nx_ip_header_source_ip & 0xFFFF0000) == 0xA9FE0000) ||
      148                 :         45 :         ((ip_header_ptr -> nx_ip_header_destination_ip & 0xFFFF0000) == 0xA9FE0000))
    */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT); 
    ip_header_ptr = (NX_IPV4_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    ip_header_ptr -> nx_ip_header_source_ip = 0x01020305; 
    ip_header_ptr -> nx_ip_header_destination_ip = 0xA9FE0000; 
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 20;
    my_packet[0] -> nx_packet_length = 20;
    _nx_ip_forward_packet_process(&ip_0,  my_packet[0]);



    /* Hit condition: first [ +  - ]
       361 [ +  - ][ +  - ]:          7 :                 if ((ip_ptr -> nx_ip_fragment_processing) && (!(fragment_bits & NX_IP_DONT_FRAGMENT)))
    */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 600;
    my_packet[0] -> nx_packet_length = 600;
    ip_header_ptr = (NX_IPV4_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;   
    ip_header_ptr -> nx_ip_header_word_0 =  (NX_IP_VERSION | NX_IP_NORMAL | (0xFFFF & my_packet[0] -> nx_packet_length));
#ifdef NX_ENABLE_IP_ID_RANDOMIZATION
    ip_header_ptr -> nx_ip_header_word_1 =  (((ULONG)NX_RAND()) << NX_SHIFT_BY_16) | NX_FRAGMENT_OKAY;
#else
    ip_header_ptr -> nx_ip_header_word_1 =  (ip_0.nx_ip_packet_id++ << NX_SHIFT_BY_16) | NX_FRAGMENT_OKAY;
#endif /* NX_ENABLE_IP_ID_RANDOMIZATION */
    ip_header_ptr -> nx_ip_header_word_2 =  ((0x80 << NX_IP_TIME_TO_LIVE_SHIFT) | NX_IP_ICMP);
    ip_header_ptr -> nx_ip_header_source_ip = 0x02020305; 
    ip_header_ptr -> nx_ip_header_destination_ip = 0x01020305; 
    ip_0.nx_ip_fragment_processing = NX_NULL;
    _nx_ip_forward_packet_process(&ip_0,  my_packet[0]);


#ifndef NX_DISABLE_FRAGMENTATION
        /* Hit condition: second [ +  - ]
       361 [ +  - ][ +  - ]:          7 :                 if ((ip_ptr -> nx_ip_fragment_processing) && (!(fragment_bits & NX_IP_DONT_FRAGMENT)))
    */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 600;
    my_packet[0] -> nx_packet_length = 600;
    ip_header_ptr = (NX_IPV4_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;   
    ip_header_ptr -> nx_ip_header_word_0 =  (NX_IP_VERSION | NX_IP_NORMAL | (0xFFFF & my_packet[0] -> nx_packet_length));
#ifdef NX_ENABLE_IP_ID_RANDOMIZATION
    ip_header_ptr -> nx_ip_header_word_1 =  (((ULONG)NX_RAND()) << NX_SHIFT_BY_16) | NX_DONT_FRAGMENT;
#else
    ip_header_ptr -> nx_ip_header_word_1 =  (ip_0.nx_ip_packet_id++ << NX_SHIFT_BY_16) | NX_DONT_FRAGMENT;
#endif /* NX_ENABLE_IP_ID_RANDOMIZATION */
    ip_header_ptr -> nx_ip_header_word_2 =  ((0x80 << NX_IP_TIME_TO_LIVE_SHIFT) | NX_IP_ICMP);
    ip_header_ptr -> nx_ip_header_source_ip = 0x02020305; 
    ip_header_ptr -> nx_ip_header_destination_ip = 0x01020305; 
    ip_0.nx_ip_fragment_processing = _nx_ip_fragment_packet;
    _nx_ip_forward_packet_process(&ip_0,  my_packet[0]);
    ip_0.nx_ip_fragment_processing = NX_NULL;
#endif



    /* Test _nx_ip_driver_packet_send()  */
#ifndef NX_DISABLE_FRAGMENTATION
    /* Hit condition: 263 [ +  + ][ -  + ]: if ((ip_ptr -> nx_ip_fragment_processing == NX_NULL) || (fragment != NX_FRAGMENT_OKAY))  */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 600;
    my_packet[0] -> nx_packet_length = 600;
    ip_0.nx_ip_fragment_processing = NX_NULL;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    _nx_ip_driver_packet_send(&ip_0,  my_packet[0], IP_ADDRESS(1, 2, 3, 5), NX_DONT_FRAGMENT, IP_ADDRESS(1, 2, 3, 5));

    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 600;
    my_packet[0] -> nx_packet_length = 600;   
    ip_0.nx_ip_fragment_processing = _nx_ip_fragment_packet;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    _nx_ip_driver_packet_send(&ip_0,  my_packet[0], IP_ADDRESS(1, 2, 3, 5), NX_DONT_FRAGMENT, IP_ADDRESS(1, 2, 3, 5));
    ip_0.nx_ip_fragment_processing = NX_NULL;
#endif


    /* Hit condition:
     378   [ +  +  -  + ]: if ((!ip_ptr -> nx_ip_arp_allocate) ||
     379                 :     ((ip_ptr -> nx_ip_arp_allocate)(ip_ptr, &(ip_ptr -> nx_ip_arp_table[index]), NX_FALSE)))  */
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    temp_arp = ip_0.nx_ip_arp_dynamic_list;
    ip_0.nx_ip_arp_dynamic_list = NX_NULL;
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 40;
    my_packet[0] -> nx_packet_length = 40;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    _nx_ip_driver_packet_send(&ip_0,  my_packet[0], IP_ADDRESS(1, 2, 3, 5), NX_DONT_FRAGMENT, IP_ADDRESS(1, 2, 3, 5));
    ip_0.nx_ip_arp_dynamic_list = temp_arp;     


    /* Hit condition:
     436 [ +  + ][ -  + ]:      17075 :         if ((((destination_ip >= NX_IP_LOOPBACK_FIRST) &&
     437         [ +  + ]:        593 :               (destination_ip <= NX_IP_LOOPBACK_LAST))) ||
     438                 :        593 :             (destination_ip == packet_ptr -> nx_packet_address.nx_packet_interface_ptr -> nx_interface_ip_address)) */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 40;
    my_packet[0] -> nx_packet_length = 40;                               
    ip_header_ptr = (NX_IPV4_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;   
    ip_header_ptr -> nx_ip_header_word_0 =  (NX_IP_VERSION | NX_IP_NORMAL | (0xFFFF & my_packet[0] -> nx_packet_length));
#ifdef NX_ENABLE_IP_ID_RANDOMIZATION
    ip_header_ptr -> nx_ip_header_word_1 =  (((ULONG)NX_RAND()) << NX_SHIFT_BY_16) | NX_FRAGMENT_OKAY;
#else
    ip_header_ptr -> nx_ip_header_word_1 =  (ip_0.nx_ip_packet_id++ << NX_SHIFT_BY_16) | NX_FRAGMENT_OKAY;
#endif /* NX_ENABLE_IP_ID_RANDOMIZATION */
    ip_header_ptr -> nx_ip_header_word_2 =  ((0x80 << NX_IP_TIME_TO_LIVE_SHIFT) | NX_IP_ICMP);
    ip_header_ptr -> nx_ip_header_source_ip = 0x01020304; 
    ip_header_ptr -> nx_ip_header_destination_ip = NX_IP_LOOPBACK_LAST; 
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    ip_0.nx_ip_interface[0].nx_interface_address_mapping_needed = 0;
    _nx_ip_driver_packet_send(&ip_0,  my_packet[0], NX_IP_LOOPBACK_LAST, NX_DONT_FRAGMENT, NX_IP_LOOPBACK_LAST);    
    ip_0.nx_ip_interface[0].nx_interface_address_mapping_needed = 1; 


#ifndef NX_ENABLE_INTERFACE_CAPABILITY
    /* Hit condition:
     436 [ +  + ][ +  - ]:      17075 :         if ((((destination_ip >= NX_IP_LOOPBACK_FIRST) &&
     437         [ +  + ]:        593 :               (destination_ip <= NX_IP_LOOPBACK_LAST))) ||
     438                 :        593 :             (destination_ip == packet_ptr -> nx_packet_address.nx_packet_interface_ptr -> nx_interface_ip_address)) */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 40;
    my_packet[0] -> nx_packet_length = 40;                               
    ip_header_ptr = (NX_IPV4_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;   
    ip_header_ptr -> nx_ip_header_word_0 =  (NX_IP_VERSION | NX_IP_NORMAL | (0xFFFF & my_packet[0] -> nx_packet_length));
#ifdef NX_ENABLE_IP_ID_RANDOMIZATION
    ip_header_ptr -> nx_ip_header_word_1 =  (((ULONG)NX_RAND()) << NX_SHIFT_BY_16) | NX_FRAGMENT_OKAY;
#else
    ip_header_ptr -> nx_ip_header_word_1 =  (ip_0.nx_ip_packet_id++ << NX_SHIFT_BY_16) | NX_FRAGMENT_OKAY;
#endif /* NX_ENABLE_IP_ID_RANDOMIZATION */
    ip_header_ptr -> nx_ip_header_word_2 =  ((0x80 << NX_IP_TIME_TO_LIVE_SHIFT) | NX_IP_ICMP);
    ip_header_ptr -> nx_ip_header_source_ip = 0x01020304; 
    ip_header_ptr -> nx_ip_header_destination_ip = NX_IP_LOOPBACK_LAST + 1; 
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    ip_0.nx_ip_interface[0].nx_interface_address_mapping_needed = 0;
    _nx_ip_driver_packet_send(&ip_0,  my_packet[0], NX_IP_LOOPBACK_LAST + 1, NX_DONT_FRAGMENT, NX_IP_LOOPBACK_LAST);  
    ip_0.nx_ip_interface[0].nx_interface_address_mapping_needed = 1; 
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */


#ifndef NX_DISABLE_FRAGMENTATION
    /* Hit condition:
       511 [ +  + ][ +  - ]:       3014 :             if ((ip_ptr -> nx_ip_fragment_processing) && (fragment != NX_DONT_FRAGMENT)) */
    nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0x0011, 0x22334457);
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 600;
    my_packet[0] -> nx_packet_length = 600;                               
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    ip_0.nx_ip_fragment_processing = _nx_ip_fragment_packet;
    _nx_ip_driver_packet_send(&ip_0,  my_packet[0], 0x01020305, NX_DONT_FRAGMENT, 0x01020305);    
    ip_0.nx_ip_fragment_processing = NX_NULL;
#endif


#ifndef NX_DISABLE_ASSERT
    /* Hit condition: packet_ptr -> nx_packet_address.nx_packet_interface_ptr -> nx_interface_link_driver_entry = NX_NULL
      NX_ASSERT(packet_ptr -> nx_packet_address.nx_packet_interface_ptr -> nx_interface_link_driver_entry != NX_NULL); */
    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);

    /* Recover.  */
    ip_0.nx_ip_interface[0].nx_interface_link_driver_entry = _nx_ram_network_driver_256;
#endif /* NX_DISABLE_ASSERT  */



#ifdef FEATURE_NX_IPV6
    /* Hit condition: second [ +  - ]
       493 [ +  + ][ +  - ]:    2264309 :                 if ((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4) ||
       494         [ +  - ]:        181 :                     ((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6) &&
       495                 :        181 :                      (incoming_addr -> nxd_ipv6_address_state == NX_IPV6_ADDR_STATE_VALID))) */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 40;
    my_packet[0] -> nx_packet_length = 40;                               
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet[0] -> nx_packet_ip_version = 5;
    _nx_ip_dispatch_process(&ip_0, my_packet[0], NX_PROTOCOL_TCP);
    nx_packet_release( my_packet[0]);

    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 40;
    my_packet[0] -> nx_packet_length = 40;                               
    my_packet[0] -> nx_packet_address.nx_packet_ipv6_address_ptr = &ip_0.nx_ipv6_address[0];
    my_packet[0] -> nx_packet_ip_version = NX_IP_VERSION_V6;
    _nx_ip_dispatch_process(&ip_0, my_packet[0], NX_PROTOCOL_TCP);
    nx_packet_release( my_packet[0]);    

    /* Hit condition: second [ +  - ]
       574 [ +  + ][ +  - ]:      16830 :                 if ((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4) ||
       575         [ +  - ]:       5041 :                     ((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6) &&
       576                 :       5041 :                      (incoming_addr -> nxd_ipv6_address_state == NX_IPV6_ADDR_STATE_VALID))) */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 40;
    my_packet[0] -> nx_packet_length = 40;                               
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet[0] -> nx_packet_ip_version = 5;
    _nx_ip_dispatch_process(&ip_0, my_packet[0], NX_PROTOCOL_UDP);
    nx_packet_release( my_packet[0]);

    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 40;
    my_packet[0] -> nx_packet_length = 40;                               
    my_packet[0] -> nx_packet_address.nx_packet_ipv6_address_ptr = &ip_0.nx_ipv6_address[0];
    my_packet[0] -> nx_packet_ip_version = NX_IP_VERSION_V6;
    _nx_ip_dispatch_process(&ip_0, my_packet[0], NX_PROTOCOL_UDP);
    nx_packet_release( my_packet[0]);


    /* Hit condition:
       601         [ +  - ]:         39 :                     if ((ip_ptr -> nx_ip_raw_ip_processing)(ip_ptr, protocol << 16, packet_ptr) == NX_SUCCESS) */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_PHYSICAL_HEADER, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 40;
    my_packet[0] -> nx_packet_length = 40;                               
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet[0] -> nx_packet_ip_version = 4;         
    ip_header_ptr = (NX_IPV4_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;   
    ip_header_ptr -> nx_ip_header_word_0 =  (NX_IP_VERSION | NX_IP_NORMAL | (0xFFFF & my_packet[0] -> nx_packet_length));
#ifdef NX_ENABLE_IP_ID_RANDOMIZATION
    ip_header_ptr -> nx_ip_header_word_1 =  (((ULONG)NX_RAND()) << NX_SHIFT_BY_16) | NX_FRAGMENT_OKAY;
#else
    ip_header_ptr -> nx_ip_header_word_1 =  (ip_0.nx_ip_packet_id++ << NX_SHIFT_BY_16) | NX_FRAGMENT_OKAY;
#endif /* NX_ENABLE_IP_ID_RANDOMIZATION */
    ip_header_ptr -> nx_ip_header_word_2 =  ((0x80 << NX_IP_TIME_TO_LIVE_SHIFT) | NX_IP_ICMP);
    ip_header_ptr -> nx_ip_header_source_ip = 0x01020305; 
    ip_header_ptr -> nx_ip_header_destination_ip = 0x01020304; 
    ip_0.nx_ip_raw_ip_processing = my_raw_packet_processing;
    _nx_ip_dispatch_process(&ip_0, my_packet[0], 203);
    nx_packet_release( my_packet[0]);      
    ip_0.nx_ip_raw_ip_processing = NX_NULL;


    /* Hit condition:
       664         [ +  - ]:       1145 :             if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6) */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    memcpy(my_packet[0] -> nx_packet_prepend_ptr, &pkt5[14], sizeof(pkt5) - 14);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + sizeof(pkt5) - 14;
    my_packet[0] -> nx_packet_length = sizeof(pkt5) - 14;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr; 
    ipv6_header_ptr = (NX_IPV6_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(ipv6_header_ptr -> nx_ip_header_word_0);
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(ipv6_header_ptr -> nx_ip_header_destination_ip);
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(ipv6_header_ptr -> nx_ip_header_source_ip);
    my_packet[0] -> nx_packet_prepend_ptr += 40;  
    my_packet[0] -> nx_packet_length -= 40;
    my_packet[0] -> nx_packet_ip_version = 5;
    _nx_ip_dispatch_process(&ip_0, my_packet[0], NX_PROTOCOL_NEXT_HEADER_HOP_BY_HOP);
#endif

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

static VOID    link_status_change_callback(NX_IP *ip_ptr, UINT interface_index, UINT link_status)
{
}

#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_ASSERT
/* Define the test threads.  */

static void    thread_for_assert_entry(ULONG thread_input)
{
NX_PACKET   *test_packet;
ULONG       src_ip_addr = 0x01020304;

    /* Check the count.  */
    if (assert_count == 0)
    {

        /* Update the count.  */
        assert_count ++;

        nx_packet_allocate(&pool_0, &test_packet, 0, NX_NO_WAIT);
        test_packet -> nx_packet_prepend_ptr = test_packet -> nx_packet_data_start - 1;

        /* Call function with NULL interface.  */
        _nx_ip_header_add(&ip_0, test_packet, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(1, 2, 3, 5), 0, 0, 0, NX_FALSE);
    }
    else if (assert_count == 1)
    {

        /* Update the count.  */
        assert_count ++;

        /* Call function with NULL src_ip_addr.  */  
        nx_packet_allocate(&pool_0, &test_packet, 0, NX_NO_WAIT);
        _nx_ip_checksum_compute(test_packet, NX_PROTOCOL_UDP, 0, NX_NULL, NX_NULL);
    }
    else if (assert_count == 2)
    {

        /* Update the count.  */
        assert_count ++;

        /* Call function with NULL src_ip_addr.  */  
        nx_packet_allocate(&pool_0, &test_packet, 0, NX_NO_WAIT);
        _nx_ip_checksum_compute(test_packet, NX_PROTOCOL_UDP, 0, &src_ip_addr, NX_NULL);
    }
    else if (assert_count == 3)
    {

        /* Update the count.  */
        assert_count ++;
                                   
        nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0x0011, 0x22334457);
        nx_packet_allocate(&pool_0, &test_packet, NX_PHYSICAL_HEADER, NX_NO_WAIT);
        test_packet -> nx_packet_append_ptr = test_packet -> nx_packet_prepend_ptr + 40;
        test_packet -> nx_packet_length = 40;                               
        test_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
        ip_0.nx_ip_interface[0].nx_interface_link_driver_entry = NX_NULL;
        _nx_ip_driver_packet_send(&ip_0,  test_packet, 0x01020305, NX_DONT_FRAGMENT, 0x01020305);  
    }
}
#endif

#ifdef FEATURE_NX_IPV6  
static UINT  my_raw_packet_processing(NX_IP *ip_ptr, ULONG protocol, NX_PACKET *packet_ptr)
{

    return(1);
}
#endif
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_branch_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Branch Test............................................N/A\n"); 

    test_control_return(3);  
}      
#endif