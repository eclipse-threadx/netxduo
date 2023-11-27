/* Test IPv6 prefix with length not equal 64. */

#include    "tx_api.h"
#include    "nx_api.h"   
#include    "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_LOOPBACK_INTERFACE)  && !defined(NX_DISABLE_IPV4)
 
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"  
#include    "nx_icmp.h"
#include    "nx_icmpv6.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;  
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;  

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);       
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Frame (74 bytes) */
/* IPv4 pakcet with next protocol 60(DESTINATION). */
static char pkt1[74] = {
0x20, 0x0b, 0xc7, 0x94, 0x45, 0x96, 0x18, 0x03, /*  ...E... */
0x73, 0x29, 0x5f, 0x66, 0x08, 0x00, 0x45, 0x00, /* s)_f..E. */
0x00, 0x3c, 0x6c, 0x31, 0x00, 0x00, 0x40, 0x3c, /* .<l1..@< */
0x10, 0x53, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* .S...... */
0x00, 0x01, 0x08, 0x00, 0x4d, 0x4a, 0x00, 0x01, /* ....MJ.. */
0x00, 0x11, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};

/* Frame (74 bytes) */
/* IPv4 pakcet with next protocol 43(ROUTING). */
static char pkt2[74] = {
0x20, 0x0b, 0xc7, 0x94, 0x45, 0x96, 0x18, 0x03, /*  ...E... */
0x73, 0x29, 0x5f, 0x66, 0x08, 0x00, 0x45, 0x00, /* s)_f..E. */
0x00, 0x3c, 0x6c, 0x31, 0x00, 0x00, 0x40, 0x2b, /* .<l1..@+ */
0x10, 0x64, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* .d...... */
0x00, 0x01, 0x08, 0x00, 0x4d, 0x4a, 0x00, 0x01, /* ....MJ.. */
0x00, 0x11, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};

/* Frame (74 bytes) */
/* IPv4 pakcet with next protocol 44(FRAGMENT). */
static char pkt3[74] = {
0x20, 0x0b, 0xc7, 0x94, 0x45, 0x96, 0x18, 0x03, /*  ...E... */
0x73, 0x29, 0x5f, 0x66, 0x08, 0x00, 0x45, 0x00, /* s)_f..E. */
0x00, 0x3c, 0x6c, 0x31, 0x00, 0x00, 0x40, 0x2c, /* .<l1..@, */
0x10, 0x63, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* .c...... */
0x00, 0x01, 0x08, 0x00, 0x4d, 0x4a, 0x00, 0x01, /* ....MJ.. */
0x00, 0x11, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};

#ifndef NX_IPSEC_ENABLE
/* Frame (74 bytes) */
/* IPv4 pakcet with next protocol 51(AH). */
static char pkt4[74] = {
0x20, 0x0b, 0xc7, 0x94, 0x45, 0x96, 0x18, 0x03, /*  ...E... */
0x73, 0x29, 0x5f, 0x66, 0x08, 0x00, 0x45, 0x00, /* s)_f..E. */
0x00, 0x3c, 0x6c, 0x31, 0x00, 0x00, 0x40, 0x33, /* .<l1..@3 */
0x10, 0x5c, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* .\...... */
0x00, 0x01, 0x08, 0x00, 0x4d, 0x4a, 0x00, 0x01, /* ....MJ.. */
0x00, 0x11, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};

/* Frame (74 bytes) */
/* IPv4 pakcet with next protocol 50(ESP). */
static char pkt5[74] = {
0x20, 0x0b, 0xc7, 0x94, 0x45, 0x96, 0x18, 0x03, /*  ...E... */
0x73, 0x29, 0x5f, 0x66, 0x08, 0x00, 0x45, 0x00, /* s)_f..E. */
0x00, 0x3c, 0x6c, 0x31, 0x00, 0x00, 0x40, 0x32, /* .<l1..@2 */
0x10, 0x5d, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* .]...... */
0x00, 0x01, 0x08, 0x00, 0x4d, 0x4a, 0x00, 0x01, /* ....MJ.. */
0x00, 0x11, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};
#endif /* NX_IPSEC_ENABLE */

/* IPv6 pakcet with next protocol 58(ICMPv6). */
/* Frame (70 bytes) */
static char pkt6[70] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x10, 0x3a, 0xff, 0xfe, 0x80, /* ....:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, /* ........ */
0x09, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x05, 0x06, 0x07, 0x08              /* ...... */
};

/* Frame (74 bytes) */
/* IPv4 pakcet with next protocol 1(ICMPv4). */
static char pkt7[74] = {
0x20, 0x0b, 0xc7, 0x94, 0x45, 0x96, 0x18, 0x03, /*  ...E... */
0x73, 0x29, 0x5f, 0x66, 0x08, 0x00, 0x45, 0x00, /* s)_f..E. */
0x00, 0x3c, 0x6c, 0x31, 0x00, 0x00, 0x40, 0x01, /* .<l1..@. */
0x10, 0x8e, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* ........ */
0x00, 0x01, 0x08, 0x00, 0x4d, 0x4a, 0x00, 0x01, /* ....MJ.. */
0x00, 0x11, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};

/* Frame (74 bytes) */
/* IPv4 pakcet with next protocol 2(IGMP). */
static char pkt8[74] = {
0x20, 0x0b, 0xc7, 0x94, 0x45, 0x96, 0x18, 0x03, /*  ...E... */
0x73, 0x29, 0x5f, 0x66, 0x08, 0x00, 0x45, 0x00, /* s)_f..E. */
0x00, 0x3c, 0x6c, 0x31, 0x00, 0x00, 0x40, 0x02, /* .<l1..@. */
0x10, 0x8d, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* ........ */
0x00, 0x01, 0x08, 0x00, 0x4d, 0x4a, 0x00, 0x01, /* ....MJ.. */
0x00, 0x11, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};

/* Frame (74 bytes) */
/* IPv4 pakcet with next protocol 17(UDP). */
static char pkt9[74] = {
0x20, 0x0b, 0xc7, 0x94, 0x45, 0x96, 0x18, 0x03, /*  ...E... */
0x73, 0x29, 0x5f, 0x66, 0x08, 0x00, 0x45, 0x00, /* s)_f..E. */
0x00, 0x3c, 0x6c, 0x31, 0x00, 0x00, 0x40, 0x11, /* .<l1..@. */
0x10, 0x7e, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* .~...... */
0x00, 0x01, 0x08, 0x00, 0x4d, 0x4a, 0x00, 0x01, /* ....MJ.. */
0x00, 0x11, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};

/* Frame (78 bytes) */
/* IPv6 pakcet with extension headers 0(hop by hop). */
/* The length in hop by hop header is larger than the packet length. */
static char pkt10[78] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x18, 0x2b, 0xff, 0xfe, 0x80, /* ....+... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3a, 0xff, /* ......:. */
0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, /* !....... */
0x72, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* r....... */
0x03, 0x04, 0x05, 0x06, 0x07, 0x08              /* ...... */
};


/* Frame (62 bytes) */
/* IPv6 packet with ICMPv6 redirect content. But the length of ICMPv6 is 8. */
static char pkt11[62] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0xa0, 0xa0, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x08, 0x3a, 0xff, 0xfe, 0x80, /* ...(:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x89, 0x00, /* ........ */
0xd7, 0x97, 0x00, 0x00, 0x00, 0x00              /* .w...... */
};

/* Frame (126 bytes) */
/* IPv6 packet with two hop by hop extension headers. */
static char pkt12[] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x8c, 0xec, /* 33...... */
0x4b, 0x68, 0xd1, 0xfe, 0x86, 0xdd, 0x60, 0x07, /* Kh....`. */
0x1f, 0xfc, 0x00, 0x48, 0x00, 0xff, 0xfe, 0x80, /* ...H.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8e, 0xec, /* ........ */
0x4b, 0xff, 0xfe, 0x68, 0xd1, 0xfe, 0xff, 0x02, /* K..h.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, /* ........ */
0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, /* ......:. */
0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x86, 0x00, /* ........ */
0xca, 0xef, 0x40, 0x00, 0x00, 0x5a, 0x00, 0x00, /* ..@..Z.. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04, /* ........ */
0x40, 0xc0, 0x00, 0x01, 0x51, 0x80, 0x00, 0x00, /* @...Q... */
0x38, 0x40, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, /* 8@.... . */
0x04, 0x70, 0xf8, 0x1e, 0x30, 0x00, 0x00, 0x00, /* .p..0... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, /* ........ */
0x8c, 0xec, 0x4b, 0x68, 0xd1, 0xfe              /* ..Kh.. */
};

/* Frame (102 bytes) */
/* RA packet with invalid option type (0). */
static char pkt13[] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x8c, 0xec, /* 33...... */
0x4b, 0x68, 0xd1, 0xfe, 0x86, 0xdd, 0x60, 0x07, /* Kh....`. */
0x1f, 0xfc, 0x00, 0x30, 0x3a, 0xff, 0xfe, 0x80, /* ...0:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8e, 0xec, /* ........ */
0x4b, 0xff, 0xfe, 0x68, 0xd1, 0xfe, 0xff, 0x02, /* K..h.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00, /* ........ */
0x79, 0x4c, 0x40, 0x00, 0x00, 0x5a, 0x00, 0x00, /* yL@..Z.. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, /* ........ */
0x40, 0xc0, 0x00, 0x01, 0x51, 0x80, 0x00, 0x00, /* @...Q... */
0x38, 0x40, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, /* 8@.... . */
0x04, 0x70, 0xf8, 0x1e, 0x30, 0x00, 0x00, 0x00, /* .p..0... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

/* Frame (74 bytes) */
/* IPv4 pakcet with invalid header length. */
static char pkt14[74] = {
0x20, 0x0b, 0xc7, 0x94, 0x44, 0x96, 0x18, 0x03, /*  ...E... */
0x73, 0x29, 0x5f, 0x66, 0x08, 0x00, 0x44, 0x00, /* s)_f..E. */
0x00, 0x3c, 0x6c, 0x31, 0x00, 0x00, 0x40, 0x01, /* .<l1..@, */
0x10, 0x8e, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, /* .c...... */
0x00, 0x01, 0x08, 0x00, 0x4d, 0x4a, 0x00, 0x01, /* ....MJ.. */
0x00, 0x11, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ip_abnormal_packet_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    /* Initialize the value.  */
    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;
  
    /* Enable IPv6 */
    status += nxd_ipv6_enable(&ip_0); 

    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;        

    /* Enable IPv6 ICMP  */
    status += nxd_icmp_enable(&ip_0); 

    /* Check IPv6 ICMP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT                    status;   
NX_PACKET              *packet_ptr;
NX_PACKET              *ping_resp;
CHAR                   *pkt_data_ptr;
CHAR                    pkt_len;

    /* Print out test information banner.  */
    printf("NetX Test:   IP Abnormal Packet Test..................................."); 

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                     

    /* Set the linklocal address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NULL); 

    /* Check the status.  */
    if(status)
        error_counter++;  

    /* Sleep 5 seconds for linklocal address DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt1;
    pkt_len = sizeof(pkt1);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Set invalid value to test destination protocol. */
    packet_ptr -> nx_packet_destination_header = 1;
    packet_ptr -> nx_packet_option_state = 0;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt2;
    pkt_len = sizeof(pkt2);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Set invalid value to test destination protocol. */
    packet_ptr -> nx_packet_destination_header = 0;
    packet_ptr -> nx_packet_option_state = ROUTING_HEADER;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt3;
    pkt_len = sizeof(pkt3);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Set invalid value to test destination protocol. */
    packet_ptr -> nx_packet_destination_header = 0;
    packet_ptr -> nx_packet_option_state = FRAGMENT_HEADER;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


#ifndef NX_IPSEC_ENABLE
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt4;
    pkt_len = sizeof(pkt4);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt5;
    pkt_len = sizeof(pkt5);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }
#endif /* NX_IPSEC_ENABLE */


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt6;
    pkt_len = sizeof(pkt6);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Disable ICMP. */
    ip_0.nx_ip_icmpv6_packet_process = NX_NULL;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Disable ICMP. */
    ip_0.nx_ip_icmpv6_packet_process = _nx_icmpv6_packet_process;

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt7;
    pkt_len = sizeof(pkt7);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Disable ICMP. */
    ip_0.nx_ip_icmp_packet_receive = NX_NULL;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Disable ICMP. */
    ip_0.nx_ip_icmp_packet_receive = _nx_icmp_packet_receive;

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt8;
    pkt_len = sizeof(pkt8);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt9;
    pkt_len = sizeof(pkt9);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt10;
    pkt_len = sizeof(pkt10);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt11;
    pkt_len = sizeof(pkt11);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "", 0, &ping_resp, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(ping_resp);
    }


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt12;
    pkt_len = sizeof(pkt12);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt13;
    pkt_len = sizeof(pkt13);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    pkt_data_ptr = pkt14;
    pkt_len = sizeof(pkt14);
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt_data_ptr[14], pkt_len - 14);
    packet_ptr -> nx_packet_length = pkt_len - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Check the error.  */
    if(error_counter)
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
void           netx_ip_abnormal_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Abnormal Packet Test...................................N/A\n"); 
    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
