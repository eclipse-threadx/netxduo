/* This NetX test concentrates on the basic TCP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_tcp.h"
#include   "nx_icmp.h"
#ifdef FEATURE_NX_IPV6
#include "nx_ipv6.h"
#endif /* FEATURE_NX_IPV6 */

#if defined(__PRODUCT_NETX__)
#define NX_PROTOCOL_TCP                          6
#define NX_PROTOCOL_UDP                         17
#define NX_PROTOCOL_ICMPV6                      58
#define NX_PROTOCOL_ICMP                         1
#define NX_IP_VERSION_V4                         4 /* IP-in-IP encapsulation */
#endif

#define     DEMO_STACK_SIZE         2048
#define     PHYSICAL_OFFSET         14

/* Define raw packet data. */
static char pkt_tcp_32[] = {
0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x00, 0x0c, 
0x29, 0x01, 0xd4, 0x79, 0x08, 0x00, 0x45, 0x10, 
0x00, 0x34, 0xf2, 0x4b, 0x40, 0x00, 0x40, 0x06, 
0xea, 0x94, 0xc0, 0xa8, 0xee, 0x80, 0xc0, 0xa8, 
0xee, 0x01, 0x00, 0x16, 0xe2, 0xb1, 0xcb, 0xe8, 
0x2a, 0xb4, 0x0a, 0x4e, 0x4c, 0x16, 0x80, 0x10, 
0x03, 0xea, 0x36, 0xba, 0x00, 0x00, 0x01, 0x01, 
0x05, 0x0a, 0x0a, 0x4e, 0x4e, 0x16, 0x0a, 0x4e, 
0x4e, 0xca };

static char pkt_tcp_37[] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x39, 0x77, 0xd7, 0x40, 0x00, 0x40, 0x06, 
0xc4, 0xe5, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 
0x00, 0x01, 0x00, 0x0d, 0x9d, 0x48, 0x52, 0x32, 
0xec, 0x47, 0x52, 0x2b, 0x98, 0x93, 0x80, 0x18, 
0x02, 0x00, 0x4f, 0x22, 0x00, 0x00, 0x01, 0x01, 
0x08, 0x0a, 0x03, 0x05, 0x9b, 0x90, 0x03, 0x05, 
0x9b, 0x90, 0x48, 0x65, 0x6c, 0x6c, 0x6f };

static char pkt_udp_53[] = {
0x00, 0x50, 0x56, 0xfb, 0x32, 0x2d, 0x00, 0x0c, 
0x29, 0x01, 0xd4, 0x79, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x49, 0x43, 0x73, 0x40, 0x00, 0x40, 0x11, 
0x99, 0x5c, 0xc0, 0xa8, 0xee, 0x80, 0xc0, 0xa8, 
0xee, 0x02, 0xe1, 0xee, 0x00, 0x35, 0x00, 0x35, 
0x61, 0x91, 0x7c, 0x8c, 0x01, 0x00, 0x00, 0x01, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x68, 
0x65, 0x6c, 0x70, 0x06, 0x75, 0x62, 0x75, 0x6e, 
0x74, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x0b, 0x6c, 
0x6f, 0x63, 0x61, 0x6c, 0x64, 0x6f, 0x6d, 0x61, 
0x69, 0x6e, 0x00, 0x00, 0x1c, 0x00, 0x01 };

static char pkt_udp_40[] = {
0x00, 0x50, 0x56, 0xfb, 0x32, 0x2d, 0x00, 0x0c, 
0x29, 0x01, 0xd4, 0x79, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x3c, 0x43, 0x5a, 0x40, 0x00, 0x40, 0x11, 
0x99, 0x82, 0xc0, 0xa8, 0xee, 0x80, 0xc0, 0xa8, 
0xee, 0x02, 0xd7, 0x98, 0x00, 0x35, 0x00, 0x28, 
0x06, 0x9c, 0x34, 0xb8, 0x01, 0x00, 0x00, 0x01, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 
0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 
0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 
0x00, 0x01 };

static char pkt_icmp_18[] = {
0x00, 0x50, 0x56, 0xfb, 0x32, 0x2d, 0x00, 0x0c, 
0x29, 0x01, 0xd4, 0x79, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x26, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 
0xcb, 0x04, 0xc0, 0xa8, 0xee, 0x80, 0xc0, 0xa8, 
0x00, 0x01, 0x08, 0x00, 0x26, 0x76, 0x15, 0xa0, 
0x00, 0x01, 0x71, 0x94, 0xd1, 0x50, 0x65, 0xfa, 
0x0b, 0x00, 0x08, 0x09 };

static char pkt_icmp_23[] = {
0x00, 0x50, 0x56, 0xfb, 0x32, 0x2d, 0x00, 0x0c, 
0x29, 0x01, 0xd4, 0x79, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x2b, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 
0xca, 0xff, 0xc0, 0xa8, 0xee, 0x80, 0xc0, 0xa8, 
0x00, 0x01, 0x08, 0x00, 0x55, 0x9b, 0x15, 0xa4, 
0x00, 0x02, 0x91, 0x94, 0xd1, 0x50, 0xf2, 0xb7, 
0x0b, 0x00, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 
0x0e };

static char pkt_icmpv6_32[] = {
0x33, 0x33, 0xff, 0x89, 0x7e, 0xba, 0x00, 0x0c, 
0x29, 0x01, 0xd4, 0x79, 0x86, 0xdd, 0x60, 0x00, 
0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0c, 
0x29, 0xff, 0xfe, 0x01, 0xd4, 0x79, 0xff, 0x02, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x01, 0xff, 0x89, 0x7e, 0xba, 0x87, 0x00, 
0x42, 0x58, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9d, 0x70, 
0x49, 0x3f, 0x59, 0x89, 0x7e, 0xba, 0x01, 0x01, 
0x00, 0x0c, 0x29, 0x01, 0xd4, 0x79 };



/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    verify_checksum(UINT index);
extern void    test_control_return(UINT status);

typedef struct CHECKSUM_TEST_SEQ_STRUCT
{
    char        *pkt_data;
    int         pkt_size;

    ULONG       protocol;
    ULONG       offset;
}CHECKSUM_TEST_SEQ;

static CHECKSUM_TEST_SEQ checksum_test_seq[] = 
{
    
    /* ICMPv6 checksum with payload size 32. */
    {pkt_icmpv6_32, sizeof(pkt_icmpv6_32), NX_PROTOCOL_ICMPV6, 54},
    
    /* Following packets are IPv4. */
    /* IPv4 checksum with payload size 43. */
    {pkt_icmp_23, sizeof(pkt_icmp_23), NX_IP_VERSION_V4, 14},
    
    /* ICMPv4 checksum with payload size 23. */
    {pkt_icmp_23, sizeof(pkt_icmp_23), NX_PROTOCOL_ICMP, 34},
    
    /* IPv4 checksum with payload size 38. */
    {pkt_icmp_18, sizeof(pkt_icmp_18), NX_IP_VERSION_V4, 14},
    
    /* ICMPv4 checksum with payload size 18. */
    {pkt_icmp_18, sizeof(pkt_icmp_18), NX_PROTOCOL_ICMP, 34},
    
    /* IPv4 checksum with payload size 60. */
    {pkt_udp_40, sizeof(pkt_udp_40), NX_IP_VERSION_V4, 14},
    
    /* UDP checksum with payload size 40. */
    {pkt_udp_40, sizeof(pkt_udp_40), NX_PROTOCOL_UDP, 34},
    
    /* IPv4 checksum with payload size 73. */
    {pkt_udp_53, sizeof(pkt_udp_53), NX_IP_VERSION_V4, 14},
    
    /* UDP checksum with payload size 53. */
    {pkt_udp_53, sizeof(pkt_udp_53), NX_PROTOCOL_UDP, 34},
    
    /* IPv4 checksum with payload size 57. */
    {pkt_tcp_37, sizeof(pkt_tcp_37), NX_IP_VERSION_V4, 14},
    
    /* TCP checksum with payload size 37. */
    {pkt_tcp_37, sizeof(pkt_tcp_37), NX_PROTOCOL_TCP, 34},
    
    /* IPv4 checksum with payload size 52. */
    {pkt_tcp_32, sizeof(pkt_tcp_32), NX_IP_VERSION_V4, 14},
    
    /* TCP checksum with payload size 32. */
    {pkt_tcp_32, sizeof(pkt_tcp_32), NX_PROTOCOL_TCP, 34}
};

static UINT     seq_size = sizeof(checksum_test_seq)/sizeof(CHECKSUM_TEST_SEQ);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_checksum_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        i;

    /* Print out some test information banners.  */
    printf("NetX Test:   Checksum Test.............................................");

    for(i = 0; i < seq_size; i++)
        verify_checksum(i);
        
    /* Check status.  */
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

/* Define the verify checksum function. */
static void    verify_checksum(UINT index)
{
NX_PACKET   *pkt_ptr;
ULONG       source_ip[4];
ULONG       dest_ip[4];
ULONG       checksum;


    /* Allocate a packet and fill data into the packet. */
    if(nx_packet_allocate(&pool_0, &pkt_ptr, NX_RECEIVE_PACKET, TX_NO_WAIT))
    {
        error_counter++;
        return;
    }
    if(nx_packet_data_append(pkt_ptr, checksum_test_seq[index].pkt_data + checksum_test_seq[index].offset,
                             checksum_test_seq[index].pkt_size - checksum_test_seq[index].offset,
                             &pool_0, TX_NO_WAIT))
    {
        error_counter++;
        nx_packet_release(pkt_ptr);
        return;
    }

#if defined(__PRODUCT_NETXDUO__)
    /* Get IP address. */
    if((*(checksum_test_seq[index].pkt_data + PHYSICAL_OFFSET) >> 4) == NX_IP_VERSION_V4)
    {
#ifndef NX_DISABLE_IPV4
        NX_IPV4_HEADER *ip_header_ptr;
        ip_header_ptr = (NX_IPV4_HEADER*)(checksum_test_seq[index].pkt_data + PHYSICAL_OFFSET);
        source_ip[0] = ip_header_ptr -> nx_ip_header_source_ip;
        dest_ip[0] = ip_header_ptr -> nx_ip_header_destination_ip;
        NX_CHANGE_ULONG_ENDIAN(source_ip[0]);
        NX_CHANGE_ULONG_ENDIAN(dest_ip[0]);

        pkt_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;
#else
        nx_packet_release(pkt_ptr);
        return;
#endif /* NX_DISABLE_IPV4 */
    }
#ifdef FEATURE_NX_IPV6
    else if((*(checksum_test_seq[index].pkt_data + PHYSICAL_OFFSET) >> 4) == NX_IP_VERSION_V6)
    {
        NX_IPV6_HEADER *ipv6_header;
        ipv6_header = (NX_IPV6_HEADER*)(checksum_test_seq[index].pkt_data + PHYSICAL_OFFSET);
        COPY_IPV6_ADDRESS(ipv6_header -> nx_ip_header_source_ip, source_ip);
        COPY_IPV6_ADDRESS(ipv6_header -> nx_ip_header_destination_ip, dest_ip);
        _nx_ipv6_address_change_endian(source_ip);
        _nx_ipv6_address_change_endian(dest_ip);
        
        pkt_ptr -> nx_packet_ip_version = NX_IP_VERSION_V6;
    }
#endif /* FEATURE_NX_IPV6 */
    else
    {

        /* Release packet. */
        nx_packet_release(pkt_ptr);
        return;
    }
    
    if(checksum_test_seq[index].protocol == NX_IP_VERSION_V4)
        pkt_ptr -> nx_packet_length = 20;
    
    /* Calculate checksum. */
    checksum = _nx_ip_checksum_compute(pkt_ptr, checksum_test_seq[index].protocol,
                                       pkt_ptr -> nx_packet_length,
                                       source_ip, dest_ip);

    checksum = ~checksum & NX_LOWER_16_MASK;
#elif defined(__PRODUCT_NETX__)
    checksum = 0;
    if(checksum_test_seq[index].protocol == NX_PROTOCOL_TCP)
    {
        NX_IP_HEADER *ip_header_ptr;
        ip_header_ptr = (NX_IP_HEADER*)(checksum_test_seq[index].pkt_data + PHYSICAL_OFFSET);
        source_ip[0] = ip_header_ptr -> nx_ip_header_source_ip;
        dest_ip[0] = ip_header_ptr -> nx_ip_header_destination_ip;
        NX_CHANGE_ULONG_ENDIAN(source_ip[0]);
        NX_CHANGE_ULONG_ENDIAN(dest_ip[0]);
        checksum = _nx_tcp_checksum(pkt_ptr, source_ip[0], dest_ip[0]);
    }
    else if(checksum_test_seq[index].protocol == NX_PROTOCOL_ICMP)
    {
        checksum = _nx_icmp_checksum_compute(pkt_ptr);
        checksum =  ~checksum & NX_LOWER_16_MASK;
    }
#endif
    if(checksum)
        error_counter++;

    /* Release packet. */
    nx_packet_release(pkt_ptr);
}
