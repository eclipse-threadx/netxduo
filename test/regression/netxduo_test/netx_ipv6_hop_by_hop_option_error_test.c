/* This NetX test to test the IPv6 onlink search.  */

#include    "tx_api.h"
#include    "nx_api.h"
extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6)  && !defined(NX_DISABLE_ICMP_INFO)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"    
#include    "nx_icmpv6.h"
#include    "nx_ram_network_driver_test_1500.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;           


/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    icmp_checksum_compute(NX_PACKET *packet_ptr);


static char pkt1[78] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x18, 0x00, 0xff, 0xfe, 0x80, /* ... .... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x3a, 0x00, /* "..3DV:. */
0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, /* ........ */
0x09, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x05, 0x06, 0x07, 0x08              /* ...... */
};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_hop_by_hop_option_error_test_application_define(void *first_unused_memory)
#endif
{
    CHAR       *pointer;
    UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*4);
    pointer = pointer + 1536*4;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = _nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
        pointer, 2048, 1);
    pointer = pointer + 2048;
                
    /* Check IP create status.  */
    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
                 
    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMP for IP Instance 0.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check ICMP enable status.  */
    if(status)
        error_counter++;

}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
    
    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Hop By Hop Option Error Test.........................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the linklocal address*/
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);
       
    /* Check the status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                                                

    /* Waiting for DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
                                             
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_IPv6_PACKET, 5 * NX_IP_PERIODIC_RATE);
               
    /* Write data into the packet payload, ignore the physical header!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt1[14], 64);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  64;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 64;

    /* Set the interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0]; 

    /* Calculate the ICMP checksum. */
    icmp_checksum_compute(my_packet);

    /* Call the _nx_ip_packet_receive function directly receive the ICMPv6 Request with hop by hop option.  */
    _nx_ip_packet_receive(&ip_0, my_packet);
  
    /* Check the value.  */    
    if ((ip_0.nx_ip_pings_received != 1) || (ip_0.nx_ip_pings_responded_to != 1))  
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                   
                        
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_IPv6_PACKET, 5 * NX_IP_PERIODIC_RATE);
               
    /* Write data into the packet payload, ignore the physical header!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt1[14], 64);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  64;

    /* Set the error append pointer.  */
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 46;

    /* Set the interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0]; 

    /* Calculate the ICMP checksum. */
    icmp_checksum_compute(my_packet);

    /* Call the _nx_ip_packet_receive function directly receive the ICMPv6 Request with hop by hop option.  */
    _nx_ip_packet_receive(&ip_0, my_packet);
 
    /* Check the value.  */    
    if ((ip_0.nx_ip_pings_received != 1) || (ip_0.nx_ip_pings_responded_to != 1))  
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                                                    

    /* buffer overread test */

    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_IPv6_PACKET, 5 * NX_IP_PERIODIC_RATE);
               
    /* Write data into the packet payload, ignore the physical header!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt1[14], 64);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  64;

    /* Set the error append pointer.  */
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 1;

    /* Set the interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];

    /* invoke _nx_ipv6_process_hop_by_hop_option with error packet. */
    status = _nx_ipv6_process_hop_by_hop_option(NX_NULL, my_packet);

    /* Check the status. */
    if (status != NX_OPTION_HEADER_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Out successful.  */
    printf("SUCCESS!\n");    
    test_control_return(0);
}                  

static void    icmp_checksum_compute(NX_PACKET *packet_ptr)
{
NX_ICMPV6_HEADER   *header_ptr;   
ULONG              *source_ip, *dest_ip;
ULONG               checksum;

    /* Set packet version. */
    packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V6;

    /* Get IPv6 addresses. */
    source_ip = (ULONG *)(packet_ptr -> nx_packet_prepend_ptr + 8);
    dest_ip = (ULONG *)(packet_ptr -> nx_packet_prepend_ptr + 24);
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(source_ip);
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(dest_ip);

    /* Skip IPv6 header and hop by hop header. */
    packet_ptr -> nx_packet_prepend_ptr += sizeof(NX_IPV6_HEADER) + 8;
    packet_ptr -> nx_packet_length -= sizeof(NX_IPV6_HEADER) + 8;

    header_ptr = (NX_ICMPV6_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);

    /* Calculate the ICMP checksum.  */
    header_ptr -> nx_icmpv6_header_checksum = 0;

    /* Calculate the checksum.  */
    checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_ICMPV6,
                                       packet_ptr -> nx_packet_length,
                                       source_ip, dest_ip);
    checksum = ~checksum & NX_LOWER_16_MASK;
    header_ptr -> nx_icmpv6_header_checksum = checksum;
    NX_CHANGE_USHORT_ENDIAN(header_ptr -> nx_icmpv6_header_checksum);

    /* Recover IPv6 header. */
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(source_ip);
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(dest_ip);
    packet_ptr -> nx_packet_prepend_ptr -= sizeof(NX_IPV6_HEADER) + 8;
    packet_ptr -> nx_packet_length += sizeof(NX_IPV6_HEADER) + 8;
}


#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_hop_by_hop_option_error_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Hop By Hop Option Error Test.........................N/A\n");

    test_control_return(3);

}
#endif
