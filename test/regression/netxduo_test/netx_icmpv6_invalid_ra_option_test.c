/* Test processing of RA with invalid option. */

#include    "nx_api.h"   

extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_ICMP_INFO) && !defined(NX_DISABLE_IP_INFO)
 
#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */
static VOID    thread_0_entry(ULONG thread_input);
extern VOID    test_control_return(UINT status);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* RA packet.
 * Invalid option length for option type ICMPV6_OPTION_TYPE_PREFIX_INFO. */
static char ra_pkt[] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00,
0x00, 0x00, 0x00, 0x40, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00, 0xa0, 0x1d, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00,
0x75, 0x30, 0x00, 0x00, 0x03, 0xe8, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x01,
0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x03, 0x04, 0x40, 0xc0, 0x00, 0x27, 0x8d, 0x00, 0x00, 0x09,
0x3a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xfe, 0x05, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmpv6_invalid_ra_option_test_application_define(void *first_unused_memory)
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
UINT                    address_index;
NXD_ADDRESS             ipv6_address;
ULONG                   prefix_length;
UINT                    interface_index;
NX_PACKET              *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 Invalid RA Option Test............................."); 

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                     

    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;
    ipv6_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[2] = 0x021122FF;
    ipv6_address.nxd_ip_address.v6[3] = 0xFE334456;

    /* Set the linklocal address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 10, &address_index); 

    /* Check the status.  */
    if(status)
        error_counter++;  

    /* Sleep 5 seconds for linklocal address DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Get the linklocal address.  */
    status = nxd_ipv6_address_get(&ip_0, address_index, &ipv6_address, &prefix_length, &interface_index);
                       
    /* Check the status.  */
    if((status) || (prefix_length != 10) || (interface_index != 0))
        error_counter++;  

    /* Inject RA packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &ra_pkt[14], sizeof(ra_pkt) - 14);
    packet_ptr -> nx_packet_length = sizeof(ra_pkt) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the RA packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);

    /* Verify the packet is received by IP but dropped by ICMP layer. */
    if ((ip_0.nx_ip_total_packets_delivered != 1) || (ip_0.nx_ip_icmp_invalid_packets != 1))
        error_counter++;  

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
void           netx_icmpv6_invalid_ra_option_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 Invalid RA Option Test.............................N/A\n"); 
    test_control_return(3);

}
#endif 
