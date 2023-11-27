/* Test the process of NA packet. Section 7.2.5, RFC 4861
 * 1. Inject RA packet with TLLA. 
 * 2. Inject NA packet with different LLA. All flags are not set. 
 * 3. Router should not be modified since overwrite bit is not set and TLLA is different.
 * 4. Inject NA packet with no TLLA. All flags are not set. 
 * 5. Router should be deleted since no TLLA. */

#include    "nx_api.h"   

extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_ICMPV6_ROUTER_ADVERTISEMENT_PROCESS)
 
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

static char ra_pkt[110] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, /* 33...... */
0x00, 0x00, 0xa0, 0xa0, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x38, 0x3a, 0xff, 0xfe, 0x80, /* ...8:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00, /* ........ */
0x1c, 0xb4, 0x40, 0x00, 0x00, 0x14, 0x00, 0x01, /* ..@..... */
0x86, 0xa0, 0x00, 0x00, 0x03, 0xe8, 0x01, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0xa0, 0xa0, 0x03, 0x04, /* ........ */
0x40, 0xc0, 0x00, 0x27, 0x8d, 0x00, 0x00, 0x09, /* @..'.... */
0x3a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xfe, /* :.....?. */
0x05, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

static char na_pkt1[86] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, /* 33...... */
0x00, 0x00, 0xc0, 0xc0, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, /* ... :... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0x00, /* ........ */
0x75, 0x9c, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, /* u....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0x02, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0xc0, 0xc0              /* ...... */
};

static char na_pkt2[78] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0xa0, 0xa0, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x18, 0x3a, 0xff, 0xfe, 0x80, /* ....:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x88, 0x00, /* "..3DV.. */
0xd1, 0x4e, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, /* .N...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0              /* ...... */
};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmpv6_na_test_application_define(void *first_unused_memory)
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
UINT        status;   
NX_PACKET  *packet_ptr;
UINT        num_entries;

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 NA Test............................................"); 

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                     

    /* Set the linklocal address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL); 

    /* Check the status.  */
    if(status)
        error_counter++;  

    /* Sleep 5 seconds for linklocal address DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);


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

    /* Check whether one router is added. */
    status = nxd_ipv6_default_router_number_of_entries_get(&ip_0, 0, &num_entries);

    /* Check status */
    if(status)
        error_counter++;

    if (num_entries != 1)
        error_counter++;


    /* Inject the first NA packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &na_pkt1[14], sizeof(na_pkt1) - 14);
    packet_ptr -> nx_packet_length = sizeof(na_pkt1) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the NA packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Check whether one router is still available. */
    status = nxd_ipv6_default_router_number_of_entries_get(&ip_0, 0, &num_entries);

    /* Check status */
    if(status)
        error_counter++;

    if (num_entries != 1)
        error_counter++;


    /* Inject the second NA packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &na_pkt2[14], sizeof(na_pkt2) - 14);
    packet_ptr -> nx_packet_length = sizeof(na_pkt2) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the NA packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Check whether no router is available. */
    status = nxd_ipv6_default_router_number_of_entries_get(&ip_0, 0, &num_entries);

    /* Check status */
    if(status)
        error_counter++;

    if (num_entries != 0)
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
void           netx_icmpv6_na_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 NA Test............................................N/A\n"); 
    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
