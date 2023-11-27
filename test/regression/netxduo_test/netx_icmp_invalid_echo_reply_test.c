/* This NetX test concentrates on processing an echo reply without sequence match.  */

#include   "nx_api.h"

extern void  test_control_return(UINT status);
#if !defined(NX_DISABLE_ICMP_INFO) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* ICMP packet.
 * src: 1.2.3.5
 * dst: 1.2.3.4 */
static char icmp_pkt[] = {
0x18, 0x03, 0x73, 0x29, 0x5f, 0x66, 0x20, 0x0b, /* ..s)_f . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x00, 0x45, 0x00, /* ..E...E. */
0x00, 0x3c, 0x2b, 0x25, 0x00, 0x00, 0xff, 0x01, /* .<+%.... */
0x88, 0x8f, 0x01, 0x02, 0x03, 0x05, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x00, 0x00, 0x55, 0x5a, 0x00, 0x01, /* ....UZ.. */
0x00, 0x01, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_invalid_echo_reply_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 4096);
    pointer = pointer + 4096;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing.  */
    status =  nx_icmp_enable(&ip_0);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Invalid Echo Reply Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Inject Echo Reply packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &icmp_pkt[14], sizeof(icmp_pkt) - 14);
    packet_ptr -> nx_packet_length = sizeof(icmp_pkt) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the Echo Reply packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    if ((ip_0.nx_ip_ping_responses_received != 1) ||
        (ip_0.nx_ip_icmp_invalid_packets != 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_invalid_echo_reply_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   ICMP Invalid Echo Reply Test..............................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_ICMP_INFO */
