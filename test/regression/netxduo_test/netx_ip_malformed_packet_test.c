/* Test processing malformed IP packet. */

#include    "netx_ip_malformed_packet_test.h"

extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_FRAGMENTATION)
 
#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static UCHAR                   pool_area[1024 * 1024];

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;  

/* Define thread prototypes.  */
static VOID    thread_0_entry(ULONG thread_input);
extern VOID    test_control_return(UINT status);       
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ip_malformed_packet_test_application_define(void *first_unused_memory)
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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1552, pool_area, sizeof(pool_area));

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(192,168,0,170), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Enable ARP  */
    status = nx_arp_enable(&ip_0, pointer, 1024); 

    /* Check ARP enable status.  */
    if(status)
        error_counter++;
    pointer = pointer + 1024;

    /* Enable IP fragmentation logic.  */
    status =  nx_ip_fragment_enable(&ip_0);

    /* Check for IP fragment enable errors.  */
    if (status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT        status;
UINT        i;
ULONG       packet_available;
NX_PACKET  *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   IP Malformed Packet Test.................................."); 

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get available packets. */
    packet_available = pool_0.nx_packet_pool_available;

    for (i = 0; i < sizeof(raw_packets) / sizeof(RAW_PACKET); i++)
    {

        /* Inject all packets. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

        /* Check status */
        if(status)
            error_counter++;

        /* Fill in the packet with data. Skip the MAC header.  */
        memcpy(packet_ptr -> nx_packet_prepend_ptr, raw_packets[i].data, raw_packets[i].length);
        packet_ptr -> nx_packet_length = raw_packets[i].length;
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

        /* Directly receive the IP packet.  */
        _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);
    }

    /* Sleep one second to let all packets consumed by IP thread. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE); 

    /* Check available packets. */
    if (packet_available != pool_0.nx_packet_pool_available)
    {
        error_counter++;
    }

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
void           netx_ip_malformed_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Malformed Packet Test..................................N/A\n"); 
    test_control_return(3);

}
#endif /* NX_DISABLE_ARP_AUTO_ENTRY */
