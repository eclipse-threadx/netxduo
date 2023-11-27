/* Test processing of ARP packet with invalid type. */

#include    "nx_api.h"   

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_ARP_INFO) && !defined(NX_DISABLE_IPV4)
 
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

/* ARP packet. 
 * Type: 0003. */
static char ra_pkt[] = {
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x06, 0x00, 0x01, /* ..E..... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x03, 0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x96, 0xc0, 0xa8, 0x64, 0x01, /* ..E...d. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, /* ........ */
0x64, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* d....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
};


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_arp_invalid_type_test_application_define(void *first_unused_memory)
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

    /* Enable ARP  */
    status = nx_arp_enable(&ip_0, pointer, 1024); 

    /* Check ARP enable status.  */
    if(status)
        error_counter++;
    pointer = pointer + 1024;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT                    status;   
NX_PACKET              *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Invalid Type Test....................................."); 

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                     

    /* Inject ARP packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &ra_pkt[14], sizeof(ra_pkt) - 14);
    packet_ptr -> nx_packet_length = sizeof(ra_pkt) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ARP packet.  */
    _nx_arp_packet_deferred_receive(&ip_0, packet_ptr);     

    if (ip_0.nx_ip_arp_invalid_messages != 1)
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
void           netx_arp_invalid_type_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Invalid Type Test.....................................N/A\n"); 
    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
