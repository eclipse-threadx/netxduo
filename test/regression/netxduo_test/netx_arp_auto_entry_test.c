/* Test ARP entry is created automatically on receiving an ARP packet. */

#include    "nx_api.h"   

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_ARP_AUTO_ENTRY) && !defined(NX_DISABLE_IPV4)
 
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
 * src MAC: 20:0b:c7:94:45:96
 * src IP: 1.2.3.5.
 * dst MAC: 00:00:00:00:00:00
 * dst IP: 1.2.3.4. */
static char arp_pkt[] = {
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x06, 0x00, 0x01, /* ..E..... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x96, 0x01, 0x02, 0x03, 0x05, /* ..E..... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
};


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_arp_auto_entry_test_application_define(void *first_unused_memory)
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
UINT        status;   
NX_PACKET  *packet_ptr;
ULONG       physical_msw, physical_lsw;

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Auto Entry Test......................................."); 

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
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &arp_pkt[14], sizeof(arp_pkt) - 14);
    packet_ptr -> nx_packet_length = sizeof(arp_pkt) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ARP packet.  */
    _nx_arp_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Verify ARP entry is created. */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 5), &physical_msw, &physical_lsw);

    /* Check status */
    if(status)
        error_counter++;

    /* Verify the MAC. */
    if ((((physical_msw >> 8) & 0xFF) != 0x20) ||
        (((physical_msw) & 0xFF) != 0x0b) ||
        (((physical_lsw >> 24) & 0xFF) != 0xc7) ||
        (((physical_lsw >> 16) & 0xFF) != 0x94) ||
        (((physical_lsw >> 8) & 0xFF) != 0x45) ||
        (((physical_lsw) & 0xFF) != 0x96))
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
void           netx_arp_auto_entry_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Invalid Type Test.....................................N/A\n"); 
    test_control_return(3);

}
#endif /* NX_DISABLE_ARP_AUTO_ENTRY */
