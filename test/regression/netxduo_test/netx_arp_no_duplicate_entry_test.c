/* Send ARP packets using the deferred receive service. This test checks that duplicate ARP entries are
   not created, that existing matching ARP entries will be updated regardless of message type, and ARP probe 
   packets (zero sender IP address) are not entered into the ARP cache. */

#include    "nx_api.h"   

extern void    test_control_return(UINT status);

#if !defined (NX_DISABLE_ARP_AUTO_ENTRY) && !defined(NX_DISABLE_IPV4)
 
#define     DEMO_STACK_SIZE    2048

#ifdef __PRODUCT_NETX__
#define NX_ARP_TABLE_MASK NX_ROUTE_TABLE_MASK
#endif

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

/* ARP request packet. This test checks that request packets are checked for adding to/updating the ARP cache.
 * src MAC: 20:0b:c7:94:45:96
 * src IP: 1.2.3.5.
 * target MAC: 00:00:00:00:00:00
 * target IP: 1.2.3.4. */
static char arp_request_pkt[] = {
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x96, 0x08, 0x06, 0x00, 0x01, /* ..E..... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 
                                    0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x96, 0x01, 0x02, 0x03, 0x05, /* ..E..... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
};


/* Second ARP request packet  
 * src MAC: 20:0b:c7:94:45:97  The test is to check if the 20:0b:c7:94:45:96 entry is updated to 20:0b:c7:94:45:97
                               there should not be duplicate entries for 1.2.3.5. 
 * src IP: 1.2.3.5.
 * target MAC: 00:00:00:00:00:00
 * target IP: 1.2.3.4. */
static char arp_request_pkt2[] = {
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x97, 0x08, 0x06, 0x00, 0x01, /* ..E..... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 
                                    0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x97, 0x01, 0x02, 0x03, 0x05, /* ..E..... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

/* An ARP reply packet; This tests that NetX checks responses for updating its ARP Cache
 * src MAC: 30:1b:d7:a4:55:a6
 * src IP: 1.2.3.44.
 * target MAC: 22:0b:c7:94:45:98
 * target IP: 1.2.3.6. */  
static char arp_reply_pkt[] = {
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x30, 0x1b, /* ...... . */
0xd7, 0xa4, 0x55, 0xa6, 0x08, 0x06, 0x00, 0x01, /* ..E..... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 
                                    0x30, 0x1b, /* ...... . */
0xd7, 0xa4, 0x55, 0xa6, 0x01, 0x02, 0x03, 0x2c, /* ..E..... */
0x22, 0x0b, 0xc7, 0x94, 0x45, 0x98, 0x01, 0x02, /* ........ */
0x03, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

/* An ARP probe packet - This test is to check that NetX does not create an entry for probe (sender address is zero) packets.
 * src MAC: 00:b1:7d:4a:55:6a
 * src IP: 0.0.0.0
 * target MAC: 00:00:00:00:00:00
 * target IP: 1.2.3.85. */
static char arp_probe_pkt[] = {
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xb1, /* ...... . */
0x7d, 0x4a, 0x55, 0x6a, 0x08, 0x06, 0x00, 0x01, /* ..E..... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 

                                    0x00, 0xb1, /* ...... . */
0x7d, 0x4a, 0x55, 0x6a, 0x00, 0x00, 0x00, 0x00, /* ..E..... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x055, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
};


/* Third ARP request packet -- The test is to check that NetX does not create a duplicate entry for 1.2.3.5. 
 * src MAC: 20:0b:c7:94:45:97  
 * src IP: 1.2.3.5.
 * target MAC: 00:00:00:00:00:00
 * target IP: 1.2.3.4. */
static char arp_request_pkt3[] = {
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x97, 0x08, 0x06, 0x00, 0x01, /* ..E..... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 
                                    0x20, 0x0b, /* ...... . */
0xc7, 0x94, 0x45, 0x97, 0x01, 0x02, 0x03, 0x05, /* ..E..... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_arp_no_duplicate_entry_application_define(void *first_unused_memory)
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
ULONG       test_ip_address;
UINT        index;
UINT        match_count = 0;
NX_ARP     *arp_ptr;


    /* Print out test information banner.  */
    printf("NetX Test:   ARP No Duplicate Entry Test..............................."); 

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

    /******************************* First ARP packet ********************************
        This will be a request.  Fill in the packet with data. Skip the MAC header.  */

    memcpy(packet_ptr -> nx_packet_prepend_ptr, &arp_request_pkt[14], sizeof(arp_request_pkt) - 14);
    packet_ptr -> nx_packet_length = sizeof(arp_request_pkt) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ARP packet.  */
    _nx_arp_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Verify ARP entry is added to the ARP table. */
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

    /******************************* Second ARP packet ********************************
                Inject a second ARP packet from same host but different MAC. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* This will be a request.  Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &arp_request_pkt2[14], sizeof(arp_request_pkt2) - 14);
    packet_ptr -> nx_packet_length = sizeof(arp_request_pkt2) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ARP packet.  */
    _nx_arp_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Verify ARP entry is added to the ARP table. */
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
        (((physical_lsw) & 0xFF) != 0x97))
    {
        error_counter++;
    }

    /* Verify this MAC is not an entry in the table. */
    physical_msw = 0x200b;
    physical_lsw = 0xc7944596;

    /* The MAC address above should not be in the table. */
    status = nx_arp_ip_address_find(&ip_0, &test_ip_address, physical_msw, physical_lsw);

    /* Check status */
    if(status != NX_ENTRY_NOT_FOUND)
        error_counter++;

    /******************************* Third ARP packet ********************************
              Inject a third ARP packet. This is a response packet */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* This will be a request.  Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &arp_reply_pkt[14], sizeof(arp_reply_pkt) - 14);
    packet_ptr -> nx_packet_length = sizeof(arp_reply_pkt) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ARP packet.  */
    _nx_arp_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Verify ARP entry is created. */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 44), &physical_msw, &physical_lsw);

    /* Check status */
    if(status)
        error_counter++;

    /* Verify the MAC. */
    else if ((((physical_msw >> 8) & 0xFF) != 0x30) ||
        (((physical_msw) & 0xFF) != 0x1b) ||
        (((physical_lsw >> 24) & 0xFF) != 0xd7) ||
        (((physical_lsw >> 16) & 0xFF) != 0xa4) ||
        (((physical_lsw >> 8) & 0xFF) != 0x55) ||
        (((physical_lsw) & 0xFF) != 0xa6))
    {
        error_counter++;
    }


    /* Verify ARP entry is created for the target of this reply packet (1.2.3.6). */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 6), &physical_msw, &physical_lsw);

    /* Check status */
    if(status != NX_ENTRY_NOT_FOUND)
        error_counter++;


    /******************************* Fourth ARP packet ********************************
            Inject a fourth ARP packet. This is a probe packet */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* This will be a request.  Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &arp_probe_pkt[14], sizeof(arp_probe_pkt) - 14);
    packet_ptr -> nx_packet_length = sizeof(arp_probe_pkt) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ARP packet.  */
    _nx_arp_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Verify ARP entry is NOT created. ARP probes should not be added to the ARP cache. */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 85), &physical_msw, &physical_lsw);

    /* Check status */
    if(status != NX_ENTRY_NOT_FOUND)
        error_counter++;

    /* This is the MAC of the sender of the ARP probe. */
    physical_msw = 0x00b1;
    physical_lsw = 0x7d4a556a;

    /* The IP address should not be in the ARP cache because it is an ARP probe. */
    status = nx_arp_ip_address_find(&ip_0, &test_ip_address, physical_msw, physical_lsw);

    /* Check status */
    if(status != NX_ENTRY_NOT_FOUND)
        error_counter++;



    /******************************* Fifth ARP packet ********************************
            Inject a fifth ARP packet. This is a duplicate request packet */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter++;

    /* This will be a request.  Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &arp_request_pkt3[14], sizeof(arp_request_pkt3) - 14);
    packet_ptr -> nx_packet_length = sizeof(arp_request_pkt3) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ARP packet.  */
    _nx_arp_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Calculate the hash index for the sender IP address.   */
    index =  (UINT) ((IP_ADDRESS(0x01, 0x02, 0x03, 0x05) + (IP_ADDRESS(0x01, 0x02, 0x03, 0x05) >> 8)) & NX_ARP_TABLE_MASK); 

    /* Pickup the first ARP entry.  */
    arp_ptr =  ip_0.nx_ip_arp_table[index];

    /* Loop to look for an ARP match. There should be only one. */
    do
    {
        match_count++;

        /* Determine if we are at the end of the ARP list.  */
        if (arp_ptr == ip_0.nx_ip_arp_table[index])
        {

            /* Clear the ARP pointer.  */
            arp_ptr =  NX_NULL;
            break;
        }

        /* Move to the next active ARP entry.  */
        arp_ptr =  arp_ptr -> nx_arp_active_next;

    } while (arp_ptr);

    /* Check out match count. */
    if (match_count != 1)
    {
        error_counter++;
    }

    /* Check for any error.  */
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
void           netx_arp_no_duplicate_entry_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP No Duplicate Entry Test...............................N/A\n"); 
    test_control_return(3);

}
#endif /* NX_DISABLE_ARP_AUTO_ENTRY */
