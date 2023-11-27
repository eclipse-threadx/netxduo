/* This NetX test concentrates on the IPv4 Address Conflict Detection.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_arp.h"

extern void    test_control_return(UINT status);
#ifndef NX_DISABLE_IPV4
#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   conflict_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    ip_address_conflict_detection(NX_IP *ip_ptr, UINT interface_index, ULONG ip_address, ULONG msw, ULONG lsw);
static void    reject_arp_packet(NX_IP *ip_ptr, UINT interface_index,
                                 ULONG source_ip, ULONG source_physical_msw, ULONG source_physical_lsw,
                                 ULONG target_ip, ULONG target_physical_msw, ULONG target_physical_lsw);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_address_conflict_callback_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;
    conflict_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

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
}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{


    /* Print out some test information banners.  */
    printf("NetX Test:   IP Address Conflict Callback Test.........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the IP address conflict callback function.  */
    ip_0.nx_ip_interface[0].nx_interface_ip_conflict_notify_handler = ip_address_conflict_detection;

    /* Reject the ARP packet without conflict.  */
    reject_arp_packet(&ip_0, 0, IP_ADDRESS(1, 2, 3, 5), 0x00000011, 0x22334457, IP_ADDRESS(1, 2, 3, 4), 0x00000011, 0x22334456); 

    /* Check the announce counter.  */
    if (conflict_counter != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Reject the ARP packet with conflict.  */
    reject_arp_packet(&ip_0, 0, IP_ADDRESS(1, 2, 3, 4), 0x00000011, 0x22334457, IP_ADDRESS(1, 2, 3, 4), 0x00000011, 0x22334456); 

    /* Check the announce counter.  */
    if (conflict_counter != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Determine if the test was successful.  */
    if (error_counter)
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
VOID  reject_arp_packet(NX_IP *ip_ptr, UINT interface_index,
                        ULONG source_ip, ULONG source_physical_msw, ULONG source_physical_lsw,
                        ULONG target_ip, ULONG target_physical_msw, ULONG target_physical_lsw)
{

NX_PACKET       *request_ptr;
ULONG           *message_ptr;

 
    /* Allocate a packet to build the ARP message in.  */
    if (nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &request_ptr, NX_PHYSICAL_HEADER, NX_NO_WAIT))
    {

        /* Increment error counter.  */
        error_counter ++;

        /* Error getting packet, so just get out!  */
        return;
    }

    /* Build the ARP request packet.  */
    
    /* Setup the size of the ARP message.  */
    request_ptr -> nx_packet_length =  NX_ARP_MESSAGE_SIZE;

    /* Setup the append pointer to the end of the message.  */
    request_ptr -> nx_packet_append_ptr =  request_ptr -> nx_packet_prepend_ptr + NX_ARP_MESSAGE_SIZE;

    /* Setup the pointer to the message area.  */
    message_ptr =  (ULONG *) request_ptr -> nx_packet_prepend_ptr;

    /* Write the Hardware type into the message.  */
    *message_ptr =      (ULONG) (NX_ARP_HARDWARE_TYPE << 16) | (NX_ARP_PROTOCOL_TYPE);
    *(message_ptr+1) =  (ULONG) (NX_ARP_HARDWARE_SIZE << 24) | (NX_ARP_PROTOCOL_SIZE << 16) |
                                NX_ARP_OPTION_REQUEST;
    *(message_ptr+2) =  (ULONG) (source_physical_msw << 16) | (source_physical_lsw >> 16);
    *(message_ptr+3) =  (ULONG) (source_physical_lsw << 16) | (source_ip >> 16);
    *(message_ptr+4) =  (ULONG) (source_ip << 16) | (target_physical_msw & 0xFFFF);
    *(message_ptr+5) =  (ULONG) target_physical_lsw;
    *(message_ptr+6) =  (ULONG) target_ip;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+6));

    /* Set the interface.  */
    request_ptr -> nx_packet_ip_interface = &ip_ptr -> nx_ip_interface[interface_index];

    /* Directly receive this packet as conflict packet.  */
    _nx_arp_packet_deferred_receive(ip_ptr, request_ptr);
}

static void    ip_address_conflict_detection(NX_IP *ip_ptr, UINT interface_index, ULONG ip_address, ULONG msw, ULONG lsw)
{

    /* Update the conflict counter.  */
    conflict_counter ++;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_address_conflict_callback_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Address Conflict Callback Test.........................N/A\n");
    test_control_return(3);
}
#endif
