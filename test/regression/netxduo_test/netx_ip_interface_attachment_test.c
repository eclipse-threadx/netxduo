/* This NetX test concentrates on the IP Interface Attachment operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void  test_control_return(UINT status);

#if (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
void           _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_attachment_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;
UINT    i;
ULONG   ip_address;

    
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver_1500);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Attach the 2nd interface to IP instance1 */
    status = nx_ip_interface_attach(&ip_1, "2nd interface", IP_ADDRESS(4, 3, 2, 11), 0xFF000000, _nx_ram_network_driver_1500);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Set the IP address for next interface.  */
    ip_address = IP_ADDRESS(5, 3, 2, 10);

    /* Loop to attached the valid interface to IP instance 0.  */
    for (i = 2; i< NX_MAX_PHYSICAL_INTERFACES; i++)
    {        
        
        /* Attach the interface.  */
        status = nx_ip_interface_attach(&ip_0, "New interface", ip_address, 0xFFFFFF00UL, _nx_ram_network_driver_1500);
        if(status != NX_SUCCESS)
            error_counter++;  

        /* Update the IP address.  */
        ip_address += 0x01000000UL;
    }

    /* Attach the invalid interface to IP instance 0.  */
    status = nx_ip_interface_attach(&ip_0, "New interface", ip_address, 0xFFFFFF00UL, _nx_ram_network_driver_1500);
    if(status != NX_NO_MORE_ENTRIES)
        error_counter++;  

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    if (status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
ULONG       pings_sent;
ULONG       ping_timeouts;
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Interface Attachment Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 9), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping an IP address that does exist.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 11), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* It should also be able to ping an IP address that is accessible via the primary interface. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
    
#ifndef NX_DISABLE_ICMP_INFO

    if ((pings_sent != 3) || (ping_timeouts != 1) || (ping_responses_received != 2) || (icmp_checksum_errors) || (icmp_unhandled_messages))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28 /* data only */) ||
        (ping_threads_suspended))
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
void    netx_ip_interface_attachment_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Interface Attachment Test..............................N/A\n");
    test_control_return(3);
}
#endif
