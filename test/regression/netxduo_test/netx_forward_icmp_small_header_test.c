/* This NetX test concentrates on the forwarding operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"       
#include   "nx_icmp.h"  

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_IP                   ip_2;               


/* Define the counters used in the test application...  */

static ULONG                   error_counter = 0;    


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_icmp_small_header_test_application_define(void *first_unused_memory)
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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an forward IP Instance 0.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;    
    if (status)
        error_counter++;

    /* Set the second interface for forward IP Instance 0.  */
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_1500);    
    if (status)
        error_counter++;

    /* Create an IP Instance 1.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 1.  */
    status = nx_ip_gateway_address_set(&ip_1, IP_ADDRESS(1, 2, 3, 4));
    if (status)
        error_counter++;

    /* Create another IP Instance 2.  */
    status = nx_ip_create(&ip_2, "NetX IP Instance 1", IP_ADDRESS(2, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 2.  */
    status = nx_ip_gateway_address_set(&ip_2, IP_ADDRESS(2, 2, 3, 4));
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
    
    /* Enable ARP and supply ARP cache memory for IP Instance 2.  */
    status = nx_arp_enable(&ip_2, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for both IP Instance 0.  */
    status = nx_icmp_enable(&ip_0);
    if (status)
        error_counter++;
    
    /* Enable ICMP processing for both IP Instance 1.  */
    status = nx_icmp_enable(&ip_1);
    if (status)
        error_counter++;
    
    /* Enable ICMP processing for both IP Instance 2.  */
    status = nx_icmp_enable(&ip_2);
    if (status)
        error_counter++;

    /* Enable the forwarding function for IP Instance 0.  */
    status = nx_ip_forwarding_enable(&ip_0);
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
    printf("NetX Test:   Forward ICMP Small Header Processing Test.................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
                    
    /* Set the callback function to get the IPv4 packet.  */
    ip_0.nx_ipv4_packet_receive = my_packet_process;

    /* Now ip_1 ping ip_2.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_1, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 1) || (ping_responses_received != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
            
    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}    
static VOID   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{           
ULONG       shift_size;

    /* Calculate the shift data size. */
    shift_size = (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);

    /* Move the data to the start location, so the forward packet should remove the packet data to added the physical header.  */
    memmove(packet_ptr -> nx_packet_data_start, packet_ptr -> nx_packet_prepend_ptr, shift_size);

    /* Update the prepend and append pointer.  */
    packet_ptr -> nx_packet_prepend_ptr = packet_ptr -> nx_packet_data_start;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + shift_size;        

    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(ip_ptr, packet_ptr);
}
#else                                                  
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_icmp_small_header_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Forward ICMP Small Header Processing Test.................N/A\n");
    test_control_return(3);
}
#endif
