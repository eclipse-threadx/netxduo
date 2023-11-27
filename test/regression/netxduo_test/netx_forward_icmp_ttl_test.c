/* This NetX test concentrates on the ICMP ping operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"         

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
static ULONG                   icmp_counter = 0;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);  
extern UINT   (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_icmp_ttl_test_application_define(void *first_unused_memory)
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
    printf("NetX Test:   Forward ICMP TTL Processing Test..........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
                    
    /* Set the callback function.  */
    packet_process_callback = my_packet_process;

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
            
    /* Now ip_1 ping ip_2 again, modified the TTL as 1, this packet should be dropped by forward function.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
                
    /* Check the status .  */
    if ((status == NX_SUCCESS) || (ip_0.nx_ip_receive_packets_dropped != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                                                                   

    /* Check the ICMP counter for IP instance 1.  */
    if (icmp_counter != 2)
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
static UINT   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

#if defined(__PRODUCT_NETXDUO__)
NX_IPV4_HEADER   *ip_header_ptr;
#else
NX_IP_HEADER     *ip_header_ptr;
#endif
ULONG            protocol; 
ULONG            checksum;
ULONG            old_m;
ULONG            new_m;    

    /* Only detect the IP instance 1.  */
    if (ip_ptr != &ip_1)
        return NX_TRUE;

    /* Ignore packet that is not ICMP. */
    if(packet_ptr -> nx_packet_length < 28)
        return NX_TRUE;

#if defined(__PRODUCT_NETXDUO__)
    ip_header_ptr = (NX_IPV4_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);

#else
    ip_header_ptr = (NX_IP_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);
#endif

    /* Get IP header. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

    /* Get the next protocol.  */
    protocol = (ip_header_ptr -> nx_ip_header_word_2 >> 16) & 0xFF;

    /* Is ICMP packet? */
    if(protocol == 1)
    {

        /* Yes it is. */

        /* Only modify the second ICMP packet.  */
        if (icmp_counter == 1)
        {          
            
            /* Get the old checksum (HC) in header. */
            checksum = ip_header_ptr -> nx_ip_header_word_2 & NX_LOWER_16_MASK; 
                              
            /* Get the old TTL(m). */
            old_m = (ip_header_ptr -> nx_ip_header_word_2 & 0xFFFF0000) >> 16;;

            /* Set the new TTL as 1. */
            new_m = ((old_m & 0x00FF) | (0x0100));       

            /* Update the checksum, get the new checksum(HC'),
            The new_m is ULONG value, so need get the lower value after invert. */
            checksum = ((~checksum) & 0xFFFF) + ((~old_m) & 0xFFFF) + new_m;

            /* Fold a 4-byte value into a two byte value */
            checksum = (checksum >> 16) + (checksum & 0xFFFF);

            /* Do it again in case previous operation generates an overflow */
            checksum = (checksum >> 16) + (checksum & 0xFFFF);          
                                                                  
            /* Set the ttl as 1.  */
            ip_header_ptr -> nx_ip_header_word_2 = (ip_header_ptr -> nx_ip_header_word_2 & 0x00FFFFFF) | 0x01000000;

            /* Now store the new checksum in the IP header.  */
            ip_header_ptr -> nx_ip_header_word_2 =  ((ip_header_ptr -> nx_ip_header_word_2 & 0xFFFF0000) | ((~checksum) & NX_LOWER_16_MASK));
        }

        /* Update the ICMP counter.  */
        icmp_counter ++;
    }
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
    return NX_TRUE;
}
#else                                                  
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_icmp_ttl_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Forward ICMP TTL Processing Test..........................N/A\n");
    test_control_return(3);
}
#endif
