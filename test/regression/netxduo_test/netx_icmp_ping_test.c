/* This NetX test concentrates on the ICMP ping operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                    msg[5000];


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT   (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping_test_application_define(void *first_unused_memory)
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

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
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

#if !defined(NX_DISABLE_FRAGMENTATION) && defined(__PRODUCT_NETXDUO__)
    /* Enable IP fragment for both IP instances.  */
    status = nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check IP fragment enable status.  */
    if (status)
        error_counter++;
#endif
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;  
NX_PACKET   *packet_ptr[20];
UINT        i;
ULONG       pings_sent;
ULONG       pings_sent_expected = 0;
ULONG       ping_timeouts;
ULONG       ping_timeouts_expected = 0;
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       ping_responses_received_expected = 0;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages;  
#ifdef __PRODUCT_NETXDUO__    
NXD_ADDRESS ip_address;
#endif

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Ping Test............................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef __PRODUCT_NETXDUO__    
    /* Bring down the primary interface. And ping limited broadcast address. */
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_FALSE;

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(255, 255, 255, 255), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* No interface to send ping packet. */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Bring up the primary interface. And ping limited broadcast address. */
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(255, 255, 255, 255), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

#ifdef NX_ENABLE_ICMP_ADDRESS_CHECK

    /* Check the status.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    ping_timeouts_expected++;
#else

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    ping_responses_received_expected++;
#endif

    pings_sent_expected++;
    nx_packet_release(my_packet);
#endif

    packet_process_callback = my_packet_process;
                                                        
    /* Loop to allocate the all packets.  */
    for (i = 0; i < pool_0.nx_packet_pool_total; i++)
    {

        /* Allocate the packets.  */
        status =   nx_packet_allocate(&pool_0, &packet_ptr[i], NX_ICMP_PACKET, 10);   

        /* Check the status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }  
    }
         
    /* Ping an IP address that does exist.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_NO_PACKET)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Loop to release the all packets.  */
    for (i = 0; i < pool_0.nx_packet_pool_total; i++)
    {

        /* Release the packets.  */
        status = nx_packet_release(packet_ptr[i]);   

        /* Check the status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }  
    }
         
    /* Ping an IP address that does exist but the packet is not enough to fill all the data.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), msg, sizeof(msg), &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

         
#if !defined(NX_DISABLE_FRAGMENTATION) && defined(__PRODUCT_NETXDUO__)
    /* Ping an IP address with big data.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 257, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
    nx_packet_release(my_packet);
    pings_sent_expected++;
    ping_responses_received_expected++;
#endif

    /* Ping an unreachable IP address with no wait.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 7), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status .  */
    if ((status != NX_IP_ADDRESS_ERROR) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Ping an unknown IP address with no wait.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 7), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_NO_WAIT);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
    pings_sent_expected++;

    /* Get no ICMP information.  */
    status = nx_icmp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);

    /* Check the status .  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != ping_timeouts_expected) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 7), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    pings_sent_expected++;
    ping_timeouts_expected++;

    /* Now ping loopback address.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    pings_sent_expected++;
    ping_responses_received_expected++;

    /* Release the packet. */
    nx_packet_release(my_packet);

#ifndef NX_DISABLE_LOOPBACK_INTERFACE

    /* Now ping loopback address.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(127, 0, 0, 1), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    pings_sent_expected++;
    ping_responses_received_expected++;

    /* Release the packet. */
    nx_packet_release(my_packet);
#endif /* NX_DISABLE_LOOPBACK_INTERFACE */

    /* Now ping an IP address that does exist.  */
    /* The reply packet contains checksum 0. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    pings_sent_expected++;
    ping_responses_received_expected++;

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != ping_timeouts_expected) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28 /* data only */) ||
        (ping_threads_suspended) || (icmp_checksum_errors) || (icmp_unhandled_messages) || error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

#ifdef __PRODUCT_NETXDUO__    
                                  
    /* Set the address.  */         
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    /* Now ping an IP address that does exist using nxd_icmp_ping API.  */
    /* The reply packet contains checksum 0. */
    status =  nxd_icmp_ping(&ip_0, &ip_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    pings_sent_expected++;
    ping_responses_received_expected++;

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != ping_timeouts_expected) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28 /* data only */) ||
        (ping_threads_suspended) || (icmp_checksum_errors) || (icmp_unhandled_messages) || error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Now ping an IP address that does exist using nxd_icmp_source_ping API.  */
    /* The reply packet contains checksum 0. */
    status =  nxd_icmp_source_ping(&ip_0, &ip_address, 0, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    pings_sent_expected++;
    ping_responses_received_expected++;

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != ping_timeouts_expected) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28 /* data only */) ||
        (ping_threads_suspended) || (icmp_checksum_errors) || (icmp_unhandled_messages) || error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
         
#ifndef FEATURE_NX_IPV6               
    /* Set the address version.  */         
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;   

    /* Now ping an IPv6 address when disable the IPv6 feature. */
    status =  nxd_icmp_ping(&ip_0, &ip_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);      

    /* Determine if the timeout error occurred.  */
    if (status != NX_NOT_SUPPORTED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Now ping an IPv6 address when disable the IPv6 feature. */
    status =  nxd_icmp_source_ping(&ip_0, &ip_address, 0, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);      

    /* Determine if the timeout error occurred.  */
    if (status != NX_NOT_SUPPORTED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
#endif
#endif

    printf("SUCCESS!\n");
    test_control_return(0);
}
    
static UINT   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

#if defined(__PRODUCT_NETXDUO__)
NX_IPV4_HEADER   *ip_header_ptr;
#else
NX_IP_HEADER     *ip_header_ptr;
#endif
ULONG            protocol;
NX_ICMP_HEADER   *icmp_header_ptr;

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
    protocol = (ip_header_ptr -> nx_ip_header_word_2 >> 16) & 0xFF;

    /* Is ICMP packet? */
    if(protocol == 1)
    {

        /* Yes it is. */
        /* Get ICMP header. */
        icmp_header_ptr = (NX_ICMP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);
        NX_CHANGE_ULONG_ENDIAN(icmp_header_ptr -> nx_icmp_header_word_0);

        if((icmp_header_ptr -> nx_icmp_header_word_0 & NX_LOWER_16_MASK) == 0xFFFF)
            error_counter++;

        NX_CHANGE_ULONG_ENDIAN(icmp_header_ptr -> nx_icmp_header_word_0);
    }
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Ping Test............................................N/A\n"); 

    test_control_return(3);  
}      
#endif