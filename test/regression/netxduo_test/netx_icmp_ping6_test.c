/* This NetX test concentrates on the ICMP ping operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"        

extern void    test_control_return(UINT status);
#ifdef FEATURE_NX_IPV6

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static NXD_ADDRESS             global_address_0; 
static NXD_ADDRESS             global_address_1;  
static NXD_ADDRESS             destination_address;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping6_test_application_define(void *first_unused_memory)
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
    
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 
    status += nxd_ipv6_enable(&ip_1);

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;
                          
    /* Enable IPv6 again.  */ 
    status = nxd_ipv6_enable(&ip_0);  

    /* Check status.  */
    if (status != NX_ALREADY_ENABLED) 
        error_counter++;
                           
    /* Disable IPv6.  */ 
    status = nxd_ipv6_disable(&ip_0);  

    /* Check status.  */
    if (status)  
        error_counter++;
                          
    /* Disable IPv6 again.  */ 
    status = nxd_ipv6_disable(&ip_0);  

    /* Check status.  */
    if (status)  
        error_counter++;
                          
    /* Enable IPv6 again.  */ 
    status = nxd_ipv6_enable(&ip_0);  

    /* Check status.  */
    if (status) 
        error_counter++;

    /* Enable ICMPv6 processing for IP instances0 .  */
    status = nxd_icmp_enable(&ip_0);      
    status += nxd_icmp_enable(&ip_1);   

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;
    
    /* Set ipv6 global address for IP instance 0.  */
    global_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_0.nxd_ip_address.v6[0] = 0x20010000;
    global_address_0.nxd_ip_address.v6[1] = 0x00000000;
    global_address_0.nxd_ip_address.v6[2] = 0x00000000;
    global_address_0.nxd_ip_address.v6[3] = 0x10000001;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &global_address_0, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;       

    /* Set ipv6 global address for IP instance 1.  */
    global_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_1.nxd_ip_address.v6[0] = 0x20010000;
    global_address_1.nxd_ip_address.v6[1] = 0x00000000;
    global_address_1.nxd_ip_address.v6[2] = 0x00000000;
    global_address_1.nxd_ip_address.v6[3] = 0x10000002;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_1, 0, &global_address_1, 64, NX_NULL);      

    /* Check status.  */
    if(status)
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
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       ping_responses_received_expected = 0;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages;  

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Ping6 Test...........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);     

    /* Loop to allocate the all packets.  */
    for (i = 0; i < pool_0.nx_packet_pool_total; i++)
    {

        /* Allocate the packets.  */
        status =   nx_packet_allocate(&pool_0, &packet_ptr[i], NX_ICMP_PACKET, 1);   

        /* Check the status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }  
    }
                             
    /* Set ipv6 destination address.  */
    destination_address.nxd_ip_version = NX_IP_VERSION_V6;
    destination_address.nxd_ip_address.v6[0] = 0x20010000;
    destination_address.nxd_ip_address.v6[1] = 0x00000000;
    destination_address.nxd_ip_address.v6[2] = 0x00000000;
    destination_address.nxd_ip_address.v6[3] = 0x10000002;  

    /* Ping an IP address that does exist.  */
    status = nxd_icmp_ping(&ip_0, &destination_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_NO_PACKET)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
                         
    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif      

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
                   
    /* Set ipv6 destination address.  */
    destination_address.nxd_ip_version = NX_IP_VERSION_V6;
    destination_address.nxd_ip_address.v6[0] = 0x20010000;
    destination_address.nxd_ip_address.v6[1] = 0x00000000;
    destination_address.nxd_ip_address.v6[2] = 0x00000000;
    destination_address.nxd_ip_address.v6[3] = 0x10000002;  

#if !defined(NX_DISABLE_FRAGMENTATION) && defined(__PRODUCT_NETXDUO__)
    /* Ping an IP address with big data.  */
    status = nxd_icmp_ping(&ip_0, &destination_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 257, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
    pings_sent_expected++;
    ping_responses_received_expected++;
    nx_packet_release(my_packet);
#endif
                         
    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif    
                       
    /* Set ipv6 destination address.  */
    destination_address.nxd_ip_version = NX_IP_VERSION_V6;
    destination_address.nxd_ip_address.v6[0] = 0x30010000;
    destination_address.nxd_ip_address.v6[1] = 0x00000000;
    destination_address.nxd_ip_address.v6[2] = 0x00000000;
    destination_address.nxd_ip_address.v6[3] = 0x10000003; 

    /* Ping an unreachable IP address (Different network) with no wait.  */
    status = nxd_icmp_ping(&ip_0, &destination_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status .  */
    if ((status != NX_NO_INTERFACE_ADDRESS) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                    
    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif  

    /* Set ipv6 destination address.  */
    destination_address.nxd_ip_version = NX_IP_VERSION_V6;
    destination_address.nxd_ip_address.v6[0] = 0x20010000;
    destination_address.nxd_ip_address.v6[1] = 0x00000000;
    destination_address.nxd_ip_address.v6[2] = 0x00000000;
    destination_address.nxd_ip_address.v6[3] = 0x10000003; 

    /* Ping an unknown IP address with no wait.  */
    status = nxd_icmp_ping(&ip_0, &destination_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_NO_WAIT);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
    pings_sent_expected++;

    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
                                    
                         
    /* Set ipv6 destination address.  */
    destination_address.nxd_ip_version = NX_IP_VERSION_V6;
    destination_address.nxd_ip_address.v6[0] = 0x20010000;
    destination_address.nxd_ip_address.v6[1] = 0x00000000;
    destination_address.nxd_ip_address.v6[2] = 0x00000000;
    destination_address.nxd_ip_address.v6[3] = 0x10000003; 

    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status =  nxd_icmp_ping(&ip_0, &destination_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    pings_sent_expected++;
                              
    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 1) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Set ipv6 destination address.  */
    destination_address.nxd_ip_version = NX_IP_VERSION_V6;
    destination_address.nxd_ip_address.v6[0] = 0x20010000;
    destination_address.nxd_ip_address.v6[1] = 0x00000000;
    destination_address.nxd_ip_address.v6[2] = 0x00000000;
    destination_address.nxd_ip_address.v6[3] = 0x10000001; 

    /* Now ping loopback address.  */
    status =  nxd_icmp_ping(&ip_0, &destination_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    pings_sent_expected++;
    ping_responses_received_expected++;
                       
    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);

#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 1) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif  

    /* Release the packet. */
    nx_packet_release(my_packet); 
                               
    /* Set ipv6 destination address.  */
    destination_address.nxd_ip_version = NX_IP_VERSION_V6;
    destination_address.nxd_ip_address.v6[0] = 0x20010000;
    destination_address.nxd_ip_address.v6[1] = 0x00000000;
    destination_address.nxd_ip_address.v6[2] = 0x00000000;
    destination_address.nxd_ip_address.v6[3] = 0x10000002;  

    /* Now ping an IP address that does exist.  */
    /* The reply packet contains checksum 0. */
    status =  nxd_icmp_ping(&ip_0, &destination_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    pings_sent_expected++;
    ping_responses_received_expected++;

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 1) || (pings_sent != pings_sent_expected) || (ping_responses_received != ping_responses_received_expected))
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

    /* Invalidate all nd caches. */
    status = nxd_nd_cache_invalidate(&ip_0);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping an IP address that does exist again.  */
    status =  nxd_icmp_ping(&ip_0, &destination_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Invalidate all nd caches. */
    status = nxd_nd_cache_invalidate(&ip_0);

    /* Disable and enable IPv6. */
    status = nxd_ipv6_disable(&ip_0);
    status += nxd_ipv6_enable(&ip_0);
                           
    /* Set the IPv6 address.  */
    status += nxd_ipv6_address_set(&ip_0, 0, &global_address_0, 64, NX_NULL);      

    /* Check status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping an IP address that does exist with icmp disabled. Skip error checking. */
    status =  _nxd_icmp_ping(&ip_0, &destination_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if(status == NX_SUCCESS)
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
void    netx_icmp_ping6_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Ping6 Test...........................................N/A\n");
    
    test_control_return(3);
}
#endif
