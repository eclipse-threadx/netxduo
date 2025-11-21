/* This NetX test concentrates on the basic multicast IGMP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status); 
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6) && (NX_MAX_PHYSICAL_INTERFACES > 1)

#define     DEMO_STACK_SIZE     2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0; 
static NX_IP                   ip_1; 
static NX_IP                   ip_2;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;   
static NXD_ADDRESS             global_address_0; 
static NXD_ADDRESS             global_address_0_1; 
static NXD_ADDRESS             global_address_1;  
static NXD_ADDRESS             global_address_2;  
static UINT                    address_index_0_1;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);

extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_multicast_ping_test_application_define(void *first_unused_memory)
#endif
{

    CHAR    *pointer;
    UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
                             
    /* Create another IP instance.  */
    status += nx_ip_create(&ip_2, "NetX IP Instance 2", IP_ADDRESS(1, 2, 3, 6), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Set the second interface.  */
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_512);
    if (status)
        error_counter++;
    
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 
    status += nxd_ipv6_enable(&ip_1);  
    status += nxd_ipv6_enable(&ip_2);

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMPv6 processing for IP instances0 .  */
    status = nxd_icmp_enable(&ip_0);      
    status += nxd_icmp_enable(&ip_1);      
    status += nxd_icmp_enable(&ip_2);  

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
    
    /* Set the second ipv6 global address for IP instance 0.  */
    global_address_0_1.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_0_1.nxd_ip_address.v6[0] = 0x20010000;
    global_address_0_1.nxd_ip_address.v6[1] = 0x00000000;
    global_address_0_1.nxd_ip_address.v6[2] = 0x00000000;
    global_address_0_1.nxd_ip_address.v6[3] = 0x20000001;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 1, &global_address_0_1, 64, &address_index_0_1);      

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

    /* Set ipv6 global address for IP instance 2.  */
    global_address_2.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_2.nxd_ip_address.v6[0] = 0x20010000;
    global_address_2.nxd_ip_address.v6[1] = 0x00000000;
    global_address_2.nxd_ip_address.v6[2] = 0x00000000;
    global_address_2.nxd_ip_address.v6[3] = 0x10000003;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_2, 0, &global_address_2, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;       
}
                     

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NXD_ADDRESS group_address; 
NX_PACKET   *my_packet;  
ULONG       pings_sent;
ULONG       ping_timeouts;
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages;            

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Multicast Ping Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                     
    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);  

    /* Set the group address .  */ 
    group_address.nxd_ip_version = NX_IP_VERSION_V6;
    group_address.nxd_ip_address.v6[0] = 0xff020000;
    group_address.nxd_ip_address.v6[1] = 0x00000000;
    group_address.nxd_ip_address.v6[2] = 0x00000000;
    group_address.nxd_ip_address.v6[3] = 0x01020301;    

    /* Ping group address before joining. */
    status =  nxd_icmp_ping(&ip_0, &group_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
                   
    /* Check status.  */
    if(status == NX_SUCCESS)              
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Perform IGMP join operations.  */
    status = nxd_ipv6_multicast_interface_join(&ip_0, &group_address,  0); 
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address, 1); 
    status += nxd_ipv6_multicast_interface_join(&ip_1, &group_address, 0); 
    status += nxd_ipv6_multicast_interface_join(&ip_2, &group_address, 0); 
                   
    /* Check status.  */
    if(status)              
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
             
    /* Now ping an Multicast address that does exist.  */
    /* The reply packet contains checksum 0. */
    status =  nxd_icmp_ping(&ip_0, &group_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_IPV4
    /* Get ICMP information.  */
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 1) || (ping_responses_received != 3))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28 /* data only */) ||
        (ping_threads_suspended) || (icmp_checksum_errors) || (icmp_unhandled_messages))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif   

    /* Release the response packet. */
    nx_packet_release(my_packet);

    /* Disable the primary interace. */
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_FALSE;

    /* And now ping an Multicast address that does exist.  */
    status =  nxd_icmp_ping(&ip_0, &group_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Release the response packet. */
    nx_packet_release(my_packet);

    /* Delete the address of the second interface. */
    nxd_ipv6_address_delete(&ip_0, address_index_0_1);

    /* And now ping an Multicast address that does exist.  */
    status =  nxd_icmp_ping(&ip_0, &group_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if (status != NX_NO_INTERFACE_ADDRESS)
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
void    netx_ipv6_multicast_ping_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   IPv6 Multicast Ping Test..................................N/A\n");
    test_control_return(3);

}
#endif /* NX_ENABLE_IPV6_MULTICAST */
