/* This NetX test concentrates on the basic IP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"

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
static CHAR                   *ip_0_memory_ptr;
static CHAR                   *ip_1_memory_ptr;
static CHAR                   *arp_0_memory_ptr;
static CHAR                   *arp_1_memory_ptr;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern ULONG   simulated_address_msw;
extern ULONG   simulated_address_lsw;


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_basic_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create IP instances.  */
    ip_0_memory_ptr =  pointer;
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    ip_1_memory_ptr =  pointer;
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 10), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    arp_0_memory_ptr =  pointer;
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    arp_1_memory_ptr =  pointer;
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;                                    
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_address;
ULONG       mask;
ULONG       value;
ULONG       ip_total_packets_sent;
ULONG       ip_total_bytes_sent;
ULONG       ip_total_packets_received;
ULONG       ip_total_bytes_received;
ULONG       ip_invalid_packets;
ULONG       ip_receive_packets_dropped;
ULONG       ip_receive_checksum_errors;
ULONG       ip_send_packets_dropped;
ULONG       ip_total_fragments_sent;
ULONG       ip_total_fragments_received;
#ifdef __PRODUCT_NETXDUO__
ULONG       physical_msw;
ULONG       physical_lsw;
ULONG       gateway_addr_getted;
#endif /* __PRODUCT_NETXDUO__ */
#ifdef NX_ENABLE_IP_STATIC_ROUTING
NX_INTERFACE
            *if_ptr = NX_NULL;
ULONG       next_hop_address;


    /* Test static routing. */
    /* Add static route. */
    nx_ip_static_route_add(&ip_0, IP_ADDRESS(1, 2, 3, 0), 0xFFFFFF00UL, IP_ADDRESS(1, 2, 3, 2));

    nx_ip_static_route_add(&ip_0, IP_ADDRESS(1, 2, 3, 0), 0xFFFFFF00UL, IP_ADDRESS(1, 2, 3, 1));

    nx_ip_static_route_add(&ip_0, IP_ADDRESS(1, 2, 4, 0), 0xFFFFFF00UL, IP_ADDRESS(1, 2, 3, 1));

    /* Find route. */
    _nx_ip_route_find(&ip_0, IP_ADDRESS(1, 2, 3, 2), &if_ptr, &next_hop_address);

    /* Check interface and next hop address. */
    if((if_ptr != &ip_0.nx_ip_interface[0]) || 
       (next_hop_address != IP_ADDRESS(1, 2, 3, 1)))
       error_counter++;
#endif /* NX_ENABLE_IP_STATIC_ROUTING */

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Basic Operation Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup the IP address.  */
    status =  nx_ip_address_get(&ip_0, &ip_address, &mask);

    /* Check for an error.  */
    if ((status) || (ip_address != IP_ADDRESS(1, 2, 3, 9)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the IP address.  */
    status =  nx_ip_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 13), 0xFFFFFF00UL);
    status += nx_ip_address_get(&ip_0, &ip_address, &mask);

    /* Check for an error.  */
    if ((status) || (ip_address != IP_ADDRESS(1, 2, 3, 13)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef NX_ENABLE_IP_STATIC_ROUTING
    /* Delete a static route. */
    status = nx_ip_static_route_delete(&ip_0, IP_ADDRESS(1,2,4,0), 0xFFFFFF00UL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif


    /* Delete both IP instances.  */
    status =  nx_ip_delete(&ip_0);
    status += nx_ip_delete(&ip_1);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create IP instances.  */
    status =  nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    ip_0_memory_ptr, 2048, 1);
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    ip_1_memory_ptr, 2048, 1);
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status +=  nx_arp_enable(&ip_0, (void *) arp_0_memory_ptr, 1024);
    status +=  nx_arp_enable(&ip_1, (void *) arp_1_memory_ptr, 1024);

    /* Check the status of the IP instances.  */
    status +=  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_INITIALIZE_DONE))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Call driver directly.  */
    status =  nx_ip_driver_direct_command(&ip_0, NX_LINK_GET_STATUS, &value);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Call driver directly specifying the interface.  */
    status =  nx_ip_driver_interface_direct_command(&ip_0, NX_LINK_GET_STATUS, 0, &value);

    /* Check for an error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable and disable forwarding.  */
    status =  nx_ip_forwarding_enable(&ip_0);
    status += nx_ip_forwarding_disable(&ip_0);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                 
                                    
#ifdef __PRODUCT_NETXDUO__
    /* Enable fragment feature.  */
    status = nx_ip_fragment_enable(&ip_0);  

#ifndef NX_DISABLE_FRAGMENTATION        
    /* Check the status.  */
    if (status)             
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
#else                                  
    /* Check the status.  */
    if (status != NX_NOT_ENABLED)   
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
#endif
                              
    /* Disable fragment feature.  */
    status = nx_ip_fragment_disable(&ip_0);  

#ifndef NX_DISABLE_FRAGMENTATION        
    /* Check the status.  */
    if (status)              
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
#else                                  
    /* Check the status.  */
    if (status != NX_NOT_ENABLED)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
#endif      
#endif

    /* Set the gateway address.  */
    status =  nx_ip_gateway_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 87));

    /* Check for an error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef __PRODUCT_NETXDUO__
    status = nx_ip_gateway_address_get(&ip_0, &gateway_addr_getted);
    if((status != NX_SUCCESS) || gateway_addr_getted != IP_ADDRESS(1,2,3,87))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* __PRODUCT_NETXDUO__ */

#ifdef __PRODUCT_NETXDUO__
    /* Get Mac address. */
    status = nx_ip_interface_physical_address_get(&ip_0, 0, &physical_msw, &physical_lsw);
    if((status != NX_SUCCESS) || 
       (physical_msw != simulated_address_msw) || 
       (physical_lsw != simulated_address_lsw))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                             
    status =  nx_ip_gateway_address_clear(&ip_0);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* __PRODUCT_NETXDUO__ */

    /* Get nothing from IP info.  */
    status =  nx_ip_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get IP info.  */
    status =  nx_ip_info_get(&ip_0, &ip_total_packets_sent, 
                                    &ip_total_bytes_sent,
                                    &ip_total_packets_received,
                                    &ip_total_bytes_received,
                                    &ip_invalid_packets,
                                    &ip_receive_packets_dropped,
                                    &ip_receive_checksum_errors,
                                    &ip_send_packets_dropped,
                                    &ip_total_fragments_sent,
                                    &ip_total_fragments_received);

    /* Check status.  */
    if ((status) || (ip_total_packets_sent) || (ip_total_bytes_sent) || (ip_total_packets_received) ||
        (ip_total_bytes_received) || (ip_invalid_packets) || (ip_receive_packets_dropped) || (ip_receive_checksum_errors) ||
        (ip_send_packets_dropped) || (ip_total_fragments_sent) || (ip_total_fragments_received))
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
void    netx_ip_basic_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Basic Operation Test...................................N/A\n"); 

    test_control_return(3);  
}      
#endif
