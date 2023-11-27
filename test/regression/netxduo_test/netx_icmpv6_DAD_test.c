/* This NetX test concentrates on the ICMP ping6 operation use second interface.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_IPV6_DAD)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"
#include    "nx_icmpv6.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;   
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;      


/* Define the counters used in the test application...  */
static ULONG                   error_counter;    
static ULONG                   NS_counter;        
#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY 
static ULONG                   Address_manual_config_counter;
static ULONG                   DAD_success_counter;
static ULONG                   DAD_failure_counter;
#endif
                                           
static NXD_ADDRESS             link_address_0;  
static NXD_ADDRESS             link_address_1;   
static NXD_ADDRESS             global_address;
static NXD_ADDRESS             global_address_0;
static NXD_ADDRESS             global_address_1;

/* Define thread prototypes.  */        
static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern UINT    (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr); 
#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
static VOID    ipv6_address_DAD_notify(NX_IP *ip_ptr, UINT status, UINT interface_index, UINT ipv6_addr_index, ULONG *ipv6_address);
#endif

/* Define what the initial system looks like.  */ 
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmpv6_DAD_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024, pointer, 8192);
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
    if (status)
        error_counter++;   

    /* Check IP create status.  */
    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);  

    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;
}                     


/* Define the test threads.  */  
static void    ntest_0_entry(ULONG thread_input)
{

UINT             status = 0;
ULONG            prefix_length;
UINT             interface_index;
UINT             valid_address_count;
UINT             packet_counter;
UINT             i;
UINT             address_index;
NX_PACKET       *my_packet[30];

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 DAD Test ..........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
                                             
#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
    /* Set the callback function.  */
    nxd_ipv6_address_change_notify(&ip_0, ipv6_address_DAD_notify);  

    /* Set the callback function.  */
    nxd_ipv6_address_change_notify(&ip_1, ipv6_address_DAD_notify);
#endif
        
    /* Hook link driver to check packets. */
    packet_process_callback = packet_process;

    /* Allocate all packet from packet pool.  */
    packet_counter = pool_0.nx_packet_pool_available;
    for(i =0; i < packet_counter; i ++)
    {

        /* Allocate the packet.  */
        status = nx_packet_allocate(&pool_0, &my_packet[i], NX_TCP_PACKET, NX_NO_WAIT);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Set the IPv6 linklocal address for IP instance 0.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, &address_index);

    /* Check the status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);     

    /* Check the NS counter.  */
    if(NS_counter != 0)
        error_counter ++;

    /* Release all allocated packet.  */
    for(i =0; i < packet_counter; i ++)
    {

        /* Allocate the packet.  */
        status = nx_packet_release(my_packet[i]);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }
    
    /* Delete the IPv6 linklocal address for IP instance 0.  */
    status = nxd_ipv6_address_delete(&ip_0, address_index);

    /* Check the status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the IPv6 linklocal address for IP instance 0 again.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, &address_index);

    /* Check the status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);     

    /* Check the NS counter.  */
    if(NS_counter != 3)
        error_counter ++;

    /* Get the IPv6 link local address for IP instance 0.  */
    status = nxd_ipv6_address_get(&ip_0, 0, &link_address_0, &prefix_length, &interface_index);
                                             
    /* Check the status.  */
    if(status) 
        error_counter ++;
                             
    /* Reset the NS_counter.  */
    NS_counter = 0;        

    /* Set the IPv6 linklocal address for IP instance 1.  */
    status = nxd_ipv6_address_set(&ip_1, 0, NX_NULL, 10, NX_NULL);

    /* Check the status.  */
    if(status) 
        error_counter ++;
                             
    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);     

    /* Check the NS counter.  */
    if(NS_counter != 3)
        error_counter ++;    
                            
    /* Get the IPv6 link local address for IP instance 0.  */
    status = nxd_ipv6_address_get(&ip_1, 0, &link_address_1, &prefix_length, &interface_index);
                                             
    /* Check the status.  */
    if(status) 
        error_counter ++;

    /* Reset the NS_counter.  */
    NS_counter = 0;      
                                    
    /* Set ipv6 global address for IP instance 0.  */
    global_address.nxd_ip_version = NX_IP_VERSION_V6;
    global_address.nxd_ip_address.v6[0] = 0x20010000;
    global_address.nxd_ip_address.v6[1] = 0x00000000;
    global_address.nxd_ip_address.v6[2] = 0x00000000;
    global_address.nxd_ip_address.v6[3] = 0x10000001;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &global_address, 64, NX_NULL);
                            
    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);  

    /* Check the NS counter.  */
    if(NS_counter != 3)
        error_counter ++;  
                               
    /* Get the IPv6 global address for IP instance 0.  */
    status = nxd_ipv6_address_get(&ip_0, 1, &global_address_0, &prefix_length, &interface_index);
                                             
    /* Check the status.  */
    if((status) ||
       (!CHECK_IPV6_ADDRESSES_SAME(&global_address.nxd_ip_address.v6[0], &global_address_0.nxd_ip_address.v6[0])))
        error_counter ++;

    /* Reset the NS_counter.  */
    NS_counter = 0;           

    /* Get count of valid addresses. */
    valid_address_count = 0;
    for (i = 0; i < NX_MAX_IPV6_ADDRESSES; i++)
    {
        if (ip_1.nx_ipv6_address[i].nxd_ipv6_address_valid)
        {
            valid_address_count++;
        }
    }

    /* Set the same IPv6 global address for instance 1.  */
    status = nxd_ipv6_address_set(&ip_1, 0, &global_address, 64, NX_NULL);
                            
    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE); 

    /* Check the NS counter.  */
    if(NS_counter != 1)
        error_counter ++;         

    /* Get the IPv6 global address for IP instance 1.  */
    status = nxd_ipv6_address_get(&ip_1, 1, &global_address_1, &prefix_length, &interface_index);
                                             
    /* Check the status.  */
    if(!status)
        error_counter ++;

    /* Is there only one address in the list of interface? */
    if (ip_1.nx_ip_interface[0].nxd_interface_ipv6_address_list_head -> nxd_ipv6_address_next != NX_NULL)
        error_counter++;

    /* Check count of valid addresses. */
    for (i = 0; i < NX_MAX_IPV6_ADDRESSES; i++)
    {
        if (ip_1.nx_ipv6_address[i].nxd_ipv6_address_valid)
        {
            valid_address_count--;
        }
    }
    if (valid_address_count)
        error_counter++;
    
    /* Clear link driver to check packets. */
    packet_process_callback = NX_NULL;  
          
#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY 
    /* Check the counter.  */
    if((Address_manual_config_counter != 5) || (DAD_success_counter != 4) || (DAD_failure_counter != 1))
    {                             
        error_counter ++;
    }
#endif

    /* Check the error counter.  */
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

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{                 

NX_ICMPV6_HEADER          *header_ptr;    
                                                         
    /* Points to the ICMP message header.  */
    header_ptr =  (NX_ICMPV6_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_IPV6_HEADER));

    /* Determine the message type and call the appropriate handler.  */
    if (header_ptr -> nx_icmpv6_header_type == NX_ICMPV6_NEIGHBOR_SOLICITATION_TYPE)
    {

        /* Update the NS counter.  */
        NS_counter ++; 
    }
                                     
    return NX_TRUE;
}
               
#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
static VOID    ipv6_address_DAD_notify(NX_IP *ip_ptr, UINT status, UINT interface_index, UINT ipv6_addr_index, ULONG *ipv6_address)
{                                                                

    /* Check thte status.  */
    switch(status)
    {            
        case NX_IPV6_ADDRESS_MANUAL_CONFIG:
        {

            /* Update the counter.  */
            Address_manual_config_counter ++;
            break;
        }     

        case NX_IPV6_ADDRESS_DAD_SUCCESSFUL:
        {

            /* Check the IPv6 address index.  */
            if((ipv6_addr_index == 1) && (ip_ptr == &ip_1))
                error_counter ++;
            
            /* Update the counter.  */
            DAD_success_counter ++;
            break;
        }
        case NX_IPV6_ADDRESS_DAD_FAILURE:
        {
              
            /* Check the IPv6 address index.  */
            if((ipv6_addr_index == 1) && (ip_ptr != &ip_1))
                error_counter ++;
            
            /* Update the counter.  */
            DAD_failure_counter ++;
            break;
        }
    }
}
#endif
#else  
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmpv6_DAD_test_application_define(void *first_unused_memory)
#endif
{   

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 DAD Test...........................................N/A\n");

    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */  
