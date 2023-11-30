/* This NetX test concentrates on the basic multicast IGMP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status); 
#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE     2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input); 
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_multicast_interface_detach_test_application_define(void *first_unused_memory)
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
              
    /* Check the status.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer =  pointer + 2048;            

    /* Check the status.  */
    if(status)
        error_counter++;

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_512);

    /* Check the status.  */
    if(status)
        error_counter++;    

    /* Enable IGMP processing for both this IP instance.  */
    status =  nx_igmp_enable(&ip_0);

    /* Check enable status.  */
    if (status)
        error_counter++;
}
                     

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;

    /* Print out test information banner.  */
    printf("NetX Test:   IP Multicast Interface Detach Test........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                        
    /* Test the first interface.  */
    /* Perform 7 IGMP join operations.  */
    status =   nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,1), 1);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,2), 1);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,3), 1);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,5), 1);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,6), 1);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,7), 1);

    /* Join one group another 4 times to test the counting operation.  */
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
         
    /* Check the groups info.  */
    if((ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_count != 1) ||
       (ip_0.nx_ipv4_multicast_entry[1].nx_ipv4_multicast_join_count != 1) ||
       (ip_0.nx_ipv4_multicast_entry[2].nx_ipv4_multicast_join_count != 1) ||
       (ip_0.nx_ipv4_multicast_entry[3].nx_ipv4_multicast_join_count != 5) ||
       (ip_0.nx_ipv4_multicast_entry[4].nx_ipv4_multicast_join_count != 1) ||
       (ip_0.nx_ipv4_multicast_entry[5].nx_ipv4_multicast_join_count != 1) ||
       (ip_0.nx_ipv4_multicast_entry[6].nx_ipv4_multicast_join_count != 1))  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
#ifndef NX_DISABLE_IGMP_INFO    
    /* Check the groups info.  */
    if(ip_0.nx_ip_igmp_groups_joined != 7)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
                                
    /* Attempt to join a new group. This should result in an error.  */
    status =  nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224,0,0,8));

    /* Determine if an error has occurred.  */
    if (status != NX_NO_MORE_ENTRIES)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                   
    /* Detach the seconde interface.  */
    status = nx_ip_interface_detach(&ip_0, 1);      
                   
    /* Check status.  */
    if(status)                     
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                             
    /* Check the groups info.  */
    if((ip_0.nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_count != 0) ||
       (ip_0.nx_ipv4_multicast_entry[1].nx_ipv4_multicast_join_count != 0) ||
       (ip_0.nx_ipv4_multicast_entry[2].nx_ipv4_multicast_join_count != 0) ||
       (ip_0.nx_ipv4_multicast_entry[3].nx_ipv4_multicast_join_count != 0) ||
       (ip_0.nx_ipv4_multicast_entry[4].nx_ipv4_multicast_join_count != 0) ||
       (ip_0.nx_ipv4_multicast_entry[5].nx_ipv4_multicast_join_count != 0) ||
       (ip_0.nx_ipv4_multicast_entry[6].nx_ipv4_multicast_join_count != 0))  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
#ifndef NX_DISABLE_IGMP_INFO    
    /* Check the groups info.  */
    if(ip_0.nx_ip_igmp_groups_joined != 0)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Output success.  */                            
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_multicast_interface_detach_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   IP Multicast Interface Detach Test........................N/A\n");
    test_control_return(3);   
}
#endif /* NX_ENABLE_IPV6_MULTICAST */
