/* This NetX test concentrates on the ARP static entry create operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048                                                             
#define     ARP_ENTRY_COUNT         35

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;   
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;           


/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_static_entry_create_test_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
 
    /* Enable ARP and supply ARP cache memory for IP Instance 0, the ARP cache can store thirty-five entries.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, ARP_ENTRY_COUNT * sizeof(NX_ARP));
    pointer = pointer + ARP_ENTRY_COUNT * sizeof(NX_ARP);
    if (status)
        error_counter++;

    /* Enable TCP processing for IP instance 0.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
UINT        i;
ULONG       address; 
ULONG       msw;
ULONG       lsw;
ULONG       ip_address;
ULONG       physical_msw;
ULONG       physical_lsw;


    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Static Entry Create Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the gateway.  */
    status = nx_ip_gateway_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 1));  

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }                               
               
#ifndef NX_DISABLE_ARP_INFO
    /* Check the static entries.  */
    if (ip_0.nx_ip_arp_static_entries != 0)    
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }                         
#endif

    /* Set a static ARP entry, the destination address is not directly accessible.  */
    status =  nx_arp_static_entry_create(&ip_0, IP_ADDRESS(2, 2, 3, 5), 0x0022, 0x22334457);

    /* Check the status.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }                    
                      
#ifndef NX_DISABLE_ARP_INFO
    /* Check the static entries.  */
    if (ip_0.nx_ip_arp_static_entries != 0)    
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }                         
#endif

    /* Set the IP address.   */
    address = 5;

    /* Set the physical address.   */
    msw = 0x0011;
    lsw = 0x22334457;
                            
    /* Loop to added the static entries to fill the arp entries, only remain one ARP entry for dynamic.  */
    for (i = 0; i < ARP_ENTRY_COUNT - 1; i++)
    {

        /* Set a static ARP entry.  */
        status =  nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, address), msw, lsw);
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
        else
        {
                          
            /* Update the IP address.  */
            address ++;

            /* Update the physical address.  */
            lsw ++;
        }
    }
                    
#ifndef NX_DISABLE_ARP_INFO
    /* Check the static entries.  */
    if (ip_0.nx_ip_arp_static_entries != ARP_ENTRY_COUNT - 1)    
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }                         
#endif

    /* Set a valid dynamic ARP entry.  */
    status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, address), msw, lsw);  

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                

#ifndef NX_DISABLE_ARP_INFO
    /* Check the static entries.  */
    if (ip_0.nx_ip_arp_static_entries != ARP_ENTRY_COUNT - 1)    
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }                         
#endif               
               
    /* Find the IP address.  */
    status = nx_arp_ip_address_find(&ip_0, &ip_address, msw, lsw);

    /* Check the result.  */
    if ((status) || (ip_address != IP_ADDRESS(1, 2, 3, address)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, address), &physical_msw, &physical_lsw); 

    /* Check the result.  */
    if ((status) || (physical_msw != msw) || (physical_lsw != lsw))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Update the physical address.  */
    lsw ++;

    /* Set a valid static ARP entry again to instead the dynamic ARP entry, same IP address, different physical address.   */
    status =  nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, address), msw, lsw);  

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

#ifndef NX_DISABLE_ARP_INFO
    /* Check the static entries.  */
    if (ip_0.nx_ip_arp_static_entries != ARP_ENTRY_COUNT)    
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }                         
#endif
            
    /* Find the IP address.  */
    status = nx_arp_ip_address_find(&ip_0, &ip_address, msw, lsw);

    /* Check the result.  */
    if ((status) || (ip_address != IP_ADDRESS(1, 2, 3, address)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, address), &physical_msw, &physical_lsw); 

    /* Check the result.  */
    if ((status) || (physical_msw != msw) || (physical_lsw != lsw))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Find the IP address.  */
    status = nx_arp_ip_address_find(&ip_0, &ip_address, 0x0000, 0xaabbccdd);
    if (status != NX_ENTRY_NOT_FOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 200), &physical_msw, &physical_lsw); 

    /* Check the result.  */
    if (status != NX_ENTRY_NOT_FOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Test was successful.  */     
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_static_entry_create_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Static Entry Create Test..............................N/A\n"); 

    test_control_return(3);  
}      
#endif
    