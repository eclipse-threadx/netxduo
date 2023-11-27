/* This NetX test concentrates on the ARP dynamic entry operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
                    
extern void    test_control_return(UINT status);
       
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
                                      
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
void    netx_arp_entry_cache_test_application_define(void *first_unused_memory)
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

    /* Enable ARP and supply ARP cache memory for IP Instance 0, the ARP cache can store five entries.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, ARP_ENTRY_COUNT * sizeof(NX_ARP));
    pointer = pointer + ARP_ENTRY_COUNT * sizeof(NX_ARP);
    if (status)
        error_counter++;        
}                          


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
                     
INT         i;
UINT        status;     
ULONG       physical_msw;
ULONG       physical_lsw;
ULONG       address;


    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Entry CACHE Processing Test...........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                   
    /* Set the IP address.   */
    address = 5;

    /* Set the physical address.   */
    physical_msw = 0x0011;
    physical_lsw = 0x22334457;

    /* Loop to added the dynamic entries, the dynamic entry can be replaced. .  */
    for (i = 0; i < 3 * ARP_ENTRY_COUNT; i++)
    {

        /* Set a dynamic ARP entry.  */
        status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, address), physical_msw, physical_lsw);
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
            physical_lsw ++;
        }
    }                   

    /* Delete the entry that does not exist.  */
    status =  nx_arp_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, address));
    if (status != NX_ENTRY_NOT_FOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {

        /* Update the IP address.  */
        address --;

        /* Update the physical address.  */
        physical_lsw --;

        /* Update the idex.  */
        i --;
    }

    /* Loop to delete the dynamic entries, the dynamic entry can be replaced. .  */
    for (; i >= 2 * ARP_ENTRY_COUNT; i--)
    {

        /* Delete a dynamic ARP entry.  */
        status =  nx_arp_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, address));
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
        else
        {
                          
            /* Update the IP address.  */
            address --;

            /* Update the physical address.  */
            physical_lsw --;
        }
    }   

    /* Loop to delete the replaced dynamic entries.  */
    for (; i >= 0; i--)
    {

        /* Delete a dynamic ARP entry.  */
        status =  nx_arp_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, address));
        if (status != NX_ENTRY_NOT_FOUND)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
        else
        {
                          
            /* Update the IP address.  */
            address --;

            /* Update the physical address.  */
            physical_lsw --;
        }
    }
                    
    /* Set the IP address.   */
    address = 5;

    /* Set the physical address.   */
    physical_msw = 0x0011;
    physical_lsw = 0x22334457;

    /* Loop to added the dynamic entries, 35.  */
    for (i = 0; i < ARP_ENTRY_COUNT; i++)
    {

        /* Set a dynamic ARP entry.  */
        status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, address), physical_msw, physical_lsw);
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
            physical_lsw ++;
        }
    }                   
        
    /* Loop to added the static entries, 35.  */
    for (; i < 2 * ARP_ENTRY_COUNT; i++)
    {

        /* Set a static ARP entry.  */
        status =  nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, address), physical_msw, physical_lsw);
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
            physical_lsw ++;
        }
    }                          

    /* Set a static ARP entry, should be fail.  */
    status =  nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, address), physical_msw, physical_lsw);
    if (status != NX_NO_MORE_ENTRIES)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Set a dynamic ARP entry, should be fail.  */
    status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, address), physical_msw, physical_lsw);
    if (status != NX_NO_MORE_ENTRIES)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
         
    /* Update the IP address.  */
    address --;

    /* Update the physical address.  */
    physical_lsw --;

    /* Update the idex.  */
    i --;
      
    /* Loop to delete the static entries.  */
    for (; i >= ARP_ENTRY_COUNT; i--)
    {

        /* Delete a static ARP entry.  */
        status =  nx_arp_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, address));
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
        else
        {
                          
            /* Update the IP address.  */
            address --;

            /* Update the physical address.  */
            physical_lsw --;
        }
    }
             
    /* Loop to delete the replaced dynamic entries.  */
    for (; i >= 0; i--)
    {

        /* Delete a dynamic ARP entry.  */
        status =  nx_arp_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, address));
        if (status != NX_ENTRY_NOT_FOUND)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
        else
        {
                          
            /* Update the IP address.  */
            address --;

            /* Update the physical address.  */
            physical_lsw --;
        }
    }               
                    
    /* Set the IP address.   */
    address = 5;

    /* Set the physical address.   */
    physical_msw = 0x0011;
    physical_lsw = 0x22334457;

    /* Loop to added the dynamic entries, 35.  */
    for (i = 0; i < ARP_ENTRY_COUNT; i++)
    {

        /* Set a dynamic ARP entry.  */
        status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, address), physical_msw, physical_lsw);
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
            physical_lsw ++;
        }
    }                   

    /* Invalidate all dynamic entries. */
    status = nx_arp_dynamic_entries_invalidate(&ip_0);
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Output successful.  */ 
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else                    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_entry_cache_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Entry CACHE Processing Test...........................N/A\n");

    test_control_return(3); 
}
#endif /* __PRODUCT_NETXDUO__ */
    
