/* This NetX test concentrates on the IP Static Route Add operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void     test_control_return(UINT status);
  
#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048      

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;    

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);  
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);  


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_static_route_add_test_application_define(void *first_unused_memory)
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

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;       

    if (status)
        error_counter++;                                   
}                                                         


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;                  
#ifdef NX_ENABLE_IP_STATIC_ROUTING
UINT        i;
ULONG       network_address;
ULONG       network_mask;
ULONG       next_hop_address;
#endif
    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Static Route Add Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             

    /* Set the gateway address with another network address.  */
    status = nx_ip_static_route_add(&ip_0, IP_ADDRESS(2, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0), IP_ADDRESS(2, 2, 3, 1));

#ifdef NX_ENABLE_IP_STATIC_ROUTING
    /* Check the status.  */
    if (status != NX_IP_ADDRESS_ERROR)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }    
#else 
    /* Check the status.  */
    if (status != NX_NOT_SUPPORTED)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }  
#endif
    
#ifdef NX_ENABLE_IP_STATIC_ROUTING       

    /* Set the network_address, networ_mask and next_hop_address.  */
    network_address = IP_ADDRESS(2, 2, 3, 4);
    network_mask = IP_ADDRESS(255, 255, 0, 0);
    next_hop_address = IP_ADDRESS(1, 2, 3, 4);

    /* Loop to add the static route.  */ 
    for (i = 0; i < NX_IP_ROUTING_TABLE_SIZE; i++)
    {

        /* Add the static route.  */
        status = nx_ip_static_route_add(&ip_0, network_address, network_mask, next_hop_address);

        /* Check the status.  */
        if (status)   
        {                         
            printf("ERROR!\n");
            test_control_return(1);
        }    

        /* Update the network_address.  */
        network_address += 0x00010000;
    }

    /* Update the network_mask.  */ 
    network_mask = IP_ADDRESS(255, 254, 0, 0);
    
    /* Add the static route with larger nets when the table is full.  */
    status = nx_ip_static_route_add(&ip_0, network_address, network_mask, next_hop_address);

    /* Check the status.  */
    if (status != NX_OVERFLOW)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Update the network_mask.  */ 
    network_mask = IP_ADDRESS(255, 255, 255, 0);

    /* Add the static route with small nets when the table is full.  */
    status = nx_ip_static_route_add(&ip_0, network_address, network_mask, next_hop_address);

    /* Check the status.  */
    if (status != NX_OVERFLOW)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Output successful.  */   
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_static_route_add_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Static Route Add Test..................................N/A\n"); 

    test_control_return(3);  
}      
#endif
