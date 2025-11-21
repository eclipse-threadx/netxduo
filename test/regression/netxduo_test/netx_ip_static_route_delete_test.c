/* This NetX test concentrates on the IP Static Route Delete operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
                   
extern void  test_control_return(UINT status);
#if defined(NX_ENABLE_IP_STATIC_ROUTING) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;    

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);  
extern void     test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);  


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_static_route_delete_test_application_define(void *first_unused_memory)
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
    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Static Route Delete Test...............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Add the static route.  */
    status = nx_ip_static_route_add(&ip_0, IP_ADDRESS(2, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0), IP_ADDRESS(1, 2, 3, 5));

    /* Check the status.  */
    if (status)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the inexistent static route.  */
    status = nx_ip_static_route_delete(&ip_0, IP_ADDRESS(3, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0));

    /* Check the status.  */
    if (status != NX_NOT_SUCCESSFUL)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the existent static route.  */
    status = nx_ip_static_route_delete(&ip_0, IP_ADDRESS(2, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0));

    /* Check the status.  */
    if (status)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the static route when the entry count is zero.  */
    status = nx_ip_static_route_delete(&ip_0, IP_ADDRESS(2, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0));

    /* Check the status.  */
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
void    netx_ip_static_route_delete_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Static Route Delete Test...............................N/A\n");
    test_control_return(3);
}
#endif
