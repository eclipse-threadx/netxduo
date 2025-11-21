/* This NetX test concentrates on the IGMP join fails when driver returns error.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static UINT                    available;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    test_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_igmp_join_fail_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    available = NX_TRUE;

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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, test_driver,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
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
    printf("NetX Test:   IGMP Join Fail Test.......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set available to false. */
    available = NX_FALSE;

    /* Perform IGMP join operations.  */
    status =   nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224,0,0,1));

    /* Determine if there is an error.  */
    if (status != NX_NO_MORE_ENTRIES)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set available to true. */
    available = NX_TRUE;

    /* Perform IGMP join operations.  */
    status =   nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224,0,0,1));

    /* Determine if there is an error.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now leave the group to make sure that processing works properly.  */
    status =   nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,1));
    
    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static void    test_driver(struct NX_IP_DRIVER_STRUCT *driver_req)
{
    if ((driver_req -> nx_ip_driver_command == NX_LINK_MULTICAST_JOIN) &&
        (available == NX_FALSE))
    {

        /* Return not supported. */
        driver_req -> nx_ip_driver_status = NX_UNHANDLED_COMMAND;
    }
    else
    {

        /* Pass the request to ram driver. */
        _nx_ram_network_driver_256(driver_req);
    }
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_igmp_join_fail_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Join Fail Test.......................................N/A\n"); 

    test_control_return(3);  
}      
#endif
