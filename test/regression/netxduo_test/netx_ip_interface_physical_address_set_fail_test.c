/* This NetX test concentrates on the IGMP join fails when driver returns error.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);

#ifdef __PRODUCT_NETXDUO__

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    test_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_physical_address_set_fail_test_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, test_driver,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT    status;

    /* Print out test information banner.  */
    printf("NetX Test:   IP Interface Physical Address Set Fail Test...............");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Perform IP interface physcial address set operations.  */
    status = nx_ip_interface_physical_address_set(&ip_0, 0, 0x0011, 0x22334458, NX_TRUE); 

    /* Check status.  */
    if (status != NX_UNHANDLED_COMMAND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static void    test_driver(struct NX_IP_DRIVER_STRUCT *driver_req)
{
    if (driver_req -> nx_ip_driver_command == NX_LINK_SET_PHYSICAL_ADDRESS)
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
void    netx_ip_interface_physical_address_set_fail_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Interface Physical Address Set Fail Test...............N/A\n");

    test_control_return(3);     
}
#endif
