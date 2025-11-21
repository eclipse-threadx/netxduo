/* This case test if the gateway has been cleared after interface detachment. */

#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_detachment_gateway_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter    = 0;

    /* Create the main threads.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
            pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver);
    if(status != NX_SUCCESS)     
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT    status;
ULONG   actual_status;
ULONG   gateway_address;

    printf("NetX Test:   IP Interface Detachment Gateway Test......................");

    /* Check earlier error. */
    if(error_counter)
    {                            
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Set gateway address. */
    status = nx_ip_gateway_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 1));
    if(status)
        error_counter++;

    /* Get gateway address. */
    status = nx_ip_gateway_address_get(&ip_0, &gateway_address);
    if((status) || (gateway_address != IP_ADDRESS(1, 2, 3, 1)))
        error_counter++;

    /* Detach the interface from ip_0. */
    status = nx_ip_interface_detach(&ip_0, 0);
    if(status)
        error_counter++;

    /* Get gateway address. */
    status = nx_ip_gateway_address_get(&ip_0, &gateway_address);
    if(status == NX_SUCCESS)
        error_counter++;

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

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_detachment_gateway_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Interface Detachment Gateway Test......................N/A\n");
    test_control_return(3);

}
#endif
