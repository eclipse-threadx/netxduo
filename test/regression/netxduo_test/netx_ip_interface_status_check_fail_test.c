/* This NetX test concentrates on the IP Interface Status Check operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"

#define     DEMO_STACK_SIZE         2048

extern void  test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */
static ULONG                   error_counter;

static ULONG                   test_enabled;
static ULONG                   test_status;
static ULONG                   reject_command;
static ULONG                   return_value;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    test_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_status_check_fail_test_application_define(void *first_unused_memory)
#endif
{
    
CHAR    *pointer;
UINT    status;

    error_counter = 0;
    reject_command = 0;
    test_enabled = NX_FALSE;
    return_value = NX_TRUE;
    
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, test_driver,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT        status;
ULONG       val;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Interface Status Check Fail Test.......................");
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_ARP_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_UDP_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_TCP_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_IGMP_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Clear the IP address.  */
    status = nx_ip_address_set(&ip_0, IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_RARP_COMPLETE, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
           
    /* Set the IP address again.  */
    status = nx_ip_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let driver return 1. */
    reject_command = NX_LINK_GET_STATUS;
    test_enabled = NX_TRUE;
    test_status = 1;

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                 

    /* Let driver return NX_UNHANDLED_COMMAND. */
    reject_command = NX_LINK_GET_STATUS;
    test_enabled = NX_TRUE;
    test_status = NX_UNHANDLED_COMMAND;
    ip_0.nx_ip_interface[0].nx_interface_link_up = 0;

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let driver return 1. */
    reject_command = NX_LINK_GET_STATUS;
    test_enabled = NX_TRUE;
    test_status = 1;

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                 

    /* Let driver return NX_UNHANDLED_COMMAND. */
    reject_command = NX_LINK_GET_STATUS;
    test_enabled = NX_TRUE;
    test_status = NX_UNHANDLED_COMMAND;
    ip_0.nx_ip_interface[0].nx_interface_link_up = 0;

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let driver return NX_SUCCESS. */
    reject_command = NX_LINK_GET_STATUS;
    test_enabled = NX_TRUE;
    test_status = NX_SUCCESS;
    return_value = NX_FALSE;

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_NOT_SUCCESSFUL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let driver return NX_SUCCESS. */
    reject_command = NX_LINK_GET_STATUS;
    test_enabled = NX_TRUE;
    test_status = NX_SUCCESS;
    return_value = NX_FALSE;

    nx_ip_interface_detach(&ip_0,0);

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static void    test_driver(struct NX_IP_DRIVER_STRUCT *driver_req)
{

    /* Inject the command. */
    if ((driver_req -> nx_ip_driver_command  == reject_command) && (test_enabled == NX_TRUE))
    {
        driver_req -> nx_ip_driver_status = test_status;
        *driver_req -> nx_ip_driver_return_ptr = return_value;
        test_enabled = NX_FALSE;
    }
    else
    {
        _nx_ram_network_driver_1500(driver_req);
    }
}

    
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_status_check_fail_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Interface Status Check Fail Test.......................N/A\n");
    test_control_return(3);
}
#endif
