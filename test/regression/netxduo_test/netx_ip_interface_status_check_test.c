/* This NetX test concentrates on the IP Interface Status Check operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"

#define     DEMO_STACK_SIZE         2048

extern void  test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

/* Define the counters used in the test application...  */
static ULONG                   error_counter;

static ULONG                   test_enabled;
static ULONG                   test_status;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    test_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_status_check_test_application_define(void *first_unused_memory)
#endif
{
    
CHAR    *pointer;
UINT    status;

    error_counter = 0;
    test_enabled = NX_FALSE;
    
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

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, test_driver,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)    

        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;


    status = nx_udp_enable(&ip_0);
    if (status)
        error_counter++;

    status = nx_tcp_enable(&ip_0);
    if(status)
        error_counter++;

    status = nx_igmp_enable(&ip_0);
    if(status)
        error_counter++;

}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT        status;
ULONG       val;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Interface Status Check Test............................");
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver_1500);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Attach the 2nd interface to IP instance1 */
    status = nx_ip_interface_attach(&ip_1, "2nd interface", IP_ADDRESS(4, 3, 2, 11), 0xFF000000, _nx_ram_network_driver_1500);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check interface IP address. */
    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_ADDRESS_RESOLVED, &val, NX_NO_WAIT);
    if((status != NX_SUCCESS) || !(val & NX_IP_ADDRESS_RESOLVED))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check link status. */
    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_LINK_ENABLED, &val, NX_NO_WAIT);
    if((status != NX_SUCCESS) || !(val & NX_IP_LINK_ENABLED))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let driver return NX_UNHANDLED_COMMAND. */
    test_enabled = NX_TRUE;
    test_status = NX_UNHANDLED_COMMAND;

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check ARP status. */
    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_ARP_ENABLED, &val, NX_NO_WAIT);
    if((status != NX_SUCCESS) || !(val & NX_IP_ARP_ENABLED))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check UDP status. */
    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_UDP_ENABLED, &val, NX_NO_WAIT);
    if((status != NX_SUCCESS) || !(val & NX_IP_UDP_ENABLED))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check TCP status. */
    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_TCP_ENABLED, &val, NX_NO_WAIT);
    if((status != NX_SUCCESS) || !(val & NX_IP_TCP_ENABLED))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check IGMP status. */
    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_IGMP_ENABLED, &val, NX_NO_WAIT);
    if((status != NX_SUCCESS) || !(val & NX_IP_IGMP_ENABLED))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check RARP status. */
    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_RARP_COMPLETE, &val, NX_NO_WAIT);
    /* ip_0 has had an IP address, RARP shoul be in complete status. */
    if((status != NX_SUCCESS) || !(val & NX_IP_RARP_COMPLETE))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check an unknown status with wait time 0.  the result should be error.*/
    status = nx_ip_interface_status_check(&ip_0, 0, 4343, &val, NX_NO_WAIT);
    if(status == NX_SUCCESS) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check an unknown status with wait time 10.  the result should be error.*/
    status = nx_ip_interface_status_check(&ip_0, 0, 4343, &val, 10);
    if(status == NX_SUCCESS) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_status_check(&ip_0, 1, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nx_ip_interface_status_check(&ip_0, 2, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif


    status = nx_ip_interface_status_check(&ip_1, 0, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_status_check(&ip_1, 1, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let driver return NX_UNHANDLED_COMMAND. */
    test_enabled = NX_TRUE;
    test_status = NX_UNHANDLED_COMMAND;

    status = nx_ip_interface_status_check(&ip_1, 0, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nx_ip_interface_status_check(&ip_1, 2, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);

    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Modify the ip instance to generate a special test condition. */
    ip_0.nx_ip_id = 1234;
    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_INTERFACE_LINK_ENABLED, &val, NX_NO_WAIT);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    ip_0.nx_ip_id = NX_IP_ID;
#endif


    printf("SUCCESS!\n");
    test_control_return(0);
}


static void    test_driver(struct NX_IP_DRIVER_STRUCT *driver_req)
{

    /* Inject NX_LINK_GET_STATUS command. */
    if ((driver_req -> nx_ip_driver_command  == NX_LINK_GET_STATUS) && (test_enabled == NX_TRUE))
    {
        driver_req -> nx_ip_driver_status = test_status;
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
void    netx_ip_interface_status_check_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Interface Status Check Test............................N/A\n");
    test_control_return(3);
}
#endif
