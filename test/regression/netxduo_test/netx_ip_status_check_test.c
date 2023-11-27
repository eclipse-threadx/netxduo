/* This NetX test concentrates on the raw packet IPv6 send/receive operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);
#include   "nx_tcp.h"
#include   "nx_udp.h"

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
void    netx_ip_status_check_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;
    if (status != NX_SUCCESS)
        error_counter++;

    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer = pointer + 2048;
    if (status != NX_SUCCESS)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status != NX_SUCCESS)
        error_counter++;

    /* Enable UDP for IP instances. */
    status = nx_udp_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Enable TCP for IP instances. */
    status = nx_tcp_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Enable IGMP for IP instances. */
    status = nx_igmp_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;

}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       value;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP status Check Test......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_INITIALIZE_DONE))
        error_counter++;

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_LINK_ENABLED, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_LINK_ENABLED))
        error_counter++;

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_ARP_ENABLED, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_ARP_ENABLED))
        error_counter++;

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_UDP_ENABLED, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_UDP_ENABLED))
        error_counter++;

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_TCP_ENABLED, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_TCP_ENABLED))
        error_counter++;

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_IGMP_ENABLED, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_IGMP_ENABLED))
        error_counter++;

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_RARP_COMPLETE, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_RARP_COMPLETE))
        error_counter++;

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INTERFACE_LINK_ENABLED, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_INTERFACE_LINK_ENABLED))
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
void    netx_ip_status_check_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP status Check Test......................................N/A\n"); 

    test_control_return(3);  
}      
#endif

