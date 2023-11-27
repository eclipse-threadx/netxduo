/* This NetX test concentrates on the IP Address Get operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void  test_control_return(UINT status);

#if (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
void           _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_address_get_test_application_define(void *first_unused_memory)
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

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
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
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       address;
ULONG       mask;

    /* Print out test information banner.  */
    printf("NetX Test:   IP Address Get Test.......................................");

    /* Check for earlier error.  */
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

    status = nx_ip_address_get(&ip_0, &address, &mask);

    if((status != NX_SUCCESS) || (address != IP_ADDRESS(1,2,3,4)) || (mask != 0xFFFFFF00))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_address_get(&ip_0, 1, &address, &mask);

    if((status != NX_SUCCESS) || (address != IP_ADDRESS(4, 3, 2, 10)) || (mask != 0xFF000000))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nx_ip_interface_address_get(&ip_0, 2, &address, &mask);

    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING  */

    status = nx_ip_address_get(&ip_1, &address, &mask);

    if((status != NX_SUCCESS) || (address != IP_ADDRESS(1,2,3,5)) || (mask != 0xFFFFFF00))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_ip_interface_address_get(&ip_1, 1, &address, &mask);


    if((status != NX_SUCCESS ) || (address != IP_ADDRESS(4,3,2,11)) || (mask != 0xFF000000))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nx_ip_interface_address_get(&ip_1, 2, &address, &mask);

    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING  */

    printf("SUCCESS!\n");
    test_control_return(0);

}
    
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_address_get_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Address Get Test.......................................N/A\n");
    test_control_return(3);
}
#endif
