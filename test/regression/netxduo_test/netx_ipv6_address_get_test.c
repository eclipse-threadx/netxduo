/* This test case validates nxd_ipv6_address_set. */

#include    "tx_api.h"
#include    "nx_api.h"
extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"


#define     DEMO_STACK_SIZE         2048
#define     TEST_INTERFACE          0

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   notify_counter;

static NXD_ADDRESS             if0_ga0;
static NXD_ADDRESS             if0_ga1;

#define PRIMARY_INTERFACE 0

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);

extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
static void   my_ipv6_addrress_change_notify(NX_IP *ip_tr, UINT type, UINT interface_index, UINT addr_index, ULONG *addr_ptr);
#endif

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ipv6_address_get_test_application_define(void *first_unused_memory)
#endif
{
    CHAR       *pointer;
    UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    notify_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;


    /* Set up IF0 GA0 */
    if0_ga0.nxd_ip_version = NX_IP_VERSION_V6;
    if0_ga0.nxd_ip_address.v6[0] = 0x20010000;
    if0_ga0.nxd_ip_address.v6[1] = 0x00000000;
    if0_ga0.nxd_ip_address.v6[2] = 0x00000000;
    if0_ga0.nxd_ip_address.v6[3] = 0x00010001;

    /* Set up IF0 GA1 */
    if0_ga1.nxd_ip_version = NX_IP_VERSION_V6;
    if0_ga1.nxd_ip_address.v6[0] = 0x20010000;
    if0_ga1.nxd_ip_address.v6[1] = 0x00000000;
    if0_ga1.nxd_ip_address.v6[2] = 0x00000000;
    if0_ga1.nxd_ip_address.v6[3] = 0x00010002;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    if(status != NX_SUCCESS)
        error_counter++;

    status = nxd_icmp_enable(&ip_0);
    if(status != NX_SUCCESS)
        error_counter++;

}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT       status;

ULONG      prefix_length;
UINT       interface_index;
NXD_ADDRESS ipv6_addr;

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Address Get Test.....................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
    status = nxd_ipv6_address_change_notify(&ip_0, my_ipv6_addrress_change_notify);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Set Global address0 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga0, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address1 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga1, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* DAD */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    status = nxd_ipv6_address_get(&ip_0, 0, &ipv6_addr, &prefix_length, &interface_index);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    if((ipv6_addr.nxd_ip_version != NX_IP_VERSION_V6) ||
       (ipv6_addr.nxd_ip_address.v6[0] != 0x20010000) ||
       (ipv6_addr.nxd_ip_address.v6[1] != 0x0) ||
       (ipv6_addr.nxd_ip_address.v6[2] != 0x0) ||
       (ipv6_addr.nxd_ip_address.v6[3] != 0x00010001))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_ipv6_address_get(&ip_0, 1, &ipv6_addr, &prefix_length, &interface_index);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    if((ipv6_addr.nxd_ip_version != NX_IP_VERSION_V6) ||
       (ipv6_addr.nxd_ip_address.v6[0] != 0x20010000) ||
       (ipv6_addr.nxd_ip_address.v6[1] != 0x0) ||
       (ipv6_addr.nxd_ip_address.v6[2] != 0x0) ||
       (ipv6_addr.nxd_ip_address.v6[3] != 0x00010002))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_ipv6_address_get(&ip_0, 2, &ipv6_addr, &prefix_length, &interface_index);
    if(status != NX_NO_INTERFACE_ADDRESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable IPv6 */
    status = nxd_ipv6_disable(&ip_0);

    /* notify counter should be 4, ipv6_address_set (ip_0, ip_1), DAD (ip_0, ip_1) calls. */
    if((status != NX_SUCCESS) 
#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
        || (notify_counter != 4)
#endif
      )
    {
        printf("ERROR!\n");
        test_control_return(1);

    }

    printf("SUCCESS!\n");
    test_control_return(0);

}

#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
static void   my_ipv6_addrress_change_notify(NX_IP *ip_tr, UINT type, UINT interface_index, UINT addr_index, ULONG *addr_ptr)
{
    notify_counter++;    
}
#endif

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ipv6_address_get_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Address Get Test.....................................N/A\n");

    test_control_return(3);

}
#endif
