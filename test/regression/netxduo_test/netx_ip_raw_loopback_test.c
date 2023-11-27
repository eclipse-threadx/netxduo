/* This NetX test concentrates on the raw packet send/receive through loopback interface.  */

#include   "nx_api.h"
extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_LOOPBACK_INTERFACE) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS  ipv6_addr;
#endif /* FEATURE_NX_IPV6 */
static NXD_ADDRESS  ipv4_lo;

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_raw_loopback_test_application_define(void *first_unused_memory)
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

    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
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
    
#ifdef FEATURE_NX_IPV6
    ipv6_addr.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_addr.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_addr.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_addr.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_addr.nxd_ip_address.v6[3] = 0x00010001;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;

    status = nxd_icmp_enable(&ip_0);
    if(status != NX_SUCCESS)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */

    ipv4_lo.nxd_ip_version = NX_IP_VERSION_V4;
    ipv4_lo.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    status =  nx_ip_raw_packet_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;
UINT        i;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Raw Loopback Test......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    for (i = 0; i < 3; i++)
#else
    for (i = 0; i < 2; i++)
#endif
    {

        /* Now, pickup the three raw packets that should be queued on the other IP instance.  */
        status =  nx_ip_raw_packet_receive(&ip_0, &my_packet, NX_WAIT_FOREVER);
        if (status != NX_SUCCESS)
            error_counter++;

       if((my_packet -> nx_packet_length != 28) || 
          (memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28)))
            error_counter++;

        status = nx_packet_release(my_packet); 
        if (status != NX_SUCCESS)
            error_counter++;
    }
    
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

static void  ntest_1_entry(ULONG thread_input)
{
UINT        status;
NX_PACKET   *my_packet;
UINT        i;

#ifdef FEATURE_NX_IPV6
    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_addr, 64, NX_NULL);
    if(status != NX_SUCCESS)
        error_counter++;

    /* DAD */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */

#ifdef FEATURE_NX_IPV6
    for (i = 0; i < 3; i++)
#else
    for (i = 0; i < 2; i++)
#endif
    {

        /* Allocate a packet.  */
        status = nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, 2 * NX_IP_PERIODIC_RATE);
        if (status != NX_SUCCESS)
            error_counter++;

        /* Write ABCs into the packet payload!  */
        status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status != NX_SUCCESS)
            error_counter++;

        /* Send the raw IP packet.  */
        if (i == 0)
        {
            status =  nx_ip_raw_packet_source_send(&ip_0, my_packet, ipv4_lo.nxd_ip_address.v4, 
                                                   NX_LOOPBACK_INTERFACE, NX_IP_NORMAL);
        }
        else if (i == 1)
        {
            status =  nxd_ip_raw_packet_source_send(&ip_0, my_packet, &ipv4_lo, 
                                                    NX_LOOPBACK_INTERFACE, NX_IP_RAW >> 16, 255, NX_IP_NORMAL);
        }
#ifdef FEATURE_NX_IPV6
        else
        {
            status =  nxd_ip_raw_packet_source_send(&ip_0, my_packet, &ipv6_addr, 
                                                    0, NX_IP_RAW >> 16, 255, NX_IP_NORMAL);
        }
#endif

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_raw_loopback_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Raw Loopback Test......................................N/A\n");

    test_control_return(3);

}
#endif
