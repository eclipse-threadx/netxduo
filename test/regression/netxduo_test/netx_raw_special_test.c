
#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_udp.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;
static TX_THREAD               ntest_2;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_2_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS  ipv6_addr_0;
static NXD_ADDRESS  ipv6_addr_1;
#endif

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_raw_special_test_application_define(void *first_unused_memory)
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
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE;

    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer = pointer + DEMO_STACK_SIZE;

    tx_thread_create(&ntest_2, "thread 2", ntest_2_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
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

    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 10), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer = pointer + 2048;
    if (status != NX_SUCCESS)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status != NX_SUCCESS)
        error_counter++;

    status =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status != NX_SUCCESS)
        error_counter++;

    /* Enable UDP for IP instances. */
    status = nx_udp_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;

    status = nx_udp_enable(&ip_1);
    if (status != NX_SUCCESS)
        error_counter++;

#ifdef FEATURE_NX_IPV6 
    ipv6_addr_0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_addr_0.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_addr_0.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_addr_0.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_addr_0.nxd_ip_address.v6[3] = 0x00010001;

    ipv6_addr_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_addr_1.nxd_ip_address.v6[0] = 0x30010000;
    ipv6_addr_1.nxd_ip_address.v6[1] = 0x02300000;
    ipv6_addr_1.nxd_ip_address.v6[2] = 0x00440000;
    ipv6_addr_1.nxd_ip_address.v6[3] = 0x00010002;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;

    status = nxd_ipv6_enable(&ip_1);
    if (status != NX_SUCCESS)
        error_counter++;

    status = nxd_icmp_enable(&ip_0);
    if(status != NX_SUCCESS)
        error_counter++;

    status = nxd_icmp_enable(&ip_1);
    if(status)
        error_counter++;

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_addr_0, 64, NX_NULL);
    if(status != NX_SUCCESS)
        error_counter++;
#endif


}

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
ULONG       value;
UINT        i;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Raw Special Test.....................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* DAD */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &value, NX_IP_PERIODIC_RATE);
    if ((status) || (value != NX_IP_INITIALIZE_DONE))
        error_counter++;

    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, 2 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
        error_counter++;

#ifndef NX_DISABLE_ERROR_CHECKING
    /* Send the raw IP packet Before enable.  */
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 10), NX_IP_NORMAL);
    if (status != NX_NOT_ENABLED)
        error_counter++;
#endif /* NX_DISABLE_ERROR_CHECKING */

    /* Enable RAW. */
    status =  nx_ip_raw_packet_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Send to a address that can't be routed. */
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(23, 42, 3, 10), NX_IP_NORMAL);
    if (status != NX_IP_ADDRESS_ERROR)
        error_counter++;

    /* Let ntest_1 do its job. */
    tx_thread_resume(&ntest_1);
    tx_thread_suspend(&ntest_0);

    /* Two threads ntest_1 and ntest_2 suspend on the packet now. This will cover some code in raw_packet_processing */
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 10), NX_IP_NORMAL);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Send packets to fill the raw packet receive queue. This will cover some code in raw_packet_processing */
    for(i = 0;  i < ip_0.nx_ip_raw_received_packet_max + 5; i++)
    {
        /* Allocate a packet.  */
        status = nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, 2 * NX_IP_PERIODIC_RATE);
        if (status != NX_SUCCESS)
            error_counter++;

        /* Write ABCs into the packet payload!  */
        status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);
        if (status != NX_SUCCESS)
            error_counter++;

        status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 10), NX_IP_NORMAL);
        if(status != NX_SUCCESS)
        {
            nx_packet_release(my_packet);
        }
    }

    /* Disable RAW for ip_1.  To test the situation that there are packets in the RAW packet queue. */
    status = nx_ip_raw_packet_disable(&ip_1);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Enable again. */
    status = nx_ip_raw_packet_enable(&ip_1);
    if(status != NX_SUCCESS)
        error_counter++;

    tx_thread_suspend(&ntest_0);

    /* When thread ends, raw_packet_cleanup will be called. */
     
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
ULONG       value;

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &value, NX_IP_PERIODIC_RATE);
    if ((status) || (value != NX_IP_INITIALIZE_DONE))
        error_counter++;

    status = nx_ip_raw_packet_enable(&ip_1);
    if (status != NX_SUCCESS)
        error_counter++;

    tx_thread_resume(&ntest_2);
    status =  nx_ip_raw_packet_receive(&ip_1, &my_packet, 5 * NX_IP_PERIODIC_RATE);
    if(status == NX_SUCCESS)
    {
        status = nx_packet_release(my_packet); 
        if (status != NX_SUCCESS)
            error_counter++;
    }

    /* Suspend on the packet to test raw_packet_cleanup. */
    status =  nx_ip_raw_packet_receive(&ip_1, &my_packet, 5 * NX_IP_PERIODIC_RATE);

}

static void  ntest_2_entry(ULONG thread_input)
{
UINT        status;
NX_PACKET   *my_packet;
    
    tx_thread_resume(&ntest_0);
    
    status =  nx_ip_raw_packet_receive(&ip_1, &my_packet, 5 * NX_IP_PERIODIC_RATE);
    if(status == NX_SUCCESS)
    {
        status = nx_packet_release(my_packet); 
        if (status != NX_SUCCESS)
            error_counter++;
    }

    tx_thread_resume(&ntest_0);
    /* Suspend on the packet to test raw_packet_cleanup. */
    status =  nx_ip_raw_packet_receive(&ip_1, &my_packet, 5 * NX_IP_PERIODIC_RATE);
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_raw_special_test_application_define(void *first_unused_memory)
#endif
{
    
    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Raw Special Test.....................................N/A\n");
    test_control_return(3);
}
#endif /* __PRODUCT_NETXDUO__ */
