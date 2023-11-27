/* This NetX test concentrates on the raw packet IPv6 send/receive operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6)
#include   "nx_tcp.h"
#include   "nx_udp.h"
#include   "nx_ip.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


static NXD_ADDRESS  ipv6_addr_0;
static NXD_ADDRESS  ipv6_addr_1;

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_raw_packet_test_application_define(void *first_unused_memory)
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

    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 10), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer = pointer + 2048;
    if (status != NX_SUCCESS)
        error_counter++;

#ifndef NX_DISABLE_IPV4
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status != NX_SUCCESS)
        error_counter++;

    status =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status != NX_SUCCESS)
        error_counter++;
#endif

    /* Enable UDP for IP instances. */
    status = nx_udp_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;

    status = nx_udp_enable(&ip_1);
    if (status != NX_SUCCESS)
        error_counter++;
    
    ipv6_addr_0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_addr_0.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_addr_0.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_addr_0.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_addr_0.nxd_ip_address.v6[3] = 0x00010001;

    ipv6_addr_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_addr_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_addr_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_addr_1.nxd_ip_address.v6[2] = 0x00000000;
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

    status =  nx_ip_raw_packet_enable(&ip_0);
    if (status != NX_SUCCESS)
        error_counter++;

    status = nx_ip_raw_packet_enable(&ip_1);
    if (status != NX_SUCCESS)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
ULONG       value;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Raw Packet Test......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_addr_0, 64, NX_NULL);
    if(status != NX_SUCCESS)
        error_counter++;

    /* DAD */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_INITIALIZE_DONE))
        error_counter++;

    /* Now, pickup the three raw packets that should be queued on the other IP instance.  */
    status =  nx_ip_raw_packet_receive(&ip_0, &my_packet, 2 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
        error_counter++;

   if(memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28))
        error_counter++;

    status = nx_packet_release(my_packet); 
    if (status != NX_SUCCESS)
        error_counter++;

#ifndef NX_DISABLE_IPV4
    /* Receive the second packet.  */
    status =  nx_ip_raw_packet_receive(&ip_0, &my_packet, NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
        error_counter++;

    if(memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28))
        error_counter++;
   
    status = nx_packet_release(my_packet); 
    if (status != NX_SUCCESS)
        error_counter++;
#endif

    /* Receive the third packet.  */
    status =  nx_ip_raw_packet_receive(&ip_0, &my_packet, NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
        error_counter++;
   
    if(memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28))
        error_counter++;

    status = nx_packet_release(my_packet); 
    if (status != NX_SUCCESS)
        error_counter++;

    /* Receive the last packet.  */
    status =  nx_ip_raw_packet_receive(&ip_0, &my_packet, NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
        error_counter++;
   
    if(memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28))
        error_counter++;

    status = nx_packet_release(my_packet); 
    if (status != NX_SUCCESS)
        error_counter++;
   
    /* Attempt to receive a packet on an empty queue.... should be an error.  */
    status =  nx_ip_raw_packet_receive(&ip_0, &my_packet, NX_IP_PERIODIC_RATE);

    if (status != NX_NO_PACKET)
        error_counter++;

    /* Suspend thread_0 to let thread_1 disable the raw, which will call raw_packet_cleanup */
    nx_ip_raw_packet_receive(&ip_0, &my_packet, 5 * NX_IP_PERIODIC_RATE);

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
NXD_ADDRESS dest_addr;


    status = nxd_ipv6_address_set(&ip_1, 0, &ipv6_addr_1, 64, NX_NULL);
    if(status != NX_SUCCESS)
        error_counter++;

    /* DAD */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_INITIALIZE_DONE))
        error_counter++;

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
    status =  nxd_ip_raw_packet_send(&ip_1, my_packet, &ipv6_addr_0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

#ifndef NX_DISABLE_IPV4
    /* Allocate another packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    dest_addr.nxd_ip_version = NX_IP_VERSION_V4;
    dest_addr.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 9);

    /* Send the second raw IP packet.  */
    status =  nxd_ip_raw_packet_source_send(&ip_1, my_packet, &dest_addr, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;
#endif

    /* Allocate another packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    
    /* Send the third raw IP packet.  */
    status =  nxd_ip_raw_packet_send(&ip_1, my_packet, &ipv6_addr_0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, 2 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Send the raw IP packet using API without error checking.  */
    status =  _nxd_ip_raw_packet_send(&ip_1, my_packet, &ipv6_addr_0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);

    status =  nx_ip_raw_packet_disable(&ip_0);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;


}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ipv6_raw_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Raw Packet Test......................................N/A\n");

    test_control_return(3);

}
#endif
