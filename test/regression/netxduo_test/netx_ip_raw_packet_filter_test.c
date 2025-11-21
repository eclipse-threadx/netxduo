/* This NetX test concentrates on the raw packet IPv6 send/receive operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);
#if defined(NX_ENABLE_IP_RAW_PACKET_FILTER) && !defined(NX_DISABLE_IPV4)
#include   "nx_tcp.h"
#include   "nx_udp.h"

#define     DEMO_STACK_SIZE         2048

#ifdef NX_ENABLE_IP_RAW_PACKET_ALL_STACK
#define PROTOCOL NX_PROTOCOL_ICMP
#else
#define PROTOCOL 0x99
#endif

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

static UINT                    flag;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static UINT    my_raw_packet_filter(NX_IP *ip_ptr, ULONG protocol, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_raw_packet_filter_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    flag = 0;

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
    
    status = nx_icmp_enable(&ip_0);
    if(status != NX_SUCCESS)
        error_counter++;

    status = nx_icmp_enable(&ip_1);
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
ULONG       value;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Raw Packet Filter Test.................................");

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

    /* Set the filter. */
    status = nx_ip_raw_packet_filter_set(&ip_0, my_raw_packet_filter);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Let filter been called. */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    if (flag != 1)
    {

        /* Expect packet received. */
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
ULONG       value;
NXD_ADDRESS dest_addr;

    dest_addr.nxd_ip_version = NX_IP_VERSION_V4;
    dest_addr.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 9);

    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &value, NX_IP_PERIODIC_RATE);
    if ((status) || (value != NX_IP_INITIALIZE_DONE))
        error_counter++;

    /* Allocate another packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Send the raw IP packet.  */
    status =  nxd_ip_raw_packet_source_send(&ip_1, my_packet, &dest_addr, 0, PROTOCOL, 0x80, NX_IP_NORMAL);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Send again. */
    /* Allocate another packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Send the second raw IP packet.  */
    status =  nxd_ip_raw_packet_source_send(&ip_1, my_packet, &dest_addr, 0, PROTOCOL, 0x80, NX_IP_NORMAL);
    if (status != NX_SUCCESS)
        error_counter++;

}

static UINT    my_raw_packet_filter(NX_IP *ip_ptr, ULONG protocol, NX_PACKET *packet_ptr)
{
    if (protocol != PROTOCOL)
    {
        error_counter++;
    }
    if (memcmp(packet_ptr -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", packet_ptr -> nx_packet_length))
    {
        error_counter++;
    }
    if (flag == 0)
    {
        flag++;
        return NX_SUCCESS;
    }
    else
    {
        /* In order to test code in _nx_ip_raw_packet_processing. */
        return 123;
    }

}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_raw_packet_filter_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Raw Packet Filter Test.................................N/A\n");
    test_control_return(3);
}
#endif
