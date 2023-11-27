/* This NetX test concentrates on the raw packet IPv6 send/receive operation.  */

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

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_raw_packet_queue_test_application_define(void *first_unused_memory)
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
NX_PACKET   *my_packet;
UINT        i;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Raw Packet Queue Test..................................");

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

    /* Set queue size to 2. */
    status = nx_ip_raw_receive_queue_max_set(&ip_0, 2);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Let thread 1 to send 3 packets. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Receive 2 packets. */
    i = 0;
    while(i < 2)
    {
        i++;

        /* Receive the second packet.  */
        status =  nx_ip_raw_packet_receive(&ip_0, &my_packet, NX_IP_PERIODIC_RATE);
        if (status != NX_SUCCESS)
            error_counter++;

        if(memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28))
            error_counter++;

        status = nx_packet_release(my_packet); 
        if (status != NX_SUCCESS)
            error_counter++;
    }

    /* Because the queue size is 2, the 3rd packet can't be received. */
    status =  nx_ip_raw_packet_receive(&ip_0, &my_packet, NX_IP_PERIODIC_RATE);

    if (status != NX_NO_PACKET)
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

static void  ntest_1_entry(ULONG thread_input)
{
UINT        status;
NX_PACKET   *my_packet;
ULONG       value;
UINT        i;


    /* Check the status of the IP instances.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_INITIALIZE_DONE))
        error_counter++;

    i = 0;
    while(i < 2)
    {
        i++;

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

        /* Send the second raw IP packet.  */
        status =  nx_ip_raw_packet_send(&ip_1, my_packet, IP_ADDRESS(1, 2, 3, 9), NX_IP_NORMAL);

        /* Check status.  */
        if (status != NX_SUCCESS)
            error_counter++;
    }
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_raw_packet_queue_test_application_define(void *first_unused_memory)
#endif
{
    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Raw Packet Queue Test..................................N/A\n");
    test_control_return(3);
}
#endif /* __PRODUCT_NETXDUO__ */
