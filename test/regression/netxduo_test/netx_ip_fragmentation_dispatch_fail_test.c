/* This NetX test concentrates on the failure of dispatch for assembled packets.  */


#include   "nx_api.h"

extern void  test_control_return(UINT status);
#if !defined(NX_DISABLE_FRAGMENTATION) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IP_INFO) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048
#define     SEND_SIZE               3000


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static CHAR                    send_buf[SEND_SIZE];
static UCHAR                   pool_area[102400];

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_dispatch_fail_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the client thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1000, pool_area, sizeof(pool_area));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for both IP instances.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP for IP_0 only. */
    status = nx_icmp_enable(&ip_0);

    /* Check for ICMP enable errors.  */
    if (status)
        error_counter++;

    /* Enable IP fragmentation logic on both IP instances.  */
    status =  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check for IP fragment enable errors.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;


    /* Print out some test information banners.  */
    printf("NetX Test:   IP Fragmentation Dispatch Fail Test.......................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now send a ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), send_buf, sizeof(send_buf), &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if (status == NX_SUCCESS) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check packet dropped by IP_1. */
    if (ip_1.nx_ip_receive_packets_dropped != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_dispatch_fail_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   IP Fragmentation Dispatch Fail Test.......................N/A\n");
    test_control_return(3);
}
#endif 
