/* This NetX test concentrates on the ICMP ping operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_FRAGMENTATION) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                    msg[256];


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping_fragment_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 4096);
    pointer = pointer + 4096;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
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



static void    ntest_0_entry(ULONG thread_input)
{
UINT        status;
NX_PACKET  *my_packet;  
    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Ping Fragment Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now send ping with fragment disabled. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), msg, sizeof(msg), &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_NO_RESPONSE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Enable IP fragment for both IP instances.  */
    status = nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check IP fragment enable status.  */
    if (status)
        error_counter++;


    /* Now send ping with fragment enabled. The fragment will be disabled while ARP is sent. */
    advanced_packet_process_callback = packet_process;
    nx_arp_dynamic_entries_invalidate(&ip_0);
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), msg, sizeof(msg), &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_NO_RESPONSE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               


    /* Enable IP fragment for both IP instances.  */
    status = nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check IP fragment enable status.  */
    if (status)
        error_counter++;


    /* Now send ping with fragment enabled. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), msg, sizeof(msg), &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    printf("SUCCESS!\n");
    test_control_return(0);
}


static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    /* Disable fragment. */
    nx_ip_fragment_disable(&ip_0);
    nx_ip_fragment_disable(&ip_1);

    advanced_packet_process_callback = NX_NULL;

    return NX_TRUE;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping_fragment_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   ICMP Ping Fragment Test...................................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_FRAGMENTATION */
