/* This NetX test concentrates on the ARP static entry may be updated by ARP packet.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_static_entry_pollute_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

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

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
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
NX_PACKET   *my_packet;
ULONG       ip_address;
ULONG       physical_msw;
ULONG       physical_lsw;
ULONG       requests_sent;
ULONG       requests_received;
ULONG       responses_sent;
ULONG       responses_received;
ULONG       dynamic_entries;
ULONG       static_entries;
ULONG       aged_entries;
ULONG       invalid_messages;


    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Static Entry Pollute Test.............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set an incorrect static ARP entry of IP1 in IP0.  */
    status =  nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0x00FF, 0x22334457);
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 5), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x00FF) || (physical_lsw != 0x22334457))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_icmp_ping(&ip_1, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if (status == NX_SUCCESS)
    {
        nx_packet_release(my_packet);
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 5), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x00FF) || (physical_lsw != 0x22334457))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Determine if the test was successful.  */
    if (error_counter)
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
void    netx_arp_static_entry_pollute_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Static Entry Pollute Test.............................N/A\n");

    test_control_return(3);
}
#endif
