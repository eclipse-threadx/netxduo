/* This NetX test concentrates on the ICMP ping through all kinds of IPv4 loopback addresses.  */

#include   "nx_api.h"

extern void  test_control_return(UINT status);
#if !defined(NX_DISABLE_LOOPBACK_INTERFACE) && defined(__PRODUCT_NETXDUO__) && !defined(NX_ENABLE_ICMP_ADDRESS_CHECK) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_loopback_test2_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 4096);
    pointer = pointer + 4096;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for IP_0.  */
    status =  nx_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       addr;
NX_PACKET  *my_packet;  

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Loopback Test 2......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test loopback address between 127.0.0.1 and 127.255.255.255. The step is a random value less than 0x1000. */
    for (addr = NX_IP_LOOPBACK_FIRST; addr <= NX_IP_LOOPBACK_LAST; addr += (NX_RAND() & 0xFFF) + 1)
    {

        /* Now ping IPv4 loopback address.  */
        status =  nx_icmp_ping(&ip_0, addr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &my_packet, 5 * NX_IP_PERIODIC_RATE);

        /* Determine if the timeout error occurred.  */
        if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
        {

            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Release the packet. */
        nx_packet_release(my_packet);
    }


    /* Now ping IPv4 interface address with address mapping.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet. */
    nx_packet_release(my_packet);


    /* Disable address mapping. */
    status = nx_ip_interface_address_mapping_configure(&ip_0, 0, NX_FALSE);

    /* Check error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now ping IPv4 interface address without address mapping.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet. */
    nx_packet_release(my_packet);
         
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_loopback_test2_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   ICMP Loopback Test 2......................................N/A\n");
    test_control_return(3);
}
#endif 
