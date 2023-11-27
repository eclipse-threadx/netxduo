#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);
#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_IPV4
#include   "nxd_mdns.h"

#define     DEMO_STACK_SIZE    2048
#define     BUFFER_SIZE        10240

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static UCHAR                   buffer[BUFFER_SIZE];
static ULONG                   current_buffer_size;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_buffer_size_test(void *first_unused_memory)
#endif
{
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;
    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, 
                          _nx_ram_network_driver, pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);

    /* Check UDP enable status.  */
    if(status)
        error_counter++;

    status = nx_igmp_enable(&ip_0);

    /* Check status. */
    if(status)
        error_counter++;

    /* Create the test thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, (ULONG)(pointer + DEMO_STACK_SIZE),  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
CHAR       *pointer = (CHAR*)thread_input;
NX_MDNS_RR *rr;

    printf("NetX Test:   MDNS Buffer Size Test.....................................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    for(current_buffer_size = 8; current_buffer_size < 1000; current_buffer_size += 60)
    {

        /* Create */
        nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, "NETX-MDNS",  
                       buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);
        
#ifndef NX_MDNS_DISABLE_SERVER
        /* Use local buffer. */
        nx_mdns_service_add(&mdns_0, (CHAR *)"ARMMDNSTest", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);
#endif /* NX_MDNS_DISABLE_SERVER  */

#ifndef NX_MDNS_DISABLE_CLIENT
        /* Use remote buffer. */
        nx_mdns_service_continuous_query(&mdns_0, "_printer", "_tcp.local", NX_NULL);

        /* Wait two seconds for probing and announcement. */
        tx_thread_sleep(200);

        /* Delete the query. */
        nx_mdns_service_query_stop(&mdns_0, "_printer", "_tcp.local", NX_NULL);
#endif /* NX_MDNS_DISABLE_CLIENT  */

#ifndef NX_MDNS_DISABLE_SERVER
        nx_mdns_service_delete(&mdns_0, (CHAR *)"ARMMDNSTest", (CHAR *)"_ipp._tcp", NX_NULL);
#endif /* NX_MDNS_DISABLE_SERVER  */

        /* Delete the mDNS. */
        nx_mdns_delete(&mdns_0);

        /* Wait one second for goodbye packets sent. */
        tx_thread_sleep(100);
    }

    /* Determine if the test was successful.  */
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
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_mdns_buffer_size_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Buffer Size Test.....................................N/A\n");
    test_control_return(3);
}
#endif
