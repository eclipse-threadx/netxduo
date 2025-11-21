#include   "tx_api.h"
#include   "nx_api.h"
                       
extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_SERVER && !defined NX_DISABLE_IPV4
#include   "nxd_mdns.h"

#define     DEMO_STACK_SIZE             2048
#define     BUFFER_SIZE                 10240
#define     LOCAL_FULL_SERVICE_COUNT    16
#define     PEER_FULL_SERVICE_COUNT     16
#define     PEER_PARTIAL_SERVICE_COUNT  32

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static UCHAR                   buffer[BUFFER_SIZE];
static ULONG                   current_buffer_size;
static UCHAR                   mdns_stack[DEMO_STACK_SIZE];
static ULONG                   buffer_org_head;
static ULONG                   buffer_org_tail;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);
static void    check_empty_buffer(UCHAR *buffer_ptr, ULONG buffer_size, UCHAR expect_empty);
static void    empty_buffer_init();

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_two_buffer_test(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(192,168,0,31), 0xFFFFFF00UL, &pool_0, 
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
CHAR      *pointer = (CHAR*)thread_input;

    printf("NetX Test:   MDNS Two Buffer Test......................................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set pointer. */
    pointer = (CHAR*)thread_input;
    /* Create */
    current_buffer_size = 160;
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    /* Check status. */
    if(status != NX_SUCCESS)
        error_counter++;

    empty_buffer_init();

#ifndef NX_MDNS_DISABLE_SERVER
    /* Buffer is too small to add a service. */
    nx_mdns_service_add(&mdns_0, (CHAR *)"ARMMDNSTest", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Check local buffer. It must be empty. */
    check_empty_buffer(buffer, current_buffer_size, NX_TRUE);

    if(mdns_0.nx_mdns_local_rr_count != 0)
        error_counter++;
#endif /* NX_MDNS_DISABLE_SERVER  */

#ifndef NX_MDNS_DISABLE_CLIENT
    /* Check remote buffer. It must be empty. */
    check_empty_buffer(buffer + current_buffer_size, current_buffer_size, NX_TRUE);
    
    /* Check mdns information. */
    if(mdns_0.nx_mdns_peer_rr_count != 0)
        error_counter++;
#endif /* NX_MDNS_DISABLE_CLIENT  */

    /* Delete */
    nx_mdns_delete(&mdns_0);

    /* Initialize the buffer. */
    current_buffer_size = (BUFFER_SIZE >> 1);
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    /* Check status. */
    if(status != NX_SUCCESS)
        error_counter++;
    
    /* Enable mDNS. */
    nx_mdns_enable(&mdns_0, 0);

    empty_buffer_init();

#ifndef NX_MDNS_DISABLE_SERVER
    /* Use local buffer. */
    nx_mdns_service_add(&mdns_0, "ARMMDNSTest", "_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Check local buffer. It must not be empty. */
    check_empty_buffer(buffer, current_buffer_size, NX_FALSE);

    /* Delete the service. */
    nx_mdns_service_delete(&mdns_0, "ARMMDNSTest", "_ipp._tcp", NX_NULL);

    /* Sleep 1 second for goodbye packet. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Check local buffer. It must be empty. */
    check_empty_buffer(buffer, current_buffer_size, NX_TRUE);

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 2)
        error_counter++;
#endif /* NX_MDNS_DISABLE_SERVER  */

#ifndef NX_MDNS_DISABLE_CLIENT
    /* Check remote buffer. It must be empty. */
    check_empty_buffer(buffer + current_buffer_size, current_buffer_size, NX_TRUE);

    if(mdns_0.nx_mdns_peer_rr_count != 0)
        error_counter++;

    /* Use remote buffer. */
    nx_mdns_service_continuous_query(&mdns_0, NX_NULL, "_printer._tcp", NX_NULL);

    /* Check local buffer. It must be empty. */
    check_empty_buffer(buffer, current_buffer_size, NX_TRUE);

    /* Check remote buffer. It must be empty. */
    check_empty_buffer(buffer + current_buffer_size, current_buffer_size, NX_FALSE);
    
    /* Check mdns information. */
    if(mdns_0.nx_mdns_peer_rr_count != 1)
        error_counter++;

    /* Clear the peer cache. */
    nx_mdns_peer_cache_clear(&mdns_0);

    /* Check local buffer. It must be empty. */
    check_empty_buffer(buffer, current_buffer_size, NX_TRUE);

    /* Check remote buffer. It must be empty. */
    check_empty_buffer(buffer + current_buffer_size, current_buffer_size, NX_TRUE);
    
    /* Check mdns information. */
    if(mdns_0.nx_mdns_peer_rr_count != 0)
        error_counter++;
#endif /* NX_MDNS_DISABLE_CLIENT  */

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

static void    check_empty_buffer(UCHAR *buffer_ptr, ULONG buffer_size, UCHAR expect_empty)
{

ULONG     *tail, *head;
ULONG     expected_head, expected_tail;

    tx_mutex_get(&mdns_0.nx_mdns_mutex, TX_WAIT_FOREVER);

    head = (ULONG*)buffer_ptr;
    tail = (ULONG*)buffer_ptr + (buffer_size >> 2) - 1;

    /* Get expected head and tail. */
    if(buffer_ptr == buffer)
    {    
        expected_head = buffer_org_head;
        expected_tail = buffer_org_tail;
    }
    else
    {
        expected_head = (ULONG)(head + 1);
        expected_tail = (ULONG)tail;
    }

    /* Check head. */
    if((*head == expected_head) && (expect_empty == NX_FALSE))
        error_counter++;
    else if((*head != expected_head) && (expect_empty == NX_TRUE))
        error_counter++;

    /* Check tail. */
    if((*tail == expected_tail) && (expect_empty == NX_FALSE))
        error_counter++;
    else if((*tail != expected_tail) && (expect_empty == NX_TRUE))
        error_counter++;

    tx_mutex_put(&mdns_0.nx_mdns_mutex);
}

static void    empty_buffer_init()
{
ULONG     *tail, *head;

    head = (ULONG*)buffer;
    buffer_org_head = *head;

    tail = (ULONG*)buffer + (current_buffer_size >> 2) - 1;
    buffer_org_tail = *tail;
}
#else            
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_two_buffer_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Two Buffer Test......................................N/A\n");
    test_control_return(3);
}
#endif
