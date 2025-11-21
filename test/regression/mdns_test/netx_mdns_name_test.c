#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"
                      
extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_IPV4
#include   "nxd_mdns.h"

#define     DEMO_STACK_SIZE    2048
#define     BUFFER_SIZE        10240
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
static UCHAR                   name_buffer[100];

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
static VOID    build_name(UINT length);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_name_test(void *first_unused_memory)
#endif
{

UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;
    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, 
                          _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
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
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, NX_NULL,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE;

}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
ULONG      name_length;

    printf("NetX Test:   MDNS Name Test............................................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
        
    /* Create mDNS. */
    current_buffer_size = (BUFFER_SIZE >> 1);
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    /* Check status. */
    if(status != NX_SUCCESS)
        error_counter++;

    nx_mdns_enable(&mdns_0, 0);

    /* Test max length instance name, (NX_MDNS_LABEL_MAX - 4). */
    name_length = (NX_MDNS_LABEL_MAX - 4);
    build_name(name_length);
    
#ifndef NX_MDNS_DISABLE_SERVER
    /* Total length is 59. */
    status += nx_mdns_service_add(&mdns_0, name_buffer, (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);
#endif /* NX_MDNS_DISABLE_SERVER  */

#ifndef NX_MDNS_DISABLE_CLIENT
    /* Total length is 59. */
    status += nx_mdns_service_continuous_query(&mdns_0, name_buffer, "_ipp._tcp", NX_NULL);
#endif /* NX_MDNS_DISABLE_CLIENT  */

    /* Check status. */
    if(status)
        error_counter++;

    /* Test strings exceed max length, (NX_MDNS_LABEL_MAX - 4) + 1. */
    name_length = (NX_MDNS_LABEL_MAX - 4) + 1;
    build_name(name_length);

#ifndef NX_DISABLE_ERROR_CHECKING
#ifndef NX_MDNS_DISABLE_SERVER
    /* Total length is 60. */
    status = nx_mdns_service_add(&mdns_0, name_buffer, (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Check status. */
    if(!status)
        error_counter++;
#endif /* NX_MDNS_DISABLE_SERVER  */
#endif /* NX_DISABLE_ERROR_CHECKING  */

#ifndef NX_MDNS_DISABLE_CLIENT
    /* Total length is 60. */
    status = nx_mdns_service_continuous_query(&mdns_0, name_buffer, "_ipp._tcp", NX_NULL);

    /* Check status. */
    if(status)
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


static VOID    build_name(UINT length)
{

UINT i;

    /* Add lower case character. */
    for(i = 1; i <= length; i++)
    {
        if(i % 64 == 0 )
            name_buffer[i - 1] = '.';
        else
            name_buffer[i - 1] = 'a' + i % 26;
    }

    name_buffer[i] = 0;
} 
#else            
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_name_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Name Test............................................N/A\n");
    test_control_return(3);
}
#endif
