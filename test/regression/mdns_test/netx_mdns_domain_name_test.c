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
static UCHAR                  *current_domain;
static USHORT                  current_flag;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_domain_name_test(void *first_unused_memory)
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

    printf("NetX Test:   MDNS Domain Name Test.....................................");

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
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);
    pointer = pointer + DEMO_STACK_SIZE;

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable mDNS.  */
    status = nx_mdns_enable(&mdns_0, 0);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;
                          
#ifndef NX_MDNS_DISABLE_SERVER
    /* Add services with default domain 'local'. */
    current_flag = (NX_MDNS_RESPONSE_FLAG | NX_MDNS_AA_FLAG);
    NX_CHANGE_USHORT_ENDIAN(current_flag);
    current_domain = "local";
    nx_mdns_service_add(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Sleep 2 seconds. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Add services with specified domain 'home'. */
    current_domain = "home.local";

    /* Set the domain. */
    status = nx_mdns_domain_name_set(&mdns_0, current_domain);

    nx_mdns_service_add(&mdns_0, "test", (CHAR *)"_printer._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);
#endif /* NX_MDNS_DISABLE_SERVER */
    
    /* Sleep 5 seconds. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

#ifndef NX_MDNS_DISABLE_CLIENT
    /* Query on 'local' domain. */
    current_flag = NX_MDNS_QUERY_FLAG;
    NX_CHANGE_USHORT_ENDIAN(current_flag);
    current_domain = "local";

    /* Set the domain. */
    status = nx_mdns_domain_name_set(&mdns_0, current_domain);

    /* Start to query. */
    nx_mdns_service_continuous_query(&mdns_0, NX_NULL, "_workstation._tcp", NX_NULL);
    
    /* Sleep 5 seconds. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Stop querying. */
    nx_mdns_service_query_stop(&mdns_0, NX_NULL, "_workstation._tcp", NX_NULL);

    /* Query on 'home' domain. */
    current_domain = "home.local";

    /* Set the domain. */
    status = nx_mdns_domain_name_set(&mdns_0, current_domain);

    /* Start to query. */
    nx_mdns_service_continuous_query(&mdns_0, NX_NULL, "_workstation._tcp", NX_NULL);
    
    /* Sleep 5 seconds. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Stop querying. */
    nx_mdns_service_query_stop(&mdns_0, NX_NULL, "_workstation._tcp", NX_NULL);
    
    current_domain = "local";

    /* Set the domain. */
    status = nx_mdns_domain_name_set(&mdns_0, current_domain);
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


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
UCHAR *string, *domain;
USHORT flag;
UCHAR *pointer;
UINT domain_length = strlen(current_domain);

    /* Get protocol. */
    pointer = packet_ptr -> nx_packet_prepend_ptr + 9;

    /* Check UDP packets only. */
    if(*pointer != NX_PROTOCOL_UDP)
        return NX_TRUE;

    /* Get port. */
    pointer = packet_ptr -> nx_packet_prepend_ptr + 20;

    /* Check UDP port 5353 only. */
    if((((*pointer << 8) + *(pointer + 1)) != 5353) ||
       (((*(pointer + 2) << 8) + *(pointer + 3)) != 5353))
        return NX_TRUE;

    /* Get flag. */
    flag = *((USHORT*)(packet_ptr -> nx_packet_prepend_ptr + 30));

    /* Check whether this packet is the one need to verify. */
    if(flag != current_flag)
        return NX_TRUE;

    string = packet_ptr -> nx_packet_prepend_ptr + 40;

    /* Find start position of domain. */
    for(domain = string + strlen(string) - 1; domain >= string; domain--)
    {
        domain_length--;
        if(domain_length == 0)
            break;

        /* Convert to dot. */
        if(*domain < 64)
            *domain = '.';
    }

    if(*domain < 64)
        domain++;

    if(strcmp(domain, current_domain))
        error_counter++;

    return NX_TRUE;
}
#else            
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_domain_name_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Domain Name Test.....................................N/A\n");
    test_control_return(3);
}
#endif
