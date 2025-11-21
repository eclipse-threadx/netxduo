#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h" 

extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_CLIENT && !defined NX_MDNS_DISABLE_SERVER && !defined NX_DISABLE_IPV4
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

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;
static CHAR                    host_registered = NX_FALSE;
static CHAR                    service_registered = NX_FALSE;
static CHAR                    query_received;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static VOID    probing_notify(struct NX_MDNS_STRUCT *mdns_ptr, UCHAR *name, UINT state);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_local_cache_continuous_query_test(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(192, 168, 0, 31), 0xFFFFFF00UL, &pool_0, 
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


    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   MDNS Local Cache Continuous Query Test....................");

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
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR*)"NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, probing_notify);
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

    /* Wait for host probing. */
    while(host_registered == NX_FALSE)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    /* Add a service. */
    if(nx_mdns_service_add(&mdns_0, (UCHAR*)"test", (UCHAR *)"_http._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for service probing. */
    while(service_registered == NX_FALSE)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    /* Initialize the query received. */
    query_received = 0;

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Start one-shot query. */
    if(nx_mdns_service_continuous_query(&mdns_0, NX_NULL, (UCHAR*)"_http._tcp", NX_NULL))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Wait for query. */
    while(query_received == 0)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
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


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
UCHAR       *packet_pointer;
USHORT      mdns_flags;
USHORT      question_count;
USHORT      answer_count;



    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(operation_ptr);
    NX_PARAMETER_NOT_USED(delay_ptr);

    /* Get protocol. */
    packet_pointer = packet_ptr -> nx_packet_prepend_ptr + 9;

    /* Check UDP packets only. */
    if(*packet_pointer != NX_PROTOCOL_UDP)
        return NX_TRUE;

    /* Get port. */
    packet_pointer = packet_ptr -> nx_packet_prepend_ptr + 20;

    /* Check UDP port 5353 only. */
    if((((*packet_pointer << 8) + *(packet_pointer + 1)) != 5353) ||
       (((*(packet_pointer + 2) << 8) + *(packet_pointer + 3)) != 5353))
        return NX_TRUE;

    /* Point to mDNS message.  */
    packet_pointer = packet_ptr -> nx_packet_prepend_ptr + 28;

    /* Extract the message type which should be the first byte.  */
    mdns_flags = NX_MDNS_GET_USHORT_DATA(packet_pointer + NX_MDNS_FLAGS_OFFSET);

    /* Check whether this packet is the query. */
    if(mdns_flags != NX_MDNS_QUERY_FLAG)
        return NX_TRUE;

    /* Increase the query count.  */
    query_received++;

    /* Get the question count.  */
    question_count = NX_MDNS_GET_USHORT_DATA(packet_pointer + NX_MDNS_QDCOUNT_OFFSET);

    /* Determine if we have any 'answers' to our DNS query. */
    answer_count = NX_MDNS_GET_USHORT_DATA(packet_pointer + NX_MDNS_ANCOUNT_OFFSET);

    /* Check the question count and answer count.  */
    if ((question_count != 1) || (answer_count != 1))
        error_counter++;

    return NX_TRUE;
}

static VOID  probing_notify(struct NX_MDNS_STRUCT *mdns_ptr, UCHAR *name, UINT state)
{

    NX_PARAMETER_NOT_USED(mdns_ptr);
    NX_PARAMETER_NOT_USED(name);

    switch(state)
    {
        case NX_MDNS_LOCAL_SERVICE_REGISTERED_SUCCESS:
        {
            service_registered = NX_TRUE;
            break;
        }
        case NX_MDNS_LOCAL_SERVICE_REGISTERED_FAILURE:
        {
            service_registered = NX_FALSE;
            break;
        }
        case NX_MDNS_LOCAL_HOST_REGISTERED_SUCCESS:
        {
            host_registered = NX_TRUE;
            break;
        }
        case NX_MDNS_LOCAL_HOST_REGISTERED_FAILURE:
        {
            host_registered = NX_FALSE;
            break;
        }   
    }
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_local_cache_continuous_query_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Local Cache Continuous Query Test....................N/A\n"); 
    test_control_return(3);
}
#endif /* NX_MDNS_DISABLE_CLIENT  */ 

