#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined NX_DISABLE_IPV4 && !defined NX_MDNS_DISABLE_SERVER && !defined NX_MDNS_DISABLE_CLIENT
#include   "nxd_mdns.h"

#define     DEMO_STACK_SIZE    2048
#define     BUFFER_SIZE        10240
#define     LOCAL_FULL_SERVICE_COUNT    16
#define     PEER_FULL_SERVICE_COUNT     16
#define     PEER_PARTIAL_SERVICE_COUNT  32

/* Define the ThreadX and NetX object control blocks...  */

TX_THREAD                      thread_0;

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
static CHAR                    packet_count = 0;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static VOID    probing_notify(NX_MDNS *mdns_ptr, UCHAR *name, UINT state);


/* Define service.  */

#define SERVICE_INSTANCE_NAME   "NETXDUO_MDNS_Test1"
#define SERVICE_TYPE_HTTP       "_http._tcp"
#define SERVICE_SUB_TYPE_NULL   NX_NULL
#define SERVICE_TXT_NULL        NX_NULL
#define SERVICE_TTL             120
#define SERVICE_PRIORITY        0
#define SERVICE_WEIGHTS         0
#define SERVICE_PORT            80

#define SERVICE_TYPE_IPP        "_ipp._tcp"

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_second_interface_test(void *first_unused_memory)
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
    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_1500);

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

    /* Enable IGMP processing for both IP instances.  */
    status = nx_igmp_enable(&ip_0);

    /* Check status. */
    if(status)
        error_counter++;
    
    /* Create the main thread.  */
    tx_thread_create(&thread_0, "mDNS Client", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
}

/* Define the test threads.  */

void    thread_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;


    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   MDNS Second Interface Test................................");

    /* Check early error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    advanced_packet_process_callback = my_packet_process;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_interface_status_check(&ip_0, 1, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create mDNS. */
    current_buffer_size = (BUFFER_SIZE >> 1);
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS-CLIENT",
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, probing_notify);
    pointer = pointer + DEMO_STACK_SIZE;

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable mDNS.  */
    status = nx_mdns_enable(&mdns_0, 1);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register service.  */
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)SERVICE_INSTANCE_NAME, (UCHAR *)SERVICE_TYPE_HTTP, SERVICE_SUB_TYPE_NULL,
                                 SERVICE_TXT_NULL, SERVICE_TTL, (USHORT)SERVICE_PRIORITY, (USHORT)SERVICE_WEIGHTS,
                                 (USHORT)SERVICE_PORT, NX_TRUE, 1);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for host register and service register.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if ((packet_count == 0) || (host_registered != NX_TRUE) || (service_registered != NX_TRUE))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Reset packet count.  */
    packet_count = 0;

    /* Perform mDNS continuous query.  */
    status = nx_mdns_service_continuous_query(&mdns_0, NX_NULL, (UCHAR *)SERVICE_TYPE_IPP, NX_NULL);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Determine if the test was successful.  */
    if((error_counter) || (packet_count == 0))
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


    NX_PARAMETER_NOT_USED(delay_ptr);

    /* Check the packet interface.  */
    if (packet_ptr -> nx_packet_address.nx_packet_interface_ptr != &ip_ptr -> nx_ip_interface[1])
        error_counter++;

    packet_count++;

    *operation_ptr = NX_NULL;
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
void           netx_mdns_second_interface_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Second Interface Test................................N/A\n");
    test_control_return(3);
}
#endif
