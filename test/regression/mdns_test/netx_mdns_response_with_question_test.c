#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"  

extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_SERVER && !defined NX_MDNS_DISABLE_CLIENT && !defined NX_DISABLE_IPV4
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
static UCHAR                   mdns_data[] =
{
    0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x00, 0x08, 0x5f, 0x70, 0x72, 
    0x69, 0x6e, 0x74, 0x65, 0x72, 0x04, 0x5f, 0x74, 
    0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 
    0x00, 0x00, 0x0c, 0x00, 0x01, 0x08, 0x5f, 0x70, 
    0x72, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x04, 0x5f, 
    0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 
    0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 
    0x11, 0x94, 0x00, 0x0f, 0x0c, 0x43, 0x61, 0x6e, 
    0x6f, 0x6e, 0x4d, 0x46, 0x34, 0x35, 0x30, 0x30, 
    0x77, 0xc0, 0x0c
};


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;
static NX_PACKET              *current_packet;
static ULONG                   response_received;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_response_with_question_test(void *first_unused_memory)
#endif
{

UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;
    error_counter = 0;
    response_received = 0;

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
NXD_ADDRESS address;

    printf("NetX Test:   MDNS Response With Question Test..........................");

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

    /* Add a service. */
    status += nx_mdns_service_add(&mdns_0, (CHAR *)"ARMMDNSTest", (CHAR *)"_printer._tcp", NX_NULL, "paper=A4;version=01", 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    if(status)
        error_counter++;

    /* Sleep 5 seconds for probing and announcement. */
    tx_thread_sleep(500);

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Send MULTICAST address. */
    address.nxd_ip_version = NX_IP_VERSION_V4;
    address.nxd_ip_address.v4 = NX_MDNS_IPV4_MULTICAST_ADDRESS;

    /* Allocate a packet and add data with mDNS response with question. */
    status = nx_packet_allocate(&pool_0, &current_packet, NX_IPv4_UDP_PACKET, 100);
    status += nx_packet_data_append(current_packet, mdns_data, sizeof(mdns_data), &pool_0, 100);
    status += nxd_udp_socket_send(&mdns_0.nx_mdns_socket, current_packet, &address, 5353);
    current_packet = NX_NULL;

    if(status)
        error_counter++;

    /* Sleep one second and check whether RR is stored. */
    tx_thread_sleep(100);

    if(mdns_0.nx_mdns_peer_rr_count != 1)
        error_counter++;

    /* Determine if the test was successful.  */
    if(error_counter || response_received)
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
UCHAR *pointer;

    if(packet_ptr == current_packet)
    {
        
        /* It is a response packet. */
        /* Inject it to IP layer. */
        packet_ptr -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];
        _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);
        return NX_FALSE;
    }

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
    pointer = packet_ptr -> nx_packet_prepend_ptr + 30;

    /* Check whether this packet is the response. */
    if(((*pointer << 8) + *(pointer + 1)) == (NX_MDNS_RESPONSE_FLAG | NX_MDNS_AA_FLAG))
        response_received = 1;

    return NX_TRUE;
}
#else                                   
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_response_with_question_test(void *first_unused_memory)
#endif
{                                                                   
    printf("NetX Test:   MDNS Response With Question Test..........................N/A\n"); 
    test_control_return(3);
}
#endif /* NX_MDNS_DISABLE_SERVER  */
