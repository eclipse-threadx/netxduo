#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h" 
extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_SERVER && !defined NX_DISABLE_IPV4
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
static UCHAR                   mdns_query;
static UCHAR                   mdns_response;
static UCHAR                   mdns_stack[DEMO_STACK_SIZE];

/* A DNS-SD response 
   rdata: "_http._tcp.local"
   TTL: 4500 */
/* Frame (112 bytes) */
static UCHAR                   mdns_data_1[] =
{
0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x00, 0x11, /* ..^..... */
0x22, 0x33, 0x44, 0x57, 0x08, 0x00, 0x45, 0x00, /* "3DW..E. */
0x00, 0x62, 0x00, 0x07, 0x40, 0x00, 0xff, 0x11, /* .b..@... */
0x90, 0x46, 0x0a, 0x00, 0x00, 0x42, 0xe0, 0x00, /* .F...B.. */
0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9, 0x00, 0x4e, /* .......N */
0x17, 0xa6, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x5f, /* ......._ */
0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, /* services */
0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, /* ._dns-sd */
0x04, 0x5f, 0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, /* ._udp.lo */
0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, /* cal..... */
0x00, 0x00, 0x11, 0x94, 0x00, 0x12, 0x05, 0x5f, /* ......._ */
0x68, 0x74, 0x74, 0x70, 0x04, 0x5f, 0x74, 0x63, /* http._tc */
0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00  /* p.local. */
};

/* A service response
   Service: "ARMMDNSTest._ipp._tcp.local"
   type: SRV
   TTL: 120 */
static UCHAR                   mdns_data_2[] =
{
0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x00, 0x11, /* ..^..... */
0x22, 0x33, 0x44, 0x57, 0x08, 0x00, 0x45, 0x00, /* "3DW..E. */
0x01, 0x07, 0x00, 0x07, 0x40, 0x00, 0xff, 0x11, /* ....@... */
0x8f, 0xa1, 0x0a, 0x00, 0x00, 0x42, 0xe0, 0x00, /* .....B.. */
0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9, 0x00, 0xf3, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x41, /* .......A */
0x52, 0x4d, 0x4d, 0x44, 0x4e, 0x53, 0x54, 0x65, /* RMMDNSTe */
0x73, 0x74, 0x04, 0x5f, 0x69, 0x70, 0x70, 0x04, /* st._ipp. */
0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, /* _tcp.loc */
0x61, 0x6c, 0x00, 0x00, 0x21, 0x80, 0x01, 0x00, /* al..!... */
0x00, 0x00, 0x78, 0x00, 0x19, 0x00, 0x00, 0x00, /* ..x..... */
0x00, 0x00, 0x50, 0x0b, 0x41, 0x52, 0x4d, 0x4d, /* ..P.ARMM */
0x44, 0x4e, 0x53, 0x54, 0x65, 0x73, 0x74, 0x05, /* DNSTest. */
0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00              /* local.   */
};

/* A service response
   Service: "ARMMDNSTest._ipp._tcp.local"
   type: SRV
   TTL: 60 */
static UCHAR                   mdns_data_3[] =
{
0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x00, 0x11, /* ..^..... */
0x22, 0x33, 0x44, 0x57, 0x08, 0x00, 0x45, 0x00, /* "3DW..E. */
0x01, 0x07, 0x00, 0x07, 0x40, 0x00, 0xff, 0x11, /* ....@... */
0x8f, 0xa1, 0x0a, 0x00, 0x00, 0x42, 0xe0, 0x00, /* .....B.. */
0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9, 0x00, 0xf3, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x41, /* .......A */
0x52, 0x4d, 0x4d, 0x44, 0x4e, 0x53, 0x54, 0x65, /* RMMDNSTe */
0x73, 0x74, 0x04, 0x5f, 0x69, 0x70, 0x70, 0x04, /* st._ipp. */
0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, /* _tcp.loc */
0x61, 0x6c, 0x00, 0x00, 0x21, 0x80, 0x01, 0x00, /* al..!... */
0x00, 0x00, 0x3c, 0x00, 0x19, 0x00, 0x00, 0x00, /* ..x..... */
0x00, 0x00, 0x50, 0x0b, 0x41, 0x52, 0x4d, 0x4d, /* ..P.ARMM */
0x44, 0x4e, 0x53, 0x54, 0x65, 0x73, 0x74, 0x05, /* DNSTest. */
0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00              /* local.   */
};

/* A service response
   Service: "ARMMDNSTest._ipp._tcp.local"
   type: SRV
   TTL: 59 */
static UCHAR                   mdns_data_4[] =
{
0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x00, 0x11, /* ..^..... */
0x22, 0x33, 0x44, 0x57, 0x08, 0x00, 0x45, 0x00, /* "3DW..E. */
0x01, 0x07, 0x00, 0x07, 0x40, 0x00, 0xff, 0x11, /* ....@... */
0x8f, 0xa1, 0x0a, 0x00, 0x00, 0x42, 0xe0, 0x00, /* .....B.. */
0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9, 0x00, 0xf3, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x41, /* .......A */
0x52, 0x4d, 0x4d, 0x44, 0x4e, 0x53, 0x54, 0x65, /* RMMDNSTe */
0x73, 0x74, 0x04, 0x5f, 0x69, 0x70, 0x70, 0x04, /* st._ipp. */
0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, /* _tcp.loc */
0x61, 0x6c, 0x00, 0x00, 0x21, 0x80, 0x01, 0x00, /* al..!... */
0x00, 0x00, 0x3b, 0x00, 0x19, 0x00, 0x00, 0x00, /* ..x..... */
0x00, 0x00, 0x50, 0x0b, 0x41, 0x52, 0x4d, 0x4d, /* ..P.ARMM */
0x44, 0x4e, 0x53, 0x54, 0x65, 0x73, 0x74, 0x05, /* DNSTest. */
0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00              /* local.   */
};


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;
static NX_PACKET              *current_packet;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_responder_cooperating_test(void *first_unused_memory)
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
NXD_ADDRESS address;

    printf("NetX Test:   MDNS Responder Cooperating Test...........................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Send MULTICAST address. */
    address.nxd_ip_version = NX_IP_VERSION_V4;
    address.nxd_ip_address.v4 = NX_MDNS_IPV4_MULTICAST_ADDRESS;
        
    /* Create mDNS. */
    current_buffer_size = (BUFFER_SIZE >> 1);
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    /* Check status. */
    if(status != NX_SUCCESS)
        error_counter++;

    nx_mdns_enable(&mdns_0, 0);


    /* Create a service. */
    status += nx_mdns_service_add(&mdns_0, (CHAR *)"ARMMDNSTest", (CHAR *)"_ipp._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    if(status)
        error_counter++;

    /* Sleep 5 seconds for probing and announcement. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Reset counter. */
    mdns_query = 0;
    mdns_response = 0;
    
    /* Inject a RR with same name(_services._dns-sd._udp), rrtype(PTR) and rrclass(1), but different rdata(_http._tcp.local). */
    /* Allocate a packet and add data with mDNS response. */
    status = nx_packet_allocate(&pool_0, &current_packet, NX_IPv4_UDP_PACKET, 100);
    status += nx_packet_data_append(current_packet, mdns_data_1 + 42, sizeof(mdns_data_1) - 42, &pool_0, 100);
    status += nxd_udp_socket_send(&mdns_0.nx_mdns_socket, current_packet, &address, 5353);
    current_packet = NX_NULL;

    if(status)
        error_counter++;

    /* Sleep one second and check whether any mDNS packet is sent. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* For shared RR, no action is required. */
    if(mdns_query || mdns_response)
        error_counter++;


    /* Reset counter. */
    mdns_query = 0;
    mdns_response = 0;
    
    /* Inject a RR with the same name(ARMMDNSTest._ipp._tcp), rrtype(SRV) and rrclass(1), but different rdata(ARMMDNSTest.local). */
    /* Allocate a packet and add data with mDNS response. */
    status = nx_packet_allocate(&pool_0, &current_packet, NX_IPv4_UDP_PACKET, 100);
    status += nx_packet_data_append(current_packet, mdns_data_2 + 42, sizeof(mdns_data_2) - 42, &pool_0, 100);
    status += nxd_udp_socket_send(&mdns_0.nx_mdns_socket, current_packet, &address, 5353);
    current_packet = NX_NULL;

    if(status)
        error_counter++;

    /* Sleep one second and check whether any mDNS packet is sent. */
    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);

    /* For unique RR, probing and announcing are required. */
    if((mdns_query != 3) || (mdns_response == 0))
        error_counter++;

    /* Delete the service. */
    nx_mdns_service_delete(&mdns_0, (CHAR *)"ARMMDNSTest", (CHAR *)"_ipp._tcp", NX_NULL);

    /* Delete mdns. */
    nx_mdns_delete(&mdns_0);
        

    /* Create mDNS. */
    current_buffer_size = (BUFFER_SIZE >> 1);
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack, DEMO_STACK_SIZE, "ARMMDNSTest",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    /* Check status. */
    if(status != NX_SUCCESS)
        error_counter++;

    nx_mdns_enable(&mdns_0, 0);


    /* Create a service with the same name, rrtype and rrclass and rdata. */
    /* The received TTL is at least half the true TTL from local RR. */
    status += nx_mdns_service_add(&mdns_0, (CHAR *)"ARMMDNSTest", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 120, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    if(status)
        error_counter++;

    /* Sleep 5 seconds for probing and announcement. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Reset counter. */
    mdns_query = 0;
    mdns_response = 0;
    
    /* Inject a RR with the same name(ARMMDNSTest._ipp._tcp), rrtype(SRV) and rrclass(1) and rdata(ARMMDNSTest.local). */
    /* The received TTL(60) is at least half the true TTL(120) from local RR. */
    /* Allocate a packet and add data with mDNS response. */
    status = nx_packet_allocate(&pool_0, &current_packet, NX_IPv4_UDP_PACKET, 100);
    status += nx_packet_data_append(current_packet, mdns_data_3 + 42, sizeof(mdns_data_3) - 42, &pool_0, 100);
    status += nxd_udp_socket_send(&mdns_0.nx_mdns_socket, current_packet, &address, 5353);
    current_packet = NX_NULL;

    if(status)
        error_counter++;

    /* Sleep one second and check whether any mDNS packet is sent. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* No action is required. */
    if(mdns_query || mdns_response)
        error_counter++;


    /* Reset counter. */
    mdns_query = 0;
    mdns_response = 0;
    
    /* Inject a RR with the same name(ARMMDNSTest._ipp._tcp), rrtype(SRV) and rrclass(1) and rdata(ARMMDNSTest.local). */
    /* The received TTL(59) is at least half the true TTL(120) from local RR. */
    /* Allocate a packet and add data with mDNS response. */
    status = nx_packet_allocate(&pool_0, &current_packet, NX_IPv4_UDP_PACKET, 100);
    status += nx_packet_data_append(current_packet, mdns_data_4 + 42, sizeof(mdns_data_4) - 42, &pool_0, 100);
    status += nxd_udp_socket_send(&mdns_0.nx_mdns_socket, current_packet, &address, 5353);
    current_packet = NX_NULL;

    if(status)
        error_counter++;

    /* Sleep one second and check whether any mDNS packet is sent. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Response is required. */
    if(mdns_query || (mdns_response == 0))
        error_counter++;
    
    /* Delete the service. */
    nx_mdns_service_delete(&mdns_0, (CHAR *)"ARMMDNSTest", (CHAR *)"_ipp._tcp", NX_NULL);

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

UCHAR *pointer;

    if(packet_ptr == current_packet)
    {
        
        /* It is a packet need to inject. */
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
        mdns_response++;
    else
        mdns_query++;

    return NX_TRUE;

}
#else               
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_responder_cooperating_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Responder Cooperating Test...........................N/A\n");
    test_control_return(3);
}
#endif /* NX_MDNS_DISABLE_SERVER  */

