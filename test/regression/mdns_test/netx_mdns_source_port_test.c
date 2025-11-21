#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"
             
extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_CLIENT && !defined NX_DISABLE_IPV4
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
static NX_UDP_SOCKET           socket_0;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static UCHAR                   buffer[BUFFER_SIZE];
static ULONG                   current_buffer_size;
static UCHAR                   mdns_data[] =
{
0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x00, 0x11, /* ..^..... */
0x22, 0x33, 0x44, 0x57, 0x08, 0x00, 0x45, 0x00, /* "3DW..E. */
0x00, 0xc8, 0x00, 0x08, 0x40, 0x00, 0xff, 0x11, /* ....@... */
0x90, 0x02, 0x0a, 0x00, 0x00, 0x1f, 0xe0, 0x00, /* ........ */
0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9, 0x00, 0xb4, /* ........ */
0x5a, 0xe8, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, /* Z....... */
0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x04, 0x5f, /* ......._ */
0x69, 0x70, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, /* ipp._tcp */
0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, /* .local.. */
0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x00, /* ......d. */
0x1d, 0x0b, 0x41, 0x52, 0x4d, 0x4d, 0x44, 0x4e, /* ..ARMMDN */
0x53, 0x54, 0x65, 0x73, 0x74, 0x04, 0x5f, 0x69, /* STest._i */
0x70, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, /* pp._tcp. */
0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x0b, 0x41, /* local..A */
0x52, 0x4d, 0x4d, 0x44, 0x4e, 0x53, 0x54, 0x65, /* RMMDNSTe */
0x73, 0x74, 0x04, 0x5f, 0x69, 0x70, 0x70, 0x04, /* st._ipp. */
0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, /* _tcp.loc */
0x61, 0x6c, 0x00, 0x00, 0x21, 0x80, 0x01, 0x00, /* al..!... */
0x00, 0x00, 0x64, 0x00, 0x19, 0x00, 0x00, 0x00, /* ..d..... */
0x00, 0x00, 0x50, 0x0b, 0x41, 0x52, 0x4d, 0x4d, /* ..P.ARMM */
0x44, 0x4e, 0x53, 0x54, 0x65, 0x73, 0x74, 0x05, /* DNSTest. */
0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x0b, 0x41, /* local..A */
0x52, 0x4d, 0x4d, 0x44, 0x4e, 0x53, 0x54, 0x65, /* RMMDNSTe */
0x73, 0x74, 0x04, 0x5f, 0x69, 0x70, 0x70, 0x04, /* st._ipp. */
0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, /* _tcp.loc */
0x61, 0x6c, 0x00, 0x00, 0x10, 0x80, 0x01, 0x00, /* al...... */
0x00, 0x00, 0x64, 0x00, 0x01, 0x00              /* ..d... */
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
void           netx_mdns_source_port_test(void *first_unused_memory)
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
UINT            status;
ULONG           actual_status;
NXD_ADDRESS     address;
NX_MDNS_SERVICE service;


    printf("NetX Test:   MDNS Source Port Test.....................................");

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

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Bind the UDP socket to the IP port.  */
    status += nx_udp_socket_bind(&socket_0, 53, TX_WAIT_FOREVER);

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Send MULTICAST address. */
    address.nxd_ip_version = NX_IP_VERSION_V4;
    address.nxd_ip_address.v4 = NX_MDNS_IPV4_MULTICAST_ADDRESS;

    /* Allocate a packet and add data with mDNS response. */
    status = nx_packet_allocate(&pool_0, &current_packet, NX_IPv4_UDP_PACKET, 100);
    status += nx_packet_data_append(current_packet, mdns_data + 42, sizeof(mdns_data) - 42, &pool_0, 100);
    status += nxd_udp_socket_send(&socket_0, current_packet, &address, 5353);
    current_packet = NX_NULL;

    if(status)
        error_counter++;

    /* Sleep one second and check whether RR is stored. */
    /* Multicast DNS implementations MUST silently ignore any 
       Multicast DNS responses they receive where the source UDP port is not 5353. */
    tx_thread_sleep(100);

    if(nx_mdns_service_lookup(&mdns_0, NX_NULL, NX_NULL, NX_NULL, 0, &service) == NX_SUCCESS)
        error_counter++;

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

    if(packet_ptr == current_packet)
    {
        
        /* It is a response packet. */
        /* Inject it to IP layer. */
        packet_ptr -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];
        _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);
        return NX_FALSE;
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_source_port_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Source Port Test.....................................N/A\n"); 
    test_control_return(3);
}
#endif /* NX_MDNS_DISABLE_CLIENT  */ 
