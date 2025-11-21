#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_CLIENT && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined NX_DISABLE_IPV4
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
static NX_IP                   ip_1;
static NX_UDP_SOCKET           socket_1;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static UCHAR                   buffer[BUFFER_SIZE];
static ULONG                   current_buffer_size;
static UCHAR                   mdns_stack[DEMO_STACK_SIZE];
static UCHAR                   mdns_data[] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x11, 
0x22, 0x33, 0x44, 0x58, 0x08, 0x00, 0x45, 0x00, 
0x00, 0xd1, 0x00, 0x01, 0x00, 0x00, 0x80, 0x11,
0x31, 0x0f, 0x01, 0x02, 0x03, 0x05, 0x02, 0x02,
0x03, 0x04, 0x14, 0xe9, 0x14, 0xe9, 0x00, 0xbd, 
0x5f, 0xe5, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x11, 0x53, /* .......S */
0x69, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x57, 0x65, /* imple We */
0x62, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, /* b Server */
0x05, 0x5f, 0x68, 0x74, 0x74, 0x70, 0x04, 0x5f, /* ._http._ */
0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, /* tcp.loca */
0x6c, 0x00, 0x00, 0x10, 0x80, 0x01, 0x00, 0x00, /* l....... */
0x11, 0x94, 0x00, 0x01, 0x00, 0xc0, 0x1e, 0x00, /* ........ */
0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, /* ........ */
0x02, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x21, 0x80, /* ......!. */
0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0f, 0x00, /* ....x... */
0x00, 0x00, 0x00, 0x00, 0x50, 0x06, 0x75, 0x62, /* ....P.ub */
0x75, 0x6e, 0x74, 0x75, 0xc0, 0x29, 0xc0, 0x5b, /* untu.).[ */
0x00, 0x1c, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, /* .......x */
0x00, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x02, 0x0c, 0x29, 0xff, 0xfe, 0x01, /* ....)... */
0xd4, 0x79, 0xc0, 0x5b, 0x00, 0x01, 0x80, 0x01, /* .y.[.... */
0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, /* ...x.... */
0x00, 0x69, 0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, /* .i._serv */
0x69, 0x63, 0x65, 0x73, 0x07, 0x5f, 0x64, 0x6e, /* ices._dn */
0x73, 0x2d, 0x73, 0x64, 0x04, 0x5f, 0x75, 0x64, /* s-sd._ud */
0x70, 0xc0, 0x29, 0x00, 0x0c, 0x00, 0x01, 0x00, /* p.)..... */
0x00, 0x11, 0x94, 0x00, 0x02, 0xc0, 0x1e        /* ....... */
};

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
static void    check_empty_buffer(UCHAR *buffer_ptr, ULONG buffer_size, UCHAR expect_empty);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_source_address_test(void *first_unused_memory)
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

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, 
                           _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;

    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_1500);

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

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
NX_PACKET *my_packet;
NXD_ADDRESS address;

    printf("NetX Test:   MDNS Source Address Test..................................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set callback function pointer to discard the probing and annoucning packet. */
    advanced_packet_process_callback = my_packet_process;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Bind the UDP socket to the IP port.  */
    status += nx_udp_socket_bind(&socket_1, 5353, TX_WAIT_FOREVER);
        
    /* Create mDNS. */
    current_buffer_size = (BUFFER_SIZE >> 1);
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    /* Check status. */
    if(status != NX_SUCCESS)
        error_counter++;

    nx_mdns_enable(&mdns_0, 0);
    nx_mdns_enable(&mdns_0, 1);

    /* Inject mDNS response from 1.2.3.5 to 2.2.3.4. This packet MUST be rejected. */
    /* Secion 11, page 38, RFC 6762. */
    status = nx_packet_allocate(&pool_0, &my_packet, 16, 100);
    status += nx_packet_data_append(my_packet, mdns_data + 14, sizeof(mdns_data) - 14, &pool_0, 100);
    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[1];
    _nx_ip_packet_deferred_receive(&ip_0, my_packet);

    /* Check status. */
    if(status)
        error_counter++;

    /* Sleep one second to then check whether it is received. */
    tx_thread_sleep(100);
    check_empty_buffer(buffer + current_buffer_size, current_buffer_size, NX_TRUE);
    nx_mdns_delete(&mdns_0);

    /* Initialize the buffer. */
    current_buffer_size = (BUFFER_SIZE >> 1);
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    /* Check status. */
    if(status != NX_SUCCESS)
        error_counter++;

    nx_mdns_enable(&mdns_0, 0);
    nx_mdns_enable(&mdns_0, 1);

    /* Send unicase response. */
    address.nxd_ip_version = NX_IP_VERSION_V4;
    address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);
    status = nx_packet_allocate(&pool_0, &my_packet, NX_IPv4_UDP_PACKET, 100);
    status += nx_packet_data_append(my_packet, mdns_data + 42, sizeof(mdns_data) - 42, &pool_0, 100);
    status += nxd_udp_socket_send(&socket_1, my_packet, &address, 5353);

    /* Check status. */
    if(status)
        error_counter++;

    /* Sleep one second to then check whether it is received. */
    tx_thread_sleep(100);
    check_empty_buffer(buffer + current_buffer_size, current_buffer_size, NX_FALSE);

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

    tx_mutex_get(&mdns_0.nx_mdns_mutex, TX_WAIT_FOREVER);

    /* Check head. */
    head = (ULONG*)buffer_ptr;
    if((*head == (ULONG)(head + 1)) && (expect_empty == NX_FALSE))
        error_counter++;
    else if((*head != (ULONG)(head + 1)) && (expect_empty == NX_TRUE))
        error_counter++;

    /* Check tail. */
    tail = (ULONG*)buffer_ptr + (buffer_size >> 2) - 1;
    if((tail == (ULONG*)(*tail)) && (expect_empty == NX_FALSE))
        error_counter++;
    else if((tail != (ULONG*)(*tail)) && (expect_empty == NX_TRUE))
        error_counter++;

    tx_mutex_put(&mdns_0.nx_mdns_mutex);
}  

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

NX_IPV4_HEADER *ip_header_ptr;

    ip_header_ptr = (NX_IPV4_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_destination_ip);

    /* Check the destination address.  */
    if (ip_header_ptr -> nx_ip_header_destination_ip == NX_MDNS_IPV4_MULTICAST_ADDRESS)
    {

        /* Discard probing and annoucning message to avoid affecting test.  */
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
    }
    
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_destination_ip);

    return(NX_TRUE);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_source_address_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Source Address Test..................................N/A\n");
    test_control_return(3);
}
#endif
