/* This case tests two TCP segments are sent but the first one is dropped. The peer can receive all segments. */

#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#ifdef __PRODUCT_NETXDUO__
#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static ULONG                   drop_packet;
static UCHAR                   pool_area[20480];
static UCHAR                   send_buffer[3000];
static UCHAR                   recv_buffer[3000];

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
#endif /* FEATURE_NX_IPV6 */

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_retransmit_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    drop_packet = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024, pool_area, sizeof(pool_area));

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                           pointer, 2048, 2);
    pointer = pointer + 2048;
    if(status)
        error_counter++;

#ifndef NX_DISABLE_IPV4
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;
#endif

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_2.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_2.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_2.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[3] = 0x10000002;   

    /* Set interfaces' address */
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);

    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status = nxd_ipv6_enable(&ip_1);

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    if(status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NX_PACKET *packet_ptr;
UINT       i; 

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Retransmit Test.......................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Initialize the buffer. */
    for (i = 0; i < sizeof(send_buffer); i++)
    {
        send_buffer[i] = i & 0xFF;
    }
    memset(recv_buffer, 0, sizeof(recv_buffer));

    /* Let server thread listen first. */
    tx_thread_relinquish();

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, 1 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Connect to server.  */ 
#ifdef FEATURE_NX_IPV6
    status = nxd_tcp_client_socket_connect(&client_socket, &ipv6_address_2, 12, 5 * NX_IP_PERIODIC_RATE);
#else

    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */

    /* Check the connection status.  */
    if(status != NX_SUCCESS)
        error_counter++;

    /* The callback function is used to drop the first data packet to trigger retransmission.  */
    advanced_packet_process_callback = my_packet_process;

    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, send_buffer, client_socket.nx_tcp_socket_connect_mss * 2, 
                                       &pool_0, 1 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
            error_counter++;
    }

    /* The packet will be fragmented into 2 TCP packets. Drop 1 packet. */
    drop_packet = 1;

    /* Send the pacekt. */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;

}

static void    ntest_1_entry(ULONG thread_input)
{
UINT         status;
NX_PACKET   *packet_ptr;
ULONG        length;
ULONG        total_length = 0;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Loop to receive the packet. */
    while (nx_tcp_socket_receive(&server_socket, &packet_ptr, 2 * NX_IP_PERIODIC_RATE) == NX_SUCCESS)
    {
        nx_packet_data_retrieve(packet_ptr, &recv_buffer[total_length], &length);
        total_length += length;
        nx_packet_release(packet_ptr);
    }

    /* Check data. */
    if ((total_length != client_socket.nx_tcp_socket_connect_mss * 2) ||
        (memcmp(send_buffer, recv_buffer, total_length)))
    {
        error_counter++;
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

    /* Skip packets from IP1*/
    if (ip_ptr != &ip_0)
    {
        return NX_TRUE;
    }

    /* Skip none TCP packets. */
#ifdef FEATURE_NX_IPV6
    if (packet_ptr -> nx_packet_length < 60)
#else
    if (packet_ptr -> nx_packet_length < 40)
#endif
    {
        return NX_TRUE;
    }

    if (drop_packet != 0)
    {

        /* This packet should be dropped. */
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
        drop_packet--;
    }

    return NX_TRUE;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_retransmit_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Retransmit Test.......................................N/A\n");

    test_control_return(3);  
}      
#endif
