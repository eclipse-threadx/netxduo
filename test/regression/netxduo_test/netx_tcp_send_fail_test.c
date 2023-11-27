/* This case tests TCP send fails. */

#include   "nx_api.h"
#include   "nx_tcp.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NX_TCP_SOCKET           fake_socket;
static UCHAR                   send_buffer[1024];
static UCHAR                   recv_buffer[1024];


/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    window_update_notify(NX_TCP_SOCKET *client_socket);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_send_fail_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create two packet pools.  */
    status = nx_packet_pool_create(&pool_0, "Packet Pool 0", 1536, pointer, 8192);
    pointer = pointer + 8192;
    status += nx_packet_pool_create(&pool_1, "Packet Pool 1", 1536, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_256,
                           pointer, 2048, 2);
    pointer = pointer + 2048;
    if(status)
        error_counter++;

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

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Send Fail Test........................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a fake socket.  */
    status = nx_tcp_socket_create(&ip_0, &fake_socket, "Fake Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup fake socket. */
    fake_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    fake_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    fake_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    fake_socket.nx_tcp_socket_next_hop_address = IP_ADDRESS(1, 2, 3, 5);
    fake_socket.nx_tcp_socket_port = 12;
    fake_socket.nx_tcp_socket_connect_port = 12;
    fake_socket.nx_tcp_socket_rx_window_current = 128;
#ifdef NX_IPSEC_ENABLE
    fake_socket.nx_tcp_socket_egress_sa = NX_NULL;
#endif /* NX_IPSEC_ENABLE */

    /* Send a fake packet with no control bits set. */
    _nx_tcp_packet_send_control(&fake_socket, 0, 0, 0, 0, 0, NX_NULL);

#ifndef NX_DISABLE_TCP_INFO
    if (ip_1.nx_ip_tcp_receive_packets_dropped == 0)
        error_counter++;
#endif /* NX_DISABLE_TCP_INFO */

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup a receive notify function.  */
    status =  nx_tcp_socket_window_update_notify_set(&client_socket, window_update_notify);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, 1 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Connect to server.  */ 
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check the connection status.  */
    if(status != NX_SUCCESS)
        error_counter++;

    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if(status != NX_SUCCESS)
        error_counter++;

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(packet_ptr, send_buffer, sizeof(send_buffer), &pool_0, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Let thread 1 consume all packets and then send the pacekt. */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE << 2);
    if(status != NX_NO_PACKET)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(packet_ptr);
    }

    tx_thread_resume(&ntest_1);

#ifndef NX_DISABLE_PACKET_CHAIN
    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if(status != NX_SUCCESS)
        error_counter++;

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(packet_ptr, send_buffer, server_socket.nx_tcp_socket_rx_window_default, &pool_0, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Break the length of packet. */
    packet_ptr -> nx_packet_length += 65535;

    /* Send the pacekt. */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
    if(status != NX_INVALID_PACKET)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(packet_ptr);
    }
#endif /* NX_DISABLE_PACKET_CHAIN */


    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if(status != NX_SUCCESS)
        error_counter++;

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(packet_ptr, send_buffer, server_socket.nx_tcp_socket_rx_window_default, &pool_0, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Break the length of packet. */
    packet_ptr -> nx_packet_length += client_socket.nx_tcp_socket_connect_mss + 10;

    /* Send the pacekt. */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
    if(status != NX_INVALID_PACKET)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(packet_ptr);
    }


    /* Send one byte then send packet larger than window size. */
    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if(status != NX_SUCCESS)
        error_counter++;

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(packet_ptr, send_buffer, 1, &pool_0, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Send the pacekt. */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
    {
        error_counter++;
        nx_packet_release(packet_ptr);
    }

    /* Init send buffer. */
    memset(send_buffer, 0xF0, sizeof(send_buffer));
    memset(recv_buffer, 0x00, sizeof(recv_buffer));
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if(status != NX_SUCCESS)
        error_counter++;

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(packet_ptr, send_buffer, sizeof(send_buffer), &pool_0, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Send the pacekt. */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
    {
        error_counter++;
        nx_packet_release(packet_ptr);
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

static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;
NX_PACKET *packet_ptr;
NX_PACKET *consume_pkt[10];
ULONG      consumed = 0;
UINT       count;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 196,
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

    /* Sleep one second so client socket will waiting for window update to send the second packet. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Release packet. */
    nx_packet_release(packet_ptr);

    /* Allocate all packets until pool_0 is empty. */
    while (nx_packet_allocate(&pool_0, &consume_pkt[consumed], 0, NX_IP_PERIODIC_RATE) == NX_SUCCESS)
        consumed++;

    /* Wait until thread 0 timeout. */
    tx_thread_suspend(&ntest_1);

    /* Release all packets. */
    while (consumed--)
    {
        nx_packet_release(consume_pkt[consumed]);
    }

#ifndef NX_DISABLE_PACKET_CHAIN
    tx_thread_sleep(NX_IP_PERIODIC_RATE >> 1);
    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Release packet. */
    nx_packet_release(packet_ptr);
#endif /* NX_DISABLE_PACKET_CHAIN */

    tx_thread_sleep(NX_IP_PERIODIC_RATE >> 1);
    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Release packet. */
    nx_packet_release(packet_ptr);

    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Release packet. */
    nx_packet_release(packet_ptr);

    count = 0;
    while (nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE) == NX_SUCCESS)
    {

        /* Copy data to recv_buffer. */
        memcpy(recv_buffer + count, packet_ptr -> nx_packet_prepend_ptr, packet_ptr -> nx_packet_length);
        count += packet_ptr -> nx_packet_length;

        /* Release packet. */
        nx_packet_release(packet_ptr);
    }

    /* Check data in received packet. */
    if (count != sizeof(send_buffer))
        error_counter++;
    else if (memcmp(recv_buffer, send_buffer, sizeof(send_buffer)))
        error_counter++;

}

static void  window_update_notify(NX_TCP_SOCKET *client_socket)
{
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_send_fail_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Send Fail Test........................................N/A\n");

    test_control_return(3);  
}      
#endif
