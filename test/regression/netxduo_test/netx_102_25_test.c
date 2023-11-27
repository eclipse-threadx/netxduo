/* 102.25 The increase in cwnd should be at most one segment each round-trip time (regardless how many ACKs are received in that RTT).  */

/* Procedure
   1. Connection.
   2. Client sends a data packet.
   3. Server receives the packet and replies an ACK packet.
   4. Check cwnd <= cwnd + MSS.
   5. Client sends a data packet again.
   6. Set ssthresh = cwnd - 10.
   7. Server starts congestion, after receives the packet, check cwnd <= cwnd + MSS.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_TCP_ACK_EVERY_N_PACKETS) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

#define     MSG "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   data_packet_counter;
static ULONG                   ack_counter;
static ULONG                   ack_number_1;
static ULONG                   ack_number_2;
/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    my_tcp_packet_receive_102_25(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_102_25_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    data_packet_counter = 0;
    ack_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
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
UINT         status;
ULONG        actual_status;
NX_PACKET    *my_packet1;
NX_PACKET    *my_packet2;
ULONG        cwnd;


    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 102.25 Test......................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status)
        error_counter++;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, ntest_0_disconnect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, ntest_0_connect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_102_25;

    /* Record the value of cwnd.  */
    cwnd = server_socket.nx_tcp_socket_tx_window_congestion;

    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet1, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    status = nx_packet_data_append(my_packet1, MSG, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Record the tx_sequence.  */
    ack_number_1 = server_socket.nx_tcp_socket_tx_sequence;

    /* Send the packet out!  */
    status = nx_tcp_socket_send(&server_socket, my_packet1, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Check the cwnd <= cwnd + MSS.  */
    if((ack_counter != 1) || (server_socket.nx_tcp_socket_tx_window_congestion > server_socket.nx_tcp_socket_connect_mss + cwnd))
        error_counter++;

    /* Let server congestion.  */
    server_socket.nx_tcp_socket_tx_slow_start_threshold = server_socket.nx_tcp_socket_tx_window_congestion - 10;

    /* Record the value of cwnd.  */
    cwnd = server_socket.nx_tcp_socket_tx_window_congestion;

    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet2, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    status = nx_packet_data_append(my_packet2, MSG, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    ack_number_2 = server_socket.nx_tcp_socket_tx_sequence;

    /* Send the second packet out!  */
    status = nx_tcp_socket_send(&server_socket, my_packet2, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Check the cwnd <= cwnd + MSS.  */
    if((ack_counter != 2) || (server_socket.nx_tcp_socket_tx_window_congestion > server_socket.nx_tcp_socket_connect_mss + cwnd))
        error_counter++;

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unaccepted the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unlisten on the server port.  */
    status = nx_tcp_server_socket_unlisten(&ip_0, 12);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;
}

static void    ntest_1_entry(ULONG thread_input)
{
UINT         status;
NX_PACKET    *rcv_packet_ptr;


    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    while(!nx_tcp_socket_receive(&client_socket, &rcv_packet_ptr, 5 * NX_IP_PERIODIC_RATE))
    {
        /* Check data length and payload */
        if((rcv_packet_ptr -> nx_packet_length == 20) && (!memcmp(rcv_packet_ptr -> nx_packet_prepend_ptr, MSG, 20)))
            data_packet_counter++;

        /* Release the packet.  */
        nx_packet_release(rcv_packet_ptr);
    }

    /* Disconnect this socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Determine if the test was successful.  */
    if(error_counter || (data_packet_counter != 2) || (ack_counter != 2))
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

static void    ntest_0_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void    ntest_0_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if(socket != &server_socket)
        error_counter++;
}

static void    my_tcp_packet_receive_102_25(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER        *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check if the packet is an ACK packet.  */
    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)
    {
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);

        if((tcp_header_ptr ->nx_tcp_acknowledgment_number == (ack_number_1 + 20)) || (tcp_header_ptr ->nx_tcp_acknowledgment_number == (ack_number_2 + 20)))
            ack_counter++;

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);

        if(ack_counter == 2)
            ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_102_25_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   TCP Spec 102.25 Test......................................N/A\n");
    test_control_return(3);
}
#endif
