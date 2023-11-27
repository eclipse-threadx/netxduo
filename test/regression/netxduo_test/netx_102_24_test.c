/* 102.24 Formula commonly used to update cwnd during congestion avoidance is cwnd += SMSS*SMSS/ cwnd executed on every incoming non-duplicate ACK.   */

/* Procedure
   1. Connection.
   2. Set ssthresh = cwnd - 10.
   3. Client sends a data packet.
   4. Server starts congestion, after receives the packet, check cwnd = cwnd + MSS * MSS / cwnd.  */

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


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
static void    my_tcp_packet_receive_102_24(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_102_24_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    data_packet_counter =0;
    ack_counter = 0;

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
UINT       status;
NX_PACKET  *my_packet;
ULONG      cwnd;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
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

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Let client congestion.  */
    client_socket.nx_tcp_socket_tx_slow_start_threshold = client_socket.nx_tcp_socket_tx_window_congestion - 10;

    /* Record the value of client socket's cwnd.  */
    cwnd = client_socket.nx_tcp_socket_tx_window_congestion;

    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_102_24;

    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    status = nx_packet_data_append(my_packet, MSG, 28, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send the packet out!  */
    status = nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

     /* Check whether the cwnd = cwnd + MSS * MSS / cwnd.  */
    if((ack_counter != 1) || (client_socket.nx_tcp_socket_tx_window_congestion != client_socket.nx_tcp_socket_connect_mss2 / cwnd + cwnd))
        error_counter++;

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
    if(error_counter || (data_packet_counter != 1) || (ack_counter != 1))
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
UINT         status;
ULONG        actual_status;
NX_PACKET    *rcv_packet_ptr;

        /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 102.24 Test......................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status)
        error_counter++;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, ntest_1_disconnect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, ntest_1_connect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    status = nx_tcp_socket_receive(&server_socket, &rcv_packet_ptr, 2 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;
    else
    {
        /* Check data length and payload */
        if((rcv_packet_ptr -> nx_packet_length == 28) && (!memcmp(rcv_packet_ptr -> nx_packet_prepend_ptr, MSG, 28)))
            data_packet_counter++;

        /* Release the packet.  */
        nx_packet_release(rcv_packet_ptr);
    }

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
    status = nx_tcp_server_socket_unlisten(&ip_1, 12);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;
}

static void    ntest_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void    ntest_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if(socket != &server_socket)
        error_counter++;
}

static void    my_tcp_packet_receive_102_24(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER        *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check if the packet is an ACK packet.  */
    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)
    {

        if(client_socket.nx_tcp_socket_duplicated_ack_received == 0)
            ack_counter++;

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
void           netx_102_24_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   TCP Spec 102.24 Test......................................N/A\n");
    test_control_return(3);
}
#endif
