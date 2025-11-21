/* 8.29.04 TCP, in CLOSE-WAIT or LAST-ACK state,MUST ignore a RST segment with OTW SEQ number.  */

/* Procedure
   1.Connection.
   2.Server disconnect without waiting.
   3.When Client is on the CLOSE-WAIT state, Server sends a RST which contains a OTW SEQ to Client.
   4.Check whether the state has been changed.
   5.Client disconnect without waiting.
   6.Delay the FIN packet.
   7.When Client is on the LAST-ACK state, Server sends a RST which contains a OTW SEQ to Client.
   8.Check whether the state has been changed.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(NX_DISABLE_RESET_DISCONNECT) && !defined(NX_DISABLE_IPV4)
#define        DEMO_STACK_SIZE    2048

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
static ULONG                   fin_counter;
static ULONG                   rst_counter;

/* Define thread prototypes.  */
static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_8_29_04(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_8_29_04(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_8_29_04_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    fin_counter = 0;
    rst_counter = 0;

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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
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
UINT             status;

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

    /* Deal the received packet with my routine. */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_8_29_04;

    /* Call connect to send an SYN.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Check whether the client socket's state changed after receiving a RST packet. */
    if((rst_counter != 1) || (client_socket.nx_tcp_socket_state != NX_TCP_CLOSE_WAIT))
        error_counter++;

    /* Delay the FIN packet in my_packet_process_8_29_04 to keep the socket in LAST_ACK state. */
    advanced_packet_process_callback = my_packet_process_8_29_04;

    status = nx_tcp_socket_disconnect(&client_socket, NX_NO_WAIT);

    if(client_socket.nx_tcp_socket_state != NX_TCP_LAST_ACK)
        error_counter++;

    tx_thread_resume(&ntest_1);

    /* Check whether the client socket's state changed after receiving a RST packet. */
    if((rst_counter != 2) || (client_socket.nx_tcp_socket_state != NX_TCP_LAST_ACK))
        error_counter++;

    tx_thread_resume(&ntest_1);

    /* Determine if the test was successful.  */
    if((error_counter) || (fin_counter != 1) || (rst_counter != 2))
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
UINT             status;
ULONG            actual_status;
NX_TCP_HEADER    header_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 8.29.04 Test.....................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
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

    status = nx_tcp_socket_disconnect(&server_socket, NX_NO_WAIT);

#if 0
    tx_thread_suspend(&ntest_1);
#endif

    /* Send RST  */
    header_ptr.nx_tcp_header_word_3 = header_ptr.nx_tcp_header_word_3 | NX_TCP_RST_BIT;
    header_ptr.nx_tcp_acknowledgment_number = client_socket.nx_tcp_socket_rx_sequence - 10;
    header_ptr.nx_tcp_sequence_number       = client_socket.nx_tcp_socket_tx_sequence;
    _nx_tcp_packet_send_rst(&server_socket, &header_ptr);

    tx_thread_suspend(&ntest_1);

    /* Send RST  */
    header_ptr.nx_tcp_header_word_3 = header_ptr.nx_tcp_header_word_3 | NX_TCP_RST_BIT;
    header_ptr.nx_tcp_acknowledgment_number = client_socket.nx_tcp_socket_rx_sequence - 20;
    header_ptr.nx_tcp_sequence_number       = client_socket.nx_tcp_socket_tx_sequence;
    _nx_tcp_packet_send_rst(&server_socket, &header_ptr);

    tx_thread_suspend(&ntest_1);

    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unlisten on the server port.  */
    status = nx_tcp_server_socket_unlisten(&ip_1, 12);

    /* Check for error.  */
    if(status)
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

static UINT    my_packet_process_8_29_04(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER   *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT) && (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT))
    {
        fin_counter++;

        /* Delay 1 second.  */
        *operation_ptr = NX_RAMDRIVER_OP_DELAY;
        *delay_ptr = NX_IP_PERIODIC_RATE;
    }

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    advanced_packet_process_callback = NX_NULL;

    return NX_TRUE;
}

static void    my_tcp_packet_receive_8_29_04(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER        *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    if(((client_socket.nx_tcp_socket_state == NX_TCP_CLOSE_WAIT) && (rst_counter == 0)) || ((client_socket.nx_tcp_socket_state == NX_TCP_LAST_ACK) && (rst_counter == 1)))
    {
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

        /* Check whether the packet is a RST one.  */
        if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT) && (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT))
        {
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);

            if ((tcp_header_ptr -> nx_tcp_sequence_number < server_socket.nx_tcp_socket_rx_sequence) ||
                (tcp_header_ptr -> nx_tcp_sequence_number >= server_socket.nx_tcp_socket_rx_sequence + server_socket.nx_tcp_socket_rx_window_current))
                rst_counter++;

            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);

            if(rst_counter == 2)
                ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
        }

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    }

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_8_29_04_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 8.29.04 Test.....................................N/A\n");
    test_control_return(3);

}
#endif
