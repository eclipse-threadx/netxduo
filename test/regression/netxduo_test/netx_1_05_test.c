/* 1.05 TCP, in CLOSED state, must send a RST in response to an incoming segment containing ACK and not containing RST and SEQ number is taken from SEG.ACK.  */

/* Procedure
1. Create server and client sockets.
2. Let the client socket connect to the server socket.
3. Unbind the client socket.
4. Let the server socket send an ACK segment.
5. Check if the client socket is in CLOSED state.
6. Check if the segment is containing ACK and not containing RST.
7. Let the client socket receive the segment and send a RST segment.
8. Check if the segment is the RST one and its SEQ number is taken from SEG.ACK.
9. Check the error_counter and rst_counter.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_tcp.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

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
static ULONG                   rst_counter;
static ULONG                   ack_counter;
static ULONG                   ack_number;

/* Define thread prototypes.  */
static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    my_tcp_packet_receive_1_05(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    my_tcp_packet_receive_1_05_2(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_1_05_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    rst_counter = 0;
    ack_counter = 0;
    ack_number = 0;

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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
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

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 1.05 Test........................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
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

    /* Call connect to send an SYN.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Let client check the packet.  */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_1_05;

    /* Set the client socket to CLOSE state.  */
    client_socket.nx_tcp_socket_state = NX_TCP_CLOSED;

    /* Unbind the client socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    tx_thread_resume(&ntest_1);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Determine if the test was successful.  */
    if((error_counter) || (ack_counter != 1) || (rst_counter != 1))
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
ULONG      actual_status;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }

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

    tx_thread_suspend(&ntest_1);

    /* Let client check the packet.  */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive_1_05_2;

    /* Send out an ACK segment.  */
    _nx_tcp_packet_send_ack(&server_socket, server_socket.nx_tcp_socket_tx_sequence);

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);

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

void           my_tcp_packet_receive_1_05(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER    *tcp_header_ptr;

    if(client_socket.nx_tcp_socket_state == NX_TCP_CLOSED)
    {

        /* Point to the TCP HEADER.  */
        tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);

        /* Determined if it set the ACK BIT and  not set RST BIT.  */
        if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)))
        {
            /* The incoming segment is containing ACK and not containing RST.  */
            ack_counter = 1;
            ack_number = tcp_header_ptr -> nx_tcp_acknowledgment_number;

            /* Deal packets with default routing.  */
            ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
        }
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);

    }

    /* Let client receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}

void           my_tcp_packet_receive_1_05_2(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER    *tcp_header_ptr;

    if (ack_counter == 1)
    {
        /* Point to the TCP HEADER.  */
        tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

        /* Determined the RST BIT,ACK BIT,SEQ. <SEQ=SEG.ACK><CTL=RST>*/
        if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT) && (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)) && (tcp_header_ptr -> nx_tcp_sequence_number == ack_number))
        {

            /* RST_BIT have been set and SEQ number is taken from SEG.ACK.  */
            rst_counter++;

            /* Deal packets with default routing.  */
            ip_1.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
        }
        else
            error_counter++;

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    }

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_1_05_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 1.05 Test........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
