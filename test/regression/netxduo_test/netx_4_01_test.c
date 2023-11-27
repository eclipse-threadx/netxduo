/* 4.01 TCP in a CLOSED state, MUST ignore a RST control message.  */
/* An incoming segment containing a RST is discarded. */

/*  Procedure
1.Client connect with server.
2.Client becomes CLOSED state.
3.Server sends a RST packet to Client.
4.Client should ignore the incoming RST packet.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);
#if !defined(NX_DISABLE_RESET_DISCONNECT) && !defined(NX_DISABLE_IPV4)
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

/* Define thread prototypes.  */
static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_4_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_4_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_4_01_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    rst_counter = 0;

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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536 * 16);
    pointer = pointer + 1536 * 16;

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

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;

    /* Let thread 1 run.  */
    tx_thread_relinquish();

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

    /* Call connect to send a SYN.  */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error*/
    if(status)
        error_counter++;

    /* The client state should be in ESTABLISHED state.  */
    if(client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
        error_counter++;

    /* Modify the Client state to NX_TCP_CLOSED.  */
    client_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
                       
    /* Monitor the RST message from Server.  */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_4_01;
                        
    /* Monitor the TCP message from Client.  */
    advanced_packet_process_callback = my_packet_process_4_01;

    /* Let Server socket send RST message to Client Socket.  */
    tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);

    /* The client state should be in CLOSED state.  */
    if(client_socket.nx_tcp_socket_state != NX_TCP_CLOSED)
        error_counter++;

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error*/
    if(status)
        error_counter++;

    /* Delete the socket*/
    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error*/
    if(status)
        error_counter++;

    /* Determine if the test was successful.  */
    if(error_counter || (rst_counter != 1))
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

/* Define the test threads.  */

static void    ntest_1_entry(ULONG thread_input)
{
UINT            status;
ULONG           actual_status;
NX_TCP_HEADER   header_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 4.01 Test........................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
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

    /* The client state should be in ESTABLISHED state.  */
    if(server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
        error_counter++;
                             
    /* Let thread 0 run.  */
    tx_thread_relinquish();

    /* Fake one TCP header to send RST packet.  */
    header_ptr.nx_tcp_header_word_3 = NX_TCP_ACK_BIT | NX_TCP_RST_BIT;
    header_ptr.nx_tcp_acknowledgment_number = 1;
    header_ptr.nx_tcp_sequence_number       = 1;

    /* Send the RST packet to Client.  */
    _nx_tcp_packet_send_rst(&server_socket, &header_ptr);
                                                             
    /* Call disconnect to send a SYN.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_NO_WAIT);

    /* Unaccepted the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unlisted on the server port.  */
    status = nx_tcp_server_socket_unlisten(&ip_1, 12);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if (status)
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

static void    my_tcp_packet_receive_4_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER   *header_ptr;

    /* Set the TCP header.  */
    header_ptr = (NX_TCP_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Check if it is a RST packet.  */
    if ((header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
    {

        /* Increase the RST counter.  */
        rst_counter++;

        /* Cover the tcp receive function.  */
        ip_ptr -> nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);
           
    /* Let Client socket receive the RST packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}
      
static UINT    my_packet_process_4_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

#ifdef __PRODUCT_NETXDUO__
NX_IPV4_HEADER *ip_header_ptr;
#else  
NX_IP_HEADER   *ip_header_ptr;
#endif
                                
    /* Set the IP header.  */
#ifdef __PRODUCT_NETXDUO__
    ip_header_ptr = (NX_IPV4_HEADER *) packet_ptr -> nx_packet_prepend_ptr;
#else             
    ip_header_ptr = (NX_IP_HEADER *) packet_ptr -> nx_packet_prepend_ptr;
#endif

    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

    /* Check if the source address is 1.2.3.4.  */
    if (ip_header_ptr -> nx_ip_header_source_ip == IP_ADDRESS(1, 2, 3, 4))
    {                    

        /* Client socket shouldn't send any packet in response. */
        error_counter ++;
    }

    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

    return NX_TRUE;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_4_01_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 4.01 Test........................................N/A\n");
    test_control_return(3);      
}

#endif
