/* 1.27.04 TCP must ignore a data segment in LAST_ACK state.  */

/* Procedure
1. Establish a connection by the "three-way handshake" procedure.
2. Let the server socket disconnect to the client socket.
3. Let the client socket disconnect to the server socket.
4. Let the driver delay the FIN packet.
5. Let the server socket send out a data segment.
6. Check if the client socket is in LAST_ACK state.
7. Let the client socket receive the data segment.
8. Check the status.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(NX_DISABLE_RESET_DISCONNECT) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048
#define     MSG                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   data_packet_counter;
static UINT                    is_ignored;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_1_27_04(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_1_27_04(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_1_27_04_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    data_packet_counter = 0;
    is_ignored = NX_FALSE;

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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
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
UINT         status;
NX_PACKET    *packet_ptr;

    printf("NetX Test:   TCP Spec 1.27.04 Test.....................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Let driver delay the FIN packet.  */
    advanced_packet_process_callback = my_packet_process_1_27_04;

    /* Disconnect.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_NO_WAIT);

    /* Setup function pointer.  */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_1_27_04;

    tx_thread_resume(&ntest_1);

    /* Check the client socket state.  */
    if(client_socket.nx_tcp_socket_state == NX_TCP_LAST_ACK)
    {
        status = nx_tcp_socket_receive(&client_socket, &packet_ptr, NX_IP_PERIODIC_RATE);

        /* Check for valid status.  */
        if(status)
            is_ignored = NX_TRUE;
    }
    else
        error_counter++;

    /* Determine if the test was successful.  */
    if((error_counter) || (data_packet_counter != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else if(is_ignored != NX_TRUE)
    {
        printf("WARNING!\n");
        test_control_return(2);
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
NX_PACKET    *my_packet;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
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

    /* Disconnect.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_NO_WAIT);

    tx_thread_suspend(&ntest_1);

    /* Set the server socket to ESTABLISHED state.  */
    server_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;

    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Write ABCs into the packet payload.  */
    status = nx_packet_data_append(my_packet, MSG, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send the packet out.  */
    status = nx_tcp_socket_send(&server_socket, my_packet, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    tx_thread_suspend(&ntest_1);

    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if (status)
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

static UINT    my_packet_process_1_27_04(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER    *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check the packet is a FIN one.  */
    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT)
    {

        /* Delay the FIN packet. */
        *operation_ptr = NX_RAMDRIVER_OP_DELAY;
        *delay_ptr = 200;

        /* FIN packet has been processed. */ 
        advanced_packet_process_callback = NX_NULL;
    }
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;
}

static void    my_tcp_packet_receive_1_27_04(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

    if(client_socket.nx_tcp_socket_state == NX_TCP_LAST_ACK)
    {
        if((packet_ptr->nx_packet_length == 40) && !(memcmp(packet_ptr->nx_packet_prepend_ptr + 20, MSG, 20)))
        {
            data_packet_counter++;

            /* Deal packets with default routing.  */
            ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
        }
    }

    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_1_27_04_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 1.27.04 Test.....................................N/A\n");
    test_control_return(3);

}
#endif
