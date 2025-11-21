/* 102.20 When congestion occurs, one-half of the current window size is saved in ssthresh.  */


#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define    DEMO_STACK_SIZE    2048
#define    MSG                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

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
static ULONG                   seq_number;
static ULONG                   ack_counter;
static ULONG                   duplicate_ack_counter;
static ULONG                   is_set;
/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_102_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_102_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_102_20_application_define(void *first_unused_memory)
#endif
{
CHAR           *pointer;
UINT           status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    data_packet_counter = 0;
    ack_counter = 0;
    seq_number = 0;
    duplicate_ack_counter = 0;
    is_set = NX_FALSE;


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
UINT         status;
ULONG        actual_status;
NX_PACKET    *my_packet1;
NX_PACKET    *my_packet2;
NX_PACKET    *my_packet3;
NX_PACKET    *my_packet4;


    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 102.20 Test......................................");

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
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
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

    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = my_packet_process_102_20;
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_102_20;

    /* Create 4 packets   */
    status = nx_packet_allocate(&pool_0, &my_packet1, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    if(status)
        error_counter++;

    /* Fill in the packet with data.  */
    status = nx_packet_data_append(my_packet1, MSG, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send the packet.  */
    status = nx_tcp_socket_send(&server_socket, my_packet1, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

        /* Create a tcp packet.   */
    status = nx_packet_allocate(&pool_0, &my_packet2, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    if(status)
        error_counter++;

    /* Fill in the packet with data.  */
    status = nx_packet_data_append(my_packet2, MSG+20, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send the packet.  */
    status = nx_tcp_socket_send(&server_socket, my_packet2, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Create a tcp packet.   */
    status = nx_packet_allocate(&pool_0, &my_packet3, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    if(status)
        error_counter++;

    /* Fill in the packet with data.  */
    status = nx_packet_data_append(my_packet3, MSG+40, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send the packet.  */
    status = nx_tcp_socket_send(&server_socket, my_packet3, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Create a tcp packet.   */
    status = nx_packet_allocate(&pool_0, &my_packet4, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    if(status)
        error_counter++;

    /* Fill in the packet with data.  */
    status = nx_packet_data_append(my_packet4, MSG+60, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send the packet.  */
    status = nx_tcp_socket_send(&server_socket, my_packet4, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unlisten on the server port.  */
    status = nx_tcp_server_socket_unlisten(&ip_0, 12);

    /* Check for error.  */
    if(status)
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
NX_PACKET    *packet_ptr;


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

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;


    while(!(status = nx_tcp_socket_receive(&client_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE)))
    {

        if((packet_ptr -> nx_packet_length == 20) && (!memcmp(packet_ptr -> nx_packet_prepend_ptr, (MSG + data_packet_counter * 20), 20)))
            data_packet_counter++;

        /* Release the packet.  */
        nx_packet_release(packet_ptr);
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
    if(error_counter || (data_packet_counter != 4) ||  (duplicate_ack_counter != 3) || (is_set != NX_TRUE))
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

static UINT    my_packet_process_102_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER        *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);

    if((packet_ptr -> nx_packet_length-40 == 20) && (!memcmp(packet_ptr -> nx_packet_prepend_ptr+40, MSG, 20)))
    {
        if(server_socket.nx_tcp_socket_timeout_retries == 0)
        {
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr ->nx_tcp_sequence_number);
            seq_number = tcp_header_ptr -> nx_tcp_sequence_number;
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr ->nx_tcp_sequence_number);

            /* Drop the packet. */
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }

        else if(server_socket.nx_tcp_socket_timeout_retries == 1)
        {
            if((server_socket.nx_tcp_socket_tx_slow_start_threshold == server_socket.nx_tcp_socket_tx_outstanding_bytes / 2) || (server_socket.nx_tcp_socket_tx_slow_start_threshold == server_socket.nx_tcp_socket_connect_mss * 2))
                is_set = NX_TRUE;

            advanced_packet_process_callback = NX_NULL;
        }
    }
    return NX_TRUE;
}

static void    my_tcp_packet_receive_102_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER        *tcp_header_ptr;


    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check if the packet is an ACK packet.  */
    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)
    {
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);

        if(tcp_header_ptr ->nx_tcp_acknowledgment_number == seq_number)
            duplicate_ack_counter++;

        if(duplicate_ack_counter == 3)
            ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    }

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_102_20_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 102.20 Test......................................N/A\n"); 

    test_control_return(3);  
}      
#endif