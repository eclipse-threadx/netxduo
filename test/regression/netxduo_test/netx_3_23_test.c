/* 3.23:TCP,  in CLOSE-WAIT state, 
        MUST return an ACK with proper SEQ and ACK numbers after recv a seg with OTW SEQ or unacc ACK number, 
        and remain in same state If the connection is in a synchronized state, 
        any unacceptable segment (out of window sequence number or unacceptible acknowledgment number) 
        must elicit only an empty acknowledgment segment containing the current send-sequence number 
        and an acknowledgment indicating the next sequence number expected to be received, 
        and the connection remains in the same state. */

/*  Procedure
    1.Connect
    2.Set server socket to CLOSE_WAIT state
    3.Client sends a packet with OTW SEQ to server
    4.Client should receive an ACK with proper SEQ and ACK numbers, and server socket should remain in CLOSE_WAIT state
    5.Client sends a packet with unacceptable acknowledge numbers
    6.Client should receive an ACK with proper SEQ and ACK numbers, and server socket should remain in CLOSE_WAIT state  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#if defined(__PRODUCT_NETXDUO__)
#include   "nx_ipv4.h"
#endif
#include   "nx_ip.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

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
static ULONG                   ack_counter;
static ULONG                   data_packet_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_3_23(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_3_23(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    my_tcp_packet_receive_3_23_2(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_3_23_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    ack_counter = 0;
    data_packet_counter = 0;

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
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
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
ULONG      actual_status;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 3.23 Test........................................");

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
    status = nx_tcp_server_socket_accept(&server_socket, 2 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    if(server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
        error_counter++;

    /* Suspend the thread ntest_0.  */
    tx_thread_suspend(&ntest_0);

    if(server_socket.nx_tcp_socket_state != NX_TCP_CLOSE_WAIT)
        error_counter++;

    /* Set the receive function to my_tcp_packet_receive_3_23.  */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_3_23;

    /* Suspend the thread ntest_0.  */
    tx_thread_suspend(&ntest_0);

    if(server_socket.nx_tcp_socket_state != NX_TCP_CLOSE_WAIT)
        error_counter++;

    /* Suspend the thread ntest_0.  */
    tx_thread_suspend(&ntest_0);

    if(server_socket.nx_tcp_socket_state != NX_TCP_CLOSE_WAIT)
        error_counter++;

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);


    /* Set the port to NULL.  */
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
UINT        status;
NX_PACKET   *my_packet1, *my_packet2;

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

    /* Call connect to send an SYN  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status != NX_SUCCESS)
        error_counter++;

    /* Set client transmit number  */
    client_socket.nx_tcp_socket_tx_sequence++;

    /* Send FIN  */
    _nx_tcp_packet_send_fin(&client_socket,client_socket.nx_tcp_socket_tx_sequence - 1);

    tx_thread_resume(&ntest_0);

    /* Set the callback function. */
    advanced_packet_process_callback = my_packet_process_3_23;

    /* Replace the TCP receive function with my_tcp_packet_receive_3_23 for ip_1.  */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive_3_23_2;

    /* Create packet1  */
    status = nx_packet_allocate(&pool_0, &my_packet1, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Fill in the packet with data.   */
    status = nx_packet_data_append(my_packet1, MSG, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send packet1  */
    status = nx_tcp_socket_send(&client_socket, my_packet1, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Resume the thread ntest_0.  */
    tx_thread_resume(&ntest_0);

    /* Create packet2.  */
    status = nx_packet_allocate(&pool_0, &my_packet2, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Fill in the packet with data.   */
    status = nx_packet_data_append(my_packet2, MSG, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send packet2  */
    status = nx_tcp_socket_send(&client_socket, my_packet2, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Resume the thread ntest_0.  */
    tx_thread_resume(&ntest_0);

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);

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
    if((error_counter == 0) && (ack_counter == 2) && (data_packet_counter == 2))
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
    else
    {
        printf("ERROR!\n");
        test_control_return(1);
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

static UINT    my_packet_process_3_23(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

ULONG              checksum = 0;
NX_TCP_HEADER      *tcp_header_ptr;

#if defined(__PRODUCT_NETXDUO__)
ULONG           *source_ip, *dest_ip;
#elif defined(__PRODUCT_NETX__)
ULONG           source_ip, dest_ip;
#else
#error "NetX Product undefined."
#endif

    /* Point to TCP header  */
    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);

    /* The data segment process.  */
    if(packet_ptr -> nx_packet_length - 40 == 20)
    {
        if (data_packet_counter == 0)
        {
            /* Chang the sequence number.  */
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
            tcp_header_ptr -> nx_tcp_sequence_number -= 100;
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
        }
        else if (data_packet_counter == 1)
        {
            /* Change the ACK number.  */
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
            tcp_header_ptr -> nx_tcp_acknowledgment_number += 100;
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);

            advanced_packet_process_callback = NULL;

        }
        client_socket.nx_tcp_socket_tx_sequence -= 20;


#if defined(__PRODUCT_NETXDUO__)
        packet_ptr -> nx_packet_prepend_ptr += sizeof(NX_IPV4_HEADER);
        packet_ptr -> nx_packet_length -= sizeof(NX_IPV4_HEADER);
#else
        packet_ptr -> nx_packet_prepend_ptr += sizeof(NX_IP_HEADER);
        packet_ptr -> nx_packet_length -= sizeof(NX_IP_HEADER);
#endif

        tcp_header_ptr -> nx_tcp_header_word_4 = 0;



#if defined(__PRODUCT_NETXDUO__)
        dest_ip = &client_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4;
        source_ip = &client_socket.nx_tcp_socket_connect_interface -> nx_interface_ip_address;
        checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                           packet_ptr -> nx_packet_length,
                                           source_ip, dest_ip);
        checksum = ~checksum & NX_LOWER_16_MASK;
#elif defined(__PRODUCT_NETX__)
        dest_ip = client_socket.nx_tcp_socket_connect_ip;
        source_ip = ip_1.nx_ip_address;
        checksum = _nx_tcp_checksum(packet_ptr, source_ip, dest_ip);
#endif

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
        tcp_header_ptr -> nx_tcp_header_word_4 =  (checksum << NX_SHIFT_BY_16);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

#if defined(__PRODUCT_NETXDUO__)
        packet_ptr -> nx_packet_prepend_ptr -= sizeof(NX_IPV4_HEADER);
        packet_ptr -> nx_packet_length += sizeof(NX_IPV4_HEADER);
#else
        packet_ptr -> nx_packet_prepend_ptr -= sizeof(NX_IP_HEADER);
        packet_ptr -> nx_packet_length += sizeof(NX_IP_HEADER);
#endif
    }

    return NX_TRUE;
}

static void    my_tcp_packet_receive_3_23(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER  *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr->nx_packet_prepend_ptr;


    /* Check if it is a segment.  */
    if((packet_ptr -> nx_packet_length - 20 == 20) && (!memcmp(packet_ptr -> nx_packet_prepend_ptr + 20, MSG, 20)))
    {
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);

        /* Check if client sends a packet with OTW SEQ and proper ACK number.  */
        if(((tcp_header_ptr -> nx_tcp_sequence_number < server_socket.nx_tcp_socket_rx_sequence) ||
            (tcp_header_ptr -> nx_tcp_sequence_number >= server_socket.nx_tcp_socket_rx_sequence + server_socket.nx_tcp_socket_rx_window_current)) &&
            (tcp_header_ptr ->nx_tcp_acknowledgment_number == server_socket.nx_tcp_socket_tx_sequence) )
            data_packet_counter ++;

        /* Check if client sends a packet with proper SEQ and unacceptable ACK number.  */
        else if(((tcp_header_ptr -> nx_tcp_sequence_number >= server_socket.nx_tcp_socket_rx_sequence) &&
            (tcp_header_ptr -> nx_tcp_sequence_number < server_socket.nx_tcp_socket_rx_sequence + server_socket.nx_tcp_socket_rx_window_current)) &&
            (tcp_header_ptr ->nx_tcp_acknowledgment_number != server_socket.nx_tcp_socket_tx_sequence))
            data_packet_counter ++;

        if (data_packet_counter == 2)
            ip_ptr -> nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    }

    /* Let server receives the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}

static void    my_tcp_packet_receive_3_23_2(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER  *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER*)packet_ptr->nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr ->nx_tcp_header_word_3);

    if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && !(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && !(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
    {

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);

        if ((tcp_header_ptr -> nx_tcp_acknowledgment_number == server_socket.nx_tcp_socket_rx_sequence) && 
            (tcp_header_ptr -> nx_tcp_sequence_number == server_socket.nx_tcp_socket_tx_sequence))
        {
            ack_counter++;

            if (ack_counter == 2)
                ip_1.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

        }

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);

    }
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr ->nx_tcp_header_word_3);

    /* Let server receives the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_3_23_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 3.23 Test........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
