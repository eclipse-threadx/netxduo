/* 13.01 A full-sized segment MUST be acknowledged within a time of 0.5 sec.  */

/* RFC 1122, Section 4.2.3.2, page 96, When to Send an ACK Segment. 
   A TCP SHOULD implement a delayed ACK, but an ACK should not be excessively delayed; 
   in particular, the delay MUST be less than 0.5 seconds, and in a stream of full-sized
   segments there SHOULD be an ACK for at least every second segment.  */

/* Procedure
   1. Client connects to server.
   2. Client sends a full-sized packet to server.
   3. When server receives packet, activate timer.
   4. When server sends ACK packet, wake up server and client thread.
   5. When  timer expired, check if segment has been acknowledged.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0

#define MSG "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

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
static TX_TIMER                my_timer;
static UINT                    ack_counter;
static ULONG                   data_packet_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_13_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_13_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    my_timer_entry(ULONG);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_13_01_application_define(void *first_unused_memory)
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

    /* Check status.  */
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

    /* Check status.  */
    if(status)
        error_counter++;

    /* Create an application timer.  */
    status = tx_timer_create(&my_timer, "my time", 
                             my_timer_entry, (ULONG) 0, 
                             NX_IP_PERIODIC_RATE / 2, 
                             NX_IP_PERIODIC_RATE / 2, 
                             TX_NO_ACTIVATE);

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
UINT            status;
ULONG           actual_status;
NX_PACKET       *rcv_packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 13.01 Test.......................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

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

    /* If accept return successfully, then it handles an illegal option length for MSS.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    advanced_packet_process_callback = my_packet_process_13_01;
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_13_01;

    status = nx_tcp_socket_receive(&server_socket, &rcv_packet_ptr, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;
    else
    {
        /* Check data length and payload */
        if((rcv_packet_ptr -> nx_packet_length == ip_1.nx_ip_interface[0].nx_interface_ip_mtu_size - 40) && 
           (!memcmp(rcv_packet_ptr -> nx_packet_prepend_ptr, MSG, ip_1.nx_ip_interface[0].nx_interface_ip_mtu_size - 40)))
            data_packet_counter++;

        /* Release the packet.  */
        nx_packet_release(rcv_packet_ptr);
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

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
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Delete timer.  */
    tx_timer_delete(&my_timer);
}

static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;
NX_PACKET  *my_packet;

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

    /* Attempt to connect the socket.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Create a full-sized packet to send.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    status = nx_packet_data_append(my_packet, MSG, ip_1.nx_ip_interface[0].nx_interface_ip_mtu_size - 40, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send packet to server.  */
    status = nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Wait until client receives ACK packet.  */
    tx_thread_suspend(&ntest_1);

    /* Call disconnect to send a FIN.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
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
    if(error_counter || (ack_counter != 1) || (data_packet_counter != 1))
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

static void    my_timer_entry(ULONG l)
{
    /* Check if segment has been acknowledged.  */
    if(ack_counter == 0)
        error_counter++;

    /* Wake up the client thread.  */
    tx_thread_resume(&ntest_1); 
}

static UINT    my_packet_process_13_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER   *header_ptr;

    header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Check if it is an ACK packet.  */
    if(!(header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && (header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && !(header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
    {
        ack_counter++;

        /* ACK packet has been processed.  */
        advanced_packet_process_callback = NX_NULL;
    }

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;
}

static void    my_tcp_packet_receive_13_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER   *header_ptr;

    /* Point to TCP header  */
    header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Check if the packet is a SEG.  */
    if(packet_ptr -> nx_packet_length == (ip_1.nx_ip_interface[0].nx_interface_ip_mtu_size - 20) && 
       (!memcmp(packet_ptr -> nx_packet_prepend_ptr + 20, MSG, ip_1.nx_ip_interface[0].nx_interface_ip_mtu_size - 40)))
    {
        /* Start timer.  */
        tx_timer_activate(&my_timer);

        /* Restore function pointer.  */
        ip_ptr -> nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Pass current packet to default function.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_13_01_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 13.01 Test.......................................N/A\n"); 

    test_control_return(3);  
}      
#endif
