/* This NetX test concentrates on connection reset.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048

#define MSG "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"



/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

/* Define a packet data send FIN from 192.168.1.10 to 192.168.1.8. The ACK bit is not set. */
static const unsigned char pkt_fin[] = {
0x00, 0x08, 0xee, 0x03, 0x6a, 0xc6, 0x00, 0x50, /* ....j..P */
0xb6, 0x07, 0xa1, 0x69, 0x08, 0x00, 0x45, 0x00, /* ...i..E. */
0x00, 0x28, 0x57, 0x1c, 0x40, 0x00, 0x80, 0x06, /* .(W.@... */
0x20, 0x51, 0xc0, 0xa8, 0x01, 0x0a, 0xc0, 0xa8, /*  Q...... */
0x01, 0x08, 0xd3, 0xed, 0x1f, 0x90, 0x66, 0xe8, /* ......f. */
0x6b, 0x67, 0x28, 0xd9, 0x25, 0x44, 0x50, 0x01, /* kg(.%DP. */
0xfa, 0xf0, 0x1d, 0xa5, 0x00, 0x00              /* ...... */
};
#ifdef __PRODUCT_NETXDUO__
static const ULONG fin_sequence = 0x66e86b67;
#endif /* __PRODUCT_NETXDUO__ */


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   rst_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
void           my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_connection_reset_test_application_define(void *first_unused_memory)
#endif
{

    CHAR    *pointer;
    UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    rst_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(192, 168, 1, 10), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
        pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(192, 168, 1, 8), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
        pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /*Enable ICMP for IP Instance 0 and 1.  */
    status = nx_icmp_enable(&ip_0);
    status = nx_icmp_enable(&ip_1);

    /* Check ARP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

    UINT        status;
    NX_PACKET   *my_packet;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Connection Reset Test.................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
        NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
        NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    tx_thread_relinquish();

    /*Send an echo request to make arp*/
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(192, 168, 1, 8), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, TX_TIMER_TICKS_PER_SECOND);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /*Deal the syn+ack packet with my routing*/
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive;
    advanced_packet_process_callback = my_packet_process;

    /*Call connect to send an syn*/ 
    nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(192, 168, 1, 8), 12, 5 * TX_TIMER_TICKS_PER_SECOND);

    /*Let server deal with rst*/
    tx_thread_relinquish();

    status = nx_packet_allocate(&pool_0, &my_packet, NX_ICMP_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt_fin[14], sizeof(pkt_fin) - 14);
    my_packet -> nx_packet_length = sizeof(pkt_fin) - 14;
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + sizeof(pkt_fin) - 14;

    /* Directly receive the RA packet.  */
    _nx_ip_packet_deferred_receive(&ip_1, my_packet);     

    /* Determine if the test was successful.  */
#ifdef __PRODUCT_NETXDUO__
    if ((error_counter) || (rst_counter != 1))
#else
    if (error_counter) 
#endif
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

static void    thread_1_entry(ULONG thread_input)
{

    UINT            status;
    ULONG           actual_status;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        error_counter++;
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
        NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
        NX_NULL, thread_1_disconnect_received);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, thread_1_connect_received);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    if(server_socket.nx_tcp_socket_state != NX_TCP_LISTEN_STATE)
        error_counter++;

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */

    tx_thread_resume(&thread_0);
}


static void  thread_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if ((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}


static void  thread_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if (socket != &server_socket)
        error_counter++;
}

void  my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER   header_ptr;

    /*Send rst*/
    header_ptr.nx_tcp_acknowledgment_number =  client_socket.nx_tcp_socket_tx_sequence;
    _nx_tcp_packet_send_rst(&client_socket, &header_ptr);
    _nx_tcp_socket_thread_resume(&(client_socket.nx_tcp_socket_connect_suspended_thread), NX_NOT_ENABLED);
    ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
}

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER *header_ptr;

    /* Do not process packets that are not TCP. */
    if ((packet_ptr -> nx_packet_length < 40) || (ip_ptr != &ip_1))
        return NX_TRUE;

    /* Get TCP header. */
    header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Check whether it is a RST packet. */
    if (header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
    {

        /* Yes it is. */
        rst_counter++;

#ifdef __PRODUCT_NETXDUO__
        /* Check whether the ACK equals SEQ in FIN plus one. */
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_acknowledgment_number);
        if (header_ptr -> nx_tcp_acknowledgment_number != fin_sequence + 1)
        {
            error_counter++;
        }
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_acknowledgment_number);
#endif
    }

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_connection_reset_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Connection Reset Test.................................N/A\n"); 

    test_control_return(3);  
}      
#endif