/* 13.17 In a stream of full-sized segments there SHOULD be an ACK for at least every second segment.  */

/* Procedure
   1. Client connects to server.
   2. Server sends a stream of full-sized segments(4 segments) to Client.
   3. Check if client sends more than 2 ACK packet to Server.  */

/* The check logic of ACK packets is incorrect. NetXDuo implements it by defining NX_TCP_ACK_EVERY_N_PACKETS to 2. */


#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#if defined(__PRODUCT_NETXDUO__)
#include   "nx_ipv4.h"
#else
#include   "nx_ip.h"
#endif
#include   <time.h> 

extern void    test_control_return(UINT status);

#if 0
/*#ifndef NX_TCP_ACK_EVERY_N_PACKETS*/

#define     DEMO_STACK_SIZE    2048



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
static INT                     is_acked_every_2seg;

static UCHAR                   rcv_buffer[352];
static UINT                    rcv_length;
static UCHAR                   data_13_17[352];
static ULONG                   mss_option_13_17;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *client_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *client_socket);
static void    rand_13_17();
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    my_tcp_packet_receive_13_17(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_13_17_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    ack_counter = 0;
    rcv_length = 0;
    is_acked_every_2seg = NX_FALSE;

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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 512*16);
    pointer = pointer + 512*16;

    if(status)
        error_counter++;

    /* Create another IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create an IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
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
    UINT         status;
    NX_PACKET    *my_packet;
    ULONG        bytes_copied;



    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 13.17 Test.......................................");

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

    while(!(nx_tcp_socket_receive(&client_socket, &my_packet, NX_IP_PERIODIC_RATE)))
    {

        /* Retrieve data from packet to the receive buffer. */
        status = nx_packet_data_retrieve(my_packet, &rcv_buffer[rcv_length], &bytes_copied);
        if(status)
            error_counter++;

        rcv_length += bytes_copied;
    }

    /*Check if the content which connected by all the received packets is the data_13_17 sent from the client socket*/
    if(memcmp(rcv_buffer, data_13_17, rcv_length))
        error_counter++;

    /* Disconnect this socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    status += nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Determine if the test was successful.  */
    if((error_counter ==0) && (is_acked_every_2seg == NX_TRUE) && (ack_counter >= 2))
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


/* Define the test threads.  */
static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
NX_PACKET  *my_packet;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Check for earlier error.  */
    if(error_counter)
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

    /*Let the server socket to check the ACK segment*/
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive_13_17;

    mss_option_13_17 = server_socket.nx_tcp_socket_connect_mss;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, 80, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Create a 4*mss_option_13_17 length message randomly. */
    rand_13_17();

    /* Fill in the packet with data.     */
    status = nx_packet_data_append(my_packet, data_13_17, 4*mss_option_13_17, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&server_socket, my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;



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



static void rand_13_17()
{
UINT       flag;
UINT       j, k = 0;

    srand((unsigned)time(NULL)); 
    for(j = 0;j < 4*mss_option_13_17;j++)
    {
        flag = rand() & 1; 
        if(flag)
            data_13_17[k++] = 'A' + rand() % 26;
        else
            data_13_17[k++] = 'a' + rand() % 26;
    }
}



static void    my_tcp_packet_receive_13_17(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER *header_ptr;

    header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Server receives a ACK packet.  */
    if(!(header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && (header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && !(header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT) && !(header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT))
    {

        ack_counter++;

        if(ack_counter >= (server_socket.nx_tcp_socket_packets_sent >> 1))
            is_acked_every_2seg  = NX_TRUE;
    }
    else if(header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT)
        ip_1.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    _nx_tcp_packet_receive(ip_ptr, packet_ptr);

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
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_13_17_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   TCP Spec 13.17 Test.......................................N/A\n");
    test_control_return(3);
}
#endif
