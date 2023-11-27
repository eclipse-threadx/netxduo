/* 15.20 If a retransmitted packet differs from the original packet in the window value,then the same IP identification field MUST NOT be used.  */

/*  Procedure
    1.Connection successfully
    2.Record the 1st coming IP_ID to ip_id_15_20
    3.Drop this packet and wait for the retransmitted packet
    4.Modify retransmitted packet's WINDOW value
    5.Check the retransmitted packet's IP_ID ?= ip_id_15_20   */

/*The NetX doesn't judge the acknowledgement field of the retransmitted packet, it uses the different IP identification when send every packet.*/

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ip.h"
#include   "nx_ram_network_driver_test_1500.h"
#if defined(__PRODUCT_NETXDUO__)
#include   "nx_ipv4.h"
#else
#include   "nx_ip.h"
#endif

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0

#define MSG              "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

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
static ULONG                   retrans_packet_counter;
static UINT                    is_different;

static ULONG                   ip_id_15_20;

/* Define thread prototypes.  */
static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_15_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_15_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_15_20_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    data_packet_counter = 0;
    retrans_packet_counter = 0;
    is_different = NX_FALSE;

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
NX_PACKET    *my_packet1;

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

    /* Call connect to send an SYN  */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 2 * NX_IP_PERIODIC_RATE);

    if(status)
        error_counter++;

    /* Create a packet to send.  */
    status = nx_packet_allocate(&pool_0, &my_packet1, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    status = nx_packet_data_append(my_packet1, MSG, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send packet to server.  */
    status = nx_tcp_socket_send(&client_socket, my_packet1, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    status = nx_packet_data_append(client_socket.nx_tcp_socket_transmit_sent_head, MSG + 20, 20, &pool_0, NX_IP_PERIODIC_RATE);

    client_socket.nx_tcp_socket_tx_sequence += 20;

    /* Increase the window size so the retransmitted packet is different from the original one. */
    client_socket.nx_tcp_socket_rx_window_current++;

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Disconnect this socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);

    if(status)
        error_counter++;

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    if(status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Determine if the test was successful.  */
    if((error_counter) || (retrans_packet_counter != 1) || (data_packet_counter != 1) || (is_different != NX_TRUE))
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
NX_PACKET    *my_packet;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 15.20 Test.......................................");

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

    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive_15_20;
    advanced_packet_process_callback = my_packet_process_15_20;

    /* Receive a TCP message from the socket.  */
    status = nx_tcp_socket_receive(&server_socket, &my_packet, 2 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;
    else
    {
        /* Check data length and payload */
        if((my_packet -> nx_packet_length == 40) && (!memcmp(my_packet -> nx_packet_prepend_ptr, MSG, 40)))
            retrans_packet_counter++;

        /* Release the packet.  */
        nx_packet_release(my_packet);
    }

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

static UINT    my_packet_process_15_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER   *tcp_header_ptr;
ULONG           checksum;

#if defined(__PRODUCT_NETXDUO__)
NX_IPV4_HEADER  *ip_header_ptr;
ULONG           *source_ip, *dest_ip;
ip_header_ptr = (NX_IPV4_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);
#elif defined(__PRODUCT_NETX__)
NX_IP_HEADER    *ip_header_ptr;
ULONG           source_ip, dest_ip;
ip_header_ptr = (NX_IP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);
#else
#error "NetX Product undefined."
#endif

    tcp_header_ptr = (NX_TCP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);

    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

    if ((packet_ptr -> nx_packet_length - 40 == 20) && (!memcmp(packet_ptr -> nx_packet_prepend_ptr + 40, MSG, 20)))
    {
        ip_id_15_20 = (ip_header_ptr -> nx_ip_header_word_1 & NX_LOWER_16_MASK);

        *operation_ptr = NX_RAMDRIVER_OP_DROP;

        data_packet_counter++;
    }

    else if ((packet_ptr -> nx_packet_length - 40 == 40) && (!memcmp(packet_ptr -> nx_packet_prepend_ptr + 40, MSG, 40)))
    {
#if defined(__PRODUCT_NETXDUO__)
        packet_ptr -> nx_packet_prepend_ptr += sizeof(NX_IPV4_HEADER);
        packet_ptr -> nx_packet_length -= sizeof(NX_IPV4_HEADER);
#else
        packet_ptr -> nx_packet_prepend_ptr += sizeof(NX_IP_HEADER);
        packet_ptr -> nx_packet_length -= sizeof(NX_IP_HEADER);
#endif

        /* Calculate the TCP checksum.  */
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
        source_ip = ip_0.nx_ip_address;
        checksum = _nx_tcp_checksum(packet_ptr, source_ip, dest_ip);
#endif


        /* Move the checksum into header.  */
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
        tcp_header_ptr -> nx_tcp_header_word_4 = (checksum << NX_SHIFT_BY_16);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

#if defined(__PRODUCT_NETXDUO__)
        packet_ptr -> nx_packet_prepend_ptr -= sizeof(NX_IPV4_HEADER);
        packet_ptr -> nx_packet_length += sizeof(NX_IPV4_HEADER);
#else
        packet_ptr -> nx_packet_prepend_ptr -= sizeof(NX_IP_HEADER);
        packet_ptr -> nx_packet_length += sizeof(NX_IP_HEADER);
#endif

        advanced_packet_process_callback = NX_NULL;
    }

    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

    return NX_TRUE;
}

static void    my_tcp_packet_receive_15_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
#if defined(__PRODUCT_NETXDUO__)
NX_IPV4_HEADER  *ip_header_ptr;
ip_header_ptr = (NX_IPV4_HEADER *)(packet_ptr -> nx_packet_prepend_ptr - 20);
#else
NX_IP_HEADER  *ip_header_ptr;
ip_header_ptr = (NX_IP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr - 20);
#endif

    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

    if ((packet_ptr -> nx_packet_length - 20 == 40) && (!memcmp(packet_ptr -> nx_packet_prepend_ptr + 20, MSG, 40)))
    {
        if(ip_id_15_20 != (ip_header_ptr -> nx_ip_header_word_1 & NX_LOWER_16_MASK))
            is_different = NX_TRUE;

        ip_1.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }

    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

    _nx_tcp_packet_receive(ip_ptr, packet_ptr);

}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_15_20_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 15.20 Test.......................................N/A\n"); 

    test_control_return(3);  
}      
#endif