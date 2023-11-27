/* 9.27 TCP, in SYN-RCVD state, MUST send a reset and go to CLOSED, on recv a seg with SYN in window. */

/* Procedure
1. Client connect to the Server.
2. Change the ACK packet sent from the Client to the Server to a SYN packet.
3. Judge whether the Client received a RST packet.
4. Judge the Server state.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ip.h"
#include   "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0

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
static ULONG                   syn_counter;
static ULONG                   rst_counter;

static UINT                    syn_flag;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);

extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

extern USHORT  _nx_ip_checksum_compute(NX_PACKET *, ULONG, UINT, ULONG *, ULONG *);

static UINT    my_packet_process_9_27(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_9_27_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    my_tcp_packet_receive_9_27_02(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_9_27_application_define(void *first_unused_memory)
#endif
{

CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    syn_counter = 0;
    rst_counter = 0;
    syn_flag = 0;

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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
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
ULONG      actual_status;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 9.27 Test........................................");

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
        error_counter++;
        return;
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

    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_9_27_01;

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_NO_WAIT);

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    if(server_socket.nx_tcp_socket_state != NX_TCP_CLOSED)
        error_counter++;

    /* Unaccept the server socket.  */
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

UINT    status;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
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

    /* Deal rst with my routing.  */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive_9_27_02;
    advanced_packet_process_callback = my_packet_process_9_27;

    /* Attempt to connect the socket.  */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Disconnect the socket.  */
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

    /* Return error.  */
    if(error_counter || (syn_counter != 1) || (rst_counter != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    /* Return success.  */
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}


static UINT    my_packet_process_9_27(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

NX_TCP_HEADER  *tcp_header_ptr;
ULONG           checksum;

#if defined(__PRODUCT_NETXDUO__)
ULONG           *source_ip, *dest_ip;
#else
ULONG           source_ip, dest_ip;
#endif

    if (packet_ptr -> nx_packet_length < 40)
        return NX_TRUE;

    tcp_header_ptr = (NX_TCP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT))
    {
        syn_flag = 1;

        /* Clean the ACK bit.  */
        tcp_header_ptr -> nx_tcp_header_word_3 = tcp_header_ptr -> nx_tcp_header_word_3 & 0xFFEFFFFF;

        /* Set the SYN bit.  */
        tcp_header_ptr -> nx_tcp_header_word_3 = tcp_header_ptr -> nx_tcp_header_word_3 | NX_TCP_SYN_BIT;

        /*SYN occupy a squence number*/
        client_socket.nx_tcp_socket_tx_sequence ++;

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

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
        source_ip = &ip_1.nx_ip_interface[TEST_INTERFACE].nx_interface_ip_address;
        checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                           packet_ptr -> nx_packet_length,
                                           source_ip, dest_ip);
        checksum = ~checksum & NX_LOWER_16_MASK;
#else
        dest_ip = client_socket.nx_tcp_socket_connect_ip;
        source_ip = ip_1.nx_ip_address;
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
    else
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;
}


static void    my_tcp_packet_receive_9_27_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_TCP_HEADER   *tcp_header_ptr;

    if((server_socket.nx_tcp_socket_state == NX_TCP_SYN_RECEIVED) && (syn_flag == 1))
    {
        tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

        /* Check the packet is a SYN one.  */
        if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
        {
            syn_counter++;

            /* Deal packets with default routing.  */
            ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
        }

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    }

    /* Let server receives the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}

static void    my_tcp_packet_receive_9_27_02(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_TCP_HEADER   *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
    {
        rst_counter++;

        /* Deal packets with default routing.  */
        ip_1.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Let server receives the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
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
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_9_27_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 9.27 Test........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
