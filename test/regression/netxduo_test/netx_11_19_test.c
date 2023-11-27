/* 11.19 TCP, in ESTABLISHED state MUST inform the application in case of aborting from remote site.  */

/* Procedure
   1. Client connects to server.
   2. Client sends a RST packet to serve.
   3. Check if server is notified.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
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

static UINT                    is_notified;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    my_tcp_packet_receive_11_19(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_11_19_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
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

UINT       status;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, ntest_0_disconnect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Let client checks the packet.  */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_11_19;

    /* Attempt to connect the socket.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;
    
    if (is_notified == NX_FALSE)
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
}

static void    ntest_1_entry(ULONG thread_input)
{

UINT            status;
ULONG           actual_status;
NX_TCP_HEADER   header_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 11.19 Test.......................................");

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
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* If accept return successfully, then it handles an illegal option length for MSS.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    is_notified = NX_FALSE;

    /* Send RST.  */
    header_ptr.nx_tcp_header_word_3 = header_ptr.nx_tcp_header_word_3 | NX_TCP_ACK_BIT | NX_TCP_RST_BIT;

    /* Send a RST packet */
    header_ptr.nx_tcp_acknowledgment_number = client_socket.nx_tcp_socket_rx_sequence;
    header_ptr.nx_tcp_sequence_number       = client_socket.nx_tcp_socket_tx_sequence;
    _nx_tcp_packet_send_rst(&server_socket, &header_ptr);

    /* let ntest_0 to check*/
    tx_thread_sleep(1);
    
    status = nx_tcp_socket_disconnect(&server_socket,NX_IP_PERIODIC_RATE);


    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Return error.  */
    if((error_counter) || (rst_counter != 1) )
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

void    my_tcp_packet_receive_11_19(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_TCP_HEADER   *tcp_header_ptr;

    if(client_socket.nx_tcp_socket_state == NX_TCP_ESTABLISHED)
    {

        tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

        /* Check the packet is a RST one.  */
        if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
        {
            rst_counter++;

            /* Deal packets with default routing.  */
            ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
        }

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    }

    /* Let server receives the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}

static void    ntest_0_disconnect_received(NX_TCP_SOCKET *socket)
{
    /* Check for proper disconnected socket.  */
    if(socket != &client_socket)
        error_counter++;

    is_notified = NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_11_19_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 11.19 Test.......................................N/A\n"); 

    test_control_return(3);  
}      
#endif