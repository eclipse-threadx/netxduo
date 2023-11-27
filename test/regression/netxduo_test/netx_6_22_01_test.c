/* 6.22.01 If RECEIVE call arrives in ESTABLISHED or FINWAIT-1 state, 
   TCP MUST reassemble queued incoming segments and return to the application.  */

/* Procedure
  1. Client connect with Server, then Client state is ESTABLISHED.
  2. Client call receive function, then judge the status.
  3. Client call disconnect, and delay a fin packet, then Client state is FIN-WAIT-1.
  4. Client call receive function, then check the status.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_tcp.h"
#include    "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);

#if defined(NX_DISABLE_RESET_DISCONNECT) && !defined(NX_DISABLE_IPV4)

#define DEMO_STACK_SIZE    2048

#define MSG_1              "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define MSG_2              "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

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
static ULONG                   fin_counter;
static ULONG                   data_packet_counter;

/* Define thread prototypes.  */
static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_6_22_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_6_22_01_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    fin_counter = 0;
    data_packet_counter = 0;

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

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

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
NX_PACKET  *rcv_packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 6.22.01 Test.....................................");

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

    /* Determine if the timeout error occurred.  */
    if((status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Call connect to send an SYN.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Check client state.  */
    if(client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) 
        error_counter++;

    /* Call socket receive.  */
    status = nx_tcp_socket_receive(&client_socket, &rcv_packet_ptr, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status != NX_SUCCESS)
        error_counter++;
    else
    {
        /* Check data length and payload */
        if((rcv_packet_ptr -> nx_packet_length == 20) && (!memcmp(rcv_packet_ptr -> nx_packet_prepend_ptr, MSG_1, 20)))
            data_packet_counter++;
        
        /* Release the packet.  */
        nx_packet_release(rcv_packet_ptr);
    }

    /* Let driver delay the FIN packet. */
    advanced_packet_process_callback = my_packet_process_6_22_01;

    status = nx_tcp_socket_disconnect(&client_socket, NX_NO_WAIT);

    /* Check client state.  */
    if(client_socket.nx_tcp_socket_state != NX_TCP_FIN_WAIT_1) 
        error_counter++;

    /* Call socket receive.  */
    status = nx_tcp_socket_receive(&client_socket, &rcv_packet_ptr, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status != NX_SUCCESS)
        error_counter++;
    else
    {
        /* Check data length and payload */
        if((rcv_packet_ptr -> nx_packet_length == 20) && (!memcmp(rcv_packet_ptr -> nx_packet_prepend_ptr, MSG_2, 20)))
            data_packet_counter++;
        
        /* Release the packet.  */
        nx_packet_release(rcv_packet_ptr);
    }

    tx_thread_resume(&ntest_1);
}

static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
NX_PACKET  *my_packet1;
NX_PACKET  *my_packet2;

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

    /* Create three packets.  */
    status = nx_packet_allocate(&pool_0, &my_packet1, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
    status += nx_packet_allocate(&pool_0, &my_packet2, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Fill in the packet with data.     */
    status = nx_packet_data_append(my_packet1, MSG_1, 20, &pool_0, NX_IP_PERIODIC_RATE);
    status += nx_packet_data_append(my_packet2, MSG_2, 20, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send the packet out!  */
    status = nx_tcp_socket_send(&server_socket, my_packet1, NX_IP_PERIODIC_RATE);
    status += nx_tcp_socket_send(&server_socket, my_packet2, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    tx_thread_suspend(&ntest_1);

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup server socket for listening again.  */
    status = nx_tcp_server_socket_unlisten(&ip_1, 12);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Return error.  */
    if(error_counter || (fin_counter != 1) || (data_packet_counter != 2))
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

static UINT    my_packet_process_6_22_01(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER    *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check if it is a FIN packet.  */
    if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT))
    {

        fin_counter++;

        /* Delay 1 seconds. */
        *operation_ptr = NX_RAMDRIVER_OP_DELAY;
        *delay_ptr = NX_IP_PERIODIC_RATE;

        /* FIN packet has been processed. */ 
        advanced_packet_process_callback = NX_NULL;
    }
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_6_22_01_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 6.22.01 Test.....................................N/A\n");
    test_control_return(3);

}
#endif
