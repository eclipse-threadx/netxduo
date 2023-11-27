/* This NetX test concentrates on TCP state change from FIN-WIAT1 to TIME-WAIT.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;



/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    tcp_packet_receive_catch_fin(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    tcp_packet_receive_drop_ack(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_fin_wait1_to_time_wait_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;
                                     
    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
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

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP FIN-WAIT1 to TIME-WAIT Test...........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                            NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1024,
                            NX_NULL, NX_NULL);
                            
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, NX_ANY_PORT, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Let server thread send FIN first. */
    tx_thread_suspend(&thread_0);

    /* Check the state of server socket. */
    if (server_socket.nx_tcp_socket_state != NX_TCP_FIN_WAIT_1)
        error_counter++;

    /* Disconnect this socket.  */
    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)
        error_counter++;

    /* Check the state of server socket. */
    if (server_socket.nx_tcp_socket_state != NX_TCP_TIMED_WAIT)
        error_counter++;

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if (status)
        error_counter++;
 
    /* Check status.  */
    if (error_counter) 
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

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                NX_NULL, thread_1_disconnect_received);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Sleep 1 second to make sure client thread is suspended. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Inject FIN packet. */
    ip_0.nx_ip_tcp_packet_receive = tcp_packet_receive_catch_fin;
    
    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;
}


static VOID    tcp_packet_receive_catch_fin(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER   *header_ptr;

    /* Point to TCP header  */
    header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Process FIN packet. */
    if (header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT)
    {

        /* Let client thread start to disconnect. */
        tx_thread_resume(&thread_0);
        ip_ptr -> nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

        /* Let server drop the ACK to prevent state FIN-WAIT2. */
        ip_1.nx_ip_tcp_packet_receive = tcp_packet_receive_drop_ack;
    }

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}


static void    tcp_packet_receive_drop_ack(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER   *header_ptr;

    /* Point to TCP header  */
    header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Process FIN packet. */
    if ((header_ptr -> nx_tcp_header_word_3 & NX_TCP_CONTROL_MASK) == NX_TCP_ACK_BIT)
    {

        /* Drop the ACK packet. . */
        nx_packet_release(packet_ptr);
        ip_ptr -> nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
        return;
    }

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}


static void  thread_1_disconnect_received(NX_TCP_SOCKET *socket)
{
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_fin_wait1_to_time_wait_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   TCP FIN-WAIT1 to TIME-WAIT Test...........................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_FRAGMENTATION  */
