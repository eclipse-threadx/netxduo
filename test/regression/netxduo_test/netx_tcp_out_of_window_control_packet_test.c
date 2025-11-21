/* This NetX test concentrates on processing out of window RST, URG, ACK packet when receive window is zero.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048
#define     WINDOW_SIZE             128


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static CHAR                    send_buff[WINDOW_SIZE];



/* Define the counters used in the demo application...  */

static ULONG                   error_counter = 0;
static ULONG                   ack_received = 0;
static ULONG                   urg_received = 0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr); 
static VOID    tcp_urgent_data_callback(NX_TCP_SOCKET *socket_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_out_of_window_control_packet_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

                     
    error_counter = 0;
    ack_received = 0;
    urg_received = 0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;   

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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
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
NX_PACKET  *my_packet;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Out of Window Control Packet Test.....................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, WINDOW_SIZE,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_NO_WAIT);

    /* Check for error.  */  
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                   

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write send_buff into the packet payload!  */
    status = nx_packet_data_append(my_packet, send_buff, WINDOW_SIZE, &pool_0, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }

    /* Sleep one second to make sure server has replied ACK. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Setup the TCP packet process function pointer. */
    ip_0.nx_ip_tcp_packet_receive = tcp_packet_receive;

    /* Send out of window URG packet. */
    _nx_tcp_packet_send_control(&client_socket, NX_TCP_URG_BIT, client_socket.nx_tcp_socket_tx_sequence + WINDOW_SIZE, 
                                client_socket.nx_tcp_socket_rx_sequence, 0, 0, NX_NULL);

    /* Sleep one second. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Make sure server is still in established state. */
    if (server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send out of window ACK packet. */
    _nx_tcp_packet_send_control(&client_socket, NX_TCP_ACK_BIT, client_socket.nx_tcp_socket_tx_sequence + WINDOW_SIZE, 
                                client_socket.nx_tcp_socket_rx_sequence, 0, 0, NX_NULL);

    /* Sleep one second. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Make sure server is still in established state. */
    if (server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send out of window RST packet. */
    _nx_tcp_packet_send_control(&client_socket, NX_TCP_RST_BIT, client_socket.nx_tcp_socket_tx_sequence + WINDOW_SIZE, 
                                client_socket.nx_tcp_socket_rx_sequence, 0, 0, NX_NULL);

    /* Sleep one second. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Make sure server is closed. */
    if (server_socket.nx_tcp_socket_state != NX_TCP_LISTEN_STATE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
 
    /* Check status.  */
    if (error_counter || ack_received || (urg_received != 0))
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
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, WINDOW_SIZE,
                                tcp_urgent_data_callback, NX_NULL);
                                
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
}


static VOID    tcp_urgent_data_callback(NX_TCP_SOCKET *socket_ptr)
{
    urg_received++;
}


static VOID    tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER  *tcp_header_ptr;

    /* Get TCP header. */
    tcp_header_ptr =  (NX_TCP_HEADER *) packet_ptr -> nx_packet_prepend_ptr;

    /* Swap word 3. */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Whether it is an ACK packet. */
    if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)
    {
        ack_received++;
    }

    /* Swap word 3. */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_out_of_window_control_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Out of Window Control Packet Test.....................N/A\n");

    test_control_return(3);  
}      
#endif
