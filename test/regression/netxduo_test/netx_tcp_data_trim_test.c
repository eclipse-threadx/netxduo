/* This NetX test concentrates on the TCP data trim operation.  */
/* Cover the code line 115-124 and line 136-146 for _nx_tcp_socket_state_trim();  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);
#if !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define DEMO_STACK_SIZE             2048
#define NX_PACKET_SIZE              (1536 + sizeof(NX_PACKET))
#define NX_PACKET_POOL_SIZE         (NX_PACKET_SIZE * 20)
#define NX_PACKET_SMALL_SIZE        (256 + sizeof(NX_PACKET))
#define NX_PACKET_POOL_SMALL_SIZE   (NX_PACKET_SMALL_SIZE * 20)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                ntest_0;
static TX_THREAD                ntest_1;
static NX_PACKET_POOL           pool_0;
static NX_PACKET_POOL           pool_1;
static NX_IP                    ip_0;
static NX_IP                    ip_1;
static NX_TCP_SOCKET            client_socket;
static NX_TCP_SOCKET            server_socket;
static UCHAR                    message[1000];
static ULONG                    data_counter;

/* Define the counters used in the test application...  */

static ULONG                    error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_data_trim_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    error_counter =  0;
    data_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool for IP instance 0.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NX_PACKET_SIZE, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    if (status)
        error_counter++;

    /* Create a packet pool for IP instance 1.  */
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
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

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;

    
    /* Let the other thread run first.  */
    tx_thread_relinquish();

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Data Trim Test........................................");

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
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

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

    tx_thread_relinquish();

    /* Check the window size.  */
    if ((client_socket.nx_tcp_socket_rx_window_current != 300) || (client_socket.nx_tcp_socket_tx_window_advertised != 300) ||
        (server_socket.nx_tcp_socket_rx_window_current != 300) || (server_socket.nx_tcp_socket_tx_window_advertised != 300))  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Reset the tx_window_advertised value to let client send large packet to server.  */
    client_socket.nx_tcp_socket_tx_window_advertised = 1000;

    /* Allocate the packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write data that is larger than window size.  */
    status = nx_packet_data_append(my_packet, message, 1000, &pool_0, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_relinquish();

    /* Check the data length. Server socket should trim the data if the data length is larger than the window.  */

    /* Determine if the test was successful.  */
    if ((data_counter != 300) || (error_counter))
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

UINT            status;
NX_PACKET       *packet_ptr;
ULONG           actual_status;


    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket with the window size 300(2 packets, one packet payload size is 256).  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                NX_NULL, ntest_1_disconnect_received);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, ntest_1_connect_received);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Receive the packet.  */
    status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }

    /* Record the received data counter.  */
    data_counter = packet_ptr -> nx_packet_length;

    /* Release the packet.  */
    nx_packet_release(packet_ptr);
}

static void  ntest_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if ((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void  ntest_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if (socket != &server_socket)
        error_counter++;
}

#else       
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_data_trim_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   TCP Data Trim Test........................................N/A\n");
    test_control_return(3);
}
#endif