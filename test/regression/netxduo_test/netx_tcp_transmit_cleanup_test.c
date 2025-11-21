/* This NetX test concentrates on the basic TCP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static TX_THREAD               thread_2;   
static TX_THREAD               thread_3;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;



/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;
static ULONG                   connections =       0;
static ULONG                   client_receives =   0;
static ULONG                   server_receives =   0;
static UINT                    client_port;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);  
static void    thread_2_entry(ULONG thread_input);
static void    thread_3_entry(ULONG thread_input);
static void    thread_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);

static void    thread_0_receive_notify(NX_TCP_SOCKET *client_socket);
static void    thread_1_receive_notify(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_transmit_cleanup_test_application_define(void *first_unused_memory)
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
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);

    pointer =  pointer + DEMO_STACK_SIZE;
    
    /* Create the main thread.  */
    tx_thread_create(&thread_2, "thread 2", thread_2_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);

    pointer =  pointer + DEMO_STACK_SIZE;
                                                
    /* Create the main thread.  */
    tx_thread_create(&thread_3, "thread 3", thread_3_entry, 0,  
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
NX_PACKET   *my_packet;
UINT        compare_port;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Transmit Cleanup Test.................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get a free port for the client's use.  */
    status =  nx_tcp_free_port_find(&ip_0, 1, &client_port);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup a receive notify function.  */
    status =  nx_tcp_socket_receive_notify(&client_socket, thread_0_receive_notify);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, client_port, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Pickup the port for the client socket.  */
    status =  nx_tcp_client_socket_port_get(&client_socket, &compare_port);

    /* Check for error.  */
    if ((status) || (client_port != compare_port))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Wait for established state.  */
    status =  nx_tcp_socket_state_wait(&client_socket, NX_TCP_ESTABLISHED, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)     
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer. 220bytes.  */
    my_packet -> nx_packet_length =  220;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 220;
                                
    /* Check the TCP socket bind suspended count.  */
    if (client_socket.nx_tcp_socket_transmit_suspended_count != 0)       
        error_counter++;                                           

    /* Send the packet out, the window size of server socket is 100!  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, 2 * NX_IP_PERIODIC_RATE);
                                
    /* Check status.  */
    if (status != NX_WINDOW_OVERFLOW)
        error_counter++;
            
    /* Check the TCP socket bind suspended count.  */
    if (client_socket.nx_tcp_socket_transmit_suspended_count != 0)       
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

UINT        status;
NX_PACKET   *my_packet;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)     
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer. 220bytes.  */
    my_packet -> nx_packet_length =  220;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 220;
                                
    /* Check the TCP socket bind suspended count.  */
    if (client_socket.nx_tcp_socket_transmit_suspended_count != 1)       
        error_counter++;                                         

    /* Send the packet out, the window size of server socket is 100!  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);

#ifdef __PRODUCT_NETXDUO__
    /* Check status.  */
    if (status != NX_WINDOW_OVERFLOW)
        error_counter++;          
#else         
    if (status != NX_ALREADY_SUSPENDED)
        error_counter++;
#endif 

    /* Check the TCP socket transmit suspended count.  */
    if (client_socket.nx_tcp_socket_transmit_suspended_count != 1)       
        error_counter++;  
}        

static void    thread_2_entry(ULONG thread_input)
{

                                 
#ifdef __PRODUCT_NETXDUO__
    /* Check the TCP socket transmit suspended count.  */
    if (client_socket.nx_tcp_socket_transmit_suspended_count != 2)       
        error_counter++;    
#else                          
    if (client_socket.nx_tcp_socket_transmit_suspended_count != 1)       
        error_counter++;    
#endif
}

static void    thread_3_entry(ULONG thread_input)
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

    /* Create a socket(window size = 100).  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                NX_NULL, thread_1_disconnect_received);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup a receive notify function.  */
    status =  nx_tcp_socket_receive_notify(&server_socket, thread_1_receive_notify);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Configure the socket further.  */
    status =  nx_tcp_socket_transmit_configure(&server_socket, 10, 300, 10, 0);

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

    /* Check for error.  */
    if (status)
        error_counter++;          

    /* Resume the test thread.  */   
    tx_thread_resume(&thread_1);   
    tx_thread_resume(&thread_2);
}


static void  thread_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if ((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
    else
        connections++;
}


static void  thread_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if (socket != &server_socket)
        error_counter++;
}

static void  thread_0_receive_notify(NX_TCP_SOCKET *client_socket)
{

    client_receives++;
}


static void  thread_1_receive_notify(NX_TCP_SOCKET *server_socket)
{

    server_receives++;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_transmit_cleanup_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Transmit Cleanup Test.................................N/A\n"); 

    test_control_return(3);  
}      
#endif
