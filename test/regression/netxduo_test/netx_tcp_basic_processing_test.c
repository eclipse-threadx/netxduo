/* This NetX test concentrates on the basic TCP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
#ifdef __PRODUCT_NETXDUO__
static NX_PACKET_POOL          my_auxiliary_pool;
#endif
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;



/* Define the counters used in the demo application...  */

static ULONG                   thread_0_counter =  0;
static ULONG                   thread_1_counter =  0;
static ULONG                   error_counter =     0;
static ULONG                   connections =       0;
static ULONG                   disconnections =    0;
static ULONG                   client_receives =   0;
static ULONG                   server_receives =   0;
static UINT                    client_port;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);
static void    thread_0_receive_notify(NX_TCP_SOCKET *client_socket);
#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
static void    thread_0_establish_notify(NX_TCP_SOCKET *client_socket);
static void    thread_0_disconnect_complete_notify(NX_TCP_SOCKET *client_socket);
#endif
static void    thread_1_receive_notify(NX_TCP_SOCKET *server_socket);
#ifdef NX_ENABLE_EXTENDED_NOTIFY_SUPPORT
static void    timed_wait_notify(NX_TCP_SOCKET *client_socket);  
#endif
static void    window_update_notify(NX_TCP_SOCKET *client_socket);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_basic_processing_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    thread_0_counter =  0;
    thread_1_counter =  0;
    error_counter =     0;
    connections =       0;
    disconnections =    0;
    client_receives =   0;
    server_receives =   0;
    client_port =       0;

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
                                     
#ifdef __PRODUCT_NETXDUO__
    /* Create a auxiliary packet pool.  128*10 = 1280 */
    status =  nx_packet_pool_create(&my_auxiliary_pool, "NetX Auxiliary Packet Pool", 128, pointer, 1280);
    pointer = pointer + 1280;

    if (status)
        error_counter++;
#endif

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
                                     
#if defined(__PRODUCT_NETXDUO__) 

    /* Set the auxiliary packet pool for IP instance 0.  */
    status = nx_ip_auxiliary_packet_pool_set(&ip_0, &my_auxiliary_pool);

    /* Check the status.  */
#ifdef NX_ENABLE_DUAL_PACKET_POOL
    if(status != NX_SUCCESS)
        error_counter++;
#else    
    if(status != NX_NOT_SUPPORTED)
        error_counter++;
#endif
                             
    /* Set the auxiliary packet pool for IP instance 1.  */
    status = nx_ip_auxiliary_packet_pool_set(&ip_1, &my_auxiliary_pool);
    
    /* Check the status.  */
#ifdef NX_ENABLE_DUAL_PACKET_POOL
    if(status != NX_SUCCESS)
        error_counter++;
#else    
    if(status != NX_NOT_SUPPORTED)
        error_counter++;
#endif

#endif
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
UINT        compare_port;
ULONG       mss, peer_mss, peer_ip_address, peer_port, bytes_available;
ULONG       tcp_packets_sent, tcp_bytes_sent, tcp_packets_received, tcp_bytes_received, tcp_invalid_packets, tcp_receive_packets_dropped, tcp_checksum_errors, tcp_connections, tcp_disconnections, tcp_connections_dropped, tcp_retransmit_packets;
ULONG       packets_sent, bytes_sent, packets_received, bytes_received, retransmit_packets, packets_queued, checksum_errors, socket_state, transmit_queue_depth, transmit_window, receive_window;
ULONG       window_size = 200;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Basic Processing Test.................................");

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

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    window_size = 0xFFFFFF;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

    /* Loop to establish 1000 connections, send one message, and disconnect.   */
    while ((thread_0_counter < 1000) && (error_counter == 0))
    {

        /* Increment thread 0's counter.  */
        thread_0_counter++;

        /* Create a socket.  */
        status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, window_size,
                                NX_NULL, NX_NULL);
                                
        /* Check for error.  */
        if (status)
            error_counter++;

        /* Setup a receive notify function.  */
        status =  nx_tcp_socket_receive_notify(&client_socket, thread_0_receive_notify);

        /* Check for error.  */
        if (status)
            error_counter++;

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
        status =  nx_tcp_socket_establish_notify(&client_socket, thread_0_establish_notify);

        /* Check for error.  */
        if (status)
            error_counter++;

        status =  nx_tcp_socket_disconnect_complete_notify(&client_socket, thread_0_disconnect_complete_notify);

        /* Check for error.  */
        if (status)
            error_counter++;
#endif
      
#ifdef NX_ENABLE_EXTENDED_NOTIFY_SUPPORT
        /* Setup a receive notify function.  */
        status =  nx_tcp_socket_timed_wait_callback(&client_socket, timed_wait_notify);

        /* Check for error.  */
        if (status)
            error_counter++;
#endif
        
        /* Setup a receive notify function.  */
        status =  nx_tcp_socket_window_update_notify_set(&client_socket, window_update_notify);

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
                  
        /* Get information about peer socket before connection.  */
        status =  nx_tcp_socket_peer_info_get(&client_socket, &peer_ip_address, &peer_port);  

        /* The status should not be successful since the connection is not established. */
        if (status == NX_SUCCESS)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }


        status =  nx_tcp_socket_mss_set(&client_socket, 200);
        if(status)
            error_counter++;

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

        /* Get the socket mss.  */
        status =  nx_tcp_socket_mss_get(&client_socket, &mss);
        
        /* Check for error.  */
        if (status)
            error_counter++;     
                                    
        /* Set the socket mss.  */
        status =  nx_tcp_socket_mss_set(&client_socket, mss - 1);
        
        /* Check for error.  */
        if (status == NX_SUCCESS)
            error_counter++; 

        /* Get the peer socket mss.  */
        status =  nx_tcp_socket_mss_peer_get(&client_socket, &peer_mss);
        
        /* Check for error.  */
        if (status)
            error_counter++;  
        
        /* Get the socket bytes available.  */
        status =  nx_tcp_socket_bytes_available(&client_socket, &bytes_available);
        
        /* Check for error.  */
        if (status)
            error_counter++;   
                  
        /* Get information about peer socket.  */
        status =  nx_tcp_socket_peer_info_get(&client_socket, &peer_ip_address, &peer_port);  

        /* Check for errors.  */
        if ((status) || (peer_ip_address != IP_ADDRESS(1, 2, 3, 5)) || (peer_port != 12))     
            error_counter++;    
     
        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            break;

        /* Write ABCs into the packet payload!  */
        memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

        /* Adjust the write pointer.  */
        my_packet -> nx_packet_length =  28;
        my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

        /* Send the packet out!  */
        status =  nx_tcp_socket_send(&client_socket, my_packet, 5 * NX_IP_PERIODIC_RATE);

        /* Determine if the status is valid.  */
        if (status)
        {
            error_counter++;
            nx_packet_release(my_packet);
        }

        /* Disconnect this socket.  */
        status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);

        /* Determine if the status is valid.  */
        if (status)
            error_counter++;

        /* Unbind the socket.  */
        status =  nx_tcp_client_socket_unbind(&client_socket);

        /* Check for error.  */
        if (status)
            error_counter++;

        /* Get nothing from the socket.  */
        status =  nx_tcp_socket_info_get(&client_socket, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);

        /* Check for error.  */
        if (status)
            error_counter++;

        /* Get information about this socket.  */
        status =  nx_tcp_socket_info_get(&client_socket, &packets_sent, &bytes_sent, 
                            &packets_received, &bytes_received, 
                            &retransmit_packets, &packets_queued,
                            &checksum_errors, &socket_state,
                            &transmit_queue_depth, &transmit_window,
                            &receive_window);

#ifndef NX_DISABLE_TCP_INFO

        if((packets_sent != 1) || (bytes_sent != 28))
            error_counter++;
#endif

        /* Check for errors.  */
        if ((error_counter) || (status) || (packets_received) || (bytes_received) ||
            (retransmit_packets) || (packets_queued) || (checksum_errors) || (socket_state != NX_TCP_CLOSED) ||
            (transmit_queue_depth) || (transmit_window != 100) || (receive_window != window_size))
        {

            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Delete the socket.  */
        status =  nx_tcp_socket_delete(&client_socket);

        /* Check for error.  */
        if (status)
            error_counter++;
    }

    /* Get nothing from the overall TCP information.  */
    status =  nx_tcp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Get the overall TCP information.  */
    status =  nx_tcp_info_get(&ip_0, &tcp_packets_sent, &tcp_bytes_sent, &tcp_packets_received, &tcp_bytes_received,
                             &tcp_invalid_packets, &tcp_receive_packets_dropped, &tcp_checksum_errors, &tcp_connections, 
                             &tcp_disconnections, &tcp_connections_dropped, &tcp_retransmit_packets);

#ifndef NX_DISABLE_TCP_INFO
    if((tcp_packets_sent != 1000) || (tcp_bytes_sent != 1000*28) || (tcp_connections != 1000) || (tcp_disconnections != 2000))
        error_counter++;
#endif
 
    /* Check status.  */
    if ((error_counter) || (status) || (thread_0_counter != 1000) || (thread_1_counter != 1000) || (connections != 1000) || (disconnections) ||
        (tcp_packets_received) || (tcp_bytes_received) || (tcp_invalid_packets) ||(tcp_receive_packets_dropped) || (tcp_checksum_errors) || 
        (tcp_connections_dropped) || (tcp_retransmit_packets))
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
NX_PACKET       *packet_ptr;
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
    status =  nx_tcp_server_socket_accept(&server_socket, 0);

    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Loop to create and establish server connections.  */
    while((thread_1_counter < 1000) && (error_counter == 0))
    {

        /* Increment thread 1's counter.  */
        thread_1_counter++;

        /* Accept a client socket connection.  */
        status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
            error_counter++;

        /* Receive a TCP message from the socket.  */
        status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
            error_counter++;
        else
            /* Release the packet.  */
            nx_packet_release(packet_ptr);
        
        /* Disconnect the server socket.  */
        status =  nx_tcp_socket_disconnect(&server_socket, 5 * NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
            error_counter++;

        /* Unaccept the server socket.  */
        status =  nx_tcp_server_socket_unaccept(&server_socket);

        /* Check for error.  */
        if (status)
            error_counter++;

        /* Setup server socket for listening again.  */
        status =  nx_tcp_server_socket_relisten(&ip_1, 12, &server_socket);

        /* Check for error.  */
        if (status)
            error_counter++;
    }

    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);

    /* Check for error.  */
    if (status)
        error_counter++;
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

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
static void  thread_0_establish_notify(NX_TCP_SOCKET *client_socket)
{
    ;
}

static void thread_0_disconnect_complete_notify(NX_TCP_SOCKET *client_socket)
{
    ;
}
#endif

static void  thread_1_receive_notify(NX_TCP_SOCKET *server_socket)
{

    server_receives++;
}                                
          
#ifdef NX_ENABLE_EXTENDED_NOTIFY_SUPPORT
static void  timed_wait_notify(NX_TCP_SOCKET *client_socket)
{
}    
#endif

static void  window_update_notify(NX_TCP_SOCKET *client_socket)
{
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_basic_processing_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Basic Processing Test.................................N/A\n"); 

    test_control_return(3);  
}      
#endif
