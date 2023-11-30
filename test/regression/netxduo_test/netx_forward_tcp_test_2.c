/* This NetX test concentrates on the basic TCP operation with forward.  */

/* Test tcp function between IP_1 and Interface1 of IP_0.  */

                                               /*************/
                                               /*           */
                                               /*   IP_1    */
        /****************/                     /*  1.2.3.5  */
        /*    1.2.3.4   */                     /*************/
        /*  Interface0  */      
        /*              */
        /*    IP_0      */
        /*              */
        /*  Interface1  */
        /*   2.2.3.4    */                     /*************/
        /****************/                     /*           */
                                               /*   IP_2    */
                                               /*  2.2.3.5  */
                                               /*************/


#include   "tx_api.h"
#include   "nx_api.h"

#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_IP                   ip_2;
static NX_TCP_SOCKET           socket_0;
static NX_TCP_SOCKET           socket_1;



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
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_tcp_test_2_application_define(void *first_unused_memory)
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
    
    /* Create an forward IP Instance 0.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;    
    if (status)
        error_counter++;

    /* Set the second interface for forward IP Instance 0.  */
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_1500);    
    if (status)
        error_counter++;

    /* Create an IP Instance 1.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 1.  */
    status = nx_ip_gateway_address_set(&ip_1, IP_ADDRESS(1, 2, 3, 4));
    if (status)
        error_counter++;

    /* Create another IP Instance 2.  */
    status = nx_ip_create(&ip_2, "NetX IP Instance 1", IP_ADDRESS(2, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 2.  */
    status = nx_ip_gateway_address_set(&ip_2, IP_ADDRESS(2, 2, 3, 4));
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
    
    /* Enable ARP and supply ARP cache memory for IP Instance 2.  */
    status  =  nx_arp_enable(&ip_2, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
    
    /* Enable UDP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    status += nx_tcp_enable(&ip_2);
    
    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
    
    /* Enable the forwarding function for IP Instance 0.  */
    status = nx_ip_forwarding_enable(&ip_0);
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
UINT        free_port;
ULONG       packets_sent, bytes_sent, packets_received, bytes_received, retransmit_packets, packets_queued, checksum_errors, socket_state, transmit_queue_depth, transmit_window, receive_window;

    /* Print out some test information banners.  */
    printf("NetX Test:   Forward TCP Processing Test2..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &socket_1, "Socket 0", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
    
    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Get a free port for the client's use.  */
    status =  nx_tcp_free_port_find(&ip_1, 0x88, &free_port);
    
    /* Check status.  */
    if ((status) || (free_port != 0x88))
    {
        
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&socket_1, 0x88, NX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup the port for the client socket.  */
    status =  nx_tcp_client_socket_port_get(&socket_1, &free_port);

    /* Check for error.  */
    if ((status) || (free_port != 0x88))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&socket_1, IP_ADDRESS(2, 2, 3, 4), 0x89, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for established state.  */
    status =  nx_tcp_socket_state_wait(&socket_1, NX_TCP_ESTABLISHED, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&socket_1, my_packet, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check status.  */
    if (status)
    {
        nx_packet_release(my_packet);
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Disconnect this socket.  */
    status =  nx_tcp_socket_disconnect(&socket_1, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&socket_1);

    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get information about this socket.  */
    status =  nx_tcp_socket_info_get(&socket_1, &packets_sent, &bytes_sent, 
                                     &packets_received, &bytes_received, 
                                     &retransmit_packets, &packets_queued,
                                     &checksum_errors, &socket_state,
                                     &transmit_queue_depth, &transmit_window,
                                     &receive_window);

#ifndef NX_DISABLE_TCP_INFO

    if((packets_sent != 1) || (bytes_sent != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Check for errors.  */
    if ((error_counter) || (status) || (packets_received) || (bytes_received) ||
        (retransmit_packets) || (packets_queued) || (checksum_errors) || (socket_state != NX_TCP_CLOSED) ||
        (transmit_queue_depth) || (transmit_window != 100) || (receive_window != 200))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&socket_1);

    /* Check for error.  */
    if (status)
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
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    
    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &socket_0, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                  NX_NULL, NX_NULL);                                

    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_0, 0x89, &socket_0, 5, NX_NULL);
    
    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&socket_0, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive a TCP message from the socket.  */
    status =  nx_tcp_socket_receive(&socket_0, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        /* Release the packet.  */
        nx_packet_release(packet_ptr);
    }

    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&socket_0, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&socket_0);
    
    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_0, 0x89);
    
    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&socket_0);
    
    /* Check for error.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
}
#else

extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_tcp_test_2_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Forward TCP Processing Test2..............................N/A\n");
    test_control_return(3);
}
#endif
