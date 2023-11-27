/* This NetX test concentrates on the TCP loopback operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;



/* Define the counters used in the demo application...  */

static ULONG                   thread_0_counter;
static ULONG                   thread_1_counter;
static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_loopback_test_application_define(void *first_unused_memory)
#endif
{
    
CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    thread_0_counter =  0;
    thread_1_counter =  0;
    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 4096);
    pointer = pointer + 4096;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable TCP processing for IP instance.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;


    tx_thread_relinquish();


    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Loopback Processing Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
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

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 13, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;
    
    /* Loop to send 1,000 packets.  */
    thread_0_counter =  0;
    while (thread_0_counter < 1000)
    {

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
        if ((thread_0_counter & 3) == 0)
        {

            /* Disable all interface capability. */
            nx_ip_interface_capability_set(&ip_0, 0, 0);
        }
        else if ((thread_0_counter & 3) == 1)
        {

            /* Enable all TX checksum capability. */
            nx_ip_interface_capability_set(&ip_0, 0, NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM | 
                                                     NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_UDP_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV4_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV6_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_IGMP_TX_CHECKSUM);
        }
        else if ((thread_0_counter & 3) == 2)
        {

            /* Enable all RX checksum capability. */
            nx_ip_interface_capability_set(&ip_0, 0, NX_INTERFACE_CAPABILITY_IPV4_RX_CHECKSUM | 
                                                     NX_INTERFACE_CAPABILITY_TCP_RX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_UDP_RX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV4_RX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV6_RX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_IGMP_RX_CHECKSUM);
        }
        else if ((thread_0_counter & 3) == 3)
        {

            /* Enable all checksum capability. */
            nx_ip_interface_capability_set(&ip_0, 0, NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM | 
                                                     NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_UDP_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV4_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV6_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_IGMP_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_IPV4_RX_CHECKSUM | 
                                                     NX_INTERFACE_CAPABILITY_TCP_RX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_UDP_RX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV4_RX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV6_RX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_IGMP_RX_CHECKSUM);
        }
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

        /* Increment thread 0's counter.  */
        thread_0_counter++;
    
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
        status =  nx_tcp_socket_send(&client_socket, my_packet, 2 * NX_IP_PERIODIC_RATE);

        /* Determine if the status is valid.  */
        if (status)
        {
            error_counter++;
            nx_packet_release(my_packet);
        }
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

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Determine how to report error.  */
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
NX_PACKET       *packet_ptr;
ULONG           actual_status;
ULONG           expected_length = 0;


    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        error_counter++;
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                NX_NULL, thread_1_disconnect_received);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, thread_1_connect_received);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Loop to create and establish server connections.  */
    thread_1_counter =  0;
    while(thread_1_counter < 1000)
    {

        if(expected_length == 0)
        {

            /* Increment thread 1's counter.  */
            thread_1_counter++;
            expected_length = 28;
        }

        /* Receive a TCP message from the socket.  */
        status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
            error_counter++;
        else
        {

            expected_length -= packet_ptr -> nx_packet_length;

            /* Release the packet.  */
            nx_packet_release(packet_ptr);
        }
    }
        
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
    status =  nx_tcp_server_socket_relisten(&ip_0, 12, &server_socket);

    /* Check for error.  */
    if (status)
        error_counter++;
}


static void  thread_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if ((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}


static void  thread_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if (socket != &server_socket)
        error_counter++;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_loopback_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Loopback Processing Test..............................N/A\n"); 

    test_control_return(3);  
}      
#endif