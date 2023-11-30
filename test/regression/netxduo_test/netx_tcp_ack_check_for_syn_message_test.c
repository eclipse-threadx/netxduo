/* This NetX test concentrates on fast retransmit.  */
    
/* Procedure:
1. Client connect with Server.
2. Check the socket state.
3. Modify client socket state to unbind the client socket.
4. Check the socket state.
5. Set the callback function to check the TCP message.
6. Bind the client socket again.
7. Call nx_tcp_client_socket_connect to send SYN messsage.
8. Modify the server rx_sequence to let the SYN sequence number in server socket window in callback function.
9. Check if the server send the RST message.
*/

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"    
#include   "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);
                                
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter; 
static ULONG                   syn_counter;
static ULONG                   rst_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    client_driver_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr); 
static void    client_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_ack_check_for_syn_message_test_application_define(void *first_unused_memory)
#endif
{

CHAR           *pointer;
UINT           status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 512 * 30);
    pointer = pointer + 512 * 30;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
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

static void    thread_0_entry(ULONG thread_input)
{

UINT           status;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP ACK Check For SYN Message Test........................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, NX_NULL);
                            
    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);
                           
    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }
                             
    /* Let thread 1 run.  */
    tx_thread_relinquish();

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);
                              
    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }

    /* Check the socket state.  */
    if ((client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) ||
        (server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED))
    {
        error_counter++;
    }

    /* Modified the socket state as NX_TCP_TIMED_WAIT to unbind client socket.  */
    client_socket.nx_tcp_socket_state = NX_TCP_TIMED_WAIT;            

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }
       
    /* Check the socket state.  */
    if ((client_socket.nx_tcp_socket_state != NX_TCP_CLOSED) ||
        (server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED))
    {
        error_counter++;
    }
                                                               
    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = client_driver_packet_process;
    
    /* Deal the packet with my routing.  */
    ip_0.nx_ip_tcp_packet_receive = client_tcp_packet_receive; 
                                 
    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }

    /* Call connection.  */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status == NX_SUCCESS)
    {
        error_counter++;
    }
       
    /* Check the socket state.  */
    if ((client_socket.nx_tcp_socket_state != NX_TCP_CLOSED) ||
        (server_socket.nx_tcp_socket_state != NX_TCP_LISTEN_STATE))
    {
        error_counter++;
    }

    /* Reset the callback functions.  */
    advanced_packet_process_callback = NX_NULL;
    ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }
}

static void    thread_1_entry(ULONG thread_input)
{

UINT           status;
ULONG          actual_status;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status != NX_SUCCESS)
    {
        error_counter++;
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                  NX_NULL, NX_NULL);
                           
    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);
                         
    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);
                           
    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }
        
    /* Let thread 0 run.  */
    tx_thread_relinquish();

    /* Determine if the test was successful.  */
    if ((error_counter) || (syn_counter != 1) || (rst_counter != 1))
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
          
static UINT    client_driver_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
                                 
NX_TCP_HEADER        *tcp_header_ptr;

    /* Ingore the server packet.  */
    if (ip_ptr != &ip_0)
        return NX_TRUE;

    /* Set the header.  */
    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
                                                                    
    /* Check if the packet is an SYN packet.  */
    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
    {

        /* Update the counter.  */
        syn_counter++;    

        /* Modified the server rx_sequence to let the SYN sequence number in server socket window.  */
        server_socket.nx_tcp_socket_rx_sequence = tcp_header_ptr -> nx_tcp_sequence_number - 1;
    }

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;
}

static void    client_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
                    
NX_TCP_HEADER        *tcp_header_ptr;

    /* Set the header.  */
    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check if the packet is an RST packet.  */
    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
    {

        /* Update the counter.  */
        rst_counter++;    
    }

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
} 
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_ack_check_for_syn_message_test_application_define(void *first_unused_memory)
#endif
{                        

    /* Print out test information banner.  */
    printf("NetX Test:   TCP ACK Check For SYN Message Test........................N/A\n");
    
    test_control_return(3);
}
#endif