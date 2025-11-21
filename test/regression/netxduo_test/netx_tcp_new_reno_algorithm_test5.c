/* This NetX test concentrates on fast retransmit.  */
    
/* Procedure:
1. Client connect with Server. The sequence number of client is modified to the edge of 32 bit number. 
2. Client send five segments to Server.
3. Drop the first segment in the driver.
4. Server send three duplicate ACKs with acknowledgment number as the sequence number of first segment.
5. Client fast retransmits the first segment.
6. Server receives the segment and check the segments data.
7. Disconnect.
8. Print the result.
*/

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ip.h"
#include   "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
                                               
/* Define the messsage.  */
static CHAR                    msg[3000];

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   window_size;
static NX_PACKET              *drop_packet;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req); 
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    client_driver_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_new_reno_algorithm_test5_application_define(void *first_unused_memory)
#endif
{

CHAR           *pointer;
UINT           status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    window_size = 0;
    drop_packet = NX_NULL;

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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

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
UINT           i;
UINT           old_threshold;
NX_PACKET      *my_packet[5];

    /* Print out test information banner.  */
    printf("NetX Test:   TCP New Reno Algorithm Test5..............................");

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
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Attempt to connect the socket.  */
    tx_thread_relinquish();

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;
                    
    /* Random genearte the data.  */
    for (i = 0; i < sizeof(msg); i ++)
        msg[i] = (CHAR)rand();

    /* Record the window size of server.  */
    window_size = client_socket.nx_tcp_socket_tx_window_advertised;
    
    /* Create 5 packets.  */
    for (i = 0; i < 5; i ++)
    {   

        /* Allocate the packet.  */
        status += nx_packet_allocate(&pool_0, &my_packet[i], NX_TCP_PACKET, NX_NO_WAIT);

        /* Check the status.  */
        if(status)
            error_counter++;

        /* Fill in the packet with data.  */
        memcpy(my_packet[i] -> nx_packet_prepend_ptr, &msg[i*(window_size>>2)], (window_size>>2));
        my_packet[i] -> nx_packet_length = (window_size>>2);
        my_packet[i] -> nx_packet_append_ptr = my_packet[i] -> nx_packet_prepend_ptr + (window_size>>2);
    }

    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = client_driver_packet_process;
    drop_packet = my_packet[0];

    /* Disable preemption. */
    tx_thread_preemption_change(&thread_0, 0, &old_threshold);
                        
    /* Loop to send packets.  */
    for (i = 0; i < 5; i ++)
    {
                                    
        /* Send the packet.  */
        status = nx_tcp_socket_send(&client_socket, my_packet[i], NX_IP_PERIODIC_RATE);

        /* Check the status.  */
        if(status)
        {
            error_counter++;
        }
    }

    /* Restore preemption. */
    tx_thread_preemption_change(&thread_0, old_threshold, &old_threshold);

    /* Disconnect this socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
    {
        error_counter++;
    }

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

static char    rcv_buffer[3000];
static void    thread_1_entry(ULONG thread_input)
{
    UINT           status;
    NX_PACKET      *packet_ptr;
    ULONG          actual_status;
    ULONG          recv_length = 0;

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
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Receive a TCP message from the socket.  */
    while (nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_IP_PERIODIC_RATE) == NX_SUCCESS)
    {

        if(packet_ptr -> nx_packet_length == 0)
            error_counter++;

        memcpy(&rcv_buffer[recv_length], packet_ptr -> nx_packet_prepend_ptr, packet_ptr -> nx_packet_length);
        recv_length += packet_ptr -> nx_packet_length;

        /* Release the packet.  */
        nx_packet_release(packet_ptr);
    }
           
    /* Check the data length.  */
    if(recv_length != (window_size + (window_size>>2)))
        error_counter++;

    /* Check the data.  */
    if(memcmp(rcv_buffer, msg, recv_length))
        error_counter++;

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    tx_thread_relinquish();   

    /* Determine if the test was successful.  */
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
    
static UINT    client_driver_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
    if (packet_ptr == drop_packet)
    {

        /* Drop the packet. */
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
        drop_packet = NX_NULL;
    }

    return NX_TRUE;
}
  
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_new_reno_algorithm_test5_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP New Reno Algorithm Test5..............................N/A\n"); 

    test_control_return(3);  
}      
#endif
