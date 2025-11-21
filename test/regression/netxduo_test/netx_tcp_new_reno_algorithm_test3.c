/* This NetX test concentrates on fast retransmit.  */
    
/* Procedure:
1. Client connect with Server.
2. Client send three segments to Server.
3. Drop the 1th segments in the driver.
4. Server send two duplicate ACKs with acknowledgment number as the sequence number of 1th segment.
5. Client should retransmit the 1th when timeout.
6. Server receives the segment and check the segments data.
7. Disconnect.
8. Print the result.
*/

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"    
#include   "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048
#define     notify printf("line %d failed.\n", __LINE__)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

/* Define the messsage.  */
static CHAR                    msg[200];

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   packet_counter;
static ULONG                   ack_counter;
static ULONG                   client_tx_sequnce;
static ULONG                   start_ticks; 
static ULONG                   end_ticks;

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
void           netx_tcp_new_reno_algorithm_test3_application_define(void *first_unused_memory)
#endif
{

CHAR           *pointer;
UINT           status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    packet_counter = 0;
    ack_counter = 0;

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
    {
        notify;
        error_counter++;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
    {
        notify;
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if(status)
    {
        notify;
        error_counter++;
    }

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
    {
        notify;
        error_counter++;
    }
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT           status;
UINT           i;
NX_PACKET      *my_packet[3];

    /* Print out test information banner.  */
    printf("NetX Test:   TCP New Reno Algorithm Test3..............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        notify;
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
        notify;
        error_counter++;
    }

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
    {
        notify;
        error_counter++;
    }

    /* Attempt to connect the socket.  */
    tx_thread_relinquish();

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
    {
        notify;
        error_counter++;
    }
    
    /* Random genearte the data.  */
    for (i = 0; i < 200; i ++)
        msg[i] = (CHAR)rand();

    /* Create 3 packets.  */
    for (i = 0; i < 3; i ++)
    {   

        /* Allocate the packet.  */
        status += nx_packet_allocate(&pool_0, &my_packet[i], NX_TCP_PACKET, NX_NO_WAIT);

        /* Check the status.  */
        if(status)
        {
            notify;
            error_counter++;
        }

        /* Fill in the packet with data.  */
        memcpy(my_packet[i] -> nx_packet_prepend_ptr, &msg[i*20], 20);
        my_packet[i] -> nx_packet_length = 20;
        my_packet[i] -> nx_packet_append_ptr = my_packet[i] -> nx_packet_prepend_ptr + 20;
    }    
                        
    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = client_driver_packet_process;
    
    /* Deal the packet with my routing.  */
    ip_0.nx_ip_tcp_packet_receive = client_tcp_packet_receive;

    /* Record the client tx_sequence.  */
    client_tx_sequnce = client_socket.nx_tcp_socket_tx_sequence;
                         
    /* Loop to send packets.  */
    for (i = 0; i < 3; i ++)
    {

        /* Send the packet.  */
        status = nx_tcp_socket_send(&client_socket, my_packet[i], NX_NO_WAIT);

        /* Check the status.  */
        if(status)
        {
            notify;
            error_counter++;
        }
    }
             
    /* Sleep 2 seconds to let client retransmit the 1th segments and  server receive segments.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Check the duplicate ACKs.  */
    if (client_socket.nx_tcp_socket_duplicated_ack_received != 0) 
    {
        notify;
        error_counter++;
    }
        
    /* Check the socket fast recovery status.  */
    if (client_socket.nx_tcp_socket_fast_recovery != NX_FALSE)
    {
        notify;
        error_counter++;
    }

    /* Reset the callback functions.  */
    advanced_packet_process_callback = NX_NULL;
    ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

    /* Disconnect this socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
    {
        notify;
        error_counter++;
    }

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if(status)
    {
        notify;
        error_counter++;
    }

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
    {
        notify;
        error_counter++;
    }
}

static char    rcv_buffer[200];
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
        notify;
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
        notify;
        error_counter++;
    }

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if(status)
    {
        notify;
        error_counter++;
    }

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
    {
        notify;
        error_counter++;
    }

    /* Receive a TCP message from the socket.  */
    while (nx_tcp_socket_receive(&server_socket, &packet_ptr, 2 * NX_IP_PERIODIC_RATE) == NX_SUCCESS)
    {

        if(packet_ptr -> nx_packet_length == 0)
        {
            notify;
            error_counter++;
        }

        memcpy(&rcv_buffer[recv_length], packet_ptr -> nx_packet_prepend_ptr, packet_ptr -> nx_packet_length);
        recv_length += packet_ptr -> nx_packet_length;

        /* Release the packet.  */
        nx_packet_release(packet_ptr);
    }
           
    /* Check the data length.  */
    if(recv_length != 60)
    {
        notify;
        error_counter++;
    }

    /* Check the data.  */
    if(memcmp(rcv_buffer, msg, recv_length))
    {
        notify;
        error_counter++;
    }

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
    {
        notify;
        error_counter++;
    }

    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
    {
        notify;
        error_counter++;
    }

    tx_thread_relinquish();   

    /* Determine if the test was successful.  */
    if ((error_counter) || (packet_counter != 6) || (ack_counter < 3))
    {
        notify;
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

    /* Check the data length.  */
    if(packet_ptr -> nx_packet_length == 60)
    {

        /* Update the counter.  */
        packet_counter ++;

        /* Discard the 1th segment.  */
        if (packet_counter == 1)
        {    

            /* Discard the segments.  */
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }

        /* Check the sequence number.  */
        if (packet_counter == 1)
        {

            /* Should be 1th segment.  */
            if (tcp_header_ptr -> nx_tcp_sequence_number != client_tx_sequnce)
            {
                notify;
                error_counter++;
            }

            /* Get the time.  */
            start_ticks = tx_time_get();
        }        
        else if (packet_counter == 2)
        {

            /* Should be 2th segment.  */
            if (tcp_header_ptr -> nx_tcp_sequence_number != client_tx_sequnce + 20)
            {
                notify;
                error_counter ++;
            }
        }
        else if (packet_counter == 3)
        {

            /* Should be 3th segment.  */
            if (tcp_header_ptr -> nx_tcp_sequence_number != client_tx_sequnce + 40)
            {
                notify;
                error_counter ++;
            }
        }
        else if (packet_counter == 4)
        {
                                          
            /* Should be 1th segment retransmitted.  */
            if (tcp_header_ptr -> nx_tcp_sequence_number != client_tx_sequnce)
            {
                notify;
                error_counter ++;
            }

            /* Check the socket fast recovery status.  */
            if (client_socket.nx_tcp_socket_fast_recovery != NX_FALSE)
            {
                notify;
                error_counter ++;
            }
                
            /* Check the recover value.  */
            if (client_socket.nx_tcp_socket_tx_sequence_recover != client_tx_sequnce - 1 + 60)
            { 
                notify;
                error_counter ++;
            }

            /* Get the time.  */
            end_ticks = tx_time_get();
             
            /* Check the time interval, should be in NX_IP_PERIODIC_RATE - _nx_tcp_fast_timer_rate and NX_IP_PERIODIC_RATE.  */
            if (((end_ticks - start_ticks) < (NX_IP_PERIODIC_RATE - _nx_tcp_fast_timer_rate)) ||
                ((end_ticks - start_ticks) > NX_IP_PERIODIC_RATE))
            {
                notify;
                error_counter ++;
            }
        }
        
        else if (packet_counter == 5)
        {
                                          
            /* Should be 2th segment retransmitted.  */
            if (tcp_header_ptr -> nx_tcp_sequence_number != client_tx_sequnce + 20)
            {
                notify;
                error_counter ++;
            }

            /* Check the socket fast recovery status.  */
            if (client_socket.nx_tcp_socket_fast_recovery != NX_FALSE)
            {
                notify;
                error_counter ++;
            }
                
            /* Check the recover value.  */
            if (client_socket.nx_tcp_socket_tx_sequence_recover != client_tx_sequnce - 1 + 60)
            { 
                notify;
                error_counter ++;
            }

            /* Get the time.  */
            end_ticks = tx_time_get();
             
            /* Check the time interval, should be in NX_IP_PERIODIC_RATE - _nx_tcp_fast_timer_rate and NX_IP_PERIODIC_RATE.  */
            if (((end_ticks - start_ticks) < (NX_IP_PERIODIC_RATE - _nx_tcp_fast_timer_rate)) ||
                ((end_ticks - start_ticks) > NX_IP_PERIODIC_RATE))
            {
                notify;
                error_counter ++;
            }
        }
        
        else if (packet_counter == 6)
        {
                                          
            /* Should be 1th segment retransmitted.  */
            if (tcp_header_ptr -> nx_tcp_sequence_number != client_tx_sequnce + 40)
            {
                notify;
                error_counter ++;
            }

            /* Check the socket fast recovery status.  */
            if (client_socket.nx_tcp_socket_fast_recovery != NX_FALSE)
            {
                notify;
                error_counter ++;
            }
                
            /* Check the recover value.  */
            if (client_socket.nx_tcp_socket_tx_sequence_recover != client_tx_sequnce - 1 + 60)
            { 
                notify;
                error_counter ++;
            }

            /* Get the time.  */
            end_ticks = tx_time_get();

            /* Check the time interval, should be in NX_IP_PERIODIC_RATE - _nx_tcp_fast_timer_rate and NX_IP_PERIODIC_RATE.  */
            if (((end_ticks - start_ticks) < (NX_IP_PERIODIC_RATE - _nx_tcp_fast_timer_rate)) ||
                ((end_ticks - start_ticks) > NX_IP_PERIODIC_RATE))
            {
                notify;
                error_counter ++;
            }
        }
    }
    
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);

    return NX_TRUE;
}
  
static void    client_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
                    
NX_TCP_HEADER        *tcp_header_ptr;

    /* Set the header.  */
    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check if the packet is an ACK packet.  */
    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)
    {

        /* Update the counter.  */
        ack_counter++;

        /* This should be duplicate ACKs for 1th segment.  */
        if ((ack_counter == 1) || (ack_counter == 2))
        {

            /* Check the acknowledgment number.  */
            if (tcp_header_ptr -> nx_tcp_acknowledgment_number != client_tx_sequnce)
            {
                notify;
                error_counter ++;
            }

            /* Check the recover value.  */
            if (client_socket.nx_tcp_socket_tx_sequence_recover != client_tx_sequnce - 1)
            { 
                notify;
                error_counter ++;
            }

            /* Check the duplicate ACKs.  */
            if (client_socket.nx_tcp_socket_duplicated_ack_received != ack_counter - 1) 
            {
                notify;
                error_counter ++;
            }

            /* Check the socket fast recovery status.  */
            if (client_socket.nx_tcp_socket_fast_recovery != NX_FALSE)
            {
                notify;
                error_counter ++;
            }
        }       
        /* This should be normal ACK for 4th segment .  */
        else if (ack_counter == 3)
        {
              
            /* Check the acknowledgment number.  */
            if (tcp_header_ptr -> nx_tcp_acknowledgment_number != client_tx_sequnce + 60)
            {
                notify;
                error_counter ++;
            }

            /* Check the socket fast recovery status.  */
            if (client_socket.nx_tcp_socket_fast_recovery != NX_FALSE)
            {
                notify;
                error_counter ++;
            }
        }
        /* Other ACKs for window update when call nx_tcp_socket_receive API.  */
    }

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
} 
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_new_reno_algorithm_test3_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP New Reno Algorithm Test3..............................N/A\n"); 

    test_control_return(3);  
}      
#endif
