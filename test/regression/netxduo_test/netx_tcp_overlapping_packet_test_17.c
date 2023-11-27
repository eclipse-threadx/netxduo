/* This NetX test concentrates on overlapping TCP data packets.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_PACKET_CHAIN) && !defined(NX_TCP_ACK_EVERY_N_PACKETS) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048
#define     MSG_LENGTH              1024

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
static ULONG                   long_msg[MSG_LENGTH >> 2];


extern ULONG    packet_gather;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_overlapping_packet_test_17_application_define(void *first_unused_memory)
#endif
{

    CHAR    *pointer;
    UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
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

UINT           status, i;
NX_PACKET     *my_packet1;
NX_PACKET     *my_packet2;
NX_PACKET     *my_packet3;
ULONG          seq1;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Overlapping Packet Test 17............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 3000,
                                   NX_NULL, NX_NULL);
    
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    tx_thread_relinquish();

    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;


    /* Create 4 packets */
    status = nx_packet_allocate(&pool_0, &my_packet1, NX_TCP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_allocate(&pool_0, &my_packet2, NX_TCP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_allocate(&pool_0, &my_packet3, NX_TCP_PACKET, NX_WAIT_FOREVER);

    if (status)
        error_counter++;

    /* Init long_msg.  */
    for (i = 1; i <= (MSG_LENGTH >> 2); i++)
    {
        long_msg[i - 1] = i;
    }

    /* Fill in the packet with data.      */
    /* The full message to send is: 0x0100000002000000......00010000 
                    Packet 1 sends: 0x0100000002000000......40000000
                    Packet 2 sends: 0xC1000000C2000000......00010000
                    Packet 3 sends: 0x0100000002000000......C0000000 */
    
    status = nx_packet_data_append(my_packet1, (VOID *)(&long_msg[0]), 0x100, &pool_0, TX_WAIT_FOREVER);
    status += nx_packet_data_append(my_packet2, (VOID *)(&long_msg[192]), 0x100, &pool_0, TX_WAIT_FOREVER);
    status += nx_packet_data_append(my_packet3, (VOID *)(&long_msg[0]), 0x300, &pool_0, TX_WAIT_FOREVER);

    if (status)
        error_counter++;

    /* Store tx_seq before sending packet1.  */
    seq1 = client_socket.nx_tcp_socket_tx_sequence;

    /* Send the 1st one */
    status = nx_tcp_socket_send(&client_socket, my_packet1, NX_IP_PERIODIC_RATE);

    /* Sleep 3 seconds to let remote send ACK.  */
    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);

    /* Set the tx_seq to seq1+0x300 to send packet2 that is out of order.  */
    client_socket.nx_tcp_socket_tx_sequence = seq1 + 0x300;
    status += nx_tcp_socket_send(&client_socket, my_packet2, NX_IP_PERIODIC_RATE);

    /* Set the tx_seq to seq1 to send packet3.  */
    client_socket.nx_tcp_socket_tx_sequence = seq1;
    status += nx_tcp_socket_send(&client_socket, my_packet3, NX_IP_PERIODIC_RATE);

    /* Set the tx_seq to seq1+0x0400 to fix tx_seq.  */
    client_socket.nx_tcp_socket_tx_sequence = seq1 + 0x0400;

    if (status)
    {
        error_counter++;
    }
}

static char rcv_buffer[MSG_LENGTH];
static void    thread_1_entry(ULONG thread_input)
{

UINT           status;
ULONG          actual_status;
NX_PACKET     *packet_ptr;
ULONG          recv_length = 0;
ULONG          total_length = 0;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        error_counter++;
        test_control_return(2);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 2000,
                                   NX_NULL, thread_1_disconnect_received);
                                
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

    /* Receive a TCP message from the socket.  */
    while(1)
    {
        status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
            break;
        else
        {
            status =  nx_packet_data_retrieve(packet_ptr, &rcv_buffer[total_length], &recv_length);
            total_length += recv_length;

            /* Release the packet.  */
            nx_packet_release(packet_ptr);
        }
    }

    if(total_length != MSG_LENGTH)
        error_counter++;

    if(memcmp(rcv_buffer, (void*)long_msg, total_length))
        error_counter++;

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
void    netx_tcp_overlapping_packet_test_17_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Overlapping Packet Test 17............................N/A\n");

    test_control_return(3);

}

#endif

