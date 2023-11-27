/* This NetX test concentrates on the basic TCP operation.  */
/* Test Process:
Step1. Let IP1(Server Socket) is on listen mode.
step2. Client Socket send SYN packet to IP1, IP1 queue the SYN packet on listen queue.
Step3. Client Socket send RST packet to IP1
Step4. Check if SYN and RST packet both are released.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           client_socket_2;
static NX_TCP_SOCKET           server_socket;



/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_listen_packet_leak_test_application_define(void *first_unused_memory)
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
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
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

UINT            status;
NX_TCP_HEADER   tcp_header;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Listen Packet Leak Test...............................");

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
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_NO_WAIT);

    /* Check status.  */
    if (status == NX_SUCCESS)
        error_counter++;

    /* Check if queue the SYN packet.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_queue_current != 1)
        error_counter++;

    /* Build TCP header.  */
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;

    /* Send the RST packet. We just want to create a fake header, so assume this packet is incoming packet.  */
    tcp_header.nx_tcp_acknowledgment_number =  client_socket.nx_tcp_socket_tx_sequence;
    tcp_header.nx_tcp_sequence_number = client_socket.nx_tcp_socket_rx_sequence;

    /* Send RST.  */
    _nx_tcp_packet_send_rst(&client_socket, &tcp_header);

    /* Check if the SYN and RST both are released.  */
    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total)
    {
        error_counter++;
    }

    /* Check the queue count.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_queue_current != 0)
        error_counter++;

    /* Disconnect the socket.  */
    status =  nx_tcp_socket_disconnect(&client_socket, NX_NO_WAIT);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);
    if (status)
        error_counter++;


    /* Test multiple SYN packet with different source port.  */
    /* Create a socket 2.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket_2, "Client Socket 2", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket_2, 0x90, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket_2, IP_ADDRESS(1, 2, 3, 5), 12, NX_NO_WAIT);

    /* Check status.  */
    if (status == NX_SUCCESS)
        error_counter++;

    /* Check if queue the SYN packet.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_queue_current != 1)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_NO_WAIT);

    /* Check status.  */
    if (status == NX_SUCCESS)
        error_counter++;

    /* Check if queue the SYN packet.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_queue_current != 2)
        error_counter++;

    /* Build TCP header.  */
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;

    /* Send the RST packet. We just want to create a fake header, so assume this packet is incoming packet.  */
    tcp_header.nx_tcp_acknowledgment_number =  client_socket.nx_tcp_socket_tx_sequence;
    tcp_header.nx_tcp_sequence_number = client_socket.nx_tcp_socket_rx_sequence;

    /* Send RST to reset the second SYN.  */
    _nx_tcp_packet_send_rst(&client_socket, &tcp_header);

    /* Check if the second SYN and the third RST both are released.  */
    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total - 1)
    {
        error_counter++;
    }

    /* Check the queue count.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_queue_current != 1)
        error_counter++;

    /* Build TCP header.  */
    tcp_header.nx_tcp_header_word_3 = NX_TCP_ACK_BIT;

    /* Send the RST packet. We just want to create a fake header, so assume this packet is incoming packet.  */
    tcp_header.nx_tcp_acknowledgment_number =  client_socket_2.nx_tcp_socket_tx_sequence;
    tcp_header.nx_tcp_sequence_number = client_socket_2.nx_tcp_socket_rx_sequence;

    /* Send RST to reset the first SYN.  */
    _nx_tcp_packet_send_rst(&client_socket_2, &tcp_header);

    /* Check if the first SYN and RST both are released.  */
    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total)
    {
        error_counter++;
    }

    /* Check the queue count.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_queue_current != 0)
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

UINT            status;
ULONG           actual_status;


    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);
    if (status)
        error_counter++;

    /* Unaccept the server socket to let IP1 on listen mode.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check status.  */
    if(status)
        error_counter++;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_listen_packet_leak_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Listen Packet Leak Test...............................N/A\n"); 

    test_control_return(3);  
}      
#endif
