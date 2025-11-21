/* This case verifies bug reported by work item #2252. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048
#define     WINDOW_SIZE             200


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static UCHAR                   send_buff[WINDOW_SIZE << 1];
static UCHAR                   recv_buff[WINDOW_SIZE << 1];
static UCHAR                   zero_window_probe = NX_FALSE;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter = 0;
static ULONG                   client_packet_counter = 0;
static ULONG                   server_packet_counter = 0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    client_driver_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_zero_window_probe_test_3_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;

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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 512, pointer, 8192);
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
NX_PACKET  *my_packet;
UINT        i;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Zero Window Probe Test 3..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Generate the data for send_buff.  */
    for (i = 0; i < sizeof(send_buff); i++)
    {
        send_buff[i] = i & 0xFF;
        recv_buff[i] = 0;
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                            NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, WINDOW_SIZE,
                            NX_NULL, NX_NULL);
                            
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Establish the connection.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;
                  
    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = client_driver_packet_process;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write send_buff into the packet payload!  */
    status = nx_packet_data_append(my_packet, send_buff, WINDOW_SIZE, &pool_0, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }

                
    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write send_buff into the packet payload!  */
    status = nx_packet_data_append(my_packet, send_buff + WINDOW_SIZE, WINDOW_SIZE, &pool_0, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE * 5);

    /* Determine if the status is valid.  */
    if (status)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }
}
    

static void    thread_1_entry(ULONG thread_input)
{

UINT status;
NX_PACKET *packet_ptr;
UINT total = 0;
ULONG bytes_copied;

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, WINDOW_SIZE,
                                NX_NULL, NX_NULL);
    
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Sleep three seconds. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE * 3);

    /* Receive all data. */
    while (nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_IP_PERIODIC_RATE) == NX_SUCCESS)
    {

        /* Retrieve data. */
        nx_packet_data_retrieve(packet_ptr, recv_buff + total, &bytes_copied);
        total += bytes_copied;

        /* Release the packet.  */
        nx_packet_release(packet_ptr);
    }

    if (total != sizeof(send_buff))
    {
        error_counter++;
    }
    else if (memcmp(send_buff, recv_buff, total) != 0)
    {
        error_counter++;
    }

    /* Check status.  */
    if ((error_counter) || (zero_window_probe == NX_FALSE) || (client_packet_counter != 4)
#ifndef NX_ENABLE_TCP_KEEPALIVE
        || (server_packet_counter != 7)
#endif
        )
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

//#define TEST_INFO

static UINT    client_driver_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
#ifdef TEST_INFO
NX_TCP_HEADER *header_ptr;
ULONG seq_number, ack_number, window_size;

    /* Get TCP header. */
#ifdef FEATURE_NX_IPV6
    header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 40);
#else
    header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);
#endif

    /* Get window size and ACK number. */
    seq_number = header_ptr -> nx_tcp_sequence_number;
    ack_number = header_ptr -> nx_tcp_acknowledgment_number;
    window_size = header_ptr -> nx_tcp_header_word_3;
    NX_CHANGE_ULONG_ENDIAN(seq_number);
    NX_CHANGE_ULONG_ENDIAN(ack_number);
    NX_CHANGE_ULONG_ENDIAN(window_size);
    window_size = window_size & NX_LOWER_16_MASK;
#endif

    /* Ignore the server packet.  */
    if (ip_ptr != &ip_0)
    {

        server_packet_counter++;
#ifdef TEST_INFO
        printf("\nserver %d seq: %d, ack: %d, window: %d, length: %d\n", server_packet_counter, seq_number, ack_number, window_size, packet_ptr -> nx_packet_length);
#endif
        return NX_TRUE;
    }

    /* Update the packet counter.  */
    client_packet_counter++;
#ifdef TEST_INFO
    printf("\nclient %d seq: %d, ack: %d, window: %d, length: %d", client_packet_counter, seq_number, ack_number, window_size, packet_ptr -> nx_packet_length);
#endif

    /* Check the packet information.  */
    if (client_packet_counter == 1)
    {

        /* Check the packet length.  */
        if (packet_ptr -> nx_packet_length != (WINDOW_SIZE + 40))
            error_counter ++;
    }
    
    /* Check the packet information.  */
    else if (client_packet_counter == 2)
    {

        /* Check the packet length.  */
        if ((packet_ptr -> nx_packet_length == (1 + 40)) &&
            (*(packet_ptr -> nx_packet_append_ptr - 1) == send_buff[WINDOW_SIZE]))
        {

            zero_window_probe = NX_TRUE;

            /* Increase the receive window by one byte. */
            server_socket.nx_tcp_socket_rx_window_current += WINDOW_SIZE;
        }
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_zero_window_probe_test_3_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Zero Window Probe Test 3..............................N/A\n");

    test_control_return(3);  
}      
#endif
