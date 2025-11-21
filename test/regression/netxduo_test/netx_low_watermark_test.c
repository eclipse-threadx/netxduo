/* This NetX test concentrates on the basic TCP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(NX_ENABLE_LOW_WATERMARK) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048
#define     PACKET_SIZE             1536
#define     POOL_0_COUNT            20
#define     POOL_1_COUNT            10


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           tcp_client;
static NX_TCP_SOCKET           tcp_server;
static NX_UDP_SOCKET           udp_client;
static NX_UDP_SOCKET           udp_server;
static ULONG                   zero_window_received = 0;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define pool area. */
static UCHAR                   pool_area_0[POOL_0_COUNT * (sizeof(NX_PACKET) + PACKET_SIZE)];
static UCHAR                   pool_area_1[POOL_1_COUNT * (sizeof(NX_PACKET) + PACKET_SIZE)];


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    verify_tcp(UINT low_watermark, UINT receive_queue_maximum, 
                          UINT expected_packet_available,
                          UINT expected_receive_queue_count);
static void    verify_udp(UINT low_watermark, UINT receive_queue_maximum, 
                          UINT expected_packet_available,
                          UINT expected_receive_queue_count);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_low_watermark_test_application_define(void *first_unused_memory)
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

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create two packet pools.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pool_area_0, sizeof(pool_area_0));
    status +=  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", PACKET_SIZE, pool_area_1, sizeof(pool_area_1));

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

    /* Enable UDP processing for both IP instances.  */
    status +=  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        i, j;
UINT        max;

    /* Print out some test information banners.  */
    printf("NetX Test:   Low Watermark Test........................................");

    /* Setup driver callback. */
    advanced_packet_process_callback = packet_process;

    /* 1. Do not set low watermark or receive queue maximum. 
     * All packets in pool_1 should be queued in TCP socket.
     * */
    verify_tcp(0, POOL_1_COUNT, 0, POOL_1_COUNT);
    verify_udp(0, POOL_1_COUNT, 0, POOL_1_COUNT);

    /* 2. Set low watermark but do not set receive queue maximum. */
    for (i = 1; i < POOL_1_COUNT; i++)
    {
        verify_tcp(i, POOL_1_COUNT, i, POOL_1_COUNT - i);
        verify_udp(i, POOL_1_COUNT, i, POOL_1_COUNT - i);

        /* Check status. */
        if (error_counter)
        {
            break;
        }
    }

    /* 3. Do not set low watermark but set receive queue maximum. */
    for (i = 1; i < POOL_1_COUNT; i++)
    {
        verify_tcp(0, POOL_1_COUNT - i, i, POOL_1_COUNT - i);
        verify_udp(0, POOL_1_COUNT - i, i, POOL_1_COUNT - i);

        /* Check status. */
        if (error_counter)
        {
            break;
        }
    }

    /* 4. Set low watermark and receive queue maximum. */
    for (i = 1; i < POOL_1_COUNT; i++)
    {
        for (j = 1; j < POOL_1_COUNT; j++)
        {

            /* Get maximum limitation.  */
            if (i > j)
                max = i;
            else
                max = j;

            verify_tcp(i, POOL_1_COUNT - j, max, POOL_1_COUNT - max);
            verify_udp(i, POOL_1_COUNT - j, max, POOL_1_COUNT - max);

            /* Check status. */
            if (error_counter)
            {
                break;
            }
        }
    }

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


static void    verify_tcp(UINT low_watermark, UINT receive_queue_maximum, 
                          UINT expected_packet_available,
                          UINT expected_receive_queue_count)
{
UINT        status;
NX_PACKET   *send_packet;
NX_PACKET   *recv_packet;
UINT        i;
CHAR        ch;

    /* Create server socket.  */
    status =  nx_tcp_socket_create(&ip_1, &tcp_server, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                   NX_NULL, NX_NULL);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &tcp_server, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&tcp_server, NX_NO_WAIT);

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &tcp_client, "Client Socket", 
                            NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                            NX_NULL, NX_NULL);
                            
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&tcp_client, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&tcp_client, IP_ADDRESS(1, 2, 3, 5), 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Set low watermark and receive queue maximum. */
    nx_packet_pool_low_watermark_set(&pool_1, low_watermark);
    nx_tcp_socket_receive_queue_max_set(&tcp_server, receive_queue_maximum);
    zero_window_received = 0;
    for (i = 0; i < POOL_1_COUNT; i++)
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &send_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            break;
        }

        ch = 'A' + i;
        status = nx_packet_data_append(send_packet, &ch, 1, &pool_0, NX_NO_WAIT);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            break;
        }

        /* Send the packet out!  */
        status =  nx_tcp_socket_send(&tcp_client, send_packet, NX_NO_WAIT);

        /* Determine if the status is valid.  */
        if (status)
        {

            if (status != NX_WINDOW_OVERFLOW)
                error_counter++;
            nx_packet_release(send_packet);
            break;
        }
    }

    /* Check whether zero window has been sent. */
    if ((tcp_server.nx_tcp_socket_receive_queue_count != POOL_1_COUNT) &&
        (zero_window_received == 0))
    {
        error_counter++;
    }
    else if ((tcp_server.nx_tcp_socket_receive_queue_count == POOL_1_COUNT) &&
             (zero_window_received != 0))
    {
        error_counter++;
    }

    /* Verify packets in server's receive queue. */
    if (tcp_server.nx_tcp_socket_receive_queue_count != expected_receive_queue_count)
    {
        error_counter++;
    }

    /* Verify packets in server's pool. */
    if (pool_1.nx_packet_pool_available != expected_packet_available)
    {
        error_counter++;
    }

    /* Receive all packets. */
    for (i = tcp_server.nx_tcp_socket_receive_queue_count; i > 0; i--)
    {
        if (nx_tcp_socket_receive(&tcp_server, &recv_packet, NX_IP_PERIODIC_RATE) == NX_SUCCESS)
        {
            nx_packet_release(recv_packet);
        }
        else
        {
            error_counter++;
        }
    }

    /* Force close the connection. */
    nx_tcp_socket_disconnect(&tcp_client, NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&tcp_client);
    nx_tcp_socket_delete(&tcp_client);
    nx_tcp_socket_disconnect(&tcp_server, NX_NO_WAIT);
    nx_tcp_server_socket_unaccept(&tcp_server);
    nx_tcp_server_socket_unlisten(&ip_1, 12);
    nx_tcp_socket_delete(&tcp_server);
}


static void    verify_udp(UINT low_watermark, UINT receive_queue_maximum, 
                          UINT expected_packet_available,
                          UINT expected_receive_queue_count)
{
UINT        status;
NX_PACKET   *send_packet;
NX_PACKET   *recv_packet;
UINT        i;
CHAR        ch;

    /* Create server socket.  */
    status = nx_udp_socket_create(&ip_1, &udp_server, "Server Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, receive_queue_maximum);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind to port 12.  */
    status =  nx_udp_socket_bind(&udp_server, 12, TX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Create client socket.  */
    status = nx_udp_socket_create(&ip_0, &udp_client, "Client Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 20);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind to port 12.  */
    status =  nx_udp_socket_bind(&udp_client, 12, TX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Set low watermark and receive queue maximum. */
    nx_packet_pool_low_watermark_set(&pool_1, low_watermark);
    for (i = 0; i < POOL_1_COUNT; i++)
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &send_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            break;
        }

        ch = 'A' + i;
        status = nx_packet_data_append(send_packet, &ch, 1, &pool_0, NX_NO_WAIT);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            break;
        }

        /* Send the packet out!  */
        status = nx_udp_socket_send(&udp_client, send_packet, IP_ADDRESS(1, 2, 3, 5), 12);

        /* Determine if the status is valid.  */
        if (status)
        {

            error_counter++;
            nx_packet_release(send_packet);
            break;
        }
    }

    /* Verify packets in server's receive queue. */
    if (udp_server.nx_udp_socket_receive_count != expected_receive_queue_count)
    {
        error_counter++;
    }

    /* Verify packets in server's pool. */
    if (pool_1.nx_packet_pool_available != expected_packet_available)
    {
        error_counter++;
    }

    /* Receive all packets. */
    for (i = udp_server.nx_udp_socket_receive_count; i > 0; i--)
    {
        if (nx_udp_socket_receive(&udp_server, &recv_packet, NX_IP_PERIODIC_RATE) == NX_SUCCESS)
        {
            nx_packet_release(recv_packet);
        }
        else
        {
            error_counter++;
        }
    }

    /* Force close the connection. */
    nx_udp_socket_unbind(&udp_client);
    nx_udp_socket_delete(&udp_client);
    nx_udp_socket_unbind(&udp_server);
    nx_udp_socket_delete(&udp_server);
}


static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER *tcp_header_ptr;

    /* Skip packets that are not TCP. */
    if ((packet_ptr -> nx_packet_length < 40) || 
        (*(packet_ptr -> nx_packet_prepend_ptr + 9) != NX_PROTOCOL_TCP))
        return NX_TRUE;

    /* Get TCP header. */
    tcp_header_ptr = (NX_TCP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check window size. */
    if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_LOWER_16_MASK) == 0)
        zero_window_received++;

    /* Restore endian. */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_low_watermark_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Low Watermark Test........................................N/A\n");

    test_control_return(3);

}
#endif /* NX_ENABLE_LOW_WATERMARK */
