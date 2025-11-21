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
#define     SERVER_IP_ADDRESS       IP_ADDRESS(1, 2, 3, 99)
#define     CLIENT_IP_ADDRESS       IP_ADDRESS(1, 2, 3, 4)


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               client_thread;
static TX_THREAD               server_thread;

static NX_PACKET_POOL          client_pool;
static NX_PACKET_POOL          server_pool;
static NX_IP                   client_ip;
static NX_IP                   server_ip;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static ULONG                   zero_window_received = 0;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;
static UINT                    client_running = NX_TRUE;


/* Define pool area. */
static UCHAR                   client_pool_area[POOL_0_COUNT * (sizeof(NX_PACKET) + PACKET_SIZE)];
static UCHAR                   server_pool_area[POOL_1_COUNT * (sizeof(NX_PACKET) + PACKET_SIZE)];


/* Define thread prototypes.  */

static void    thread_client_entry(ULONG thread_input);
static void    thread_server_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_low_watermark_zero_window_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the Client thread.  */
    tx_thread_create(&client_thread, "Client thread", thread_client_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

        /* Create the Server thread.  */
    tx_thread_create(&server_thread, "Server thread", thread_server_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create two packet pools.  */
    status =  nx_packet_pool_create(&client_pool, "ClientPacket Pool", PACKET_SIZE, client_pool_area, sizeof(client_pool_area));
    status +=  nx_packet_pool_create(&server_pool, "Server Packet Pool", PACKET_SIZE, server_pool_area, sizeof(server_pool_area));

    if (status)
        error_counter++;
                                     
    /* Create client IP instance.  */
    status = nx_ip_create(&client_ip, "Client IP Instance", CLIENT_IP_ADDRESS, 0xFFFFFF00UL, &client_pool, 
                          _nx_ram_network_driver_1500,  pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create sever IP instance.  */
    status += nx_ip_create(&server_ip, "Server IP Instance", SERVER_IP_ADDRESS, 0xFFFFFF00UL, &server_pool, 
                           _nx_ram_network_driver_1500,  pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&client_ip);
    status += nx_tcp_enable(&server_ip);


    /* Check enable status.  */
    if (status)
        error_counter++;

    return;
}

static void    thread_server_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *send_packet;


    tx_thread_sleep(10);

    /* Print out some test information banners.  */
    printf("NetX Test:   Low Watermark  Zero Window Test...........................");

    /* Setup driver callback. */
    advanced_packet_process_callback = packet_process;

    /* Create server socket.  */
    status =  nx_tcp_socket_create(&server_ip, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                   NX_NULL, NX_NULL);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&server_ip, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_WAIT_FOREVER);

    zero_window_received = 0;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&server_pool, &send_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Write ABCs into the first packet payload!  */
    memcpy(send_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    send_packet -> nx_packet_length =  28;
    send_packet -> nx_packet_append_ptr =  send_packet -> nx_packet_prepend_ptr + 28;
   
    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&server_socket, send_packet, NX_NO_WAIT);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        nx_packet_release(send_packet);
        error_counter++;
    }

    while(client_running)
        tx_thread_sleep(100);

    nx_tcp_socket_disconnect(&server_socket, 200);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&server_ip, 12);
    nx_tcp_socket_delete(&server_socket);

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

static void    thread_client_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *recv_packet;

    tx_thread_sleep(50);

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&client_ip, &client_socket, "Client Socket", 
                            NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
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
    status =  nx_tcp_client_socket_connect(&client_socket, SERVER_IP_ADDRESS, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Set low watermark to prevent using any packets. */
    status = nx_packet_pool_low_watermark_set(&client_pool, client_pool.nx_packet_pool_total);

    /* Check for error.  */
    if (status)
        error_counter++;

    status = nx_tcp_socket_receive(&client_socket, &recv_packet, NX_IP_PERIODIC_RATE);

    if (status && (status != NX_NO_PACKET))
    {
          error_counter++;
    }
    else if (status == NX_SUCCESS) 
    {
          error_counter++;
          nx_packet_release(recv_packet);
    }

    /* Set low watermark to allow using all packets. */
    nx_packet_pool_low_watermark_set(&client_pool, 0);

    status = nx_tcp_socket_receive(&client_socket, &recv_packet, 5*NX_IP_PERIODIC_RATE);

    if (status != NX_SUCCESS)
    {
          error_counter++;
    }
    else
        nx_packet_release(recv_packet);

    /* Check whether zero window has been sent. */
    if (zero_window_received == 0)
    {
        error_counter++;
    }

    client_running = NX_FALSE;

     /* Force close the connection. */
    nx_tcp_socket_disconnect(&client_socket, 300);
    nx_tcp_client_socket_unbind(&client_socket);
    nx_tcp_socket_delete(&client_socket);

    return;

}

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

NX_TCP_HEADER *tcp_header_ptr;

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
void    netx_low_watermark_zero_window_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Low Watermark  Zero Window Test...........................N/A\n");
    test_control_return(3);

}
#endif /* NX_ENABLE_LOW_WATERMARK */
