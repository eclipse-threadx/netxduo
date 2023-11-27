/* If the ACK is a duplicate, the window size can be ignored. Page 72, Section 3.9, RFC 793.  */

/* Procedure
1. Client socket connects to server socket.
2. Client sends five packets to server. The size of each packet is 1/5 of window size. Then the send window should be zero. 
3. Drop the second packet from client to server. 
4. Try to send 1/5 of window size from client to server without wait. It should fail since send window is zero. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NX_PACKET              *drop_packet = NX_NULL;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_window_update_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
                           pointer, 2048, 2);
    pointer = pointer + 2048;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
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
static UCHAR send_buffer[200];

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
UINT       i;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Window Update Test....................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_relinquish();

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, 1 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* The callback function is used to drop the second data packet.  */
    advanced_packet_process_callback = my_packet_process;

    /* Connect to server.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 1 * NX_IP_PERIODIC_RATE);

    /* Check the connection status.  */
    if(status != NX_SUCCESS)
        error_counter++;

    /* Send two packets. */
    for(i = 0; i < 2; i++)
    {

        /* Allocate a packet and fill data. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 1 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
            error_counter++;
        else
        {
            status = nx_packet_data_append(packet_ptr, send_buffer, sizeof(send_buffer), &pool_0, 1 * NX_IP_PERIODIC_RATE);
            if(status != NX_SUCCESS)
                error_counter++;
        }

        /* Send the pacekt. */
        status = nx_tcp_socket_send(&client_socket, packet_ptr, 0);
        if(status != NX_SUCCESS)
            error_counter++;
    }

    /* Wait ACK packet. */
    tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);

    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, send_buffer, sizeof(send_buffer), &pool_0, 1 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
            error_counter++;
    }

    /* Drop the packet. */
    drop_packet = packet_ptr;

    /* Send the pacekt. */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, 0);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Send two packets. */
    for(i = 0; i < 2; i++)
    {

        /* Allocate a packet and fill data. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 1 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
            error_counter++;
        else
        {
            status = nx_packet_data_append(packet_ptr, send_buffer, sizeof(send_buffer), &pool_0, 1 * NX_IP_PERIODIC_RATE);
            if(status != NX_SUCCESS)
                error_counter++;
        }

        /* Send the pacekt. */
        status = nx_tcp_socket_send(&client_socket, packet_ptr, 0);
        if(status != NX_SUCCESS)
            error_counter++;
    }

    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, send_buffer, sizeof(send_buffer), &pool_0, 1 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
            error_counter++;
    }

    /* Send the pacekt. Since window is full, send call should not be successful. */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, 0);
    if(status == NX_SUCCESS)
        error_counter++;

    /* Determine if the test was successful.  */
    if(error_counter)
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

static void    ntest_1_entry(ULONG thread_input)
{
UINT            status;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, sizeof(send_buffer) * 5,
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
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;
}

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
    if(packet_ptr == drop_packet)
    {

        /* This packet should be dropped. */
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
        drop_packet = NX_NULL;
        return NX_TRUE;
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_window_update_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Window Update Test....................................N/A\n"); 

    test_control_return(3);  
}      
#endif