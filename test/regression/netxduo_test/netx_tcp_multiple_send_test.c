/* This NetX test concentrates on sending TCP packets in multiple threads simultaneously.  */

#include   "nx_api.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static TX_THREAD               thread_2;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

static UCHAR                   pool_area_0[20480];
static UCHAR                   pool_area_1[20480];

static CHAR                    send_buff[512];

static ULONG                   end_time;

static ULONG                   thread_0_counter;
static ULONG                   thread_1_counter;
static ULONG                   thread_2_counter;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_2_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_multiple_send_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;
    thread_0_counter =  0;
    thread_1_counter =  0;
    thread_2_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, 1, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, 1, TX_DONT_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_2, "thread 2", thread_2_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create two packet pools.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pool_area_0, sizeof(pool_area_0));
    status +=  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 256, pool_area_1, sizeof(pool_area_1));

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_256,
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
NX_PACKET   *my_packet;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Multiple Send Test....................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;


    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Reset the system timer. */
    tx_time_set(0);

    /* Set the timer that stops sending. */
    end_time = NX_IP_PERIODIC_RATE;

    /* Resume thread 1. */
    tx_thread_resume(&thread_1);

    while (tx_time_get() < end_time)
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;

        status = nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_0, 2 * NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Send the packet out!  */
        status =  nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);
        if (status)
        {
            error_counter++;
            nx_packet_release(my_packet);
        }

        thread_0_counter++;
    }

    /* Sleep 1 second to make sure thread 1 exists. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Disconnect this socket.  */
    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&client_socket);
    if (status)
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

UINT        status;
NX_PACKET   *my_packet;

    while (tx_time_get() < end_time)
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;

        status = nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_0, 2 * NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Send the packet out!  */
        status =  nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);
        if (status)
        {
            error_counter++;
            nx_packet_release(my_packet);
        }
        thread_1_counter++;
    }
}
    

static void    thread_2_entry(ULONG thread_input)
{

UINT            status;
NX_PACKET       *packet_ptr;
ULONG           actual_status;


    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1024,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Receive a TCP message from the socket.  */
    while (nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_IP_PERIODIC_RATE) == NX_SUCCESS)
    {

        /* Release the packet. */
        nx_packet_release(packet_ptr);
        thread_2_counter++;
    }

    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&server_socket);
    if (status)
        error_counter++;

    /* Unlisten on the server port 12.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&server_socket);
    if (status)
        error_counter++;

}
#else  
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_multiple_send_test_application_define(void *first_unused_memory)
#endif
{   

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Multiple Send Test....................................N/A\n");

    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */  
