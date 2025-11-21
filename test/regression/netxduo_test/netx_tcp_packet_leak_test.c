/* This NetX test concentrates no packet leak after socket is deleted.  */

#include   "nx_api.h"
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
static NX_TCP_SOCKET           server_socket;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_packet_leak_test_application_define(void *first_unused_memory)
#endif
{

CHAR   *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 4096);
    pointer = pointer + 2048;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFF0000UL, &pool_0, _nx_ram_network_driver,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
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
NX_PACKET  *packet_ptr;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Packet Leak Test......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Create the client socket. */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                  NX_NULL, NX_NULL);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
    
    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
    
    /* Connect to server. */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }

    /* Prepare a packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }

    status = nx_packet_data_append(packet_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_IP_PERIODIC_RATE);
    
    /* Check for error */
    if (status)
    {
        nx_packet_release(packet_ptr);
        error_counter++;
    }

    /* Send the packet out!  */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);

    /* Check for error */
    if (status)
    {
        error_counter++;
        nx_packet_release(packet_ptr);
    }
   
    /* Disconnect from server. */
    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
    
    /* Unbind the client socket. */
    status =  nx_tcp_client_socket_unbind(&client_socket);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
    
    /* Delete the client socket. */
    status =  nx_tcp_socket_delete(&client_socket);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }

    /* Verify no packet leak. */
    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total)
    {
        error_counter++;
    }
    
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
NX_PACKET  *packet_ptr;

    /* Create the server socket. */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                  NX_NULL, NX_NULL);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
    
    /* Listen the socket.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
    
    /* Accept connection from client. */
    status = nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }

    /* Prepare a packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }

    status = nx_packet_data_append(packet_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_IP_PERIODIC_RATE);
    
    /* Check for error */
    if (status)
    {
        nx_packet_release(packet_ptr);
        error_counter++;
    }

    /* Send the packet out!  */
    status = nx_tcp_socket_send(&server_socket, packet_ptr, NX_IP_PERIODIC_RATE);

    /* Check for error */
    if (status)
    {
        error_counter++;
        nx_packet_release(packet_ptr);
    }
    
    /* Disconnect from client. */
    status = nx_tcp_socket_disconnect(&server_socket, 5);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
    
    /* Unaccept the server socket. */
    status = nx_tcp_server_socket_unaccept(&server_socket);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
       
    /* Unlisten on the server port. */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
    
    /* Delete the client socket. */
    status = nx_tcp_socket_delete(&server_socket);
    
    /* Check for error */
    if (status)
    {
        error_counter++;
    }
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_packet_leak_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Packet Leak Test......................................N/A\n");

    test_control_return(3);  
}      
#endif
