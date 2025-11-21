/* This case tests link status down and up. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ip.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_RESET_DISCONNECT) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static UINT                    link_up_count;
static UINT                    link_down_count;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    link_status_change_notify(NX_IP *ip_ptr, UINT interface_index, UINT link_up);
static VOID    set_link_status(NX_IP *ip_ptr, UINT link_status);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ip_link_status_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    link_up_count = 0;
    link_down_count = 0;

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
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
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

    /* Enable ICMP processing for both IP instances. */
    status = nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check ICMP enable status.  */
    if(status)
        error_counter++;
}

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   IP Link Status Test.......................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let server thread listen first. */
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

    /* Connect to server.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 1 * NX_IP_PERIODIC_RATE);

    /* Check the connection status.  */
    if(status != NX_SUCCESS)
        error_counter++;
                                       
    /* Set link status change notify as NULL. */
    nx_ip_link_status_change_notify_set(&ip_0, NX_NULL);

    /* Simulator link down. */
    set_link_status(&ip_0, NX_FALSE);

    /* Set link status change notify. */
    nx_ip_link_status_change_notify_set(&ip_0, link_status_change_notify);

    /* Simulator link down. */
    set_link_status(&ip_0, NX_FALSE);

    /* Check whether TCP connections are dropped. */
    if (client_socket.nx_tcp_socket_state != NX_TCP_CLOSED)
        error_counter++;

    /* Check whether network is reachable. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABC", 3, &packet_ptr, 1 * NX_IP_PERIODIC_RATE);
    if (status == NX_SUCCESS)
    {
        
        /* It is not expected to receive a response. */
        error_counter++;
        nx_packet_release(packet_ptr);
    }

    /* Simulator link up. */
    set_link_status(&ip_0, NX_TRUE);

    /* Check whether network is reachable. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABC", 3, &packet_ptr, 1 * NX_IP_PERIODIC_RATE);
    if (status == NX_SUCCESS)
    {
        
        /* It is expected to receive a response. */
        nx_packet_release(packet_ptr);
    }
    else
    {
        error_counter++;
    }

    /* Determine if the test was successful.  */
    if((error_counter) || (link_up_count != 1) || (link_down_count != 1))
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
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
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


static VOID    link_status_change_notify(NX_IP *ip_ptr, UINT interface_index, UINT link_up)
{
    if (link_up == NX_TRUE)
    {

        /* Link status from down to up. */
        link_up_count++;
    }
    else
    {
        /* Link status from up to down. */
        link_down_count++;

        nx_tcp_socket_disconnect(&client_socket, NX_NO_WAIT);
        nx_tcp_socket_disconnect(&server_socket, NX_NO_WAIT);
    }
}


static VOID    set_link_status(NX_IP *ip_ptr, UINT link_status)
{
    
    /* Set link status and notify IP layer. */
    ip_ptr -> nx_ip_interface[0].nx_interface_link_up = (UCHAR)link_status;
    _nx_ip_driver_link_status_event(ip_ptr, 0);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ip_link_status_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Link Status Test.......................................N/A\n");

    test_control_return(3);  
}      
#endif
