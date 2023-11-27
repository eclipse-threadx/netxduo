/* This is a small demo of the NetX TCP/IP stack using the AUTO IP module.  */

#include "nx_auto_ip.h"
#include "tx_api.h"
#include "nx_api.h"


#define     DEMO_STACK_SIZE         4096

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           server_socket;
static NX_TCP_SOCKET           client_socket;
static TX_SEMAPHORE            sema_0;
static TX_SEMAPHORE            sema_1;


/* Define the AUTO IP structures for each IP instance.   */

static NX_AUTO_IP              auto_ip_0;
static NX_AUTO_IP              auto_ip_1;


/* Define the counters used in the demo application...  */
static ULONG                   address_changes;
static ULONG                   error_counter;
static ULONG                   packet_counter;
static ULONG                   conn_ip_address;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
static void    ip_address_changed(NX_IP *ip_ptr, VOID *auto_ip_address);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    test_control_return(UINT status);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_auto_ip_basic_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Initializes the variables. */
    error_counter = 0;
    packet_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 4096, 1);
    pointer =  pointer + 4096;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           pointer, 4096, 1);
    pointer =  pointer + 4096;

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

    /* Check UDP enable status.  */
    if (status)
        error_counter++;

    /* Create the AutoIP instance for each IP instance.   */
    status =  nx_auto_ip_create(&auto_ip_0, "AutoIP 0", &ip_0, pointer, 4096, 2);
    pointer = pointer + 4096;
    status += nx_auto_ip_create(&auto_ip_1, "AutoIP 1", &ip_1, pointer, 4096, 2);
    pointer = pointer + 4096;

    /* Check AutoIP create status.  */
    if (status)
        error_counter++;

    /* Start both AutoIP instances.  */
    status =  nx_auto_ip_start(&auto_ip_0, 0 /*IP_ADDRESS(169,254,254,255)*/);
    status += nx_auto_ip_start(&auto_ip_1, 0 /*IP_ADDRESS(169,254,254,255)*/);

    /* Check AutoIP start status.  */
    if (status)
        error_counter++;

    /* Register an IP address change function for each IP instance.  */
    status =  nx_ip_address_change_notify(&ip_0, ip_address_changed, (void *) &auto_ip_0);
    status += nx_ip_address_change_notify(&ip_1, ip_address_changed, (void *) &auto_ip_1);

    /* Check IP address change notify status.  */
    if (status)
        error_counter++;

    /* Create semaphores. */
    status = tx_semaphore_create(&sema_0, "SEMA 0", 0);
    status += tx_semaphore_create(&sema_1, "SEMA 1", 0);

    /* Check semaphore create status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

void    ntest_0_entry(ULONG thread_input)
{

UINT         status;
ULONG        network_mask;

    printf("NetX Test:   Auto_IP Basic Processing Test.............................");

    status = tx_semaphore_get(&sema_0, (NX_AUTO_IP_PROBE_NUM * NX_AUTO_IP_PROBE_MAX + NX_AUTO_IP_ANNOUNCE_NUM * NX_AUTO_IP_ANNOUNCE_INTERVAL) * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wakeup thread_1. */
    tx_semaphore_put(&sema_1);

    /* Pickup the current IP address.  */
 
    nx_ip_address_get(&ip_0, &conn_ip_address, &network_mask);

    /* Check whether the AutoIP allocates addresses in the range of 169.254.1.0 through 169.254.254.255.*/
    if((conn_ip_address & 0xFFFF0000UL) != IP_ADDRESS(169, 254, 0, 0) || (conn_ip_address < IP_ADDRESS(169, 254, 1, 0)) || (conn_ip_address > IP_ADDRESS(169, 254, 254, 255)))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a TCP socket.  */
    status =  nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, ntest_0_disconnect_received);

    /* Check status.  */
    if (status)
        error_counter++;

        /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, ntest_0_connect_received);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Server socket disconnect the connection.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);
    
    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unaccepted the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unlisted on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_0, 12);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Stop the AutoIP instance auto_ip_0.  */
    status = nx_auto_ip_stop(&auto_ip_0);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Delete the AutoIP instance auto_ip_0.  */
    status =  nx_auto_ip_delete(&auto_ip_0);

    /* Check for error.  */
    if(status)
        error_counter++;

}
    

void    ntest_1_entry(ULONG thread_input)
{

UINT         status;
ULONG        ip_address;
ULONG        network_mask;

    status = tx_semaphore_get(&sema_1, (NX_AUTO_IP_PROBE_NUM * NX_AUTO_IP_PROBE_MAX + NX_AUTO_IP_ANNOUNCE_NUM * NX_AUTO_IP_ANNOUNCE_INTERVAL) * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_semaphore_get(&sema_1, TX_WAIT_FOREVER);

    /* Pickup the current IP address.  */
    nx_ip_address_get(&ip_1, &ip_address, &network_mask);

    /* Check whether the AutoIP allocates addresses in the range of 169.254.1.0 through 169.254.254.255.*/
    if((ip_address & 0xFFFF0000UL) != IP_ADDRESS(169, 254, 0, 0) || (ip_address < IP_ADDRESS(169, 254, 1, 0)) || (ip_address > IP_ADDRESS(169, 254, 254, 255)))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


       /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, conn_ip_address, 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Disconnect this socket.  */
    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)
        error_counter++;

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Stop the AutoIP instance auto_ip_1.  */
    status = nx_auto_ip_stop(&auto_ip_1);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Delete the AutoIP instance auto_ip_1.  */
    status =  nx_auto_ip_delete(&auto_ip_1);

    /* Check for error.  */
    if(status)
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

void  ip_address_changed(NX_IP *ip_ptr, VOID *auto_ip_address)
{

ULONG         ip_address;
ULONG         network_mask;
NX_AUTO_IP    *auto_ip_ptr;


    /* Setup pointer to auto IP instance.  */
    auto_ip_ptr =  (NX_AUTO_IP *) auto_ip_address;

    /* Pickup the current IP address.  */
    nx_ip_address_get(ip_ptr, &ip_address, &network_mask);

    /* Determine if the IP address has changed back to zero. If so, make sure the
       AutoIP instance is started.  */
    if (ip_address == 0)
    {

        /* Get the last AutoIP address for this node.  */
        nx_auto_ip_get_address(auto_ip_ptr, &ip_address);

        /* Start this AutoIP instance.  */
        nx_auto_ip_start(auto_ip_ptr, ip_address);
    }

    /* Determine if the IP address has transitioned to a non local IP address.  */
    else if ((ip_address & 0xFFFF0000UL) != IP_ADDRESS(169, 254, 0, 0))
    {

        /* Stop the AutoIP processing.  */
        nx_auto_ip_stop(auto_ip_ptr);

        /* Delete the AutoIP instance.  */
        nx_auto_ip_delete(auto_ip_ptr);
    }

    /* Increment a counter.  */
    address_changes++;

    /* Wakeup test threads. */
    if(ip_ptr == &ip_0)
        tx_semaphore_put(&sema_0);
    else
        tx_semaphore_put(&sema_1);
}

static void  ntest_0_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if ((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void  ntest_0_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if (socket != &server_socket)
        error_counter++;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_auto_ip_basic_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Auto_IP Basic Processing Test.............................N/A\n"); 

    test_control_return(3);  
}      
#endif
