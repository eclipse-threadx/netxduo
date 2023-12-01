/* This case tests the Telnet server on handling RST packet.
 */
#include  "tx_api.h"
#include  "nx_api.h"
#include <stdio.h>
#include <stdlib.h>
extern void    test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_RESET_DISCONNECT)



#include  "nxd_telnet_server.h"

#define     DEMO_STACK_SIZE         4096
#define     LOOP                    100


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               server_thread;
static NX_PACKET_POOL          pool_server;
static NX_PACKET_POOL          pool_client;
static NX_IP                   ip_server;
static NX_IP                   ip_client;
static TX_THREAD               test_threads[NX_TELNET_MAX_CLIENTS];
static NX_TCP_SOCKET           test_sockets[NX_TELNET_MAX_CLIENTS];
static UINT                    run_count[NX_TELNET_MAX_CLIENTS];
static UCHAR                   test_thread_stack[NX_TELNET_MAX_CLIENTS][DEMO_STACK_SIZE];
static TX_SEMAPHORE            sema_0;

/* Define TELNET objects.  */

static NX_TELNET_SERVER        my_server;

static UINT                    data_received;
static UCHAR                   send_buff[256];
static UCHAR                   recv_buff[256];


#define         SERVER_ADDRESS          IP_ADDRESS(1,2,3,4)
#define         CLIENT_ADDRESS          IP_ADDRESS(1,2,3,5)


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define timeout in ticks for connecting and sending/receiving data. */

#define                 TELNET_TIMEOUT  200

/* Define function prototypes.  */

static void    thread_server_entry(ULONG thread_input);
static void    thread_test_entry(ULONG thread_input);

/* Replace the 'ram' driver with your actual Ethernet driver. */
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define the application's TELNET Server callback routines.  */

static void    telnet_new_connection(NX_TELNET_SERVER *server_ptr, UINT logical_connection);
static void    telnet_receive_data(NX_TELNET_SERVER *server_ptr, UINT logical_connection, NX_PACKET *packet_ptr);
static void    telnet_connection_end(NX_TELNET_SERVER *server_ptr, UINT logical_connection);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_telnet_rst_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
CHAR    *pointer;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&server_thread, "server thread", thread_server_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create packet pool.  */
    status = nx_packet_pool_create(&pool_server, "Server NetX Packet Pool", 600, pointer, 8192);
    pointer = pointer + 8192;
    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_server, "Server NetX IP Instance", SERVER_ADDRESS,
                          0xFFFFFF00UL, &pool_server, _nx_ram_network_driver_512,
                          pointer, 4096, 1);
    pointer =  pointer + 4096;
    if(status)
        error_counter++;

    /* Create another packet pool. */
    status = nx_packet_pool_create(&pool_client, "Client NetX Packet Pool", 600, pointer, 8192);
    pointer = pointer + 8192;
    if(status)
        error_counter++;

    /* Create another IP instance.  */
    status = nx_ip_create(&ip_client, "Client NetX IP Instance", CLIENT_ADDRESS,
                          0xFFFFFF00UL, &pool_client, _nx_ram_network_driver_512,
                          pointer, 4096, 1);
    pointer = pointer + 4096;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_server, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_client, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_server);
    status += nx_tcp_enable(&ip_client);
    if(status)
        error_counter++;

    /* Create the NetX Duo TELNET Server.  */
    status =  nx_telnet_server_create(&my_server, "Telnet Server", &ip_server,
                    pointer, 2048, telnet_new_connection, telnet_receive_data,
                    telnet_connection_end);

    /* Check for errors.  */
    if (status)
        error_counter++;

    status = tx_semaphore_create(&sema_0, "Semaphore", 0);
    if (status)
        error_counter++;
}

static void thread_test_entry(ULONG thread_input)
{
NX_TCP_SOCKET *socket_ptr = &test_sockets[thread_input];
UINT status;
UINT i;

    /* Create Client socket.  */
    status =  nx_tcp_socket_create(&ip_client, socket_ptr, "Client Socket",
                            NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                            NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
    {
        error_counter++;
        return;
    }

    for (i = 0; i < LOOP; i++)
    {

        /* Bind the socket.  */
        status =  nx_tcp_client_socket_bind(socket_ptr, NX_ANY_PORT, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
            break;
        }

        status = nx_tcp_client_socket_connect(socket_ptr, SERVER_ADDRESS, NX_TELNET_SERVER_PORT, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
            break;
        }

        nx_tcp_socket_disconnect(socket_ptr, NX_NO_WAIT);

        /* Unbind the socket.  */
        status =  nx_tcp_client_socket_unbind(socket_ptr);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
            break;
        }

        run_count[thread_input]++;
    }

    nx_tcp_socket_delete(socket_ptr);
    tx_semaphore_put(&sema_0);
}

/* Define the Server thread.  */
static void    thread_server_entry(ULONG thread_input)
{

UINT    i;
UINT    status;

    /* Print out test information banner.  */
    printf("NetX Test:   Telnet RST Test...........................................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef NX_TELNET_SERVER_USER_CREATE_PACKET_POOL
    nx_telnet_server_packet_pool_set(&my_server, &pool_server);
#endif

    /* Start the TELNET Server.  */
    status =  nx_telnet_server_start(&my_server);
    if (status)
        error_counter++;

    for (i = 0; i < sizeof(test_threads) / sizeof(TX_THREAD); i++)
    {
        run_count[i] = 0;
        tx_thread_create(&test_threads[i], "Test thread", thread_test_entry, i,
                         test_thread_stack[i], DEMO_STACK_SIZE,
                         8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);
    }

    for (i = 0; i < sizeof(test_threads) / sizeof(TX_THREAD); i++)
    {
        if (tx_semaphore_get(&sema_0, 30 * NX_IP_PERIODIC_RATE))
        {
            error_counter++;
            break;
        }
    }

    for (i = 0; i < sizeof(test_threads) / sizeof(TX_THREAD); i++)
    {
        if (run_count[i] != LOOP)
        {
            error_counter++;
        }
    }

    status = nx_telnet_server_delete(&my_server);
    if (status)
        error_counter++;

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

/* This routine is called by the NetX Telnet Server whenever a new Telnet client
   connection is established.  */
static void  telnet_new_connection(NX_TELNET_SERVER *server_ptr, UINT logical_connection)
{
}

/* This routine is called by the NetX Telnet Server whenever data is present on a Telnet client
   connection.  */
static void  telnet_receive_data(NX_TELNET_SERVER *server_ptr, UINT logical_connection, NX_PACKET *packet_ptr)
{
}


/* This routine is called by the NetX Telnet Server whenever the client disconnects.  */
static void  telnet_connection_end(NX_TELNET_SERVER *server_ptr, UINT logical_connection)
{
}

#else /* NX_TELNET_SERVER_USER_CREATE_PACKET_POOL */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_telnet_rst_test_application_define(void *first_unused_memory)
#endif
{
    /* Print out test information banner.  */
    printf("NetX Test:   Telnet RST Test...........................................N/A\n");
    test_control_return(3);
}
#endif /* NX_TELNET_SERVER_USER_CREATE_PACKET_POOL */


