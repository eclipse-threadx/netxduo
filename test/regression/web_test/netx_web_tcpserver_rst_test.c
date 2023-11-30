/* This case tests the tcpserver on handling RST packet. */
#include    "nx_api.h"
#include    "nx_tcpserver.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_RESET_DISCONNECT)

#define     DEMO_STACK_SIZE         2048
#define     PACKET_SIZE             256
#define     SERVER_ADDRESS          IP_ADDRESS(1,2,3,4)
#define     SERVER_PORT             1234
#define     LOOP                    100

static NX_TCP_SESSION      session_buffer[5];
static NX_TCPSERVER        tcpserver;
static TX_THREAD           server_thread;
static TX_THREAD           test_threads[10];
static NX_TCP_SOCKET       test_sockets[10];
static UINT                run_count[10];
static NX_IP               ip_0;
static NX_PACKET_POOL      pool_0;
static UINT                error_counter;
static UCHAR               pool_area[(sizeof(NX_PACKET) + PACKET_SIZE) * 64];
static UCHAR               tcpserver_stack[DEMO_STACK_SIZE];
static UCHAR               test_thread_stack[10][DEMO_STACK_SIZE];
static TX_SEMAPHORE        sema_0;

static void thread_test_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_tcpserver_rst_test_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;


    error_counter = 0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&server_thread, "Server thread", thread_server_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "Packet Pool", PACKET_SIZE,
                                    pool_area, sizeof(pool_area));
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "IP 0", SERVER_ADDRESS,
                          0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1024,
                          pointer, 4096, 1);
    pointer =  pointer + 4096;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&ip_0);
    if (status)
        error_counter++;

    status = tx_semaphore_create(&sema_0, "Semaphore", 0);
    if (status)
        error_counter++;
}

static void connection_end(NX_TCPSERVER *server_ptr, NX_TCP_SESSION *session_ptr)
{
    nx_tcp_socket_disconnect(&session_ptr -> nx_tcp_session_socket, NX_NO_WAIT);
    nx_tcp_server_socket_unaccept(&session_ptr -> nx_tcp_session_socket);
}

static void thread_test_entry(ULONG thread_input)
{
NX_TCP_SOCKET *socket_ptr = &test_sockets[thread_input];
UINT status;
UINT i;

    /* Create Client socket.  */
    status =  nx_tcp_socket_create(&ip_0, socket_ptr, "Client Socket",
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

        status = nx_tcp_client_socket_connect(socket_ptr, SERVER_ADDRESS, SERVER_PORT, NX_IP_PERIODIC_RATE);

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


/* Define the server thread.  */
static void    thread_server_entry(ULONG thread_input)
{
UINT            i;
UINT            status;


    /* Print out test information banner.  */
    printf("NetX Test:   Web TCPServer RST Test....................................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_tcpserver_create(&ip_0, &tcpserver, "TCP server",
                                 NX_IP_NORMAL,  NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                                 200, NX_NULL, NX_NULL, connection_end, NX_NULL, 60 * NX_IP_PERIODIC_RATE,
                                 tcpserver_stack, sizeof(tcpserver_stack), session_buffer,
                                 sizeof(session_buffer), 4, 1);
    if (status)
    {
        error_counter++;
    }

    status = nx_tcpserver_start(&tcpserver, SERVER_PORT, 20);
    if (status)
    {
        error_counter++;
    }

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

    nx_tcpserver_stop(&tcpserver);
    nx_tcpserver_delete(&tcpserver);

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
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_tcpserver_rst_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Web TCPServer RST Test....................................N/A\n");

    test_control_return(3);
}
#endif
