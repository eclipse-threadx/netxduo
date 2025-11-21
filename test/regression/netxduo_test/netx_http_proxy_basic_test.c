/* This case tests basic HTTP Proxy connection. */
#include    "tx_api.h"
#include    "nx_api.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(NX_ENABLE_HTTP_PROXY) && defined(__PRODUCT_NETXDUO__)
#include    "nx_http_proxy_client.h"

#define     DEMO_STACK_SIZE         4096
#define     PACKET_SIZE             1536
#define     TOTAL_SIZE              DEMO_STACK_SIZE + (PACKET_SIZE * 8) + 2048 + 1024

/* Define device drivers.  */
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

static TX_THREAD           client_thread;
static NX_PACKET_POOL      client_pool;
static NX_TCP_SOCKET       test_client;
static NX_IP               client_ip;
static UINT                error_counter;

static NX_TCP_SOCKET       test_server;
static NX_PACKET_POOL      server_pool;
static TX_THREAD           server_thread;
static NX_IP               server_ip;
static UINT                test_server_start = 0;
static UINT                test_client_stop = 0;

/* Set up the HTTP proxy server global variables */
static TX_THREAD           proxy_thread;
static NX_PACKET_POOL      proxy_pool;
static NX_IP               proxy_ip;
static NX_TCP_SOCKET       agent_server, agent_client;

static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);
static void thread_proxy_entry(ULONG thread_input);

#define TEST_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define TEST_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)
#define HTTP_PROXY_ADDRESS   IP_ADDRESS(1,2,3,6)
#define HTTP_PROXY_PORT      8888
#define TEST_SERVER_PORT     8080

static UCHAR connect_200[] = 
{
0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x20, 0x32, 0x30, 0x30, 0x20, 0x43, 0x6f, 0x6e,
0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x65, 0x73, 0x74, 0x61, 0x62, 0x6c, 0x69, 0x73,
0x68, 0x65, 0x64, 0x0d, 0x0a, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74,
0x3a, 0x20, 0x74, 0x69, 0x6e, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x31, 0x2e, 0x38, 0x2e,
0x34, 0x0d, 0x0a, 0x0d, 0x0a,
};

static UCHAR connect_req[] = 
{
0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x20, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x3a,  /* CONNECT 1.2.3.4: */
0x38, 0x30, 0x38, 0x30, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48,  /* 8080 HTTP/1.1..H */
0x6f, 0x73, 0x74, 0x3a, 0x20, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x0d, 0x0a, 0x50, 0x72,  /* ost: 1.2.3.4..Pr */
0x6f, 0x78, 0x79, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f,  /* oxy-authorizatio */
0x6e, 0x3a, 0x20, 0x42, 0x61, 0x73, 0x69, 0x63, 0x20, 0x64, 0x58, 0x4e, 0x6c, 0x63, 0x6a, 0x70,  /* n: Basic dXNlcjp */
0x77, 0x59, 0x58, 0x4e, 0x7a, 0x64, 0x32, 0x39, 0x79, 0x5a, 0x41, 0x3d, 0x3d, 0x0d, 0x0a, 0x0d,  /* wYXNzd29yZA==... */
0x0a
};

static UCHAR test_data[] = "HTTP Proxy Basic Test!";

#define TEST_LOOP 3

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_proxy_basic_test_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;


    error_counter = 0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&server_thread, "Test Server thread", thread_server_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "Test Server Packet Pool", PACKET_SIZE, 
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, "Test Server IP", TEST_SERVER_ADDRESS, 
                          0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status = nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;


     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&server_ip);
    if (status)
        error_counter++;

    /* Create the Test Client thread. */
    status = tx_thread_create(&client_thread, "Test Client", thread_client_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "Test Client Packet Pool", PACKET_SIZE, 
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip, "Test Client IP", TEST_CLIENT_ADDRESS, 
                          0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status  = nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip);
    if (status)
        error_counter++;

    /* Create the HTTP Proxy thread. */
    status = tx_thread_create(&proxy_thread, "HTTP Proxy", thread_proxy_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&proxy_pool, "HTTP Proxy Packet Pool", PACKET_SIZE, 
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&proxy_ip, "HTTP Proxy IP", HTTP_PROXY_ADDRESS, 
                          0xFFFFFF00UL, &proxy_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status  = nx_arp_enable(&proxy_ip, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&proxy_ip);
    if (status)
        error_counter++;
}

void thread_client_entry(ULONG thread_input)
{
UINT            i, status;
NX_PACKET       *packet_ptr;
NXD_ADDRESS     proxy_server_address;
NXD_ADDRESS     server_ip_address;


    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = TEST_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    proxy_server_address.nxd_ip_version = NX_IP_VERSION_V4;
    proxy_server_address.nxd_ip_address.v4 = HTTP_PROXY_ADDRESS;

    status = nx_http_proxy_client_enable(&client_ip, &proxy_server_address, HTTP_PROXY_PORT, NX_NULL, 1, "password", sizeof("password") - 1);
    if (status != NX_PTR_ERROR)
        error_counter++;

    status = nx_http_proxy_client_enable(&client_ip, &proxy_server_address, HTTP_PROXY_PORT, "user", sizeof("user") - 1, NX_NULL, 1);
    if (status != NX_PTR_ERROR)
        error_counter++;

    status = nx_http_proxy_client_enable(&client_ip, &proxy_server_address, HTTP_PROXY_PORT, "user", NX_HTTP_PROXY_MAX_USERNAME + 1, "password", sizeof("password") - 1);
    if (status != NX_SIZE_ERROR)
        error_counter++;

    status = nx_http_proxy_client_enable(&client_ip, &proxy_server_address, HTTP_PROXY_PORT, "user", sizeof("user") - 1, "password", NX_HTTP_PROXY_MAX_PASSWORD + 1);
    if (status != NX_SIZE_ERROR)
        error_counter++;

    status = nx_http_proxy_client_enable(&client_ip, &proxy_server_address, HTTP_PROXY_PORT, "user", sizeof("user") - 1, "password", sizeof("password") - 1);
    if(status)
        error_counter++;

    status = nx_tcp_socket_create(&client_ip, &test_client, "Test Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    if(status)
        error_counter++;

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&test_client, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    for ( i = 0 ; i < TEST_LOOP; i++)
    {

        /* Wait test server started.  */
        while(!test_server_start)
        {
            tx_thread_sleep(NX_IP_PERIODIC_RATE);
        }

        status = nxd_tcp_client_socket_connect(&test_client, &server_ip_address, TEST_SERVER_PORT, NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Send data.  */
        status = nx_packet_allocate(&client_pool, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        status = nx_packet_data_append(packet_ptr, test_data, sizeof(test_data) - 1, &client_pool, NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        status = nx_tcp_socket_send(&test_client, packet_ptr, NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Receive the echo data from server.  */
        status = nx_tcp_socket_receive(&test_client, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;
        else
        {

            /* Check the received data.  */
            if ((packet_ptr -> nx_packet_length != (sizeof(test_data) - 1)) ||
                (memcmp(packet_ptr -> nx_packet_prepend_ptr, test_data, packet_ptr -> nx_packet_length) != 0))
                error_counter++;

            nx_packet_release(packet_ptr);
        }

        /* Set the flag.  */
        test_client_stop = 1;
        nx_tcp_socket_disconnect(&test_client, NX_IP_PERIODIC_RATE);
    }

    nx_tcp_client_socket_unbind(&test_client);
    nx_tcp_socket_delete(&test_client);
}

void thread_proxy_entry(ULONG thread_input)
{
UINT       i, status;
ULONG      actual_status;
NX_PACKET  *packet_ptr;
NXD_ADDRESS server_ip_address;

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = TEST_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&proxy_ip, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&proxy_ip, &agent_server, "Agent Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    status += nx_tcp_socket_create(&proxy_ip, &agent_client, "Agent Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                   NX_NULL, NX_NULL);
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&proxy_ip, HTTP_PROXY_PORT, &agent_server, 5, NX_NULL);
    if(status)
        error_counter++;

    for (i = 0; i < TEST_LOOP; i++)
    {

        /* Accept a connection from test client.  */
        status = nx_tcp_server_socket_accept(&agent_server, 5 * NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Receive CONNECT request.  */
        status = nx_tcp_socket_receive(&agent_server, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Check the received CONNECT request.  */
        if (memcmp(packet_ptr -> nx_packet_prepend_ptr, connect_req, sizeof(connect_req)) != 0)
            error_counter++;

        /* Connect to the test server.  */
        status = nx_tcp_client_socket_bind(&agent_client, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
        status += nxd_tcp_client_socket_connect(&agent_client, &server_ip_address, TEST_SERVER_PORT, NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Send response to test client.  */
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;
        packet_ptr -> nx_packet_length = 0;
        nx_packet_data_append(packet_ptr, connect_200, sizeof(connect_200), &proxy_pool, NX_IP_PERIODIC_RATE);
        status = nx_tcp_socket_send(&agent_server, packet_ptr, NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Tunneling...  */
        status = nx_tcp_socket_receive(&agent_server, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;
        status = nx_tcp_socket_send(&agent_client, packet_ptr, NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;
        status = nx_tcp_socket_receive(&agent_client, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;
        status = nx_tcp_socket_send(&agent_server, packet_ptr, NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Wait client test finished.  */
        tx_thread_sleep(NX_IP_PERIODIC_RATE);

        /* Disconnet.  */
        nx_tcp_socket_disconnect(&agent_server, NX_IP_PERIODIC_RATE);
        nx_tcp_server_socket_unaccept(&agent_server);
        nx_tcp_server_socket_relisten(&proxy_ip, HTTP_PROXY_PORT, &agent_server);
        nx_tcp_socket_disconnect(&agent_client, NX_IP_PERIODIC_RATE);
        nx_tcp_client_socket_unbind(&agent_client);
    }

    nx_tcp_socket_delete(&agent_server);
    nx_tcp_socket_delete(&agent_client);
}

/* Define the helper Test server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT            i, status;
NX_PACKET       *packet_ptr;


    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Proxy Basic Test.....................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Give NetX a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    status = nx_tcp_socket_create(&server_ip, &test_server, "Test Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);

    status = nx_tcp_server_socket_listen(&server_ip, TEST_SERVER_PORT, &test_server, 5, NX_NULL);
    if(status)
        error_counter++;

    for (i = 0; i < TEST_LOOP; i++)
    {

        /* Set the flag.  */
        test_server_start = 1;

        /* Accept a connection from test client.  */
        status = nx_tcp_server_socket_accept(&test_server, 5 * NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Receive client data.  */
        status = nx_tcp_socket_receive(&test_server, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Echo data.  */
        status = nx_tcp_socket_send(&test_server, packet_ptr, NX_IP_PERIODIC_RATE);
        if(status)
            error_counter++;

        /* Wait client test finished.  */
        while(!test_client_stop)
        {
            tx_thread_sleep(NX_IP_PERIODIC_RATE);
        }
        test_server_start = 0;
        test_client_stop = 0;

        nx_tcp_socket_disconnect(&test_server, NX_IP_PERIODIC_RATE);
        nx_tcp_server_socket_unaccept(&test_server);
        nx_tcp_server_socket_relisten(&server_ip, TEST_SERVER_PORT, &test_server);
    }
    nx_tcp_server_socket_unlisten(&server_ip, TEST_SERVER_PORT);
    nx_tcp_socket_delete(&test_server);

    /* Check packet pool.  */
    if (server_pool.nx_packet_pool_available != server_pool.nx_packet_pool_total)
    {
        error_counter++;
    }

    if (client_pool.nx_packet_pool_available != client_pool.nx_packet_pool_total)
    {
        error_counter++;
    }

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
void    netx_http_proxy_basic_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Proxy Basic Test.....................................N/A\n"); 

    test_control_return(3);  
}      
#endif

