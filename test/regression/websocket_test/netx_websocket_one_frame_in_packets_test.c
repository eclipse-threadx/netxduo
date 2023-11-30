/* This case tests websocket process data ability when one websocket frame is composited by several TCP packets. */
#include    "tx_api.h"
#include    "nx_api.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN)
#include    "nx_websocket_client.h"
#include    "netx_websocket_common_process.c"

#define     DEMO_STACK_SIZE         4096
#define     PACKET_SIZE             1536
#define     TOTAL_SIZE              DEMO_STACK_SIZE + (PACKET_SIZE * 8) + 2048 + 1024

/* Define device drivers.  */
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

static UINT                test_done = NX_FALSE;

static TX_THREAD           client_thread;
static NX_PACKET_POOL      client_pool;
static NX_TCP_SOCKET       test_client;
static NX_IP               client_ip;

static NX_TCP_SOCKET       test_server;
static NX_PACKET_POOL      server_pool;
static TX_THREAD           server_thread;
static NX_IP               server_ip;
static UINT                test_server_start = 0;
static UINT                test_client_stop = 0;

/* Set up the websocket global variables */
static NX_WEBSOCKET_CLIENT client_websocket;
static UCHAR               *client_websocket_host;
static UINT                client_websocket_host_length;
static UCHAR               *client_websocket_uri_path;
static UINT                client_websocket_uri_path_length;


static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);

#define TEST_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define TEST_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)
#define TEST_SERVER_PORT     80

#define TEST_HOST_NAME       "1.2.3.4"
#define TEST_URI_PATH        "/test"
#define TEST_PROTOCOL        "test"

static UCHAR server_switch_101[] =
{
0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20,                                      // HTTP1.1/
0x31, 0x30, 0x31, 0x20, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x20,        // 101 Switching
0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x73, 0x0d, 0x0a,                          // Protocols\r\n
0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x3a, 0x20,                                      // Upgrade:
0x57, 0x65, 0x62, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x0d, 0x0a,                          // WebSocket\r\n
0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20,                    // Connection:
0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x0d, 0x0a,                                      // Upgrade\r\n
0x53, 0x65, 0x63, 0x2d, 0x57, 0x65, 0x62, 0x53, 0x6f, 0x63, 0x6b, 0x65,                    // Sec-WebSocket-Protocol:
0x74, 0x2d, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x3a, 0x20,
0x74, 0x65, 0x73, 0x74, 0x0d, 0x0a,                                                        // test
0x53, 0x65, 0x63, 0x2d, 0x57, 0x65, 0x62, 0x53, 0x6f, 0x63, 0x6b,                          // Sec-WebSocket-Accept:
0x65, 0x74, 0x2d, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
0x35, 0x75, 0x31, 0x6c, 0x55, 0x72, 0x32, 0x57, 0x68, 0x70, 0x34, 0x64, 0x44, 0x57, 0x6e,  // 5u1lUr2Whp4dDWnskk9JcJZobO0=
0x73, 0x6b, 0x6b, 0x39, 0x4a, 0x63, 0x4a, 0x5a, 0x6f, 0x62, 0x4f, 0x30, 0x3d, 0x0d, 0x0a,
0x0d, 0x0a,
};

static UCHAR server_response_1[] =
{
0x82, 0x04, 0x01, 0x02, 0x03, 0x04,
};

static UCHAR server_response_2_1[] =
{
0x82
};

static UCHAR server_response_2_2[] =
{
0x04,
};

static UCHAR server_response_2_3[] =
{
0x01, 0x02, 0x03, 0x04,
};

static UCHAR client_test_data[] =
{
0x11, 0x22, 0x33, 0x44,
};

static ULONG                   error_counter;

extern void SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number);

#define TEST_LOOP 3

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_websocket_one_frame_in_packets_test_application_define(void *first_unused_memory)
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
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, "Test Server IP", TEST_SERVER_ADDRESS,
                          0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status = nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);


     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&server_ip);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create the Test Client thread. */
    status = tx_thread_create(&client_thread, "Test Client", thread_client_entry, 0,
                              pointer, DEMO_STACK_SIZE,
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "Test Client Packet Pool", PACKET_SIZE,
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip, "Test Client IP", TEST_CLIENT_ADDRESS,
                          0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    status  = nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
}

void thread_client_entry(ULONG thread_input)
{
UINT            i, status;
NX_PACKET       *packet_ptr;
NX_PACKET       *packet_ptr1;
NXD_ADDRESS     server_ip_address;
UINT            code;

    /* Create client socket.  */
    status = nx_tcp_socket_create(&client_ip, &test_client, "Client Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                  NX_IP_TIME_TO_LIVE, 1000, NX_NULL, NX_NULL);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create WebSocket.  */
    status = nx_websocket_client_create(&client_websocket, (UCHAR *)" ", &client_ip, &client_pool);

    /* Check status.  */
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&test_client, TEST_SERVER_PORT, NX_IP_PERIODIC_RATE);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Wait test server started.  */
    while(!test_server_start)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = TEST_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    /* Connect to the server  */
    status = nxd_tcp_client_socket_connect(&test_client, &server_ip_address, TEST_SERVER_PORT, NX_WAIT_FOREVER);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Upgrade to websocket */
    status = nx_websocket_client_connect(&client_websocket, &test_client,
                                        TEST_HOST_NAME, sizeof(TEST_HOST_NAME) - 1,
                                        (UCHAR *)TEST_URI_PATH, sizeof(TEST_URI_PATH) - 1,
                                        (UCHAR *)TEST_PROTOCOL, sizeof(TEST_PROTOCOL) - 1,
                                        NX_WAIT_FOREVER);

    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    else
    {
        status = nx_packet_allocate(&client_pool, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        /* ---- Normal frame test ---- */

        /* Append and send data.  */
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;
        packet_ptr -> nx_packet_length = 0;
        status = nx_packet_data_append(packet_ptr, client_test_data, sizeof(client_test_data), &client_pool, NX_IP_PERIODIC_RATE);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        status = nx_websocket_client_send(&client_websocket, packet_ptr, NX_WEBSOCKET_OPCODE_BINARY_FRAME, NX_TRUE, NX_WAIT_FOREVER);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        /* Receive the responsed data from server.  */
        status = nx_websocket_client_receive(&client_websocket, &packet_ptr, &code, NX_NO_WAIT);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        /* The first response from the server shall be an unfragmented frame  */
        if (client_websocket.nx_websocket_client_frame_fragmented == NX_TRUE)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        nx_packet_release(packet_ptr);

        /* ---- One frame in packets test ---- */

        status = nx_packet_allocate(&client_pool, &packet_ptr1, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        /* Append and send data.  */
        packet_ptr1 -> nx_packet_append_ptr = packet_ptr1 -> nx_packet_prepend_ptr;
        packet_ptr1 -> nx_packet_length = 0;
        status = nx_packet_data_append(packet_ptr1, client_test_data, sizeof(client_test_data), &client_pool, NX_IP_PERIODIC_RATE);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        status = nx_websocket_client_send(&client_websocket, packet_ptr1, NX_WEBSOCKET_OPCODE_BINARY_FRAME, NX_TRUE, NX_WAIT_FOREVER);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        /* Receive the responsed data from server.  */
        status = nx_websocket_client_receive(&client_websocket, &packet_ptr1, &code, NX_NO_WAIT);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        if (code != NX_WEBSOCKET_OPCODE_BINARY_FRAME)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        if (packet_ptr1 -> nx_packet_length != 4)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        nx_packet_release(packet_ptr1);
    }

    nx_tcp_client_socket_unbind(&test_client);
    nx_tcp_socket_delete(&test_client);

    test_done = NX_TRUE;
}

/* Define the helper Test server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT            i, status;
NX_PACKET       *packet_ptr;


    /* Print out test information banner.  */
    printf("NetX Test:   Websocket One Frame in Packets Test.....................................");

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
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Set the flag.  */
    test_server_start = 1;

    /* Accept a connection from test client.  */
    status = nx_tcp_server_socket_accept(&test_server, 5 * NX_IP_PERIODIC_RATE);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    for (i = 0; i < TEST_LOOP; i++)
    {
        /* Receive client data.  */
        status = nx_tcp_socket_receive(&test_server, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        if(status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        else
        {
            /* Response data.  */
            switch (i)
            {
            case 0:
                /* Update the value in the field Sec-Protocol-Accept since it is calculated based on a random value */
                _server_connect_response_process(packet_ptr);
                memcpy(&server_switch_101[127], connect_key, 28);

                packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;
                packet_ptr -> nx_packet_length = 0;
                nx_packet_data_append(packet_ptr, server_switch_101, sizeof(server_switch_101), &server_pool, NX_IP_PERIODIC_RATE);
                status = nx_tcp_socket_send(&test_server, packet_ptr, NX_IP_PERIODIC_RATE);
                if(status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
                break;
            case 1:
                packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;
                packet_ptr -> nx_packet_length = 0;
                nx_packet_data_append(packet_ptr, server_response_1, sizeof(server_response_1), &server_pool, NX_IP_PERIODIC_RATE);
                status = nx_tcp_socket_send(&test_server, packet_ptr, NX_IP_PERIODIC_RATE);
                if(status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
                break;
            case 2:
                packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;
                packet_ptr -> nx_packet_length = 0;
                nx_packet_data_append(packet_ptr, server_response_2_1, sizeof(server_response_2_1), &server_pool, NX_IP_PERIODIC_RATE);
                status = nx_tcp_socket_send(&test_server, packet_ptr, NX_IP_PERIODIC_RATE);
                if(status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
                status = nx_packet_allocate(&server_pool, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
                if(status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
                nx_packet_data_append(packet_ptr, server_response_2_2, sizeof(server_response_2_2), &server_pool, NX_IP_PERIODIC_RATE);
                status = nx_tcp_socket_send(&test_server, packet_ptr, NX_IP_PERIODIC_RATE);
                if(status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
                status = nx_packet_allocate(&server_pool, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
                if(status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
                nx_packet_data_append(packet_ptr, server_response_2_3, sizeof(server_response_2_3), &server_pool, NX_IP_PERIODIC_RATE);
                status = nx_tcp_socket_send(&test_server, packet_ptr, NX_IP_PERIODIC_RATE);
                if(status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
                break;
            default:
                break;
            }
        }
    }

    /* Wait for test done.  */
    while (test_done == NX_FALSE)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    nx_tcp_server_socket_unlisten(&server_ip, TEST_SERVER_PORT);
    nx_tcp_socket_delete(&test_server);

    if (client_pool.nx_packet_pool_available != client_pool.nx_packet_pool_total)
    {
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }
    else if (client_pool.nx_packet_pool_invalid_releases)
    {
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }

    if (server_pool.nx_packet_pool_available != server_pool.nx_packet_pool_total)
    {
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
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
void    netx_websocket_one_frame_in_packets_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Websocket One Frame in Packets Test.....................................N/A\n");

    test_control_return(3);
}
#endif

