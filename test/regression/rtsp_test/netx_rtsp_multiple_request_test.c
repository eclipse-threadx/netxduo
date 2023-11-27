/* This case tests RTSP request in multiple packets. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "netxtestcontrol.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(__PRODUCT_NETXDUO__)
#include    "nx_rtsp_server.h"

#define     DEMO_STACK_SIZE         4096
#define     PACKET_SIZE             1536

/* Define device drivers.  */
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

static UCHAR rtsp_stack[DEMO_STACK_SIZE];

static TX_THREAD           client_thread;
static NX_PACKET_POOL      client_pool;
static NX_IP               client_ip;
static NX_TCP_SOCKET       rtsp_client;

static TX_THREAD           server_thread;
static NX_PACKET_POOL      server_pool;
static NX_IP               server_ip;
static NX_RTSP_SERVER      rtsp_server;

static UINT                error_counter;

static TX_SEMAPHORE        semaphore_server_start;
static TX_SEMAPHORE        semaphore_client_done;


static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);
static UINT rtsp_describe_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);
static UINT rtsp_setup_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr);
static UINT rtsp_play_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);
static UINT rtsp_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);
static UINT rtsp_pause_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);
static UINT rtsp_set_parameter_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length);
static UINT rtsp_disconnect_callback(NX_RTSP_CLIENT *rtsp_client_ptr);

#define TEST_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define TEST_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)
#define RTSP_SERVER_PORT     554

#define TEST_LOOP 3

/* Test packet, length = 157 = 54 + 11 + 19 + 20 + 30 + 20. */
static UCHAR test_data[] = "\
SET_PARAMETER rtsp://example.com/fizzle/foo RTSP/1.0\r\n\
CSeq: 421\r\n\
Session: 23754311\r\n\
Content-length: 20\r\n\
Content-type: text/parameters\r\n\
\r\n\
barparam: barstuff\r\n\
";

static UCHAR expected_response[] = "RTSP/1.0 200 OK\r\nCSeq: 421\r\nServer: RTSP Server\r\n\r\n";

static UINT test_size[TEST_LOOP][3] = 
{
    {50, 39, 68}, // Conten-length in multiple packets.
    {69, 70, 18}, // Content in multiple packets.
    {39, 98, 20}, // Header in multiple packets and content in another packet
};

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtsp_multiple_request_test_application_define(void *first_unused_memory)
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
    CHECK_STATUS(0, status);

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, "Test Server IP", TEST_SERVER_ADDRESS, 
                          0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    CHECK_STATUS(0, status);

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status = nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    CHECK_STATUS(0, status);


     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&server_ip);
    CHECK_STATUS(0, status);

    /* Create the Test Client thread. */
    status = tx_thread_create(&client_thread, "Test Client", thread_client_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    CHECK_STATUS(0, status);

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "Test Client Packet Pool", PACKET_SIZE, 
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    CHECK_STATUS(0, status);

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip, "Test Client IP", TEST_CLIENT_ADDRESS, 
                          0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    CHECK_STATUS(0, status);

    status  = nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    CHECK_STATUS(0, status);

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip);
    CHECK_STATUS(0, status);

    /* Create semaphores.  */
    tx_semaphore_create(&semaphore_server_start, "semaphore server start", 0);
    tx_semaphore_create(&semaphore_client_done, "semaphore client done", 0);
}

void thread_client_entry(ULONG thread_input)
{
UINT            i, j, status;
NX_PACKET       *packet_ptr;
NXD_ADDRESS     server_ip_address;


    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = TEST_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    status = nx_tcp_socket_create(&client_ip, &rtsp_client, "Test Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    CHECK_STATUS(0, status);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&rtsp_client, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Wait test server started.  */
    tx_semaphore_get(&semaphore_server_start, NX_WAIT_FOREVER);

    for (i = 0 ; i < TEST_LOOP; i++)
    {

        status = nxd_tcp_client_socket_connect(&rtsp_client, &server_ip_address, RTSP_SERVER_PORT, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Set static session ID for test.  */
        for (j = 0; j < NX_RTSP_SERVER_MAX_CLIENTS; j++)
        {
            rtsp_server.nx_rtsp_server_client_list[j].nx_rtsp_client_session_id = 23754311;
        }

        /* Send data.  */
        status = nx_packet_allocate(&client_pool, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, test_data, test_size[i][0], &client_pool, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_tcp_socket_send(&rtsp_client, packet_ptr, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Send data 1.  */
        status = nx_packet_allocate(&client_pool, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, test_data + test_size[i][0], test_size[i][1], &client_pool, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_tcp_socket_send(&rtsp_client, packet_ptr, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Send data 2.  */
        status = nx_packet_allocate(&client_pool, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, test_data + test_size[i][0] + test_size[i][1], test_size[i][2], &client_pool, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_tcp_socket_send(&rtsp_client, packet_ptr, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Receive the response from server.  */
        status = nx_tcp_socket_receive(&rtsp_client, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Check response status code.  */
        status = memcmp(packet_ptr -> nx_packet_prepend_ptr, expected_response, sizeof(expected_response) - 1);
        CHECK_STATUS(0, status);

        nx_packet_release(packet_ptr);

        nx_tcp_socket_disconnect(&rtsp_client, NX_IP_PERIODIC_RATE);
    }


    /* Set the flag.  */
    tx_semaphore_put(&semaphore_client_done);
    nx_tcp_client_socket_unbind(&rtsp_client);
    nx_tcp_socket_delete(&rtsp_client);
}

/* Define the helper Test server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT status;

    /* Print out test information banner.  */
    printf("NetX Test:   RTSP Multiple Request Test................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Give NetX a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Create RTSP server.  */
    status = nx_rtsp_server_create(&rtsp_server, "RTSP Server", sizeof("RTSP Server") - 1,&server_ip, &server_pool, rtsp_stack, DEMO_STACK_SIZE, 3, RTSP_SERVER_PORT, rtsp_disconnect_callback);
    CHECK_STATUS(0, status);

    /* Set callback functions. */
    nx_rtsp_server_describe_callback_set(&rtsp_server, rtsp_describe_callback);
    nx_rtsp_server_setup_callback_set(&rtsp_server, rtsp_setup_callback);
    nx_rtsp_server_play_callback_set(&rtsp_server, rtsp_play_callback);
    nx_rtsp_server_teardown_callback_set(&rtsp_server, rtsp_teardown_callback);
    nx_rtsp_server_pause_callback_set(&rtsp_server, rtsp_pause_callback);
    nx_rtsp_server_set_parameter_callback_set(&rtsp_server, rtsp_set_parameter_callback);

    /* Start RTSP server. */
    nx_rtsp_server_start(&rtsp_server);

    tx_semaphore_put(&semaphore_server_start);

    tx_semaphore_get(&semaphore_client_done, NX_WAIT_FOREVER);

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


static UINT rtsp_describe_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length)
{
    return(NX_SUCCESS);
}

static UINT rtsp_setup_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr)
{
    return(NX_SUCCESS);
}

static UINT rtsp_play_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length)
{
    return(NX_SUCCESS);
}

static UINT rtsp_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length)
{

    return(NX_SUCCESS);
}

static UINT rtsp_pause_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length)
{
    return(NX_SUCCESS);
}

static UINT rtsp_set_parameter_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length)
{

    if ((parameter_length != 20) || (memcmp(parameter_ptr, "barparam: barstuff", sizeof("barparam: barstuff") - 1) != 0))
    {
        error_counter++;
        CHECK_STATUS(0, error_counter);
    }
    return(NX_SUCCESS);
}

static UINT rtsp_disconnect_callback(NX_RTSP_CLIENT *rtsp_client_ptr)
{
    return(NX_SUCCESS);
}


#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtsp_multiple_request_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RTSP Multiple Request Test................................N/A\n"); 

    test_control_return(3);  
}      
#endif

