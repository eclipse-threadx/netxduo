/* This case tests websocket connect corresponding logic, especially focusing on testing secure connect feature */
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

#ifdef NX_SECURE_ENABLE

#include "../web_test/test_device_cert.c"
#include "../web_test/test_ca_cert.c"

/* Declare external cryptosuites. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

static NX_SECURE_TLS_SESSION tls_client_session;
static NX_SECURE_TLS_SESSION tls_server_session;
static NX_SECURE_X509_CERT server_local_certificate;

/* Define crypto metadata buffer. */
static UCHAR client_metadata[5*4096];
static UCHAR server_metadata[5*4096];

/* For remote certificate. */
static NX_SECURE_X509_CERT remote_certificate, remote_issuer, ca_certificate;
static UCHAR remote_cert_buffer[2000];
static UCHAR remote_issuer_buffer[2000];
static UCHAR tls_packet_buffer[2][4096];

#endif /* NX_SECURE_ENABLE */


static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);

#define TEST_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define TEST_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)
#define TEST_SERVER_PORT     80

#define TEST_HOST_NAME       "1.2.3.4"
#define TEST_URI_PATH        "/test"
#define TEST_PROTOCOL        "test"

static UCHAR bad_server_switch_101[] =
{
0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20,                                      // HTTP1.1/
0x31, 0x30, 0x31, 0x20, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x20,        // 101 Switching
0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x73, //0x0d, 0x0a,                        // Protocols\r\n
0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x3a, 0x20,                                      // Upgrade:
0x57, 0x65, 0x62, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x0d, 0x0a,                          // WebSocket\r\n
0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20,                    // Connection:
0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x0d, 0x0a,                                      // Upgrade\r\n
0x53, 0x65, 0x63, 0x2d, 0x57, 0x65, 0x62, 0x53, 0x6f, 0x63, 0x6b, 0x65,                    // Sec-WebSocket-Protocol:
0x74, 0x2d, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x3a, 0x20,
0x74, 0x65, 0x73, 0x74, 0x0d, 0x0a,                                                      // test
0x53, 0x65, 0x63, 0x2d, 0x57, 0x65, 0x62, 0x53, 0x6f, 0x63, 0x6b,                          // Sec-WebSocket-Accept:
0x65, 0x74, 0x2d, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
0x35, 0x75, 0x31, 0x6c, 0x55, 0x72, 0x32, 0x57, 0x68, 0x70, 0x34, 0x64, 0x44, 0x57, 0x6e,  // 5u1lUr2Whp4dDWnskk9JcJZobO0=
0x73, 0x6b, 0x6b, 0x39, 0x4a, 0x63, 0x4a, 0x5a, 0x6f, 0x62, 0x4f, 0x30, 0x3d, 0x0d, 0x0a,
0x0d, 0x0a,
};

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
void    netx_websocket_connect_test_application_define(void *first_unused_memory)
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

#ifdef NX_SECURE_ENABLE

/* Define the callback function for tls connection. */
static UINT client_tls_setup(NX_SECURE_TLS_SESSION* tls_session)
{
UINT status;

    /* Create a tls session. */
    status = nx_secure_tls_session_create(tls_session,
                                          &nx_crypto_tls_ciphers,
                                          client_metadata,
                                          sizeof(client_metadata));

    if (status)
    {
        return status;
    }
    
    nx_secure_tls_session_packet_buffer_set(tls_session, tls_packet_buffer[0], sizeof(tls_packet_buffer[0]));
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));

    nx_secure_x509_certificate_initialize(&ca_certificate, test_ca_cert_der, test_ca_cert_der_len,
                                          NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(tls_session, &ca_certificate);

    return(NX_SUCCESS);
}

static UINT server_tls_setup(NX_SECURE_TLS_SESSION *tls_session)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session,
                                          &nx_crypto_tls_ciphers,
                                          server_metadata,
                                          sizeof(server_metadata));
    if (status)
    {
        return status;
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    nx_secure_x509_certificate_initialize(&server_local_certificate,
                                          test_device_cert_der, test_device_cert_der_len,
                                          NX_NULL, 0, test_device_cert_key_der,
                                          test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);

    nx_secure_tls_local_certificate_add(tls_session, &server_local_certificate);

    nx_secure_tls_session_packet_buffer_set(tls_session, tls_packet_buffer[1], sizeof(tls_packet_buffer[1]));

    return(NX_SUCCESS);
}
#endif /* NX_SECURE_ENABLE */

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
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create WebSocket.  */
    status = nx_websocket_client_create(&client_websocket, (UCHAR *)" ", &client_ip, &client_pool);
    if (status || client_websocket.nx_websocket_client_mutex.tx_mutex_ownership_count != 0)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&test_client, TEST_SERVER_PORT, NX_IP_PERIODIC_RATE);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Wait test server started.  */
    while(!test_server_start)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = TEST_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    status = nxd_tcp_client_socket_connect(&test_client, &server_ip_address, TEST_SERVER_PORT, NX_IP_PERIODIC_RATE);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Upgrade to websocket */
    status = nx_websocket_client_connect(&client_websocket, &test_client,
                                         TEST_HOST_NAME, sizeof(TEST_HOST_NAME) - 1,
                                         (UCHAR *)TEST_URI_PATH, sizeof(TEST_URI_PATH) - 1,
                                         (UCHAR *)TEST_PROTOCOL, sizeof(TEST_PROTOCOL) - 1,
                                         NX_WAIT_FOREVER);

    /* The first time is to test whether the bad response from server will be checked and found */
    if (status != NX_WEBSOCKET_INVALID_PACKET || client_websocket.nx_websocket_client_mutex.tx_mutex_ownership_count != 0)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Upgrade to websocket */
    status = nx_websocket_client_connect(&client_websocket, &test_client,
                                         TEST_HOST_NAME, sizeof(TEST_HOST_NAME) - 1,
                                         (UCHAR *)TEST_URI_PATH, sizeof(TEST_URI_PATH) - 1,
                                         (UCHAR *)TEST_PROTOCOL, sizeof(TEST_PROTOCOL) - 1,
                                         NX_WAIT_FOREVER);
    if (status || client_websocket.nx_websocket_client_mutex.tx_mutex_ownership_count != 0)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    status = nx_websocket_client_delete(&client_websocket);
    if (status || client_websocket.nx_websocket_client_mutex.tx_mutex_ownership_count != 0)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

#ifdef NX_SECURE_ENABLE
    /* Re-create WebSocket for secure test.  */
    status = nx_websocket_client_create(&client_websocket, (UCHAR *)" ", &client_ip, &client_pool);
    if (status || client_websocket.nx_websocket_client_mutex.tx_mutex_ownership_count != 0)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    client_tls_setup(&tls_client_session);

    status = nx_secure_tls_session_start(&tls_client_session, &test_client, NX_WAIT_FOREVER);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    status = nx_websocket_client_secure_connect(&client_websocket, &tls_client_session,
                                                TEST_HOST_NAME, sizeof(TEST_HOST_NAME) - 1,
                                                (UCHAR *)TEST_URI_PATH, sizeof(TEST_URI_PATH) - 1,
                                                (UCHAR *)TEST_PROTOCOL, sizeof(TEST_PROTOCOL) - 1,
                                                NX_WAIT_FOREVER);
    if (status || client_websocket.nx_websocket_client_mutex.tx_mutex_ownership_count != 0)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    else
    {
        status = nx_secure_tls_packet_allocate(&tls_client_session, &client_pool, &packet_ptr, NX_NO_WAIT);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        /* Append client test data.  */
        status = nx_packet_data_append(packet_ptr, client_test_data, sizeof(client_test_data), &client_pool, NX_NO_WAIT);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        status = nx_secure_tls_session_send(&tls_client_session, packet_ptr, NX_WAIT_FOREVER);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        status = nx_secure_tls_session_receive(&tls_client_session, &packet_ptr, NX_WAIT_FOREVER);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        nx_packet_release(packet_ptr);
    }

    nx_websocket_client_delete(&client_websocket);
    if (client_websocket.nx_websocket_client_mutex.tx_mutex_ownership_count != 0)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* End session.  */
    nx_secure_tls_session_delete(&tls_client_session);
    
#endif

    /* TCP Disconnect.  */
    status = nx_tcp_socket_disconnect(&test_client, NX_IP_PERIODIC_RATE);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

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
    printf("NetX Test:   Websocket Connect Test.....................................");

    /* Check for earlier error.  */
    if (error_counter)
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
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

#ifdef NX_SECURE_ENABLE
    /* Session setup.  */
    server_tls_setup(&tls_server_session);
#endif

    /* Set the flag.  */
    test_server_start = 1;

    /* Accept a connection from test client.  */
    status = nx_tcp_server_socket_accept(&test_server, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    
    /* Bad server response test */
    status = nx_tcp_socket_receive(&test_server, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    else
    {
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;
        packet_ptr -> nx_packet_length = 0;
        nx_packet_data_append(packet_ptr, bad_server_switch_101, sizeof(bad_server_switch_101), &server_pool, NX_IP_PERIODIC_RATE);
        status = nx_tcp_socket_send(&test_server, packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }

    /* ---- Insecure websocket connect test ---- */
    status = nx_tcp_socket_receive(&test_server, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    else
    {
        /* Update the value in the field Sec-Protocol-Accept since it is calculated based on a random value */
        _server_connect_response_process(packet_ptr);
        memcpy(&server_switch_101[127], connect_key, 28);

        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;
        packet_ptr -> nx_packet_length = 0;
        nx_packet_data_append(packet_ptr, server_switch_101, sizeof(server_switch_101), &server_pool, NX_IP_PERIODIC_RATE);
        status = nx_tcp_socket_send(&test_server, packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }

    /* ---- Secure websocket connect test ---- */

#ifdef NX_SECURE_ENABLE

    status = nx_secure_tls_session_start(&tls_server_session, &test_server, NX_WAIT_FOREVER);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    tx_thread_sleep(1);

    status = nx_secure_tls_session_receive(&tls_server_session, &packet_ptr, NX_WAIT_FOREVER);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    _server_connect_response_process(packet_ptr);
    memcpy(&server_switch_101[127], connect_key, 28);
    nx_packet_release(packet_ptr);

    status = nx_secure_tls_packet_allocate(&tls_server_session, &server_pool, &packet_ptr, NX_NO_WAIT);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    /* Append response 101.  */
    status = nx_packet_data_append(packet_ptr, server_switch_101, sizeof(server_switch_101), &server_pool, NX_NO_WAIT);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    status = nx_secure_tls_session_send(&tls_server_session, packet_ptr, NX_WAIT_FOREVER);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Receive client data.  */
    status = nx_secure_tls_session_receive(&tls_server_session, &packet_ptr, NX_IP_PERIODIC_RATE);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    nx_packet_release(packet_ptr);
    /* Send a response */
    status = nx_secure_tls_packet_allocate(&tls_server_session, &server_pool, &packet_ptr, NX_NO_WAIT);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    nx_packet_data_append(packet_ptr, server_response_1, sizeof(server_response_1), &server_pool, NX_IP_PERIODIC_RATE);
    status = nx_secure_tls_session_send(&tls_server_session, packet_ptr, NX_WAIT_FOREVER);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    nx_packet_release(packet_ptr);

    /* End session.  */
    nx_secure_tls_session_end(&tls_server_session, NX_NO_WAIT);
#endif

    /* Disconnect.  */
    status = nx_tcp_socket_disconnect(&test_server, NX_IP_PERIODIC_RATE);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&test_server);
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

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

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_websocket_connect_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Websocket Connect Test.....................................N/A\n");

    test_control_return(3);
}
#endif

