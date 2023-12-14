/* This test TLS 1.3 server process empty KeyShare and two KeyShares.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "ecc_certs.c"
#include   "nx_crypto_aes.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && (NX_SECURE_TLS_TLS_1_3_ENABLED)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define SERVER_PORT                 4433

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_server;
static TX_THREAD                thread_client;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static UINT                     error_counter;

static NX_TCP_SOCKET            client_socket_0;
static NX_SECURE_TLS_SESSION    tls_client_session_0;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      client_local_certificate;
static NX_TCP_SOCKET            server_socket_0;
static NX_SECURE_TLS_SESSION    tls_server_session_0;
static NX_SECURE_X509_CERT      server_trusted_ca;
static NX_SECURE_X509_CERT      server_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_server_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_client_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];
static UCHAR                    server_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    tls_packet_buffer[2][4000];

extern const                    UCHAR _nx_secure_tls_hello_retry_request_random[32];
extern const                    USHORT nx_crypto_ecc_supported_groups[];
extern const                    NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const                    UINT nx_crypto_ecc_supported_groups_size;
extern const                    NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

extern const NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_tls_1_3[];
extern const UINT _nx_crypto_ciphersuite_lookup_table_tls_1_3_size;


/* Define thread prototypes.  */

static VOID    test_client_entry(ULONG thread_input);
static VOID    test_server_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static UINT    tls_session_start_test(NX_SECURE_TLS_SESSION *tls_session, NX_TCP_SOCKET *tcp_socket, UINT wait_option);

/* Define what the initial system looks like.  */

static VOID    ERROR_COUNTER()
{
    error_counter++;
}

#define do_something_if_fail( p) if(!(p)){ERROR_COUNTER();}

static UCHAR cookie[] = "This is cookie!!!";
static UCHAR hello_retry_request[] = {
0x03, 0x03,
/* server_random */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00,
0x13, 0x01,
0x00,
0x00, 0x0c + 4 + sizeof(cookie), /* extension length */
0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
0x00, 0x33, 0x00, 0x02, 0x00, 0x17,
/* cookie extension */
0x00, 0x2c, /* cookie type code */
0x00, sizeof(cookie) + 2, /* extension length */
0x00, sizeof(cookie), /* cookie length */
};

static ULONG   cookie_check_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extensions, UINT num_extensions)
{
UCHAR *packet_buffer, cookie_extension[6 + sizeof(cookie)];
USHORT message_length, i;

    cookie_extension[0] = 0x00;
    cookie_extension[1] = 0x2c;
    cookie_extension[2] = 0x00;
    cookie_extension[3] = sizeof(cookie) + 2;
    cookie_extension[4] = 0x00;
    cookie_extension[5] = sizeof(cookie);
    memcpy(&cookie_extension[6], cookie, sizeof(cookie));
    packet_buffer = tls_session -> nx_secure_tls_packet_buffer;
    message_length = (packet_buffer[2] << 8) + packet_buffer[3];
    /* Find out cookie extension. */
    for(i = 0; i < message_length - sizeof(cookie_extension); i++)
    {
        if (!memcmp(&packet_buffer[i], cookie_extension, sizeof(cookie_extension)))
        {
            return(NX_SUCCESS);
        }
    }

    do_something_if_fail(0);
    return(NX_SUCCESS);
}

static TX_SEMAPHORE            semaphore_server;

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_hello_retry_cookie_test_application_define(void *first_unused_memory)
#endif
{
UINT     status;
CHAR    *pointer;


    error_counter = 0;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&thread_server, "thread server", test_server_entry, 0,
                     thread_server_stack, sizeof(thread_server_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Create the client thread.  */
    tx_thread_create(&thread_client, "thread client", test_client_entry, 0,
                     thread_client_stack, sizeof(thread_client_stack),
                     8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_semaphore_create(&semaphore_server, "semaphore server", 0);

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE,
                                    pool_0_memory, PACKET_POOL_SIZE);
    do_something_if_fail(status == NX_SUCCESS);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &pool_0, _nx_ram_network_driver_1500,
                          ip_0_stack, sizeof(ip_0_stack), 1);
    do_something_if_fail(status == NX_SUCCESS);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (VOID *)arp_cache, sizeof(arp_cache));
    do_something_if_fail(status == NX_SUCCESS);

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    do_something_if_fail(status == NX_SUCCESS);

    nx_secure_tls_initialize();
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                          &nx_crypto_tls_ciphers_ecc,
                                          client_metadata,
                                          sizeof(client_metadata));
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    do_something_if_fail(status == NX_SUCCESS);

    memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &client_remote_cert,
                                                       client_cert_buffer,
                                                       sizeof(client_cert_buffer));
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca, ECCA4_der, ECCA4_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr, &client_trusted_ca);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    do_something_if_fail(status == NX_SUCCESS);
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           server_metadata,
                                           sizeof(server_metadata));
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    do_something_if_fail(status == NX_SUCCESS);

    memset(&server_remote_cert, 0, sizeof(server_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &server_remote_cert,
                                                       server_cert_buffer,
                                                       sizeof(server_cert_buffer));
    do_something_if_fail(status == NX_SUCCESS);

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   ECTestServer4_der, ECTestServer4_der_len,
                                                   NX_NULL, 0, ECTestServer4_key_der,
                                                   ECTestServer4_key_der_len,
                                                   NX_SECURE_X509_KEY_TYPE_EC_DER);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                 &server_local_certificate);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[1],
                                                     sizeof(tls_packet_buffer[1]));
    do_something_if_fail(status == NX_SUCCESS);

    status = _nx_secure_tls_session_server_callback_set(tls_session_ptr, cookie_check_callback);
    do_something_if_fail(status == NX_SUCCESS);
}

static void test_server_entry(ULONG thread_input)
{
UINT status;
NX_PACKET *packet_ptr;
UCHAR receive_buffer[64];
ULONG receive_length;
UINT i = 0;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 HelloRetry Cookie Test.....................");

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &server_socket_0, "Server socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_tcp_server_socket_listen(&ip_0, SERVER_PORT, &server_socket_0, 5, NX_NULL);
    do_something_if_fail(status == NX_SUCCESS);

    server_tls_setup(&tls_server_session_0);

    tx_semaphore_put(&semaphore_server);

    status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);

    /* Start TLS session. */
    tls_session_start_test(&tls_server_session_0, &server_socket_0, NX_WAIT_FOREVER);

    nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
    nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
    nx_tcp_server_socket_unaccept(&server_socket_0);

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

static void test_client_entry(ULONG thread_input)
{
UINT status;
NX_PACKET *packet_ptr;
NXD_ADDRESS server_address;
UINT i;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    do_something_if_fail(status == NX_SUCCESS);

    client_tls_setup(&tls_client_session_0);

    tx_semaphore_get(&semaphore_server, NX_WAIT_FOREVER);

    status = nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);

    /* Start TLS session. */
    status = tls_session_start_test(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);

    nx_secure_tls_session_delete(&tls_client_session_0);
    nx_tcp_client_socket_unbind(&client_socket_0);
    nx_tcp_socket_delete(&client_socket_0);
}

/* Rewrite the session start function. 
   For the first loop, client will send ClientHello with two KeyShares.
   For the second loop, client will send ClientHello with empty KeyShare. */
static UINT tls_session_start_test(NX_SECURE_TLS_SESSION *tls_session, NX_TCP_SOCKET *tcp_socket,
                                  UINT wait_option)
{
UINT gmt_time, random_value, i;
USHORT protocol_version;
UINT       status = NX_NOT_SUCCESSFUL;
UINT       error_return;
#ifndef NX_SECURE_TLS_CLIENT_DISABLED
NX_PACKET *send_packet;
#endif
NX_SECURE_TLS_ECDHE_HANDSHAKE_DATA   *ecdhe_data;

    /* Get the protection. */
    tx_mutex_get(&_nx_secure_tls_protection, TX_WAIT_FOREVER);

    /* Assign the packet pool from which TLS will allocate internal message packets. */
    tls_session -> nx_secure_tls_packet_pool = tcp_socket -> nx_tcp_socket_ip_ptr -> nx_ip_default_packet_pool;

    /* Assign the TCP socket to the TLS session. */
    tls_session -> nx_secure_tls_tcp_socket = tcp_socket;

    /* Reset the record queue. */
    tls_session -> nx_secure_record_queue_header = NX_NULL;
    tls_session -> nx_secure_record_decrypted_packet = NX_NULL;

    /* Make sure we are starting with a fresh session. */
    tls_session -> nx_secure_tls_local_session_active = 0;
    tls_session -> nx_secure_tls_remote_session_active = 0;
    tls_session -> nx_secure_tls_received_remote_credentials = NX_FALSE;

    /* See if this is a TCP server started with listen/accept, or a TCP client started with connect. */
    if (tcp_socket -> nx_tcp_socket_client_type)
    {
        /* The TCP socket is a client, so our TLS session is a TLS Client. */
        tls_session -> nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    }
    else
    {
        /* This session is now being treated as a server - indicate that fact to the TLS stack. */
        tls_session -> nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    }

    status = _nx_secure_tls_1_3_crypto_init(tls_session);
    do_something_if_fail(status == NX_SUCCESS);

    if (tls_session -> nx_secure_tls_socket_type == NX_SECURE_TLS_SESSION_TYPE_SERVER)
    {

        tls_session -> nx_secure_tls_server_state = NX_SECURE_TLS_SERVER_STATE_SEND_HELLO_RETRY;
        _nx_secure_tls_protocol_version_get(tls_session, &protocol_version, NX_SECURE_TLS);
        tls_session -> nx_secure_tls_protocol_version = protocol_version;

        /* Install server random. */
        NX_SECURE_MEMCPY(tls_session -> nx_secure_tls_key_material.nx_secure_tls_server_random, _nx_secure_tls_hello_retry_request_random, sizeof(_nx_secure_tls_hello_retry_request_random));
        NX_SECURE_MEMCPY(tls_session -> nx_secure_tls_key_material.nx_secure_tls_client_random, _nx_secure_tls_hello_retry_request_random, sizeof(_nx_secure_tls_hello_retry_request_random));

        /* Allocate a handshake packet so we can send the ServerHello. */
        status = _nx_secure_tls_allocate_handshake_packet(tls_session, tls_session -> nx_secure_tls_packet_pool, &send_packet, wait_option);
        do_something_if_fail(status == NX_SUCCESS);

        /* Populate our packet with HelloRetryRequest and cookie data. */
        NX_SECURE_MEMCPY(&hello_retry_request[2], _nx_secure_tls_hello_retry_request_random, sizeof(_nx_secure_tls_hello_retry_request_random));
        status = nx_packet_data_append(send_packet, hello_retry_request, sizeof(hello_retry_request), tls_session -> nx_secure_tls_packet_pool, NX_NO_WAIT);
        status += nx_packet_data_append(send_packet, cookie, sizeof(cookie), tls_session -> nx_secure_tls_packet_pool, NX_NO_WAIT);
        do_something_if_fail(status == NX_SUCCESS);

        status = _nx_secure_tls_send_handshake_record(tls_session, send_packet, NX_SECURE_TLS_SERVER_HELLO, wait_option);
        do_something_if_fail(status == NX_SUCCESS);
    }
    else
    /* Initialize client session as if we sent a ClientHello. */
    {

        _nx_secure_tls_protocol_version_get(tls_session, &protocol_version, NX_SECURE_TLS);
        tls_session -> nx_secure_tls_protocol_version = protocol_version;

        NX_SECURE_MEMCPY(tls_session -> nx_secure_tls_key_material.nx_secure_tls_server_random, _nx_secure_tls_hello_retry_request_random, sizeof(_nx_secure_tls_hello_retry_request_random));
        NX_SECURE_MEMCPY(tls_session -> nx_secure_tls_key_material.nx_secure_tls_client_random, _nx_secure_tls_hello_retry_request_random, sizeof(_nx_secure_tls_hello_retry_request_random));
    }

    /* Release the protection. */
    tx_mutex_put(&_nx_secure_tls_protection);

    /* Handshake failed since serverhello did not provide any key shares. */
    _nx_secure_tls_handshake_process(tls_session, wait_option);

    return(status);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_hello_retry_cookie_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 HelloRetry Cookie Test.....................N/A\n");
    test_control_return(3);
}
#endif
