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

static TX_SEMAPHORE            semaphore_server;

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_invalid_client_state_test_application_define(void *first_unused_memory)
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
}

static void test_server_entry(ULONG thread_input)
{
UINT status;
USHORT protocol_version;
NX_PACKET *packet_ptr, *send_packet;
UCHAR buffer[32];

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Invalid Client State Test..................");

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

    tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
    tls_server_session_0.nx_secure_tls_packet_pool = &pool_0;
    tls_server_session_0.nx_secure_tls_tcp_socket = &server_socket_0;
    tls_server_session_0.nx_secure_tls_protocol_version = 0x0303;
    tx_mutex_put(&_nx_secure_tls_protection);

    /* Receive ClientHello */
    status =  nx_tcp_socket_receive(&server_socket_0, &packet_ptr, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);
    nx_packet_release(packet_ptr);

    /* Send a handshake message with invalid message type. */
    /* Client will receive NEW_SESSION_TICKET while client_state is unknown. */
    tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
    tls_client_session_0.nx_secure_tls_client_state = 0xfe;
    status = _nx_secure_tls_allocate_handshake_packet(&tls_server_session_0, &pool_0, &send_packet, NX_WAIT_FOREVER);
    status += _nx_secure_tls_send_handshake_record(&tls_server_session_0, send_packet, NX_SECURE_TLS_NEW_SESSION_TICKET, NX_WAIT_FOREVER);
    tx_mutex_put(&_nx_secure_tls_protection);
    do_something_if_fail(status == NX_SUCCESS);

    /* Receive alert */
    status =  nx_tcp_socket_receive(&server_socket_0, &packet_ptr, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);
    nx_packet_release(packet_ptr);

    /* Receive ClientHello */
    status =  nx_tcp_socket_receive(&server_socket_0, &packet_ptr, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);
    nx_packet_release(packet_ptr);

    /* Send a handshake message while CLIENT_STATE_ERROR. */
    tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
    tls_client_session_0.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_ERROR;
    status = _nx_secure_tls_allocate_handshake_packet(&tls_server_session_0, &pool_0, &send_packet, NX_WAIT_FOREVER);
    status += _nx_secure_tls_send_handshake_record(&tls_server_session_0, send_packet, NX_SECURE_TLS_NEW_SESSION_TICKET, NX_WAIT_FOREVER);
    tx_mutex_put(&_nx_secure_tls_protection);
    do_something_if_fail(status == NX_SUCCESS);

    /* Receive alert */
    status =  nx_tcp_socket_receive(&server_socket_0, &packet_ptr, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);
    nx_packet_release(packet_ptr);

    status =  nx_tcp_socket_receive(&server_socket_0, &packet_ptr, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);
    nx_packet_release(packet_ptr);

    /* Send a handshake message while CLIENT_STATE_IDLE. */
    tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
    tls_client_session_0.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_IDLE;
    status = _nx_secure_tls_allocate_handshake_packet(&tls_server_session_0, &pool_0, &send_packet, NX_WAIT_FOREVER);
    status += _nx_secure_tls_send_handshake_record(&tls_server_session_0, send_packet, NX_SECURE_TLS_NEW_SESSION_TICKET, NX_WAIT_FOREVER);
    tx_mutex_put(&_nx_secure_tls_protection);
    do_something_if_fail(status == NX_SUCCESS);

    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
    nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
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
    status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SECURE_TLS_INVALID_STATE);

    status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SECURE_TLS_HANDSHAKE_FAILURE);

    status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_NOT_CONNECTED);

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
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_invalid_client_state_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Invalid Client State Test..................N/A\n");
    test_control_return(3);
}
#endif
