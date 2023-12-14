/* Length and bounds checking tests. Length fields are the most likely to be exploited by an attacker so we need to be sure all of our parsing is checking them correctly.
One idea: generate a number of valid TLS handshake messages but use random lengths for each length field. 
Focus particularly on ClientHello and ServerHello extensions. Bugs like Heartbleed in OpenSSL occur in those extensions. Pay close attention to any length fields in the extensions.

 */

#include   "nx_api.h"
#include   "nx_secure_tls.h"
#include   "nx_secure_tls_api.h"
#include   "nx_crypto_ecdh.h"
#include   "ecc_certs.c"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define SERVER_PORT                 4433
#define CIPHERSUITE_INIT(p, s, c)   {p, sizeof(p) / sizeof(UINT), s, c}
#define CERTIFICATE_INIT(s, k, c, t) {s, sizeof(s), k, sizeof(k), c, sizeof(c), t}

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static TX_THREAD                thread_1;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static UINT                     error_counter;

static NX_TCP_SOCKET            client_socket_0;
static NX_TCP_SOCKET            server_socket_0;
static NX_SECURE_TLS_SESSION    tls_client_session_0;
static NX_SECURE_TLS_SESSION    tls_server_session_0;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;
static NX_SECURE_TLS_CRYPTO     tls_ciphers_client;
static NX_SECURE_TLS_CRYPTO     tls_ciphers_server;
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table_client[10];
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table_server[10];

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_1_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    request_buffer[BUFFER_SIZE];
static UCHAR                    response_buffer[BUFFER_SIZE];
static UCHAR                    tls_packet_buffer[2][4000];

extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc[];
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


#define do_something_if_fail( p) if(!(p)){ERROR_COUNTER();}
/* Define what the initial system looks like.  */


static VOID    ERROR_COUNTER()
{
    error_counter++;
}

static UCHAR client_hello_empty_key_share[] = {
0x03, 0x03,
0x00, 0x00, 0x00, 0x00, 0x25, 0x3b, 0x00, 0x00, 0x1f, 0x1e, 0x00, 0x00, 0x5d, 0x6e, 0x00, 0x00,
0xd4, 0x1a, 0x00, 0x00, 0xcb, 0x63, 0x00, 0x00, 0xfc, 0x6b, 0x00, 0x00, 0x96, 0x7f, 0x00, 0x00,
0x00, /* session id length */
0x00, 0x34, /* ciphersuites */
0x13, 0x01, 0x13, 0x04, 0x13, 0x05, 0xc0, 0x23, 0xc0, 0x09, 0xc0, 0x0a, 0xc0, 0x27, 0xc0, 0x13,
0xc0, 0x14, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x3d, 0x00, 0x35, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0x9c,
0xc0, 0x25, 0xc0, 0x04, 0xc0, 0x05, 0xc0, 0x29, 0xc0, 0x0e, 0xc0, 0x0f, 0xc0, 0x2d, 0xc0, 0x31,
0x00, 0x02, 0x00, 0x01,
0x01, /* compression method */
0x00,
0x00, 0x41, /* extensions */
0x00, 0x0a, /* ec groups */
0x00, 0x08,
0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
0x00, 0x0b, /* ec point formats */
0x00, 0x02,
0x01, 0x00,
0x00, 0x2b, /* supported versions */
0x00, 0x07,
0x06, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02,
0x00, 0x33, /* key shares */
0x00, 0x02,
0x00, 0x00,
0x00, 0x0d, /* signature algorithms */
0x00, 0x16,
0x00, 0x14,
0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x02, 0x03,
0x02, 0x01, 0x01, 0x01,
/* empty extension */
0x00, 0x00, 0x00, 0x00,
};

static UCHAR client_hello_size[] = {0x00, 0x9e};

/* various extension types. */
static UCHAR extension_NX_SECURE_TLS_EXTENSION_PRE_SHARED_KEY_ZERO[] = {0x00, 0x29, 0x00, 0x00};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_PRE_SHARED_KEY_MAX_INT[] = {0x00, 0x29, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_SECURE_RENEGOTIATION_ZERO[] = {0xff, 0x01, 0x00, 0x00};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_SECURE_RENEGOTIATION_MAX_INT[] = {0xff, 0x01, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_SERVER_NAME_INDICATION_MAX_INT[] = {0x00, 0x00, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_MAX_FRAGMENT_LENGTH_MAX_INT[] = {0x00, 0x01, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_CLIENT_CERTIFICATE_URL_MAX_INT[] = {0x00, 0x02, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_TRUSTED_CA_INDICATION_MAX_INT[] = {0x00, 0x03, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_TRUNCATED_HMAC_MAX_INT[] = {0x00, 0x04, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_CERTIFICATE_STATUS_REQUEST_MAX_INT[] = {0x00, 0x05, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_EARLY_DATA_MAX_INT[] = {0x00, 0x2a, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES_MAX_INT[] = {0x00, 0x2d, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_CERTIFICATE_AUTHORITIES_MAX_INT[] = {0x00, 0x2f, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_OID_FILTERS_MAX_INT[] = {0x00, 0x30, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_POST_HANDSHAKE_AUTH_MAX_INT[] = {0x00, 0x31, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT_MAX_INT[] = {0x00, 0x32, 0xff, 0xff};
static UCHAR extension_NX_SECURE_TLS_EXTENSION_ECJPAKE_KEY_KP_PAIR_MAX_INT[] = {0x01, 0x00, 0xff, 0xff};

static UCHAR MAX_INT[] = {0xff, 0xff, 0xff, 0xff};
static UCHAR MAX_CIPHERS[] = {0xff, 0xfe};
static UCHAR ZERO[] = {0x00, 0x00, 0x00, 0x00};
static UCHAR EMPTY_CIPHERSUITE_LIST_AND_COMPRESSION_METHODS[] = {
0x00, 0x00,
0x35,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00,
};
typedef struct
{
    UINT expected_return;
    UINT location;
    UCHAR *value, size;
} TEST_POINT;

static TEST_POINT test_array[] =
{
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 34, MAX_INT, 1}, /* session id length = 0xff. */
    {NX_SECURE_TLS_SUCCESS, 35, NULL, 0}, /* ciphersuites length is valid. */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 35, MAX_INT, 2}, /* ciphersuites length = 0xffff. */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 35, ZERO, 2}, /* ciphersuites length = 0x0000. */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 35, EMPTY_CIPHERSUITE_LIST_AND_COMPRESSION_METHODS, sizeof(EMPTY_CIPHERSUITE_LIST_AND_COMPRESSION_METHODS)}, /* ciphersuites length = 0x0000. */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 35, MAX_CIPHERS, 2}, /* ciphersuites length = MAX_CIPHERS(2^16 - 2). */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 35, client_hello_size, 2}, /* ciphersuites length = entire clienthello size. */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 89, MAX_INT, 1}, /* compression method length = 0xff. */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 91, MAX_INT, 2}, /* total extensions length = 0xff. */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 95, MAX_INT, 2}, /* ec groups extension length field */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 107, MAX_INT, 2}, /* ec point formats extension length field */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 113, MAX_INT, 2}, /* supported versions extension length field */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 124, MAX_INT, 2}, /* key shares extension length field */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 130, MAX_INT, 2}, /* signature algorithms extension length field */
    /* other extension length fields. */
#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_PRE_SHARED_KEY_ZERO, 4},
#endif
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_PRE_SHARED_KEY_MAX_INT, 4},
#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_SECURE_RENEGOTIATION_ZERO, 4},
#endif /* NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_SECURE_RENEGOTIATION_MAX_INT, 4},
#endif /* NX_SECURE_TLS_TLS_1_3_ENABLED */
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_SERVER_NAME_INDICATION_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_MAX_FRAGMENT_LENGTH_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_CLIENT_CERTIFICATE_URL_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_TRUSTED_CA_INDICATION_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_TRUNCATED_HMAC_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_CERTIFICATE_STATUS_REQUEST_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_EARLY_DATA_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_CERTIFICATE_AUTHORITIES_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_OID_FILTERS_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_POST_HANDSHAKE_AUTH_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT_MAX_INT, 4},
    {NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, 154, extension_NX_SECURE_TLS_EXTENSION_ECJPAKE_KEY_KP_PAIR_MAX_INT, 4},
};

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_clienthello_length_checking_test_application_define(void *first_unused_memory)
#endif
{
UINT     status;
CHAR    *pointer;


    error_counter = 0;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&thread_0, "thread 0", ntest_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Create the client thread.  */
    tx_thread_create(&thread_1, "thread 1", ntest_1_entry, 0,
                     thread_1_stack, sizeof(thread_1_stack),
                     8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE,
                                    pool_0_memory, PACKET_POOL_SIZE);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &pool_0, _nx_ram_network_driver_1500,
                          ip_0_stack, sizeof(ip_0_stack), 1);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (VOID *)arp_cache, sizeof(arp_cache));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    do_something_if_fail(!status);

    nx_secure_tls_initialize();
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    status = _nx_secure_tls_session_create(tls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           client_metadata,
                                           sizeof(client_metadata));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &client_remote_cert,
                                                       client_cert_buffer,
                                                       sizeof(client_cert_buffer));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca, ECCA4_der, ECCA4_der_len,
                                                    NX_NULL, 0, NULL, 0,
                                                    NX_SECURE_X509_KEY_TYPE_NONE);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &client_trusted_ca);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    status = _nx_secure_tls_session_create(tls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           server_metadata,
                                           sizeof(server_metadata));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   ECTestServer4_der, ECTestServer4_der_len,
                                                   NX_NULL, 0, ECTestServer4_key_der,
                                                   ECTestServer4_key_der_len,
                                                   NX_SECURE_X509_KEY_TYPE_EC_DER);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                 &server_local_certificate);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[1],
                                                     sizeof(tls_packet_buffer[1]));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);
}

static void ntest_0_entry(ULONG thread_input)
{
UINT status, j;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 ClientHello Length Checking Test...........");

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &server_socket_0, "Server socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_tcp_server_socket_listen(&ip_0, SERVER_PORT, &server_socket_0, 5, NX_NULL);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Make sure client thread is ready. */
    tx_thread_suspend(&thread_0);

    for (j = 0; j < sizeof(test_array)/sizeof(TEST_POINT); j++)
    {

        server_tls_setup(&tls_server_session_0);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0, NX_WAIT_FOREVER);
        do_something_if_fail(test_array[j].expected_return == status);

        nx_secure_tls_session_end(&tls_server_session_0, NX_IP_PERIODIC_RATE);
        nx_secure_tls_session_delete(&tls_server_session_0);

        nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
        nx_tcp_server_socket_unaccept(&server_socket_0);
        nx_tcp_server_socket_relisten(&ip_0, SERVER_PORT, &server_socket_0);
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

static void ntest_1_entry(ULONG thread_input)
{
UINT j;
UINT status;
NX_PACKET *packet_ptr, *send_packet;
NXD_ADDRESS server_address;
UCHAR packet_buffer[256];

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Let server thread run first. */
    tx_thread_resume(&thread_0);

    for (j = 0; j < sizeof(test_array)/sizeof(TEST_POINT); j++)
    {

        client_tls_setup(&tls_client_session_0);

        status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                                NX_WAIT_FOREVER);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

        /* Get the protection. */
        tx_mutex_get(&_nx_secure_tls_protection, TX_WAIT_FOREVER);

        tls_client_session_0.nx_secure_tls_packet_pool = &pool_0;
        tls_client_session_0.nx_secure_tls_tcp_socket = &client_socket_0;
        tls_client_session_0.nx_secure_record_queue_header = NX_NULL;
        tls_client_session_0.nx_secure_record_decrypted_packet = NX_NULL;
        tls_client_session_0.nx_secure_tls_local_session_active = 0;
        tls_client_session_0.nx_secure_tls_remote_session_active = 0;
        tls_client_session_0.nx_secure_tls_received_remote_credentials = NX_FALSE;
        tls_client_session_0.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
        status = _nx_secure_tls_1_3_crypto_init(&tls_client_session_0);
#endif /* NX_SECURE_TLS_TLS_1_3_ENABLED */
        do_something_if_fail(NX_SUCCESS == status);

        /* Send ClientHello. */
        status = _nx_secure_tls_allocate_handshake_packet(&tls_client_session_0, tls_client_session_0.nx_secure_tls_packet_pool, &send_packet, NX_WAIT_FOREVER);
        NX_SECURE_MEMCPY(packet_buffer, client_hello_empty_key_share, sizeof(client_hello_empty_key_share));
        /* Modify length fields. */
        NX_SECURE_MEMCPY(packet_buffer + test_array[j].location, test_array[j].value, test_array[j].size);
        status += nx_packet_data_append(send_packet, packet_buffer, sizeof(client_hello_empty_key_share), tls_client_session_0.nx_secure_tls_packet_pool, NX_NO_WAIT);
        status += _nx_secure_tls_send_handshake_record(&tls_client_session_0, send_packet, NX_SECURE_TLS_CLIENT_HELLO, NX_WAIT_FOREVER);
        do_something_if_fail(NX_SUCCESS == status);

        tx_mutex_put(&_nx_secure_tls_protection);

        _nx_secure_tls_handshake_process(&tls_client_session_0, NX_WAIT_FOREVER);
        nx_secure_tls_session_end(&tls_client_session_0, NX_IP_PERIODIC_RATE);
        nx_secure_tls_session_delete(&tls_client_session_0);

        nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    }
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_clienthello_length_checking_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 ClientHello Length Checking Test...........N/A\n");
    test_control_return(3);
}
#endif
