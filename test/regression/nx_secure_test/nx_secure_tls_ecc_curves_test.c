/* This test concentrates on TLS ECC curve selection.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "nx_crypto_ecdh.h"
#include   "ecc_certs.c"

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
#define CERTIFICATE_INIT(s, k, c, t) {s, sizeof(s), k, sizeof(k), c, sizeof(c), t}
#define TEST_CASE_INIT(g, c, s, t)  {g, sizeof(g) / sizeof(USHORT),\
                                     c, sizeof(c) / sizeof(NX_CRYPTO_METHOD *), s, t}

typedef struct
{
    UCHAR *server_cert;
    UINT   server_cert_len;
    UCHAR *server_key;
    UINT   server_key_len;
    UCHAR *ca_cert;
    UINT   ca_cert_len;
    UINT   key_type;
} CERTIFICATE;

typedef struct
{
    USHORT *supported_groups;
    UINT supported_groups_count;
    const NX_CRYPTO_METHOD **curves;
    UINT curve_count;
    UINT session_succ;
    CERTIFICATE *cert;
} TEST_CASE;

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

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern NX_CRYPTO_METHOD crypto_method_ec_x25519;
extern NX_CRYPTO_METHOD crypto_method_ec_x448;
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

static USHORT supported_groups_0[] =
{
    (USHORT)NX_CRYPTO_EC_SECP192R1,
    (USHORT)NX_CRYPTO_EC_SECP224R1,
    (USHORT)NX_CRYPTO_EC_SECP256R1,
    (USHORT)NX_CRYPTO_EC_SECP384R1,
    (USHORT)NX_CRYPTO_EC_SECP521R1,
};
static USHORT supported_groups_1[] = {(USHORT)NX_CRYPTO_EC_SECP192R1};
static USHORT supported_groups_2[] = {(USHORT)NX_CRYPTO_EC_SECP224R1};
static USHORT supported_groups_3[] = {(USHORT)NX_CRYPTO_EC_SECP256R1};
static USHORT supported_groups_4[] = {(USHORT)NX_CRYPTO_EC_SECP384R1};
static USHORT supported_groups_5[] = {(USHORT)NX_CRYPTO_EC_SECP521R1};
static USHORT supported_groups_6[] = {(USHORT)NX_CRYPTO_EC_SECP192R1, (USHORT)NX_CRYPTO_EC_SECP256R1};
static USHORT supported_groups_7[] = {(USHORT)NX_CRYPTO_EC_SECP224R1, (USHORT)NX_CRYPTO_EC_SECP256R1};
#ifdef NX_CRYPTO_ENABLE_CURVE25519_448
static USHORT supported_groups_8[] = {(USHORT)NX_CRYPTO_EC_X25519, (USHORT)NX_CRYPTO_EC_SECP256R1};
static USHORT supported_groups_9[] = {(USHORT)NX_CRYPTO_EC_X448, (USHORT)NX_CRYPTO_EC_SECP256R1};
#endif /* NX_CRYPTO_ENABLE_CURVE25519_448 */

static const NX_CRYPTO_METHOD *ecc_curves_0[] =
{
    &crypto_method_ec_secp192,
    &crypto_method_ec_secp224,
    &crypto_method_ec_secp256,
    &crypto_method_ec_secp384,
    &crypto_method_ec_secp521,
};
static const NX_CRYPTO_METHOD *ecc_curves_1[] = {&crypto_method_ec_secp192};
static const NX_CRYPTO_METHOD *ecc_curves_2[] = {&crypto_method_ec_secp224};
static const NX_CRYPTO_METHOD *ecc_curves_3[] = {&crypto_method_ec_secp256};
static const NX_CRYPTO_METHOD *ecc_curves_4[] = {&crypto_method_ec_secp384};
static const NX_CRYPTO_METHOD *ecc_curves_5[] = {&crypto_method_ec_secp521};
static const NX_CRYPTO_METHOD *ecc_curves_6[] = {&crypto_method_ec_secp192, &crypto_method_ec_secp256};
static const NX_CRYPTO_METHOD *ecc_curves_7[] = {&crypto_method_ec_secp224, &crypto_method_ec_secp256};
#ifdef NX_CRYPTO_ENABLE_CURVE25519_448
static const NX_CRYPTO_METHOD *ecc_curves_8[] = {&crypto_method_ec_x25519, &crypto_method_ec_secp256};
static const NX_CRYPTO_METHOD *ecc_curves_9[] = {&crypto_method_ec_x448, &crypto_method_ec_secp256};
#endif /* NX_CRYPTO_ENABLE_CURVE25519_448 */

static CERTIFICATE test_certs[] =
{
    CERTIFICATE_INIT(ECTestServer9_192_der, ECTestServer9_192_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer8_224_der, ECTestServer8_224_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer2_der, ECTestServer2_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer4_der, ECTestServer4_key_der, ECCA4_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer3_der, ECTestServer3_key_der, ECCA3_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
};

static TEST_CASE test_case_client[] =
{

    /* Select curve by certificate. */
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[1]),
#endif
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

    /* Specify curve from client. */
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    TEST_CASE_INIT(supported_groups_6, ecc_curves_6, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_7, ecc_curves_7, NX_TRUE, &test_certs[1]),
#endif
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_TRUE, &test_certs[4]),

    /* Specify curve from server. */
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[1]),
#endif
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* Configure invalid curves at server side. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[0]),

    /* Multiple curves used by server and CA cert. */
    TEST_CASE_INIT(supported_groups_1, ecc_curves_1, NX_FALSE, &test_certs[0]),  /* ECCA2_der uses P256 which is not supported. */
    TEST_CASE_INIT(supported_groups_2, ecc_curves_2, NX_FALSE, &test_certs[1]),  /* ECCA2_der uses P256 which is not supported. */

    /* Client curve not supported by server. */
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_FALSE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_FALSE, &test_certs[2]),
#endif

#ifdef NX_CRYPTO_ENABLE_CURVE25519_448
    TEST_CASE_INIT(supported_groups_8, ecc_curves_8, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_9, ecc_curves_9, NX_TRUE, &test_certs[2]),
#endif /* NX_CRYPTO_ENABLE_CURVE25519_448 */
};

static TEST_CASE test_case_server[] =
{

    /* Select curve by certificate. */
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[1]),
#endif
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

    /* Specify curve from client. */
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[1]),
#endif
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

    /* Specify curve from server. */
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    TEST_CASE_INIT(supported_groups_1, ecc_curves_1, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_2, ecc_curves_2, NX_TRUE, &test_certs[1]),
#endif
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_TRUE, &test_certs[4]),

#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* Configure invalid curves at server side. */
    TEST_CASE_INIT(supported_groups_2, ecc_curves_2, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_FALSE, &test_certs[0]),

    /* Multiple curves used by server and CA cert. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[1]),

    /* Client curve not supported by server. */
    TEST_CASE_INIT(supported_groups_1, ecc_curves_1, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_2, ecc_curves_2, NX_FALSE, &test_certs[1]),
#endif

#ifdef NX_CRYPTO_ENABLE_CURVE25519_448
    TEST_CASE_INIT(supported_groups_8, ecc_curves_8, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_9, ecc_curves_9, NX_TRUE, &test_certs[2]),
#endif /* NX_CRYPTO_ENABLE_CURVE25519_448 */
};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#define ERROR_COUNTER() _error_counter(status, __FILE__, __LINE__)
static VOID    _error_counter(UINT status, char *filename, int line)
{
    printf("Error: 0x%02x at %s:%d\n", status, filename, line);
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_ecc_curves_test_application_define(void *first_unused_memory)
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
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &pool_0, _nx_ram_network_driver_1500,
                          ip_0_stack, sizeof(ip_0_stack), 1);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (VOID *)arp_cache, sizeof(arp_cache));
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    nx_secure_tls_initialize();
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, TEST_CASE *test_case)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           client_metadata,
                                           sizeof(client_metadata));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, test_case -> supported_groups,
                                          test_case -> supported_groups_count,
                                          test_case -> curves);
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &client_remote_cert,
                                                       client_cert_buffer,
                                                       sizeof(client_cert_buffer));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca,
                                                   test_case -> cert -> ca_cert,
                                                   test_case -> cert -> ca_cert_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &client_trusted_ca);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    if (status)
    {
        ERROR_COUNTER();
    }
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, TEST_CASE *test_case)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           server_metadata,
                                           sizeof(server_metadata));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, test_case -> supported_groups,
                                          test_case -> supported_groups_count,
                                          test_case -> curves);
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   test_case -> cert -> server_cert,
                                                   test_case -> cert -> server_cert_len,
                                                   NX_NULL, 0, test_case -> cert -> server_key,
                                                   test_case -> cert -> server_key_len,
                                                   test_case -> cert -> key_type);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                 &server_local_certificate);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[1],
                                                     sizeof(tls_packet_buffer[1]));
    if (status)
    {
        ERROR_COUNTER();
    }
}

static void ntest_0_entry(ULONG thread_input)
{
UINT i;
UINT status;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ECC Curves Test................................");

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &server_socket_0, "Server socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_tcp_server_socket_listen(&ip_0, SERVER_PORT, &server_socket_0, 5, NX_NULL);
    if (status)
    {
        ERROR_COUNTER();
    }

    for (i = 0; i < sizeof(test_case_server) / sizeof(TEST_CASE); i++)
    {

        /* Make sure client thread is ready. */
        tx_thread_suspend(&thread_0);

        server_tls_setup(&tls_server_session_0, &test_case_server[i]);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                              NX_WAIT_FOREVER);
        if ((status && test_case_server[i].session_succ) ||
            (!status && !test_case_server[i].session_succ))
        {
            ERROR_COUNTER();
        }

        if (!status)
        {
            status = nx_secure_tls_session_receive(&tls_server_session_0, &packet_ptr, NX_WAIT_FOREVER);
            if (status)
            {
                ERROR_COUNTER();
            }

            nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
            nx_packet_release(packet_ptr);
            if ((response_length != sizeof(request_buffer)) ||
                memcmp(request_buffer, response_buffer, response_length))
            {
                ERROR_COUNTER();
            }
        }

        nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
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
UINT i, j;
UINT status;
NX_PACKET *packet_ptr;
NXD_ADDRESS server_address;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    for (i = 0; i < sizeof(test_case_client) / sizeof(TEST_CASE); i++)
    {

        /* Let server thread run first. */
        tx_thread_resume(&thread_0);

        for (j = 0; j < sizeof(request_buffer); j++)
        {
            request_buffer[j] = j;
            response_buffer[j] = 0;
        }

        client_tls_setup(&tls_client_session_0, &test_case_client[i]);

        status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                                NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0,
                                              NX_WAIT_FOREVER);
        if ((status && test_case_client[i].session_succ) ||
            (!status && !test_case_client[i].session_succ))
        {
            ERROR_COUNTER();
        }

        if (!status)
        {

            /* Prepare packet to send. */
            status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }

            packet_ptr -> nx_packet_prepend_ptr += NX_SECURE_TLS_RECORD_HEADER_SIZE;
            packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;

            status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                           &pool_0, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }

            /* Send the packet. */
            status = nx_secure_tls_session_send(&tls_client_session_0, packet_ptr, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }
        }

        nx_secure_tls_session_end(&tls_client_session_0, NX_NO_WAIT);
        nx_secure_tls_session_delete(&tls_client_session_0);

        nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    }
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_ecc_curves_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ECC Curves Test................................N/A\n");
    test_control_return(3);
}
#endif
