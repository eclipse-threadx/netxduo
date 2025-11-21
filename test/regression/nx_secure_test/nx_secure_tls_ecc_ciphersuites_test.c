/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include   "nx_api.h"
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
    UINT *list;
    UINT count;
    UINT session_succ;
    CERTIFICATE *cert;
} CIPHERSUITE;

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

static CERTIFICATE test_certs[] =
{
    CERTIFICATE_INIT(ECTest_der, ECTest_key_der, ECCA_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer2_der, ECTestServer2_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(test_device_cert_der, test_device_cert_key_der, test_ca_cert_der, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER),
    CERTIFICATE_INIT(ECTestServer10_der, ECTestServer10_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
};

static UINT ciphersuite_list_0[] = {};
static UINT ciphersuite_list_1[] = {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_2[] = {TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_3[] = {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_4[] = {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_5[] =
{
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
};
static UINT ciphersuite_list_6[] = {TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_7[] = {TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_8[] = {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_9[] = {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};

static CIPHERSUITE ciphersuites_client[] =
{
    /* Select ciphersuite according to certificate. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2]),
#endif
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[3]),

    /* Select ciphersuite according to certificate.
     * The order of client ciphersuites are reversed of server. */
    CIPHERSUITE_INIT(ciphersuite_list_5, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_5, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_5, NX_TRUE, &test_certs[2]),

    /* Specified ciphersuites. */
    CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2]),

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    CIPHERSUITE_INIT(ciphersuite_list_6, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_7, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_8, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2]),
#endif

    /* The Server cert supports ECDH_ECDSA and ECDHE_ECDSA. */
    CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_2, NX_FALSE, &test_certs[1]),     /* ECDH_RSA not supported. */
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_FALSE, &test_certs[1]),     /* ECDHE_RSA not supported. */

    /* Let the server pickup supported ciphersuite. */
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2]),
#endif

#if defined(NX_SECURE_TLS_ENABLE_TLS_1_1) && !defined(NX_SECURE_TLS_DISABLE_TLS_1_0) && defined(NX_SECURE_ENABLE_AEAD_CIPHER)
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2]),
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2]),
#endif /* defined(NX_SECURE_TLS_ENABLE_TLS_1_1) && !defined(NX_SECURE_TLS_DISABLE_TLS_1_0) */
};

static CIPHERSUITE ciphersuites_server[] =
{

    /* Select ciphersuite according to certificate. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2]),
#endif
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[3]),

    /* Select ciphersuite according to certificate.
     * The order of client ciphersuites are reversed of server. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2]),

    /* Specified ciphersuites. */
    CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2]),

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    CIPHERSUITE_INIT(ciphersuite_list_6, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_7, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_8, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2]),
#endif

    /* The Server cert supports ECDH_ECDSA and ECDHE_ECDSA. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_FALSE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_FALSE, &test_certs[1]),

    /* Let the server pickup supported ciphersuite. */
#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2]),
#endif

#if defined(NX_SECURE_TLS_ENABLE_TLS_1_1) && !defined(NX_SECURE_TLS_DISABLE_TLS_1_0) && defined(NX_SECURE_ENABLE_AEAD_CIPHER)
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2]),
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2]),
#endif /* defined(NX_SECURE_TLS_ENABLE_TLS_1_1) && !defined(NX_SECURE_TLS_DISABLE_TLS_1_0) */
};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */


static VOID    ERROR_COUNTER()
{
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_ecc_ciphersuites_test_application_define(void *first_unused_memory)
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

static VOID ciphersuites_setup(CIPHERSUITE *ciphersuite, NX_SECURE_TLS_CRYPTO *tls_ciphers,
                               NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite_table)
{
UINT i;
UINT status;
UINT count;

    /* Initialize ciphersuites. */
    memcpy(tls_ciphers, &nx_crypto_tls_ciphers_ecc, sizeof(NX_SECURE_TLS_CRYPTO));
    if (ciphersuite -> count > 0)
    {
        for (count = 0; count < ciphersuite -> count; count++)
        {
            i = 0;
            while (ciphersuite -> list[count] !=
                   (UINT)_nx_crypto_ciphersuite_lookup_table_ecc[i].nx_secure_tls_ciphersuite)
            {
                i++;
            }
            memcpy(&ciphersuite_table[count],
                   &_nx_crypto_ciphersuite_lookup_table_ecc[i],
                   sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
        }
        tls_ciphers -> nx_secure_tls_ciphersuite_lookup_table = ciphersuite_table;
        tls_ciphers -> nx_secure_tls_ciphersuite_lookup_table_size = count;
    }
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, CERTIFICATE *cert)
{
UINT status;

    memset(client_metadata, 0xFF, sizeof(client_metadata));
    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &tls_ciphers_client,
                                           client_metadata,
                                           sizeof(client_metadata));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
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
                                                   cert -> ca_cert,
                                                   cert -> ca_cert_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
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

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, CERTIFICATE *cert)
{
UINT status;

    memset(server_metadata, 0xFF, sizeof(server_metadata));
    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &tls_ciphers_server,
                                           server_metadata,
                                           sizeof(server_metadata));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   cert -> server_cert, cert -> server_cert_len,
                                                   NX_NULL, 0, cert -> server_key,
                                                   cert -> server_key_len,
                                                   cert -> key_type);
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
    printf("NetX Secure Test:   TLS ECC Ciphersuites Test..........................");

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

    for (i = 0; i < sizeof(ciphersuites_server) / sizeof(CIPHERSUITE); i++)
    {

        /* Make sure client thread is ready. */
        tx_thread_suspend(&thread_0);

        ciphersuites_setup(&ciphersuites_server[i], &tls_ciphers_server, ciphersuite_table_server);

        server_tls_setup(&tls_server_session_0, ciphersuites_server[i].cert);

#if defined(NX_SECURE_TLS_ENABLE_TLS_1_1) && !defined(NX_SECURE_TLS_DISABLE_TLS_1_0) && defined(NX_SECURE_ENABLE_AEAD_CIPHER)
        if ((sizeof(ciphersuites_server) / sizeof(CIPHERSUITE) - 2) == i)
        {
            nx_secure_tls_session_protocol_version_override(&tls_server_session_0, NX_SECURE_TLS_VERSION_TLS_1_1);
        }

        if ((sizeof(ciphersuites_server) / sizeof(CIPHERSUITE) - 1) == i)
        {
            nx_secure_tls_session_protocol_version_override(&tls_server_session_0, NX_SECURE_TLS_VERSION_TLS_1_0);
        }
#endif /* defined(NX_SECURE_TLS_ENABLE_TLS_1_1) && !defined(NX_SECURE_TLS_DISABLE_TLS_1_0) && defined(NX_SECURE_ENABLE_AEAD_CIPHER) */

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                              NX_WAIT_FOREVER);
        if ((status && ciphersuites_server[i].session_succ) ||
            (!status && !ciphersuites_server[i].session_succ))
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

    for (i = 0; i < sizeof(ciphersuites_client) / sizeof(CIPHERSUITE); i++)
    {

        /* Let server thread run first. */
        tx_thread_resume(&thread_0);

        for (j = 0; j < sizeof(request_buffer); j++)
        {
            request_buffer[j] = j;
            response_buffer[j] = 0;
        }

        ciphersuites_setup(&ciphersuites_client[i], &tls_ciphers_client, ciphersuite_table_client);

        client_tls_setup(&tls_client_session_0, ciphersuites_client[i].cert);

#if defined(NX_SECURE_TLS_ENABLE_TLS_1_1) && !defined(NX_SECURE_TLS_DISABLE_TLS_1_0) && defined(NX_SECURE_ENABLE_AEAD_CIPHER)
        if ((sizeof(ciphersuites_server) / sizeof(CIPHERSUITE) - 2) == i)
        {
            nx_secure_tls_session_client_verify_disable(&tls_client_session_0);
            nx_secure_tls_session_protocol_version_override(&tls_client_session_0, NX_SECURE_TLS_VERSION_TLS_1_1);
        }

        if ((sizeof(ciphersuites_server) / sizeof(CIPHERSUITE) - 1) == i)
        {
            nx_secure_tls_session_client_verify_disable(&tls_client_session_0);
            nx_secure_tls_session_protocol_version_override(&tls_client_session_0, NX_SECURE_TLS_VERSION_TLS_1_0);
        }
#endif /* defined(NX_SECURE_TLS_ENABLE_TLS_1_1) && !defined(NX_SECURE_TLS_DISABLE_TLS_1_0) && defined(NX_SECURE_ENABLE_AEAD_CIPHER) */

        status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                                NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0,
                                              NX_WAIT_FOREVER);
        if ((status && ciphersuites_client[i].session_succ) ||
            (!status && !ciphersuites_client[i].session_succ))
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
VOID    nx_secure_tls_ecc_ciphersuites_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ECC Ciphersuites Test..........................N/A\n");
    test_control_return(3);
}
#endif
