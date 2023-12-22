/* This test concentrates on TLS ECC curve selection.  */
#include "tls_test_frame.h"

#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)
#include   "nx_crypto_ecdh.h"
#include   "../../nx_secure_test/ecc_certs.c"

#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
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
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;

static NX_TCP_SOCKET            server_socket_0;
static NX_SECURE_TLS_SESSION    tls_server_session_0;
static NX_SECURE_X509_CERT      server_local_certificate;
static NX_SECURE_TLS_CRYPTO     tls_ciphers_server;
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table_server[10];

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];

static UCHAR                    tls_packet_buffer[4000];
static UCHAR                    response_buffer[100];

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
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

static CERTIFICATE test_certs[] =
{
    CERTIFICATE_INIT(ECTestServer9_192_der, ECTestServer9_192_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer8_224_der, ECTestServer8_224_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer2_der, ECTestServer2_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer4_der, ECTestServer4_key_der, ECCA4_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer3_der, ECTestServer3_key_der, ECCA3_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
};

static TEST_CASE test_case_server[] =
{

    /* Select curve by certificate. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[1]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

    /* Specify curve from client. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[1]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

    /* Specify curve from server. */
    TEST_CASE_INIT(supported_groups_1, ecc_curves_1, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_2, ecc_curves_2, NX_TRUE, &test_certs[1]),
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_TRUE, &test_certs[4]),

    /* Configure invalid curves at server side. */
    TEST_CASE_INIT(supported_groups_2, ecc_curves_2, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_FALSE, &test_certs[0]),

#if 0
    /* Though the P256 is not in supported list, openssl is still able to verify the issuer. */
    /* Multiple curves used by server and CA cert. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[1]),
#endif

    /* Client curve not supported by server. */
    TEST_CASE_INIT(supported_groups_1, ecc_curves_1, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_2, ecc_curves_2, NX_FALSE, &test_certs[1]),

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
        /* Specify curve from client. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

    /* Specify curve from server. */
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_TRUE, &test_certs[4]),

    /* Configure invalid curves at server side. */
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_FALSE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_FALSE, &test_certs[2]),

    /* Client curve not supported by server. */
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_FALSE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_FALSE, &test_certs[3]),
#endif
};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* Global demo emaphore. */
extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;


/* Define the pointer of current instance control block. */
static TLS_TEST_INSTANCE* demo_instance_ptr;

/*  Instance one test entry. */
INT nx_secure_ecc_server_curves_entry(TLS_TEST_INSTANCE* instance_ptr)
{


    /* Get instance pointer. */
    demo_instance_ptr = instance_ptr;

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
}

/* Define what the initial system looks like.  */

VOID    tx_application_define(void *first_unused_memory)
{
UINT     status;
CHAR    *pointer;



    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&thread_0, "thread 0", ntest_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE,
                                    pool_0_memory, PACKET_POOL_SIZE);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", TLS_TEST_IP_ADDRESS_NUMBER, 0xFFFFFF00UL,
                          &pool_0, _nx_pcap_network_driver,
                          ip_0_stack, sizeof(ip_0_stack), 1);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (VOID *)arp_cache, sizeof(arp_cache));
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    nx_secure_tls_initialize();
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, TEST_CASE *test_case)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           server_metadata,
                                           sizeof(server_metadata));
    show_error_message_if_fail( NX_SUCCESS == status);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, test_case -> supported_groups,
                                          test_case -> supported_groups_count,
                                          test_case -> curves);
    show_error_message_if_fail( NX_SUCCESS == status);

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   test_case -> cert -> server_cert,
                                                   test_case -> cert -> server_cert_len,
                                                   NX_NULL, 0, test_case -> cert -> server_key,
                                                   test_case -> cert -> server_key_len,
                                                   test_case -> cert -> key_type);
    show_error_message_if_fail( NX_SUCCESS == status);

    status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                 &server_local_certificate);
    show_error_message_if_fail( NX_SUCCESS == status);

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer,
                                                     sizeof(tls_packet_buffer));
    show_error_message_if_fail( NX_SUCCESS == status);
}

static void ntest_0_entry(ULONG thread_input)
{
UINT i;
UINT status;
ULONG actual_status;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status,
                                 NX_IP_PERIODIC_RATE);
    show_error_message_if_fail( NX_SUCCESS == status);

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &server_socket_0, "Server socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    show_error_message_if_fail( NX_SUCCESS == status);

    status = nx_tcp_server_socket_listen(&ip_0, DEVICE_SERVER_PORT, &server_socket_0, 5, NX_NULL);
    show_error_message_if_fail( NX_SUCCESS == status);

    for (i = 0; i < sizeof(test_case_server) / sizeof(TEST_CASE); i++)
    {

        server_tls_setup(&tls_server_session_0, &test_case_server[i]);

        tls_test_semaphore_post(semaphore_echo_server_prepared);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        exit_if_fail( NX_SUCCESS == status, 1);

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                              NX_WAIT_FOREVER);
        exit_if_fail (!((status && test_case_server[i].session_succ) ||
                        (!status && !test_case_server[i].session_succ)), 2);

        if (!status)
        {
            status = nx_secure_tls_session_receive(&tls_server_session_0, &packet_ptr, NX_WAIT_FOREVER);
            exit_if_fail ( NX_SUCCESS == status, 3);

            nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
            nx_packet_release(packet_ptr);
            response_buffer[response_length] = 0;
            print_error_message("Received data: %s\n", (CHAR *)response_buffer);

            /* Allocate a return packet and send our HTML data back to the client. */
            status = nx_secure_tls_packet_allocate(&tls_server_session_0, &pool_0, &packet_ptr,
                                                   NX_WAIT_FOREVER);
            exit_if_fail( NX_SUCCESS == status, 4);

            /* Echo the message received. */
            status = nx_packet_data_append(packet_ptr, response_buffer, response_length, &pool_0,
                                           NX_WAIT_FOREVER);
            exit_if_fail( NX_SUCCESS == status, 5);

            /* TLS send the HTML/HTTPS data back to the client. */
            status = nx_secure_tls_session_send(&tls_server_session_0, packet_ptr,
                                                NX_IP_PERIODIC_RATE);
            /* Exit the test process directly without release packet. */
            exit_if_fail( NX_SUCCESS == status, 6);
        }

        nx_secure_tls_session_end(&tls_server_session_0, NX_IP_PERIODIC_RATE);
        nx_secure_tls_session_delete(&tls_server_session_0);

        nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
        nx_tcp_server_socket_unaccept(&server_socket_0);
        nx_tcp_server_socket_relisten(&ip_0, DEVICE_SERVER_PORT, &server_socket_0);
    }

    exit(0);
}

#else
INT nx_secure_ecc_server_curves_entry(TLS_TEST_INSTANCE* instance_ptr)
{
    exit(TLS_TEST_NOT_AVAILABLE);
}
#endif
