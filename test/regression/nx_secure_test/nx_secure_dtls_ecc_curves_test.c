/* This test concentrates on DTLS ECC curve selection.  */

#include   "nx_api.h"
#include   "nx_secure_dtls_api.h"
#include   "ecc_certs.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_DTLS) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            (2048 + sizeof(NX_SECURE_X509_CERT))
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

static NX_UDP_SOCKET            client_socket_0;
static NX_SECURE_DTLS_SESSION   dtls_client_session_0;
static NX_SECURE_DTLS_SERVER    dtls_server_0;
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

static UINT                     server_running;

/* Session buffer for DTLS server. Must be equal to the size of NX_SECURE_DTLS_SESSION times the
   number of desired DTLS sessions. */
static UCHAR                    server_session_buffer[sizeof(NX_SECURE_DTLS_SESSION)];

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc[];
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

static TEST_CASE test_case_client[] =
{

    /* Select curve by certificate. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[1]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

    /* Specify curve from client. */
    TEST_CASE_INIT(supported_groups_6, ecc_curves_6, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_7, ecc_curves_7, NX_TRUE, &test_certs[1]),
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_TRUE, &test_certs[4]),

    /* Specify curve from server. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[1]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

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

    /* Multiple curves used by server and CA cert. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_FALSE, &test_certs[1]),

    /* Client curve not supported by server. */
    TEST_CASE_INIT(supported_groups_1, ecc_curves_1, NX_FALSE, &test_certs[0]),
    TEST_CASE_INIT(supported_groups_2, ecc_curves_2, NX_FALSE, &test_certs[1]),
};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#define ERROR_COUNTER() _ERROR_COUNTER(__FILE__, __LINE__)

static VOID    _ERROR_COUNTER(const char *file, int line)
{
	printf("Error at %s:%d", file, line);
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_ecc_curves_test_application_define(void *first_unused_memory)
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

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    nx_secure_tls_initialize();
    nx_secure_dtls_initialize();
}

static VOID client_dtls_setup(NX_SECURE_DTLS_SESSION *dtls_session_ptr, TEST_CASE *test_case)
{
UINT status;

    status = nx_secure_dtls_session_create(dtls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           client_metadata,
                                           sizeof(client_metadata),
                                           tls_packet_buffer[0], sizeof(tls_packet_buffer[0]),
                                           1, client_cert_buffer, sizeof(client_cert_buffer));

    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_dtls_ecc_initialize(dtls_session_ptr, test_case -> supported_groups,
                                           test_case -> supported_groups_count,
                                           test_case -> curves);
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

    status = nx_secure_dtls_session_trusted_certificate_add(dtls_session_ptr, &client_trusted_ca, 1);
    if (status)
    {
        ERROR_COUNTER();
    }


}

/* Notification flags for DTLS server connect/receive. */
static UINT server_connect_notify_flag = NX_FALSE;
static UINT server_receive_notify_flag = NX_FALSE;

NX_SECURE_DTLS_SESSION *connect_session;
NX_SECURE_DTLS_SESSION *receive_session;

/* Connect notify callback for DTLS server - notifies the application thread that
   a DTLS connection is ready to kickoff a handshake. */
static UINT server_connect_notify(NX_SECURE_DTLS_SESSION *dtls_session, NXD_ADDRESS *ip_address, UINT port)
{
    /* Drop connections if one is in progress. Better way would be to have
     * an array of pointers to DTLS sessions and check the port/IP address
     * to see if it's an existing connection. Application thread then loops
     * through array servicing each session.
     */
    if (server_connect_notify_flag == NX_FALSE)
    {
        server_connect_notify_flag = NX_TRUE;
        connect_session = dtls_session;
    }

    return(NX_SUCCESS);
}

/* Receive notify callback for DTLS server - notifies the application thread that
   we have received a DTLS record over an established DTLS session. */
static UINT server_receive_notify(NX_SECURE_DTLS_SESSION *dtls_session)
{

    /* Drop records if more come in while processing one. Better would be to
       service each session in a queue. */
    if (server_receive_notify_flag == NX_FALSE)
    {
        server_receive_notify_flag = NX_TRUE;
        receive_session = dtls_session;
    }

    return(NX_SUCCESS);
}

static VOID server_dtls_setup(NX_SECURE_DTLS_SERVER *dtls_server_ptr, TEST_CASE *test_case)
{
UINT status;

    status = nx_secure_dtls_server_create(dtls_server_ptr, &ip_0, SERVER_PORT, NX_IP_PERIODIC_RATE,
                                          server_session_buffer, sizeof(server_session_buffer),
                                          &nx_crypto_tls_ciphers_ecc, server_metadata, sizeof(server_metadata),
                                          tls_packet_buffer[1], sizeof(tls_packet_buffer[1]),
                                          server_connect_notify, server_receive_notify);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_dtls_server_ecc_initialize(dtls_server_ptr, test_case -> supported_groups,
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

    status = nx_secure_dtls_server_local_certificate_add(dtls_server_ptr, &server_local_certificate, 1);
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
    printf("NetX Secure Test:   DTLS ECC Curves Test...............................");

    for (i = 0; i < sizeof(test_case_server) / sizeof(TEST_CASE); i++)
    {

        server_dtls_setup(&dtls_server_0, &test_case_server[i]);

        /* Start DTLS server. */
        status = nx_secure_dtls_server_start(&dtls_server_0);
        if (status)
        {
            ERROR_COUNTER();
        }

        server_running = 1;

        /* Wait for connection attempt. */
        while (server_connect_notify_flag != NX_TRUE)
        {
            tx_thread_sleep(1);
        }
        server_connect_notify_flag = NX_FALSE;

        status = nx_secure_dtls_server_session_start(connect_session, 20 * NX_IP_PERIODIC_RATE);
        if ((status && test_case_server[i].session_succ) ||
            (!status && !test_case_server[i].session_succ))
        {
            ERROR_COUNTER();
        }

        if (!status)
        {
        
            /* Wait for records to be received. */
            while (server_receive_notify_flag != NX_TRUE)
            {
                tx_thread_sleep(1);
            }

            status = nx_secure_dtls_session_receive(receive_session, &packet_ptr, 20 * NX_IP_PERIODIC_RATE);
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

        /* Clear the receive flag. */
        server_receive_notify_flag = NX_FALSE;

        /* Shutdown DTLS server. */
        nx_secure_dtls_server_stop(&dtls_server_0);

        /* Delete server. */
        nx_secure_dtls_server_delete(&dtls_server_0);

        server_running = 0;
        tx_thread_suspend(&thread_0);
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

    /* Create UDP socket. */
    status = nx_udp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, 0x80, 5);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    for (i = 0; i < sizeof(test_case_client) / sizeof(TEST_CASE); i++)
    {

        for (j = 0; j < sizeof(request_buffer); j++)
        {
            request_buffer[j] = j;
            response_buffer[j] = 0;
        }

        client_dtls_setup(&dtls_client_session_0, &test_case_client[i]);

        /* Start DTLS session. */
        status = nx_secure_dtls_client_session_start(&dtls_client_session_0, &client_socket_0, &server_address, SERVER_PORT, NX_WAIT_FOREVER);
        if ((status && test_case_client[i].session_succ) ||
            (!status && !test_case_client[i].session_succ))
        {
            ERROR_COUNTER();
        }

        if (!status)
        {

            /* Prepare packet to send. */
            status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }

            packet_ptr -> nx_packet_prepend_ptr += NX_SECURE_DTLS_RECORD_HEADER_SIZE;
            packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;

            status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                           &pool_0, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }

            /* Send the packet. */
            status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
                                                  &server_address, SERVER_PORT);
            if (status)
            {
                ERROR_COUNTER();
            }
        }

        nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);
        nx_secure_dtls_session_delete(&dtls_client_session_0);

         while (server_running)
        {
            tx_thread_sleep(1);
        }
        tx_thread_resume(&thread_0);
    }
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_ecc_curves_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS ECC Curves Test...............................N/A\n");
    test_control_return(3);
}
#endif
