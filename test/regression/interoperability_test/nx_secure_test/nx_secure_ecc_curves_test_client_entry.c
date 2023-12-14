#include "tls_test_frame.h"
#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)

#include   "nx_crypto_ecdh.h"

/* Define the ThreadX and NetX object control blocks...  */

NX_PACKET_POOL    pool_0;
NX_IP             ip_0;  

NX_TCP_SOCKET tcp_socket;
NX_SECURE_TLS_SESSION tls_session;
NX_SECURE_X509_CERT remote_certificate, remote_issuer;
UCHAR remote_cert_buffer[2000];
UCHAR remote_issuer_buffer[2000];
NX_SECURE_X509_CERT trusted_certificate;
NX_SECURE_X509_CERT client_local_certificate;

UCHAR tls_packet_buffer[4000];
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

#include "../../nx_secure_test/ecc_certs.c"
#include "../../nx_secure_test/test_ca_cert.c"
#include "../../nx_secure_test/test_device_cert.c"

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;


extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_METHOD crypto_method_ecdh;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;
extern NX_CRYPTO_METHOD crypto_method_aes_128_gcm_16;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_hkdf;

static NX_SECURE_TLS_CIPHERSUITE_INFO ciphersuite_lookup_table[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,  &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    {TLS_AES_128_GCM_SHA256,                  &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  96,      16,        &crypto_method_sha256,          32,        &crypto_method_hkdf},
#endif
};
static NX_SECURE_TLS_CRYPTO tls_ciphers_ecc;

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

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* Specify curve from client. */
    TEST_CASE_INIT(supported_groups_3, ecc_curves_3, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_TRUE, &test_certs[4]),

    /* Specify curve from server. */
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[2]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_0, ecc_curves_0, NX_TRUE, &test_certs[4]),

    /* Client curves not suitable for signature. */
    TEST_CASE_INIT(supported_groups_4, ecc_curves_4, NX_FALSE, &test_certs[3]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_FALSE, &test_certs[4]),

    /* Client curve not supported by server. */
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_FALSE, &test_certs[4]),
    TEST_CASE_INIT(supported_groups_5, ecc_curves_5, NX_FALSE, &test_certs[4]),
#endif
};

/* Define the IP thread's stack area.  */
ULONG             ip_thread_stack[3 * 1024 / sizeof(ULONG)];

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)

ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

/* Define an error counter.  */

ULONG             error_counter;


/* Define the ARP cache area.  */
ULONG             arp_space_area[512 / sizeof(ULONG)];

/* Define the demo thread.  */
ULONG             demo_thread_stack[6 * 1024 / sizeof(ULONG)];
TX_THREAD         demo_thread;

TLS_TEST_INSTANCE* client_instance_ptr;
extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;
VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);
void client_thread_entry(ULONG thread_input);
CHAR crypto_metadata[30000]; // 2*sizeof(NX_AES) + sizeof(NX_SHA1_HMAC) + 2*sizeof(NX_CRYPTO_RSA) + (2 * (sizeof(NX_MD5) + sizeof(NX_SHA1) + sizeof(NX_SHA256)))];
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;


static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, TEST_CASE *test_case)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &tls_ciphers_ecc,
                                           crypto_metadata,
                                           sizeof(crypto_metadata));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, test_case -> supported_groups,
                                          test_case -> supported_groups_count,
                                          test_case -> curves);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    memset(&remote_cert_buffer, 0, sizeof(remote_cert_buffer));
    memset(&remote_issuer_buffer, 0, sizeof(remote_issuer_buffer));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &remote_certificate,
                                                       remote_cert_buffer,
                                                       sizeof(remote_cert_buffer));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &remote_issuer,
                                                       remote_issuer_buffer,
                                                       sizeof(remote_issuer_buffer));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_x509_certificate_initialize(&trusted_certificate,
                                                   test_case -> cert -> ca_cert,
                                                   test_case -> cert -> ca_cert_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &trusted_certificate);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    if (test_case -> cert != NX_NULL)
    {
        memset(&client_local_certificate, 0, sizeof(client_local_certificate));
        status = nx_secure_x509_certificate_initialize(&client_local_certificate,
                                                       test_case -> cert -> server_cert, test_case -> cert -> server_cert_len,
                                                       NX_NULL, 0, test_case -> cert -> server_key,
                                                       test_case -> cert -> server_key_len,
                                                       test_case -> cert -> key_type);
        exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

        status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                     &client_local_certificate);
        exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer,
                                                     sizeof(tls_packet_buffer));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
}


INT nx_secure_echo_client_entry(TLS_TEST_INSTANCE* instance_ptr)
{


    client_instance_ptr = instance_ptr;
    tx_kernel_enter();


}

void    tx_application_define(void *first_unused_memory)
{
ULONG gateway_ipv4_address;
UINT  status;
    

    /* Initialize the NetX system.  */
    nx_system_initialize();
    
    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, 
                          "NetX IP Instance 0", 
                          TLS_TEST_IP_ADDRESS_NUMBER,                           
                          0xFFFFFF00UL, 
                          &pool_0,
                          _nx_pcap_network_driver,
                          (UCHAR*)ip_thread_stack,
                          sizeof(ip_thread_stack),
                          1);
    show_error_message_if_fail(NX_SUCCESS == status);
    
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *)arp_space_area, sizeof(arp_space_area));
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    status =  nx_ip_fragment_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    nx_secure_tls_initialize();
    
    tx_thread_create(&demo_thread, "demo thread", client_thread_entry, 0,
            demo_thread_stack, sizeof(demo_thread_stack),
            16, 16, 4, TX_AUTO_START);
}

void client_thread_entry(ULONG thread_input)
{
UINT        status;
ULONG       actual_status;
NX_PACKET   *send_packet;
NX_PACKET   *receive_packet;
UCHAR       receive_buffer[100];
ULONG       bytes;
UINT        i;
NX_PARAMETER_NOT_USED(thread_input);
    
    /* Address of remote server. */
    print_error_message( "remote ip address number %lu, remote ip address string %s.\n", REMOTE_IP_ADDRESS_NUMBER, REMOTE_IP_ADDRESS_STRING);
    
    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    /* Create a socket. */
    status =  nx_tcp_socket_create(&ip_0, &tcp_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192,
                                   NX_NULL, NX_NULL);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    
    /* Setup this thread to bind to a port.  */
    status =  nx_tcp_client_socket_bind(&tcp_socket, 0, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    memcpy(&tls_ciphers_ecc, &nx_crypto_tls_ciphers_ecc, sizeof(nx_crypto_tls_ciphers_ecc));
    tls_ciphers_ecc.nx_secure_tls_ciphersuite_lookup_table = ciphersuite_lookup_table;
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    tls_ciphers_ecc.nx_secure_tls_ciphersuite_lookup_table_size = 2;
#else
    tls_ciphers_ecc.nx_secure_tls_ciphersuite_lookup_table_size = 1;
#endif

    for (i = 0; i < sizeof(test_case_client) / sizeof(TEST_CASE); i++)
    {
        /* Wait for the semaphore. */
        tls_test_semaphore_wait(semaphore_echo_server_prepared);
        tx_thread_sleep(20 * NX_IP_PERIODIC_RATE);

        client_tls_setup(&tls_session, &test_case_client[i]);

        /* Attempt to connect the echo server. */
        status = nx_tcp_client_socket_connect(&tcp_socket, REMOTE_IP_ADDRESS_NUMBER, DEVICE_SERVER_PORT, NX_WAIT_FOREVER);
        exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

        status = nx_secure_tls_session_start(&tls_session, &tcp_socket, NX_WAIT_FOREVER);
        exit_if_fail(!((status && test_case_client[i].session_succ) ||
                        (!status && !test_case_client[i].session_succ)), TLS_TEST_UNKNOWN_TYPE_ERROR);
    
        if (!status)
        {
            /* Send some data to be echoed by the OpenSSL s_server echo instance. */
            status = nx_secure_tls_packet_allocate(&tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
            exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

            /* Append application to the allocated packet. */
            status = nx_packet_data_append(send_packet, "hello\n", 6, &pool_0, NX_WAIT_FOREVER);
            exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

            /* Send "hello" message. */
            status = nx_secure_tls_session_send(&tls_session, send_packet, NX_IP_PERIODIC_RATE);
            exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

            /* Receive the echoed and reversed data, and print it out. */
            status = nx_secure_tls_session_receive(&tls_session, &receive_packet, NX_WAIT_FOREVER);
            exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

            /* Extract data received from server. */
            status = nx_packet_data_extract_offset(receive_packet, 0, receive_buffer, 100, &bytes);
            nx_packet_release(receive_packet);
            exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

            /* Check the reverse text received from openssl server. */
            exit_if_fail('o' == ((CHAR*)receive_buffer)[0], TLS_TEST_UNKNOWN_TYPE_ERROR);
            exit_if_fail('l' == ((CHAR*)receive_buffer)[1], TLS_TEST_UNKNOWN_TYPE_ERROR);
            exit_if_fail('l' == ((CHAR*)receive_buffer)[2], TLS_TEST_UNKNOWN_TYPE_ERROR);
            exit_if_fail('e' == ((CHAR*)receive_buffer)[3], TLS_TEST_UNKNOWN_TYPE_ERROR);
            exit_if_fail('h' == ((CHAR*)receive_buffer)[4], TLS_TEST_UNKNOWN_TYPE_ERROR);
            exit_if_fail('\n' == ((CHAR*)receive_buffer)[5], TLS_TEST_UNKNOWN_TYPE_ERROR);
            exit_if_fail(6 == bytes, TLS_TEST_UNKNOWN_TYPE_ERROR);
        }

        /* End the TLS session. This is required to properly shut down the TLS connection. */
        nx_secure_tls_session_end(&tls_session, NX_NO_WAIT);
        nx_secure_tls_session_delete(&tls_session);

        /* Close the TCP connection. */
        nx_tcp_socket_disconnect(&tcp_socket, NX_NO_WAIT);
    }


    /* Unbind the TCP socket from our port. */
    status = nx_tcp_client_socket_unbind(&tcp_socket);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    /* Delete the TCP socket instance to clean up. */
    status = nx_tcp_socket_delete(&tcp_socket);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    exit(0);
}
#else
INT nx_secure_echo_client_entry(TLS_TEST_INSTANCE* instance_ptr)
{

    exit(TLS_TEST_NOT_AVAILABLE);


}
#endif
