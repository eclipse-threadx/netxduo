/* This test TLS 1.3 client with OpenSSL server.  */
/* openssl s_server -key ECTestServer2.key -cert ECTestServer2.crt -tls1_3 -rev */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "ecc_certs.c"
#include   "nx_crypto_aes.h"

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

extern const                    USHORT nx_crypto_ecc_supported_groups[];
extern const                    NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const                    UINT nx_crypto_ecc_supported_groups_size;
extern const                    NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;
static                          NX_SECURE_TLS_CRYPTO nx_crypto_tls_1_3_ciphers_ecc;


extern NX_CRYPTO_METHOD crypto_method_ecdh;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_sha384;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
static NX_CRYPTO_METHOD crypto_method_aes_256_gcm_16 =
{
    NX_CRYPTO_ENCRYPTION_AES_GCM_16,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_256_KEY_LEN_IN_BITS,           /* Key size in bits                       */
    96,                                          /* IV size in bits                        */
    128,                                         /* ICV size in bits                       */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),     /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_AES),                       /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,                  /* AES-GCM initialization routine.        */
    _nx_crypto_method_aes_cleanup,               /* AES-GCM cleanup routine.               */
    _nx_crypto_method_aes_gcm_operation,         /* AES-GCM operation                      */
};
static NX_CRYPTO_METHOD crypto_method_aes_128_gcm_16 = 
{
    NX_CRYPTO_ENCRYPTION_AES_GCM_16,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_128_KEY_LEN_IN_BITS,           /* Key size in bits                       */
    96,                                          /* IV size in bits                        */
    128,                                         /* ICV size in bits                       */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),     /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_AES),                       /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,                  /* AES-GCM initialization routine.        */
    _nx_crypto_method_aes_cleanup,               /* AES-GCM cleanup routine.               */
    _nx_crypto_method_aes_gcm_operation,         /* AES-GCM operation                      */
};

static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_tls_1_3[] =
{
{TLS_AES_128_GCM_SHA256,                  &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
{TLS_AES_256_GCM_SHA384,                  &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_256_gcm_16,  16,      16,        &crypto_method_sha384,         48,         &crypto_method_hkdf},
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
VOID    nx_secure_tls_1_3_handshake_fail_test_application_define(void *first_unused_memory)
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

static VOID ciphersuites_setup()
{

    /* Initialize ciphersuites. */
    memcpy(&nx_crypto_tls_1_3_ciphers_ecc, &nx_crypto_tls_ciphers_ecc, sizeof(NX_SECURE_TLS_CRYPTO));
    nx_crypto_tls_1_3_ciphers_ecc.nx_secure_tls_ciphersuite_lookup_table = _nx_crypto_ciphersuite_tls_1_3;
    nx_crypto_tls_1_3_ciphers_ecc.nx_secure_tls_ciphersuite_lookup_table_size = 1;
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    ciphersuites_setup();

    status = nx_secure_tls_session_create(tls_session_ptr,
                                          &nx_crypto_tls_1_3_ciphers_ecc,
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

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca, ECCA2_der, ECCA2_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr, &client_trusted_ca);
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

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
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

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   ECTestServer2_der, ECTestServer2_der_len,
                                                   NX_NULL, 0, ECTestServer2_key_der,
                                                   ECTestServer2_key_der_len,
                                                   NX_SECURE_X509_KEY_TYPE_EC_DER);
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
UINT status;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Handshake Fail Test........................");

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

    server_tls_setup(&tls_server_session_0);

    status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Start TLS session. */
    status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0, NX_WAIT_FOREVER);
    if (!status || (tls_server_session_0.nx_secure_tls_received_alert_value != NX_SECURE_TLS_ALERT_ILLEGAL_PARAMETER))
    {
        ERROR_COUNTER();
    }

    tx_thread_sleep(10);

    nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
    nx_secure_tls_session_delete(&tls_server_session_0);

    nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
    nx_tcp_server_socket_unaccept(&server_socket_0);
    nx_tcp_server_socket_relisten(&ip_0, SERVER_PORT, &server_socket_0);

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

static VOID test_tcp_receive(NX_TCP_SOCKET *tcp_socket)
{

    /* Modify the ciphersuite, client should abort handshake with an "illegal_parameter" alert.  */
    tls_client_session_0.nx_secure_tls_crypto_table -> nx_secure_tls_ciphersuite_lookup_table = &_nx_crypto_ciphersuite_tls_1_3[1];
}

static void ntest_1_entry(ULONG thread_input)
{
UINT status;
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

    client_tls_setup(&tls_client_session_0);

    nx_tcp_socket_receive_notify(&client_socket_0, test_tcp_receive);

    status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT, NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Start TLS session. */
    status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
    if (!status)
    {
        ERROR_COUNTER();
    }

    nx_secure_tls_session_end(&tls_client_session_0, NX_NO_WAIT);
    nx_secure_tls_session_delete(&tls_client_session_0);

    nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client_socket_0);
    nx_tcp_socket_delete(&client_socket_0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_handshake_fail_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Handshake Fail Test........................N/A\n");
    test_control_return(3);
}
#endif
