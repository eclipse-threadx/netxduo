/* The test of properly fail unsupported cipher suites.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define PSK                         "simple_psk"
#define PSK_IDENTITY                "psk_indentity"
#define PSK_HINT                    "psk_hint"
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
static NX_SECURE_TLS_CRYPTO     tls_ciphers;
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table[1];
extern const NX_SECURE_TLS_CRYPTO
                                nx_crypto_tls_ciphers;


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

extern NX_CRYPTO_METHOD crypto_method_none;
extern NX_CRYPTO_METHOD crypto_method_null;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_aes_ccm_8;
extern NX_CRYPTO_METHOD crypto_method_aes_ccm_16;
extern NX_CRYPTO_METHOD crypto_method_aes_128_gcm_16;
extern NX_CRYPTO_METHOD crypto_method_aes_256_gcm_16;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_METHOD crypto_method_ecdh;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha1;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_hmac_md5;
extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_pkcs1;
extern NX_CRYPTO_METHOD crypto_method_auth_psk;
extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha224;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_sha384;
extern NX_CRYPTO_METHOD crypto_method_sha512;
extern NX_CRYPTO_METHOD crypto_method_hkdf_sha1;
extern NX_CRYPTO_METHOD crypto_method_hkdf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha384;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;

static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_all[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    {TLS_AES_128_GCM_SHA256,                  &crypto_method_ecdhe,     &crypto_method_ecdsa,       &crypto_method_aes_128_gcm_16,  96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
    {TLS_AES_128_CCM_SHA256,                  &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_ccm_16,      96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
    {TLS_AES_128_CCM_8_SHA256,                &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_ccm_8,       96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
    
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
//    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,    &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
//    {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,    &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
//    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,      &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
//    {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,      &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},

    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
//    {TLS_RSA_WITH_AES_256_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
//    {TLS_RSA_WITH_AES_128_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    
//    {TLS_PSK_WITH_AES_128_CBC_SHA,            &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
//    {TLS_PSK_WITH_AES_256_CBC_SHA,            &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_PSK_WITH_AES_128_CBC_SHA256,         &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_PSK_WITH_AES_128_CCM_8,              &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_ccm_8,       16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},

    {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,  &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
//    {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,     &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
//    {TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,     &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,    &crypto_method_ecdh,      &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
//    {TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,       &crypto_method_ecdh,      &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
//    {TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,       &crypto_method_ecdh,      &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,  &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,    &crypto_method_ecdh,      &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},

//    {TLS_RSA_WITH_NULL_SHA,                   &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_null,            0,       0,         &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
//    {TLS_RSA_WITH_NULL_MD5,                   &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_null,            0,       0,         &crypto_method_hmac_md5,        16,        &crypto_method_tls_prf_sha256},
};

static UINT ciphersuites[] =
{
#ifndef NX_SECURE_ENABLE_PSK_CIPHERSUITES
//    TLS_PSK_WITH_AES_128_CBC_SHA,
//    TLS_PSK_WITH_AES_256_CBC_SHA,
    TLS_PSK_WITH_AES_128_CBC_SHA256,
#endif /* !NX_SECURE_ENABLE_PSK_CIPHERSUITES */
#if !defined(NX_SECURE_ENABLE_AEAD_CIPHER) || !defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES)
    TLS_PSK_WITH_AES_128_CCM_8,
#endif /* !defined(NX_SECURE_ENABLE_AEAD_CIPHER) || !defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) */

#ifndef NX_SECURE_ENABLE_AEAD_CIPHER
    TLS_RSA_WITH_AES_128_GCM_SHA256,
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */

#ifndef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */

#if !(NX_SECURE_TLS_TLS_1_3_ENABLED)
    TLS_AES_128_GCM_SHA256,
#endif /* !(NX_SECURE_TLS_TLS_1_3_ENABLED) */

};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */


#define ERROR_COUNTER(status) _ERROR_COUNTER(status, __FILE__, __LINE__)

static VOID    _ERROR_COUNTER(UINT status, const char *file, int line)
{
	printf("Error (status = 0x%x) at %s:%d\n", status, file, line);
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_unsupported_ciphersuites_test_application_define(void *first_unused_memory)
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
        ERROR_COUNTER(status);
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &pool_0, _nx_ram_network_driver_1500,
                          ip_0_stack, sizeof(ip_0_stack), 1);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (VOID *)arp_cache, sizeof(arp_cache));
    if (status)
    {
        ERROR_COUNTER(status);
    }

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    nx_secure_tls_initialize();
}

static VOID ciphersuites_setup(UINT ciphersuite)
{
UINT i;
UINT status;

    /* Initialize ciphersuites. */
    memcpy(&tls_ciphers, &nx_crypto_tls_ciphers, sizeof(NX_SECURE_TLS_CRYPTO));

    for (i = 0; i < sizeof(_nx_crypto_ciphersuite_lookup_table_all) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO); i++)
    {
        if (ciphersuite ==
           (UINT)_nx_crypto_ciphersuite_lookup_table_all[i].nx_secure_tls_ciphersuite)
        {
            break;
        }
    }
    
    if (i == sizeof(_nx_crypto_ciphersuite_lookup_table_all) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO))
    {
        ERROR_COUNTER(0);
    }
    
    memcpy(ciphersuite_table,
           &_nx_crypto_ciphersuite_lookup_table_all[i],
           sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
        
    tls_ciphers.nx_secure_tls_ciphersuite_lookup_table = ciphersuite_table;
    tls_ciphers.nx_secure_tls_ciphersuite_lookup_table_size = 1;
    
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    NX_CRYPTO_MEMSET(client_metadata, 0xcc, sizeof(client_metadata));

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &tls_ciphers,
                                           client_metadata,
                                           sizeof(client_metadata));
    if (status)
    {
        ERROR_COUNTER(status);
    }

    memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &client_remote_cert,
                                                       client_cert_buffer,
                                                       sizeof(client_cert_buffer));
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca,
                                                   test_ca_cert_der,
                                                   test_ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &client_trusted_ca);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    if (status)
    {
        ERROR_COUNTER(status);
    }

}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    NX_CRYPTO_MEMSET(server_metadata, 0xcc, sizeof(server_metadata));

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &tls_ciphers,
                                           server_metadata,
                                           sizeof(server_metadata));
    if (status)
    {
        ERROR_COUNTER(status);
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   test_device_cert_der, test_device_cert_der_len,
                                                   NX_NULL, 0, test_device_cert_key_der,
                                                   test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                 &server_local_certificate);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[1],
                                                     sizeof(tls_packet_buffer[1]));
    if (status)
    {
        ERROR_COUNTER(status);
    }

}

static void ntest_0_entry(ULONG thread_input)
{
UINT i;
UINT status;
ULONG response_length;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Unsupported Ciphersuites Test..................");

    if (sizeof(ciphersuites) == 0)
    {
        
        printf("N/A\n");
        test_control_return(3);
    }

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &server_socket_0, "Server socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_tcp_server_socket_listen(&ip_0, SERVER_PORT, &server_socket_0, 5, NX_NULL);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    for (i = 0; i < sizeof(ciphersuites) / sizeof(UINT); i++)
    {

        /* Make sure client thread is ready. */
        tx_thread_suspend(&thread_0);

        ciphersuites_setup(ciphersuites[i]);

        server_tls_setup(&tls_server_session_0);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER(status);
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                              NX_WAIT_FOREVER);
        if (!status)
        {
            ERROR_COUNTER(status);
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
NXD_ADDRESS server_address;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    for (i = 0; i < sizeof(ciphersuites) / sizeof(UINT); i++)
    {

        /* Let server thread run first. */
        tx_thread_resume(&thread_0);

        client_tls_setup(&tls_client_session_0);

        status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                                NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER(status);
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0,
                                              NX_WAIT_FOREVER);
        if (!status)
        {
            ERROR_COUNTER(status);
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
VOID    nx_secure_tls_unsupported_ciphersuites_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Unsupported Ciphersuites Test..................N/A\n");
    test_control_return(3);
}
#endif
