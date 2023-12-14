/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "nx_crypto_ecdh.h"
#include "ecc_certs.c"
#include "test_ca_cert.c"
#include "test_device_cert.c"
#include "nx_crypto_tls_prf_1.h"
#include "nx_crypto_tls_prf_sha256.h"
#include "nx_crypto_hkdf.h"
#include "nx_crypto_md5.h"
#include "nx_crypto_sha1.h"
#include "nx_crypto_sha2.h"
#include "nx_crypto_hmac_sha1.h"
#include "nx_crypto_hmac_sha2.h"
#include "nx_crypto_hmac_md5.h"
#include "nx_crypto_aes.h"
#include "nx_crypto_rsa.h"
#include "nx_crypto_null.h"
#include "nx_crypto_ecdsa.h"
#include "nx_crypto_ecdh.h"
#include "nx_crypto_pkcs1_v1.5.h"

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
#define CIPHERSUITE_INIT(p, s, c)   {p, sizeof(p) / sizeof(UINT), s, c}
#define CERTIFICATE_INIT(s, k, c, t) {s, sizeof(s), k, sizeof(k), c, sizeof(c), t}

/* Define the number of times to (re)establish a TLS connection. */
#define TLS_CONNECT_TIMES           (6)

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
extern const NX_CRYPTO_METHOD *supported_crypto[];
extern const UINT supported_crypto_size;
extern const NX_CRYPTO_CIPHERSUITE *ciphersuite_map[];
extern const UINT ciphersuite_map_size;


static NX_CRYPTO_METHOD test_crypto_method_rsa =
{
    NX_CRYPTO_KEY_EXCHANGE_RSA,               /* RSA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_RSA) + 1,                /* Metadata size in bytes                 */
    _nx_crypto_method_rsa_init,               /* RSA initialization routine.            */
    _nx_crypto_method_rsa_cleanup,            /* RSA cleanup routine                    */
    _nx_crypto_method_rsa_operation           /* RSA operation                          */
};
static NX_CRYPTO_METHOD test_crypto_method_pkcs1 =
{
    NX_CRYPTO_DIGITAL_SIGNATURE_RSA,             /* PKCS#1v1.5 crypto algorithm            */
    0,                                           /* Key size in bits, not used             */
    0,                                           /* IV size in bits, not used              */
    0,                                           /* ICV size in bits, not used             */
    0,                                           /* Block size in bytes, not used          */
    sizeof(NX_CRYPTO_PKCS1) + 1,                     /* Metadata size in bytes                 */
    _nx_crypto_method_pkcs1_v1_5_init,           /* PKCS#1v1.5 initialization routine      */
    _nx_crypto_method_pkcs1_v1_5_cleanup,        /* PKCS#1v1.5 cleanup routine             */
    _nx_crypto_method_pkcs1_v1_5_operation       /* PKCS#1v1.5 operation                   */
};
static NX_CRYPTO_METHOD test_crypto_method_ecdhe =
{
    NX_CRYPTO_KEY_EXCHANGE_ECDHE,                /* ECDHE crypto algorithm                 */
    0,                                           /* Key size in bits                       */
    0,                                           /* IV size in bits                        */
    0,                                           /* ICV size in bits, not used             */
    0,                                           /* Block size in bytes                    */
    sizeof(NX_CRYPTO_ECDH) + 1,                      /* Metadata size in bytes                 */
    _nx_crypto_method_ecdh_init,                 /* ECDH initialization routine            */
    _nx_crypto_method_ecdh_cleanup,              /* ECDH cleanup routine                   */
    _nx_crypto_method_ecdh_operation             /* ECDH operation                         */
};
static NX_CRYPTO_METHOD test_crypto_method_ecdsa =
{
    NX_CRYPTO_DIGITAL_SIGNATURE_ECDSA,           /* ECDSA crypto algorithm                 */
    0,                                           /* Key size in bits                       */
    0,                                           /* IV size in bits                        */
    0,                                           /* ICV size in bits, not used             */
    0,                                           /* Block size in bytes                    */
    sizeof(NX_CRYPTO_ECDSA) + 1,                     /* Metadata size in bytes                 */
    _nx_crypto_method_ecdsa_init,                /* ECDSA initialization routine           */
    _nx_crypto_method_ecdsa_cleanup,             /* ECDSA cleanup routine                  */
    _nx_crypto_method_ecdsa_operation            /* ECDSA operation                        */
};
static NX_CRYPTO_METHOD test_crypto_method_aes_cbc_128 =
{
    NX_CRYPTO_ENCRYPTION_AES_CBC,                /* AES crypto algorithm                   */
    NX_CRYPTO_AES_128_KEY_LEN_IN_BITS,           /* Key size in bits                       */
    NX_CRYPTO_AES_IV_LEN_IN_BITS,                /* IV size in bits                        */
    0,                                           /* ICV size in bits, not used             */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),     /* Block size in bytes                    */
    sizeof(NX_CRYPTO_AES) + 1,                       /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,                  /* AES-CBC initialization routine         */
    _nx_crypto_method_aes_cleanup,               /* AES-CBC cleanup routine                */
    _nx_crypto_method_aes_cbc_operation          /* AES-CBC operation                      */
};
static NX_CRYPTO_METHOD test_crypto_method_hmac =
{
    NX_CRYPTO_HASH_HMAC,                            /* HMAC algorithm                        */
    0,                                              /* Key size in bits, not used            */
    0,                                              /* IV size in bits, not used             */
    0,                                              /* Transmitted ICV size in bits, not used*/
    0,                                              /* Block size in bytes, not used         */
    sizeof(NX_CRYPTO_HMAC) + 1,                         /* Metadata size in bytes                */
    _nx_crypto_method_hmac_init,                    /* HKDF initialization routine           */
    _nx_crypto_method_hmac_cleanup,                 /* HKDF cleanup routine                  */
    _nx_crypto_method_hmac_operation                /* HKDF operation                        */
};
static NX_CRYPTO_METHOD test_crypto_method_hmac_md5 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_MD5_128,            /* HMAC MD5 algorithm                    */
    0,                                                /* Key size in bits                      */
    0,                                                /* IV size in bits, not used             */
    NX_CRYPTO_HMAC_MD5_ICV_FULL_LEN_IN_BITS,          /* Transmitted ICV size in bits          */
    NX_CRYPTO_MD5_BLOCK_SIZE_IN_BYTES,                /* Block size in bytes                   */
    sizeof(NX_CRYPTO_MD5_HMAC) + 1,                       /* Metadata size in bytes                */
    _nx_crypto_method_hmac_md5_init,                  /* HMAC MD5 initialization routine       */
    _nx_crypto_method_hmac_md5_cleanup,               /* HMAC MD5 cleanup routine              */
    _nx_crypto_method_hmac_md5_operation              /* HMAC MD5 operation                    */
};
static NX_CRYPTO_METHOD test_crypto_method_hmac_sha1 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA1_160,      /* HMAC SHA1 algorithm                   */
    0,                                           /* Key size in bits                      */
    0,                                           /* IV size in bits, not used             */
    NX_CRYPTO_HMAC_SHA1_ICV_FULL_LEN_IN_BITS,    /* Transmitted ICV size in bits          */
    NX_CRYPTO_SHA1_BLOCK_SIZE_IN_BYTES,          /* Block size in bytes                   */
    sizeof(NX_CRYPTO_SHA1_HMAC) + 1,                 /* Metadata size in bytes                */
    _nx_crypto_method_hmac_sha1_init,            /* HMAC SHA1 initialization routine      */
    _nx_crypto_method_hmac_sha1_cleanup,         /* HMAC SHA1 cleanup routine             */
    _nx_crypto_method_hmac_sha1_operation        /* HMAC SHA1 operation                   */
};
static NX_CRYPTO_METHOD test_crypto_method_hmac_sha256 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256,       /* HMAC SHA256 algorithm                 */
    0,                                            /* Key size in bits                      */
    0,                                            /* IV size in bits, not used             */
    NX_CRYPTO_HMAC_SHA256_ICV_FULL_LEN_IN_BITS,   /* Transmitted ICV size in bits          */
    NX_CRYPTO_SHA2_BLOCK_SIZE_IN_BYTES,           /* Block size in bytes                   */
    sizeof(NX_CRYPTO_SHA256_HMAC) + 1,                /* Metadata size in bytes                */
    _nx_crypto_method_hmac_sha256_init,           /* HMAC SHA256 initialization routine    */
    _nx_crypto_method_hmac_sha256_cleanup,        /* HMAC SHA256 cleanup routine           */
    _nx_crypto_method_hmac_sha256_operation       /* HMAC SHA256 operation                 */
};
static NX_CRYPTO_METHOD test_crypto_method_md5 =
{
    NX_CRYPTO_HASH_MD5,                            /* MD5 algorithm                         */
    0,                                             /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    NX_CRYPTO_MD5_ICV_LEN_IN_BITS,                 /* Transmitted ICV size in bits          */
    NX_CRYPTO_MD5_BLOCK_SIZE_IN_BYTES,             /* Block size in bytes                   */
    sizeof(NX_CRYPTO_MD5) + 1,                         /* Metadata size in bytes                */
    _nx_crypto_method_md5_init,                    /* MD5 initialization routine            */
    _nx_crypto_method_md5_cleanup,                 /* MD5 cleanup routine                   */
    _nx_crypto_method_md5_operation                /* MD5 operation                         */
};
static NX_CRYPTO_METHOD test_crypto_method_sha1 =
{
    NX_CRYPTO_HASH_SHA1,                           /* SHA1 algorithm                        */
    0,                                             /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    NX_CRYPTO_SHA1_ICV_LEN_IN_BITS,                /* Transmitted ICV size in bits          */
    NX_CRYPTO_SHA1_BLOCK_SIZE_IN_BYTES,            /* Block size in bytes                   */
    sizeof(NX_CRYPTO_SHA1) + 1,                        /* Metadata size in bytes                */
    _nx_crypto_method_sha1_init,                   /* SHA1 initialization routine           */
    _nx_crypto_method_sha1_cleanup,                /* SHA1 cleanup routine                  */
    _nx_crypto_method_sha1_operation               /* SHA1 operation                        */
};
static NX_CRYPTO_METHOD test_crypto_method_sha256 =
{
    NX_CRYPTO_HASH_SHA256,                         /* SHA256 algorithm                      */
    0,                                             /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    NX_CRYPTO_SHA256_ICV_LEN_IN_BITS,              /* Transmitted ICV size in bits          */
    NX_CRYPTO_SHA2_BLOCK_SIZE_IN_BYTES,            /* Block size in bytes                   */
    sizeof(NX_CRYPTO_SHA256) + 1,                      /* Metadata size in bytes                */
    _nx_crypto_method_sha256_init,                 /* SHA256 initialization routine         */
    _nx_crypto_method_sha256_cleanup,              /* SHA256 cleanup routine                */
    _nx_crypto_method_sha256_operation             /* SHA256 operation                      */
};
static NX_CRYPTO_METHOD test_crypto_method_tls_prf_1 =
{
    NX_CRYPTO_PRF_HMAC_SHA1,                       /* TLS PRF algorithm                     */
    0,                                             /* Key size in bits, not used            */
    0,                                             /* IV size in bits, not used             */
    0,                                             /* Transmitted ICV size in bits, not used*/
    0,                                             /* Block size in bytes, not used         */
    sizeof(NX_CRYPTO_TLS_PRF_1) + 1,                   /* Metadata size in bytes                */
    _nx_crypto_method_prf_1_init,                  /* TLS PRF 1 initialization routine      */
    _nx_crypto_method_prf_1_cleanup,               /* TLS PRF 1 cleanup routine             */
    _nx_crypto_method_prf_1_operation              /* TLS PRF 1 operation                   */
};
static NX_CRYPTO_METHOD test_crypto_method_tls_prf_sha256 =
{
    NX_CRYPTO_PRF_HMAC_SHA2_256,                   /* TLS PRF algorithm                     */
    0,                                             /* Key size in bits, not used            */
    0,                                             /* IV size in bits, not used             */
    0,                                             /* Transmitted ICV size in bits, not used*/
    0,                                             /* Block size in bytes, not used         */
    sizeof(NX_CRYPTO_TLS_PRF_SHA256) + 1,              /* Metadata size in bytes                */
    _nx_crypto_method_prf_sha_256_init,            /* TLS PRF SHA256 initialization routine */
    _nx_crypto_method_prf_sha_256_cleanup,         /* TLS PRF SHA256 cleanup routine        */
    _nx_crypto_method_prf_sha_256_operation        /* TLS PRF SHA256 operation              */
};
static NX_CRYPTO_METHOD test_crypto_method_hkdf =
{
    NX_CRYPTO_HKDF_METHOD,                          /* HKDF algorithm                        */
    0,                                              /* Key size in bits, not used            */
    0,                                              /* IV size in bits, not used             */
    0,                                              /* Transmitted ICV size in bits, not used*/
    0,                                              /* Block size in bytes, not used         */
    sizeof(NX_CRYPTO_HKDF) + sizeof(NX_CRYPTO_HMAC),/* Metadata size in bytes                */
    _nx_crypto_method_hkdf_init,                    /* HKDF initialization routine           */
    _nx_crypto_method_hkdf_cleanup,                 /* HKDF cleanup routine                  */
    _nx_crypto_method_hkdf_operation                /* HKDF operation                        */
};
static NX_CRYPTO_METHOD test_crypto_method_ec_secp256 =
{
    NX_CRYPTO_EC_SECP256R1,                   /* EC placeholder                         */
    256,                                      /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    0,                                        /* Metadata size in bytes                 */
    NX_CRYPTO_NULL,                           /* Initialization routine.                */
    NX_CRYPTO_NULL,                           /* Cleanup routine, not used.             */
    _nx_crypto_method_ec_secp256r1_operation, /* Operation                              */
};
extern NX_CRYPTO_METHOD crypto_method_none;
static const NX_CRYPTO_METHOD *test_supported_crypto[] =
{
    &crypto_method_none,
    &test_crypto_method_rsa,
    &test_crypto_method_pkcs1,
    &test_crypto_method_ecdhe,
    &test_crypto_method_ecdsa,
    &test_crypto_method_aes_cbc_128,
    &test_crypto_method_hmac,
    &test_crypto_method_hmac_md5,
    &test_crypto_method_hmac_sha1,
    &test_crypto_method_hmac_sha256,
    &test_crypto_method_md5,
    &test_crypto_method_sha1,
    &test_crypto_method_sha256,
    &test_crypto_method_tls_prf_1,
    &test_crypto_method_tls_prf_sha256,
    &test_crypto_method_hkdf,
    &test_crypto_method_ec_secp256,
};

static const UINT test_supported_crypto_size = sizeof(test_supported_crypto) / sizeof(NX_CRYPTO_METHOD *);


/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


#define do_something_if_fail( p) if(!(p)){printf("ERROR!\n%s:%d\nError: "#p" failed.\n", __FILE__, __LINE__);ERROR_COUNTER();}
//#define do_something_if_fail( p) if(!(p)){ERROR_COUNTER();}
/* Define what the initial system looks like.  */


static VOID    ERROR_COUNTER()
{
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_session_create_ext_test_application_define(void *first_unused_memory)
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

    memset(client_metadata, 0, sizeof(client_metadata));
    status = _nx_secure_tls_session_create_ext(tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           client_metadata,
                                           sizeof(client_metadata));
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

    status = _nx_secure_tls_session_create_ext(tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           server_metadata,
                                           sizeof(server_metadata));
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
UINT status;
ULONG response_length;
NX_PACKET *packet_ptr;
UINT connect_count;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 session_create_ext Test....................");

    /* Test the alignment of crypto buffers. */
    status = _nx_secure_tls_session_create_ext(&tls_server_session_0,
                                               test_supported_crypto, test_supported_crypto_size,
                                               ciphersuite_map, ciphersuite_map_size,
                                               &server_metadata[1],
                                               sizeof(server_metadata) - 1);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    do_something_if_fail(((ULONG)tls_server_session_0.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_scratch & 0x3) == 0);
    do_something_if_fail(((ULONG)tls_server_session_0.nx_secure_session_cipher_metadata_area_client & 0x3) == 0);
    do_something_if_fail(((ULONG)tls_server_session_0.nx_secure_public_cipher_metadata_area & 0x3) == 0);
    do_something_if_fail(((ULONG)tls_server_session_0.nx_secure_hash_mac_metadata_area & 0x3) == 0);
    do_something_if_fail(((ULONG)tls_server_session_0.nx_secure_tls_prf_metadata_area & 0x3) == 0);

    status = nx_secure_tls_session_delete(&tls_server_session_0);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &server_socket_0, "Server socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_tcp_server_socket_listen(&ip_0, SERVER_PORT, &server_socket_0, 5, NX_NULL);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Make sure client thread is ready. */
    tx_thread_suspend(&thread_0);

    server_tls_setup(&tls_server_session_0);

    for(connect_count = 0; connect_count < TLS_CONNECT_TIMES; ++connect_count)
    {

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                              NX_WAIT_FOREVER);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

        if (connect_count == TLS_CONNECT_TIMES - 1)
        {
            tls_server_session_0.nx_secure_tls_remote_sequence_number[0] = 0xFFFFFFFF;
            tls_server_session_0.nx_secure_tls_remote_sequence_number[1] = 0xFFFFFFFF;

            status = nx_secure_tls_session_receive(&tls_server_session_0, &packet_ptr, NX_WAIT_FOREVER);
            do_something_if_fail(NX_NOT_SUCCESSFUL == status);
        }

        nx_secure_tls_session_end(&tls_server_session_0, NX_IP_PERIODIC_RATE);

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
NX_PACKET *packet_ptr;
NXD_ADDRESS server_address;
UINT connect_count;
UINT message_length;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    for(connect_count = 0; connect_count < TLS_CONNECT_TIMES; ++connect_count)
    {
        status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

        /* Let server thread run first. */
        tx_thread_resume(&thread_0);

        client_tls_setup(&tls_client_session_0);

        status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                                NX_WAIT_FOREVER);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

        if (connect_count == TLS_CONNECT_TIMES - 1)
        {
            /* Prepare packet to send. */
            status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }

            packet_ptr->nx_packet_prepend_ptr += NX_SECURE_TLS_RECORD_HEADER_SIZE;
            packet_ptr->nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;

            status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                           &pool_0, NX_NO_WAIT);

            do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);
            tls_client_session_0.nx_secure_tls_local_sequence_number[0] = 0xFFFFFFFF;
            tls_client_session_0.nx_secure_tls_local_sequence_number[1] = 0xFFFFFFFF;

            _nx_secure_tls_send_record(&tls_client_session_0, packet_ptr, NX_SECURE_TLS_APPLICATION_DATA, NX_NO_WAIT);

            message_length = packet_ptr -> nx_packet_length;

            packet_ptr -> nx_packet_prepend_ptr -= NX_SECURE_TLS_RECORD_HEADER_SIZE;
            packet_ptr -> nx_packet_length += NX_SECURE_TLS_RECORD_HEADER_SIZE;

            packet_ptr -> nx_packet_prepend_ptr[3] = (UCHAR)((message_length & 0xFF00) >> 8);
            packet_ptr -> nx_packet_prepend_ptr[4] = (UCHAR)(message_length & 0x00FF);

            status = nx_tcp_socket_send(&client_socket_0, packet_ptr, NX_NO_WAIT);
            do_something_if_fail(NX_SUCCESS == status);
        }

        nx_secure_tls_session_end(&tls_client_session_0, NX_IP_PERIODIC_RATE);
        nx_secure_tls_session_delete(&tls_client_session_0);

        nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
        nx_tcp_client_socket_unbind(&client_socket_0);
    }
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_session_create_ext_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 session_create_ext Test....................N/A\n");
    test_control_return(3);
}
#endif
