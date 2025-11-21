/* This test concentrates on TLS ECC ciphersuites negotiation.  */
#include "tls_test_frame.h"

#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && (defined(NX_SECURE_TLS_ENABLE_TLS_1_0) || defined(NX_SECURE_TLS_ENABLE_TLS_1_1))
#include   "nx_crypto_ecdh.h"
#include   "../../nx_secure_test/ecc_certs.c"
#include   "../../nx_secure_test/test_ca_cert.c"
#include   "../../nx_secure_test/test_device_cert.c"

#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define CIPHERSUITE_INIT(p, s, c, v)   {p, sizeof(p) / sizeof(UINT), s, c, v}
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
    USHORT version;
} CIPHERSUITE;

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

extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha224;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_sha384;
extern NX_CRYPTO_METHOD crypto_method_sha512;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha1;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_hkdf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;

NX_SECURE_X509_CRYPTO _nx_crypto_x509_cipher_lookup_table_ecc[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256,  &crypto_method_ecdsa,     &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_384,  &crypto_method_ecdsa,     &crypto_method_sha384},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_512,  &crypto_method_ecdsa,     &crypto_method_sha512},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_rsa,       &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_384,    &crypto_method_rsa,       &crypto_method_sha384},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_512,    &crypto_method_rsa,       &crypto_method_sha512},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_224,  &crypto_method_ecdsa,     &crypto_method_sha224},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_1,    &crypto_method_ecdsa,     &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_1,      &crypto_method_rsa,       &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_MD5,        &crypto_method_rsa,       &crypto_method_md5},
};

/* Ciphersuite table with ECC. */
static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    {TLS_AES_128_GCM_SHA256,                  &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
    {TLS_AES_128_CCM_SHA256,                  &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_ccm_16,      96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
    {TLS_AES_128_CCM_8_SHA256,                &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_ccm_8,       96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
#endif

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */

    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,    &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,      &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,    &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,      &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */

    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_256_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},

};

static const UINT _nx_crypto_ciphersuite_lookup_table_ecc_size = sizeof(_nx_crypto_ciphersuite_lookup_table_ecc) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO);


/* Define the object we can pass into TLS. */
static const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table_ecc,
    sizeof(_nx_crypto_ciphersuite_lookup_table_ecc) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _nx_crypto_x509_cipher_lookup_table_ecc,
    sizeof(_nx_crypto_x509_cipher_lookup_table_ecc) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    & crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256,
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif


};

static CERTIFICATE test_certs[] =
{
    CERTIFICATE_INIT(ECTest_der, ECTest_key_der, ECCA_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer2_der, ECTestServer2_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(test_device_cert_der, test_device_cert_key_der, test_ca_cert_der, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER),
    CERTIFICATE_INIT(ECTestServer10_der, ECTestServer10_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
};

static UINT ciphersuite_list_0[] = {};
static UINT ciphersuite_list_1[] = {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA};
static UINT ciphersuite_list_2[] = {TLS_ECDH_RSA_WITH_AES_128_CBC_SHA};
static UINT ciphersuite_list_3[] = {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA};
static UINT ciphersuite_list_4[] = {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA};
static UINT ciphersuite_list_5[] =
{
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
};
static UINT ciphersuite_list_6[] = {TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA};
static UINT ciphersuite_list_7[] = {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA};
static UINT ciphersuite_list_8[] = {TLS_ECDH_RSA_WITH_AES_256_CBC_SHA};
static UINT ciphersuite_list_9[] = {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA};


static CIPHERSUITE ciphersuites_server[] =
{
#ifdef NX_SECURE_TLS_ENABLE_TLS_1_0
    /* Select ciphersuite according to certificate. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[3], NX_SECURE_TLS_VERSION_TLS_1_0),

    /* Select ciphersuite according to certificate.
     * The order of client ciphersuites are reversed of server. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_0),

    /* Specified ciphersuites. */
    /*CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_0),

    /* The Server cert supports ECDH_ECDSA and ECDHE_ECDSA. */
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_FALSE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_FALSE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),

    /* Let the server pickup supported ciphersuite. */
    /*CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_0),

    /* AES256 ciphersuites. */
    /*CIPHERSUITE_INIT(ciphersuite_list_6, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    CIPHERSUITE_INIT(ciphersuite_list_7, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),
    /*CIPHERSUITE_INIT(ciphersuite_list_8, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_0),
#endif /* NX_SECURE_TLS_ENABLE_TLS_1_0 */

#ifdef NX_SECURE_TLS_ENABLE_TLS_1_1
    /* Select ciphersuite according to certificate. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_1),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_1),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[3], NX_SECURE_TLS_VERSION_TLS_1_1),

    /* Select ciphersuite according to certificate.
     * The order of client ciphersuites are reversed of server. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_1),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_1),

    /* Specified ciphersuites. */
    /*CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_1),

    /* The Server cert supports ECDH_ECDSA and ECDHE_ECDSA. */
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_FALSE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_FALSE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),

    /* Let the server pickup supported ciphersuite. */
    /*CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_1),

    /* AES256 ciphersuites. */
    /*CIPHERSUITE_INIT(ciphersuite_list_6, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    CIPHERSUITE_INIT(ciphersuite_list_7, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),
    /*CIPHERSUITE_INIT(ciphersuite_list_8, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2], NX_SECURE_TLS_VERSION_TLS_1_1),
#endif /* NX_SECURE_TLS_ENABLE_TLS_1_1 */

};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* Global demo emaphore. */
extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;


/* Define the pointer of current instance control block. */
static TLS_TEST_INSTANCE* demo_instance_ptr;

/*  Instance one test entry. */
INT nx_secure_ecc_server_ciphersuites_entry(TLS_TEST_INSTANCE* instance_ptr)
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

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, CERTIFICATE *cert, USHORT version)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &tls_ciphers_server,
                                           server_metadata,
                                           sizeof(server_metadata));
    show_error_message_if_fail( NX_SUCCESS == status);

    status = nx_secure_tls_session_protocol_version_override(tls_session_ptr, version);
    show_error_message_if_fail( NX_SUCCESS == status);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    show_error_message_if_fail( NX_SUCCESS == status);

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   cert -> server_cert, cert -> server_cert_len,
                                                   NX_NULL, 0, cert -> server_key,
                                                   cert -> server_key_len,
                                                   cert -> key_type);
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

    for (i = 0; i < sizeof(ciphersuites_server) / sizeof(CIPHERSUITE); i++)
    {

        ciphersuites_setup(&ciphersuites_server[i], &tls_ciphers_server, ciphersuite_table_server);

        server_tls_setup(&tls_server_session_0, ciphersuites_server[i].cert, ciphersuites_server[i].version);

        tls_test_semaphore_post(semaphore_echo_server_prepared);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        exit_if_fail( NX_SUCCESS == status, 1);

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                              NX_WAIT_FOREVER);
        exit_if_fail (!((status && ciphersuites_server[i].session_succ) ||
                        (!status && !ciphersuites_server[i].session_succ)), 2);

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
INT nx_secure_ecc_server_ciphersuites_entry(TLS_TEST_INSTANCE* instance_ptr)
{
    exit(TLS_TEST_NOT_AVAILABLE);
}
#endif
