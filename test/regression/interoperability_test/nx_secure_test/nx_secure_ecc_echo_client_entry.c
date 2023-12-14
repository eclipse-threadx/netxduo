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
NX_SECURE_TLS_CRYPTO tls_ciphers_client;
NX_SECURE_TLS_CIPHERSUITE_INFO ciphersuite_table_client[10];

UCHAR tls_packet_buffer[4000];

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

#include "../../nx_secure_test/ecc_certs.c"
#include "../../nx_secure_test/test_ca_cert.c"
#include "../../nx_secure_test/test_device_cert.c"

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;

#if defined(NX_SECURE_TLS_ENABLE_TLS_1_0) || defined(NX_SECURE_TLS_ENABLE_TLS_1_1)
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
    &crypto_method_md5,
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

#else
extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc[];
extern const UINT _nx_crypto_ciphersuite_lookup_table_ecc_size;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;
#endif

static CERTIFICATE test_certs[] =
{
    CERTIFICATE_INIT(ECTest_der, ECTest_key_der, ECCA_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer2_der, ECTestServer2_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(test_device_cert_der, test_device_cert_key_der, test_ca_cert_der, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER),
    CERTIFICATE_INIT(ECTestServer10_der, ECTestServer10_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer6_der, ECTestServer6_key_der, ECCA4_der, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER),
};

static UINT ciphersuite_list_0[] = {};
static UINT ciphersuite_list_1[] = {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA};
static UINT ciphersuite_list_2[] = {TLS_ECDH_RSA_WITH_AES_128_CBC_SHA};
static UINT ciphersuite_list_3[] = {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_4[] = {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_5[] =
{
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
};
static UINT ciphersuite_list_6[] = {TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA};
static UINT ciphersuite_list_7[] = {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA};
static UINT ciphersuite_list_8[] = {TLS_ECDH_RSA_WITH_AES_256_CBC_SHA};
static UINT ciphersuite_list_9[] = {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA};
static UINT ciphersuite_list_10[] = {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_11[] = {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384};
static UINT ciphersuite_list_12[] = {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_13[] = {TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384};
static UINT ciphersuite_list_14[] = {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_15[] = {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384};
static UINT ciphersuite_list_16[] = {TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_17[] = {TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384};
static UINT ciphersuite_list_18[] = {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_19[] = {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_20[] = {TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_21[] = {TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_22[] = {TLS_AES_128_GCM_SHA256};
static UINT ciphersuite_list_23[] = {TLS_AES_256_GCM_SHA384};
static UINT ciphersuite_list_24[] = {TLS_AES_128_CCM_SHA256};
static UINT ciphersuite_list_25[] = {TLS_AES_128_CCM_8_SHA256};

static CIPHERSUITE ciphersuites_client[] =
{

    /* Select ciphersuite according to certificate. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0], 0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], 0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[4], 0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[3], 0),

    /* Select ciphersuite according to certificate.
     * The order of client ciphersuites are reversed of server. */
    CIPHERSUITE_INIT(ciphersuite_list_5, NX_TRUE, &test_certs[0], 0),
    CIPHERSUITE_INIT(ciphersuite_list_5, NX_TRUE, &test_certs[1], 0),
    CIPHERSUITE_INIT(ciphersuite_list_5, NX_TRUE, &test_certs[4], 0),

    /* Specified ciphersuites. */
    /*CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0], 0),*/
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1], 0),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[4], 0),

    /* The Server cert supports ECDH_ECDSA and ECDHE_ECDSA. */
    /*CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_2, NX_FALSE, &test_certs[1], 0),*/     /* ECDH_RSA not supported. */
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1], 0),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_FALSE, &test_certs[1], 0),     /* ECDHE_RSA not supported. */

    /* Let the server pickup supported ciphersuite. */
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0], 0),*/
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], 0),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[4], 0),

    /* AES256 or SHA256 or SHA384 ciphersuites. */
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[4], 0),*/
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], 0),
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1], 0),*/
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[4], 0),
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[4], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0], 0),*/

#ifdef NX_SECURE_TLS_ENABLE_TLS_1_0

    /* Specified ciphersuites. */
    /*CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_0),*/
    CIPHERSUITE_INIT(ciphersuite_list_7, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_0),
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[4], NX_SECURE_TLS_VERSION_TLS_1_0),

#endif /* NX_SECURE_TLS_ENABLE_TLS_1_0 */

#ifdef NX_SECURE_TLS_ENABLE_TLS_1_1
    /* Specified ciphersuites. */
    /*CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0], NX_SECURE_TLS_VERSION_TLS_1_1),*/
    CIPHERSUITE_INIT(ciphersuite_list_7, NX_TRUE, &test_certs[1], NX_SECURE_TLS_VERSION_TLS_1_1),
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[4], NX_SECURE_TLS_VERSION_TLS_1_1),
#endif /* NX_SECURE_TLS_ENABLE_TLS_1_1 */

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    /* AES128-GCM ciphersuites. */
    CIPHERSUITE_INIT(ciphersuite_list_18, NX_TRUE, &test_certs[1], 0),
    CIPHERSUITE_INIT(ciphersuite_list_19, NX_TRUE, &test_certs[4], 0),
    /*CIPHERSUITE_INIT(ciphersuite_list_20, NX_TRUE, &test_certs[1], 0),*/
    /*CIPHERSUITE_INIT(ciphersuite_list_21, NX_TRUE, &test_certs[0], 0),*/

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* Test TLS 1.3 ciphersuites. */
    CIPHERSUITE_INIT(ciphersuite_list_22, NX_TRUE, &test_certs[1], 0),
    CIPHERSUITE_INIT(ciphersuite_list_24, NX_TRUE, &test_certs[1], 0),
    CIPHERSUITE_INIT(ciphersuite_list_25, NX_TRUE, &test_certs[1], 0),

    /* Client sends ciphersuites not supported by server. */
    CIPHERSUITE_INIT(ciphersuite_list_22, NX_FALSE, &test_certs[1], 0), 
#endif
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

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &tls_ciphers_client,
                                           crypto_metadata,
                                           sizeof(crypto_metadata));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
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
                                                   cert -> ca_cert,
                                                   cert -> ca_cert_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &trusted_certificate);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    if (cert != NX_NULL)
    {
        memset(&client_local_certificate, 0, sizeof(client_local_certificate));
        status = nx_secure_x509_certificate_initialize(&client_local_certificate,
                                                       cert -> server_cert, cert -> server_cert_len,
                                                       NX_NULL, 0, cert -> server_key,
                                                       cert -> server_key_len,
                                                       cert -> key_type);
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


    for (i = 0; i < sizeof(ciphersuites_client) / sizeof(CIPHERSUITE); i++)
    {

        /* Wait for the semaphore. */
        tls_test_semaphore_wait(semaphore_echo_server_prepared);
        tx_thread_sleep(20 * NX_IP_PERIODIC_RATE);

        ciphersuites_setup(&ciphersuites_client[i], &tls_ciphers_client, ciphersuite_table_client);

        client_tls_setup(&tls_session, ciphersuites_client[i].cert);

        if (ciphersuites_client[i].version)
        {
            status = nx_secure_tls_session_protocol_version_override(&tls_session, ciphersuites_client[i].version);
            exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
        }

        /* Attempt to connect the echo server. */
        status = nx_tcp_client_socket_connect(&tcp_socket, REMOTE_IP_ADDRESS_NUMBER, DEVICE_SERVER_PORT, NX_WAIT_FOREVER);
        exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

        status = nx_secure_tls_session_start(&tls_session, &tcp_socket, NX_WAIT_FOREVER);
        if (((status && ciphersuites_client[i].session_succ) ||
             (!status && !ciphersuites_client[i].session_succ)))
        {
            printf("SESSION START status = %d\n", status);
        }
        exit_if_fail(!((status && ciphersuites_client[i].session_succ) ||
                        (!status && !ciphersuites_client[i].session_succ)), TLS_TEST_UNKNOWN_TYPE_ERROR);
    
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
            exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

            /* Release the receive packet. */
            nx_packet_release(receive_packet);

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
