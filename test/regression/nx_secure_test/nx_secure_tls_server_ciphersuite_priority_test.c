/* This test verifies that a TLS server will select the top-priority ciphersuite in the local ciphersuite table from the selection provided 
   by the remote client. The priority is determined by the order in the ciphersuite table, thus the highest priority ciphersuite has
   the lowest-value index in the table. */
#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
#define __LINUX__

/* Define the number of times to (re)establish a TLS connection. */
#define TLS_CONNECT_TIMES (6)

#define LARGE_SEND_SIZE   3000

#define MSG "----------abcdefgh20----------ABCDEFGH40----------klmnopqr60----------KLMNOPQR80--------------------"


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


extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;

NX_SECURE_X509_CRYPTO _test_x509_cipher_lookup_table[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_rsa,       &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_384,    &crypto_method_rsa,       &crypto_method_sha384},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_512,    &crypto_method_rsa,       &crypto_method_sha512},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_1,      &crypto_method_rsa,       &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_MD5,        &crypto_method_rsa,       &crypto_method_md5},
};   

/* Server ciphersuite table - lowest index is highest priority. */
static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_server[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */   
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif

    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    
    {TLS_PSK_WITH_AES_128_CBC_SHA256,         &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_PSK_WITH_AES_128_CCM_8,              &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_ccm_8,       16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,  &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,    &crypto_method_ecdh,      &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,  &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,    &crypto_method_ecdh,      &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif
};

/* Client table - NOTE: ordering is purposefully changed in this table to force the negotiation on the server side. */
static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_client[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */    
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif

/* ------- > IF ECC is not enabled this ciphersuite should be chosen. */
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},

/*-----> Note that with ECC, this ciphersuite should be chosen given the server table above. */
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#endif

    {TLS_PSK_WITH_AES_128_CBC_SHA256,         &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_PSK_WITH_AES_128_CCM_8,              &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_ccm_8,       16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,  &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,    &crypto_method_ecdh,      &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,  &crypto_method_ecdh,      &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,    &crypto_method_ecdh,      &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif
};


/* EXPECTED VALUES for test case below. */

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
/*ECC case: we are using an RSA cert so use RSA instead of ECDSA. */
USHORT expected_ciphersuite = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
#else
/* RSA case: */
USHORT expected_ciphersuite = TLS_RSA_WITH_AES_256_CBC_SHA256;
#endif

/* Define the object we can pass into TLS. */
NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_server =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table_server,
    sizeof(_nx_crypto_ciphersuite_lookup_table_server) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _test_x509_cipher_lookup_table,
    sizeof(_test_x509_cipher_lookup_table) / sizeof(NX_SECURE_X509_CRYPTO),
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

  

/* Define the object we can pass into TLS. */
NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_client =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table_client,
    sizeof(_nx_crypto_ciphersuite_lookup_table_client) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _test_x509_cipher_lookup_table,
    sizeof(_test_x509_cipher_lookup_table) / sizeof(NX_SECURE_X509_CRYPTO),
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



/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NX_SECURE_TLS_SESSION   client_tls_session;
static NX_SECURE_TLS_SESSION   server_tls_session;

static NX_SECURE_X509_CERT certificate;
static NX_SECURE_X509_CERT server_certificate;
static NX_SECURE_X509_CERT duplicate_server_certificate;
static NX_SECURE_X509_CERT ica_certificate;
static NX_SECURE_X509_CERT client_certificate;
static NX_SECURE_X509_CERT trusted_certificate;

/* Combined certificate buffers for new API. */
UCHAR remote_client_certs_buffer[(sizeof(NX_SECURE_X509_CERT) + 2000) * 2];
UCHAR remote_server_certs_buffer[(sizeof(NX_SECURE_X509_CERT) + 2000) * 2];

UCHAR server_packet_buffer[4000];
UCHAR client_packet_buffer[4000];

CHAR server_crypto_metadata[16000]; 
CHAR client_crypto_metadata[16000]; 

static UCHAR large_app_data[LARGE_SEND_SIZE];
static UCHAR server_recv_buffer[LARGE_SEND_SIZE];
static UCHAR client_recv_buffer[LARGE_SEND_SIZE];

/* Test PKI (3-level). */
#include "test_ca_cert.c"
#include "tls_two_test_certs.c"
#define ca_cert_der test_ca_cert_der
#define ca_cert_der_len test_ca_cert_der_len

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
static UCHAR tls_psk[] = { 0x1a, 0x2b, 0x3c, 0x4d };
#endif


#define     DEMO_STACK_SIZE  4096 //  (3 * 1024 / sizeof(ULONG))

/* Define the IP thread's stack area.  */
#define IP_STACK_SIZE 4096 //(2 * 1024 / sizeof(ULONG))

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_BYTES  ((1536 + sizeof(NX_PACKET)) * 20)
#define NX_PACKET_POOL_SIZE (NX_PACKET_POOL_BYTES/sizeof(ULONG) + 64 / sizeof(ULONG))

/* Define the ARP cache area.  */
#define ARP_AREA_SIZE 1024 // (512 / sizeof(ULONG))

#define TOTAL_STACK_SPACE (2 * (DEMO_STACK_SIZE + IP_STACK_SIZE + NX_PACKET_POOL_SIZE + ARP_AREA_SIZE))

#ifndef __LINUX__
ULONG test_stack_area[TOTAL_STACK_SPACE + 2000];
#endif

static ULONG pool_area[2][NX_PACKET_POOL_SIZE];

/* Define the counters used in the demo application...  */
ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */
#ifndef __LINUX__
void    tx_application_define(void *first_unused_memory)
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void           nx_secure_tls_server_cipher_priority_test_application_define(void *first_unused_memory)
#endif
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
#ifndef __LINUX__
    pointer = (CHAR*)test_stack_area;
#else
    pointer = (CHAR *) first_unused_memory;
#endif

    error_counter = 0;
    
    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();
      
    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pool_area[0], sizeof(pool_area[0]));

    if(status)
    {
        printf("Error in function nx_packet_pool_create: 0x%x\n", status);
        error_counter++;
    }
      
    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 1536, pool_area[1], sizeof(pool_area[1]));

    if(status)
    {
        printf("Error in function nx_packet_pool_create: 0x%x\n", status);
        error_counter++;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, IP_STACK_SIZE, 1);
    pointer = pointer + IP_STACK_SIZE;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_1500,
                           pointer, IP_STACK_SIZE, 1);
    pointer = pointer + IP_STACK_SIZE;

    if(status)
    {
        printf("Error in function nx_ip_create: 0x%x\n", status);
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;

    /* Check ARP enable status.  */
    if(status)
    {
        printf("Error in function nx_arp_enable: 0x%x\n", status);
        error_counter++;
    }

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
    {
        printf("Error in function tcp_enable: 0x%x\n", status);
        error_counter++;
    }
    
    nx_secure_tls_initialize();
}

/*  Define callbacks used by TLS.  */
/* Include CRL associated with Verisign root CA (for AWS) for demo purposes. */
#include "test_ca.crl.der.c"


/* Timestamp function - should return Unix time formatted 32-bit integer. */
ULONG tls_timestamp_function(void)
{
    // Return a fixed epoch - 1500939067 seconds = 07/24/2017 @ 11:31pm (UTC) 
    // 1541030400 = 0x5BDA4200L = 11/01/2018 @ 12:00AM (UTC)
    return(0x5BDA4200L); 
}

/* Callback invoked whenever TLS has to validate a certificate from a remote host. Additional checking
   of the certificate may be done by the application here. */
ULONG certificate_verification_callback(NX_SECURE_TLS_SESSION *session, NX_SECURE_X509_CERT* certificate)
{
const CHAR *dns_tld = "certificate_with_policies"; //"NX Secure Device Certificate";
UINT status;
NX_SECURE_X509_CERTIFICATE_STORE *store;
NX_SECURE_X509_CERT *issuer_certificate;
UINT                 issuer_location;
USHORT key_usage_bitfield;

    /* Check DNS entry string. */
    status = nx_secure_x509_common_name_dns_check(certificate, (UCHAR*)dns_tld, strlen(dns_tld));
  
    if(status != NX_SUCCESS)
    {
        printf("Error in certificate verification: DNS name did not match CN\n");
        return(status);
    }    

#if !defined(NX_SECURE_X509_DISABLE_CRL) && !defined(NX_SECURE_DISABLE_X509)

    /* Check CRL revocation status. */
    store = &session -> nx_secure_tls_credentials.nx_secure_tls_certificate_store;
    
    status = nx_secure_x509_crl_revocation_check(test_ca_crl_der, test_ca_crl_der_len, store, certificate);

    if(status != NX_SUCCESS)
    {
        return(status);
    }
#endif

    /* Check key usage extension. */
    status = nx_secure_x509_key_usage_extension_parse(certificate, &key_usage_bitfield);

    if(status != NX_SUCCESS)
    {
        printf("Error in parsing key usage extension: 0x%x\n", status);
        return(status);
    }

    if((key_usage_bitfield & NX_SECURE_X509_KEY_USAGE_DIGITAL_SIGNATURE) == 0 ||
       (key_usage_bitfield & NX_SECURE_X509_KEY_USAGE_NON_REPUDIATION)   == 0 ||
       (key_usage_bitfield & NX_SECURE_X509_KEY_USAGE_KEY_ENCIPHERMENT)  == 0)
    {
        printf("Expected key usage bitfield bits not set!\n");
        return(NX_SECURE_X509_KEY_USAGE_ERROR);
    }

    /* Extended key usage - look for specific OIDs. */
    status = nx_secure_x509_extended_key_usage_extension_parse(certificate, NX_SECURE_TLS_X509_TYPE_PKIX_KP_TIME_STAMPING);

    if(status != NX_SUCCESS)
    {
        printf("Expected certificate extension not found!\n");
    }

    return(NX_SUCCESS);
}


/* Define the test threads.  */

/* -----===== SERVER =====----- */

/* Define a TLS name to test the Server Name Indication extension. */
#define TLS_SNI_SERVER_NAME "testing"

static CHAR *html_data =  "HTTP/1.1 200 OK\r\n" \
        "Date: Fri, 15 Sep 2016 23:59:59 GMT\r\n" \
        "Content-Type: text/html\r\n" \
        "Content-Length: 200\r\n\r\n" \
        "<html>\r\n"\
        "<body>\r\n"\
        "<b>Hello NetX Secure User!</b>\r\n"\
        "This is a simple webpage\r\n"\
        "served up using NetX Secure!\r\n"\
        "</body>\r\n"\
        "</html>\r\n";

/* Callback for ClientHello extensions processing. */
static ULONG tls_server_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extensions, UINT num_extensions)
{
NX_SECURE_X509_DNS_NAME dns_name;
INT compare_value;
UINT status;
NX_SECURE_X509_CERT *cert_ptr;

    /* Process clienthello extensions. */
    status = _nx_secure_tls_session_sni_extension_parse(tls_session, extensions, num_extensions, &dns_name);

#ifdef NX_SECURE_TLS_SNI_EXTENSION_DISABLED
    if(status != NX_SECURE_TLS_EXTENSION_NOT_FOUND)
    {
        printf("SNI extension should not exist\n");
        error_counter++;
    }
#else
    if(status != NX_SUCCESS)
    {
        printf("SNI extension parsing failed with status 0x%x\n", status);
        error_counter++;
    }

    /* NULL-terminate name string. */
    dns_name.nx_secure_x509_dns_name[dns_name.nx_secure_x509_dns_name_length] = 0;

    /* Make sure our SNI name matches. */
    compare_value = memcmp(dns_name.nx_secure_x509_dns_name, TLS_SNI_SERVER_NAME, strlen(TLS_SNI_SERVER_NAME));

    if(compare_value || dns_name.nx_secure_x509_dns_name_length != strlen(TLS_SNI_SERVER_NAME))
    {
        printf("Error in SNI processing. SNI name '%s' does not match '%s'\n", dns_name.nx_secure_x509_dns_name, TLS_SNI_SERVER_NAME);
        error_counter++;
    }
#endif

    /* Find a certificate based on it's unique ID. */
    _nx_secure_tls_server_certificate_find(tls_session, &cert_ptr, 1);

    /* Set the certificate we want to use. */
    nx_secure_tls_active_certificate_set(tls_session, cert_ptr);

    return(NX_SUCCESS);
}



static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
NX_PACKET *send_packet;
NX_PACKET *receive_packet;
UCHAR receive_buffer[100];
ULONG bytes;
UINT connect_count;
UINT i;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Server Ciphersuite Priority Test...............");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_ip_status_check: 0x%x\n", status);
        error_counter++;
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16*1024,
                                  NX_NULL, ntest_0_disconnect_received);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_create: 0x%x\n", status);
        error_counter++;
    }

    /* Create a TLS session for our socket.  */
    status =  nx_secure_tls_session_create(&server_tls_session,
                                           &nx_crypto_tls_ciphers_server,
                                           server_crypto_metadata,
                                           sizeof(server_crypto_metadata));

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_secure_tls_session_create: 0x%x\n", status);
        error_counter++;
    }

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    status = _nx_secure_tls_ecc_initialize(&server_tls_session, nx_crypto_ecc_supported_groups, nx_crypto_ecc_supported_groups_size, nx_crypto_ecc_curves);

    if(status)
    {
        printf("Failed ECC init: %02x\n", status);
        error_counter++;
    }
#endif

    /* Setup our packet reassembly buffer. */
    nx_secure_tls_session_packet_buffer_set(&server_tls_session, server_packet_buffer, sizeof(server_packet_buffer));

    /* Enable Client Certificate Verification. */
    nx_secure_tls_session_x509_client_verify_configure(&server_tls_session, 2, remote_client_certs_buffer,
    																	sizeof(remote_client_certs_buffer));

    /* Add a timestamp function for time checking and timestamps in the TLS handshake. */
    _nx_secure_tls_session_time_function_set(&server_tls_session, tls_timestamp_function);

    /* Setup the callback invoked when TLS has a certificate it wants to verify so we can
       do additional checks not done automatically by TLS. */
    _nx_secure_tls_session_certificate_callback_set(&server_tls_session, certificate_verification_callback);
    
    /* Set callback for server TLS extension handling. */
    _nx_secure_tls_session_server_callback_set(&server_tls_session, tls_server_callback);



    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Initialize our certificate
    status = nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_tls_server_certificate_add(&server_tls_session, &certificate, 1);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_secure_x509_certificate_initialize(&server_certificate, test_server_cert_der, test_server_cert_der_len, NX_NULL, 0, test_server_cert_key_der, test_server_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_tls_server_certificate_add(&server_tls_session, &server_certificate, 2);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add a duplicate of the server certificate to make sure we handle duplicate certificates in the handshake. */
    status = nx_secure_x509_certificate_initialize(&duplicate_server_certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_tls_server_certificate_add(&server_tls_session, &duplicate_server_certificate, 3);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_secure_x509_certificate_initialize(&ica_certificate, ica_cert_der, ica_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_tls_local_certificate_add(&server_tls_session, &ica_certificate);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add a CA Certificate to our trusted store for verifying incoming client certificates. */
    status = nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_tls_trusted_certificate_add(&server_tls_session, &trusted_certificate);
    EXPECT_EQ(NX_SUCCESS, status);

    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, ntest_0_connect_received);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_server_socket_listen: 0x%x\n", status);
        error_counter++;
    }

    /* Fill the large send buffer.  */
    for (i = 0; i < LARGE_SEND_SIZE; ++i)
    {
        large_app_data[i] = (UCHAR)(i & 0xFF);
    }

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    /* For PSK ciphersuites, add a PSK and identity hint.  */
    nx_secure_tls_psk_add(&server_tls_session, tls_psk, sizeof(tls_psk), "Client_identity", 15, "12345678", 8);
#endif

    for(connect_count = 0; connect_count < TLS_CONNECT_TIMES; ++connect_count)
    {

        /* Accept a client socket connection.  */
        status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

        tx_thread_suspend(&ntest_0);


        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_server_socket_accept: 0x%x\n", status);
            error_counter++;
        }

        /* Start the TLS Session now that we have a connected socket. */
        status = nx_secure_tls_session_start(&server_tls_session, &server_socket, NX_WAIT_FOREVER);

        /* Check for error.  */
        if (status)
        {
            printf("TLS Server Session start failed, error: %x\n", status);
            error_counter++;
        }

/* -----> Verify that the server has selected the appropriate ciphersuite. */
        if(server_tls_session.nx_secure_tls_session_ciphersuite->nx_secure_tls_ciphersuite != expected_ciphersuite)
        {
            printf("TLS Server did not choose the highest-priority ciphersuite, expected: %x got:%x ERROR\n", expected_ciphersuite, server_tls_session.nx_secure_tls_session_ciphersuite->nx_secure_tls_ciphersuite);
            error_counter++;
        }

        /* Receive the HTTP request, and print it out. */
        status = nx_secure_tls_session_receive(&server_tls_session, &receive_packet, NX_WAIT_FOREVER);
    
        /* Check for error.  */
        if (status)
        {
            printf("TLS Server receive failed, error: %x\n", status);
            error_counter++;
            return;
        }
        else
        {
            status = nx_packet_data_extract_offset(receive_packet, 0, receive_buffer, 100, &bytes);
            receive_buffer[bytes] = 0;

            if(bytes != 14)
            {
                printf("ERROR: data received by server does not match that sent by client.\n");
                error_counter++;
            }

            error_counter += strncmp((CHAR *)receive_buffer, "Hello there!\r\n", bytes);

            if(error_counter)
            {
                printf("Error in receiving data.\n");
            }

            //printf("Received data: %s\n", receive_buffer);

        }

        nx_packet_release(receive_packet);

        /* Allocate a return packet and send our HTML data back to the client. */

        nx_secure_tls_packet_allocate(&server_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, html_data, strlen(html_data), &pool_0, NX_WAIT_FOREVER);

        /* TLS send the HTML/HTTPS data back to the client. */
        status = nx_secure_tls_session_send(&server_tls_session, send_packet, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
              printf("Error in Server TLS send: %x\n", status);

              /* Release the packet.  */
              nx_packet_release(send_packet);
              error_counter++;
        }


        /* Receive the large application data. */
        status = nx_secure_tls_session_receive(&server_tls_session, &receive_packet, NX_WAIT_FOREVER);

        /* Check for error.  */
        if (status)
        {
            printf("TLS Server receive failed, error: %x\n", status);
            error_counter++;
        }
        else
        {
            memset(server_recv_buffer, 0, LARGE_SEND_SIZE);

            status = nx_packet_data_extract_offset(receive_packet, 0, server_recv_buffer, LARGE_SEND_SIZE, &bytes);

            if (bytes != LARGE_SEND_SIZE)
            {
                printf("ERROR: data received by server does not match that sent by client.\n");
                error_counter++;
            }

            /* Check the received buffer. */
            for (i = 0; i < LARGE_SEND_SIZE; ++i)
            {
                if (server_recv_buffer[i] != large_app_data[i])
                {
                    printf("ERROR: data received by server does not match that sent by client.\n");
                    error_counter++;
                    break;
                }
            }

        }

        nx_packet_release(receive_packet);


        /* Attempt a renegotiation after receiving. */
#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
        status  = nx_secure_tls_session_renegotiate(&server_tls_session, NX_WAIT_FOREVER);

        if(status)
        {
            printf("TLS renegotiation request failed with error: 0x%x\n", status);
            error_counter++;
        }
#endif

        /* Allocate a return packet and send the large application data back to the client. */

        nx_secure_tls_packet_allocate(&server_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, large_app_data, LARGE_SEND_SIZE, &pool_0, NX_WAIT_FOREVER);

        /* TLS send the data back to the client. */
        status = nx_secure_tls_session_send(&server_tls_session, send_packet, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            printf("Error in Server TLS send: %x\n", status);

            /* Release the packet.  */
            nx_packet_release(send_packet);
            error_counter++;
        }


        tx_thread_sleep(10);

        /* End the TLS session. This is required to properly shut down the TLS connection. */
        status = nx_secure_tls_session_end(&server_tls_session, NX_WAIT_FOREVER);

        /* If the session did not shut down cleanly, this is a possible security issue. */
        if (status)
        {
              printf("Error in TLS Server session end: %x\n", status);
              error_counter++;
        }

        /* Disconnect the server socket.  */
        status = nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);

        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_socket_disconnect: 0x%x\n", status);
            error_counter++;
        }

        /* Unaccept the server socket.  */
        status = nx_tcp_server_socket_unaccept(&server_socket);

        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_server_socket_unaccept: 0x%x\n", status);
            error_counter++;
        }

        /* Unlisten on the server port.  */
        status = nx_tcp_server_socket_relisten(&ip_0, 12, &server_socket);

        /* Check for error.  */
        if (status)
        {
            printf("Error in function nx_tcp_server_socket_relisten: 0x%x\n", status);
            error_counter++;
        }


    } /* End connect loop. */

    /* Unlisten on the server port.  */
    status = nx_tcp_server_socket_unlisten(&ip_0, 12);

    /* Check for error.  */
    if (status)
    {
        printf("Error in function nx_tcp_server_socket_unlisten: 0x%x\n", status);
        error_counter++;
    }

    /* Delete TLS session. */
    status = nx_secure_tls_session_delete(&server_tls_session);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_secure_tls_session_delete: 0x%x\n", status);
        error_counter++;
    }

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_delete: 0x%x\n", status);
        error_counter++;
    }
}



/* -----===== CLIENT =====----- */

static ULONG tls_client_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extensions, UINT num_extensions)
{
    /* Process serverhello extensions. */
    return(NX_SUCCESS);
}


static void    ntest_1_entry(ULONG thread_input)
{
UINT         status;
NX_PACKET *send_packet;
NX_PACKET *receive_packet;
UCHAR receive_buffer[400];
ULONG bytes;
UINT connect_count;
UINT i;
NX_SECURE_X509_DNS_NAME dns_name;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 1024*16,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_create: 0x%x\n", status);
        error_counter++;
    }


    /* Create a TLS session for our socket.  */
    status =  nx_secure_tls_session_create(&client_tls_session,
                                           &nx_crypto_tls_ciphers_client,
                                           client_crypto_metadata,
                                           sizeof(client_crypto_metadata));

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_secure_tls_session_create: 0x%x\n", status);
        error_counter++;
    }

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    status = _nx_secure_tls_ecc_initialize(&client_tls_session, nx_crypto_ecc_supported_groups, nx_crypto_ecc_supported_groups_size, nx_crypto_ecc_curves);

    if(status)
    {
        printf("Failed ECC init: %02x\n", status);
        error_counter++;
    }
#endif

    /* Setup our packet reassembly buffer. */
    nx_secure_tls_session_packet_buffer_set(&client_tls_session, client_packet_buffer, sizeof(client_packet_buffer));

    /* Make sure client certificate verification is disabled. */
    nx_secure_tls_session_client_verify_disable(&client_tls_session);

    /* Need to allocate space for the certificate coming in from the remote host. */
    nx_secure_tls_remote_certificate_buffer_allocate(&client_tls_session, 2, remote_server_certs_buffer, sizeof(remote_server_certs_buffer));

    //nx_secure_x509_certificate_initialize(&certificate, cert_der, cert_der_len, NX_NULL, 0, private_key_der, private_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    nx_secure_x509_certificate_initialize(&client_certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    nx_secure_tls_local_certificate_add(&client_tls_session, &client_certificate);

    /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
    nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&client_tls_session, &trusted_certificate);


    /* Add a timestamp function for time checking and timestamps in the TLS handshake. */
    _nx_secure_tls_session_time_function_set(&client_tls_session, tls_timestamp_function);

    /* Setup the callback invoked when TLS has a certificate it wants to verify so we can
       do additional checks not done automatically by TLS. */
    _nx_secure_tls_session_certificate_callback_set(&client_tls_session, certificate_verification_callback);

    /* Set callback for server TLS extension handling. */
    _nx_secure_tls_session_client_callback_set(&client_tls_session, tls_client_callback);


    /* Set up a DNS name for the Server Name Indication extension. The server thread will compare
     * to make sure the name was sent and recieved appropriately. */
    nx_secure_x509_dns_name_initialize(&dns_name, TLS_SNI_SERVER_NAME, strlen(TLS_SNI_SERVER_NAME));
    nx_secure_tls_session_sni_extension_set(&client_tls_session, &dns_name);

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    /* For PSK ciphersuites, add a PSK and identity hint.  For the client, we need to add the identity
       and set it for the particular server with which we want to communicate.
       "Client_identity" is the identity hint used by default in the OpenSSL s_server application
       when uisng PSK ciphersuites. */
    nx_secure_tls_psk_add(&client_tls_session, tls_psk, sizeof(tls_psk), "Client_identity", 15, "12345678", 8);
    
    /* Our target server will use this PSK entry. */
    nx_secure_tls_client_psk_set(&client_tls_session, tls_psk, sizeof(tls_psk), "Client_identity", 15, "12345678", 8);
#endif

    /* Connect multiple times. */
    for(connect_count = 0; connect_count < TLS_CONNECT_TIMES; ++connect_count)
    {
        /* Bind the socket.  */
        status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_client_socket_bind: 0x%x\n", status);
            error_counter++;
        }

        status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);

        if(status)
        {
            printf("Error in function nx_tcp_client_socket_connect: 0x%x\n", status);
            error_counter++;
        }

        tx_thread_resume(&ntest_0);

        status = nx_secure_tls_session_start(&client_tls_session, &client_socket, NX_WAIT_FOREVER);

        /* Check for error.  */
        if (status)
        {
            printf("Error in Client TLS handshake: 0x%02X\n", status);
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Send some data to be read by the server thread instance. */
        nx_secure_tls_packet_allocate(&client_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, "Hello there!\r\n", 14, &pool_0, NX_WAIT_FOREVER);
        status = nx_secure_tls_session_send(&client_tls_session, send_packet, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
              printf("Error in Client TLS send: %x\n", status);

              /* Release the packet.  */
              nx_packet_release(send_packet);
              error_counter++;
        }

        /* Receive the echoed and reversed data, and print it out. */
        status = nx_secure_tls_session_receive(&client_tls_session, &receive_packet, NX_WAIT_FOREVER);

        /* Check for error.  */
        if (status)
        {
            printf("TLS receive failed in Client, error: %x\n", status);
            error_counter++;
        }
        else
        {
            status = nx_packet_data_extract_offset(receive_packet, 0, receive_buffer, 400, &bytes);
            receive_buffer[bytes] = 0;
            if(strlen(html_data) != bytes)
            {
                printf("Error: received data on client does not match that sent by server. \n");
                error_counter++;
            }
            error_counter += strncmp((CHAR *)receive_buffer, html_data, strlen(html_data));
            
            if(error_counter)
            {
                printf("Error in received data from server\n");
            }
            //printf("Received data: %s\n", receive_buffer);
        }

        /* Attempt a renegotiation after receiving. */
#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
        status  = nx_secure_tls_session_renegotiate(&client_tls_session, NX_WAIT_FOREVER);

        if(status)
        {
            printf("TLS renegotiation request failed with error: 0x%x\n", status);
            error_counter++;
        }
#endif

        nx_packet_release(receive_packet);

        /* Send a large data to the server. */
        nx_secure_tls_packet_allocate(&client_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, large_app_data, LARGE_SEND_SIZE, &pool_0, NX_WAIT_FOREVER);
        status = nx_secure_tls_session_send(&client_tls_session, send_packet, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            printf("Error in Client TLS send: %x\n", status);

            /* Release the packet.  */
            nx_packet_release(send_packet);
            error_counter++;
        }

        /* Receive the large data. */
        status = nx_secure_tls_session_receive(&client_tls_session, &receive_packet, NX_WAIT_FOREVER);

        /* Check for error.  */
        if (status)
        {
            printf("TLS receive failed in Client, error: %x\n", status);
            error_counter++;
        }
        else
        {
            memset(client_recv_buffer, 0, LARGE_SEND_SIZE);
            status = nx_packet_data_extract_offset(receive_packet, 0, client_recv_buffer, LARGE_SEND_SIZE, &bytes);
            
            if (LARGE_SEND_SIZE != bytes)
            {
                printf("Error: received data on client does not match that sent by server. \n");
                error_counter++;
            }
            
            /* Check the received buffer. */
            for (i = 0; i < LARGE_SEND_SIZE; ++i)
            {
                if (client_recv_buffer[i] != large_app_data[i])
                {
                    printf("Error: received data on client does not match that sent by server. \n");
                    error_counter++;
                    break;
                }
            }
        }

        /* Test nx_secure_tls_session_send for send_packet with insufficient header room. */
        nx_packet_allocate(&pool_0, &send_packet, 0, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, "Hello there!\r\n", 14, &pool_0, NX_WAIT_FOREVER);
        status = nx_secure_tls_session_send(&client_tls_session, send_packet, NX_IP_PERIODIC_RATE);
        if (status != NX_SECURE_TLS_INVALID_PACKET)
        {
            printf("Expected NX_SECURE_TLS_INVALID_PACKET but got %x\n", status);
            error_counter++;
        }
        nx_packet_release(send_packet);

        tx_thread_sleep(10);
        nx_packet_release(receive_packet);

        /* End the TLS session. This is required to properly shut down the TLS connection. */
        status = nx_secure_tls_session_end(&client_tls_session, NX_WAIT_FOREVER);
    
        /* If the session did not shut down cleanly, this is a possible security issue. */
        if (status)
        {
            printf("Error in TLS Client session end: %x\n", status);
            error_counter++;
        }


        /* Disconnect this socket.  */
        status = nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_socket_disconnect: 0x%x\n", status);
            error_counter++;
        }

        /* Bind the socket.  */
        status = nx_tcp_client_socket_unbind(&client_socket);

        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_client_socket_unbind: 0x%x\n", status);
            error_counter++;
        }

    } /* End connect loop. */

    /* Delete TLS session. */
    status = nx_secure_tls_session_delete(&client_tls_session);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_secure_tls_session_delete: %x\n", status);
        error_counter++;
    }

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_delete: %x\n", status);
        error_counter++;
    }

    /* Shutdown the TLS services. */
    nx_secure_tls_shutdown();

    /* Determine if the test was successful.  */
    if(error_counter)
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

static void    ntest_0_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void    ntest_0_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if(socket != &server_socket)
        error_counter++;
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_two_way_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Two Way Client/Server Test.....................N/A\n");
    test_control_return(3);
}
#endif
