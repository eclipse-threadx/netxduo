/* This test is to cover nx_secure_tls_process_remote_certificate.c.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_crypto_rsa.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"
#include   "ecc_certs.c"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && \
    !defined(NX_SECURE_TLS_ENABLE_TLS_1_0) && !defined(NX_SECURE_TLS_ENABLE_TLS_1_1) && !(NX_SECURE_TLS_TLS_1_3_ENABLED) && !defined(NX_SECURE_DISABLE_X509)
#define __LINUX__

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
static NX_SECURE_X509_CERT ica_certificate;
static NX_SECURE_X509_CERT client_certificate;
static NX_SECURE_X509_CERT remote_certificate, remote_issuer;
static NX_SECURE_X509_CERT test_certificate, test_certificate_rsa;
static NX_SECURE_X509_CERT client_remote_certificate, client_remote_issuer;
static NX_SECURE_X509_CERT trusted_certificate;
static NX_SECURE_X509_CERT trusted_certificate_duplicate;

static UCHAR remote_cert_buffer[2000];
static UCHAR test_cert_buffer[2000];
static UCHAR client_remote_cert_buffer[2000];
static UCHAR client_remote_issuer_buffer[2000];

static UCHAR server_packet_buffer[4000];
static UCHAR client_packet_buffer[4000];

static CHAR server_crypto_metadata[16000]; 
static CHAR client_crypto_metadata[16000]; 

/* Test PKI (3-level). */
#include "test_ca_cert.c"
#include "test_device_cert.c"
#define ca_cert_der test_ca_cert_der
#define ca_cert_der_len test_ca_cert_der_len


/*  Cryptographic routines. */
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_sha384;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_pkcs1;
extern NX_CRYPTO_METHOD crypto_method_auth_psk;
static NX_CRYPTO_METHOD test_auth;
static NX_CRYPTO_METHOD test_cipher;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;

static NX_SECURE_TLS_CIPHERSUITE_INFO ciphersuite_lookup_table_test[] =
{
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
};

static NX_SECURE_TLS_CIPHERSUITE_INFO ciphersuite_lookup_table_test_ecc[] =
{
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &crypto_method_ecdhe,     &test_auth,               &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &crypto_method_ecdhe,     &test_auth,               &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &test_cipher,             &test_auth,               &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
};

static NX_SECURE_X509_CRYPTO x509_cipher_lookup_table_ecc[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256,  &crypto_method_ecdsa,     &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_rsa,       &crypto_method_sha256},
};

static const USHORT ecc_supported_groups[] =
{
    (USHORT)NX_CRYPTO_EC_SECP256R1,
};

static const NX_CRYPTO_METHOD *ecc_curves[] =
{
    &crypto_method_ec_secp256,
};

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

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */
#ifndef __LINUX__
void tx_application_define(void *first_unused_memory)
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_server_key_exchange_coverage_test_application_define(void *first_unused_memory)
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
    EXPECT_EQ(NX_SUCCESS, status);

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 1536, pool_area[1], sizeof(pool_area[1]));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, IP_STACK_SIZE, 1);
    pointer = pointer + IP_STACK_SIZE;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_1500,
                           pointer, IP_STACK_SIZE, 1);
    pointer = pointer + IP_STACK_SIZE;
    EXPECT_EQ(NX_SUCCESS, status);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;
    EXPECT_EQ(NX_SUCCESS, status);

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    EXPECT_EQ(NX_SUCCESS, status);

    nx_secure_tls_initialize();
}

/* Server hello.  */
static UCHAR serverhello[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67, 0x00, 0x00, 0xe1, 0x4a,
0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72, 0x00, 0x00, 0x52, 0x69,
0x00, 0x00, 0x00, 0xc0, 0x23, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00,
};

static UCHAR serverhello_rsa[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x47, 0x15, 0x00, 0x00, 0xde, 0x54, 0x00, 0x00, 0xb3, 0x39,
0x00, 0x00, 0x12, 0x2d, 0x00, 0x00, 0x4d, 0x07, 0x00, 0x00, 0xc8, 0x4d, 0x00, 0x00, 0x43, 0x64,
0x00, 0x00, 0x00, 0xc0, 0x27, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00,
};

/* Certificate.  */
static UCHAR certificate_header[] = {
0x00, 0x02, 0x5a, 0x00, 0x02, 0x57,
};

static UCHAR certificate_header_rsa[] = {
0x00, 0x03, 0xd9, 0x00, 0x03, 0xd6,
};

/* Server key exchange.  */
static UCHAR server_key_exchange[] = {
0x03, 0x00, 0x17, 0x41, 0x04, 0xd3, 0xd2, 0xd5, 0x12, 0x1e, 0xaf, 0x65, 0x6d, 0x20, 0x19, 0x22,
0xf7, 0x11, 0x11, 0x06, 0x6c, 0xef, 0x7d, 0xce, 0xda, 0x00, 0x1b, 0x60, 0x4c, 0xef, 0x4e, 0x80,
0xa9, 0x9e, 0xe5, 0xbf, 0x28, 0x87, 0x57, 0x1b, 0xf2, 0xa2, 0xc9, 0x5e, 0x57, 0xdb, 0xb5, 0x0e,
0x4a, 0x69, 0x5d, 0x88, 0x6f, 0xfa, 0xbb, 0xa2, 0x5a, 0x74, 0xdf, 0x3e, 0x28, 0x55, 0x00, 0xa0,
0x05, 0x1c, 0x35, 0x80, 0x3b, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20, 0x0a, 0xfb, 0x1d,
0xde, 0xc7, 0xe5, 0x3d, 0x05, 0x19, 0xda, 0x16, 0x72, 0x49, 0x1a, 0xb9, 0xaf, 0x91, 0x23, 0xcc,
0xbb, 0xe2, 0xf7, 0xba, 0x16, 0x0a, 0xf4, 0x51, 0x01, 0xfe, 0x0b, 0xef, 0x02, 0x02, 0x21, 0x00,
0xf1, 0xc0, 0xf7, 0x60, 0xc3, 0xb7, 0xe4, 0xec, 0x51, 0xcb, 0xad, 0x69, 0x8e, 0x61, 0xd8, 0xec,
0x4c, 0x54, 0xea, 0x87, 0xe7, 0xd8, 0xf1, 0x13, 0x92, 0x70, 0xe6, 0x40, 0xd2, 0x5c, 0xa3, 0xfd,
};

static UCHAR server_key_exchange_1[] = {
0x04, 0x00, 0x17, 0x41, 0x04, 0xd3, 0xd2, 0xd5, 0x12, 0x1e, 0xaf, 0x65, 0x6d, 0x20, 0x19, 0x22,
0xf7, 0x11, 0x11, 0x06, 0x6c, 0xef, 0x7d, 0xce, 0xda, 0x00, 0x1b, 0x60, 0x4c, 0xef, 0x4e, 0x80,
0xa9, 0x9e, 0xe5, 0xbf, 0x28, 0x87, 0x57, 0x1b, 0xf2, 0xa2, 0xc9, 0x5e, 0x57, 0xdb, 0xb5, 0x0e,
0x4a, 0x69, 0x5d, 0x88, 0x6f, 0xfa, 0xbb, 0xa2, 0x5a, 0x74, 0xdf, 0x3e, 0x28, 0x55, 0x00, 0xa0,
0x05, 0x1c, 0x35, 0x80, 0x3b, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20, 0x0a, 0xfb, 0x1d,
0xde, 0xc7, 0xe5, 0x3d, 0x05, 0x19, 0xda, 0x16, 0x72, 0x49, 0x1a, 0xb9, 0xaf, 0x91, 0x23, 0xcc,
0xbb, 0xe2, 0xf7, 0xba, 0x16, 0x0a, 0xf4, 0x51, 0x01, 0xfe, 0x0b, 0xef, 0x02, 0x02, 0x21, 0x00,
0xf1, 0xc0, 0xf7, 0x60, 0xc3, 0xb7, 0xe4, 0xec, 0x51, 0xcb, 0xad, 0x69, 0x8e, 0x61, 0xd8, 0xec,
0x4c, 0x54, 0xea, 0x87, 0xe7, 0xd8, 0xf1, 0x13, 0x92, 0x70, 0xe6, 0x40, 0xd2, 0x5c, 0xa3, 0xfd,
};

static UCHAR server_key_exchange_2[] = {
0x03, 0x00, 0xff, 0x41, 0x04, 0xd3, 0xd2, 0xd5, 0x12, 0x1e, 0xaf, 0x65, 0x6d, 0x20, 0x19, 0x22,
0xf7, 0x11, 0x11, 0x06, 0x6c, 0xef, 0x7d, 0xce, 0xda, 0x00, 0x1b, 0x60, 0x4c, 0xef, 0x4e, 0x80,
0xa9, 0x9e, 0xe5, 0xbf, 0x28, 0x87, 0x57, 0x1b, 0xf2, 0xa2, 0xc9, 0x5e, 0x57, 0xdb, 0xb5, 0x0e,
0x4a, 0x69, 0x5d, 0x88, 0x6f, 0xfa, 0xbb, 0xa2, 0x5a, 0x74, 0xdf, 0x3e, 0x28, 0x55, 0x00, 0xa0,
0x05, 0x1c, 0x35, 0x80, 0x3b, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20, 0x0a, 0xfb, 0x1d,
0xde, 0xc7, 0xe5, 0x3d, 0x05, 0x19, 0xda, 0x16, 0x72, 0x49, 0x1a, 0xb9, 0xaf, 0x91, 0x23, 0xcc,
0xbb, 0xe2, 0xf7, 0xba, 0x16, 0x0a, 0xf4, 0x51, 0x01, 0xfe, 0x0b, 0xef, 0x02, 0x02, 0x21, 0x00,
0xf1, 0xc0, 0xf7, 0x60, 0xc3, 0xb7, 0xe4, 0xec, 0x51, 0xcb, 0xad, 0x69, 0x8e, 0x61, 0xd8, 0xec,
0x4c, 0x54, 0xea, 0x87, 0xe7, 0xd8, 0xf1, 0x13, 0x92, 0x70, 0xe6, 0x40, 0xd2, 0x5c, 0xa3, 0xfd,
};

static UCHAR server_key_exchange_3[] = {
0x03, 0x00, 0x17, 0x41, 0x04, 0xd3, 0xd2, 0xd5, 0x12, 0x1e, 0xaf, 0x65, 0x6d, 0x20, 0x19, 0x22,
0xf7, 0x11, 0x11, 0x06, 0x6c, 0xef, 0x7d, 0xce, 0xda, 0x00, 0x1b, 0x60, 0x4c, 0xef, 0x4e, 0x80,
0xa9, 0x9e, 0xe5, 0xbf, 0x28, 0x87, 0x57, 0x1b, 0xf2, 0xa2, 0xc9, 0x5e, 0x57, 0xdb, 0xb5, 0x0e,
0x4a, 0x69, 0x5d, 0x88, 0x6f, 0xfa, 0xbb, 0xa2, 0x5a, 0x74, 0xdf, 0x3e, 0x28, 0x55, 0x00, 0xa0,
0x05, 0x1c, 0x35, 0x80, 0x3b, 0x0f, 0x0f, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20, 0x0a, 0xfb, 0x1d,
0xde, 0xc7, 0xe5, 0x3d, 0x05, 0x19, 0xda, 0x16, 0x72, 0x49, 0x1a, 0xb9, 0xaf, 0x91, 0x23, 0xcc,
0xbb, 0xe2, 0xf7, 0xba, 0x16, 0x0a, 0xf4, 0x51, 0x01, 0xfe, 0x0b, 0xef, 0x02, 0x02, 0x21, 0x00,
0xf1, 0xc0, 0xf7, 0x60, 0xc3, 0xb7, 0xe4, 0xec, 0x51, 0xcb, 0xad, 0x69, 0x8e, 0x61, 0xd8, 0xec,
0x4c, 0x54, 0xea, 0x87, 0xe7, 0xd8, 0xf1, 0x13, 0x92, 0x70, 0xe6, 0x40, 0xd2, 0x5c, 0xa3, 0xfd,
};

static UCHAR server_key_exchange_4[] = {
0x03, 0x00, 0x17, 0x41, 0x04, 0xd3, 0xd2, 0xd5, 0x12, 0x1e, 0xaf, 0x65, 0x6d, 0x20, 0x19, 0x22,
0xf7, 0x11, 0x11, 0x06, 0x6c, 0xef, 0x7d, 0xce, 0xda, 0x00, 0x1b, 0x60, 0x4c, 0xef, 0x4e, 0x80,
0xa9, 0x9e, 0xe5, 0xbf, 0x28, 0x87, 0x57, 0x1b, 0xf2, 0xa2, 0xc9, 0x5e, 0x57, 0xdb, 0xb5, 0x0e,
0x4a, 0x69, 0x5d, 0x88, 0x6f, 0xfa, 0xbb, 0xa2, 0x5a, 0x74, 0xdf, 0x3e, 0x28, 0x55, 0x00, 0xa0,
0x05, 0x1c, 0x35, 0x80, 0x3b, 0x04, 0x03, 0x00, 0x48, 0x30, 0x45, 0x02, 0x20, 0x0a, 0xfb, 0x1d,
0xde, 0xc7, 0xe5, 0x3d, 0x05, 0x19, 0xda, 0x16, 0x72, 0x49, 0x1a, 0xb9, 0xaf, 0x91, 0x23, 0xcc,
0xbb, 0xe2, 0xf7, 0xba, 0x16, 0x0a, 0xf4, 0x51, 0x01, 0xfe, 0x0b, 0xef, 0x02, 0x02, 0x21, 0x00,
0xf1, 0xc0, 0xf7, 0x60, 0xc3, 0xb7, 0xe4, 0xec, 0x51, 0xcb, 0xad, 0x69, 0x8e, 0x61, 0xd8, 0xec,
0x4c, 0x54, 0xea, 0x87, 0xe7, 0xd8, 0xf1, 0x13, 0x92, 0x70, 0xe6, 0x40, 0xd2, 0x5c, 0xa3, 0xfd,
};

static UCHAR server_key_exchange_5[] = {
0x03, 0x00, 0x17, 0xff, 0x04, 0xd3, 0xd2, 0xd5, 0x12, 0x1e, 0xaf, 0x65, 0x6d, 0x20, 0x19, 0x22,
0xf7, 0x11, 0x11, 0x06, 0x6c, 0xef, 0x7d, 0xce, 0xda, 0x00, 0x1b, 0x60, 0x4c, 0xef, 0x4e, 0x80,
0xa9, 0x9e, 0xe5, 0xbf, 0x28, 0x87, 0x57, 0x1b, 0xf2, 0xa2, 0xc9, 0x5e, 0x57, 0xdb, 0xb5, 0x0e,
0x4a, 0x69, 0x5d, 0x88, 0x6f, 0xfa, 0xbb, 0xa2, 0x5a, 0x74, 0xdf, 0x3e, 0x28, 0x55, 0x00, 0xa0,
0x05, 0x1c, 0x35, 0x80, 0x3b, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20, 0x0a, 0xfb, 0x1d,
0xde, 0xc7, 0xe5, 0x3d, 0x05, 0x19, 0xda, 0x16, 0x72, 0x49, 0x1a, 0xb9, 0xaf, 0x91, 0x23, 0xcc,
0xbb, 0xe2, 0xf7, 0xba, 0x16, 0x0a, 0xf4, 0x51, 0x01, 0xfe, 0x0b, 0xef, 0x02, 0x02, 0x21, 0x00,
0xf1, 0xc0, 0xf7, 0x60, 0xc3, 0xb7, 0xe4, 0xec, 0x51, 0xcb, 0xad, 0x69, 0x8e, 0x61, 0xd8, 0xec,
0x4c, 0x54, 0xea, 0x87, 0xe7, 0xd8, 0xf1, 0x13, 0x92, 0x70, 0xe6, 0x40, 0xd2, 0x5c, 0xa3, 0xfd,
};

static UCHAR server_key_exchange_rsa[] = {
0x03, 0x00, 0x17, 0x41, 0x04, 0x73, 0xda, 0x96, 0x0d, 0x83, 0x1c, 0x4c, 0x06, 0xea, 0xeb, 0xb2,
0xc7, 0x4e, 0x66, 0x98, 0xc7, 0xb2, 0xb5, 0x1e, 0x5e, 0x3e, 0x0d, 0xd1, 0x62, 0x32, 0x7f, 0xfc,
0xef, 0x18, 0xbe, 0x08, 0x3c, 0x41, 0xd9, 0xe4, 0xbc, 0xf3, 0x9c, 0x76, 0x42, 0x42, 0xcd, 0x17,
0xcb, 0x0e, 0xb7, 0xd0, 0x34, 0xe6, 0xb2, 0xa8, 0x6b, 0x53, 0xcc, 0x18, 0xe1, 0xcd, 0x51, 0xb9,
0x63, 0x87, 0x93, 0xca, 0x9c, 0x04, 0x01, 0x01, 0x00, 0x36, 0x33, 0xad, 0x4d, 0x36, 0x23, 0xde,
0x1c, 0x2e, 0xa9, 0x6a, 0x68, 0x35, 0xd1, 0x42, 0xbd, 0x8a, 0x19, 0xbf, 0x48, 0xf0, 0x55, 0x60,
0x71, 0x5a, 0xe1, 0xf5, 0xba, 0xcb, 0xd1, 0xef, 0x21, 0x94, 0x6c, 0x7b, 0x4d, 0xbc, 0xe8, 0x47,
0xb0, 0xb1, 0x0f, 0x28, 0xe7, 0x7b, 0xd2, 0x77, 0x95, 0x35, 0xf1, 0x79, 0xcd, 0x2a, 0x58, 0x36,
0x57, 0x93, 0x14, 0x43, 0xfe, 0xde, 0xca, 0x27, 0x34, 0xb0, 0xf3, 0x39, 0x74, 0x2f, 0x98, 0x0c,
0x06, 0xc0, 0x8d, 0x04, 0x2a, 0x6a, 0xdc, 0x9b, 0x6d, 0x19, 0x0e, 0xfc, 0x45, 0x7e, 0xd2, 0x66,
0x74, 0x30, 0xa2, 0x75, 0x18, 0xad, 0x5b, 0x94, 0xd4, 0x7f, 0x80, 0x7e, 0x41, 0x6d, 0xba, 0x83,
0x4f, 0xdd, 0x5d, 0xd6, 0x98, 0xa2, 0x08, 0x4e, 0xff, 0xb6, 0x18, 0x45, 0xa2, 0x45, 0xd9, 0xc3,
0xfb, 0x3d, 0x23, 0x2f, 0x82, 0xd6, 0x50, 0x21, 0x4a, 0xe3, 0xaf, 0x14, 0x65, 0x8b, 0xcc, 0xec,
0x3b, 0x3e, 0x72, 0x82, 0x89, 0x30, 0xe6, 0x8c, 0xee, 0xea, 0xe9, 0x72, 0xa2, 0x88, 0x76, 0xfc,
0xd9, 0x40, 0x67, 0xb4, 0x9b, 0xfd, 0xdc, 0x66, 0x44, 0x9c, 0xa2, 0x74, 0xec, 0x80, 0x70, 0x09,
0x44, 0x43, 0xef, 0xcb, 0xb2, 0x12, 0x3f, 0x5e, 0xf2, 0xaf, 0x84, 0x6c, 0xa7, 0x1b, 0xe7, 0x34,
0x25, 0xa9, 0x43, 0x8f, 0xb1, 0xc3, 0xfe, 0xc8, 0x73, 0xc9, 0x75, 0xf8, 0xa5, 0x43, 0x22, 0xbf,
0x5f, 0xca, 0xd0, 0x56, 0x2f, 0x57, 0x3c, 0xe5, 0xb9, 0x53, 0xb5, 0xa0, 0x5f, 0x86, 0xf7, 0x82,
0xf0, 0x87, 0xdd, 0xd0, 0xb8, 0x39, 0xb8, 0x62, 0x7c, 0x18, 0x17, 0x11, 0x6d, 0xd8, 0x39, 0xfb,
0xd5, 0x06, 0x41, 0xce, 0xc5, 0xd0, 0x5b, 0xd6, 0x7f, 0xcb, 0x63, 0x28, 0x06, 0xd8, 0xf8, 0x65,
0x47, 0x36, 0xde, 0x2b, 0xe9, 0x59, 0x8d, 0x2b, 0xd9,
};

static UCHAR server_key_exchange_rsa_1[] = {
0x03, 0x00, 0x17, 0x41, 0x04, 0x73, 0xda, 0x96, 0x0d, 0x83, 0x1c, 0x4c, 0x06, 0xea, 0xeb, 0xb2,
0xc7, 0x4e, 0x66, 0x98, 0xc7, 0xb2, 0xb5, 0x1e, 0x5e, 0x3e, 0x0d, 0xd1, 0x62, 0x32, 0x7f, 0xfc,
0xef, 0x18, 0xbe, 0x08, 0x3c, 0x41, 0xd9, 0xe4, 0xbc, 0xf3, 0x9c, 0x76, 0x42, 0x42, 0xcd, 0x17,
0xcb, 0x0e, 0xb7, 0xd0, 0x34, 0xe6, 0xb2, 0xa8, 0x6b, 0x53, 0xcc, 0x18, 0xe1, 0xcd, 0x51, 0xb9,
0x63, 0x87, 0x93, 0xca, 0x9c, 0x04, 0x01, 0x01, 0x00, 0x36, 0x33, 0xff, 0x4d, 0x36, 0x23, 0xde,
0x1c, 0x2e, 0xa9, 0x6a, 0x68, 0x35, 0xd1, 0x42, 0xbd, 0x8a, 0x19, 0xbf, 0x48, 0xf0, 0x55, 0x60,
0x71, 0x5a, 0xe1, 0xf5, 0xba, 0xcb, 0xd1, 0xef, 0x21, 0x94, 0x6c, 0x7b, 0x4d, 0xbc, 0xe8, 0x47,
0xb0, 0xb1, 0x0f, 0x28, 0xe7, 0x7b, 0xd2, 0x77, 0x95, 0x35, 0xf1, 0x79, 0xcd, 0x2a, 0x58, 0x36,
0x57, 0x93, 0x14, 0x43, 0xfe, 0xde, 0xca, 0x27, 0x34, 0xb0, 0xf3, 0x39, 0x74, 0x2f, 0x98, 0x0c,
0x06, 0xc0, 0x8d, 0x04, 0x2a, 0x6a, 0xdc, 0x9b, 0x6d, 0x19, 0x0e, 0xfc, 0x45, 0x7e, 0xd2, 0x66,
0x74, 0x30, 0xa2, 0x75, 0x18, 0xad, 0x5b, 0x94, 0xd4, 0x7f, 0x80, 0x7e, 0x41, 0x6d, 0xba, 0x83,
0x4f, 0xdd, 0x5d, 0xd6, 0x98, 0xa2, 0x08, 0x4e, 0xff, 0xb6, 0x18, 0x45, 0xa2, 0x45, 0xd9, 0xc3,
0xfb, 0x3d, 0x23, 0x2f, 0x82, 0xd6, 0x50, 0x21, 0x4a, 0xe3, 0xaf, 0x14, 0x65, 0x8b, 0xcc, 0xec,
0x3b, 0x3e, 0x72, 0x82, 0x89, 0x30, 0xe6, 0x8c, 0xee, 0xea, 0xe9, 0x72, 0xa2, 0x88, 0x76, 0xfc,
0xd9, 0x40, 0x67, 0xb4, 0x9b, 0xfd, 0xdc, 0x66, 0x44, 0x9c, 0xa2, 0x74, 0xec, 0x80, 0x70, 0x09,
0x44, 0x43, 0xef, 0xcb, 0xb2, 0x12, 0x3f, 0x5e, 0xf2, 0xaf, 0x84, 0x6c, 0xa7, 0x1b, 0xe7, 0x34,
0x25, 0xa9, 0x43, 0x8f, 0xb1, 0xc3, 0xfe, 0xc8, 0x73, 0xc9, 0x75, 0xf8, 0xa5, 0x43, 0x22, 0xbf,
0x5f, 0xca, 0xd0, 0x56, 0x2f, 0x57, 0x3c, 0xe5, 0xb9, 0x53, 0xb5, 0xa0, 0x5f, 0x86, 0xf7, 0x82,
0xf0, 0x87, 0xdd, 0xd0, 0xb8, 0x39, 0xb8, 0x62, 0x7c, 0x18, 0x17, 0x11, 0x6d, 0xd8, 0x39, 0xfb,
0xd5, 0x06, 0x41, 0xce, 0xc5, 0xd0, 0x5b, 0xd6, 0x7f, 0xcb, 0x63, 0x28, 0x06, 0xd8, 0xf8, 0x65,
0x47, 0x36, 0xde, 0x2b, 0xe9, 0x59, 0x8d, 0x2b, 0xd9,
};

static UCHAR *test_packets_data[] = {
server_key_exchange, // if (tls_session -> nx_secure_tls_client_state != NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE)
server_key_exchange_1, // if (packet_buffer[0] != 3)
server_key_exchange_2, // _nx_secure_tls_find_curve_method returns error
server_key_exchange_3, // _nx_secure_x509_find_certificate_methods returns error
server_key_exchange_rsa, // if (compare_result != 0)
};

static UINT test_packets_size[] = {
sizeof(server_key_exchange),
sizeof(server_key_exchange_1),
sizeof(server_key_exchange_2),
sizeof(server_key_exchange_3),
sizeof(server_key_exchange_rsa),
};

/* Set expected status.  */
static UINT test_status[] = {
NX_SECURE_TLS_UNEXPECTED_MESSAGE,
NX_SECURE_TLS_UNSUPPORTED_ECC_FORMAT,
NX_SECURE_TLS_UNSUPPORTED_ECC_CURVE,
NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM,
NX_SECURE_TLS_SIGNATURE_VERIFICATION_ERROR,
};

#define TEST_START 0
#define RSA_TEST_START 4

static UCHAR server_random[] = {
0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67, 0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00,
0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72, 0x00, 0x00, 0x52, 0x69, 0x00, 0x00,
};

static UCHAR client_random[] = {
0x00, 0x00, 0x00, 0x00, 0x84, 0x67, 0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00,
0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72, 0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x90, 0x5f, 0x00, 0x00,
};

static UCHAR server_random_rsa[] = {
0x00, 0x00, 0x00, 0x00, 0x47, 0x15, 0x00, 0x00, 0xde, 0x54, 0x00, 0x00, 0xb3, 0x39, 0x00, 0x00,
0x12, 0x2d, 0x00, 0x00, 0x4d, 0x07, 0x00, 0x00, 0xc8, 0x4d, 0x00, 0x00, 0x43, 0x64, 0x00, 0x00,
};

static UCHAR client_random_rsa[] = {
0x00, 0x00, 0x00, 0x00, 0x0c, 0x39, 0x00, 0x00, 0x3e, 0x0f, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00,
0x24, 0x01, 0x00, 0x00, 0x5e, 0x30, 0x00, 0x00, 0x0d, 0x44, 0x00, 0x00, 0x1c, 0x49, 0x00, 0x00,
};

/* -----===== SERVER =====----- */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status, i;
ULONG      actual_status;
NX_PACKET *send_packet, *receive_packet;
UINT       test_cert_size = 0;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Server Key Exchange Coverage Test..............");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16*1024,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Create a TLS session for our socket.  */
    status =  nx_secure_tls_session_create(&server_tls_session,
                                           &nx_crypto_tls_ciphers_ecc,
                                           server_crypto_metadata,
                                           sizeof(server_crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_secure_tls_ecc_initialize(&server_tls_session, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup our packet reassembly buffer. */
    nx_secure_tls_session_packet_buffer_set(&server_tls_session, server_packet_buffer, sizeof(server_packet_buffer));

    /* Initialize our certificate. */
    nx_secure_x509_certificate_initialize(&certificate, ECTestServer2_der, ECTestServer2_der_len, NX_NULL, 0, ECTestServer2_key_der, ECTestServer2_key_der_len, NX_SECURE_X509_KEY_TYPE_EC_DER);
    nx_secure_tls_local_certificate_add(&server_tls_session, &certificate);

    /* If we are testing client certificate verify, allocate remote certificate space. */
    nx_secure_tls_remote_certificate_allocate(&server_tls_session, &client_remote_certificate, client_remote_cert_buffer, sizeof(client_remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&server_tls_session, &client_remote_issuer, client_remote_issuer_buffer, sizeof(client_remote_issuer_buffer));

    /* Add a CA Certificate to our trusted store for verifying incoming client certificates. */
    nx_secure_x509_certificate_initialize(&trusted_certificate, ECCA4_der, ECCA4_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&server_tls_session, &trusted_certificate);

    /* Initialize server session manually. */
    server_tls_session.nx_secure_tls_tcp_socket = &server_socket;
    server_tls_session.nx_secure_tls_packet_pool = &pool_0;
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    for (i = TEST_START; i < (sizeof(test_packets_size) / sizeof(UINT)); i++)
    {

        /* Accept a client socket connection.  */
        status = nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
        EXPECT_EQ(NX_SUCCESS, status);
        tx_thread_suspend(&ntest_0);

        /* Receive ClientHello. */
        status =  nx_tcp_socket_receive(&server_socket, &receive_packet, NX_WAIT_FOREVER);
        EXPECT_EQ(NX_SUCCESS, status);

        /* Release the ClientHello packet. */
        nx_packet_release(receive_packet);
        if (i < (RSA_TEST_START + 1))
        {
            memcpy(client_tls_session.nx_secure_tls_key_material.nx_secure_tls_client_random, client_random, NX_SECURE_TLS_RANDOM_SIZE);
        }
        else
        {
            memcpy(client_tls_session.nx_secure_tls_key_material.nx_secure_tls_client_random, client_random_rsa, NX_SECURE_TLS_RANDOM_SIZE);
        }

        /* Send ServerHello. */
        tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
        server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
        status = _nx_secure_tls_allocate_handshake_packet(&server_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
        tx_mutex_put(&_nx_secure_tls_protection);
        EXPECT_EQ(NX_SUCCESS, status);

        if (i < RSA_TEST_START)
        {
            memcpy(send_packet -> nx_packet_prepend_ptr, serverhello, sizeof(serverhello));
            send_packet -> nx_packet_length = sizeof(serverhello);
        }
        else
        {
            memcpy(send_packet -> nx_packet_prepend_ptr, serverhello_rsa, sizeof(serverhello_rsa));
            send_packet -> nx_packet_length = sizeof(serverhello_rsa);
        }

        send_packet -> nx_packet_append_ptr = send_packet -> nx_packet_prepend_ptr + send_packet -> nx_packet_length;

        tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
        status = _nx_secure_tls_send_handshake_record(&server_tls_session, send_packet, NX_SECURE_TLS_SERVER_HELLO, NX_WAIT_FOREVER);
        tx_mutex_put(&_nx_secure_tls_protection);
        EXPECT_EQ(NX_SUCCESS, status);

        if (i != 0)
        {
            /* Send certificate. */
            tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
            server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
            status = _nx_secure_tls_allocate_handshake_packet(&server_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
            tx_mutex_put(&_nx_secure_tls_protection);
            EXPECT_EQ(NX_SUCCESS, status);

            if (i < RSA_TEST_START)
            {
                nx_packet_data_append(send_packet, certificate_header, sizeof(certificate_header), &pool_0, NX_WAIT_FOREVER);
                memcpy(test_cert_buffer, ECTestServer2_der, ECTestServer2_der_len);
                test_cert_size = ECTestServer2_der_len;
            }
            else
            {
                nx_packet_data_append(send_packet, certificate_header_rsa, sizeof(certificate_header_rsa), &pool_0, NX_WAIT_FOREVER);
                memcpy(test_cert_buffer, test_device_cert_der, test_device_cert_der_len);
                test_cert_size = test_device_cert_der_len;
            }
            nx_packet_data_append(send_packet, test_cert_buffer, test_cert_size, &pool_0, NX_WAIT_FOREVER);

            tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
            status = _nx_secure_tls_send_handshake_record(&server_tls_session, send_packet, NX_SECURE_TLS_CERTIFICATE_MSG, NX_WAIT_FOREVER);
            tx_mutex_put(&_nx_secure_tls_protection);
            EXPECT_EQ(NX_SUCCESS, status);
        }

        /* Send server key exchange. */
        tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
        server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
        status = _nx_secure_tls_allocate_handshake_packet(&server_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
        tx_mutex_put(&_nx_secure_tls_protection);
        EXPECT_EQ(NX_SUCCESS, status);

        nx_packet_data_append(send_packet, test_packets_data[i], test_packets_size[i], &pool_0, NX_WAIT_FOREVER);

        tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
        status = _nx_secure_tls_send_handshake_record(&server_tls_session, send_packet, NX_SECURE_TLS_SERVER_KEY_EXCHANGE, NX_WAIT_FOREVER);
        tx_mutex_put(&_nx_secure_tls_protection);
        EXPECT_EQ(NX_SUCCESS, status);

        /* Waiting client thread. */
        tx_thread_suspend(&ntest_0);

        status = nx_secure_tls_session_end(&server_tls_session, NX_NO_WAIT);
        status += nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER);
        status += nx_tcp_server_socket_unaccept(&server_socket);
        status += nx_tcp_server_socket_relisten(&ip_0, 12, &server_socket);
        EXPECT_EQ(NX_SUCCESS, status);
    }

    /* End the TLS session. This is required to properly shut down the TLS connection. */
    status += nx_tcp_server_socket_unlisten(&ip_0, 12);
    status += nx_secure_tls_session_delete(&server_tls_session);
    status += nx_tcp_socket_delete(&server_socket);
    EXPECT_EQ(NX_SUCCESS, status);

}

/* -----===== CLIENT =====----- */
static UINT test_op;
static UINT test_count;
static UINT op_count;
static UINT test_error_status;
static UINT  test_operation(UINT op, VOID *handle, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key,
                            NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte,
                            UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata,
                            ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == test_op)
    {
        if (op == NX_CRYPTO_VERIFY)
        {
            return(test_error_status);
        }

        if (op != NX_CRYPTO_HASH_UPDATE || op_count == test_count)
        {
            return(NX_CRYPTO_NOT_SUCCESSFUL);
        }
        op_count++;
    }

    return(NX_CRYPTO_SUCCESS);
}

static UINT test_init(NX_CRYPTO_METHOD*method,
                           UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                           VOID **handler,
                           VOID *crypto_metadata,
                           ULONG crypto_metadata_size)
{
    return(NX_CRYPTO_NOT_SUCCESSFUL);
}

static UINT test_cleanup(VOID *crypto_metadata)
{
    return(NX_CRYPTO_NOT_SUCCESSFUL);
}

static void    ntest_1_entry(ULONG thread_input)
{
UINT       status, i;
NX_PACKET *send_packet = NX_NULL;
NX_SECURE_X509_CRYPTO x509_ciphers;
NX_SECURE_TLS_CIPHERSUITE_INFO ciphersuite_table;
NX_CRYPTO_METHOD test_hash;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 1024*16,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Create a TLS session for our socket.  */
    status =  nx_secure_tls_session_create(&client_tls_session,
                                           &nx_crypto_tls_ciphers_ecc,
                                           client_crypto_metadata,
                                           sizeof(client_crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_secure_tls_ecc_initialize(&client_tls_session, ecc_supported_groups,
                                          1,
                                          ecc_curves);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup our packet reassembly buffer. */
    nx_secure_tls_session_packet_buffer_set(&client_tls_session, client_packet_buffer, sizeof(client_packet_buffer));

    /* Initialize our certificate. */
    nx_secure_x509_certificate_initialize(&client_certificate, ECTestServer7_256_der, ECTestServer7_256_der_len, NX_NULL, 0, ECTestServer7_256_key_der, ECTestServer7_256_key_der_len, NX_SECURE_X509_KEY_TYPE_EC_DER);
    nx_secure_tls_local_certificate_add(&client_tls_session, &client_certificate);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Cover if (ciphersuite -> nx_secure_tls_public_cipher -> nx_crypto_algorithm == NX_CRYPTO_KEY_EXCHANGE_ECDHE). */
    client_tls_session.nx_secure_tls_session_ciphersuite = &ciphersuite_lookup_table_test[0];
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    /* Cover _nx_secure_x509_remote_endpoint_certificate_get returns error. */
    client_tls_session.nx_secure_tls_session_ciphersuite = &ciphersuite_lookup_table_test_ecc[0];
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_IDLE;
    client_tls_session.nx_secure_tls_session_ciphersuite = NX_NULL;

    for (i = TEST_START; i < (sizeof(test_packets_size) / sizeof(UINT)); i++)
    {

        /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
        if (i < RSA_TEST_START)
        {
            nx_secure_x509_certificate_initialize(&trusted_certificate, ECCA2_der, ECCA2_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
            nx_secure_tls_trusted_certificate_add(&client_tls_session, &trusted_certificate);
        }
        else
        {
            nx_secure_x509_certificate_initialize(&trusted_certificate, test_ca_cert_der, test_ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
            nx_secure_tls_trusted_certificate_add(&client_tls_session, &trusted_certificate);
        }

        status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
        EXPECT_EQ(NX_SUCCESS, status);

        tx_thread_sleep(10);
        tx_thread_resume(&ntest_0);
        status = nx_secure_tls_session_start(&client_tls_session, &client_socket, 5 * NX_IP_PERIODIC_RATE);
        EXPECT_EQ(test_status[i], status);
        tx_thread_sleep(10);
        tx_thread_resume(&ntest_0);

        /* Disconnect this socket.  */
        status = nx_secure_tls_session_end(&client_tls_session, NX_NO_WAIT);
        status += nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER);
        EXPECT_EQ(NX_SUCCESS, status);
    }

    /* Cover hash_method error.  */
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(client_tls_session.nx_secure_tls_key_material.nx_secure_tls_client_random, client_random, NX_SECURE_TLS_RANDOM_SIZE);
    memcpy(client_tls_session.nx_secure_tls_key_material.nx_secure_tls_server_random, server_random, NX_SECURE_TLS_RANDOM_SIZE);
    memcpy(&x509_ciphers, &x509_cipher_lookup_table_ecc[0], sizeof(NX_SECURE_X509_CRYPTO));
    memcpy(&ciphersuite_table, &ciphersuite_lookup_table_test_ecc[0], sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
    memcpy(&test_hash, &crypto_method_sha256, sizeof(NX_CRYPTO_METHOD));
    test_hash.nx_crypto_init = NX_NULL;
    test_hash.nx_crypto_operation = NX_NULL;
    client_tls_session.nx_secure_tls_session_ciphersuite = &ciphersuite_table;
    nx_secure_x509_certificate_initialize(&test_certificate, ECTestServer2_der, ECTestServer2_der_len, NX_NULL, 0, ECTestServer2_key_der, ECTestServer2_key_der_len, NX_SECURE_X509_KEY_TYPE_EC_DER);
    _nx_secure_x509_certificate_list_add(&client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates,
                                         &test_certificate, NX_TRUE);
    x509_ciphers.nx_secure_x509_hash_method = &test_hash;
    test_certificate.nx_secure_x509_cipher_table = &x509_ciphers;
    test_certificate.nx_secure_x509_cipher_table_size = 1;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, 2);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    test_hash.nx_crypto_init = test_init;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_hash, &crypto_method_sha256, sizeof(NX_CRYPTO_METHOD));
    test_hash.nx_crypto_operation = test_operation;
    test_op = NX_CRYPTO_HASH_INITIALIZE;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    for (i = 0; i < 3; i++)
    {
        client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
        test_op = NX_CRYPTO_HASH_UPDATE;
        test_count = i;
        op_count = 0;
        status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
        EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    }

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    test_op = NX_CRYPTO_HASH_CALCULATE;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_hash, &crypto_method_sha256, sizeof(NX_CRYPTO_METHOD));
    test_hash.nx_crypto_cleanup = test_cleanup;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover wrong signature_length.  */
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_hash, &crypto_method_sha256, sizeof(NX_CRYPTO_METHOD));
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange_4, sizeof(server_key_exchange_4));
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* Cover wrong pubkey length.  */
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_hash, &crypto_method_sha256, sizeof(NX_CRYPTO_METHOD));
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange_5, sizeof(server_key_exchange_5));
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* Cover ECDSA signature with unsupported auth method.  */
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_hash, &crypto_method_sha256, sizeof(NX_CRYPTO_METHOD));
    test_hash.nx_crypto_cleanup = NX_NULL;
    memcpy(&ciphersuite_table, &ciphersuite_lookup_table_test_ecc[1], sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&ciphersuite_table, &ciphersuite_lookup_table_test_ecc[3], sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
    memcpy(&test_auth, &crypto_method_pkcs1, sizeof(NX_CRYPTO_METHOD));
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);

    /* Cover ECDSA signature auth_method with test functions.  */
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_ecdsa, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_init = NX_NULL;
    test_auth.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_ecdsa, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_init = test_init;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_ecdsa, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_operation = test_operation;
    test_op = NX_CRYPTO_EC_CURVE_SET;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_ecdsa, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_operation = test_operation;
    test_op = NX_CRYPTO_VERIFY;
    test_error_status = NX_CRYPTO_AUTHENTICATION_FAILED;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SECURE_TLS_SIGNATURE_VERIFICATION_ERROR, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_ecdsa, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_operation = test_operation;
    test_op = NX_CRYPTO_VERIFY;
    test_error_status = NX_CRYPTO_NOT_SUCCESSFUL;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_ecdsa, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_cleanup = test_cleanup;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover ecdhe_method with test functions.  */
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&ciphersuite_table, &ciphersuite_lookup_table_test_ecc[4], sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
    memcpy(&test_auth, &crypto_method_ecdsa, sizeof(NX_CRYPTO_METHOD));
    memcpy(&test_cipher, &crypto_method_ecdhe, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_cleanup = NX_NULL;
    test_cipher.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_cipher, &crypto_method_ecdhe, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_init = test_init;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_cipher, &crypto_method_ecdhe, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_init = NX_NULL;
    test_cipher.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SUCCESS, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_cipher, &crypto_method_ecdhe, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_operation = test_operation;
    test_op = NX_CRYPTO_EC_CURVE_SET;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_cipher, &crypto_method_ecdhe, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_operation = test_operation;
    test_op = NX_CRYPTO_DH_SETUP;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover the remote certificate is using an unsupported curve.  */
    _nx_secure_tls_remote_certificate_free_all(&client_tls_session);
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&x509_ciphers, &x509_cipher_lookup_table_ecc[0], sizeof(NX_SECURE_X509_CRYPTO));
    memcpy(&ciphersuite_table, &ciphersuite_lookup_table_test_ecc[0], sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
    client_tls_session.nx_secure_tls_session_ciphersuite = &ciphersuite_table;
    nx_secure_x509_certificate_initialize(&test_certificate, ECTestServer4_der, ECTestServer4_der_len, NX_NULL, 0, ECTestServer4_key_der, ECTestServer4_key_der_len, NX_SECURE_X509_KEY_TYPE_EC_DER);
    _nx_secure_x509_certificate_list_add(&client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates,
                                         &test_certificate, NX_TRUE);
    test_certificate.nx_secure_x509_cipher_table = &x509_ciphers;
    test_certificate.nx_secure_x509_cipher_table_size = 1;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange, sizeof(server_key_exchange));
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_ECC_CURVE, status);

    /* Cover RSA signature auth_method with test functions.  */
    _nx_secure_tls_remote_certificate_free_all(&client_tls_session);
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(client_tls_session.nx_secure_tls_key_material.nx_secure_tls_client_random, client_random_rsa, NX_SECURE_TLS_RANDOM_SIZE);
    memcpy(client_tls_session.nx_secure_tls_key_material.nx_secure_tls_server_random, server_random_rsa, NX_SECURE_TLS_RANDOM_SIZE);
    memcpy(&x509_ciphers, &x509_cipher_lookup_table_ecc[1], sizeof(NX_SECURE_X509_CRYPTO));
    memcpy(&ciphersuite_table, &ciphersuite_lookup_table_test_ecc[2], sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
    memcpy(&test_auth, &crypto_method_pkcs1, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_init = NX_NULL;
    test_auth.nx_crypto_cleanup = NX_NULL;
    client_tls_session.nx_secure_tls_session_ciphersuite = &ciphersuite_table;
    nx_secure_x509_certificate_initialize(&test_certificate_rsa, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    _nx_secure_x509_certificate_list_add(&client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates,
                                         &test_certificate_rsa, NX_TRUE);
    test_certificate_rsa.nx_secure_x509_cipher_table = &x509_ciphers;
    test_certificate_rsa.nx_secure_x509_cipher_table_size = 1;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange_rsa, sizeof(server_key_exchange_rsa));
    EXPECT_EQ(NX_SUCCESS, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_rsa, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_init = test_init;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange_rsa, sizeof(server_key_exchange_rsa));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_rsa, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_operation = test_operation;
    test_op = NX_CRYPTO_DECRYPT;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange_rsa, sizeof(server_key_exchange_rsa));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_rsa, sizeof(NX_CRYPTO_METHOD));
    test_auth.nx_crypto_cleanup = test_cleanup;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange_rsa, sizeof(server_key_exchange_rsa));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_auth, &crypto_method_auth_psk, sizeof(NX_CRYPTO_METHOD));
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange_rsa, sizeof(server_key_exchange_rsa));
#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);
#else
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);
#endif

    /* Cover _nx_secure_x509_pkcs7_decode error.  */
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&ciphersuite_table, &ciphersuite_lookup_table_test_ecc[1], sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange_rsa_1, sizeof(server_key_exchange_rsa_1));
    EXPECT_EQ(NX_SECURE_TLS_SIGNATURE_VERIFICATION_ERROR, status);

    /* Cover if (decrypted_hash_length != (hash_method -> nx_crypto_ICV_size_in_bits >> 3)).  */
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_CERTIFICATE;
    memcpy(&test_hash, &crypto_method_sha384, sizeof(NX_CRYPTO_METHOD));
    x509_ciphers.nx_secure_x509_hash_method = &test_hash;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, server_key_exchange_rsa, sizeof(server_key_exchange_rsa));
    EXPECT_EQ(NX_SECURE_TLS_SIGNATURE_VERIFICATION_ERROR, status);

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete TLS session. */
    status = nx_secure_tls_session_delete(&client_tls_session);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_server_key_exchange_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Server Key Exchange Coverage Test..............N/A\n");
    test_control_return(3);
}
#endif
