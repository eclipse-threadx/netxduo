/* 14.19 TCP MUST include an SWS avoidance algorithm in the receiver when effective send MSS < (1/ 2)*RCV_BUFF.  */

/*  Procedure
    1.Connection successfully  
    2.First Client sends 40 data to Server, then check if the last_sent changed
    3.Then Client sends more 20 data to Server, also check if the last_sent changed
    4.If the last_sent changed, the SWS avoidance algorithm has not been used.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED)
#define __LINUX__

/* Define the number of times to (re)establish a TLS connection. */
#define TLS_CONNECT_TIMES (6)

#define LARGE_SEND_SIZE   3000

#define MSG "----------abcdefgh20----------ABCDEFGH40----------klmnopqr60----------KLMNOPQR80--------------------"

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
static NX_SECURE_X509_CERT client_remote_certificate, client_remote_issuer;
static NX_SECURE_X509_CERT trusted_certificate;

UCHAR remote_cert_buffer[2000];
UCHAR remote_issuer_buffer[2000];
UCHAR client_remote_cert_buffer[2000];
UCHAR client_remote_issuer_buffer[2000];

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

/*  Cryptographic routines. */
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

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
void nx_secure_tls_coverage_2_test_application_define(void *first_unused_memory)
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

/*  Define callbacks used by TLS.  */
/* Include CRL associated with Verisign root CA (for AWS) for demo purposes. */
#include "test_ca.crl.der.c"

static UCHAR CertMsg[] = {
    /* total length. */
    0x00, 0x03, 0x27,
    /* cert length */
    0x00, 0x03, 0x24,
    0x30, 0x82, 0x03, 0x20, 0x30, 0x82, 0x02, 0x08, 0x02, 0x09, 0x00, 0xc0,
    0xbe, 0x29, 0xae, 0x89, 0x1b, 0xc9, 0xe5, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x52,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43,
    0x4e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02,
    0x53, 0x48, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
    0x02, 0x53, 0x48, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0a,
    0x0c, 0x02, 0x45, 0x4c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x02, 0x45, 0x4c, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x06, 0x54, 0x65, 0x73, 0x74, 0x43, 0x41, 0x30, 0x1e,
    0x17, 0x0d, 0x31, 0x37, 0x31, 0x31, 0x30, 0x39, 0x30, 0x32, 0x33, 0x33,
    0x31, 0x39, 0x5a, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x38, 0x32, 0x39, 0x30,
    0x32, 0x33, 0x33, 0x31, 0x39, 0x5a, 0x30, 0x52, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4e, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x53, 0x48, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x02, 0x53, 0x48, 0x31,
    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x02, 0x45, 0x4c,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x02, 0x45,
    0x4c, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06,
    0x54, 0x65, 0x73, 0x74, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
    0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
    0x01, 0x01, 0x00, 0xc3, 0x79, 0x72, 0xa4, 0xe2, 0xc6, 0xb7, 0x5d, 0x0f,
    0x41, 0x8c, 0x8e, 0xd1, 0x3c, 0xfd, 0x97, 0xf4, 0x8e, 0x82, 0x7e, 0x75,
    0xac, 0x4d, 0x85, 0xbb, 0xba, 0xe3, 0xd6, 0x22, 0xad, 0xc5, 0xc2, 0xd5,
    0x9d, 0x78, 0x1c, 0xab, 0x9c, 0x33, 0xb7, 0x95, 0x36, 0xcb, 0x63, 0x76,
    0x88, 0xc7, 0x3c, 0xa7, 0xf7, 0xfb, 0x84, 0x1d, 0x7c, 0xc5, 0x17, 0x25,
    0x5f, 0x1d, 0x41, 0xf3, 0x8c, 0xf9, 0x2f, 0x93, 0xab, 0xb2, 0x6b, 0x84,
    0xa9, 0x07, 0x70, 0xa1, 0xa0, 0xb3, 0xe0, 0x86, 0x5b, 0x5f, 0x4e, 0x0c,
    0x78, 0x7f, 0x20, 0x10, 0x12, 0x60, 0x13, 0x5c, 0xf8, 0x15, 0xe0, 0xc6,
    0xcb, 0xb2, 0x61, 0xe4, 0x78, 0x9d, 0xb8, 0x91, 0x60, 0x0f, 0xe6, 0xce,
    0xa4, 0x57, 0xa9, 0xb3, 0xb1, 0x9e, 0x3b, 0xc7, 0xf1, 0x66, 0x96, 0x23,
    0xf7, 0xe5, 0x40, 0xfa, 0xf6, 0x3a, 0xb9, 0x32, 0x64, 0xd0, 0x01, 0x14,
    0x31, 0x81, 0x3c, 0x3e, 0xf1, 0x9e, 0x64, 0x3d, 0xd0, 0x37, 0xee, 0xcd,
    0xf1, 0x82, 0x79, 0x3e, 0x08, 0x48, 0x2d, 0x2f, 0xa4, 0x5d, 0x41, 0xff,
    0x1f, 0xc1, 0x99, 0x26, 0x53, 0xb8, 0x7b, 0x59, 0xe5, 0x79, 0x9d, 0x25,
    0x2c, 0x35, 0xe6, 0x7b, 0x22, 0x02, 0x8c, 0x78, 0x05, 0xda, 0x90, 0x5d,
    0xbd, 0xd4, 0x53, 0xca, 0xa2, 0x73, 0xcc, 0xa0, 0xd7, 0x63, 0x3c, 0x22,
    0xe4, 0x2a, 0xb8, 0xc8, 0x5f, 0x58, 0x74, 0xce, 0x6c, 0x3b, 0xf3, 0x21,
    0x9a, 0xfa, 0xa0, 0x40, 0xc3, 0x10, 0x32, 0x46, 0xbb, 0x14, 0xff, 0xd6,
    0x1c, 0x41, 0x90, 0xb1, 0xb0, 0x0b, 0x59, 0x18, 0xaa, 0xfd, 0x43, 0x63,
    0x4b, 0x7c, 0xf1, 0x68, 0x1d, 0xa7, 0xed, 0x2c, 0x35, 0x11, 0xb8, 0xbc,
    0x02, 0x27, 0xc6, 0x39, 0x48, 0x62, 0x2b, 0xc1, 0xa9, 0x08, 0x53, 0x1f,
    0x7c, 0xdb, 0xa1, 0x6d, 0x41, 0x58, 0xc5, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x3d, 0xa4, 0x36, 0xc9,
    0x9d, 0x91, 0xd1, 0x25, 0xe7, 0x41, 0x2c, 0x8d, 0xda, 0xcd, 0xb3, 0x8a,
    0x53, 0xe4, 0xee, 0x4f, 0x94, 0xa4, 0x84, 0xee, 0xaf, 0x06, 0x85, 0x6a,
    0xa6, 0x54, 0xe5, 0x8f, 0x12, 0xd3, 0x5e, 0x84, 0x33, 0x7a, 0x1d, 0x66,
    0x24, 0xb0, 0x9d, 0x94, 0x71, 0xad, 0x5b, 0x91, 0x6d, 0x06, 0xf3, 0x7b,
    0x41, 0x8f, 0x1a, 0x97, 0xa2, 0xe9, 0x52, 0x57, 0x2e, 0xfb, 0xaf, 0x1f,
    0xb7, 0xf9, 0x9c, 0xf8, 0xa9, 0xde, 0x4e, 0xdb, 0x92, 0x92, 0x94, 0xe0,
    0x06, 0x50, 0xfa, 0x76, 0x4f, 0x45, 0xeb, 0x8f, 0x60, 0x49, 0xeb, 0x98,
    0x32, 0x65, 0xb9, 0x85, 0xc4, 0x21, 0x81, 0xe3, 0x81, 0x33, 0x41, 0x45,
    0xc4, 0xbc, 0x3b, 0xda, 0x7a, 0x74, 0xe8, 0x4e, 0x3e, 0xc9, 0x39, 0xdf,
    0xdd, 0xa0, 0xb3, 0x49, 0x76, 0x58, 0x13, 0x46, 0x74, 0x66, 0x9e, 0xc1,
    0xbc, 0x6b, 0x37, 0xb8, 0x77, 0x6a, 0x8e, 0xf1, 0x6a, 0xad, 0xb4, 0x75,
    0x13, 0x1b, 0x2b, 0x3f, 0x62, 0x5e, 0xc7, 0x18, 0x6f, 0x65, 0xfa, 0x5c,
    0xc6, 0xb3, 0xf9, 0xa2, 0x83, 0xfa, 0x79, 0x50, 0xfa, 0xa8, 0xc8, 0xa7,
    0xc5, 0xeb, 0x7d, 0x4a, 0x27, 0x82, 0xe5, 0x09, 0xfb, 0x20, 0x06, 0x25,
    0x0a, 0x35, 0x4e, 0x43, 0x01, 0x2e, 0x09, 0x41, 0x8d, 0x1d, 0xf5, 0x4e,
    0x58, 0x72, 0x3c, 0x52, 0x34, 0x25, 0x64, 0xb6, 0xc5, 0x24, 0x9c, 0xd8,
    0xe4, 0xc9, 0xe6, 0xee, 0x23, 0xce, 0xa8, 0x1d, 0x46, 0xd0, 0xc8, 0xd6,
    0x8f, 0x27, 0xc1, 0x48, 0x66, 0x3d, 0x30, 0x7f, 0xf4, 0xf5, 0xd7, 0x81,
    0x3a, 0x62, 0x92, 0xbb, 0x9a, 0x66, 0x65, 0xaf, 0x27, 0x93, 0xd8, 0x63,
    0xfa, 0xa8, 0x3f, 0x14, 0x2e, 0xbd, 0xd2, 0x20, 0x30, 0x5b, 0x41, 0x6d,
    0x01, 0x07, 0x37, 0xe9, 0x9c, 0x8a, 0x07, 0xe3, 0x32, 0xb7, 0x68, 0xae
};

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

extern NX_SECURE_X509_CRYPTO _nx_crypto_x509_cipher_lookup_table[];
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;

static void    ntest_0_entry(ULONG thread_input)
{
UCHAR receive_buffer[100];
USHORT extension_length, iv_size;
UINT       status, i, num_extensions, connect_count, length;
ULONG      actual_status, bytes, metadata_size;
NX_PACKET *send_packet, *receive_packet, npacket;
NX_SECURE_TLS_HELLO_EXTENSION extension_data[NX_SECURE_TLS_HELLO_EXTENSIONS_MAX];
NX_SECURE_X509_CERTIFICATE_STORE store, *store_ptr;
NX_SECURE_X509_CERT *cert_list, *cert_ptr, cert_1, cert_2;
NX_SECURE_TLS_HELLO_EXTENSION sni_extension;
NX_SECURE_X509_DNS_NAME dns_name;
NX_SECURE_X509_CERT test_cert;
NX_CRYPTO_METHOD test_md5, test_sha1, test_sha256;
UCHAR test_iv[16];

/* Lookup table used to map ciphersuites to cryptographic routines. */
NX_SECURE_TLS_CIPHERSUITE_INFO test_ciphersuite = {TLS_NULL_WITH_NULL_NULL, NX_NULL, NX_NULL, NX_NULL, 0, 0, NX_NULL, 0, NX_NULL};

/* Define the object we can pass into TLS. */
NX_SECURE_TLS_CRYPTO test_crypto_table =
{
    /* Ciphersuite lookup table and size. */
    &test_ciphersuite,
    1,
#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    NX_NULL,
    0,
#endif
    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    NX_NULL,
    NX_NULL,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    NX_NULL,
    &crypto_method_tls_prf_sha256
#endif
};

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Coverage 2 Test................................");

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
                                           &nx_crypto_tls_ciphers,
                                           server_crypto_metadata,
                                           sizeof(server_crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup our packet reassembly buffer. */
    nx_secure_tls_session_packet_buffer_set(&server_tls_session, server_packet_buffer, sizeof(server_packet_buffer));

    /* Enable Client Certificate Verification. */
    nx_secure_tls_session_client_verify_enable(&server_tls_session);

    /* Initialize our certificate. */
    nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    nx_secure_tls_local_certificate_add(&server_tls_session, &certificate);

    nx_secure_x509_certificate_initialize(&ica_certificate, ica_cert_der, ica_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_local_certificate_add(&server_tls_session, &ica_certificate);

    /* If we are testing client certificate verify, allocate remote certificate space. */
    nx_secure_tls_remote_certificate_allocate(&server_tls_session, &client_remote_certificate, client_remote_cert_buffer, sizeof(client_remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&server_tls_session, &client_remote_issuer, client_remote_issuer_buffer, sizeof(client_remote_issuer_buffer));

    /* Add a CA Certificate to our trusted store for verifying incoming client certificates. */
    nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&server_tls_session, &trusted_certificate);

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);
    tx_thread_suspend(&ntest_0);

    /* Receive ClientHello. */
    status =  nx_tcp_socket_receive(&server_socket, &receive_packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Release the ClientHello packet. */
    nx_packet_release(receive_packet);

    /* Initialize server session manually. */
    server_tls_session.nx_secure_tls_tcp_socket = &server_socket;
    server_tls_session.nx_secure_tls_packet_pool = &pool_0;
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;

    status = _nx_secure_tls_allocate_handshake_packet(&server_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
    tx_mutex_put(&_nx_secure_tls_protection);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Send an invaild message type - NX_SECURE_TLS_HELLO_REQUEST_VERIFY. */
    status = _nx_secure_tls_send_handshake_record(&server_tls_session, send_packet, NX_SECURE_TLS_HELLO_VERIFY_REQUEST, NX_WAIT_FOREVER);
    tx_mutex_put(&_nx_secure_tls_protection);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Try receiving records from the remote host. */
    status = nx_packet_allocate(&pool_0, &receive_packet, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    tx_mutex_put(&_nx_secure_tls_protection);
    server_tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    status = _nx_secure_tls_session_receive_records(&server_tls_session, &receive_packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_ALERT_RECEIVED, status);

    /* End the TLS session. This is required to properly shut down the TLS connection. */
    status = nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    status += nx_tcp_server_socket_unaccept(&server_socket);
    status += nx_tcp_server_socket_unlisten(&ip_0, 12);
    status += nx_secure_tls_session_delete(&server_tls_session);
    status += nx_tcp_socket_delete(&server_socket);
    EXPECT_EQ(NX_SUCCESS, status);

}

/* -----===== CLIENT =====----- */

static void    ntest_1_entry(ULONG thread_input)
{
UINT         status;
NX_PACKET *send_packet = NX_NULL;
NX_PACKET *receive_packet;
NX_PACKET unused_packet;
UCHAR receive_buffer[400];
ULONG bytes;
UINT connect_count;
UINT i, bytes_processed;
NX_SECURE_X509_DNS_NAME dns_name;
NX_SECURE_X509_CERT cert;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 1024*16,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Create a TLS session for our socket.  */
    status =  nx_secure_tls_session_create(&client_tls_session,
                                           &nx_crypto_tls_ciphers,
                                           client_crypto_metadata,
                                           sizeof(client_crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup our packet reassembly buffer. */
    nx_secure_tls_session_packet_buffer_set(&client_tls_session, client_packet_buffer, sizeof(client_packet_buffer));

    /* Make sure client certificate verification is disabled. */
    nx_secure_tls_session_client_verify_disable(&client_tls_session);

    /* Need to allocate space for the certificate coming in from the remote host. */
    nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));

    //nx_secure_x509_certificate_initialize(&certificate, cert_der, cert_der_len, NX_NULL, 0, private_key_der, private_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    nx_secure_x509_certificate_initialize(&client_certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    nx_secure_tls_local_certificate_add(&client_tls_session, &client_certificate);

    /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
    nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&client_tls_session, &trusted_certificate);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    tx_thread_resume(&ntest_0);

    status = nx_secure_tls_session_start(&client_tls_session, &client_socket, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_HANDSHAKE_FAILURE, status);

    /* Disconnect this socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
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
void nx_secure_tls_coverage_2_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Coverage 2 Test................................N/A\n");
    test_control_return(3);
}
#endif
