#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"
#include   "nx_crypto_rsa.h"
#include   "nx_crypto_ecdsa.h"
#include   "nx_secure_tls_test_init_functions.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
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
static NX_PACKET_POOL          pool_small;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NX_SECURE_TLS_SESSION   client_tls_session;
static NX_SECURE_TLS_SESSION   server_tls_session;
static NX_SECURE_TLS_SESSION   fake_tls_session;

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
static ULONG small_pool_area[1024];

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
void nx_secure_tls_coverage_test_application_define(void *first_unused_memory)
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

    /* Create a small packet pool.  */
    status = nx_packet_pool_create(&pool_small, "Small Packet Pool",
                                   (NX_IPv4_TCP_PACKET + NX_SECURE_TLS_RECORD_HEADER_SIZE + 2),
                                   small_pool_area, sizeof(small_pool_area));
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

/* Renegotiation callback. */
static ULONG _failed_renegotiation_callback(NX_SECURE_TLS_SESSION *tls_session)
{
    return(NX_SECURE_TLS_HANDSHAKE_FAILURE);
}

static ULONG _passed_renegotiation_callback(NX_SECURE_TLS_SESSION *tls_session)
{
    return(NX_SECURE_TLS_SUCCESS);
}

static ULONG _failed_server_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION* extension_data, UINT num_extensions)
{
    return(NX_SECURE_TLS_HANDSHAKE_FAILURE);
}

static ULONG _session_time_function(VOID)
{
    return 1;
}

static UINT _hash_initialize_fail(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 233;
}

static UINT _hash_update_fail(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_HASH_UPDATE)
    {
        return 147;
    }
    return NX_SUCCESS;
}

static UINT _nx_test_encrypt(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (input[0] == 0xff)
        return 233;
    return NX_SUCCESS;
}

static UINT _nx_test_decrypt(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    /* padding length > output length. */
    output[3] = 5;
    return NX_SUCCESS;
}

static UINT _bad_crypto_operation1(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    output[0] = 1; /* Illegal. */
    return 0;
}

static UINT _bad_crypto_operation2(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    output[0] = 0;
    output[1] = 2;
    output[input_length_in_byte - NX_SECURE_TLS_PREMASTER_SIZE - 1] = 1;/* Illegal. */
    return 0;
}

static UINT _bad_crypto_init1(struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    return 0;
}

static UINT _crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 0;
}

static UINT _crypto_operation_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 233;
}

extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table[];
extern NX_SECURE_X509_CRYPTO _nx_crypto_x509_cipher_lookup_table[];
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_auth_psk;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;


/* Lookup table used to map ciphersuites to cryptographic routines. */
static NX_SECURE_TLS_CIPHERSUITE_INFO test_ciphersuite = {TLS_NULL_WITH_NULL_NULL, NX_NULL, NX_NULL, NX_NULL, 0, 0, NX_NULL, 0, NX_NULL};

/* Define the object we can pass into TLS. */
static NX_SECURE_TLS_CRYPTO test_crypto_table =
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
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};

#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && !defined(NX_SECURE_DISABLE_X509)
/* Declare the NONE method:  encrypt / hash method not config */
static NX_CRYPTO_METHOD crypto_method_none =
{
    NX_CRYPTO_NONE,                           /* Name of the crypto algorithm          */
    0,                                        /* Key size in bits, not used            */
    0,                                        /* IV size in bits, not used             */
    0,                                        /* ICV size in bits, not used            */
    0,                                        /* Block size in bytes                   */
    0,                                        /* Metadata size in bytes                */
    NX_CRYPTO_NULL,                           /* Initialization routine, not used      */
    NX_CRYPTO_NULL,                           /* Cleanup routine, not used             */
    NX_CRYPTO_NULL                            /* NULL operation                        */
};

/* Declare the DES method:  encrypt / hash method not config */
static NX_CRYPTO_METHOD crypto_method_dsa =
{
    NX_CRYPTO_DIGITAL_SIGNATURE_DSA,          /* Name of the crypto algorithm          */
    0,                                        /* Key size in bits, not used            */
    0,                                        /* IV size in bits, not used             */
    0,                                        /* ICV size in bits, not used            */
    0,                                        /* Block size in bytes                   */
    0,                                        /* Metadata size in bytes                */
    NX_CRYPTO_NULL,                           /* Initialization routine, not used      */
    NX_CRYPTO_NULL,                           /* Cleanup routine, not used             */
    NX_CRYPTO_NULL                            /* NULL operation                        */
};

static NX_SECURE_X509_CRYPTO _ntest_crypto_x509_cipher_lookup_table[] = {
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_UNKNOWN,        &crypto_method_dsa,       &crypto_method_none},
    {NX_SECURE_TLS_X509_TYPE_UNKNOWN,        &crypto_method_none,      &crypto_method_none}
};
#endif

static UINT crypto_operation_func(UINT op,       /* Encrypt, Decrypt, Authenticate */
                                  VOID *handler, /* Crypto handler */
                                  struct NX_CRYPTO_METHOD_STRUCT *method,
                                  UCHAR *key,
                                  NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                  UCHAR *input,
                                  ULONG input_length_in_byte,
                                  UCHAR *iv_ptr,
                                  UCHAR *output,
                                  ULONG output_length_in_byte,
                                  VOID *crypto_metadata,
                                  ULONG crypto_metadata_size,
                                  VOID *packet_ptr,
                                  VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return NX_CRYPTO_NOT_SUCCESSFUL;
}

static NX_SECURE_TLS_CRYPTO  fake_crypto_table;
static NX_CRYPTO_METHOD      fake_sha256_method; 


static void    ntest_0_entry(ULONG thread_input)
{
UCHAR receive_buffer[100];
USHORT extension_length, iv_size;
UINT       status, i, num_extensions, connect_count, length;
ULONG      actual_status, bytes = 0, metadata_size, returned_length;
NX_PACKET *send_packet, *receive_packet, npacket;
NX_SECURE_TLS_HELLO_EXTENSION extension_data[NX_SECURE_TLS_HELLO_EXTENSIONS_MAX];
NX_SECURE_X509_CERTIFICATE_STORE store, *store_ptr;
NX_SECURE_X509_CERT *cert_list, *cert_ptr, cert_1, cert_2;
NX_SECURE_TLS_HELLO_EXTENSION sni_extension;
NX_SECURE_X509_DNS_NAME dns_name;
NX_SECURE_X509_CERT test_cert;
NX_CRYPTO_METHOD test_md5, test_sha1, test_sha256;
UCHAR test_iv[16];

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Coverage Test..................................");

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

    /* Test duplicate ID. */
    client_remote_certificate.nx_secure_x509_cert_identifier = 1;
    client_remote_issuer.nx_secure_x509_cert_identifier = 1;
    status = nx_secure_tls_remote_certificate_allocate(&server_tls_session, &client_remote_issuer, client_remote_issuer_buffer, sizeof(client_remote_issuer_buffer));
    EXPECT_EQ(NX_SECURE_TLS_CERT_ID_DUPLICATE, status);
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

    /* Fail to allocate handshake packet from small pool as no room for TLS handshake header.  */
    /* Cover nx_secure_tls_allocate_handshake_packet.c
        if (((ULONG)((*packet_ptr) -> nx_packet_data_end) - (ULONG)((*packet_ptr) -> nx_packet_prepend_ptr)) <
            NX_SECURE_TLS_HANDSHAKE_HEADER_SIZE)
        {

            /* Packet buffer is too small. * /
            nx_packet_release(*packet_ptr);
            return(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL);
        }
    */
    status = _nx_secure_tls_allocate_handshake_packet(&server_tls_session, &pool_small, &send_packet, NX_WAIT_FOREVER);
    tx_mutex_put(&_nx_secure_tls_protection);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

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


#if (NX_SECURE_TLS_TLS_1_2_ENABLED) && !(NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)

#ifndef NX_SECURE_ENABLE_DTLS
    /* Cover line 214 in nx_secure_tls_handshake_hash_update.c */
    fake_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_1;
    status = _nx_secure_tls_handshake_hash_update(&fake_tls_session, NX_NULL, 0);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);    

    /* Cover line 219 in nx_secure_tls_handshake_hash_update.c */
    fake_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    fake_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &fake_sha256_method;
    fake_sha256_method.nx_crypto_operation = NX_NULL;    
    fake_tls_session.nx_secure_tls_crypto_table = &fake_crypto_table;
    status = _nx_secure_tls_handshake_hash_update(&fake_tls_session, NX_NULL, 0);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);    

    /* Cover line 236 in nx_secure_tls_handshake_hash_update.c */
    fake_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &fake_sha256_method;
    fake_sha256_method.nx_crypto_operation = &crypto_operation_func;
    status = _nx_secure_tls_handshake_hash_update(&fake_tls_session, NX_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    
#endif /* NX_SECURE_ENABLE_DTLS*/
#endif /* NX_SECURE_TLS_TLS_1_2_ENABLED */

    /* Try to cover all branches in server handshake. */
    /* Invalid message type. */
    receive_buffer[0] = NX_SECURE_TLS_HELLO_VERIFY_REQUEST;
    /* Set message length as zero. */
    receive_buffer[1] = 0;
    receive_buffer[2] = 0;
    receive_buffer[3] = 0;

    /* Process invalid message type in server handshake. */
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 4, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    /* Set the length of first extension as zero. */
#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) && defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    server_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[3];
#else
    server_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[1];
#endif
    receive_buffer[2] = 0;
    receive_buffer[3] = 0;

    /* Process the extension to be saved off. */
    receive_buffer[0] = NX_SECURE_TLS_EXTENSION_SERVER_NAME_INDICATION >> 8;
    receive_buffer[1] = NX_SECURE_TLS_EXTENSION_SERVER_NAME_INDICATION & 0xff;
    status = _nx_secure_tls_process_serverhello_extensions(&server_tls_session, receive_buffer, 4/* message length */, extension_data, &num_extensions);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Process the extension to be ignored. */
    receive_buffer[0] = NX_SECURE_TLS_EXTENSION_SIGNATURE_ALGORITHMS >> 8;
    receive_buffer[1] = NX_SECURE_TLS_EXTENSION_SIGNATURE_ALGORITHMS & 0xff;
    status = _nx_secure_tls_process_serverhello_extensions(&server_tls_session, receive_buffer, 4/* message length */, extension_data, &num_extensions);
    EXPECT_EQ(NX_SUCCESS, status);

#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    /* Fail to process renegotiation extensions. */
    receive_buffer[0] = NX_SECURE_TLS_EXTENSION_SECURE_RENEGOTIATION >> 8;
    receive_buffer[1] = NX_SECURE_TLS_EXTENSION_SECURE_RENEGOTIATION & 0xff;
    receive_buffer[2] = 0;
    receive_buffer[3] = 1;
    receive_buffer[4] = 0;
    server_tls_session.nx_secure_tls_local_session_active = 1;
    server_tls_session.nx_secure_tls_remote_session_active = 1;
    /* The renegotiation flag is not set. */
    server_tls_session.nx_secure_tls_secure_renegotiation = 0;
    status = _nx_secure_tls_process_serverhello_extensions(&server_tls_session, receive_buffer, 5/* message_length */, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    /* Received verify data is not the expected size. */
    server_tls_session.nx_secure_tls_secure_renegotiation = 1;
    receive_buffer[2] = 1;
    receive_buffer[3] = 0;
    receive_buffer[4] = 0xff;
    status = _nx_secure_tls_process_serverhello_extensions(&server_tls_session, receive_buffer, 260/* message_length */, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    receive_buffer[2] = 0;
    receive_buffer[3] = 0x19;
    receive_buffer[4] = 0x18; /* expected size */
    /* Received verify data is not equal to locally-stored version. */
    receive_buffer[5] = 0xff;
    server_tls_session.nx_secure_tls_local_verify_data[0] = 0x00;
    status = _nx_secure_tls_process_serverhello_extensions(&server_tls_session, receive_buffer, 29/* message_length */, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    memset(receive_buffer + 5, 0, NX_SECURE_TLS_FINISHED_HASH_SIZE);
    memset(server_tls_session.nx_secure_tls_local_verify_data, 0, NX_SECURE_TLS_FINISHED_HASH_SIZE);
    /* Received verify data is not equal to remote verify data. */
    receive_buffer[5 + NX_SECURE_TLS_FINISHED_HASH_SIZE] = 0xff;
    server_tls_session.nx_secure_tls_remote_verify_data[0] = 0x00;
    status = _nx_secure_tls_process_serverhello_extensions(&server_tls_session, receive_buffer, 29/* message_length */, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    /* Try to cover branches in _nx_secure_tls_process_clienthello. */
    server_tls_session.nx_secure_tls_local_session_active = 1;
    server_tls_session.nx_secure_tls_renegotation_enabled = 0;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 38);
    EXPECT_EQ(NX_SECURE_TLS_NO_RENEGOTIATION_ERROR, status);

    /* Renegotiation callback failed. */
    server_tls_session.nx_secure_tls_local_session_active = 1;
    server_tls_session.nx_secure_tls_renegotation_enabled = 1;
    server_tls_session.nx_secure_tls_session_renegotiation_callback = _failed_renegotiation_callback;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 38);
    EXPECT_EQ(NX_SECURE_TLS_HANDSHAKE_FAILURE, status);
#endif

    /* Failed in protocol version checking. */
#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    server_tls_session.nx_secure_tls_secure_renegotiation = 1;
#endif
    server_tls_session.nx_secure_tls_protocol_version = 0;
    server_tls_session.nx_secure_tls_protocol_version_override = 0;
    server_tls_session.nx_secure_tls_local_session_active = 0;
    receive_buffer[0] = 0xff;
    receive_buffer[1] = 0xff;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 38);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_TLS_VERSION, status);

    server_tls_session.nx_secure_tls_protocol_version = 0;
    server_tls_session.nx_secure_tls_protocol_version_override = 0;
    server_tls_session.nx_secure_tls_local_session_active = 0;
#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    server_tls_session.nx_secure_tls_renegotation_enabled = 1;
#endif
    /* Specify a valid protocol version. */
    receive_buffer[0] = NX_SECURE_TLS_VERSION_TLS_1_2 >> 8;
    receive_buffer[1] = NX_SECURE_TLS_VERSION_TLS_1_2 & 0xff;
    /* Set session_id_length as 1. */
    receive_buffer[34] = 0x01;
    /* Specify an illegal ciphersuite_list_length which overflow the length of the whole message. */
    receive_buffer[36] = 0xff;
    receive_buffer[37] = 0xff;
#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    server_tls_session.nx_secure_tls_session_renegotiation_callback = _passed_renegotiation_callback;
#endif
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 38);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* Specify a valid protocol version. */
    receive_buffer[0] = NX_SECURE_TLS_VERSION_TLS_1_2 >> 8;
    receive_buffer[1] = NX_SECURE_TLS_VERSION_TLS_1_2 & 0xff;
    /* No supported ciphers. */
    server_tls_session.nx_secure_tls_protocol_version = 0;
    server_tls_session.nx_secure_tls_protocol_version_override = 0;
    server_tls_session.nx_secure_tls_local_session_active = 0;
#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    server_tls_session.nx_secure_tls_renegotiation_handshake = 0;
    server_tls_session.nx_secure_tls_renegotation_enabled = 0;
#endif
    /* No ciphersuite is in use. */
    server_tls_session.nx_secure_tls_session_ciphersuite = 0x0;
    receive_buffer[36] = 0x0;
    receive_buffer[37] = 0x02;
    receive_buffer[38] = 0xff;
    receive_buffer[39] = 0xff;
    /* Compression methods length. */
    receive_buffer[40] = 1;
    receive_buffer[41] = 0;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 42);
    EXPECT_EQ(NX_SECURE_TLS_NO_SUPPORTED_CIPHERS, status);

    /* Set session_id_length as 0. */
    receive_buffer[34] = 0x0;
    /* Ciphersuites list. */
    /* Length */
    receive_buffer[35] = 0x0;
    receive_buffer[36] = 0x02;
    /* Requested ciphersuite. */
    receive_buffer[37] = (UCHAR)(TLS_RSA_WITH_AES_128_CBC_SHA256 >> 8);
    receive_buffer[38] = (UCHAR)(TLS_RSA_WITH_AES_128_CBC_SHA256 & 0xff);
    /* Compression methods length. */
    receive_buffer[39] = 1;
    receive_buffer[40] = 1;
    /* No ciphersuite is in use. */
    server_tls_session.nx_secure_tls_session_ciphersuite = 0x0;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 41);
    EXPECT_EQ(NX_SECURE_TLS_BAD_COMPRESSION_METHOD, status);

    /* Compression methods length. */
    receive_buffer[39] = 1;
    receive_buffer[40] = 0;
    /* No ciphersuite is in use. */
    server_tls_session.nx_secure_tls_session_ciphersuite = 0x0;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 41);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Compression methods length. */
    receive_buffer[39] = 2;
    receive_buffer[40] = 1;
    receive_buffer[41] = 0;
    /* No ciphersuite is in use. */
    server_tls_session.nx_secure_tls_session_ciphersuite = 0x0;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 42);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Set the length of extensions as zero. */
    receive_buffer[39] = 1;
    receive_buffer[40] = 0;
    receive_buffer[41] = 0;
    receive_buffer[42] = 0;
    /* No ciphersuite is in use. */
    server_tls_session.nx_secure_tls_session_ciphersuite = 0x0;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 43);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Process an illegal renegotiation extension. */
    /* Only an established session can process renegotiation extensions with verify data. */
    /* Set the length of extensions as 8. */
    receive_buffer[41] = 0;
    receive_buffer[42] = 6;
    /* Renegotiation extension flag. */
    receive_buffer[43] = 0xff;
    receive_buffer[44] = 0x01;
    /* The length of this extension. */
    receive_buffer[45] = 0x0;
    receive_buffer[46] = 0x02;
    /* Renegotiation connection length, which is invalid to a inactive session. */
    receive_buffer[47] = 0x01;
    /* No ciphersuite is in use. */
    server_tls_session.nx_secure_tls_session_ciphersuite = 0x0;

#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    /* Session has to be active on both ends, with renegotiation enabled. */
    server_tls_session.nx_secure_tls_remote_session_active = NX_TRUE;
    server_tls_session.nx_secure_tls_local_session_active = NX_TRUE;
    server_tls_session.nx_secure_tls_secure_renegotiation = NX_TRUE;
    server_tls_session.nx_secure_tls_renegotation_enabled = NX_TRUE;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 49);

    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    /* Reset flags. */
    server_tls_session.nx_secure_tls_remote_session_active = NX_FALSE;
    server_tls_session.nx_secure_tls_local_session_active = NX_FALSE;
    server_tls_session.nx_secure_tls_secure_renegotiation = NX_FALSE;
    server_tls_session.nx_secure_tls_renegotation_enabled = NX_FALSE;
    server_tls_session.nx_secure_tls_renegotiation_handshake = NX_FALSE;

    /* Process an empty renegotiation extension to enable renegotiations. */
    receive_buffer[42] = 5;
    receive_buffer[46] = 0x01;
    receive_buffer[47] = 0x00;
    server_tls_session.nx_secure_tls_local_session_active = 0;
    /* No ciphersuite is in use. */
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 48);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Incorrect message length. */
    receive_buffer[42] = 8;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 48);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* Server callback failed. */
    receive_buffer[42] = 5;
    server_tls_session.nx_secure_tls_session_server_callback = _failed_server_callback;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 48);
    EXPECT_EQ(NX_SECURE_TLS_HANDSHAKE_FAILURE, status);

    /* _nx_secure_tls_proc_clienthello_sec_reneg_extension. */
    server_tls_session.nx_secure_tls_local_session_active = 1;
    server_tls_session.nx_secure_tls_renegotation_enabled = 1;
    server_tls_session.nx_secure_tls_remote_session_active = NX_TRUE;
    server_tls_session.nx_secure_tls_secure_renegotiation = NX_TRUE;
    /* Set the length of renegotiation connection as an invalid value. */
    receive_buffer[42] = 6;
    receive_buffer[46] = 0x02;
    receive_buffer[47] = 0x01;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 49);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    receive_buffer[42] = 17;
    receive_buffer[46] = 0x0d;
    receive_buffer[47] = 0x0c;
    /* Received verify data is different from our locally-stored version. */
    receive_buffer[48] = 0x01;
    server_tls_session.nx_secure_tls_remote_verify_data[0] = 0x0;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 60);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    receive_buffer[42] = 6;
    receive_buffer[46] = 0x02;
    receive_buffer[47] = 0x01;
    server_tls_session.nx_secure_tls_local_session_active = 0;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 49);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_SESSION_INACTIVE, status);
#endif

    /* Empty reneg extension. */
    receive_buffer[42] = 5;
    receive_buffer[47] = 0x0;
    /* The length of this extension is invalid. */
    receive_buffer[45] = 0x0;
    receive_buffer[46] = 0x02;
    server_tls_session.nx_secure_tls_local_session_active = 1;
#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 48);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    receive_buffer[46] = 0x01;
    /* Received an empty reneg extension while local session is already active. */
    server_tls_session.nx_secure_tls_local_session_active = 1;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 48);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    server_tls_session.nx_secure_tls_local_session_active = 1;
    server_tls_session.nx_secure_tls_remote_session_active = 1;
    /* scsv is not seen. */
    server_tls_session.nx_secure_tls_secure_renegotiation = 0;
    status = _nx_secure_tls_process_clienthello(&server_tls_session, receive_buffer, 48);
    EXPECT_EQ(NX_SECURE_TLS_NO_RENEGOTIATION_ERROR, status);

    /* Session id exists. */
    UCHAR session_id[10];
    server_tls_session.nx_secure_tls_session_id_length = 1;
    nx_packet_allocate(&pool_0, &send_packet, NX_IPv4_TCP_PACKET, NX_NO_WAIT);
    status = _nx_secure_tls_send_serverhello(&server_tls_session, send_packet);
    nx_packet_release(send_packet);
    EXPECT_EQ(NX_SUCCESS, status);

    /* No remote endpoint certificate is allocated earlier. 
       As of 5.12, it is OK if no certificates are allocated - _nx_secure_tls_process_remote_certificate will
       instead allocate certificate space from the packet reassembly buffer. This function as tested now should
       return an incorrect message length error. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = NX_NULL;
    /* Set the total length of certificate list as 16 bytes. */
    receive_buffer[0] = 0;
    receive_buffer[1] = 0x10;
    receive_buffer[2] = 0;
    status = _nx_secure_tls_process_remote_certificate(&server_tls_session, receive_buffer, 0x100000, 0);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* Initialized a certificate for test. */
    nx_secure_x509_certificate_initialize(&test_cert, remote_cert_buffer, sizeof(remote_cert_buffer), NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);

    /* Certificate exists. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = &test_cert;
    /* Overflow the length of the whole certificate list. */
    receive_buffer[3] = 0;
    receive_buffer[4] = 0x11;
    receive_buffer[5] = 0;
    status = _nx_secure_tls_process_remote_certificate(&server_tls_session, receive_buffer, 0x100000, 0);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* Certificate exists. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = &test_cert;
    /* Not enougn buffer. */
    receive_buffer[4] = 0xf;
    status = _nx_secure_tls_process_remote_certificate(&server_tls_session, receive_buffer, 0x100000, 0);
    EXPECT_EQ(NX_SECURE_TLS_INSUFFICIENT_CERT_SPACE, status);

    /* Certificate exists. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = &test_cert;
    receive_buffer[4] = 0;
    receive_buffer[5] = 1;
    /* Invalid tlv type, certificate_parse failed. */
    receive_buffer[6] = 0xff;
    status = _nx_secure_tls_process_remote_certificate(&server_tls_session, receive_buffer, 0x100000, 0);
    EXPECT_EQ(NX_SECURE_X509_MULTIBYTE_TAG_UNSUPPORTED, status);
#endif

    /* Tests for hash_update. */
    server_tls_session.nx_secure_tls_session_ciphersuite = NX_NULL;
    status = _nx_secure_tls_record_hash_update(&server_tls_session, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    /* No remote certificates in this store. */
    store.nx_secure_x509_remote_certificates = NX_NULL;
    status = _nx_secure_x509_remote_endpoint_certificate_get(&store, &cert_ptr);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);

    /* Need to initialize certificate names for comparison. */
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "cert1";
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = strlen("cert1");
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "cert2";
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = strlen("cert2");

    /* Local certificates not found. */
    store.nx_secure_x509_local_certificates = &cert_1;
    cert_1.nx_secure_x509_cert_identifier = 1;
    cert_1.nx_secure_x509_user_allocated_cert = 1;
    cert_1.nx_secure_x509_next_certificate = &cert_2;
    cert_2.nx_secure_x509_cert_identifier = 2;
    cert_2.nx_secure_x509_user_allocated_cert = 1;
    cert_2.nx_secure_x509_next_certificate = NX_NULL;
    /* Try to find out the certificate with id 3. */
    status = _nx_secure_x509_local_certificate_find(&store, &cert_ptr, 3);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);

    /* Structure:
     * |       1            |    <Cert types count>    |             2              |  <Sig algs length>        |
     * |  Cert types count  | Cert types (1 byte each) | Sig Hash algorithms length | Algorithms (2 bytes each) |
     */

    /* Processing certificate requests. */
    /* message length = 0, cert_types_length = 1. */
    receive_buffer[0] = 1;
    status = _nx_secure_tls_process_certificate_request(&server_tls_session, receive_buffer, 0);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* No supported certificate type. */
    receive_buffer[1] = 0xff;
    status = _nx_secure_tls_process_certificate_request(&server_tls_session, receive_buffer, 2);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_CERT_SIGN_TYPE, status);

    receive_buffer[1] = NX_SECURE_TLS_CERT_TYPE_RSA_SIGN;
    /* Incorrect algorithm list length. */
    receive_buffer[2] = 0xff;
    receive_buffer[3] = 0;
    status = _nx_secure_tls_process_certificate_request(&server_tls_session, receive_buffer, 2);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    status = _nx_secure_tls_process_certificate_request(&server_tls_session, receive_buffer, 4);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    receive_buffer[2] = 0;
    receive_buffer[3] = 2;
    /* No supported signature algorithms. */
    receive_buffer[4] = 0xff;
    receive_buffer[5] = 0xff;
    status = _nx_secure_tls_process_certificate_request(&server_tls_session, receive_buffer, 6);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_CERT_SIGN_ALG, status);

#if !defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) && !defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) && !defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)
    /* Special case - NULL ciphersuite. No keys are generated. */
    /* Overflow the key buffer. */
    receive_buffer[0] = 0;
    receive_buffer[1] = sizeof(client_tls_session.nx_secure_tls_key_material.nx_secure_tls_pre_master_secret) + 1;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    /* No local device certificates. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = NX_NULL;
    /* Take use of the crypto table with TLS_NULL_WITH_NULL_NULL. */
    server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    status = _nx_secure_tls_process_client_key_exchange(&server_tls_session, receive_buffer, 1024, NX_SECURE_TLS);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    /* Do not overflow the key buffer. */
    receive_buffer[0] = 0;
    receive_buffer[1] = 1;
    status = _nx_secure_tls_process_client_key_exchange(&server_tls_session, receive_buffer, 1024, NX_SECURE_TLS);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    /* Incorrect message length. */
    status = _nx_secure_tls_process_client_key_exchange(&server_tls_session, receive_buffer, 0, NX_SECURE_TLS);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);
#endif

    /* Local certificates not found. */
    store.nx_secure_x509_local_certificates = &cert_1;
    cert_1.nx_secure_x509_certificate_is_identity_cert = 0;
    cert_1.nx_secure_x509_next_certificate = &cert_2;
    cert_2.nx_secure_x509_certificate_is_identity_cert = 0;
    cert_2.nx_secure_x509_next_certificate = NX_NULL;
    /* Try to find out the certificate with id 3. */
    status = _nx_secure_x509_local_device_certificate_get(&store, NX_NULL, &cert_ptr);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);

    /* Insufficient certificate space. */
    status = _nx_secure_x509_certificate_initialize(&test_cert, NX_NULL/* certificate_data */, 1, receive_buffer/* raw_data_buffer */, 0, NX_NULL/* private_key */, 0, 0);
    EXPECT_EQ(NX_SECURE_X509_INSUFFICIENT_CERT_SPACE, status);

    /* NULL pointers. */
    status = _nx_secure_x509_certificate_list_find(NX_NULL, NX_NULL, 0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = _nx_secure_x509_certificate_list_find(NX_NULL, NX_NULL, 0, &cert_ptr);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Find out certificate by id. */
    cert_list = &cert_1;
    cert_1.nx_secure_x509_cert_identifier = 1;
    status = _nx_secure_x509_certificate_list_find(&cert_list, NX_NULL, 1, &cert_ptr);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Cannot find certificate list. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = NX_NULL;
    status = _nx_secure_tls_remote_certificate_free(&server_tls_session, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    /* One certificate exists in both remote and free list. */
    cert_1.nx_secure_x509_cert_identifier = 0;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert_1;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = &cert_1;
    status = _nx_secure_tls_remote_certificate_free(&server_tls_session, NX_NULL);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    status = _nx_secure_tls_remote_certificate_free_all(&server_tls_session);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Invalid ciphersuite. */
    server_tls_session.nx_secure_tls_session_ciphersuite = NX_NULL;
    status = _nx_secure_tls_record_hash_calculate(&server_tls_session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    status = _nx_secure_tls_generate_keys(&server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    /* Access the exceptions certificate list. */
    status = _nx_secure_x509_store_certificate_remove(&(server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store), NX_NULL, NX_SECURE_X509_CERT_LOCATION_EXCEPTIONS, 0);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);

    /* Extract the data from the extension. */
    /* Server Name Indication Extension structure:
     *              |  extension_data
     * |     2      |      2        |      1     |     2       |   <name length>   |
     * |  Ext Type  |  list length  |  name type | name length |  Host name string |
     */

    /* Server name indication extension not found. */
    sni_extension.nx_secure_tls_extension_id = 0xffff;
    status = _nx_secure_tls_session_sni_extension_parse(&server_tls_session, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_EXTENSION_NOT_FOUND, status);

    sni_extension.nx_secure_tls_extension_id = NX_SECURE_TLS_EXTENSION_SERVER_NAME_INDICATION;
    /* Invalid name type. */
    receive_buffer[2] = 0xff;
    sni_extension.nx_secure_tls_extension_data = receive_buffer;
    status = _nx_secure_tls_session_sni_extension_parse(&server_tls_session, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SNI_EXTENSION_INVALID, status);

    receive_buffer[2] = NX_SECURE_TLS_SNI_NAME_TYPE_DNS;
    /* Incorrect list length. */
    receive_buffer[0] = 0xff;
    receive_buffer[1] = 0xff;
    sni_extension.nx_secure_tls_extension_data_length = 0x20;
    status = _nx_secure_tls_session_sni_extension_parse(&server_tls_session, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SNI_EXTENSION_INVALID, status);

    receive_buffer[0] = 0;
    receive_buffer[1] = 0x1f;
    /* Incorrect name length. */
    receive_buffer[3] = 0;
    receive_buffer[4] = 0x21;
    status = _nx_secure_tls_session_sni_extension_parse(&server_tls_session, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SNI_EXTENSION_INVALID, status);

    sni_extension.nx_secure_tls_extension_data_length = NX_SECURE_X509_DNS_NAME_MAX + 1;
    receive_buffer[0] = 0;
    receive_buffer[1] = NX_SECURE_X509_DNS_NAME_MAX + 1;
    /* Overflow the dns name length max. */
    receive_buffer[3] = 0;
    receive_buffer[4] = NX_SECURE_X509_DNS_NAME_MAX + 1;
    status = _nx_secure_tls_session_sni_extension_parse(&server_tls_session, &sni_extension, NX_SECURE_X509_DNS_NAME_MAX + 1, &dns_name);
    EXPECT_EQ(NX_SUCCESS, status);

    /* remote_certificate_endpoint_get failed. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = NX_NULL;
    status = _nx_secure_tls_remote_certificate_verify(&server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_NO_CERT_SPACE_ALLOCATED, status);

    /* certificate_chain_verify cannot find issuer certificate. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert_1;
    cert_1.nx_secure_x509_next_certificate = NX_NULL;
    status = _nx_secure_tls_remote_certificate_verify(&server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_ISSUER_CERTIFICATE_NOT_FOUND, status);

    /* expiration_check failed. */
    server_tls_session.nx_secure_tls_session_time_function = _session_time_function;
    cert_1.nx_secure_x509_validity_format = NX_SECURE_ASN_TAG_GENERALIZED_TIME;
    status = _nx_secure_tls_remote_certificate_verify(&server_tls_session);
    EXPECT_EQ(NX_SECURE_X509_INVALID_DATE_FORMAT, status);

    certificate.nx_secure_x509_validity_format = 0xff;
    status = _nx_secure_tls_remote_certificate_verify(&server_tls_session);
    EXPECT_EQ(NX_SECURE_X509_INVALID_DATE_FORMAT, status);

    /* process_finished failed. */
    server_tls_session.nx_secure_tls_remote_session_active = 1;
    server_tls_session.nx_secure_tls_received_remote_credentials = 0;
    status = _nx_secure_tls_process_finished(&server_tls_session, receive_buffer, NX_SECURE_TLS_FINISHED_HASH_SIZE);
    EXPECT_EQ(NX_SECURE_TLS_HANDSHAKE_FAILURE, status);

    server_tls_session.nx_secure_tls_received_remote_credentials = 1;
    memset(receive_buffer, 0xff, NX_SECURE_TLS_FINISHED_HASH_SIZE);
    status = _nx_secure_tls_process_finished(&server_tls_session, receive_buffer, NX_SECURE_TLS_FINISHED_HASH_SIZE);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    /* Certificate id duplicate. */
    cert_ptr = &cert_1;
    cert_1.nx_secure_x509_cert_identifier = 1;
    cert_2.nx_secure_x509_cert_identifier = 1;
    status = _nx_secure_x509_certificate_list_add(&cert_ptr, &cert_2, 1);
    EXPECT_EQ(NX_SECURE_X509_CERT_ID_DUPLICATE, status);

    /* Make the common names of cert_1 and cert_2 the same. */
    cert_ptr = &cert_1;
    cert_1.nx_secure_x509_cert_identifier = 1;
    cert_2.nx_secure_x509_cert_identifier = 2;
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "test";
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = 4;
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "test";
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = 4;
    /* Disabled duplicate_ok. */
    status = _nx_secure_x509_certificate_list_add(&cert_ptr, &cert_2, 0);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Do not compare common name. */
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_country = "usa";
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_country_length = 3;
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_country = "usa";
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_country_length = 3;
    status = _nx_secure_x509_distinguished_name_compare(&cert_1.nx_secure_x509_distinguished_name, &cert_2.nx_secure_x509_distinguished_name, NX_SECURE_X509_NAME_COUNTRY);
    EXPECT_EQ(0, status);

    /* NULL certificate store pointer. */
    status = _nx_secure_x509_store_certificate_add(&cert_1, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Add certificate to exceptions list. */
    store.nx_secure_x509_certificate_exceptions = NX_NULL;
    status = _nx_secure_x509_store_certificate_add(&cert_1, &store, NX_SECURE_X509_CERT_LOCATION_EXCEPTIONS);
    EXPECT_EQ(NX_SUCCESS, status);

#ifndef NX_SECURE_X509_USE_EXTENDED_DISTINGUISHED_NAMES
    /* Make the distinguished names of cert_1 and cert_2 the same. */
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "test";
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = 4;
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_country_length = 0;
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_organization_length = 0;
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_org_unit_length = 0;
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_distinguished_name_qualifier_length = 0;
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_state_length = 0;
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_serial_number_length = 0;

    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "sss";
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = 3;
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_country_length = 0;
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_organization_length = 0;
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_org_unit_length = 0;
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_distinguished_name_qualifier_length = 0;
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_state_length = 0;
    cert_2.nx_secure_x509_distinguished_name.nx_secure_x509_serial_number_length = 0;

    /* The issuer of cert_2 is cert_1. */
    memcpy(&cert_2.nx_secure_x509_issuer, &cert_1.nx_secure_x509_distinguished_name, sizeof(cert_1.nx_secure_x509_distinguished_name));

    /* Loop to find cert_2 though cert_1. */
    store.nx_secure_x509_remote_certificates = &cert_1;
    cert_1.nx_secure_x509_next_certificate = &cert_2;
    cert_2.nx_secure_x509_next_certificate = NX_NULL;
    status = _nx_secure_x509_remote_endpoint_certificate_get(&store, &cert_ptr);
    EXPECT_EQ(NX_SUCCESS, status);
#endif

    /* Recreate the session. */
    nx_secure_tls_session_delete(&server_tls_session);
    nx_secure_tls_session_create(&server_tls_session,
                                           &nx_crypto_tls_ciphers,
                                           server_crypto_metadata,
                                           sizeof(server_crypto_metadata));
    length = 0xff;
    nx_packet_allocate(&pool_0, &send_packet, 0, NX_NO_WAIT);
    nx_packet_data_append(send_packet, receive_buffer, length, &pool_0, NX_NO_WAIT);
#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) && defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    server_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[3];
#else
    server_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[1];
#endif
    /* header_length > sizeof(header) */
    status = _nx_secure_tls_verify_mac(&server_tls_session, receive_buffer, 7, send_packet, 12, &length);
    EXPECT_EQ(NX_SECURE_TLS_HASH_MAC_VERIFY_FAILURE, status);

    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_active_certificate = NX_NULL;
    /* No local certificates. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = NX_NULL;
    status = _nx_secure_tls_send_certificate(&server_tls_session, send_packet, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    /* Make sha256 > md5 + sha1 */
    test_crypto_table.nx_secure_tls_handshake_hash_md5_method = &test_md5;
    test_md5.nx_crypto_metadata_area_size = 0;
    test_crypto_table.nx_secure_tls_handshake_hash_sha1_method = &test_sha1;
    test_sha1.nx_crypto_metadata_area_size = 0;
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    test_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &test_sha256;
    test_sha256.nx_crypto_metadata_area_size = 1;
#endif

    /* Disable all ciphersuites. */
    test_crypto_table.nx_secure_tls_ciphersuite_lookup_table_size = 0;
#ifndef NX_SECURE_DISABLE_X509
    /* Set x509 cipher table. */
    test_crypto_table.nx_secure_tls_x509_cipher_table = _nx_crypto_x509_cipher_lookup_table;
    test_crypto_table.nx_secure_tls_x509_cipher_table_size = 1;
#endif
    status = _nx_secure_tls_metadata_size_calculate(&test_crypto_table, &metadata_size);
    EXPECT_EQ(NX_SUCCESS, status);

    NX_CRYPTO_METHOD hash_method;
    ULONG sequence_number[NX_SECURE_TLS_SEQUENCE_NUMBER_SIZE];

    memset(&hash_method, 0, sizeof(hash_method));

    /* Hash operations failed. */
    nx_secure_tls_session_delete(&server_tls_session);
    nx_secure_tls_session_create(&server_tls_session,
                                           &test_crypto_table,
                                           server_crypto_metadata,
                                           sizeof(server_crypto_metadata));
    test_crypto_table.nx_secure_tls_ciphersuite_lookup_table = &test_ciphersuite;
    test_crypto_table.nx_secure_tls_ciphersuite_lookup_table_size = 1;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    test_ciphersuite.nx_secure_tls_hash = &hash_method;
    hash_method.nx_crypto_operation = _hash_initialize_fail;
    status = _nx_secure_tls_record_hash_initialize(&server_tls_session, sequence_number, NX_NULL, 0, NX_NULL, NX_NULL);
    EXPECT_EQ(233, status);

    hash_method.nx_crypto_operation = _hash_update_fail;
    status = _nx_secure_tls_record_hash_initialize(&server_tls_session, sequence_number, NX_NULL, 0, NX_NULL, NX_NULL);
    EXPECT_EQ(147, status);

    /* tls_send_record failed while calling tls_record_hash_initialize. */
    server_tls_session.nx_secure_tls_local_session_active = 1;
    NX_CRYPTO_METHOD test_method;
    memset(&test_method, 0, sizeof(test_method));
    test_ciphersuite.nx_secure_tls_session_cipher = &test_method;
    test_method.nx_crypto_algorithm = 0;
    status = nx_packet_allocate(&pool_0, &send_packet, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);
    server_tls_session.nx_secure_tls_tcp_socket = &server_socket;
    tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
    status = _nx_secure_tls_send_record(&server_tls_session, send_packet, 0, NX_NO_WAIT);
    tx_mutex_put(&_nx_secure_tls_protection);
    nx_packet_release(send_packet);
    EXPECT_EQ(147, status);

    /* No space for certificate message's header. */
    status = nx_packet_allocate(&pool_0, &send_packet, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);
    /* No space left for certificate's length field. */
    send_packet -> nx_packet_append_ptr = send_packet -> nx_packet_data_end - 3;
    server_tls_session.nx_secure_tls_packet_pool = &pool_0;
    pool_0.nx_packet_pool_available = 0;
    /* Active certificate is set. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_active_certificate = &cert_1;
    status = _nx_secure_tls_send_certificate(&server_tls_session, send_packet, NX_NO_WAIT);
    EXPECT_EQ(NX_NO_PACKET, status);

    /* No space left for certificate's data. */
    cert_1.nx_secure_x509_certificate_raw_data = receive_buffer;
    cert_1.nx_secure_x509_certificate_raw_data_length = 2;
    send_packet -> nx_packet_append_ptr = send_packet -> nx_packet_data_end - 6;
    status = _nx_secure_tls_send_certificate(&server_tls_session, send_packet, NX_NO_WAIT);
    EXPECT_EQ(NX_NO_PACKET, status);

    /* Enough space for the certificate and the certificate is self-signed. */
    send_packet -> nx_packet_append_ptr = send_packet -> nx_packet_data_end - 8;
    memset(&cert_1.nx_secure_x509_distinguished_name, 0, sizeof(NX_SECURE_X509_DISTINGUISHED_NAME));
    memset(&cert_1.nx_secure_x509_issuer, 0, sizeof(NX_SECURE_X509_DISTINGUISHED_NAME));
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "cert";
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = 4;
    cert_1.nx_secure_x509_issuer.nx_secure_x509_common_name = "cert";
    cert_1.nx_secure_x509_issuer.nx_secure_x509_common_name_length = 4;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = &cert_1;
    status = _nx_secure_tls_send_certificate(&server_tls_session, send_packet, NX_NO_WAIT);
    EXPECT_EQ(NX_SUCCESS, status);
    nx_packet_release(send_packet);

    /* Unknown protocol version. */
    cert_1.nx_secure_x509_certificate_is_identity_cert = 1;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = &cert_1;
    server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    server_tls_session.nx_secure_tls_protocol_version = 0xff;
#ifndef NX_SECURE_DISABLE_X509
    test_crypto_table.nx_secure_tls_x509_cipher_table_size = 5;
#endif
    nx_secure_tls_local_certificate_add(&server_tls_session, &cert_1);
    status = _nx_secure_tls_send_certificate_verify(&server_tls_session, send_packet);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_TLS_VERSION, status);
#ifndef NX_SECURE_DISABLE_X509
    test_crypto_table.nx_secure_tls_x509_cipher_table_size = 1;
#endif

    status = _nx_secure_tls_finished_hash_generate(&server_tls_session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_TLS_VERSION, status);

    /* Process the same certificate raw data twice. */
    server_tls_session.nx_secure_public_cipher_metadata_area = server_crypto_metadata;
    server_tls_session.nx_secure_public_cipher_metadata_size = sizeof(NX_CRYPTO_RSA);
    /* Allocate space for the processed certificate. */
    nx_secure_tls_remote_certificate_allocate(&server_tls_session, &client_remote_certificate, client_remote_cert_buffer, sizeof(client_remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&server_tls_session, &client_remote_issuer, client_remote_issuer_buffer, sizeof(client_remote_issuer_buffer));
    _nx_secure_tls_process_remote_certificate(&server_tls_session, CertMsg, sizeof(CertMsg), 0);

    /* Tests for tls_generate_keys. */
    NX_CRYPTO_METHOD test_crypto_method, test_auth_method;
    /* Unknown crypto algorithm. */
    test_crypto_method.nx_crypto_algorithm = 0xff;
    test_auth_method.nx_crypto_algorithm = 0xff;
    test_ciphersuite.nx_secure_tls_public_cipher = &test_crypto_method;
    test_ciphersuite.nx_secure_tls_public_auth = &test_auth_method;
    status = _nx_secure_tls_generate_keys(&server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_CIPHER, status);

    /* Valid crypto algorithm. */
    test_crypto_method.nx_crypto_algorithm = TLS_CIPHER_RSA;
    /* Invalid protocol version. */
    server_tls_session.nx_secure_tls_protocol_version = 0xff;
    status = _nx_secure_tls_generate_keys(&server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_PROTOCOL_VERSION_CHANGED, status);

    /* Tests for _nx_secure_tls_record_payload_encrypt. */
    server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    test_ciphersuite.nx_secure_tls_session_cipher = &test_method;
    ULONG sequence_num[NX_SECURE_TLS_SEQUENCE_NUMBER_SIZE];
    UINT len;
    NX_PACKET _packet = { 0 };
    _packet.nx_packet_prepend_ptr = receive_buffer;
    _packet.nx_packet_append_ptr = receive_buffer;
    _packet.nx_packet_length = 0;
    _packet.nx_packet_next = NX_NULL;
    sequence_num[0] = 0;
    test_method.nx_crypto_operation = _crypto_operation_failed;
    server_tls_session.nx_secure_tls_session_ciphersuite = NX_NULL;
    status = _nx_secure_tls_record_payload_encrypt(&server_tls_session, &_packet, sequence_num, 0);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    UCHAR header[12];
    length = 12;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    test_crypto_table.nx_secure_tls_ciphersuite_lookup_table = &test_ciphersuite;
    test_crypto_table.nx_secure_tls_ciphersuite_lookup_table_size = 1;
    test_ciphersuite.nx_secure_tls_hash = &hash_method;
    hash_method.nx_crypto_operation = NX_NULL;
    /* sequence_number[0] == -1, need to add one to sequence_number[1]. */
    server_tls_session.nx_secure_tls_remote_sequence_number[0] = -1;
    _nx_secure_tls_verify_mac(&server_tls_session, header, 6, &_packet, 0, &length);

    /* Fail to allocate a packet for sending ServerHello. */
    /* Handshake header. */
    receive_buffer[0] = NX_SECURE_TLS_CLIENT_HELLO; /* message type. */
    /* message length. */
    receive_buffer[1] = 0;
    receive_buffer[2] = 0;
    receive_buffer[3] = 42;

    /* TLS version */
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    receive_buffer[4] = NX_SECURE_TLS_VERSION_TLS_1_2 >> 8;
    receive_buffer[5] = NX_SECURE_TLS_VERSION_TLS_1_2 & 0xff;
    /* SID length. */
    receive_buffer[38] = 0;
    /* ciphersuite list length. */
    receive_buffer[39] = 0;
    receive_buffer[40] = 2;
    /* ciphersuite field. */
    receive_buffer[41] = TLS_RSA_WITH_AES_128_CBC_SHA256 >> 8;
    receive_buffer[42] = TLS_RSA_WITH_AES_128_CBC_SHA256 & 0xff;
    /* Compression method length. */
    receive_buffer[43] = 1;
    /* NULL compression method. */
    receive_buffer[44] = 0;
    /* No packets left. */
    server_tls_session.nx_secure_tls_packet_pool = &pool_0;
    pool_0.nx_packet_pool_available = 0;
    server_tls_session.nx_secure_tls_tcp_socket = &server_socket;
    server_tls_session.nx_secure_tls_local_session_active = 0;
    server_tls_session.nx_secure_tls_crypto_table = &nx_crypto_tls_ciphers;
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 46, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);

    /* Certificate found but the certificate pointer is null. */
    store.nx_secure_x509_local_certificates = &cert_1;
    cert_1.nx_secure_x509_cert_identifier = 1;
    status = _nx_secure_x509_local_certificate_find(&store, NX_NULL, 1);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Certificate found but the certificate pointer is null. */
    store.nx_secure_x509_local_certificates = &cert_1;
    cert_1.nx_secure_x509_certificate_is_identity_cert = NX_TRUE;
    status = _nx_secure_x509_local_device_certificate_get(&store, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    server_tls_session.nx_secure_tls_local_session_active = 1;
    server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    test_crypto_table.nx_secure_tls_ciphersuite_lookup_table = &test_ciphersuite;
    test_crypto_table.nx_secure_tls_ciphersuite_lookup_table_size = 1;
    test_ciphersuite.nx_secure_tls_session_cipher = &hash_method;
    hash_method.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CBC;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    /* AES_CBC but protocol version is TlsV1.0 */
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_0;
    status = _nx_secure_tls_session_iv_size_get(&server_tls_session, &iv_size);
    EXPECT_EQ(NX_SUCCESS, status);

    /* crypto_init and crypto_operation are null. */
    server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    test_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &hash_method;
#endif
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    test_crypto_table.nx_secure_tls_handshake_hash_md5_method = &hash_method;
    test_crypto_table.nx_secure_tls_handshake_hash_sha1_method = &hash_method;
#endif
    hash_method.nx_crypto_init = NX_NULL;
    hash_method.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_handshake_hash_init(&server_tls_session);
    EXPECT_EQ(NX_SUCCESS, status);

    /* crypto_init and crypto_operation are null. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_0;
    status = _nx_secure_tls_handshake_hash_update(&server_tls_session, receive_buffer, 16);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);

    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_1;
    status = _nx_secure_tls_handshake_hash_update(&server_tls_session, receive_buffer, 16);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);

    server_tls_session.nx_secure_tls_protocol_version = 0xff;
    status = _nx_secure_tls_handshake_hash_update(&server_tls_session, receive_buffer, 16);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);
#endif

    {
#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
        ULONG available_size;
        USHORT tmp_nx_secure_tls_renegotation_enabled = server_tls_session.nx_secure_tls_renegotation_enabled;
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
        USHORT tmp_nx_secure_tls_ecc_supported_groups_count = server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count;
        UCHAR tmp_nx_secure_tls_local_session_active = server_tls_session.nx_secure_tls_local_session_active;
        USHORT tmp_nx_secure_tls_protocol_version = server_tls_session.nx_secure_tls_protocol_version;
#ifndef NX_SECURE_TLS_SNI_EXTENSION_DISABLED
        NX_SECURE_X509_DNS_NAME *tmp_nx_secure_tls_sni_extension_server_name = server_tls_session.nx_secure_tls_sni_extension_server_name;
#endif
#endif
        /* secure-reneg is not enabled. */
        server_tls_session.nx_secure_tls_renegotation_enabled = NX_FALSE;
        available_size = 0xFFFFFFFFUL;
        status = _nx_secure_tls_send_clienthello_extensions(&server_tls_session, receive_buffer, &bytes, &returned_length, available_size);
        EXPECT_EQ(NX_SUCCESS, status);

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
        /* Available size for sec spf extension not enough */
        available_size = 0;
        tmp_nx_secure_tls_ecc_supported_groups_count = server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count;
        server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 1;
        status = _nx_secure_tls_send_clienthello_extensions(&server_tls_session, receive_buffer, &bytes, &returned_length, available_size);
        EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

        /* No sec spf extension, available size for sec reneg extension is not enough case 1 */
        server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 0;
        available_size = 0;
        server_tls_session.nx_secure_tls_renegotation_enabled = NX_TRUE;
        status = _nx_secure_tls_send_clienthello_extensions(&server_tls_session, receive_buffer, &bytes, &returned_length, available_size);
        EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

        /* No sec spf extension, available size for sec reneg extension is not enough case 2 */
        server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 0;
        available_size = 2;
        server_tls_session.nx_secure_tls_renegotation_enabled = NX_TRUE;
        server_tls_session.nx_secure_tls_local_session_active = NX_TRUE;
        status = _nx_secure_tls_send_clienthello_extensions(&server_tls_session, receive_buffer, &bytes, &returned_length, available_size);
        EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

        /* No sec spf extension, available size for sec reneg extension is not enough case 3 */
        server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 0;
        available_size = 2;
        server_tls_session.nx_secure_tls_renegotation_enabled = NX_TRUE;
        server_tls_session.nx_secure_tls_local_session_active = NX_FALSE;
        status = _nx_secure_tls_send_clienthello_extensions(&server_tls_session, receive_buffer, &bytes, &returned_length, available_size);
        EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

        /* No sec spf, reneg extensions, available size for sig extension is not enough */
        server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 0;
        server_tls_session.nx_secure_tls_renegotation_enabled = NX_FALSE;
        server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
        available_size = 2;
        status = _nx_secure_tls_send_clienthello_extensions(&server_tls_session, receive_buffer, &bytes, &returned_length, available_size);
        EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

        /* No sec spf, no reneg extensions, sig entension is existed */
        server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 0;
        server_tls_session.nx_secure_tls_renegotation_enabled = NX_FALSE;
        server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
        available_size = 0xFFFFFFFFUL;
#ifndef NX_SECURE_DISABLE_X509
        test_crypto_table.nx_secure_tls_x509_cipher_table = _ntest_crypto_x509_cipher_lookup_table;
        test_crypto_table.nx_secure_tls_x509_cipher_table_size = sizeof(_ntest_crypto_x509_cipher_lookup_table)/sizeof(NX_SECURE_X509_CRYPTO);
#endif
        server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
        status = _nx_secure_tls_send_clienthello_extensions(&server_tls_session, receive_buffer, &bytes, &returned_length, available_size);
        EXPECT_EQ(NX_SUCCESS, status);

#ifndef NX_SECURE_TLS_SNI_EXTENSION_DISABLED
        /* No sec spf, no reneg extensions, no sig entension, available size for sni extension is not enough*/
        NX_SECURE_X509_DNS_NAME test_name;
        server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 0;
        server_tls_session.nx_secure_tls_renegotation_enabled = NX_FALSE;
        server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_0;
        if (server_tls_session.nx_secure_tls_sni_extension_server_name == NULL) {
            server_tls_session.nx_secure_tls_sni_extension_server_name = &test_name;
        }
        available_size = 0x8;
        status = _nx_secure_tls_send_clienthello_extensions(&server_tls_session, receive_buffer, &bytes, &returned_length, available_size);
        EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

        server_tls_session.nx_secure_tls_sni_extension_server_name = tmp_nx_secure_tls_sni_extension_server_name;
#endif /* NX_SECURE_TLS_SNI_EXTENSION_DISABLED */
        server_tls_session.nx_secure_tls_renegotation_enabled = tmp_nx_secure_tls_renegotation_enabled;
        server_tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = tmp_nx_secure_tls_ecc_supported_groups_count;
        server_tls_session.nx_secure_tls_local_session_active = tmp_nx_secure_tls_local_session_active;
        server_tls_session.nx_secure_tls_protocol_version = tmp_nx_secure_tls_protocol_version;
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */
#endif /* !NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION && !NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION*/
    }

#if (!defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) && !defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES))
    test_ciphersuite.nx_secure_tls_ciphersuite = 0xff;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    receive_buffer[0] = 0;
    receive_buffer[1] = 100;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = &cert_1;
    cert_1.nx_secure_x509_certificate_is_identity_cert = 1;
    cert_1.nx_secure_x509_private_key_type &= !NX_SECURE_X509_KEY_TYPE_USER_DEFINED_MASK;
    test_ciphersuite.nx_secure_tls_public_cipher = &hash_method;
    /* nx_crypto_algorithm != TLS_CIPHER_RSA */
    hash_method.nx_crypto_algorithm = 0xff;
    status = _nx_secure_tls_process_client_key_exchange(&server_tls_session, receive_buffer, 102, NX_SECURE_TLS);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_PUBLIC_CIPHER, status);

    /* nx_crypto_algorithm == TLS_CIPHER_RSA && nx_secure_x509_public_algorithm != NX_SECURE_TLS_X509_TYPE_RSA */
    hash_method.nx_crypto_algorithm = TLS_CIPHER_RSA;
    cert_1.nx_secure_x509_public_algorithm = 0xff;
    status = _nx_secure_tls_process_client_key_exchange(&server_tls_session, receive_buffer, 102, NX_SECURE_TLS);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_PUBLIC_CIPHER, status);

    /* nx_crypto_init ans nx_crypto_operation are null. */
    cert_1.nx_secure_x509_public_algorithm = NX_SECURE_TLS_X509_TYPE_RSA;
    hash_method.nx_crypto_init = NX_NULL;
    hash_method.nx_crypto_operation = NX_NULL;
    _nx_secure_tls_process_client_key_exchange(&server_tls_session, receive_buffer, 100, NX_SECURE_TLS);

#endif

#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
#ifndef NX_SECURE_ENABLE_DTLS
    test_ciphersuite.nx_secure_tls_ciphersuite = 0xff;
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_0;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = &cert_1;
    cert_1.nx_secure_x509_certificate_is_identity_cert = 1;
    cert_1.nx_secure_x509_private_key_type &= !NX_SECURE_X509_KEY_TYPE_USER_DEFINED_MASK;

    /* Invalid md5 and sha1 methods. */
    server_tls_session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_scratch = receive_buffer;
    server_tls_session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha1_metadata = receive_buffer;
    server_tls_session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_md5_metadata = receive_buffer;
    server_tls_session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha1_metadata_size = 1;
    server_tls_session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_md5_metadata_size = 1;
    test_crypto_table.nx_secure_tls_handshake_hash_sha1_method = &hash_method;
    test_crypto_table.nx_secure_tls_handshake_hash_md5_method = &hash_method;
    test_ciphersuite.nx_secure_tls_public_cipher = &hash_method;
    hash_method.nx_crypto_algorithm = 0xff;
    hash_method.nx_crypto_init = NX_NULL;
    hash_method.nx_crypto_operation = NX_NULL;
    npacket.nx_packet_append_ptr = receive_buffer;
    npacket.nx_packet_length = 0;
#if 0
    _nx_secure_tls_send_certificate_verify(&server_tls_session, &npacket);
#endif

    /* Invalid public cipher method. */
    test_ciphersuite.nx_secure_tls_public_cipher = &hash_method;
    cert_1.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = 40;
    hash_method.nx_crypto_algorithm = TLS_CIPHER_RSA;
    cert_1.nx_secure_x509_public_algorithm == NX_SECURE_TLS_X509_TYPE_RSA;
#if 0
    _nx_secure_tls_send_certificate_verify(&server_tls_session, &npacket);
#endif

    /* prf_1_method is NX_NULL. */
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_0;
    hash_method.nx_crypto_algorithm = TLS_CIPHER_RSA;
    test_crypto_table.nx_secure_tls_prf_1_method = NX_NULL;
    status = _nx_secure_tls_generate_keys(&server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_PROTOCOL_VERSION_CHANGED, status);

    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_0;
    status = _nx_secure_tls_finished_hash_generate(&server_tls_session, "server finished", receive_buffer);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);
#endif
#endif

    /* compare value != 0 */
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    test_ciphersuite.nx_secure_tls_prf = &hash_method;
    hash_method.nx_crypto_init = _bad_crypto_init1;
    hash_method.nx_crypto_operation = _bad_crypto_operation1;
    server_tls_session.nx_secure_tls_remote_session_active = 1;
    server_tls_session.nx_secure_tls_received_remote_credentials = 1;
    status = _nx_secure_tls_process_finished(&server_tls_session, receive_buffer, NX_SECURE_TLS_FINISHED_HASH_SIZE);
    EXPECT_EQ(NX_SECURE_TLS_FINISHED_HASH_FAILURE, status);

    /* tls_remote_certificate_free_all fails. */
    server_socket.nx_tcp_socket_client_type = 0;
    store_ptr = &server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store;
    store_ptr -> nx_secure_x509_remote_certificates = &cert_1;
    store_ptr -> nx_secure_x509_free_certificates = &cert_1;
    cert_1.nx_secure_x509_cert_identifier = 0;
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "hello";
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = 5;
    status = _nx_secure_tls_session_start(&server_tls_session, &server_socket, NX_NO_WAIT);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    server_tls_session.nx_secure_record_queue_header = NX_NULL;
    server_tls_session.nx_secure_record_decrypted_packet = NX_NULL;
    /* send_close_notify = 1 */
    server_tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    server_tls_session.nx_secure_tls_server_state = NX_SECURE_TLS_SERVER_STATE_HANDSHAKE_FINISHED;
    /* tls_remote_certificate_free_all fails. */
    status = _nx_secure_tls_session_end(&server_tls_session, NX_NO_WAIT);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    server_tls_session.nx_secure_record_queue_header = NX_NULL;
    server_tls_session.nx_secure_record_decrypted_packet = NX_NULL;
    /* send_close_notify = 1 */
    server_tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    server_tls_session.nx_secure_tls_server_state = NX_SECURE_TLS_SERVER_STATE_HANDSHAKE_FINISHED;
    server_tls_session.nx_secure_tls_packet_pool = &pool_0;
    pool_0.nx_packet_pool_available = 10;
    server_socket.nx_tcp_socket_client_type = 0;
    store_ptr = &server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store;
    store_ptr -> nx_secure_x509_remote_certificates = &cert_1;
    store_ptr -> nx_secure_x509_free_certificates = &cert_1;
    /* tls_remote_certificate_free_all fails. */
    status = _nx_secure_tls_session_end(&server_tls_session, NX_NO_WAIT);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    /* Cannot find certificate list. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = NX_NULL;
    status = _nx_secure_tls_remote_certificate_free(&server_tls_session, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    /* Find dulplicated free certificate. */
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "cert1";
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = strlen("cert1");
    cert_1.nx_secure_x509_cert_identifier = 1;
    cert_1.nx_secure_x509_user_allocated_cert = 1;
    cert_1.nx_secure_x509_next_certificate = NX_NULL;
    test_cert = cert_1;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert_1;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = &test_cert;
    status = _nx_secure_tls_remote_certificate_free(&server_tls_session, &cert_1.nx_secure_x509_distinguished_name);
    EXPECT_EQ(NX_SECURE_TLS_CERT_ID_DUPLICATE, status);

    /* One certificate exists in both remote and free list. */
    cert_1.nx_secure_x509_cert_identifier = 0;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert_1;
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = &cert_1;
    status = _nx_secure_tls_remote_certificate_free_all(&server_tls_session);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* remote_certificate_endpoint_get failed. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = NX_NULL;
    status = _nx_secure_tls_remote_certificate_verify(&server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_NO_CERT_SPACE_ALLOCATED, status);

    /* certificate_chain_verify cannot find issuer certificate. */
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert_1;
    cert_1.nx_secure_x509_next_certificate = NX_NULL;
    status = _nx_secure_tls_remote_certificate_verify(&server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_ISSUER_CERTIFICATE_NOT_FOUND, status);

    /* expiration_check failed. */
    server_tls_session.nx_secure_tls_session_time_function = _session_time_function;
    cert_1.nx_secure_x509_validity_format = NX_SECURE_ASN_TAG_GENERALIZED_TIME;
    status = _nx_secure_tls_remote_certificate_verify(&server_tls_session);
    EXPECT_EQ(NX_SECURE_X509_INVALID_DATE_FORMAT, status);

    certificate.nx_secure_x509_validity_format = 0xff;
    status = _nx_secure_tls_remote_certificate_verify(&server_tls_session);
    EXPECT_EQ(NX_SECURE_X509_INVALID_DATE_FORMAT, status);

    /* Unsupported public cipher. */
    NX_SECURE_TLS_SESSION   test_server_tls_session;
    memset(&test_server_tls_session, 0, sizeof(NX_SECURE_TLS_SESSION));
    nx_secure_tls_test_init_functions(&test_server_tls_session);

    const NX_CRYPTO_METHOD tmp_nx_secure_x509_hash_method = {0};

    /* Add an unsupppported public cipher */
    NX_SECURE_X509_CRYPTO test_x509_cipher_table[] =
    {
        /* OID identifier,                        public cipher,            hash method */
        {NX_SECURE_TLS_X509_TYPE_DH,           &crypto_method_auth_psk,    &tmp_nx_secure_x509_hash_method},
    };

    /* add a remote cert */
    test_server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert_1;
    test_server_tls_session.nx_secure_public_cipher_metadata_area = server_crypto_metadata;
    test_server_tls_session.nx_secure_public_cipher_metadata_size = sizeof(server_crypto_metadata);
    
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "cert1";
    cert_1.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = strlen("cert1");
    cert_1.nx_secure_x509_cert_identifier = 1;
    cert_1.nx_secure_x509_user_allocated_cert = 1;
    cert_1.nx_secure_x509_next_certificate = NX_NULL;
    cert_1.nx_secure_x509_cipher_table = test_x509_cipher_table;
    cert_1.nx_secure_x509_cipher_table_size = 1;
    cert_1.nx_secure_x509_signature_algorithm = NX_SECURE_TLS_X509_TYPE_DH;

    /* add an issuer cert */
    cert_1.nx_secure_x509_issuer.nx_secure_x509_common_name = "cert1";
    cert_1.nx_secure_x509_issuer.nx_secure_x509_common_name_length = strlen("cert1");
    server_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_trusted_certificates = &cert_1;
    status = _nx_secure_tls_remote_certificate_verify(&test_server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_PUBLIC_CIPHER, status);

    /* UNKNOWN CERT SIG ALGORITHM */
    cert_1.nx_secure_x509_cipher_table_size = 0;
    status = _nx_secure_tls_remote_certificate_verify(&test_server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CERT_SIG_ALGORITHM, status);

    /* NX_SECURE_X509_CERTIFICATE_SIG_CHECK_FAILED */
    const NX_CRYPTO_METHOD tmp_pub_cipher_method_ecc =
    {
        NX_CRYPTO_DIGITAL_SIGNATURE_ECDSA,           /* ECDSA crypto algorithm                 */
        0,                                           /* Key size in bits                       */
        0,                                           /* IV size in bits                        */
        0,                                           /* ICV size in bits, not used             */
        0,                                           /* Block size in bytes                    */
        sizeof(NX_CRYPTO_ECDSA),                     /* Metadata size in bytes                 */
        _nx_crypto_method_ecdsa_init,                /* ECDSA initialization routine           */
        NX_CRYPTO_NULL,                              /* ECDSA cleanup routine                  */
        _nx_crypto_method_ecdsa_operation            /* ECDSA operation                        */
    };

    NX_SECURE_X509_CRYPTO test_x509_cipher_table_2[] =
    {
        /* OID identifier,                        public cipher,            hash method */
        {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256,  &tmp_pub_cipher_method_ecc,     &tmp_nx_secure_x509_hash_method},
    };
    cert_1.nx_secure_x509_cipher_table = test_x509_cipher_table_2;
    cert_1.nx_secure_x509_cipher_table_size = 1;
    cert_1.nx_secure_x509_signature_algorithm = NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256;

    cert_1.nx_secure_x509_public_algorithm = NX_SECURE_TLS_X509_TYPE_EC;
    cert_1.nx_secure_x509_public_key.ec_public_key.nx_secure_ec_named_curve = NX_CRYPTO_EC_SECP256R1;
    /* ecc initialization */
    extern const USHORT nx_crypto_ecc_supported_groups[];
    extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
    extern const UINT nx_crypto_ecc_supported_groups_size;

    status = _nx_secure_tls_ecc_initialize(&test_server_tls_session, nx_crypto_ecc_supported_groups, nx_crypto_ecc_supported_groups_size, nx_crypto_ecc_curves);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_remote_certificate_verify(&test_server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_SIG_CHECK_FAILED, status);

    /* NX_SECURE_X509_MISSING_CRYPTO_ROUTINE */
    const NX_CRYPTO_METHOD tmp_pub_cipher_method_ecc_2 =
    {
        NX_CRYPTO_DIGITAL_SIGNATURE_ECDSA,           /* ECDSA crypto algorithm                 */
        0,                                           /* Key size in bits                       */
        0,                                           /* IV size in bits                        */
        0,                                           /* ICV size in bits, not used             */
        0,                                           /* Block size in bytes                    */
        sizeof(NX_CRYPTO_ECDSA),                     /* Metadata size in bytes                 */
        _nx_crypto_method_ecdsa_init,                /* ECDSA initialization routine           */
        NX_CRYPTO_NULL,                              /* ECDSA cleanup routine                  */
        NX_CRYPTO_NULL                               /* ECDSA operation                        */
    };
    NX_SECURE_X509_CRYPTO test_x509_cipher_table_3[] =
    {
        /* OID identifier,                        public cipher,            hash method */
        {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256,  &tmp_pub_cipher_method_ecc_2,     &tmp_nx_secure_x509_hash_method},
    };
    cert_1.nx_secure_x509_cipher_table = test_x509_cipher_table_3;
    status = _nx_secure_tls_remote_certificate_verify(&test_server_tls_session);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */

    /* nx_secure_tls_protocol_check. */
    /* Protocol version changed. */
    server_tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    status = _nx_secure_tls_check_protocol_version(&server_tls_session, NX_SECURE_TLS_VERSION_TLS_1_1, 0);
    EXPECT_EQ(NX_SECURE_TLS_PROTOCOL_VERSION_CHANGED, status);

    /* Different from the overrided protocol version. */
    server_tls_session.nx_secure_tls_protocol_version = 0;
    server_tls_session.nx_secure_tls_protocol_version_override = NX_SECURE_TLS_VERSION_TLS_1_2;
    status = _nx_secure_tls_check_protocol_version(&server_tls_session, NX_SECURE_TLS_VERSION_TLS_1_1, 0);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_TLS_VERSION, status);

    /* Unknown tls protocol verison. */
    server_tls_session.nx_secure_tls_protocol_version = 0;
    server_tls_session.nx_secure_tls_protocol_version_override = 0;
    status = _nx_secure_tls_check_protocol_version(&server_tls_session, 0xffff, 0);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_TLS_VERSION, status);

#ifndef NX_SECURE_TLS_CLIENT_DISABLED
    /* Unknown tls protocol verison. */
    client_tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    client_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    client_tls_session.nx_secure_tls_protocol_version_override = 0;
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVERHELLO_DONE;
    status = _nx_secure_tls_check_protocol_version(&client_tls_session, 0xffff, 0);
    EXPECT_EQ(NX_SECURE_TLS_PROTOCOL_VERSION_CHANGED, status);
#endif

#ifndef NX_SECURE_TLS_ENABLE_TLS_1_0
    /* Make sure that tlsV1.0 is unsupported. */
    server_tls_session.nx_secure_tls_protocol_version = 0;
    server_tls_session.nx_secure_tls_protocol_version_override = 0;
    status = _nx_secure_tls_check_protocol_version(&server_tls_session, NX_SECURE_TLS_VERSION_TLS_1_0, 0);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_TLS_VERSION, status);
#endif

    dns_name.nx_secure_x509_dns_name_length = NX_SECURE_X509_DNS_NAME_MAX + 1;
    status = _nx_secure_x509_dns_name_initialize(&dns_name, "test_name", sizeof("test_name"));
    EXPECT_EQ(NX_SECURE_X509_SUCCESS, status);
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
UINT i, bytes_processed, alert_number, alert_level;
NX_SECURE_X509_DNS_NAME dns_name;
NX_SECURE_X509_CERT cert;
USHORT protocol_version;
USHORT ushort;

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

    /* Try to cover all branches in client handshake. */
#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) && defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    client_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[3];
#else
    client_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[1];
#endif
    receive_buffer[0] = NX_SECURE_TLS_SERVER_KEY_EXCHANGE; /* Invalid message type. */
    /* Set message length as zero */
    receive_buffer[1] = 0;
    receive_buffer[2] = 0;
    receive_buffer[3] = 0;

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_HELLO_VERIFY; /* Invalid client session state. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_IDLE; /* the client session state to do nothing. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_ALERT_SENT; /* the client session state to return error number. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVER_KEY_EXCHANGE; /* the client session state to return error number. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    /* error occurrs in renegotiation callback. */
    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_renegotation_enabled = 1;
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_HELLO_REQUEST;
    client_tls_session.nx_secure_tls_session_renegotiation_callback = _failed_renegotiation_callback;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    /* no error occurrs in renegotiation callback, but fails to allocate a packet. */
    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_renegotation_enabled = 1;
    client_tls_session.nx_secure_tls_packet_pool = &pool_0;
    pool_0.nx_packet_pool_available = 0;
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_HELLO_REQUEST;
    client_tls_session.nx_secure_tls_session_renegotiation_callback = _passed_renegotiation_callback;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    /* Received HelloRequest while current session is active but renegotiation is no enabled. */
    receive_buffer[0] = NX_SECURE_TLS_HELLO_REQUEST; /* Invalid message type. */
    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_renegotation_enabled = 0;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_NO_RENEGOTIATION_ERROR, status);

    /* Received HelloRequest while current session is inactive. */
    client_tls_session.nx_secure_tls_local_session_active = 0;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_HANDSHAKE_FAILURE, status);

    /* Renegotiation is not enabled but client state is NX_SECURE_TLS_SERVER_KEY_EXCHANGE. */
    receive_buffer[0] = NX_SECURE_TLS_SERVER_KEY_EXCHANGE;
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_HELLO_REQUEST;
    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_renegotation_enabled = 0;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);
#endif

    /* Current session is inactive and client state is NX_SECURE_TLS_CLIENT_STATE_HELLO_REQUEST. */
    receive_buffer[0] = NX_SECURE_TLS_SERVER_KEY_EXCHANGE;
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_HELLO_REQUEST;
    client_tls_session.nx_secure_tls_local_session_active = 0;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    /* Client certificate is requested but unable to allocate a packet. */
    client_tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVERHELLO_DONE;
    client_tls_session.nx_secure_tls_client_certificate_requested = 1;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    /* Succeed in _nx_secure_tls_generate_premaster_secret but unable to allocate a packet. */
    client_tls_session.nx_secure_tls_client_certificate_requested = 0;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

#if 0
    /* _nx_secure_tls_generate_premaster_secret failed. */
    client_tls_session.nx_secure_tls_session_ciphersuite = 0x0;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);
#endif

    /* Incorrect message length. */
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 0);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* Invalid protocol version. */
    receive_buffer[0] = 0xff;
    receive_buffer[1] = 0xff;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 38);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_TLS_VERSION, status);

    /* Specify a valid protocol version. */
    receive_buffer[0] = NX_SECURE_TLS_VERSION_TLS_1_2 >> 8;
    receive_buffer[1] = NX_SECURE_TLS_VERSION_TLS_1_2 & 0xff;
    /* Set session id length as zero. */
    receive_buffer[34] = 0;
    /* Invalid ciphersuite. */
    receive_buffer[35] = 0xff;
    receive_buffer[36] = 0xff;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 38);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    receive_buffer[35] = (UCHAR)(TLS_RSA_WITH_AES_128_CBC_SHA256 >> 8);
    receive_buffer[36] = (UCHAR)(TLS_RSA_WITH_AES_128_CBC_SHA256 & 0xff);
    /* Bad compression method. */
    receive_buffer[37] = 0x01;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 38);
    EXPECT_EQ(NX_SECURE_TLS_BAD_COMPRESSION_METHOD, status);

    receive_buffer[37] = 0x0;
    /* No extensions. */
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 38);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Incorrect extension length. */
    receive_buffer[38] = 0x0;
    receive_buffer[39] = 0x10;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 40);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* Zero bytes extensions. */
    receive_buffer[39] = 0x0;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 40);
    EXPECT_EQ(NX_SUCCESS, status);

#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    /* An invalid reneg extension. */
    receive_buffer[39] = 0x06;
    /* The extension id of renegotiation. */
    receive_buffer[40] = 0xff;
    receive_buffer[41] = 0x01;
    /* The length of this extension. */
    receive_buffer[42] = 0x0;
    receive_buffer[43] = 0x02;
    /* Incorrect renegotiation connection length. */
    receive_buffer[44] = 0x0;
    /* No verify data in initial ServerHello. */
    receive_buffer[45] = 0x0;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 46);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    /* Verify data exists. */
    receive_buffer[39] = 0x1d;
    receive_buffer[43] = 0x19;
    /* 12 bytes verify data. */
    receive_buffer[44] = 0x18;
    /* Renegotiation flag is not set. */
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 69);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    /* Renegotiation flag is set but local session is inactive. */
    client_tls_session.nx_secure_tls_local_session_active = 0;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 69);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    client_tls_session.nx_secure_tls_local_session_active = 1;
    /* Incorrect renegotiated connection length. */
    receive_buffer[38] = 0x01;
    receive_buffer[39] = 0x04;
    receive_buffer[42] = 0x01;
    receive_buffer[43] = 0x00;
    receive_buffer[44] = 0xff;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 300);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    receive_buffer[38] = 0x0;
    receive_buffer[39] = 0x1d;
    receive_buffer[42] = 0x00;
    receive_buffer[43] = 0x19;
    receive_buffer[44] = 0x18;
    /* Local verification failed. */
    receive_buffer[45] = 0x01;
    client_tls_session.nx_secure_tls_local_verify_data[0] = 0x0;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 69);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    /* Local verification succeeded but remote verification failed. */
    memset(receive_buffer + 45, 0, NX_SECURE_TLS_FINISHED_HASH_SIZE);
    memset(client_tls_session.nx_secure_tls_local_verify_data, 0, NX_SECURE_TLS_FINISHED_HASH_SIZE);
    receive_buffer[45 + NX_SECURE_TLS_FINISHED_HASH_SIZE] = 0x01;
    client_tls_session.nx_secure_tls_remote_verify_data[0] = 0x0;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 69);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    /* Received an empty reng extension while the local session is active. */
    receive_buffer[38] = 0x0;
    receive_buffer[39] = 0x5;
    receive_buffer[42] = 0x0;
    receive_buffer[43] = 0x01;
    receive_buffer[44] = 0x0;
    client_tls_session.nx_secure_tls_local_session_active = 1;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 45);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    client_tls_session.nx_secure_tls_local_session_active = 0;
    /* User defined callback failed while process ServerHello. */
    client_tls_session.nx_secure_tls_session_client_callback = _failed_server_callback;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, receive_buffer, 45);
    EXPECT_EQ(NX_SECURE_TLS_HANDSHAKE_FAILURE, status);

    /* tls_remote_certificate_free_all fails while processing TLS_HELLO_REQUEST. */
    receive_buffer[0] = NX_SECURE_TLS_HELLO_REQUEST;
    receive_buffer[1] = 0;
    receive_buffer[2] = 0;
    receive_buffer[3] = 0;
    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_renegotation_enabled = 1;

    /* One certificate exists in both remote and free list. */
    cert.nx_secure_x509_cert_identifier = 0;
    cert.nx_secure_x509_user_allocated_cert = 1;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = &cert;
    cert.nx_secure_x509_distinguished_name.nx_secure_x509_common_name = "cert1";
    cert.nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length = strlen("cert1");
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);
#endif

    /* Invalid message type. */
    nx_secure_tls_session_delete(&client_tls_session);
    nx_secure_tls_session_create(&client_tls_session,
                                 &nx_crypto_tls_ciphers,
                                 client_crypto_metadata,
                                 sizeof(client_crypto_metadata));
    receive_buffer[0] = NX_SECURE_TLS_HELLO_VERIFY_REQUEST;
    receive_buffer[1] = 0;
    receive_buffer[2] = 0;
    receive_buffer[3] = 0;
    client_tls_session.nx_secure_tls_packet_pool = &pool_1;
    client_tls_session.nx_secure_tls_tcp_socket = &client_socket;
    ip_1.nx_ip_interface[1].nx_interface_link_up = NX_FALSE;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    ip_1.nx_ip_interface[1].nx_interface_link_up = NX_TRUE;
    EXPECT_EQ(NX_SECURE_TLS_HANDSHAKE_FAILURE, status);

    /* tls_send_certificate failed. */
    receive_buffer[0] = NX_SECURE_TLS_SERVER_HELLO_DONE;
    receive_buffer[1] = 0;
    receive_buffer[2] = 0;
    receive_buffer[3] = 0;
    client_tls_session.nx_secure_tls_client_certificate_requested = 1;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = NX_NULL;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    /* Fail to send certificates. */
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_active_certificate = &client_certificate;
    ip_1.nx_ip_interface[1].nx_interface_link_up = NX_FALSE;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 4/* Only one header */, NX_NO_WAIT);
    ip_1.nx_ip_interface[1].nx_interface_link_up = NX_TRUE;
    EXPECT_EQ(NX_NOT_BOUND, status);

    /* No local device certificates found while sending certificate verify. */
#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) && defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    client_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[3];
#else
    client_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[1];
#endif
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = NX_NULL;
    status = _nx_secure_tls_send_certificate_verify(&client_tls_session, send_packet);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    /* tls_remote_certificate_free_all fail in tls_process_clienthello. */
    client_tls_session.nx_secure_tls_local_session_active = 1;
#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    client_tls_session.nx_secure_tls_renegotation_enabled = 1;
    client_tls_session.nx_secure_tls_secure_renegotiation = 1;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = &cert;
    status = _nx_secure_tls_process_clienthello(&client_tls_session, NX_NULL, 38);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* tls_remote_certificate_free_all fail in tls_session_renegotiate. */
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_free_certificates = &cert;
    client_tls_session.nx_secure_tls_renegotation_enabled = 1;
    client_tls_session.nx_secure_tls_secure_renegotiation = 1;
    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_remote_session_active = 1;
    client_tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    status = nx_secure_tls_session_renegotiate(&client_tls_session, NX_NO_WAIT);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);
#endif

    /* x509_remote_endpoint_certificate_get failed. */
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = NX_NULL;
    status = _nx_secure_tls_send_client_key_exchange(&client_tls_session, &unused_packet);
    EXPECT_EQ(NX_SECURE_TLS_NO_CERT_SPACE_ALLOCATED, status);

#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    NX_SECURE_TLS_HELLO_EXTENSION extensions;
    UINT num = NX_SECURE_TLS_HELLO_EXTENSIONS_MAX;
    /* the id the renegotiation extension. */
    receive_buffer[0] = NX_SECURE_TLS_EXTENSION_SECURE_RENEGOTIATION >> 8;
    receive_buffer[1] = NX_SECURE_TLS_EXTENSION_SECURE_RENEGOTIATION & 0xff;
    receive_buffer[2] = 0;
    receive_buffer[3] = 2;
    /* Renegotiated connection length. */
    receive_buffer[4] = 1;
    client_tls_session.nx_secure_tls_local_session_active = 1;
    /* Remote tls session is inactive. */
    client_tls_session.nx_secure_tls_remote_session_active = 0;
    status = _nx_secure_tls_process_clienthello_extensions(&client_tls_session, receive_buffer, 6, &extensions, &num, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_SESSION_INACTIVE, status);

    /* Received renegotiation extensions while the flag of renegotiation is not set. */
    client_tls_session.nx_secure_tls_remote_session_active = 1;
    client_tls_session.nx_secure_tls_secure_renegotiation = 0;
    num = NX_SECURE_TLS_HELLO_EXTENSIONS_MAX;
    status = _nx_secure_tls_process_clienthello_extensions(&client_tls_session, receive_buffer, 6, &extensions, &num, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_FAILURE, status);
#endif

    /* Invalid tag NX_SECURE_ASN_TAG_CLASS_CONTEXT + NX_SECURE_ASN_TAG_SEQUENCE. */
    receive_buffer[0] = 0x90;
    /* tlv_length. */
    receive_buffer[1] = 0x1;
    status = _nx_secure_x509_pkcs1_rsa_private_key_parse(receive_buffer, 255, &bytes_processed, NX_NULL);
    EXPECT_EQ(NX_SECURE_X509_INVALID_CERTIFICATE_SEQUENCE, status);

    status = _nx_secure_x509_certificate_parse(NX_NULL, 0, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)

    /* Attempt to override the protocol version as 1.3 while 1.3 is unsupported. */
    client_tls_session.nx_secure_tls_1_3_supported = 0;
    status = _nx_secure_tls_session_protocol_version_override(&client_tls_session, NX_SECURE_TLS_VERSION_TLS_1_3);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_TLS_VERSION, status);

    /* Override the protocol version as 1.3. */
    client_tls_session.nx_secure_tls_1_3_supported = 1;
    _nx_secure_tls_session_protocol_version_override(&client_tls_session, NX_SECURE_TLS_VERSION_TLS_1_3);
    EXPECT_EQ(client_tls_session.nx_secure_tls_protocol_version_override, NX_SECURE_TLS_VERSION_TLS_1_2);

    status = _nx_secure_tls_1_3_crypto_init(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);
#endif

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)

    /* Too much psks to add. */
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_psk_count = NX_SECURE_TLS_MAX_PSK_KEYS;
    status = _nx_secure_tls_psk_add(&client_tls_session, NX_NULL, 0, NX_NULL, 0, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_NO_MORE_PSK_SPACE, status);
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_psk_count = 0;

    /* Not enough space for new psk. */
    status = _nx_secure_tls_psk_add(&client_tls_session, NX_NULL, NX_SECURE_TLS_MAX_PSK_SIZE + 1 , NX_NULL, 0, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_NO_MORE_PSK_SPACE, status);

    /* Not enough space for new identity. */
    status = _nx_secure_tls_psk_add(&client_tls_session, NX_NULL, 0 , NX_NULL, NX_SECURE_TLS_MAX_PSK_ID_SIZE + 1, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_NO_MORE_PSK_SPACE, status);
#endif

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES)

    /* Not enough space for new psk. */
    status = _nx_secure_tls_client_psk_set(&client_tls_session, NX_NULL, NX_SECURE_TLS_MAX_PSK_SIZE + 1, NX_NULL, 0, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_NO_MORE_PSK_SPACE, status);

    /* Not enough space for new identity. */
    status = _nx_secure_tls_client_psk_set(&client_tls_session, NX_NULL, 0, NX_NULL, NX_SECURE_TLS_MAX_PSK_ID_SIZE + 1, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_NO_MORE_PSK_SPACE, status);

    /* Not enough space for new hint. */
    status = _nx_secure_tls_client_psk_set(&client_tls_session, NX_NULL, 0, NX_NULL, 0, NX_NULL, NX_SECURE_TLS_MAX_PSK_ID_SIZE + 1);
    EXPECT_EQ(NX_SECURE_TLS_NO_MORE_PSK_SPACE, status);
#endif

    /* tls_session_ciphersuite is NULL. */
    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_session_ciphersuite = NX_NULL;
    status = _nx_secure_tls_session_iv_size_get(&client_tls_session, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    /* Tests for error mapping. */
    _nx_secure_tls_map_error_to_alert(NX_SECURE_TLS_MISSING_EXTENSION, &alert_number, &alert_level);
    EXPECT_EQ(NX_SECURE_TLS_ALERT_MISSING_EXTENSION, alert_number);
    EXPECT_EQ(NX_SECURE_TLS_ALERT_LEVEL_FATAL, alert_level);

    _nx_secure_tls_map_error_to_alert(NX_SECURE_TLS_CERTIFICATE_REQUIRED, &alert_number, &alert_level);
    EXPECT_EQ(NX_SECURE_TLS_ALERT_CERTIFICATE_REQUIRED, alert_number);
    EXPECT_EQ(NX_SECURE_TLS_ALERT_LEVEL_FATAL, alert_level);

    /* packet_ptr is NULL. */
    status = _nx_secure_tls_process_header(NX_NULL, NX_NULL, 0, NX_NULL, NX_NULL, NX_NULL, &ushort);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    /* nx_packet_data_extract_offset fails. */
    memset(&unused_packet, 0, sizeof(unused_packet));
    unused_packet.nx_packet_length = 0;
    status = _nx_secure_tls_process_header(NX_NULL, &unused_packet, 5, NX_NULL, NX_NULL, NX_NULL, &ushort);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    /* Not enough packet buffer for total extension length field. */
    status = _nx_secure_tls_send_serverhello_extensions(&client_tls_session, receive_buffer, &bytes, 0);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
    /* Not enough packet buffer for renegotiation extension length field. */
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    client_tls_session.nx_secure_tls_1_3 = 0;
#endif /* if (NX_SECURE_TLS_TLS_1_3_ENABLED) */
    status = _nx_secure_tls_send_serverhello_extensions(&client_tls_session, receive_buffer, &bytes, 2);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)

    /* ciphersuite is null. */
    client_tls_session.nx_secure_tls_1_3 = 1;
    client_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    test_crypto_table.nx_secure_tls_ecdhe_method = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(client_tls_session.nx_secure_tls_session_ciphersuite, client_tls_session.nx_secure_tls_protocol_version,
                                              client_tls_session.nx_secure_tls_1_3, client_tls_session.nx_secure_tls_crypto_table,
                                              &client_tls_session.nx_secure_tls_handshake_hash, &client_tls_session.nx_secure_tls_ecc, &client_tls_session.nx_secure_tls_key_material,
                                              &client_tls_session.nx_secure_tls_credentials, 0, 0, NX_NULL, NX_NULL, NX_NULL,
                                              client_tls_session.nx_secure_public_cipher_metadata_area,
                                              client_tls_session.nx_secure_public_cipher_metadata_size,
                                              client_tls_session.nx_secure_public_auth_metadata_area,
                                              client_tls_session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);
#endif /* if (NX_SECURE_TLS_TLS_1_3_ENABLED) */

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) || \
   (defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && !defined(NX_SECURE_TLS_CLIENT_DISABLED))
    client_tls_session.nx_secure_tls_session_ciphersuite = NX_NULL;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);
#endif

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    client_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    test_ciphersuite.nx_secure_tls_public_auth = &crypto_method_auth_psk;
    receive_buffer[0] = 1;
    status = _nx_secure_tls_process_server_key_exchange(&client_tls_session, receive_buffer, 0);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */

#ifndef NX_SECURE_POWER_ON_SELF_TEST_MODULE_INTEGRITY_CHECK
    nx_secure_module_hash_compute(NX_NULL, 0, 0, NX_NULL, 0, NX_NULL, 0, NX_NULL, 0, NX_NULL);
#endif /* NX_SECURE_POWER_ON_SELF_TEST_MODULE_INTEGRITY_CHECK */

    nx_secure_tls_session_delete(&client_tls_session);
    client_tls_session.nx_secure_tls_crypto_table = NX_NULL;
    status = _nx_secure_tls_session_create_ext(&client_tls_session,
                                               NX_NULL, 0, NX_NULL, 0,
                                               client_crypto_metadata,
                                               sizeof(client_crypto_metadata));
    EXPECT_EQ(NX_PTR_ERROR, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Coverage Test..................................N/A\n");
    test_control_return(3);
}
#endif
