/* This test concentrates on ClientHello message processing - this tests whether unrecognized
   cipher suites and extensions are ignored properly.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"
#include   "test_ca_cert.c"
#include   "tls_two_test_certs.c"
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
#include   "ecc_certs.c"
#endif

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define SERVER_PORT                 4433

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static TX_THREAD                thread_1;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static UINT                     error_counter;

static NX_TCP_SOCKET            client_socket_0;
static NX_TCP_SOCKET            server_socket_0;
static NX_SECURE_TLS_SESSION    tls_server_session_0;
static NX_SECURE_X509_CERT      server_trusted_ca;
static NX_SECURE_X509_CERT      server_local_certificate;
static NX_SECURE_X509_CERT      ica_certificate;
extern const NX_SECURE_TLS_CRYPTO
                                nx_crypto_tls_ciphers;

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_1_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];

static UCHAR                    tls_packet_buffer[4000];

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;
#endif


/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */


static VOID _error_print(char *file, unsigned int line)
{
    printf("Error at %s:%d\n", file, line);
    error_counter++;
}
#define ERROR_COUNTER() _error_print(__FILE__, __LINE__);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_unrecognized_ciphersuite_test_application_define(void *first_unused_memory)
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

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
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
                                                   ECTestServer2_key_der_len, NX_SECURE_X509_KEY_TYPE_EC_DER);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_server_certificate_add(tls_session_ptr,
                                                  &server_local_certificate, 1);
    if (status)
    {
        ERROR_COUNTER();
    }


    status = nx_secure_x509_certificate_initialize(&server_trusted_ca,
                                                   ECCA2_der,
                                                   ECCA2_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &server_trusted_ca);
    if (status)
    {
        ERROR_COUNTER();
    }

#else
    status = nx_secure_tls_session_create(tls_session_ptr,
                                          &nx_crypto_tls_ciphers,
                                          server_metadata,
                                          sizeof(server_metadata));
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   test_server_cert_der, test_server_cert_der_len,
                                                   NX_NULL, 0, test_server_cert_key_der,
                                                   test_server_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_server_certificate_add(tls_session_ptr,
                                                 &server_local_certificate, 1);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_x509_certificate_initialize(&ica_certificate,
                                                   ica_cert_der, ica_cert_der_len,
                                                   NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_local_certificate_add(tls_session_ptr, &ica_certificate);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_x509_certificate_initialize(&server_trusted_ca,
                                                   test_ca_cert_der,
                                                   test_ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &server_trusted_ca);
    if (status)
    {
        ERROR_COUNTER();
    }
#endif

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer,
                                                     sizeof(tls_packet_buffer));
    if (status)
    {
        ERROR_COUNTER();
    }

}

static void ntest_0_entry(ULONG thread_input)
{
UINT status;
ULONG response_length;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Unrecognized Cipher Suites Test................");

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


    /* Make sure client thread is ready. */
    tx_thread_suspend(&thread_0);

    server_tls_setup(&tls_server_session_0);

    status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Start TLS session. */
    status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                         NX_WAIT_FOREVER);
    if (!status)
    {
        ERROR_COUNTER();
    }

    nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
    nx_secure_tls_session_delete(&tls_server_session_0);

    nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
    nx_tcp_server_socket_unaccept(&server_socket_0);
    nx_tcp_server_socket_relisten(&ip_0, SERVER_PORT, &server_socket_0);


}

static UCHAR serverhello[512];
static UCHAR clienthello_bytes[] = {
  0x16, 0x03, 0x01, 0x01, 0x1b, 0x01, 0x00, 0x01, 0x17, 0x03, 0x03, 0x86,
  0x97, 0xcc, 0x33, 0x0b, 0xaf, 0xe3, 0xf0, 0x10, 0x94, 0x21, 0x9b, 0x0a,
  0x3b, 0x67, 0xa0, 0x78, 0xe4, 0xf0, 0x48, 0xc9, 0xaa, 0x78, 0x33, 0x0b,
  0x44, 0xb8, 0xf4, 0xe7, 0xff, 0x01, 0x69, 0x20, 0xf4, 0x38, 0xa9, 0x47,
  0xdb, 0x9d, 0xa2, 0x1d, 0x1a, 0xed, 0xdb, 0x4d, 0x70, 0x6f, 0x25, 0xa2,
  0x31, 0x13, 0xd3, 0x42, 0xeb, 0xb1, 0x03, 0x26, 0xa8, 0xe4, 0x1b, 0x95,
  0x23, 0xa6, 0xce, 0xfa, 0x00, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xc0, 0x09, 0x13, 0x03, 0x13, 0x01, 0x00, 0x3c, 0x00, 0xff, 0x01, 0x00,
  0x00, 0xbe, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x31,
  0x30, 0x2e, 0x30, 0x2e, 0x32, 0x30, 0x30, 0x2e, 0x31, 0x37, 0x00, 0x0b,
  0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x17, 0x00, 0x23,
  0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d,
  0x00, 0x26, 0x00, 0x24, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09,
  0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
  0x05, 0x01, 0x06, 0x01, 0x00, 0x2b, 0x00, 0x07, 0x06, 0xff, 0xff, 0xff,
  0xff, 0x03, 0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00,
  0x47, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04, 0xae, 0x4c, 0xc4, 0x0d,
  0xd0, 0x87, 0xd8, 0xd6, 0x84, 0x7c, 0x5d, 0x72, 0x44, 0x93, 0xe2, 0xfd,
  0x23, 0xb2, 0xde, 0xc0, 0x57, 0xc1, 0x08, 0x14, 0x4a, 0x83, 0x12, 0x63,
  0x52, 0x1f, 0x4d, 0x35, 0xd7, 0x52, 0xfa, 0x1c, 0x07, 0x8d, 0xfb, 0x4e,
  0x1d, 0x8c, 0x08, 0xc5, 0x5e, 0x54, 0xb5, 0xfd, 0xe1, 0x77, 0xb5, 0x7f,
  0xd0, 0x31, 0xfd, 0x77, 0x73, 0x7f, 0xc7, 0xbe, 0x96, 0x75, 0xd1, 0xf5
};

static void ntest_1_entry(ULONG thread_input)
{
UINT status;
UINT i;
NXD_ADDRESS server_address;
NX_PACKET *send_packet;
NX_PACKET *receive_packet;
ULONG      bytes_copied;

    srand(1);

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

    /* Let server thread run first. */
    tx_thread_resume(&thread_0);

    status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                            NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Random cipher suite */
    for (i = 78; i < 84; i++)
    {
        clienthello_bytes[i] = (UCHAR)NX_RAND();
    }

    /* Random supported groups */
    for (i = 132; i < 140; i++)
    {
        clienthello_bytes[i] = (UCHAR)NX_RAND();
    }

    /* Random signature algorithms */
    for (i = 160; i < 168; i++)
    {
        clienthello_bytes[i] = (UCHAR)NX_RAND();
    }

    /* Random supported versions */
    for (i = 201; i < 205; i++)
    {
        clienthello_bytes[i] = (UCHAR)NX_RAND();
    }

    status = nx_packet_allocate(&pool_0, &send_packet, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_packet_data_append(send_packet, clienthello_bytes, sizeof(clienthello_bytes), &pool_0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_socket_send(&client_socket_0, send_packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Receive ServerHello. */
    status = nx_tcp_socket_receive(&client_socket_0, &receive_packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    nx_packet_data_extract_offset(receive_packet, 0, serverhello, sizeof(serverhello), &bytes_copied);
    EXPECT_EQ(NX_SUCCESS, status);

    EXPECT_TRUE(bytes_copied >= 7);

    /* Content Type: Handshake (22). */
    EXPECT_EQ(22, serverhello[0]);

    /* Handshake Type: Server Hello (2). */
    EXPECT_EQ(2, serverhello[5]);



    nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);

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
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_unrecognized_ciphersuite_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Unrecognized Cipher Suites Test................N/A\n");
    test_control_return(3);
}
#endif
