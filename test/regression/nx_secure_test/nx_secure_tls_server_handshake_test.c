#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"
#include   "nx_secure_tls_test_init_functions.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && !defined(NX_SECURE_DISABLE_X509)
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
#define ca_cert_der test_ca_cert_der
#define ca_cert_der_len test_ca_cert_der_len

/*  Cryptographic routines. */
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

/* Import certificates from nx_secure_tls_two_way_test.c  */
extern unsigned char ica_cert_der[];
extern unsigned int ica_cert_der_len;

extern unsigned char test_device_cert_der[];
extern unsigned int test_device_cert_der_len;

extern unsigned char test_device_cert_key_der[];
extern unsigned int test_device_cert_key_der_len;

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

static UINT test_crypto_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                               UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                               VOID **handler,
                               VOID *crypto_metadata,
                               ULONG crypto_metadata_size)
{
    return(NX_SUCCESS);
};

static UINT test_crypto_operation(UINT op,       /* Encrypt, Decrypt, Authenticate */
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
    memset(output, 0, output_length_in_byte);
    return(NX_SUCCESS);
};

/* Define what the initial system looks like.  */
#ifndef __LINUX__
void tx_application_define(void *first_unused_memory)
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_server_handshake_test_application_define(void *first_unused_memory)
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

/* -----===== SERVER =====----- */

/* Define a TLS name to test the Server Name Indication extension. */
#define TLS_SNI_SERVER_NAME "testing"

static void    ntest_0_entry(ULONG thread_input)
{
UCHAR receive_buffer[100];
UINT       status;
ULONG      actual_status;
NX_PACKET  *receive_packet;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Server Handshake Test..........................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16*1024,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    /* Receive packets. */
    nx_tcp_socket_receive(&server_socket, &receive_packet, NX_NO_WAIT);
    nx_packet_release(receive_packet);
    nx_tcp_socket_receive(&server_socket, &receive_packet, NX_NO_WAIT);
    nx_packet_release(receive_packet);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);


#ifdef NX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY
    /* Reset the tcp socket for the second test. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16*1024,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    /* Receive packets. */
    nx_tcp_socket_receive(&server_socket, &receive_packet, NX_NO_WAIT);
    nx_packet_release(receive_packet);
    nx_tcp_socket_receive(&server_socket, &receive_packet, NX_NO_WAIT);
    nx_packet_release(receive_packet);
    nx_tcp_socket_receive(&server_socket, &receive_packet, NX_NO_WAIT);
    nx_packet_release(receive_packet);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);
#endif

    /* Reset the tcp socket for the third test. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16*1024,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);

    /* The fourth test. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16*1024,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);

#if !defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) && !defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) 
    /* The first test for tls_client_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16*1024,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);

    /* The third test for tls_client_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16*1024,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);


    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);


    /* The fourth test for tls_client_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 62,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);


    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);


    /* The fifth test for tls_client_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16 * 1024,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);


    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);


    /* The sixth test for tls_client_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100,77,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);


    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);
#endif

    /* Last test for tls_server_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100,77,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);


    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_0, 12);
    nx_tcp_socket_delete(&server_socket);
}

/* -----===== CLIENT =====----- */

static void    ntest_1_entry(ULONG thread_input)
{
UINT         status;
UCHAR receive_buffer[400];
NX_SECURE_X509_CERT cert;
NX_SECURE_X509_CERT remote_cert;
NX_CRYPTO_METHOD crypto_method;
NX_CRYPTO_METHOD test_method;
NX_PACKET *receive_packet;

    /* Create a socket.  */
    /* Special window size for test. */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 54 * 2 + 1/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

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
    server_tls_session.nx_secure_tls_packet_pool = &pool_1;
    /* Only one packets left. */
    pool_1.nx_packet_pool_available = 1;
    server_tls_session.nx_secure_tls_tcp_socket = &server_socket;
    server_tls_session.nx_secure_tls_local_session_active = 0;
    server_tls_session.nx_secure_tls_crypto_table = &nx_crypto_tls_ciphers;
    /* Fail to allocate the second packet for certificate message. */
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 46, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);

    /* Enough packet, but not enough window size to send certificate message. */
    pool_1.nx_packet_pool_available = 10;
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 46, NX_NO_WAIT);
    EXPECT_EQ(NX_WINDOW_OVERFLOW, status);

    tx_thread_resume(&ntest_0);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);


#ifdef NX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY
    /* The second test. */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 64/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Enable the client cerificate verification. */
    nx_secure_tls_session_client_verify_enable(&server_tls_session);

    /* No enough window size to send client certificate verify. */
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 46, NX_NO_WAIT);
    EXPECT_EQ(NX_WINDOW_OVERFLOW, status);

    tx_thread_resume(&ntest_0);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);
#endif

    /* The third test. */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 100/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Disable the client certificate verification. */
    nx_secure_tls_session_client_verify_disable(&server_tls_session);
    /* Unable to allocate a packet for the 0 bytes ServerHelloDone. */
    pool_1.nx_packet_pool_available = 3;
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 46, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);

    pool_1.nx_packet_pool_available = 10;
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 46, NX_NO_WAIT);
    EXPECT_EQ(NX_WINDOW_OVERFLOW, status);

    tx_thread_resume(&ntest_0);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* The fourth test. */

    /* Define a NULL hash method. */
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
        NX_NULL,
    #endif

    #if (NX_SECURE_TLS_TLS_1_2_ENABLED)
        NX_NULL,
        NX_NULL,
    #endif
    };
    NX_CRYPTO_METHOD hash_method;
    memset(&hash_method, 0, sizeof(hash_method));
    test_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &hash_method;
    test_ciphersuite.nx_secure_tls_prf = &hash_method;
    hash_method.nx_crypto_operation = test_crypto_operation;
    hash_method.nx_crypto_init = test_crypto_init;

    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 1/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Finished message. */
    /* Handshake header. */
    receive_buffer[0] = NX_SECURE_TLS_FINISHED; /* message type. */
    /* message length. */
    receive_buffer[1] = 0;
    receive_buffer[2] = 0;
    receive_buffer[3] = NX_SECURE_TLS_FINISHED_HASH_SIZE;

    server_tls_session.nx_secure_tls_remote_session_active = 1;
    server_tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    /* Store the finshed hash in buffer. */
    memset(receive_buffer + 4, 0, NX_SECURE_TLS_FINISHED_HASH_SIZE);

    /* Unable to allocate a packet for CCS. */
    pool_1.nx_packet_pool_available = 0;
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 4 + NX_SECURE_TLS_FINISHED_HASH_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_NO_PACKET, status);

    /* Unable to send CCS, no enough window size. */
    pool_1.nx_packet_pool_available = 10;
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 4 + NX_SECURE_TLS_FINISHED_HASH_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_WINDOW_OVERFLOW, status);
    tx_thread_resume(&ntest_0);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

#if !defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) && !defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) 
    /* The first test for tls_client_handshake. */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16 * 1024/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    receive_buffer[0] = NX_SECURE_TLS_SERVER_HELLO_DONE;
    receive_buffer[1] = 0;
    receive_buffer[2] = 0;
    receive_buffer[3] = 4;

    /* Initialization. */
    client_tls_session.nx_secure_tls_tcp_socket = &client_socket;
    client_tls_session.nx_secure_tls_packet_pool = &pool_1;
    client_tls_session.nx_secure_tls_client_certificate_requested = 0;
    client_tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    client_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    client_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    nx_secure_tls_test_init_functions(&client_tls_session);

    /* Cannot find remote endpoint. */
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = NX_NULL;
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 8, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_NO_CERT_SPACE_ALLOCATED, status);
    tx_thread_resume(&ntest_0);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);


    /* The second test for tls_client_handshake. */
    crypto_method.nx_crypto_init = NX_NULL;
    crypto_method.nx_crypto_operation = NX_NULL;
    crypto_method.nx_crypto_cleanup = NX_NULL;
    test_ciphersuite.nx_secure_tls_public_cipher = &crypto_method;
    cert.nx_secure_x509_next_certificate = NX_NULL;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    cert.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = NX_SECURE_TLS_PREMASTER_SIZE + 2;/* Avoid buffer overflow. */
    /* Unable to send client key exchange. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 8, NX_NO_WAIT);
    EXPECT_EQ(NX_NOT_BOUND, status);


    /* The third test for tls_client_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16 * 1024/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Unsupported ciphersuite, fail to generate keys. We need to allocate remote certificate space
     * since we free the remote certificates as soon as possible rather than waiting for the session to complete. */
    ((NX_CRYPTO_METHOD *)test_ciphersuite.nx_secure_tls_public_cipher) -> nx_crypto_algorithm = 0xff;
    cert.nx_secure_x509_next_certificate = NX_NULL;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    cert.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = NX_SECURE_TLS_PREMASTER_SIZE + 2;/* Avoid buffer overflow. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 8, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_CIPHER, status);

    client_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    ((NX_CRYPTO_METHOD *)test_ciphersuite.nx_secure_tls_public_cipher) -> nx_crypto_algorithm = TLS_CIPHER_RSA;
    pool_1.nx_packet_pool_available = 1;
    test_ciphersuite.nx_secure_tls_prf = &test_method;
    test_method.nx_crypto_init = NX_NULL;
    test_method.nx_crypto_operation = NX_NULL;
    test_ciphersuite.nx_secure_tls_session_cipher = &test_method;
    cert.nx_secure_x509_next_certificate = NX_NULL;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    cert.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = NX_SECURE_TLS_PREMASTER_SIZE + 2;/* Avoid buffer overflow. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 8, NX_NO_WAIT);
    EXPECT_EQ(NX_NO_PACKET, status);

    pool_1.nx_packet_pool_available = 2;
    cert.nx_secure_x509_next_certificate = NX_NULL;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    cert.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = NX_SECURE_TLS_PREMASTER_SIZE + 2;/* Avoid buffer overflow. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 8, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);
    tx_thread_resume(&ntest_0);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);


    /* The fourth test for tls_client_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16 * 1024/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    tx_thread_resume(&ntest_0);

    /* Unable to send CCS. */
    pool_1.nx_packet_pool_available = 10;
    client_tls_session.nx_secure_tls_local_session_active = 0;
    cert.nx_secure_x509_next_certificate = NX_NULL;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    cert.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = NX_SECURE_TLS_PREMASTER_SIZE + 2;/* Avoid buffer overflow. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 8, NX_NO_WAIT);
    EXPECT_EQ(NX_WINDOW_OVERFLOW, status);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);


    /* The fifth test for tls_client_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16 * 1024/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    client_tls_session.nx_secure_tls_client_certificate_requested = 1;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_active_certificate = &cert;
    /* Unable to allocate a packet for CertificateVeriry. */
    pool_1.nx_packet_pool_available = 2;
    cert.nx_secure_x509_next_certificate = NX_NULL;
    cert.nx_secure_x509_certificate_raw_data_length = 10;
    cert.nx_secure_x509_certificate_raw_data = remote_cert_buffer;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_active_certificate = &cert;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    cert.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = NX_SECURE_TLS_PREMASTER_SIZE + 2;/* Avoid buffer overflow. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 8, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);

    client_tls_session.nx_secure_tls_client_certificate_requested = 1;
    pool_1.nx_packet_pool_available = 10;
    /* tls_send_certificate_verify fail to get a local certificate. */
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = NX_NULL;
    cert.nx_secure_x509_next_certificate = NX_NULL;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &cert;
    cert.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = NX_SECURE_TLS_PREMASTER_SIZE + 2;/* Avoid buffer overflow. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 8, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    tx_thread_resume(&ntest_0);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);


    /* The sixth test for tls_client_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16 * 1024/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates = &cert;
    cert.nx_secure_x509_certificate_is_identity_cert = NX_TRUE;
    cert.nx_secure_x509_next_certificate = NX_NULL;
    client_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    test_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &test_method;
    test_method.nx_crypto_operation = NX_NULL;
    remote_cert.nx_secure_x509_next_certificate = NX_NULL;
    client_tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates = &remote_cert;
    remote_cert.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = NX_SECURE_TLS_PREMASTER_SIZE + 2;/* Avoid buffer overflow. */
    client_tls_session.nx_secure_tls_client_certificate_requested = 1;
    /* Not enough window size to send certificate verify. */
    status = _nx_secure_tls_client_handshake(&client_tls_session, receive_buffer, 8, NX_NO_WAIT);
    EXPECT_EQ(NX_WINDOW_OVERFLOW, status);

    tx_thread_resume(&ntest_0);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);
#endif /* !defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) && !defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) */

    /* Last test for tls_server_handshake. */
    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16 * 1024/* window size. */,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    nx_secure_tls_test_init_functions(&server_tls_session);

    receive_buffer[0] = NX_SECURE_TLS_FINISHED;
    receive_buffer[1] = 0;
    receive_buffer[2] = 0;
    receive_buffer[3] = NX_SECURE_TLS_FINISHED_HASH_SIZE;
    _nx_secure_tls_finished_hash_generate(&server_tls_session, "server finished", receive_buffer + 4);
    server_tls_session.nx_secure_tls_tcp_socket = &client_socket;
    server_tls_session.nx_secure_tls_crypto_table = &nx_crypto_tls_ciphers;
    server_tls_session.nx_secure_tls_packet_pool = &pool_1;
    server_tls_session.nx_secure_tls_remote_session_active = 1;
    server_tls_session.nx_secure_tls_received_remote_credentials = NX_TRUE;
    /* unknown ciphersuite. tls_session_keys_set fail. */
    server_tls_session.nx_secure_tls_session_ciphersuite = NX_NULL;
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 4 + NX_SECURE_TLS_FINISHED_HASH_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

#if !defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) && !defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) 
    test_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &hash_method;
    test_ciphersuite.nx_secure_tls_prf = &hash_method;
    hash_method.nx_crypto_operation = test_crypto_operation;
    hash_method.nx_crypto_init = test_crypto_init;

    server_tls_session.nx_secure_tls_local_session_active = 0;
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    pool_1.nx_packet_pool_available = 1;
    /* Fail to allocate a packet for the finished message. */
    status = _nx_secure_tls_server_handshake(&server_tls_session, receive_buffer, 4 + NX_SECURE_TLS_FINISHED_HASH_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);
#endif

    tx_thread_resume(&ntest_0);

    /* Disconnect this socket.  */
    nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);
    EXPECT_EQ(NX_SUCCESS, status);

#if 0 /* TLS handshake will not allocate packet any more. This test point is deprecated. */
    ULONG bytes_processed;
    server_tls_session.nx_secure_tls_remote_session_active = 0;
    /* No packet left. */
    pool_1.nx_packet_pool_available = 10;
    status = nx_packet_allocate(&pool_1, &receive_packet, 0, NX_NO_WAIT);
    EXPECT_EQ(NX_SUCCESS, status);
    /* message type. */
    receive_buffer[0] = NX_SECURE_TLS_APPLICATION_DATA;
    /* protocol version. */
    receive_buffer[1] = NX_SECURE_TLS_VERSION_TLS_1_2 >> 8;
    receive_buffer[2] = NX_SECURE_TLS_VERSION_TLS_1_2 & 0xff;
    /* length. */
    receive_buffer[3] = 0;
    receive_buffer[4] = 1;
    /* data. */
    receive_buffer[5] = 1;
    nx_packet_data_append(receive_packet, receive_buffer, 6, &pool_1, NX_NO_WAIT);
    server_tls_session.nx_secure_record_queue_header = receive_packet;
    pool_1.nx_packet_pool_available = 0;
    server_tls_session.nx_secure_tls_packet_buffer_size = 400;
    server_tls_session.nx_secure_tls_packet_buffer = receive_buffer;
    server_tls_session.nx_secure_record_decrypted_packet = NX_NULL;
    /* Fail to allocate a packet for packet buffer in tls_process_record. */
    status = _nx_secure_tls_process_record(&server_tls_session, NX_NULL, &bytes_processed, NX_NO_WAIT);
    EXPECT_EQ(NX_NO_PACKET, status);
#endif

#if NX_SECURE_TLS_TLS_1_1_ENABLED
    /* NULL md5 operation pointer. */
    server_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    NX_CRYPTO_METHOD _method, _method_0;
    _method.nx_crypto_operation = NX_NULL;
    _method.nx_crypto_init = NX_NULL;
    _method_0.nx_crypto_operation = test_crypto_operation;
    server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_1;
    server_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    test_crypto_table.nx_secure_tls_handshake_hash_md5_method = &_method;
    status = _nx_secure_tls_finished_hash_generate(&server_tls_session, "server finished", receive_buffer);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

    /* NULL sha1 operation pointer. */
    test_crypto_table.nx_secure_tls_handshake_hash_md5_method = &_method_0;
    test_crypto_table.nx_secure_tls_handshake_hash_sha1_method = &_method;
    status = _nx_secure_tls_finished_hash_generate(&server_tls_session, "server finished", receive_buffer);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

    /* NULL prf init pointer. */
    test_crypto_table.nx_secure_tls_handshake_hash_sha1_method = &_method_0;
    test_crypto_table.nx_secure_tls_prf_1_method = &_method;
    status = _nx_secure_tls_finished_hash_generate(&server_tls_session, "server finished", receive_buffer);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

    /* NULL prf operation pointer. */
    _method.nx_crypto_init = &test_crypto_init;
    status = _nx_secure_tls_finished_hash_generate(&server_tls_session, "server finished", receive_buffer);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);
#endif

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_server_handshake_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Server Handshake Test..........................N/A\n");
    test_control_return(3);
}
#endif
