/* This test concentrates on TLS ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA. The curve used in this demo is P256.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "test_device_cert.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 128
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
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
static NX_SECURE_X509_CERT      server_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_1_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];

static UCHAR                    request_buffer[BUFFER_SIZE];
static UCHAR                    response_buffer[BUFFER_SIZE];
static UCHAR                    tls_packet_buffer[4000];

/*  Cryptographic routines. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

static unsigned char clienthello[] = {
  0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x8d,
  0x1e, 0x10, 0xfd, 0xcd, 0xee, 0x9a, 0x58, 0x5b, 0xff, 0xe8, 0x50, 0x25,
  0x2f, 0x19, 0x16, 0x96, 0x5c, 0x19, 0x8a, 0x7f, 0xbc, 0xfa, 0xef, 0xd3,
  0xb5, 0xe3, 0x08, 0x4f, 0xbb, 0xb4, 0x20, 0x20, 0x6a, 0x09, 0x27, 0xc5,
  0xb6, 0x3b, 0x6b, 0xbe, 0x54, 0x7a, 0x02, 0xb0, 0xe3, 0x8e, 0x3f, 0x8c,
  0x3c, 0x51, 0x8f, 0xa6, 0x0e, 0xd9, 0x0d, 0x2b, 0xf6, 0xfd, 0x35, 0x69,
  0xc0, 0x9b, 0xab, 0xf4, 0x00, 0x22, 0x6a, 0x6a, 0x13, 0x01, 0x13, 0x02,
  0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9,
  0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f,
  0x00, 0x35, 0x00, 0x0a, 0x01, 0x00, 0x01, 0x91, 0x6a, 0x6a, 0x00, 0x00,
  0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00,
  0x00, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04,
  0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02,
  0x01, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
  0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08,
  0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x75, 0x50, 0x00, 0x00,
  0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x33, 0x00, 0x2b, 0x00, 0x29,
  0xca, 0xca, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20, 0xcf, 0x94, 0xa2,
  0xf5, 0xda, 0x87, 0x0d, 0x0c, 0x53, 0xb3, 0x02, 0xde, 0x22, 0xf1, 0xc1,
  0xeb, 0x76, 0xb9, 0x2d, 0x6f, 0x85, 0xf6, 0xe8, 0x6e, 0x98, 0xc5, 0x04,
  0x51, 0x57, 0xd2, 0x5e, 0x5f, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00,
  0x2b, 0x00, 0x0b, 0x0a, 0x7a, 0x7a, 0x7f, 0x17, 0x03, 0x03, 0x03, 0x02,
  0x03, 0x01, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0xca, 0xca, 0x00, 0x1d,
  0x00, 0x17, 0x00, 0x18, 0x7a, 0x7a, 0x00, 0x01, 0x00, 0x00, 0x15, 0x00,
  0xe4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00
};

static UCHAR session_id[] = {
  0x6a, 0x09, 0x27, 0xc5,
  0xb6, 0x3b, 0x6b, 0xbe, 0x54, 0x7a, 0x02, 0xb0, 0xe3, 0x8e, 0x3f, 0x8c,
  0x3c, 0x51, 0x8f, 0xa6, 0x0e, 0xd9, 0x0d, 0x2b, 0xf6, 0xfd, 0x35, 0x69,
  0xc0, 0x9b, 0xab, 0xf4,
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
VOID    nx_secure_tls_serverhello_session_id_test_application_define(void *first_unused_memory)
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

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                          &nx_crypto_tls_ciphers,
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
                                                   test_device_cert_key_der_len,
                                                   NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
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

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer,
                                                     sizeof(tls_packet_buffer));
    if (status)
    {
        ERROR_COUNTER(status);
    }
}

static void ntest_0_entry(ULONG thread_input)
{
UINT status;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ServerHello Session ID Test....................");

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
UINT i;
UINT status;
NX_PACKET *packet_ptr;
ULONG response_length;
ULONG session_id_length;
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

    status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                            NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER(status);
    }


    /* Prepare packet to send. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_packet_data_append(packet_ptr, clienthello, sizeof(clienthello),
                                   &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    /* Send the ClientHello packet. */
    status = nx_tcp_socket_send(&client_socket_0, packet_ptr, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    /* Receive a ServerHello from the server.  */
    status =  nx_tcp_socket_receive(&client_socket_0, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        ERROR_COUNTER(status);
    }


    status = nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    if (response_length < 43)
    {
        ERROR_COUNTER(status);
    }

    session_id_length = response_buffer[43];
    if (response_length < 43 + session_id_length)
    {
        ERROR_COUNTER(status);
    }

    /* TLS 1.2 server should not response the same fake session id to the client. */
    if (session_id_length == sizeof(session_id) &&
        memcmp(session_id, &response_buffer[44], sizeof(session_id)) == 0)
    {
        ERROR_COUNTER(status);
    }

    nx_packet_release(packet_ptr);


    nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client_socket_0);
    nx_tcp_socket_delete(&client_socket_0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_serverhello_session_id_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ServerHello Session ID Test....................N/A\n");
    test_control_return(3);
}
#endif
