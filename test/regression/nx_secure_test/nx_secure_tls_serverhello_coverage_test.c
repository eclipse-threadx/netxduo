/* This test is to cover nx_secure_tls_process_serverhello.c.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_crypto_rsa.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
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
static NX_SECURE_X509_CERT client_remote_certificate, client_remote_issuer;
static NX_SECURE_X509_CERT trusted_certificate;

static UCHAR remote_cert_buffer[2000];
static UCHAR remote_issuer_buffer[2000];
static UCHAR client_remote_cert_buffer[2000];
static UCHAR client_remote_issuer_buffer[2000];

static UCHAR server_packet_buffer[4000];
static UCHAR client_packet_buffer[4000];

static CHAR server_crypto_metadata[16000]; 
static CHAR client_crypto_metadata[16000]; 

/* Test PKI (3-level). */
#include "test_ca_cert.c"
#include "tls_two_test_certs.c"
#define ca_cert_der test_ca_cert_der
#define ca_cert_der_len test_ca_cert_der_len

/*  Cryptographic routines. */
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table[];

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
void nx_secure_tls_serverhello_coverage_test_application_define(void *first_unused_memory)
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

/* Test packets.  */
/* Message size < 38.  */
static UCHAR server_hello_test_1[] = {
0x03, 0x03, 0x2f, 0xda, 0xe5, 0x9b, 0x11,
0xdc, 0x13, 0x74, 0x31, 0xb5, 0x5d, 0xcf, 0x37, 0xe4, 0xb0, 0x5c, 0x06, 0x5c, 0x11, 0x74, 0xe1,
0x72, 0xfd, 0x7c, 0xd0, 0xce, 0x3f, 0x66, 0x54, 0x06, 0x4d, 0xa1, 0x00, 0xc0, 0x2c,
};

/* Invalid seesion_id length.  */
static UCHAR server_hello_test_2[] = {
0x03, 0x03, 0x2f, 0xda, 0xe5, 0x9b, 0x11,
0xdc, 0x13, 0x74, 0x31, 0xb5, 0x5d, 0xcf, 0x37, 0xe4, 0xb0, 0x5c, 0x06, 0x5c, 0x11, 0x74, 0xe1,
0x72, 0xfd, 0x7c, 0xd0, 0xce, 0x3f, 0x66, 0x54, 0x06, 0x4d, 0xa1, 0x30, 0xf1, 0xf2, 0xc0, 0x2c, 0x00, 0x00,
0x15, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x23,
0x00, 0x00, 0x00, 0x17, 0x00, 0x00
};

/* Unknow ciphersuite.  */
static UCHAR server_hello_test_3[] = {
0x03, 0x03, 0x2f, 0xda, 0xe5, 0x9b, 0x11,
0xdc, 0x13, 0x74, 0x31, 0xb5, 0x5d, 0xcf, 0x37, 0xe4, 0xb0, 0x5c, 0x06, 0x5c, 0x11, 0x74, 0xe1,
0x72, 0xfd, 0x7c, 0xd0, 0xce, 0x3f, 0x66, 0x54, 0x06, 0x4d, 0xa1, 0x02, 0xf1, 0xf2, 0xc0, 0x2c, 0x00, 0x00,
0x15, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x23,
0x00, 0x00, 0x00, 0x17, 0x00, 0x00
};

/* No supported compression methods. */
static UCHAR server_hello_test_4[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67,
0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72,
0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x01, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01,
0x00
};

/* Invalid extension length. */
static UCHAR server_hello_test_5[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67,
0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72,
0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x06, 0xff, 0x01, 0x00, 0x01,
0x00
};

/* nx_secure_tls_session_client_callback return error status. */
static UCHAR server_hello_test_6[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67,
0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72,
0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01,
0x00
};

/* Cover if (message_length >= (length + 2)). */
static UCHAR server_hello_test_7[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67,
0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72,
0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00
};

/* nx_secure_tls_process_serverhello_extensions.c */
static UCHAR server_hello_reneg[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67,
0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72,
0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01,
0x00
};

/* if (offset + 4 > message_length) */
static UCHAR server_hello_test_8[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67,
0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72,
0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x03, 0xff, 0x01, 0x00, 0x01,
0x00
};

#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
/* if (*extension_length > message_length || *extension_length < 3) */
static UCHAR server_hello_test_9[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67,
0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72,
0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x00,
0x00
};

/* if (*extension_length > message_length || *extension_length < 3) */
static UCHAR server_hello_test_10[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67,
0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72,
0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x02,
0x00
};

/* if (*extension_length > message_length || *extension_length < 3) */
static UCHAR server_hello_test_11[] = {
0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x18, 0x00, 0x00, 0x84, 0x67,
0x00, 0x00, 0xe1, 0x4a, 0x00, 0x00, 0x6c, 0x3d, 0x00, 0x00, 0xd6, 0x2c, 0x00, 0x00, 0xae, 0x72,
0x00, 0x00, 0x52, 0x69, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01,
0x01
};

static UCHAR server_hello_test_12[] = {
0xff, 0x01, 0x00, 0x19,
0x18, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x01, 0x02, 0x03, 0x04,
0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
};

static UCHAR server_hello_test_13[] = {
0xff, 0x01, 0x00, 0x19,
0x17, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x01, 0x02, 0x03, 0x04,
0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
};

static UCHAR server_hello_test_14[] = {
0xff, 0x01, 0x00, 0x02, 0x00, 0x00
};

static UCHAR server_hello_test_15[] = {
0xff, 0x01, 0x00, 0x01, 0x00
};
#endif

/* Set test packets' info.  */
static UCHAR *test_packets_data[] = {
server_hello_test_1,
server_hello_test_2,
server_hello_test_3,
server_hello_test_4,
server_hello_test_5,
server_hello_test_6,
server_hello_test_7,
server_hello_test_8,
#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
server_hello_test_9,
server_hello_test_10,
server_hello_test_11,
#endif
};

static UINT test_packets_size[] = {
sizeof(server_hello_test_1),
sizeof(server_hello_test_2),
sizeof(server_hello_test_3),
sizeof(server_hello_test_4),
sizeof(server_hello_test_5),
sizeof(server_hello_test_6),
sizeof(server_hello_test_7),
sizeof(server_hello_test_8),
#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
sizeof(server_hello_test_9),
sizeof(server_hello_test_10),
sizeof(server_hello_test_11),
#endif
};

/* Set expected status.  */
static UINT test_status[] = {
NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH,
NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH,
NX_SECURE_TLS_UNKNOWN_CIPHERSUITE,
NX_SECURE_TLS_BAD_COMPRESSION_METHOD,
NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH,
111,
NX_NO_PACKET,
NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH,
#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH,
NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH,
NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH,
#endif
};

#define TEST_START 0

static ULONG test_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extensions, UINT num_extensions)
{
    return 111;
}

/* -----===== SERVER =====----- */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status, i;
ULONG      actual_status;
NX_PACKET *send_packet, *receive_packet;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ServeHello Coverage Test.......................");

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

        tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
        server_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
        status = _nx_secure_tls_allocate_handshake_packet(&server_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
        tx_mutex_put(&_nx_secure_tls_protection);
        EXPECT_EQ(NX_SUCCESS, status);

        memcpy(send_packet -> nx_packet_prepend_ptr, test_packets_data[i], test_packets_size[i]);
        send_packet -> nx_packet_length = test_packets_size[i];
        send_packet -> nx_packet_append_ptr = send_packet -> nx_packet_prepend_ptr + send_packet -> nx_packet_length;

        /* Send an invaild message. */
        tx_mutex_get(&_nx_secure_tls_protection, NX_WAIT_FOREVER);
        status = _nx_secure_tls_send_handshake_record(&server_tls_session, send_packet, NX_SECURE_TLS_SERVER_HELLO, NX_WAIT_FOREVER);
        tx_mutex_put(&_nx_secure_tls_protection);
        EXPECT_EQ(NX_SUCCESS, status);

        /* Try receiving records from the remote host. */
        status = nx_packet_allocate(&pool_0, &receive_packet, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
        EXPECT_EQ(NX_SUCCESS, status);
        server_tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
        status = _nx_secure_tls_session_receive_records(&server_tls_session, &receive_packet, 5 * NX_IP_PERIODIC_RATE);
        if (i == 6)
        {
            EXPECT_EQ(NX_NO_PACKET, status);
        }
        else
        {
            EXPECT_EQ(NX_SECURE_TLS_ALERT_RECEIVED, status);
        }

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

static void    ntest_1_entry(ULONG thread_input)
{
UINT       status, i;
NX_PACKET *send_packet = NX_NULL;
NX_SECURE_TLS_HELLO_EXTENSION         extension_data[NX_SECURE_TLS_HELLO_EXTENSIONS_MAX];
UINT                                  num_extensions;

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

    nx_secure_tls_session_client_callback_set(&client_tls_session, test_callback);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    for (i = TEST_START ; i < (sizeof(test_packets_size) / sizeof(UINT)); i++)
    {

        status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
        EXPECT_EQ(NX_SUCCESS, status);

        tx_thread_sleep(10);
        tx_thread_resume(&ntest_0);
        status = nx_secure_tls_session_start(&client_tls_session, &client_socket, 5 * NX_IP_PERIODIC_RATE);
        EXPECT_EQ(test_status[i], status);

        /* Disconnect this socket.  */
        status = nx_secure_tls_session_end(&client_tls_session, NX_NO_WAIT);
        status += nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER);
        EXPECT_EQ(NX_SUCCESS, status);
    }

#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
    client_tls_session.nx_secure_tls_local_session_active = 0;
    client_tls_session.nx_secure_tls_remote_session_active = 1;
    client_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[1];
    status = _nx_secure_tls_process_serverhello_extensions(&client_tls_session, server_hello_test_12, 0x1d, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_remote_session_active = 0;
    status = _nx_secure_tls_process_serverhello_extensions(&client_tls_session, server_hello_test_12, 0x1d, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_remote_session_active = 1;
    client_tls_session.nx_secure_tls_secure_renegotiation = 0;
    status = _nx_secure_tls_process_serverhello_extensions(&client_tls_session, server_hello_test_12, 0x1d, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    client_tls_session.nx_secure_tls_local_session_active = 1;
    client_tls_session.nx_secure_tls_remote_session_active = 1;
    client_tls_session.nx_secure_tls_secure_renegotiation = 1;
    status = _nx_secure_tls_process_serverhello_extensions(&client_tls_session, server_hello_test_13, 0x1d, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    memcpy(client_tls_session.nx_secure_tls_local_verify_data, &server_hello_test_12[5], NX_SECURE_TLS_FINISHED_HASH_SIZE);
    memcpy(client_tls_session.nx_secure_tls_remote_verify_data, &server_hello_test_12[17], NX_SECURE_TLS_FINISHED_HASH_SIZE);

    client_tls_session.nx_secure_tls_remote_verify_data[0] = 0xff;
    status = _nx_secure_tls_process_serverhello_extensions(&client_tls_session, server_hello_test_12, 0x1d, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    client_tls_session.nx_secure_tls_local_verify_data[0] = 0xff;
    status = _nx_secure_tls_process_serverhello_extensions(&client_tls_session, server_hello_test_12, 0x1d, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    status = _nx_secure_tls_process_serverhello_extensions(&client_tls_session, server_hello_test_14, 0x6, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);

    status = _nx_secure_tls_process_serverhello_extensions(&client_tls_session, server_hello_test_15, 0x5, extension_data, &num_extensions);
    EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_EXTENSION_ERROR, status);
#endif

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
VOID    nx_secure_tls_serverhello_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ServerHello Coverage Test......................N/A\n");
    test_control_return(3);
}
#endif
