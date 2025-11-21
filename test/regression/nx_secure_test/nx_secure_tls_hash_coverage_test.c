/* This test is to cover nx_secure_tls_record_hash_*.c.  */

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
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
static NX_SECURE_TLS_CRYPTO  tls_ciphers;
static NX_SECURE_TLS_CIPHERSUITE_INFO ciphersuite_table;
static NX_CRYPTO_METHOD test_hash;
#define TEST_COUNT 5

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
void nx_secure_tls_hash_coverage_test_application_define(void *first_unused_memory)
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

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status, i;
ULONG      actual_status;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Hash Coverage Test.............................");

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

    for (i = 0; i < TEST_COUNT; i++)
    {
        status = nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
        EXPECT_EQ(NX_SUCCESS, status);
        tx_thread_suspend(&ntest_0);

        status = nx_secure_tls_session_start(&server_tls_session, &server_socket, NX_IP_PERIODIC_RATE);
        //EXPECT_EQ(NX_SUCCESS, status);
        tx_thread_suspend(&ntest_0);

        status = nx_secure_tls_session_end(&server_tls_session, NX_NO_WAIT);
        status += nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER);
        status += nx_tcp_server_socket_unaccept(&server_socket);
        status += nx_tcp_server_socket_relisten(&ip_0, 12, &server_socket);
        EXPECT_EQ(NX_SUCCESS, status);
    }

    /* End the TLS session. This is required to properly shut down the TLS connection. */
    status = nx_tcp_server_socket_unlisten(&ip_0, 12);
    status += nx_secure_tls_session_delete(&server_tls_session);
    status += nx_tcp_socket_delete(&server_socket);
    EXPECT_EQ(NX_SUCCESS, status);

}

/* -----===== CLIENT =====----- */
static UINT test_op;
UINT  test_operation(UINT op, VOID *handle, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key,
                     NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte,
                     UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata,
                     ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == test_op)
    {
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }

    return(NX_CRYPTO_SUCCESS);
}
static void    ntest_1_entry(ULONG thread_input)
{
UINT       status, i;
NX_PACKET *send_packet = NX_NULL;
UCHAR      record_buffer[] = {0x17, 0x03, 0x03, 0x00, 0x80};
UCHAR      record_hash[NX_SECURE_TLS_MAX_HASH_SIZE];
UINT       hash_length = 0;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 1024*16,
                                  NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    for (i = 0; i < TEST_COUNT; i++)
    {

        /* Initialize ciphersuites. */
        memcpy(&tls_ciphers, &nx_crypto_tls_ciphers, sizeof(NX_SECURE_TLS_CRYPTO));
        tls_ciphers.nx_secure_tls_ciphersuite_lookup_table = &ciphersuite_table;
        tls_ciphers.nx_secure_tls_ciphersuite_lookup_table_size = 1;
        memcpy(&ciphersuite_table,
                &nx_crypto_tls_ciphers.nx_secure_tls_ciphersuite_lookup_table[1],
                sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));

        if (i == 0)
        {
            memcpy(&test_hash, &crypto_method_hmac_sha256, sizeof(NX_CRYPTO_METHOD));
            test_hash.nx_crypto_algorithm = NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_384;
            ciphersuite_table.nx_secure_tls_hash = &test_hash;
        }
        else if (i == 1)
        {
            memcpy(&test_hash, &crypto_method_hmac_sha256, sizeof(NX_CRYPTO_METHOD));
            test_hash.nx_crypto_operation = test_operation;
            test_op = NX_CRYPTO_HASH_UPDATE;
            ciphersuite_table.nx_secure_tls_hash = &test_hash;
        }
        else if (i == 2)
        {
            memcpy(&test_hash, &crypto_method_hmac_sha256, sizeof(NX_CRYPTO_METHOD));
            test_hash.nx_crypto_operation = test_operation;
            test_op = NX_CRYPTO_HASH_CALCULATE;
            ciphersuite_table.nx_secure_tls_hash = &test_hash;
        }
        else if (i == 3)
        {
            memcpy(&test_hash, &crypto_method_hmac_sha256, sizeof(NX_CRYPTO_METHOD));
            test_hash.nx_crypto_init = NX_NULL;
            test_hash.nx_crypto_cleanup = NX_NULL;
            ciphersuite_table.nx_secure_tls_hash = &test_hash;
        }

        /* Create a TLS session for our socket.  */
        status =  nx_secure_tls_session_create(&client_tls_session,
                                               &tls_ciphers,
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
        nx_secure_x509_certificate_initialize(&client_certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
        nx_secure_tls_local_certificate_add(&client_tls_session, &client_certificate);

        /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
        nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
        nx_secure_tls_trusted_certificate_add(&client_tls_session, &trusted_certificate);

        status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
        EXPECT_EQ(NX_SUCCESS, status);
        tx_thread_sleep(10);
        tx_thread_resume(&ntest_0);

        status = nx_secure_tls_session_start(&client_tls_session, &client_socket, NX_IP_PERIODIC_RATE);

        if (i == (TEST_COUNT - 1))
        {
            EXPECT_EQ(NX_SUCCESS, status);
            status = _nx_secure_tls_record_hash_initialize(&client_tls_session, client_tls_session.nx_secure_tls_local_sequence_number,
                                                record_buffer, sizeof(record_buffer), &hash_length, NX_NULL);
            EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);
            client_tls_session.nx_secure_tls_session_ciphersuite = NX_NULL;
            status = _nx_secure_tls_record_hash_initialize(&client_tls_session, client_tls_session.nx_secure_tls_local_sequence_number,
                                                           record_buffer, sizeof(record_buffer), &hash_length, client_tls_session.nx_secure_tls_key_material.nx_secure_tls_client_write_mac_secret);
            EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);
            status = _nx_secure_tls_record_hash_update(&client_tls_session, record_hash, hash_length);
            EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);
            status = _nx_secure_tls_record_hash_calculate(&client_tls_session, record_hash, &hash_length);
            EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);
        }

        /* End session. */
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
        tx_thread_resume(&ntest_0);
        nx_secure_tls_session_end(&client_tls_session, NX_NO_WAIT);
        nx_secure_tls_session_delete(&client_tls_session);
        status = nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER);
        EXPECT_EQ(NX_SUCCESS, status);
    }

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);
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
VOID    nx_secure_tls_hash_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Hash Coverage Test.............................N/A\n");
    test_control_return(3);
}
#endif
