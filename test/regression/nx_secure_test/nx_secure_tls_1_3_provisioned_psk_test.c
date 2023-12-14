/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "nx_crypto_ecdh.h"
#include   "ecc_certs.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && (NX_SECURE_TLS_TLS_1_3_ENABLED) && defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define SERVER_PORT                 4433
#define CIPHERSUITE_INIT(p, s, c)   {p, sizeof(p) / sizeof(UINT), s, c}
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

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static TX_THREAD                thread_1;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static UINT                     error_counter;

static NX_TCP_SOCKET            client_socket_0;
static NX_TCP_SOCKET            server_socket_0;
static NX_SECURE_TLS_SESSION    tls_client_session_0;
static NX_SECURE_TLS_SESSION    tls_server_session_0;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;
static NX_SECURE_TLS_CRYPTO     tls_ciphers_client;
static NX_SECURE_TLS_CRYPTO     tls_ciphers_server;
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table_client[10];
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table_server[10];

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_1_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    request_buffer[BUFFER_SIZE];
static UCHAR                    response_buffer[BUFFER_SIZE];
static UCHAR                    tls_packet_buffer[2][4000];

extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc[];
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

static CERTIFICATE test_certs[] =
{
    CERTIFICATE_INIT(ECTestServer2_der, ECTestServer2_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
};

static UINT ciphersuite_list_0[] = {TLS_AES_128_GCM_SHA256, 
                                    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_1[] = {TLS_AES_128_GCM_SHA256};
static UINT ciphersuite_list_2[] = {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

static UCHAR tls_psk[] = { 0x1a, 0x2b, 0x3c, 0x4d };

#define do_something_if_fail( p) if(!(p)){ERROR_COUNTER();}
/* Define what the initial system looks like.  */


static VOID    ERROR_COUNTER()
{
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_provisioned_psk_test_application_define(void *first_unused_memory)
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
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &pool_0, _nx_ram_network_driver_1500,
                          ip_0_stack, sizeof(ip_0_stack), 1);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (VOID *)arp_cache, sizeof(arp_cache));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    do_something_if_fail(!status);

    nx_secure_tls_initialize();
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, CERTIFICATE *cert)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           client_metadata,
                                           sizeof(client_metadata));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_psk_add(tls_session_ptr, tls_psk, sizeof(tls_psk), "Client_identity", 15, "12345678", 8);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);
    status = nx_secure_tls_client_psk_set(tls_session_ptr, tls_psk, sizeof(tls_psk), "Client_identity", 15, "12345678", 8);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);
    
    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &client_remote_cert,
                                                       client_cert_buffer,
                                                       sizeof(client_cert_buffer));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca,
                                                   cert -> ca_cert,
                                                   cert -> ca_cert_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &client_trusted_ca);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, CERTIFICATE *cert)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           server_metadata,
                                           sizeof(server_metadata));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_psk_add(tls_session_ptr, tls_psk, sizeof(tls_psk), "Client_identity", 15, "12345678", 8);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   cert -> server_cert, cert -> server_cert_len,
                                                   NX_NULL, 0, cert -> server_key,
                                                   cert -> server_key_len,
                                                   cert -> key_type);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                 &server_local_certificate);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[1],
                                                     sizeof(tls_packet_buffer[1]));
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);
}

static void ntest_0_entry(ULONG thread_input)
{
UINT status;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Provisioned PSK Test.......................");

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &server_socket_0, "Server socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_tcp_server_socket_listen(&ip_0, SERVER_PORT, &server_socket_0, 5, NX_NULL);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Make sure client thread is ready. */
    tx_thread_suspend(&thread_0);

    server_tls_setup(&tls_server_session_0, &test_certs[0]);

    status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Start TLS session. */
    status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                          NX_WAIT_FOREVER);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    nx_secure_tls_session_end(&tls_server_session_0, NX_IP_PERIODIC_RATE);
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
UINT j;
UINT status;
NX_PACKET *packet_ptr;
NXD_ADDRESS server_address;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    /* Let server thread run first. */
    tx_thread_resume(&thread_0);

    for (j = 0; j < sizeof(request_buffer); j++)
    {
        request_buffer[j] = j;
        response_buffer[j] = 0;
    }

    client_tls_setup(&tls_client_session_0, &test_certs[0]);

    status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                            NX_WAIT_FOREVER);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    tls_client_session_0.nx_secure_tls_1_3 = NX_TRUE;
#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
    tls_client_session_0.nx_secure_tls_renegotation_enabled = NX_FALSE;
#endif

    /* Start TLS session. */
    status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

    if (!status)
    {

        /* Prepare packet to send. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

        packet_ptr -> nx_packet_prepend_ptr += NX_SECURE_TLS_RECORD_HEADER_SIZE;
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;

        status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                       &pool_0, NX_NO_WAIT);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);

        /* Send the packet. */
        status = nx_secure_tls_session_send(&tls_client_session_0, packet_ptr, NX_NO_WAIT);
        do_something_if_fail(NX_SECURE_TLS_SUCCESS == status);
    }

    nx_secure_tls_session_end(&tls_client_session_0, NX_IP_PERIODIC_RATE);
    nx_secure_tls_session_delete(&tls_client_session_0);

    nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_provisioned_psk_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Provisioned PSK Test.......................N/A\n");
    test_control_return(3);
}
#endif
