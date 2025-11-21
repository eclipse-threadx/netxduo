/* This test TLS 1.3 server process empty KeyShare and two KeyShares.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "ecc_certs.c"
#include   "nx_crypto_aes.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && (NX_SECURE_TLS_TLS_1_3_ENABLED)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define SERVER_PORT                 4433

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_server;
static TX_THREAD                thread_client;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static UINT                     error_counter;

static NX_TCP_SOCKET            client_socket_0;
static NX_SECURE_TLS_SESSION    tls_client_session_0;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      client_local_certificate;
static NX_TCP_SOCKET            server_socket_0;
static NX_SECURE_TLS_SESSION    tls_server_session_0;
static NX_SECURE_X509_CERT      server_trusted_ca;
static NX_SECURE_X509_CERT      server_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_server_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_client_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];
static UCHAR                    server_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    tls_packet_buffer[2][4000];

extern const                    USHORT nx_crypto_ecc_supported_groups[];
extern const                    NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const                    UINT nx_crypto_ecc_supported_groups_size;
extern const                    NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

extern const NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_tls_1_3[];
extern const UINT _nx_crypto_ciphersuite_lookup_table_tls_1_3_size;


/* Define thread prototypes.  */

static VOID    test_client_entry(ULONG thread_input);
static VOID    test_server_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

static VOID    ERROR_COUNTER()
{
    error_counter++;
}

static UCHAR client_hello_empty_key_share[] = {
0x03,
0x03, 0x00, 0x00, 0x00, 0x00, 0x25, 0x3b, 0x00, 0x00, 0x1f, 0x1e, 0x00, 0x00, 0x5d, 0x6e, 0x00,
0x00, 0xd4, 0x1a, 0x00, 0x00, 0xcb, 0x63, 0x00, 0x00, 0xfc, 0x6b, 0x00, 0x00, 0x96, 0x7f, 0x00,
0x00, 0x00, 0x00, 0x34, 0x13, 0x01, 0x13, 0x04, 0x13, 0x05, 0xc0, 0x23, 0xc0, 0x09, 0xc0, 0x0a,
0xc0, 0x27, 0xc0, 0x13, 0xc0, 0x14, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x3d, 0x00, 0x35, 0x00, 0x3c,
0x00, 0x2f, 0x00, 0x9c, 0xc0, 0x25, 0xc0, 0x04, 0xc0, 0x05, 0xc0, 0x29, 0xc0, 0x0e, 0xc0, 0x0f,
0xc0, 0x2d, 0xc0, 0x31, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00, 0x3d, 0x00, 0x0a, 0x00, 0x08,
0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x2b,
0x00, 0x07, 0x06, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x00, 0x33, 0x00, 0x02, 0x00, 0x00, 0x00,
0x0d, 0x00, 0x16, 0x00, 0x14, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x04, 0x01, 0x05, 0x01, 0x06,
0x01, 0x03, 0x03, 0x02, 0x03, 0x02, 0x01, 0x01, 0x01,
};

static UCHAR client_hello_two_key_share[] = {
0x03,
0x03, 0x00, 0x00, 0x00, 0x00, 0x25, 0x3b, 0x00, 0x00, 0x1f, 0x1e, 0x00, 0x00, 0x5d, 0x6e, 0x00,
0x00, 0xd4, 0x1a, 0x00, 0x00, 0xcb, 0x63, 0x00, 0x00, 0xfc, 0x6b, 0x00, 0x00, 0x96, 0x7f, 0x00,
0x00, 0x00, 0x00, 0x34, 0x13, 0x01, 0x13, 0x04, 0x13, 0x05, 0xc0, 0x23, 0xc0, 0x09, 0xc0, 0x0a,
0xc0, 0x27, 0xc0, 0x13, 0xc0, 0x14, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x3d, 0x00, 0x35, 0x00, 0x3c,
0x00, 0x2f, 0x00, 0x9c, 0xc0, 0x25, 0xc0, 0x04, 0xc0, 0x05, 0xc0, 0x29, 0xc0, 0x0e, 0xc0, 0x0f,
0xc0, 0x2d, 0xc0, 0x31, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00, 0xe7, 0x00, 0x0a, 0x00, 0x08,
0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x2b,
0x00, 0x07, 0x06, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x00, 0x33, 0x00, 0xac, 0x00, 0xaa, 0x00,
0x17, 0x00, 0x41, 0x04, 0xcb, 0x1f, 0x71, 0x44, 0xac, 0x9a, 0x0c, 0x71, 0xb6, 0xa2, 0x20, 0x29,
0x3d, 0x9b, 0xb4, 0xc6, 0xc2, 0x19, 0x76, 0x32, 0x17, 0xd8, 0x7f, 0xcd, 0x92, 0xb4, 0xae, 0xa8,
0xfe, 0x5a, 0x40, 0x9b, 0x66, 0x4d, 0x35, 0x6c, 0x5c, 0x7c, 0xad, 0x28, 0x96, 0x43, 0xd2, 0xa2,
0xb8, 0xc8, 0xf0, 0x23, 0xca, 0x0d, 0x84, 0xea, 0xab, 0xd3, 0x9a, 0xc5, 0x88, 0x13, 0x58, 0x15,
0x87, 0xbb, 0xab, 0x4b, 0x00, 0x18, 0x00, 0x61, 0x04, 0xea, 0xf3, 0xa1, 0x57, 0x96, 0xb2, 0x76,
0x8d, 0x0e, 0x14, 0xb5, 0xed, 0x52, 0x56, 0x0d, 0x89, 0x05, 0x87, 0xdf, 0x73, 0x5f, 0x48, 0x32,
0x0d, 0xbb, 0xe9, 0xeb, 0x5d, 0x7d, 0xa9, 0xbe, 0xad, 0xe2, 0xfe, 0x1f, 0xa7, 0xde, 0xe2, 0x8e,
0xf8, 0x43, 0xf3, 0xac, 0xea, 0x96, 0xe1, 0xb0, 0x90, 0x68, 0xe6, 0x42, 0xc2, 0x7e, 0x4c, 0x12,
0x0b, 0x04, 0x08, 0x32, 0xdc, 0x09, 0x90, 0xd5, 0x0d, 0x27, 0xfb, 0x0f, 0x1d, 0x44, 0xb8, 0x7a,
0x04, 0xf1, 0x51, 0x69, 0x0e, 0x45, 0xae, 0x0f, 0x07, 0x00, 0x2e, 0xac, 0xe4, 0x1c, 0x7a, 0xac,
0xdb, 0x57, 0x05, 0x17, 0x27, 0x2b, 0x91, 0x3c, 0xdd, 0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x04,
0x03, 0x05, 0x03, 0x06, 0x03, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x02, 0x03, 0x02,
0x01, 0x01, 0x01,
};

static TX_SEMAPHORE            semaphore_server;

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_key_share_test_application_define(void *first_unused_memory)
#endif
{
UINT     status;
CHAR    *pointer;


    error_counter = 0;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&thread_server, "thread server", test_server_entry, 0,
                     thread_server_stack, sizeof(thread_server_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Create the client thread.  */
    tx_thread_create(&thread_client, "thread client", test_client_entry, 0,
                     thread_client_stack, sizeof(thread_client_stack),
                     8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_semaphore_create(&semaphore_server, "semaphore server", 0);

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

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                          &nx_crypto_tls_ciphers_ecc,
                                          client_metadata,
                                          sizeof(client_metadata));
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

    memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &client_remote_cert,
                                                       client_cert_buffer,
                                                       sizeof(client_cert_buffer));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca, ECCA4_der, ECCA4_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr, &client_trusted_ca);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    if (status)
    {
        ERROR_COUNTER();
    }
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

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

    memset(&server_remote_cert, 0, sizeof(server_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &server_remote_cert,
                                                       server_cert_buffer,
                                                       sizeof(server_cert_buffer));
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   ECTestServer4_der, ECTestServer4_der_len,
                                                   NX_NULL, 0, ECTestServer4_key_der,
                                                   ECTestServer4_key_der_len,
                                                   NX_SECURE_X509_KEY_TYPE_EC_DER);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                 &server_local_certificate);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[1],
                                                     sizeof(tls_packet_buffer[1]));
    if (status)
    {
        ERROR_COUNTER();
    }
}

static void test_server_entry(ULONG thread_input)
{
UINT status;
NX_PACKET *packet_ptr;
UCHAR receive_buffer[64];
ULONG receive_length;
UINT i = 0;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Key Share Test.............................");

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

    server_tls_setup(&tls_server_session_0);


    for (i = 0; i < 2; i++)
    {

        tx_semaphore_put(&semaphore_server);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        if (status == NX_SUCCESS)
        {
            status = nx_secure_tls_session_receive(&tls_server_session_0, &packet_ptr, NX_WAIT_FOREVER);

            if (status)
            {
                ERROR_COUNTER();
            }
            else
            {
                /* Extract data received from server. */
                nx_packet_data_retrieve(packet_ptr, receive_buffer, &receive_length);
                if (memcmp(receive_buffer, "hello", 5) != 0)
                {
                    ERROR_COUNTER();
                }
                nx_packet_release(packet_ptr);
            }
        }

        nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
        nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
        nx_tcp_server_socket_unaccept(&server_socket_0);

        if (i == 0)
        {
            tx_thread_sleep(100);
        }
        nx_tcp_server_socket_relisten(&ip_0, SERVER_PORT, &server_socket_0);
    }

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

/* Rewrite the session start function. 
   For the first loop, client will send ClientHello with two KeyShares.
   For the second loop, client will send ClientHello with empty KeyShare. */
static UINT test_count = 0;
static UINT tls_session_start_test(NX_SECURE_TLS_SESSION *tls_session, NX_TCP_SOCKET *tcp_socket,
                                  UINT wait_option)
{
UINT       status = NX_NOT_SUCCESSFUL;
UINT       error_return;
#ifndef NX_SECURE_TLS_CLIENT_DISABLED
NX_PACKET *send_packet;
#endif
NX_SECURE_TLS_ECDHE_HANDSHAKE_DATA   *ecdhe_data;

    /* Get the protection. */
    tx_mutex_get(&_nx_secure_tls_protection, TX_WAIT_FOREVER);

    /* Assign the packet pool from which TLS will allocate internal message packets. */
    tls_session -> nx_secure_tls_packet_pool = tcp_socket -> nx_tcp_socket_ip_ptr -> nx_ip_default_packet_pool;

    /* Assign the TCP socket to the TLS session. */
    tls_session -> nx_secure_tls_tcp_socket = tcp_socket;

    /* Reset the record queue. */
    tls_session -> nx_secure_record_queue_header = NX_NULL;
    tls_session -> nx_secure_record_decrypted_packet = NX_NULL;

    /* Make sure we are starting with a fresh session. */
    tls_session -> nx_secure_tls_local_session_active = 0;
    tls_session -> nx_secure_tls_remote_session_active = 0;
    tls_session -> nx_secure_tls_received_remote_credentials = NX_FALSE;

    /* See if this is a TCP server started with listen/accept, or a TCP client started with connect. */
    if (tcp_socket -> nx_tcp_socket_client_type)
    {
        /* The TCP socket is a client, so our TLS session is a TLS Client. */
        tls_session -> nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    }
    else
    {
        /* This session is now being treated as a server - indicate that fact to the TLS stack. */
        tls_session -> nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    }

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* Initialize TLS 1.3 cryptographic primitives. */
    if(tls_session->nx_secure_tls_1_3)
    {
        status = _nx_secure_tls_1_3_crypto_init(tls_session);

        if(status != NX_SUCCESS)
        {
            return(status);
        }
    }
#endif

    /* Now process the handshake depending on the TLS session type. */
#ifndef NX_SECURE_TLS_CLIENT_DISABLED
    if (tls_session -> nx_secure_tls_socket_type == NX_SECURE_TLS_SESSION_TYPE_CLIENT)
    {

        /* Allocate a handshake packet so we can send the ClientHello. */
        status = _nx_secure_tls_allocate_handshake_packet(tls_session, tls_session -> nx_secure_tls_packet_pool, &send_packet, wait_option);

        if (status != NX_SUCCESS)
        {

            /* Release the protection. */
            tx_mutex_put(&_nx_secure_tls_protection);
            return(status);
        }

        if (test_count == 0)
        {

            /* Populate our packet with clienthello data. */
            status = nx_packet_data_append(send_packet, client_hello_empty_key_share, sizeof(client_hello_empty_key_share), tls_session -> nx_secure_tls_packet_pool, NX_NO_WAIT);
            test_count++;
        }
        else
        {
            ecdhe_data = &tls_session -> nx_secure_tls_key_material.nx_secure_tls_ecc_key_data[0];

            memcpy(&client_hello_two_key_share[132], ecdhe_data -> nx_secure_tls_ecdhe_public_key, ecdhe_data -> nx_secure_tls_ecdhe_public_key_length);

            
            ecdhe_data = &tls_session -> nx_secure_tls_key_material.nx_secure_tls_ecc_key_data[1];

            memcpy(&client_hello_two_key_share[201], ecdhe_data -> nx_secure_tls_ecdhe_public_key, ecdhe_data -> nx_secure_tls_ecdhe_public_key_length);

            /* Populate our packet with clienthello data. */
            status = nx_packet_data_append(send_packet, client_hello_two_key_share, sizeof(client_hello_two_key_share), tls_session -> nx_secure_tls_packet_pool, NX_NO_WAIT);
        }

        if (status == NX_SUCCESS)
        {

            /* Send the ClientHello to kick things off. */
            status = _nx_secure_tls_send_handshake_record(tls_session, send_packet, NX_SECURE_TLS_CLIENT_HELLO, wait_option);
        }

        /* If anything after the allocate fails, we need to release our packet. */
        if (status != NX_SUCCESS)
        {

            /* Release the protection. */
            tx_mutex_put(&_nx_secure_tls_protection);
            nx_packet_release(send_packet);
            return(status);
        }
    }
#endif

    /* Release the protection. */
    tx_mutex_put(&_nx_secure_tls_protection);

    /* Now handle our incoming handshake messages. Continue processing until the handshake is complete
       or an error/timeout occurs. */
    status = _nx_secure_tls_handshake_process(tls_session, wait_option);

    if(status != NX_SUCCESS)
    {
        /* Save the return status before resetting the TLS session. */
        error_return = status;

        /* Reset the TLS state so this socket can be reused. */
        status = _nx_secure_tls_session_reset(tls_session);

        if(status != NX_SUCCESS)
        {
            return(status);
        }

        return(error_return);
    }

    return(status);
}

static void test_client_entry(ULONG thread_input)
{
UINT status;
NX_PACKET *packet_ptr;
NXD_ADDRESS server_address;
UINT i;

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

    client_tls_setup(&tls_client_session_0);

    for (i = 0; i < 2; i++)
    {
        tx_semaphore_get(&semaphore_server, NX_WAIT_FOREVER);

        status = nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = tls_session_start_test(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        if (status == NX_SUCCESS)
        {
            /* Prepare packet to send. */
            status = nx_secure_tls_packet_allocate(&tls_client_session_0, &pool_0, &packet_ptr, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }

            status = nx_packet_data_append(packet_ptr, "hello\n", 6, &pool_0, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }

            /* Send the packet. */
            status = nx_secure_tls_session_send(&tls_client_session_0, packet_ptr, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }
        }

        nx_secure_tls_session_end(&tls_client_session_0, NX_NO_WAIT);
        nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    }

    nx_secure_tls_session_delete(&tls_client_session_0);
    nx_tcp_client_socket_unbind(&client_socket_0);
    nx_tcp_socket_delete(&client_socket_0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_key_share_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Key Share Test.............................N/A\n");
    test_control_return(3);
}
#endif
