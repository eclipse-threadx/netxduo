/* This test TLS 1.3 server negotiate TLS 1.2.  */
/*
   rfc8446 p32
   If negotiating TLS 1.2, TLS 1.3 servers MUST set the last 8 bytes of
   their Random value to the bytes:
     44 4F 57 4E 47 52 44 01
   If negotiating TLS 1.1 or below, TLS 1.3 servers MUST, and TLS 1.2
   servers SHOULD, set the last 8 bytes of their ServerHello.Random
   value to the bytes:
     44 4F 57 4E 47 52 44 00
*/

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "ecc_certs.c"
#include   "nx_crypto_ecdh.h"
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

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_1_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    tls_packet_buffer[2][4000];

static TX_SEMAPHORE             semaphore_client;
static TX_SEMAPHORE             semaphore_server;

extern const                    USHORT nx_crypto_ecc_supported_groups[];
extern const                    NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const                    UINT nx_crypto_ecc_supported_groups_size;
extern const                    NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

static UCHAR client_hello_tls_1_1[] = {
0x16, 0x03, 0x01, 0x00, 0x75, 0x01, 0x00, 0x00, 0x71, 0x03, 0x02, 0xa9, 0xa6, 0x84, 0x55, 0x7f,
0x83, 0xd9, 0xbf, 0x79, 0x71, 0xe4, 0x04, 0x5c, 0xb0, 0x14, 0x2d, 0x17, 0x37, 0x43, 0x35, 0xd9,
0xea, 0x3b, 0xd8, 0xa4, 0x82, 0x46, 0xb7, 0x66, 0xeb, 0x8d, 0x26, 0x00, 0x00, 0x12, 0xc0, 0x0a,
0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
0x01, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63,
0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a,
0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x00, 0x23,
0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
};

static UCHAR client_hello_tls_1_2[] = {
0x16, 0x03, 0x01, 0x00, 0xcf, 0x01, 0x00, 0x00, 0xcb, 0x03, 0x03, 0xa5, 0x75, 0x05, 0xb6, 0x5c,
0xc9, 0x02, 0x7b, 0x6b, 0xe8, 0x43, 0xff, 0x6a, 0x02, 0x78, 0x76, 0xb9, 0x0d, 0xe5, 0xf2, 0xe2,
0x64, 0xeb, 0x55, 0xff, 0xc5, 0xc0, 0x51, 0xbd, 0x0d, 0x42, 0x8a, 0x00, 0x00, 0x38, 0xc0, 0x2c,
0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14,
0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c,
0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0x6a, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c,
0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x0b, 0x00, 0x04,
0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e,
0x00, 0x19, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
0x00, 0x0d, 0x00, 0x30, 0x00, 0x2e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
0x06, 0x01, 0x03, 0x03, 0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x02, 0x04, 0x02,
0x05, 0x02, 0x06, 0x02,
};

static UCHAR client_hello_tls_1_2_no_ext[] = {
0x16, 0x03, 0x01, 0x00, 0x65, 0x01, 0x00, 0x00, 0x61, 0x03, 0x03, 0x75, 0xa5, 0xb6, 0x05, 0xc9,
0x5c, 0x7b, 0x02, 0xe8, 0x6b, 0x43, 0xff, 0x6a, 0x02, 0x78, 0x76, 0xb9, 0x0d, 0xe5, 0xf2, 0xe2,
0x64, 0x55, 0xeb, 0xc5, 0xff, 0x51, 0xc0, 0x0d, 0xbd, 0x8a, 0x42, 0x00, 0x00, 0x38, 0xc0, 0x2c,
0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14,
0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c,
0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0x00, 
};

static UCHAR server_hello_tls_1_2[] = {
0x16, 0x03, 0x03, 0x00, 0x31, 0x02, 0x00, 0x00, 0x2d, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x69,
0x98, 0x3c, 0x64, 0x73, 0x48, 0x33, 0x66, 0x51, 0xdc, 0xb0, 0x74, 0xff, 0x5c, 0x49, 0x19, 0x4a,
0x94, 0xe8, 0x2a, 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01, 0x00, 0x00, 0x3d, 0x00, 0x00,
0x05, 0xff, 0x01, 0x00, 0x01, 0x00,
};

static UCHAR server_hello_tls_1_1[] = {
0x16, 0x03, 0x02, 0x00, 0x51, 0x02, 0x00, 0x00, 0x4d, 0x03, 0x02, 0x28, 0x2e, 0xd3, 0x55, 0xee,
0x77, 0xd7, 0x45, 0xa0, 0xf5, 0x71, 0x9e, 0x02, 0x2b, 0x86, 0x12, 0x83, 0xe6, 0x04, 0x00, 0xc5,
0x64, 0xbb, 0x6f, 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00, 0x20, 0xe0, 0x36, 0x6a, 0xc7,
0xac, 0x50, 0x44, 0x66, 0x9a, 0x43, 0x61, 0x52, 0x15, 0xc5, 0x35, 0xaa, 0x17, 0xc1, 0x7e, 0x87,
0xfe, 0x3a, 0x1b, 0x29, 0xd8, 0xd8, 0x1f, 0x4f, 0x6d, 0x43, 0x58, 0xfe, 0x00, 0x35, 0x00, 0x00,
0x05, 0xff, 0x01, 0x00, 0x01, 0x00,
};

static UCHAR server_hello_tls_1_2_no_ext[] = {
0x16, 0x03, 0x03, 0x00, 0x2c, 0x02, 0x00, 0x00, 0x28, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x69,
0x98, 0x3c, 0x64, 0x73, 0x48, 0x33, 0x66, 0x51, 0xdc, 0xb0, 0x74, 0xff, 0x5c, 0x49, 0x19, 0x4a,
0x94, 0xe8, 0x2a, 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01, 0x00, 0x00, 0x3d, 0x00, 0x00,
0x00,
};

/* Define what the initial system looks like.  */


#define ERROR_COUNTER() __ERROR_COUNTER(__FILE__, __LINE__)

static VOID    __ERROR_COUNTER(UCHAR *file, UINT line)
{
    printf("Error on line %d in %s", line, file);
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_version_negotiation_test_application_define(void *first_unused_memory)
#endif
{
UINT     status;
CHAR    *pointer;


    error_counter = 0;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    tx_semaphore_create(&semaphore_client, "semaphore client", 0);
    tx_semaphore_create(&semaphore_server, "semaphore server", 0);

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

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca, ECCA2_der, ECCA2_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &client_trusted_ca);
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

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, UINT use_rsa_cert)
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

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    if (use_rsa_cert)
    {
        status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                       test_device_cert_der, test_device_cert_der_len,
                                                       NX_NULL, 0, test_device_cert_key_der,
                                                       test_device_cert_key_der_len,
                                                       NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    }
    else
    {
        status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                       ECTestServer2_der, ECTestServer2_der_len,
                                                       NX_NULL, 0, ECTestServer2_key_der,
                                                       ECTestServer2_key_der_len,
                                                       NX_SECURE_X509_KEY_TYPE_EC_DER);
    }

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

static void ntest_0_entry(ULONG thread_input)
{
UINT i;
UINT status;
NX_PACKET *packet_ptr;
UCHAR *server_hello;
UINT server_hello_size;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Version Negotiation Test...................");

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


    for (i = 0; i < 6; i++)
    {
        tx_semaphore_put(&semaphore_server);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        if (i >= 3)
        {

            status = nx_tcp_socket_receive(&server_socket_0, &packet_ptr, NX_IP_PERIODIC_RATE);

            if (status)
            {
                ERROR_COUNTER();
            }
            else
            {
                nx_packet_release(packet_ptr);

                if (i == 3)
                {
                    server_hello = server_hello_tls_1_2;
                    server_hello_size = sizeof(server_hello_tls_1_2);
                }
                else if (i == 4)
                {
#if (NX_SECURE_TLS_TLS_1_1_ENABLED)
                    server_hello = server_hello_tls_1_1;
                    server_hello_size = sizeof(server_hello_tls_1_1);
#else
                    server_hello = server_hello_tls_1_2;
                    server_hello_size = sizeof(server_hello_tls_1_2);
#endif
                }
                else
                {
                    server_hello = server_hello_tls_1_2_no_ext;
                    server_hello_size = sizeof(server_hello_tls_1_2_no_ext);
                }

                /* Prepare packet to send. */
                status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
                if (status)
                {
                    ERROR_COUNTER();
                }

                status = nx_packet_data_append(packet_ptr, server_hello, server_hello_size, &pool_0, NX_NO_WAIT);
                if (status)
                {
                    ERROR_COUNTER();
                }

                status = nx_tcp_socket_send(&server_socket_0, packet_ptr, NX_NO_WAIT);

                if (status)
                {
                    ERROR_COUNTER();
                }

            }

        }
        else
        {
            if (i == 2)
            {
                server_tls_setup(&tls_server_session_0, 1);
            }
            else
            {
                server_tls_setup(&tls_server_session_0, 0);
            }

            /* Start TLS session. */
            nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0, NX_IP_PERIODIC_RATE);

            nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
            nx_secure_tls_session_delete(&tls_server_session_0);
        }

        tx_semaphore_get(&semaphore_client, NX_WAIT_FOREVER);

        nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
        nx_tcp_server_socket_unaccept(&server_socket_0);
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

static UCHAR tls_1_2_random[] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
static UCHAR tls_1_1_random[] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00};

static void ntest_1_entry(ULONG thread_input)
{
UINT i;
UINT status;
NXD_ADDRESS server_address;
NX_PACKET *packet_ptr;
UCHAR *client_hello;
UINT client_hello_size;
UCHAR *data;
static UCHAR *server_hello_random;

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


    for (i = 0; i < 6; i++)
    {
        tx_semaphore_get(&semaphore_server, NX_WAIT_FOREVER);

        if (i == 0)
        {
            client_hello = client_hello_tls_1_2;
            client_hello_size = sizeof(client_hello_tls_1_2);
            server_hello_random = tls_1_2_random;
        }
        else if (i == 1)
        {
            client_hello = client_hello_tls_1_1;
            client_hello_size = sizeof(client_hello_tls_1_1);
            server_hello_random = tls_1_1_random;
        }
        else if (i == 2)
        {
            client_hello = client_hello_tls_1_2_no_ext;
            client_hello_size = sizeof(client_hello_tls_1_2_no_ext);
            server_hello_random = tls_1_2_random;
        }

        status = nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        if (i >= 3)
        {
            client_tls_setup(&tls_client_session_0);

            status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
            if (status != NX_SECURE_TLS_DOWNGRADE_DETECTED)
            {
                ERROR_COUNTER();
            }

            nx_secure_tls_session_end(&tls_client_session_0, NX_IP_PERIODIC_RATE);
            nx_secure_tls_session_delete(&tls_client_session_0);

        }
        else
        {
            /* Prepare packet to send. */
            status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }

            status = nx_packet_data_append(packet_ptr, client_hello, client_hello_size, &pool_0, NX_NO_WAIT);
            if (status)
            {
                ERROR_COUNTER();
            }

            status = nx_tcp_socket_send(&client_socket_0, packet_ptr, NX_NO_WAIT);

            if (status)
            {
                ERROR_COUNTER();
            }

            status = nx_tcp_socket_receive(&client_socket_0, &packet_ptr, NX_IP_PERIODIC_RATE);

            if (status)
            {
                ERROR_COUNTER();
            }
            else
            {
                data = packet_ptr -> nx_packet_prepend_ptr + 11 + 24;
                if (memcmp(data, server_hello_random, 8) != 0)
                {
                    ERROR_COUNTER();
                }
                nx_packet_release(packet_ptr);
            }
        }

        tx_semaphore_put(&semaphore_client);

        nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    }

    nx_tcp_client_socket_unbind(&client_socket_0);
    nx_tcp_socket_delete(&client_socket_0);

}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_version_negotiation_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Version Negotiation Test...................N/A\n");
    test_control_return(3);
}
#endif
