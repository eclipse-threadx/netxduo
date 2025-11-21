/* This test concentrates on TLS ciphersuites negotiation.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define PSK                         tls_psk
#define PSK_IDENTITY                "psk_indentity1234567"
#define PSK_HINT                    "psk_hint"
#define SERVER_PORT                 4433
#define CIPHERSUITE_INIT(p)         {p, sizeof(p) / sizeof(UINT)}

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
static UCHAR tls_psk[] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00,
    0x90, 0x8f, 0x7e, 0x6d, 0x5c, 0x4b, 0x3a, 0x29, 0x18, 0x07, 0xf6, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1,
    0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f, 0xff };
#endif

typedef struct
{
    UINT *list;
    UINT count;
} CIPHERSUITE;

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
static NX_SECURE_TLS_CRYPTO     tls_ciphers;
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table[20];
extern const NX_SECURE_TLS_CRYPTO
                                nx_crypto_tls_ciphers;
extern NX_SECURE_TLS_CIPHERSUITE_INFO
                                _nx_crypto_ciphersuite_lookup_table[];

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

static UINT ciphersuite_list_0[] = {};
static UINT ciphersuite_list_1[] = {TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_2[] = {TLS_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_3[] = {TLS_RSA_WITH_AES_256_CBC_SHA256};
//static UINT ciphersuite_list_4[] = {TLS_RSA_WITH_NULL_MD5};
//static UINT ciphersuite_list_5[] = {TLS_RSA_WITH_NULL_SHA};
//static UINT ciphersuite_list_6[] = {TLS_PSK_WITH_AES_128_CBC_SHA};
//static UINT ciphersuite_list_7[] = {TLS_PSK_WITH_AES_256_CBC_SHA};
static UINT ciphersuite_list_8[] = {TLS_PSK_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_9[] = {TLS_PSK_WITH_AES_128_CCM_8};
static UINT ciphersuite_list_10[] = {TLS_ECJPAKE_WITH_AES_128_CCM_8};
static UINT ciphersuite_list_11[] = {TLS_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_12[] = {TLS_RSA_WITH_AES_256_CBC_SHA256};
static UINT ciphersuite_list_13[] = {TLS_RSA_WITH_AES_128_GCM_SHA256};
static CIPHERSUITE ciphersuites[] =
{
    CIPHERSUITE_INIT(ciphersuite_list_0),
    CIPHERSUITE_INIT(ciphersuite_list_1),
    CIPHERSUITE_INIT(ciphersuite_list_2),
    CIPHERSUITE_INIT(ciphersuite_list_3),
 //   CIPHERSUITE_INIT(ciphersuite_list_4),
 //   CIPHERSUITE_INIT(ciphersuite_list_5),
#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
 //   CIPHERSUITE_INIT(ciphersuite_list_6),
 //   CIPHERSUITE_INIT(ciphersuite_list_7),
    CIPHERSUITE_INIT(ciphersuite_list_8),
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    CIPHERSUITE_INIT(ciphersuite_list_9),
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */
#if 0 /* ECJPAKE is not supported by TLS now. */
#ifdef NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE
    CIPHERSUITE_INIT(ciphersuite_list_10)
#endif /* NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE */
#endif
    CIPHERSUITE_INIT(ciphersuite_list_11),
    CIPHERSUITE_INIT(ciphersuite_list_12),
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    CIPHERSUITE_INIT(ciphersuite_list_13),
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */
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
VOID    nx_secure_tls_ciphersuites_test_application_define(void *first_unused_memory)
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

static VOID ciphersuites_setup(CIPHERSUITE *ciphersuite)
{
UINT i;
UINT status;
UINT count;

    /* Initialize ciphersuites. */
    memcpy(&tls_ciphers, &nx_crypto_tls_ciphers, sizeof(NX_SECURE_TLS_CRYPTO));
    if (ciphersuite -> count > 0)
    {
        for (count = 0; count < ciphersuite -> count; count++)
        {
            i = 0;
            while (ciphersuite -> list[count] !=
                   (UINT)_nx_crypto_ciphersuite_lookup_table[i].nx_secure_tls_ciphersuite)
            {
                i++;
            }
            memcpy(&ciphersuite_table[count],
                   &_nx_crypto_ciphersuite_lookup_table[i],
                   sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
        }
        tls_ciphers.nx_secure_tls_ciphersuite_lookup_table = ciphersuite_table;
        tls_ciphers.nx_secure_tls_ciphersuite_lookup_table_size = count;
    }
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &tls_ciphers,
                                           client_metadata,
                                           sizeof(client_metadata));
    if (status)
    {
        ERROR_COUNTER(status);
    }

    memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &client_remote_cert,
                                                       client_cert_buffer,
                                                       sizeof(client_cert_buffer));
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca,
                                                   test_ca_cert_der,
                                                   test_ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &client_trusted_ca);
    if (status)
    {
        ERROR_COUNTER(status);
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    if (status)
    {
        ERROR_COUNTER(status);
    }

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    /* For PSK ciphersuites, add a PSK and identity hint.  */
    status = _nx_secure_tls_psk_add(tls_session_ptr, PSK, sizeof(PSK),
                                    PSK_IDENTITY, strlen(PSK_IDENTITY), PSK_HINT, strlen(PSK_HINT));
    if (status)
    {
        ERROR_COUNTER(status);
    }
#endif
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &tls_ciphers,
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
                                                   test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
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

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[1],
                                                     sizeof(tls_packet_buffer[1]));
    if (status)
    {
        ERROR_COUNTER(status);
    }

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    /* For PSK ciphersuites, add a PSK and identity hint.  */
    status = nx_secure_tls_psk_add(tls_session_ptr, PSK, sizeof(PSK),
                                   PSK_IDENTITY, strlen(PSK_IDENTITY), PSK_HINT, strlen(PSK_HINT));
    if (status)
    {
        ERROR_COUNTER(status);
    }
#endif
}

static void ntest_0_entry(ULONG thread_input)
{
UINT i;
UINT status;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Ciphersuites Test..............................");

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

    for (i = 0; i < sizeof(ciphersuites) / sizeof(CIPHERSUITE); i++)
    {

        /* Make sure client thread is ready. */
        tx_thread_suspend(&thread_0);

        ciphersuites_setup(&ciphersuites[i]);

        server_tls_setup(&tls_server_session_0);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER(status);
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                              NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER(status);
        }

        status = nx_secure_tls_session_receive(&tls_server_session_0, &packet_ptr, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER(status);
        }

        nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
        nx_packet_release(packet_ptr);
        if ((response_length != sizeof(request_buffer)) ||
            memcmp(request_buffer, response_buffer, response_length))
        {
            ERROR_COUNTER(status);
        }

        nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
        nx_secure_tls_session_delete(&tls_server_session_0);

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

static void ntest_1_entry(ULONG thread_input)
{
UINT i, j;
UINT status;
NX_PACKET *packet_ptr;
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

    for (i = 0; i < sizeof(ciphersuites) / sizeof(CIPHERSUITE); i++)
    {

        /* Let server thread run first. */
        tx_thread_resume(&thread_0);

        for (j = 0; j < sizeof(request_buffer); j++)
        {
            request_buffer[j] = j;
            response_buffer[j] = 0;
        }

        client_tls_setup(&tls_client_session_0);

        status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                                NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER(status);
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0,
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

        packet_ptr -> nx_packet_prepend_ptr += NX_SECURE_TLS_RECORD_HEADER_SIZE;
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;

        status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                       &pool_0, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER(status);
        }

        /* Send the packet. */
        status = nx_secure_tls_session_send(&tls_client_session_0, packet_ptr, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER(status);
        }

        nx_secure_tls_session_end(&tls_client_session_0, NX_NO_WAIT);
        nx_secure_tls_session_delete(&tls_client_session_0);

        nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    }
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_ciphersuites_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Ciphersuites Test..............................N/A\n");
    test_control_return(3);
}
#endif
