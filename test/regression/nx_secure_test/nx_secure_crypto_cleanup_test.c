/* This test concentrates on nx_crypto_init and nx_crypto_cleanup are used.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"
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
#define PSK                         "simple_psk"
#define PSK_IDENTITY                "psk_indentity"
#define PSK_HINT                    "psk_hint"
#define SERVER_PORT                 4433
#define NUMBER_OF_HANDLERS          10
#define NUMBER_OF_RESOURCES         128

typedef struct HANDLER_STRUCT
{
    const NX_CRYPTO_METHOD   *original_crypto_method;
    NX_CRYPTO_METHOD    test_crypto_method;
    UINT                inited;
    VOID               *metadata_area;
} HANDLER;

typedef struct RESOURCE_STRUCT
{
    const NX_CRYPTO_METHOD *crypto_method;
    UINT              in_use;
    VOID             *resource;
} RESOURCE;

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
                                ciphersuite_table;
extern const NX_SECURE_TLS_CRYPTO
                                nx_crypto_tls_ciphers;

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

static HANDLER                  handlers[NUMBER_OF_HANDLERS];
static UINT                     handlers_count;

static RESOURCE                 resource_records[NUMBER_OF_RESOURCES];
static UINT                     resource_record_count;

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static UINT    crypto_init(NX_CRYPTO_METHOD *method,
                           UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                           VOID **handler,
                           VOID *crypto_metadata,
                           ULONG crypto_metadata_size);
static UINT    crypto_cleanup(VOID *handler);
static UINT    crypto_operation(UINT op,
                                VOID *handler,
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
                                VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status));


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
VOID    nx_secure_crypto_cleanup_test_application_define(void *first_unused_memory)
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

static HANDLER *find_handler(const NX_CRYPTO_METHOD *crypto_method, UINT is_original)
{
UINT i;

    for (i = 0; i < handlers_count; i++)
    {
        if (is_original)
        {
            if (handlers[i].original_crypto_method == crypto_method)
            {
                return(&handlers[i]);
            }
        }
        else
        {
            if (&handlers[i].test_crypto_method == crypto_method)
            {
                return(&handlers[i]);
            }
        }
    }

    return(NX_NULL);
}

static VOID insert_handler(const NX_CRYPTO_METHOD **crypto_method)
{
HANDLER *handler_ptr;

    if (*crypto_method == NX_NULL)
    {
        return;
    }

    if ((*crypto_method) -> nx_crypto_operation == NX_NULL)
    {
        return;
    }

    handler_ptr = find_handler(*crypto_method, NX_CRYPTO_TRUE);

    /* Crypto method already modified. */
    if (handler_ptr != NX_NULL)
    {
        *crypto_method = &(handler_ptr -> test_crypto_method);
        return;
    }

    EXPECT_TRUE(handlers_count < NUMBER_OF_HANDLERS);

    handlers[handlers_count].original_crypto_method = *crypto_method;
    memcpy(&handlers[handlers_count].test_crypto_method, *crypto_method, sizeof(NX_CRYPTO_METHOD));

    /* Redirect the function pointers. */
    handlers[handlers_count].test_crypto_method.nx_crypto_init = crypto_init;
    handlers[handlers_count].test_crypto_method.nx_crypto_cleanup = crypto_cleanup;
    handlers[handlers_count].test_crypto_method.nx_crypto_operation = crypto_operation;

    handlers[handlers_count].inited = 0;
    handlers[handlers_count].metadata_area = NX_NULL;

    *crypto_method = &handlers[handlers_count].test_crypto_method;

    handlers_count++;
}

static VOID check_handler()
{
UINT i;

    /* All resources are not expected to be in use. */
    for (i = 0; i < resource_record_count; i++)
    {
        EXPECT_EQ(resource_records[i].in_use, 0);
    }
}

static VOID ciphersuites_setup(UINT i)
{

    /* Initialize ciphersuites. */
    memcpy(&tls_ciphers, &nx_crypto_tls_ciphers, sizeof(NX_SECURE_TLS_CRYPTO));
    tls_ciphers.nx_secure_tls_ciphersuite_lookup_table = &ciphersuite_table;
    tls_ciphers.nx_secure_tls_ciphersuite_lookup_table_size = 1;
    memcpy(&ciphersuite_table,
           &nx_crypto_tls_ciphers.nx_secure_tls_ciphersuite_lookup_table[i],
           sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));

    handlers_count = 0;
    resource_record_count = 0;

    insert_handler(&ciphersuite_table.nx_secure_tls_public_cipher);
    insert_handler(&ciphersuite_table.nx_secure_tls_public_auth);
    insert_handler(&ciphersuite_table.nx_secure_tls_session_cipher);
    insert_handler(&ciphersuite_table.nx_secure_tls_hash);
    insert_handler(&ciphersuite_table.nx_secure_tls_prf);
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    insert_handler(&tls_ciphers.nx_secure_tls_handshake_hash_md5_method);
    insert_handler(&tls_ciphers.nx_secure_tls_handshake_hash_sha1_method);
    insert_handler(&tls_ciphers.nx_secure_tls_prf_1_method);
#endif /* (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED) */
#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    insert_handler(&tls_ciphers.nx_secure_tls_handshake_hash_sha256_method);
    insert_handler(&tls_ciphers.nx_secure_tls_prf_sha256_method);
#endif /* (NX_SECURE_TLS_TLS_1_2_ENABLED) */
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

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca,
                                                   test_ca_cert_der,
                                                   test_ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
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

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    /* For PSK ciphersuites, add a PSK and identity hint.  */
    nx_secure_tls_psk_add(tls_session_ptr, PSK, strlen(PSK),
                         PSK_IDENTITY, strlen(PSK_IDENTITY), PSK_HINT, strlen(PSK_HINT));
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
        ERROR_COUNTER();
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   test_device_cert_der, test_device_cert_der_len,
                                                   NX_NULL, 0, test_device_cert_key_der,
                                                   test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
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

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    /* For PSK ciphersuites, add a PSK and identity hint.  */
    nx_secure_tls_psk_add(tls_session_ptr, PSK, strlen(PSK),
                         PSK_IDENTITY, strlen(PSK_IDENTITY), PSK_HINT, strlen(PSK_HINT));
#endif
}

static void ntest_0_entry(ULONG thread_input)
{
UINT i;
UINT status;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   Crypto Cleanup Test................................");

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

    for (i = 0; i < nx_crypto_tls_ciphers.nx_secure_tls_ciphersuite_lookup_table_size; i++)
    {

        /* Make sure client thread is ready. */
        tx_thread_suspend(&thread_0);

        ciphersuites_setup(i);

        server_tls_setup(&tls_server_session_0);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                              NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        status = nx_secure_tls_session_receive(&tls_server_session_0, &packet_ptr, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
        nx_packet_release(packet_ptr);
        if ((response_length != sizeof(request_buffer)) ||
            memcmp(request_buffer, response_buffer, response_length))
        {
            ERROR_COUNTER();
        }

        nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
        nx_secure_tls_session_delete(&tls_server_session_0);

        nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
        nx_tcp_server_socket_unaccept(&server_socket_0);
        nx_tcp_server_socket_relisten(&ip_0, SERVER_PORT, &server_socket_0);
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
        ERROR_COUNTER();
    }

    status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    for (i = 0; i < nx_crypto_tls_ciphers.nx_secure_tls_ciphersuite_lookup_table_size; i++)
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
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0,
                                              NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Attempt a renegotiation. */
#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_TLS_DISABLE_CLIENT_INITIATED_RENEGOTIATION)
        status = nx_secure_tls_session_renegotiate(&tls_client_session_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }
#endif

        /* Prepare packet to send. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        packet_ptr -> nx_packet_prepend_ptr += NX_SECURE_TLS_RECORD_HEADER_SIZE;
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;

        status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                       &pool_0, NX_NO_WAIT);
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

        nx_secure_tls_session_end(&tls_client_session_0, NX_NO_WAIT);
        nx_secure_tls_session_delete(&tls_client_session_0);

        nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
        check_handler();
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

static UINT    crypto_init(NX_CRYPTO_METHOD *method,
                           UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                           VOID **handler,
                           VOID *crypto_metadata,
                           ULONG crypto_metadata_size)
{
const NX_CRYPTO_METHOD *original_crypto_method;
HANDLER *handle;

    handle = find_handler(method, NX_CRYPTO_FALSE);
    EXPECT_TRUE(handle != NX_NULL);

    original_crypto_method = handle -> original_crypto_method;
    handle -> inited = 1;

    /* Add resource record. */
    resource_records[resource_record_count].in_use = 1;
    resource_records[resource_record_count].crypto_method = original_crypto_method;
    resource_records[resource_record_count].resource = crypto_metadata;
    resource_record_count++;

    /* Call original_crypto_method. */
    if (original_crypto_method -> nx_crypto_init)
    {
        return(original_crypto_method -> nx_crypto_init((NX_CRYPTO_METHOD*)original_crypto_method,
                                                        key,
                                                        key_size_in_bits,
                                                        NX_NULL,
                                                        crypto_metadata,
                                                        crypto_metadata_size));
    }
    else
    {
        return(NX_CRYPTO_SUCCESS);
    }
}

static UINT    crypto_cleanup(VOID *metadata)
{
const NX_CRYPTO_METHOD *original_crypto_method;
HANDLER          *handler = NX_NULL;
UINT              i, found = 0;

    EXPECT_TRUE(metadata != NX_NULL);

    /* Find the handler by metadata pointer. */
    for (i = 0; i < resource_record_count; i++)
    {
        /* Mark the resource released. */
        if  (resource_records[i].in_use && resource_records[i].resource == metadata)
        {
            original_crypto_method = resource_records[i].crypto_method;
            resource_records[i].in_use = 0;
            found = 1;
            break;
        }
    }

    EXPECT_TRUE(found);

    if (original_crypto_method -> nx_crypto_cleanup)
    {
        return(original_crypto_method -> nx_crypto_cleanup(metadata));
    }
    else
    {
        return(NX_CRYPTO_SUCCESS);
    }
}

static UINT    crypto_operation(UINT op,
                                VOID *handler,
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
const NX_CRYPTO_METHOD *original_crypto_method;
HANDLER          *handle;

    handle = find_handler(method, NX_CRYPTO_FALSE);
    EXPECT_TRUE(handle != NX_NULL);
    EXPECT_TRUE(handle -> inited);

    original_crypto_method = handle -> original_crypto_method;
    return(original_crypto_method -> nx_crypto_operation(op,
                                                         NX_NULL,
                                                         (NX_CRYPTO_METHOD*)original_crypto_method,
                                                         key,
                                                         key_size_in_bits,
                                                         input,
                                                         input_length_in_byte,
                                                         iv_ptr,
                                                         output,
                                                         output_length_in_byte,
                                                         crypto_metadata,
                                                         crypto_metadata_size,
                                                         packet_ptr,
                                                         nx_crypto_hw_process_callback));
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_crypto_cleanup_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   Crypto Cleanup Test................................N/A\n");
    test_control_return(3);
}
#endif
