#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"
#include "ecc_certs.c"
#include   "nx_crypto_ecdh.h"
#include "google_cert.c"
#include "test_ca_cert.c"
#include "test_device_cert.c"
#include "nx_secure_tls_test_init_functions.h"

extern void    test_control_return(UINT status);
static NX_IP  ip_0;
static NX_PACKET_POOL       pool_0;
static NX_SECURE_TLS_SESSION session;
static NX_CRYPTO_METHOD fake_crypto_method;
static NX_SECURE_TLS_CRYPTO fake_crypto_table;
static int set_crypto_table = 0;
#define TEST_POOL_NO_CHANGE                   0
#define TEST_POOL_TINY                        1
#define TEST_POOL_NORMAL                      2

static UINT test_packet_pool = TEST_POOL_NO_CHANGE;
#define NUM_PACKETS                 3
#define TINY_PACKET_SIZE             48
#define INVALID_PACKET_SIZE          64
#define SMALL_PACKET_SIZE           128
#define NORMAL_PACKET_SIZE          1500
#define PACKET_POOL_SIZE     (NUM_PACKETS * (NORMAL_PACKET_SIZE + sizeof(NX_PACKET)))
static UCHAR pool_0_memory[PACKET_POOL_SIZE];
static void NX_Secure_TLS_handshake_coverage_test();
#define  NUM_TEST_CERTS    3
NX_SECURE_X509_CERT certificate_array[NUM_TEST_CERTS];

static NX_SECURE_X509_CRYPTO local_cipher_table;


/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_client_handshake_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Client Handshake Coverage Test.................");

#if (NX_SECURE_TLS_TLS_1_2_ENABLED) && (!defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION)) && !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
    NX_Secure_TLS_handshake_coverage_test();

    printf("SUCCESS!\n");

#else
    printf("N/A\n");
#endif

    test_control_return(0);

}

#if (NX_SECURE_TLS_TLS_1_2_ENABLED) && (!defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION)) && !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_DISABLE_X509)

static VOID forward_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

    packet_ptr -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];

}
static NX_TCP_SOCKET        tcp_socket;
static int driver_entry_count = 0;
/* Note that the first invokation of the driver entry function is at line 454 of nx_secure_tls_client_handshake.c */
static VOID link_driver_entry(NX_IP_DRIVER *drv_ptr)
{
    driver_entry_count++;


    if((driver_entry_count == 2) || (driver_entry_count == 9) || (driver_entry_count == 13))
    {
        /* Test line 505. */
        nx_packet_pool_delete(&pool_0);
        nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TINY_PACKET_SIZE,
                              pool_0_memory, PACKET_POOL_SIZE);
    }
    else if(driver_entry_count == 4)
    {
        /* Remove local certificate. This causes failure around line 508 */
        _nx_secure_x509_store_certificate_remove(&session.nx_secure_tls_credentials.nx_secure_tls_certificate_store, NX_NULL, NX_SECURE_X509_CERT_LOCATION_LOCAL, 0);
    }
    else if(driver_entry_count == 6)
    {
        /* Remove nx_tcp_socket_bound_next value.. which causes line 515 to fail. */
        tcp_socket.nx_tcp_socket_bound_next = NX_NULL;
    }
#if 1
    else if (driver_entry_count == 17)
    {
        nx_packet_pool_delete(&pool_0);
        nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", INVALID_PACKET_SIZE,
                              pool_0_memory, ((INVALID_PACKET_SIZE + sizeof(NX_PACKET)) * 2 - 1));

    }
#endif   
    if(drv_ptr -> nx_ip_driver_packet)
        nx_packet_release(drv_ptr -> nx_ip_driver_packet);
    
}

static int cleanup_call_count = 0;
static NX_SECURE_TLS_CRYPTO fake_crypto_table;
static NX_CRYPTO_METHOD     fake_sha256_method;


static NX_SECURE_TLS_CLIENT_STATE test_client_state = 0xFF;
static int cleanup_iteration = 0;
static volatile int call_count = 1;
static int iteration = 0;
static int install_remote_cert = 0;
static int set_client_certificate_requested = 0;
static UINT fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                      UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                      VOID **handler,
                      VOID *crypto_metadata,
                      ULONG crypto_metadata_size)
{

    return(NX_CRYPTO_SUCCESS);
}

static UINT fake_operation(UINT op,       /* Encrypt, Decrypt, Authenticate */
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

    if((call_count++ == iteration) )
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
    
}

static UINT fake_sha256_cleanup(VOID *crypto_metadata)
{

    if(cleanup_call_count++ == 0)
        return(NX_CRYPTO_NOT_SUCCESSFUL);

    if(test_client_state != 0xFF)
        session.nx_secure_tls_client_state = test_client_state;

    if(test_packet_pool == TEST_POOL_TINY)
    {
        if(pool_0.nx_packet_pool_payload_size != TINY_PACKET_SIZE)
        {
            


            nx_packet_pool_delete(&pool_0);
            nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TINY_PACKET_SIZE,
                                  pool_0_memory, PACKET_POOL_SIZE);
        }
    }
    else if(test_packet_pool == TEST_POOL_NORMAL)
    {
        if((pool_0.nx_packet_pool_payload_size != NORMAL_PACKET_SIZE) || (install_remote_cert == 1))
        {
            nx_secure_x509_certificate_initialize(&certificate_array[0], google_cert_der, google_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
            /* Add our certificates to the store. */
            _nx_secure_x509_store_certificate_add(&certificate_array[0], &session.nx_secure_tls_credentials.nx_secure_tls_certificate_store,
                                                  NX_SECURE_X509_CERT_LOCATION_REMOTE);    
            nx_packet_pool_delete(&pool_0);
            nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
                                  pool_0_memory, PACKET_POOL_SIZE);
        }
    }
    if(set_client_certificate_requested)
    {        
        nx_secure_x509_certificate_initialize(&certificate_array[2], test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
        /* Add our certificates to the store. */
        _nx_secure_x509_store_certificate_add(&certificate_array[2], &session.nx_secure_tls_credentials.nx_secure_tls_certificate_store,
                                              NX_SECURE_X509_CERT_LOCATION_LOCAL);    
        session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates->nx_secure_x509_certificate_is_identity_cert = 1;
        session.nx_secure_tls_client_certificate_requested = 1;

        if(set_crypto_table == 1)
        {
            local_cipher_table.nx_secure_x509_crypto_identifier = 4;
            local_cipher_table.nx_secure_x509_public_cipher_method = &fake_sha256_method;
            certificate_array[2].nx_secure_x509_cipher_table_size = 1;
            certificate_array[2].nx_secure_x509_cipher_table = &local_cipher_table;
        }

    }
    return(NX_CRYPTO_SUCCESS);
}

static UINT fake_crypto_cleanup(VOID* crypto_metadata)
{


    return(NX_CRYPTO_SUCCESS);
}

static UINT renegotiation_callback_count = 0;
static ULONG fake_renegotiation_callback(NX_SECURE_TLS_SESSION *tls_session)
{
    if(renegotiation_callback_count++ == 0)
        return(NX_NOT_SUCCESSFUL);
    
    return(NX_SUCCESS);
}
            

#if 0
static UCHAR handshake_hash_scratch[100];
#endif
#define SHA256_METADATA_SIZE 10
static UCHAR sha256_metadata[SHA256_METADATA_SIZE];
#define DATA_BUFFER_SIZE 100
static UCHAR data_buffer[DATA_BUFFER_SIZE];
static USHORT temp_crypto_algorithm;

static void setup_socket(void);

static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc_test =
{
    /* Ciphersuite,                           public cipher,             public_auth,                 session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &fake_crypto_method, &fake_crypto_method, &fake_crypto_method,     16,      16,        &fake_crypto_method,     32,        &fake_crypto_method
};


static const UINT _nx_crypto_ciphersuite_lookup_table_ecc_test_size = sizeof(_nx_crypto_ciphersuite_lookup_table_ecc_test) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO);


TEST(NX_Secure_TLS, handshake_coverage_test)
{
UINT status;
UINT header_size, message_length;

    
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", SMALL_PACKET_SIZE,
                                    pool_0_memory, PACKET_POOL_SIZE);
    fake_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &fake_sha256_method;
    session.nx_secure_tls_crypto_table = &fake_crypto_table;
    nx_secure_tls_test_init_functions(&session);

    /* Cover line 163 */
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 2, NX_NO_WAIT);
    //    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);


    /* fill in a fake header */
    data_buffer[0] = NX_SECURE_TLS_FINISHED;
    /* Set message length 10 */
    data_buffer[1] = 0;
    data_buffer[2] = 0;
    data_buffer[3] = 10;
    session.nx_secure_tls_packet_pool = &pool_0;
    session.nx_secure_tls_tcp_socket = &tcp_socket;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    
    /* Cover line 237 */
   // fake_sha256_method.nx_crypto_init = fake_init;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);
    
    /* Cover line 232 */
    fake_sha256_method.nx_crypto_init = NX_NULL;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);


    /* Cover line 276, 395 */
    data_buffer[0] = NX_SECURE_TLS_HELLO_REQUEST;
    session.nx_secure_tls_local_session_active = NX_TRUE;
    session.nx_secure_tls_renegotation_enabled = NX_TRUE;
    session.nx_secure_tls_secure_renegotiation  = NX_FALSE;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_NO_RENEGOTIATION_ERROR, status);

    /* Cover line 360, 378*/
    session.nx_secure_tls_secure_renegotiation  = NX_TRUE;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);

    /* Install valid cipihersuite. */
    session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table_ecc_test;
    session.nx_secure_tls_session_id_length = 100;
    /* Cover line 386 */
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

    /* Cover line 366 */
    nx_packet_pool_delete(&pool_0);
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
                                    pool_0_memory, PACKET_POOL_SIZE);

    session.nx_secure_tls_session_renegotiation_callback = fake_renegotiation_callback;
    session.nx_secure_tls_session_id_length = 0;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);

    /* Cover line 386 */
    nx_packet_pool_delete(&pool_0);
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", SMALL_PACKET_SIZE,
        pool_0_memory, PACKET_POOL_SIZE);
    session.nx_secure_tls_session_id_length = 255;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

#if 0
    data_buffer[0] = NX_SECURE_TLS_FINISHED;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);   
#endif

    /* Cover line 232 */
    fake_sha256_method.nx_crypto_cleanup = NX_NULL;
    fake_sha256_method.nx_crypto_operation = fake_operation;
    fake_sha256_method.nx_crypto_init = fake_init;
    fake_crypto_method.nx_crypto_init = fake_init;
    fake_crypto_method.nx_crypto_operation = fake_operation;
    fake_crypto_method.nx_crypto_cleanup = fake_crypto_cleanup;
    data_buffer[0] = NX_SECURE_TLS_FINISHED;
    /* Set message length 12 */
    data_buffer[1] = 0;
    data_buffer[2] = 0;
    data_buffer[3] = 12;
    session.nx_secure_tls_remote_session_active = NX_TRUE;
    session.nx_secure_tls_received_remote_credentials = NX_TRUE;
    session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

    /* Cover line 237 */
    fake_sha256_method.nx_crypto_cleanup = fake_sha256_cleanup;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, DATA_BUFFER_SIZE, NX_NO_WAIT);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);


    test_client_state = NX_SECURE_TLS_CLIENT_STATE_IDLE;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SUCCESS, status);

    test_client_state = NX_SECURE_TLS_CLIENT_STATE_RENEGOTIATING;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SUCCESS, status);

    test_client_state = NX_SECURE_TLS_CLIENT_STATE_ERROR;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_HANDSHAKE_FAILURE, status);

    test_client_state = NX_SECURE_TLS_CLIENT_STATE_ALERT_SENT;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_HANDSHAKE_FAILURE, status);

#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION 
    test_client_state = NX_SECURE_TLS_CLIENT_STATE_HELLO_REQUEST;

    /* Test 4 conditions at line 357.*/
    session.nx_secure_tls_renegotation_enabled = NX_TRUE;
    session.nx_secure_tls_secure_renegotiation = NX_TRUE;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);

    session.nx_secure_tls_renegotation_enabled = NX_FALSE;
    session.nx_secure_tls_secure_renegotiation = NX_TRUE;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_NO_RENEGOTIATION_ERROR, status);

    session.nx_secure_tls_renegotation_enabled = NX_TRUE;
    session.nx_secure_tls_secure_renegotiation = NX_FALSE;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_NO_RENEGOTIATION_ERROR, status);

    session.nx_secure_tls_renegotation_enabled = NX_FALSE;
    session.nx_secure_tls_secure_renegotiation = NX_FALSE;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_NO_RENEGOTIATION_ERROR, status);

    /* Test line 360 */
    session.nx_secure_tls_renegotation_enabled = NX_TRUE;
    session.nx_secure_tls_secure_renegotiation = NX_TRUE;
    session.nx_secure_tls_session_renegotiation_callback = fake_renegotiation_callback;
    renegotiation_callback_count = 0;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);

    /* Test line 354 */
    session.nx_secure_tls_local_session_active = NX_FALSE;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SUCCESS, status);


    /* Test line 376 */

    /* Test line 386 */

#endif /* NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION */

    test_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVERHELLO;

    session.nx_secure_tls_key_material.nx_secure_tls_handshake_cache_length = 0;
    call_count = 0;
    iteration = 2;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SUCCESS, status);

    session.nx_secure_tls_key_material.nx_secure_tls_handshake_cache_length = 10;
    call_count = 0;
    iteration = 2;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);



    /* Test Line 444 */
    test_client_state = NX_SECURE_TLS_CLIENT_STATE_SERVERHELLO_DONE;
    session.nx_secure_tls_client_certificate_requested = NX_TRUE;
    nx_packet_pool_delete(&pool_0);
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TINY_PACKET_SIZE,
                                    pool_0_memory, PACKET_POOL_SIZE);
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);

    /* Test Line 466 */
    session.nx_secure_tls_client_certificate_requested = NX_FALSE;
    //nx_packet_pool_delete(&pool_0);
    
    temp_crypto_algorithm = fake_crypto_method.nx_crypto_algorithm;
    fake_crypto_method.nx_crypto_algorithm = NX_CRYPTO_KEY_EXCHANGE_ECDH;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    //EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);
    fake_crypto_method.nx_crypto_algorithm = temp_crypto_algorithm;

    /* Test Line 482 */
    nx_packet_pool_delete(&pool_0);
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
        pool_0_memory, PACKET_POOL_SIZE);
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_NO_CERT_SPACE_ALLOCATED, status);

    /* Test Line 474 */
    test_packet_pool = TEST_POOL_TINY;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);

    /* Test Line 489 */
    test_packet_pool = TEST_POOL_NORMAL;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_NOT_BOUND, status);



     /* Test Line 505 */
    nx_packet_pool_delete(&pool_0);
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
                                   pool_0_memory, PACKET_POOL_SIZE);
    /* Add our certificates to the store. */
    install_remote_cert = 1;
    set_client_certificate_requested = 1;
    setup_socket();
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);


     /* Test Line 512 */
    nx_packet_pool_delete(&pool_0);
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
                                   pool_0_memory, PACKET_POOL_SIZE);
    setup_socket();
    
    set_client_certificate_requested = 1;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

     /* Test Line 519 */
    nx_packet_pool_delete(&pool_0);
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
                                   pool_0_memory, PACKET_POOL_SIZE);
    set_client_certificate_requested = 1;
    set_crypto_table = 1;
    setup_socket();
    //tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 0;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_NOT_BOUND, status);
    //set_crypto_table = 0;

    /* Test Line 546 */
    nx_packet_pool_delete(&pool_0);
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
                                   pool_0_memory, PACKET_POOL_SIZE);
    set_crypto_table = 1;
    set_client_certificate_requested = 1;
    setup_socket();
    fake_crypto_method.nx_crypto_algorithm = NX_CRYPTO_KEY_EXCHANGE_RSA;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Test Line 578 */
    nx_packet_pool_delete(&pool_0);
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
                                   pool_0_memory, PACKET_POOL_SIZE);
    set_crypto_table = 1;
    set_client_certificate_requested = 1;
    setup_socket();
    fake_crypto_method.nx_crypto_algorithm = NX_CRYPTO_KEY_EXCHANGE_RSA;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);

     /* Test Line 618 */
    nx_packet_pool_delete(&pool_0);
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
        pool_0_memory, PACKET_POOL_SIZE);
    set_crypto_table = 1;
    set_client_certificate_requested = 1;
    setup_socket();
    fake_crypto_method.nx_crypto_algorithm = NX_CRYPTO_KEY_EXCHANGE_RSA;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
#if 0
    nx_packet_pool_delete(&pool_0);
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NORMAL_PACKET_SIZE,
        pool_0_memory, PACKET_POOL_SIZE);
    set_crypto_table = 1;
    set_client_certificate_requested = 1;
    setup_socket();
    fake_crypto_method.nx_crypto_algorithm = NX_CRYPTO_KEY_EXCHANGE_RSA;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SUCCESS, status);
#endif
    test_client_state = NX_SECURE_TLS_CLIENT_STATE_HELLO_VERIFY;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_STATE, status);

    test_client_state = 0xf0;
    status = _nx_secure_tls_client_handshake(&session, data_buffer, 16, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_STATE, status);

}

static void setup_socket(void)
{

    ip_0.nx_ip_interface[0].nx_interface_ip_address = 0x01020305;
    ip_0.nx_ip_interface[0].nx_interface_ip_network_mask = 0xffffff00;
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_TRUE;
    ip_0.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;
    ip_0.nx_ip_interface[0].nx_interface_ip_network = 0x01020300;
    ip_0.nx_ip_interface[0].nx_interface_ip_mtu_size = 1500;
    ip_0.nx_ip_interface[0].nx_interface_link_driver_entry = link_driver_entry;
    ip_0.nx_ip_forward_packet_process = forward_packet_process;
    
    tcp_socket.nx_tcp_socket_bound_next = tcp_socket.nx_tcp_socket_bound_previous = &tcp_socket;
    tcp_socket.nx_tcp_socket_ip_ptr = &ip_0;
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = 0x01020304;
    tcp_socket.nx_tcp_socket_connect_mss = 1460;
    tcp_socket.nx_tcp_socket_tx_window_advertised = 8192;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 8192;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 0;
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_transmit_queue_maximum = 2000;
    tcp_socket.nx_tcp_socket_rx_window_current = 3200;
    tcp_socket.nx_tcp_socket_transmit_sent_head = NX_NULL;
    tcp_socket.nx_tcp_socket_transmit_sent_count = 0;
    tcp_socket.nx_tcp_socket_bytes_sent = 0;




}


#endif


