/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"
#include "ecc_certs.c"
#include   "nx_crypto_ecdh.h"
#include "google_cert.c"
#include "test_ca_cert.c"
#include "test_device_cert.c"

extern volatile ULONG _tx_thread_preempt_disable;

extern VOID    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED)
#define THREAD_STACK_SIZE           1024
#define METADATA_SIZE               16000

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);

static NX_SECURE_TLS_SESSION tls_session;
static NX_PACKET send_packet;
static NX_TCP_SOCKET tcp_socket;
static NX_IP ip_0;
static NX_CRYPTO_METHOD fake_crypto_method;

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_send_record_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Create the client thread.  */
    tx_thread_create(&ip_0.nx_ip_thread, "test thread",  ntest_0_entry, 0, 
                     thread_0_stack, sizeof(thread_0_stack),
                     1, 1, TX_NO_TIME_SLICE, TX_AUTO_START);


}
static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc_test =
{
    /* Ciphersuite,                           public cipher,             public_auth,                 session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &fake_crypto_method, &fake_crypto_method, &fake_crypto_method,     16,      16,        &fake_crypto_method,     32,        &fake_crypto_method
};


static const UINT _nx_crypto_ciphersuite_lookup_table_ecc_test_size = sizeof(_nx_crypto_ciphersuite_lookup_table_ecc_test) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO);

static volatile int call_count = 1;
static int iteration = 0;
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


static UINT fake_crypto_cleanup(VOID* crypto_metadata)
{


    return(NX_CRYPTO_SUCCESS);
}

            

static UCHAR buffer[100];


static void ntest_0_entry(ULONG thread_input)
{
UINT status;
UINT saved_value;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Send Record Coverage Test .......");

    fake_crypto_method.nx_crypto_init = fake_init;
    fake_crypto_method.nx_crypto_operation = fake_operation;
    fake_crypto_method.nx_crypto_cleanup = fake_crypto_cleanup;
    fake_crypto_method.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CBC;
    fake_crypto_method.nx_crypto_IV_size_in_bits = 8*8;
    fake_crypto_method.nx_crypto_block_size_in_bytes = 8;

    /* Cover line 113-115 */
    tls_session.nx_secure_tls_session_transmit_mutex.tx_mutex_ownership_count = 1;
    saved_value = _tx_thread_preempt_disable;
    _tx_thread_preempt_disable = 1;

    tls_session.nx_secure_tls_tcp_socket = NX_NULL;
    status = _nx_secure_tls_send_record(&tls_session, &send_packet, 0, 0);
    
    tls_session.nx_secure_tls_tcp_socket = &tcp_socket;
    status = _nx_secure_tls_send_record(&tls_session, &send_packet, 0, 0);

    tcp_socket.nx_tcp_socket_ip_ptr = &ip_0;
    status = _nx_secure_tls_send_record(&tls_session, &send_packet, 0, 0);

    tls_session.nx_secure_tls_session_transmit_mutex.tx_mutex_ownership_count = 0;
    _tx_thread_preempt_disable = saved_value;

    /* Cover line (170, 174, 175) */
    send_packet.nx_packet_prepend_ptr = send_packet.nx_packet_data_start + 8;
    tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table_ecc_test;
    tls_session.nx_secure_tls_local_session_active = 1;
    status = _nx_secure_tls_send_record(&tls_session, &send_packet, 0, 0);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    /* Cover line 323, 332 */
    send_packet.nx_packet_prepend_ptr = buffer + 20;
    send_packet.nx_packet_data_start = buffer;
    send_packet.nx_packet_append_ptr = send_packet.nx_packet_prepend_ptr + 20;
    tls_session.nx_secure_tls_key_material.nx_secure_tls_client_iv = buffer;
    tls_session.nx_secure_tls_local_sequence_number[0] = 0xFFFFFFFF;
    status = _nx_secure_tls_send_record(&tls_session, &send_packet, 0, 0);

    /* Cover line 329 */
    send_packet.nx_packet_prepend_ptr = buffer + 20;
    send_packet.nx_packet_data_start = buffer;
    send_packet.nx_packet_append_ptr = send_packet.nx_packet_prepend_ptr + 20;
    tls_session.nx_secure_tls_key_material.nx_secure_tls_client_iv = buffer;
    tls_session.nx_secure_tls_local_sequence_number[0] = 0xFFFFFFFF;
    tls_session.nx_secure_tls_local_sequence_number[1] = 0xFFFFFFFF;
    status = _nx_secure_tls_send_record(&tls_session, &send_packet, 0, 0);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);

    printf("SUCCESS!\n");
    test_control_return(0);


}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_shutdown_test_application_define(void *first_unused_memory)
#endif
{
    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Send Record Coverage Test .......N/A\n");
    test_control_return(3);
}
#endif
