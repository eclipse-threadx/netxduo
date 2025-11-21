/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"
#include "nx_tcp.h"
#include "nx_packet.h"
#if 0
#include "ecc_certs.c"
#include "nx_crypto_ecdh.h"
#include "google_cert.c"
#include "test_ca_cert.c"
#include "test_device_cert.c"
#endif
#include "nx_secure_tls_test_init_functions.h"

extern VOID    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED)
#define THREAD_STACK_SIZE           1024
#define METADATA_SIZE               16000

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);

static NX_SECURE_TLS_SESSION tls_session;
static NX_PACKET send_packet;
static NX_TCP_SOCKET tcp_socket;
static NX_IP ip_0;
static NX_CRYPTO_METHOD fake_crypto_method;
static NX_PACKET_POOL pool_0;
#define PACKET_SIZE 256
#define PACKET_POOL_SIZE ((PACKET_SIZE + sizeof(NX_PACKET)) * 3)
#define CIPHERTEXT_LENGTH 50
static ULONG pool_0_memory[PACKET_POOL_SIZE/sizeof(ULONG)];



#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_session_receive_coverage_test_application_define(void *first_unused_memory)
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


static UINT fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                      UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                      VOID **handler,
                      VOID *crypto_metadata,
                      ULONG crypto_metadata_size)
{

    return(NX_CRYPTO_SUCCESS);
}
static UINT counter = 0;
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
    counter++;
//    printf("Iteration %d\n", counter);
    if(counter == 16)
        tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_HANDSHAKE_FINISHED;
    return(NX_CRYPTO_SUCCESS);
    
}


static UINT fake_cleanup(VOID* crypto_metadata)
{


    return(NX_CRYPTO_SUCCESS);
}

static NX_SECURE_TLS_CIPHERSUITE_INFO fake_tls_session_ciphersuite;
static NX_CRYPTO_METHOD fake_crypto_method;
            

static UCHAR buffer[100];
static UCHAR tls_packet_buffer[100];
static UCHAR next_packet_buffer[100];


static void prepare_next_packet(void)
{
NX_TCP_HEADER *tcp_header;
UCHAR *write_ptr;
NX_PACKET *packet2_ptr;
UINT data_length = CIPHERTEXT_LENGTH + 1;

    tls_session.nx_secure_tls_tcp_socket = &tcp_socket;
    tcp_socket.nx_tcp_socket_ip_ptr = &ip_0;
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_receive_queue_count = 1;
    tcp_socket.nx_tcp_socket_rx_window_default = 1000;
    tcp_socket.nx_tcp_socket_rx_window_last_sent = 900;

    tcp_header = (NX_TCP_HEADER*)next_packet_buffer;

    tcp_header -> nx_tcp_header_word_0 = 0; /* SRC/DEST port numbers. Don't care in this case. */
    tcp_header -> nx_tcp_sequence_number = 0; /* SEQ, don't care in this case. */
    tcp_header -> nx_tcp_acknowledgment_number = 0; /* ACK, don't care in this case. */
    tcp_header -> nx_tcp_header_word_3 = NX_TCP_HEADER_SIZE;

    write_ptr = next_packet_buffer + sizeof(NX_TCP_HEADER);
    *write_ptr++ = NX_SECURE_TLS_APPLICATION_DATA;
    *write_ptr++ = (NX_SECURE_TLS_VERSION_TLS_1_2 >> 8);
    *write_ptr++ = (NX_SECURE_TLS_VERSION_TLS_1_2 & 0xff);
    *write_ptr++ = ((data_length >> 8) & 0xFF);
    *write_ptr++ = (data_length & 0xff);

    nx_packet_allocate(&pool_0, &packet2_ptr, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    nx_packet_data_append(packet2_ptr, next_packet_buffer, sizeof(NX_TCP_HEADER) + 5 + data_length, &pool_0, NX_WAIT_FOREVER);
    packet2_ptr -> nx_packet_queue_next = (NX_PACKET*)NX_PACKET_READY;
    tcp_socket.nx_tcp_socket_receive_queue_head = packet2_ptr;
}

static void ntest_0_entry(ULONG thread_input)
{
UINT status;
NX_PACKET *packet_ptr;
NX_PACKET *packet2_ptr;

ULONG data_length;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Session Receive Coverage Test ...");

    nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pool_0_memory, PACKET_POOL_SIZE);
    nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    data_length = CIPHERTEXT_LENGTH + 1;

    buffer[0] = NX_SECURE_TLS_APPLICATION_DATA;
    buffer[1] = (NX_SECURE_TLS_VERSION_TLS_1_2 >> 8);
    buffer[2] = (NX_SECURE_TLS_VERSION_TLS_1_2 & 0xff);
    buffer[3] = ((data_length >> 8) & 0xFF);
    buffer[4] = (data_length & 0xff);
    nx_packet_data_append(packet_ptr, buffer, 5 + data_length, &pool_0, NX_WAIT_FOREVER);
    /* intentionally corrupt the packet structure, to test nx_secure_tls_session_receive_record.c line 206. */
    packet_ptr->nx_packet_append_ptr -= 10;

    nx_secure_tls_test_init_functions(&tls_session);
    tls_session.nx_secure_record_queue_header = packet_ptr;
    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    tls_session.nx_secure_tls_packet_buffer = tls_packet_buffer;
    tls_session.nx_secure_tls_packet_buffer_size = sizeof(tls_packet_buffer);

    status = _nx_secure_tls_session_receive_records(&tls_session, NX_NULL, NX_WAIT_FOREVER);

    nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    tls_session.nx_secure_tls_server_state = NX_SECURE_TLS_SERVER_STATE_HANDSHAKE_FINISHED;

    nx_packet_data_append(packet_ptr, buffer, 5 + data_length, &pool_0, NX_WAIT_FOREVER);
    tls_session.nx_secure_record_queue_header = packet_ptr;
    /* test line 236 */
    status = _nx_secure_tls_session_receive_records(&tls_session, NX_NULL, NX_WAIT_FOREVER);
    
    /* Test nx_secure_tls_session_recieve.c line 136 */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    nx_packet_data_append(packet_ptr, buffer, 5 + data_length, &pool_0, NX_WAIT_FOREVER);
    tls_session.nx_secure_record_queue_header = packet_ptr;
    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    tls_session.nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_RENEGOTIATING;
    prepare_next_packet();
#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
    tls_session.nx_secure_tls_renegotiation_handshake = NX_TRUE;
    tls_session.nx_secure_tls_local_initiated_renegotiation = NX_TRUE;
#endif
    tls_session.nx_secure_tls_remote_session_active = NX_TRUE;
    tls_session.nx_secure_tls_session_ciphersuite = &fake_tls_session_ciphersuite;
    fake_tls_session_ciphersuite.nx_secure_tls_session_cipher = &fake_crypto_method;
    fake_tls_session_ciphersuite.nx_secure_tls_hash = &fake_crypto_method;
    fake_crypto_method.nx_crypto_init = fake_init;
    fake_crypto_method.nx_crypto_operation = fake_operation;
    fake_crypto_method.nx_crypto_cleanup = fake_cleanup;
    tls_session.nx_secure_tls_packet_pool = &pool_0;
    _nx_secure_tls_session_receive(&tls_session, &packet2_ptr, NX_WAIT_FOREVER);


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
    printf("NetX Secure Test:   TLS Session Receive Coverage Test ...N/A\n");
    test_control_return(3);
}
#endif
