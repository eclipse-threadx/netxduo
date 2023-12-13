/* This test is to cover nx_secure_tls_record_payload_encrypt.c.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED)
#define __LINUX__

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           client_socket;
static NX_SECURE_TLS_SESSION   client_tls_session;

static UCHAR client_packet_buffer[4000];
static CHAR client_crypto_metadata[16000]; 

/* Test PKI (3-level). */
#include "test_ca_cert.c"
#include "test_device_cert.c"
#define ca_cert_der test_ca_cert_der
#define ca_cert_der_len test_ca_cert_der_len

/*  Cryptographic routines. */
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_des;
static NX_CRYPTO_METHOD test_cipher;

static NX_SECURE_TLS_CIPHERSUITE_INFO ciphersuite_lookup_table_test[] =
{
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &test_cipher,                   16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
};

#define DEMO_STACK_SIZE  4096

/* Define the IP thread's stack area.  */
#define IP_STACK_SIZE 4096

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_BYTES  ((1536 + sizeof(NX_PACKET)) * 20)
#define NX_PACKET_POOL_SIZE (NX_PACKET_POOL_BYTES/sizeof(ULONG) + 64 / sizeof(ULONG))

/* Define the ARP cache area.  */
#define ARP_AREA_SIZE 1024

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
void nx_secure_tls_record_encrypt_coverage_test_application_define(void *first_unused_memory)
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

    /* Initialize the NetX system.  */
    nx_system_initialize();
      
    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pool_area[0], sizeof(pool_area[0]));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, IP_STACK_SIZE, 1);
    pointer = pointer + IP_STACK_SIZE;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    EXPECT_EQ(NX_SUCCESS, status);

    nx_secure_tls_initialize();
}

static UINT test_op;
static UINT test_count;
static UINT op_count;
static UINT  test_operation(UINT op, VOID *handle, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key,
                            NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte,
                            UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata,
                            ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == test_op)
    {

        if (op != NX_CRYPTO_ENCRYPT_UPDATE || op_count == test_count)
        {
            return(NX_CRYPTO_NOT_SUCCESSFUL);
        }
        op_count++;
    }

    return(NX_CRYPTO_SUCCESS);
}

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NX_PACKET *send_packet = NX_NULL, *test_packet;
ULONG sequence_num[NX_SECURE_TLS_SEQUENCE_NUMBER_SIZE] = {0};
UCHAR test_iv[32] = {0};
UCHAR *temp_pointer = NX_NULL;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Record Encrypt Coverage Test...................");

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
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

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    client_tls_session.nx_secure_tls_session_ciphersuite = &ciphersuite_lookup_table_test[0];
    client_tls_session.nx_secure_tls_local_session_active = NX_TRUE;
    client_tls_session.nx_secure_tls_tcp_socket = &client_socket;
    client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    client_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1,2,3,5);
    client_tls_session.nx_secure_tls_key_material.nx_secure_tls_client_iv = test_iv;

    status = _nx_secure_tls_allocate_handshake_packet(&client_tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Cover packet buffer too small.  */
    client_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    temp_pointer = send_packet -> nx_packet_prepend_ptr;
    send_packet -> nx_packet_prepend_ptr = send_packet -> nx_packet_data_end;
    status = _nx_secure_tls_record_payload_encrypt(&client_tls_session, send_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
    send_packet -> nx_packet_prepend_ptr = temp_pointer;

    /* Cover invalid block size.  */
    client_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_0;
    client_tls_session.nx_secure_tls_session_ciphersuite = &ciphersuite_lookup_table_test[1];
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_block_size_in_bytes = 0;
    status = _nx_secure_tls_record_payload_encrypt(&client_tls_session, send_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_STATE, status);

    test_cipher.nx_crypto_IV_size_in_bits = 0;
    test_cipher.nx_crypto_ICV_size_in_bits = 1;
    status = _nx_secure_tls_record_payload_encrypt(&client_tls_session, send_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Cover session_cipher_method NX_CRYPTO_ENCRYPT_UPDATE error.  */
    status = nx_packet_data_append(send_packet, "abcd", 4, &pool_0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_operation = test_operation;
    test_op = NX_CRYPTO_ENCRYPT_UPDATE;
    test_count = 0;
    status = _nx_secure_tls_record_payload_encrypt(&client_tls_session, send_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_op = NX_CRYPTO_ENCRYPT_CALCULATE;
    status = _nx_secure_tls_record_payload_encrypt(&client_tls_session, send_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    status = nx_packet_allocate(&pool_0, &test_packet, 0, NX_WAIT_FOREVER);
    status += nx_packet_data_append(test_packet, "efg", 3, &pool_0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);
    send_packet -> nx_packet_next = test_packet;
    send_packet -> nx_packet_length += test_packet -> nx_packet_length;
    test_op = NX_CRYPTO_ENCRYPT_UPDATE;
    test_count = 0;
    status = _nx_secure_tls_record_payload_encrypt(&client_tls_session, send_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_count = 1;
    status = _nx_secure_tls_record_payload_encrypt(&client_tls_session, send_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_op = 0;
    test_count = 0;
    test_cipher.nx_crypto_block_size_in_bytes = 0;
    test_cipher.nx_crypto_IV_size_in_bits = 0;
    test_cipher.nx_crypto_ICV_size_in_bits = ((NX_SECURE_TLS_MAX_CIPHER_BLOCK_SIZE + 1) << 3);
    send_packet -> nx_packet_append_ptr = send_packet -> nx_packet_prepend_ptr;
    send_packet -> nx_packet_length = test_packet -> nx_packet_length;
    status = _nx_secure_tls_record_payload_encrypt(&client_tls_session, send_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA);
    EXPECT_EQ(NX_SIZE_ERROR, status);

    memcpy(&test_cipher, &crypto_method_des, sizeof(NX_CRYPTO_METHOD));
    status = _nx_secure_tls_record_payload_encrypt(&client_tls_session, send_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA);
    EXPECT_EQ(NX_SUCCESS, status);

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
VOID    nx_secure_tls_record_encrypt_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Record Encrypt Coverage Test...................N/A\n");
    test_control_return(3);
}
#endif
