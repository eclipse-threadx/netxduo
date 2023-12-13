/* This test is to cover nx_secure_tls_record_payload_decrypt.c.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_ENABLE_TLS_1_0)
#define __LINUX__

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0, test_pool;
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
void nx_secure_tls_record_decrypt_coverage_test_application_define(void *first_unused_memory)
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

static UINT test_op = 0;
static UCHAR test_data[256];
static UINT  test_operation(UINT op, VOID *handle, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key,
                            NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte,
                            UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata,
                            ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_DECRYPT_UPDATE)
    {
        memcpy(output, test_data, output_length_in_byte);
    }

    if (op == test_op)
    {
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }

    return(NX_CRYPTO_SUCCESS);
}

static NX_PACKET *encrypt_packet = NX_NULL, *decrypt_packet;

static UINT  test_operation_init(UINT op, VOID *handle, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key,
                                 NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte,
                                 UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata,
                                 ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_DECRYPT_INITIALIZE)
    {
        encrypt_packet -> nx_packet_length = 15;
    }

    return(NX_CRYPTO_SUCCESS);
}

static void    ntest_0_entry(ULONG thread_input)
{
UINT status, offset, message_length, temp_count;
ULONG sequence_num[NX_SECURE_TLS_SEQUENCE_NUMBER_SIZE] = {0};
UCHAR test_iv[32] = {0};

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Record Decrypt Coverage Test...................");

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

    client_tls_session.nx_secure_tls_session_ciphersuite = &ciphersuite_lookup_table_test[1];
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_operation = test_operation;
    client_tls_session.nx_secure_tls_local_session_active = NX_TRUE;
    client_tls_session.nx_secure_tls_tcp_socket = &client_socket;
    client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    client_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1,2,3,5);
    client_tls_session.nx_secure_tls_key_material.nx_secure_tls_server_iv = test_iv;
    client_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    client_tls_session.nx_secure_tls_packet_pool = &pool_0;
    memset(test_data, 0, sizeof(test_data));

    status = _nx_secure_tls_allocate_handshake_packet(&client_tls_session, &pool_0, &encrypt_packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Cover nx_packet_data_extract_offset error.  */
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 32;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 33;
    message_length = encrypt_packet -> nx_packet_length;
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    offset = 30;
    message_length = encrypt_packet -> nx_packet_length;
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    /* Cover padding length error.  */
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 17;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = encrypt_packet -> nx_packet_length;
    memset(test_data, 0x03, sizeof(test_data));
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_PADDING_CHECK_FAILED, status);

    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 0xff;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = encrypt_packet -> nx_packet_length;
    memset(test_data, 0x90, sizeof(test_data));
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);
    nx_packet_release(decrypt_packet);

    /* Cover padding data error.  */
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 50;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = encrypt_packet -> nx_packet_length;
    memset(test_data, 0x03, sizeof(test_data));
    test_data[1] = 0x02;
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_PADDING_CHECK_FAILED, status);

    /* Cover ICV size larger than message length.  */
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 32;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = encrypt_packet -> nx_packet_length;
    memset(test_data, 0x03, sizeof(test_data));
    test_cipher.nx_crypto_ICV_size_in_bits = ((message_length + 1) << 3);
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    /* Cover cipher operation error.  */
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_operation = test_operation;
    test_cipher.nx_crypto_block_size_in_bytes = 0;
    test_op = NX_CRYPTO_DECRYPT_CALCULATE;
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_op = NX_CRYPTO_DECRYPT_UPDATE;
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    test_op = 0;

    /* Cover ICV size larger than block size.  */
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 0xff;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = encrypt_packet -> nx_packet_length;
    memset(test_data, 0x03, sizeof(test_data));
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_ICV_size_in_bits = ((NX_SECURE_TLS_MAX_CIPHER_BLOCK_SIZE + 1) << 3);
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    /* Cover nx_packet_data_extract_offset error.  */
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 31;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = encrypt_packet -> nx_packet_length;
    memset(test_data, 0x03, sizeof(test_data));
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_operation = test_operation_init;
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_PACKET_OFFSET_ERROR, status);

    /* Cover packet allocate error.  */
    temp_count = pool_0.nx_packet_pool_available;
    pool_0.nx_packet_pool_available = 0;
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 32;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = encrypt_packet -> nx_packet_length;
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_NO_PACKET, status);
    pool_0.nx_packet_pool_available = temp_count;

    /* Extract ICV error. */
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 32;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = 64;
    test_cipher.nx_crypto_ICV_size_in_bits = (32 << 3);
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 48;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = 64;
    test_cipher.nx_crypto_ICV_size_in_bits = (32 << 3);
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    /* if ((decrypted_length < block_size) && (decrypted_length < length)).  */
    status = nx_packet_pool_create(&test_pool, "NetX Main Packet Pool", 32, pool_area[1], sizeof(pool_area[1]));
    EXPECT_EQ(NX_SUCCESS, status);
    client_tls_session.nx_secure_tls_packet_pool = &test_pool;
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 64;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    offset = 0;
    message_length = encrypt_packet -> nx_packet_length;
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_block_size_in_bytes = NX_SECURE_TLS_MAX_CIPHER_BLOCK_SIZE;
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Append decrypted data error. */
    temp_count = test_pool.nx_packet_pool_available;
    test_pool.nx_packet_pool_available = 1;
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_NO_PACKET, status);
    test_pool.nx_packet_pool_available = temp_count;

    /* Allocate another packet for decryption error. */
    temp_count = test_pool.nx_packet_pool_available;
    test_pool.nx_packet_pool_available = 1;
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_NO_PACKET, status);
    test_pool.nx_packet_pool_available = temp_count;

    /* if ((decrypted_length < block_size) && (decrypted_length > length)).  */
    encrypt_packet -> nx_packet_append_ptr = encrypt_packet -> nx_packet_prepend_ptr + 32;
    encrypt_packet -> nx_packet_length = encrypt_packet -> nx_packet_append_ptr - encrypt_packet -> nx_packet_prepend_ptr;
    message_length = encrypt_packet -> nx_packet_length;
    offset = 0;
    memcpy(&test_cipher, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    test_cipher.nx_crypto_block_size_in_bytes = NX_SECURE_TLS_MAX_CIPHER_BLOCK_SIZE;
    status = _nx_secure_tls_record_payload_decrypt(&client_tls_session, encrypt_packet, offset, message_length, &decrypt_packet, sequence_num, NX_SECURE_TLS_APPLICATION_DATA, NX_IP_PERIODIC_RATE);
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
VOID    nx_secure_tls_record_decrypt_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Record Decrypt Coverage Test...................N/A\n");
    test_control_return(3);
}
#endif
