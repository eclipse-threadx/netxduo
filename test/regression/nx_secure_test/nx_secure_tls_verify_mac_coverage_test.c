#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"
#include "nx_secure_tls_test_init_functions.h"

extern void    test_control_return(UINT status);

static NX_SECURE_TLS_SESSION   client_tls_session;
static NX_PACKET_POOL          pool_0;
#define NX_PACKET_POOL_BYTES  ((128 + sizeof(NX_PACKET)) * 3)
void NX_Secure_TLS_verify_mac_coverage();

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_verify_mac_test_application_define(void *first_unused_memory)
#endif
{

    CHAR* pointer;
    UINT       status;

    pointer = (CHAR*)first_unused_memory;


    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 128, pointer, NX_PACKET_POOL_BYTES);

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS verify mac Test................................");


    NX_Secure_TLS_verify_mac_coverage();

    printf("SUCCESS!\n");
    test_control_return(0);

}
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table[];

TEST(NX_Secure_TLS, verify_mac_coverage)
{
UINT status;
int hash_size;
UINT length = 0;
NX_PACKET *send_packet;
NX_PACKET *receive_packet;
UCHAR receive_buffer[10];



    
    nx_packet_allocate(&pool_0, &send_packet, 0, NX_WAIT_FOREVER);

    /* Invalid hash size. */
    length = 0;

    nx_secure_tls_test_init_functions(&client_tls_session);

    /* Test Line 102 */
    client_tls_session.nx_secure_tls_session_ciphersuite = NX_NULL;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    /* Set up the correct ciphersuite and crypto table. */
#ifdef NX_SECURE_DISABLE_X509
    client_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[0];
#else
    client_tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[3];
#endif
    client_tls_session.nx_secure_tls_crypto_table = &nx_crypto_tls_ciphers;

    /* Test Line 124 */
    hash_size = client_tls_session.nx_secure_tls_session_ciphersuite -> nx_secure_tls_hash_size;
    
    receive_buffer[0] = NX_SECURE_TLS_APPLICATION_DATA;
    length = hash_size;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);
    EXPECT_EQ(NX_SUCCESS, status);


    length = 0;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);
    EXPECT_EQ(NX_SECURE_TLS_HASH_MAC_VERIFY_FAILURE, status);

    receive_buffer[0] = 0;
    length = hash_size;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);
    EXPECT_EQ(NX_SECURE_TLS_HASH_MAC_VERIFY_FAILURE, status);

    length = 1;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);
    EXPECT_EQ(NX_SECURE_TLS_HASH_MAC_VERIFY_FAILURE, status);


    /* Test Line 137 */
    receive_buffer[0] = NX_SECURE_TLS_APPLICATION_DATA;
    length = hash_size;
    client_tls_session.nx_secure_tls_remote_sequence_number[0] = 0xFFFFFFFF;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Test Line 142 */
    receive_buffer[0] = NX_SECURE_TLS_APPLICATION_DATA;
    length = hash_size;
    client_tls_session.nx_secure_tls_remote_sequence_number[0] = 0xFFFFFFFF;
    client_tls_session.nx_secure_tls_remote_sequence_number[1] = 0xFFFFFFFF;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);
    client_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    client_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;


    /* Test line 160 */
    length = hash_size + 1;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 7, send_packet, 0, &length);    
    EXPECT_EQ(NX_SECURE_TLS_HASH_MAC_VERIFY_FAILURE, status);


    /* Test line 178 */
    client_tls_session.nx_secure_tls_remote_sequence_number[0] = 0xFFFFFFFF;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);    
    EXPECT_EQ(NX_SECURE_TLS_PADDING_CHECK_FAILED, status);

    /* Test line 184 */
    client_tls_session.nx_secure_tls_remote_sequence_number[0] = 0xFFFFFFFF;
    client_tls_session.nx_secure_tls_remote_sequence_number[1] = 0xFFFFFFFF;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);
    client_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;

    /* Test line 205 */
    client_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;    
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);    
    EXPECT_EQ(NX_SECURE_TLS_PADDING_CHECK_FAILED, status);

    /* Test Line 212 */
    send_packet -> nx_packet_append_ptr = send_packet->nx_packet_prepend_ptr + 15;
    send_packet -> nx_packet_length = 15;
    length = 30;
    status = _nx_secure_tls_verify_mac(&client_tls_session, receive_buffer, 0, send_packet, 0, &length);
    EXPECT_EQ(NX_SECURE_TLS_PADDING_CHECK_FAILED, status);

}

