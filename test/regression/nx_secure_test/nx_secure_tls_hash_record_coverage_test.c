#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"

extern void    test_control_return(UINT status);

static NX_CRYPTO_METHOD fake_crypto_method;


void NX_Secure_TLS_HashRecord();

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_hash_record_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Hash Record Test...............................");

    NX_Secure_TLS_HashRecord();

    printf("SUCCESS!\n");
    test_control_return(0);

}


static NX_PACKET_POOL    pool_0;

#define NX_PACKET_POOL_SIZE ((32 + sizeof(NX_PACKET)) * 2)

static ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

static NX_SECURE_TLS_CIPHERSUITE_INFO fake_tls_session_ciphersuite;
static NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
static NX_CRYPTO_METHOD fake_hash_method;

static int init_count = 0;
static int iterations = 0;
static int call_count = 0;
static UINT fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                      UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                      VOID **handler,
                      VOID *crypto_metadata,
                      ULONG crypto_metadata_size)
{
    call_count = 0;
    if (init_count++ == 0)
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
}

static UINT fake_cleanup(VOID *crypto_metadata)
{
    return(NX_CRYPTO_NOT_SUCCESSFUL);
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
    if(call_count == iterations)
    {
        call_count = 0;
        iterations ++;
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }
    else
        call_count++;
    return(NX_CRYPTO_SUCCESS);
}


TEST(NX_Secure_TLS, HashRecord)
{
UINT hash_length;
UINT status;
NX_PACKET *packet1_ptr, *packet2_ptr;
ULONG sequence_num[NX_SECURE_TLS_SEQUENCE_NUMBER_SIZE];


    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 32,  (ULONG*)(((int)packet_pool_area + 4) & ~4) , NX_PACKET_POOL_SIZE);
    status = nx_packet_allocate(&pool_0, &packet1_ptr, 0, NX_NO_WAIT);
    status = nx_packet_allocate(&pool_0, &packet2_ptr, 0, NX_NO_WAIT);

    packet1_ptr -> nx_packet_append_ptr = packet1_ptr -> nx_packet_prepend_ptr + 6;
    packet1_ptr -> nx_packet_length = 6;

    packet2_ptr -> nx_packet_append_ptr = packet2_ptr -> nx_packet_prepend_ptr + 5;
    packet2_ptr -> nx_packet_length = 5;

    packet1_ptr -> nx_packet_next = packet2_ptr;

    fake_tls_session_ciphersuite.nx_secure_tls_hash = &fake_hash_method;

    fake_hash_method.nx_crypto_operation = fake_operation;
    fake_hash_method.nx_crypto_init = fake_init;
    fake_hash_method.nx_crypto_cleanup = fake_cleanup;

    /* Cover line 144 */
    status = _nx_secure_tls_hash_record(&fake_tls_session_ciphersuite, sequence_num, NX_NULL, 0, packet1_ptr, 10, 15, NX_NULL, &hash_length, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    

    /* Cover line 168 */
    status = _nx_secure_tls_hash_record(&fake_tls_session_ciphersuite, sequence_num, NX_NULL, 0, packet1_ptr, 10, 15, NX_NULL, &hash_length, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 188 */
    status = _nx_secure_tls_hash_record(&fake_tls_session_ciphersuite, sequence_num, NX_NULL, 0, packet1_ptr, 10, 15, NX_NULL, &hash_length, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 208 */
    status = _nx_secure_tls_hash_record(&fake_tls_session_ciphersuite, sequence_num, NX_NULL, 0, packet1_ptr, 10, 15, NX_NULL, &hash_length, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 219 and 257 */
    status = _nx_secure_tls_hash_record(&fake_tls_session_ciphersuite, sequence_num, NX_NULL, 0, packet1_ptr, 10, 15, NX_NULL, &hash_length, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 268 */
    status = _nx_secure_tls_hash_record(&fake_tls_session_ciphersuite, sequence_num, NX_NULL, 0, packet1_ptr, 10, 15, NX_NULL, &hash_length, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    /* Cover line 286 */
    packet2_ptr->nx_packet_append_ptr = packet2_ptr->nx_packet_prepend_ptr + 20;
    packet2_ptr->nx_packet_length = 20;
    status = _nx_secure_tls_hash_record(&fake_tls_session_ciphersuite, sequence_num, NX_NULL, 0, packet1_ptr, 10, 10, NX_NULL, &hash_length, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    


    /* Cover line 301 */
    status = _nx_secure_tls_hash_record(&fake_tls_session_ciphersuite, sequence_num, NX_NULL, 0, packet1_ptr, 10, 10, NX_NULL, &hash_length, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 212 */
    status = _nx_secure_tls_hash_record(&fake_tls_session_ciphersuite, sequence_num, NX_NULL, 0, packet1_ptr, 50, 15, NX_NULL, &hash_length, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    nx_packet_release(packet1_ptr);

    nx_packet_pool_delete(&pool_0);

}

