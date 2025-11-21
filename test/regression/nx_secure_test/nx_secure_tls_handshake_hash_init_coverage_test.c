#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"
#include "ecc_certs.c"
#include   "nx_crypto_ecdh.h"



extern void    test_control_return(UINT status);

static NX_SECURE_TLS_SESSION session;
static NX_CRYPTO_METHOD fake_method;
static NX_SECURE_TLS_CRYPTO fake_crypto_table;

static void NX_Secure_TLS_handshake_hash_coverage_test();

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_handshake_hash_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Handshake Hash Init Test.......................");
#if ((NX_SECURE_TLS_TLS_1_2_ENABLED) && !defined(NX_SECURE_TLS_ENABLE_TLS_1_3) && !defined(NX_SECURE_TLS_ENABLE_TLS_1_0) && !defined(NX_SECURE_TLS_ENABLE_TLS_1_1))
    NX_Secure_TLS_handshake_hash_coverage_test();

    printf("SUCCESS!\n");
#else
    printf("N/A\n");
#endif
    test_control_return(0);

}



static int call_count = 0;
static int iteration = 0;

static UINT fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                      UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                      VOID **handler,
                      VOID *crypto_metadata,
                      ULONG crypto_metadata_size)
{
    call_count++;
    if(call_count == iteration)
        return(NX_CRYPTO_NOT_SUCCESSFUL);
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
    call_count++;
    if(call_count == iteration)
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
    
}

static UINT fake_cleanup(VOID *crypto_metadata)
{
    call_count++;
    if(call_count == iteration)
       return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
}



static UCHAR handshake_hash_scratch[100];
#define SHA256_METADATA_SIZE 10
static UCHAR sha256_metadata[SHA256_METADATA_SIZE];


TEST(NX_Secure_TLS, handshake_hash_coverage_test)
{
UINT status;
    session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_scratch = handshake_hash_scratch;
    session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha256_metadata = sha256_metadata;
    session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha256_metadata_size = SHA256_METADATA_SIZE;
    session.nx_secure_tls_supported_versions = NX_SECURE_TLS_BITFIELD_VERSION_1_2;
    session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    session.nx_secure_tls_crypto_table = &fake_crypto_table;
    fake_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &fake_method;
    fake_method.nx_crypto_init = NX_NULL;
    fake_method.nx_crypto_operation = NX_NULL;
    fake_method.nx_crypto_cleanup = NX_NULL;

    /* Cover line 163 */
    status = _nx_secure_tls_handshake_hash_init(&session);
    EXPECT_EQ(NX_SUCCESS, status);    

    fake_method.nx_crypto_init = fake_init;
    fake_method.nx_crypto_operation = fake_operation;
    fake_method.nx_crypto_cleanup = fake_cleanup;

    call_count = 0; iteration = 1;
    status = _nx_secure_tls_handshake_hash_init(&session);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);   

    call_count = 0; iteration++;
    status = _nx_secure_tls_handshake_hash_init(&session);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);   

}

