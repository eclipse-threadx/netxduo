#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"
#include "ecc_certs.c"
#include   "nx_crypto_ecdh.h"



extern void    test_control_return(UINT status);

static NX_SECURE_TLS_SESSION session;
static NX_CRYPTO_METHOD fake_sha256_method;
static NX_CRYPTO_METHOD fake_prf_method;
static NX_SECURE_TLS_CIPHERSUITE_INFO fake_tls_session_ciphersuite;
static NX_SECURE_TLS_CRYPTO  fake_crypto_table;

void     NX_Secure_TLS_finished_hash_generate_coverage_test();

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_finished_hash_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Finished Hash Generate Test....................");
#if (!(defined(NX_SECURE_TLS_ENABLE_TLS_1_0) || defined(NX_SECURE_TLS_ENABLE_TLS_1_1)))
    NX_Secure_TLS_finished_hash_generate_coverage_test();

    printf("SUCCESS!\n");
#else
    printf("N/A\n");
#endif

    test_control_return(0);

}


static int init_count = 0;
static int call_count = 0;

static UINT fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                      UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                      VOID **handler,
                      VOID *crypto_metadata,
                      ULONG crypto_metadata_size)
{
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
    if(call_count++ == 0)
    {
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }

    call_count++;
    return(NX_CRYPTO_SUCCESS);
}


static int prf_init_count = 0;
static int prf_iterations = 0;
static int prf_call_count = 0;

static UINT prf_fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                          UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                          VOID **handler,
                          VOID *crypto_metadata,
                          ULONG crypto_metadata_size)
{
    prf_call_count = 0;
    if (prf_init_count++ == 0)
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
}


static UINT prf_fake_operation(UINT op,       /* Encrypt, Decrypt, Authenticate */
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
    if(prf_call_count == prf_iterations)
    {
        prf_call_count = 0;
        prf_iterations ++;
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }
    else
        prf_call_count++;
    return(NX_CRYPTO_SUCCESS);
}

static UCHAR handshake_hash_scratch[100];
#define SHA256_METADATA_SIZE 100
static UCHAR sha256_metadata[SHA256_METADATA_SIZE];



TEST(NX_Secure_TLS, finished_hash_generate_coverage_test)
{
UINT status;

    session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_scratch = handshake_hash_scratch;
    session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha256_metadata = sha256_metadata;
    session.nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha256_metadata_size = SHA256_METADATA_SIZE;
    /* Cover line 121 */
    session.nx_secure_tls_session_ciphersuite = NX_NULL;
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);    

    /* Set a fake tls_session_ciphersuite. */
    session.nx_secure_tls_session_ciphersuite = &fake_tls_session_ciphersuite;
    fake_tls_session_ciphersuite.nx_secure_tls_prf = &fake_prf_method;

    /* Cover line 135/284/286 */
    session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_1;
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_TLS_VERSION, status);    

    /* Cover line 147/173/175 */
    session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    session.nx_secure_tls_crypto_table = &fake_crypto_table;
    fake_crypto_table.nx_secure_tls_handshake_hash_sha256_method = &fake_sha256_method;
    fake_sha256_method.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);    

    /* Cover line 167 */
    fake_sha256_method.nx_crypto_operation = &fake_operation;
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);   

    /* Cover line 290/350 */
    fake_prf_method.nx_crypto_init = NX_NULL;
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);    


    /* Cover line 300 */
    fake_prf_method.nx_crypto_init = prf_fake_init;
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    


    /* Cover line 308 */
    fake_prf_method.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);    


    /* Cover line 327 */
    fake_prf_method.nx_crypto_operation = &prf_fake_operation;    
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    


    /* Cover line 335 */
    fake_prf_method.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);    

    /* Cover line 341 */
    fake_prf_method.nx_crypto_cleanup = &fake_cleanup;
    status = _nx_secure_tls_finished_hash_generate(&session, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

}

