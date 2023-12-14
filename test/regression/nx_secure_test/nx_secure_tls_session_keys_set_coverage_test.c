#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"
#include "nx_secure_tls_test_init_functions.h"

extern void    test_control_return(UINT status);

static NX_SECURE_TLS_SESSION   tls_session;

static void  NX_Secure_TLS_session_keys_set_coverage(void);

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_session_keys_set_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Session Keys Set Coverage Test.................");


    NX_Secure_TLS_session_keys_set_coverage();

    printf("SUCCESS!\n");
    test_control_return(0);

}

static NX_SECURE_TLS_SESSION tls_session;
static NX_SECURE_TLS_CIPHERSUITE_INFO session_ciphersuite;
static NX_CRYPTO_METHOD session_cipher;


static int init_count = 0;
static int cleanup_count = 0;
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
    if(cleanup_count ++ == 0)
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
}


TEST(NX_Secure_TLS, session_keys_set_coverage)
{

USHORT key_set = NX_SECURE_TLS_KEY_SET_LOCAL;
UINT   status;

    nx_secure_tls_test_init_functions(&tls_session);

    /* Test line 131 */

    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    
    /* Test line 153 */
    session_cipher.nx_crypto_key_size_in_bits = (NX_SECURE_TLS_MAX_KEY_SIZE * 8 * 3);
    session_ciphersuite.nx_secure_tls_hash_size = NX_SECURE_TLS_MAX_HASH_SIZE * 3;
    session_cipher.nx_crypto_IV_size_in_bits = NX_SECURE_TLS_MAX_IV_SIZE * 3;
    tls_session.nx_secure_tls_session_ciphersuite = &session_ciphersuite;    
    session_ciphersuite.nx_secure_tls_session_cipher = &session_cipher;
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_SECURE_TLS_CRYPTO_KEYS_TOO_LARGE, status);
    

    session_cipher.nx_crypto_key_size_in_bits = NX_SECURE_TLS_MAX_KEY_SIZE * 8;
    session_ciphersuite.nx_secure_tls_hash_size = NX_SECURE_TLS_MAX_HASH_SIZE;
    session_cipher.nx_crypto_IV_size_in_bits = NX_SECURE_TLS_MAX_IV_SIZE;

    /* Test line 234 */
    session_cipher.nx_crypto_init = fake_init;
    session_cipher.nx_crypto_cleanup = fake_cleanup;
    key_set = NX_SECURE_TLS_KEY_SET_LOCAL;
    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    tls_session.nx_secure_tls_session_cipher_client_initialized = 1;
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Test Line 229*/
    session_cipher.nx_crypto_cleanup = fake_cleanup;
    tls_session.nx_secure_tls_session_cipher_client_initialized = 0;
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    session_cipher.nx_crypto_cleanup = NX_NULL;
    tls_session.nx_secure_tls_session_cipher_client_initialized = 0;
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    session_cipher.nx_crypto_cleanup = NX_NULL;
    tls_session.nx_secure_tls_session_cipher_client_initialized = 1;
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    /* Test line 274 */
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    /* Test line 256 */
    cleanup_count = 0;
    init_count = 0;
    key_set = NX_SECURE_TLS_KEY_SET_REMOTE;
    session_cipher.nx_crypto_cleanup = fake_cleanup;
    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    tls_session.nx_secure_tls_session_cipher_server_initialized = 1;
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    
    
    /* Test Line 251*/
    session_cipher.nx_crypto_cleanup = fake_cleanup;
    tls_session.nx_secure_tls_session_cipher_server_initialized = 0;
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    session_cipher.nx_crypto_cleanup = NX_NULL;
    tls_session.nx_secure_tls_session_cipher_server_initialized = 0;
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    session_cipher.nx_crypto_cleanup = NX_NULL;
    tls_session.nx_secure_tls_session_cipher_server_initialized = 1;
    status = _nx_secure_tls_session_keys_set(&tls_session, key_set);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

}

