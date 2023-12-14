/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

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

static UINT test_crypto_cleanup(VOID *crypto_metadata){return(NX_CRYPTO_INVALID_LIBRARY);}


#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_session_delete_test_application_define(void *first_unused_memory)
#endif
{
    /* Create the client thread.  */
    tx_thread_create(&thread_0, "thread 0", ntest_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);
}

static void ntest_0_entry(ULONG thread_input)
{
UINT status;
NX_SECURE_TLS_SESSION tls_session[2];
NX_SECURE_TLS_CIPHERSUITE_INFO session_ciphersuite;
NX_CRYPTO_METHOD session_cipher;
UCHAR session_metadata[METADATA_SIZE];

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Session Delete Test....................");

    nx_secure_tls_initialize();

    tls_session[0].nx_secure_tls_created_next = &tls_session[0];
    status = _nx_secure_tls_session_delete(&tls_session[0]);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_create(&tls_session[0], &nx_crypto_tls_ciphers, session_metadata, sizeof(session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);
	
	/*test line 111,118:nx_secure_tls_session_reset()*/
	tls_session[0].nx_secure_tls_session_ciphersuite = &session_ciphersuite; 
	tls_session[0].nx_secure_tls_remote_session_active	= 1;
    session_ciphersuite.nx_secure_tls_session_cipher = &session_cipher;
	session_cipher.nx_crypto_cleanup = test_crypto_cleanup;

	status = nx_secure_tls_session_reset(&tls_session[0]);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);
	/*end of test:nx_secure_tls_session_reset()*/

    status = nx_secure_tls_session_create(&tls_session[1], &nx_crypto_tls_ciphers, session_metadata, sizeof(session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    tls_session[1].nx_secure_tls_created_next = NX_NULL;
    status = _nx_secure_tls_session_delete(&tls_session[1]);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_session_delete_test_application_define(void *first_unused_memory)
#endif
{
    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Session Delete Test....................N/A\n");
    test_control_return(3);
}
#endif
