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

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_shutdown_test_application_define(void *first_unused_memory)
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
NX_SECURE_TLS_SESSION tls_session;
UCHAR session_metadata[METADATA_SIZE];

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Shutdown Test....................");

    nx_secure_tls_initialize();

    status = nx_secure_tls_session_create(&tls_session, &nx_crypto_tls_ciphers, session_metadata, sizeof(session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_shutdown();
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

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
    printf("NetX Secure Test:   TLS Shutdown Test....................N/A\n");
    test_control_return(3);
}
#endif
