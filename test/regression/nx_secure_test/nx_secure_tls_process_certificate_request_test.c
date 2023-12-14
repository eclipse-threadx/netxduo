/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

extern VOID    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
#define METADATA_SIZE               16000

/* Define the ThreadX and NetX object control blocks...  */

static NX_SECURE_TLS_SESSION    tls_session;
static UCHAR                    tls_session_metadata[METADATA_SIZE];

extern const NX_CRYPTO_METHOD *supported_crypto[];
extern const UINT supported_crypto_size;
extern const NX_CRYPTO_CIPHERSUITE *ciphersuite_map[];
extern const UINT ciphersuite_map_size;

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_process_certificate_request_test_application_define(void *first_unused_memory)
#endif
{
UINT   status;
UCHAR  message[100];
NX_SECURE_X509_CERT certificate;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Process Certificate Request Test....................");

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    /* Initialize our certificate */
    memset(&certificate, 0, sizeof(certificate));
    tls_session.nx_secure_tls_credentials.nx_secure_tls_active_certificate = &certificate;
    message[0] = 1;
    message[1] = NX_SECURE_TLS_X509_TYPE_RSA;
    status = _nx_secure_tls_process_certificate_request(&tls_session, message, 100);
#if NX_SECURE_TLS_TLS_1_3_ENABLED
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_CERT_SIGN_ALG, status);
#else
    EXPECT_EQ(NX_SUCCESS, status);
#endif

    status = nx_secure_tls_session_delete(&tls_session);
    EXPECT_EQ(NX_SUCCESS, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_process_certificate_request_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Process Certificate Request Test....................N/A\n");
    test_control_return(3);
}
#endif
