/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

extern VOID    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED)
#define METADATA_SIZE               16000

extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_process_changecipherspec_test_application_define(void *first_unused_memory)
#endif
{
UINT status;
NX_SECURE_TLS_SESSION tls_session;
UCHAR tls_session_metadata[METADATA_SIZE];
UCHAR packet_buffer[1];

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Process Change Cipher Spec Test....................");

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status =  nx_secure_tls_session_create(&tls_session,
                                           &nx_crypto_tls_ciphers,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    packet_buffer[0] = 0x1;

    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    tls_session.nx_secure_tls_server_state = 0;
    status = _nx_secure_tls_process_changecipherspec(&tls_session, packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    tls_session.nx_secure_tls_client_state = 0;
    status = _nx_secure_tls_process_changecipherspec(&tls_session, packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNEXPECTED_MESSAGE, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_process_changecipherspec_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Process Change Cipher Spec Test....................N/A\n");
    test_control_return(3);
}
#endif
