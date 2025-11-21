#include "nx_api.h"
#include "tls_test_utility.h"
#include "nx_secure_tls_api.h"

static TX_THREAD thread_0;
static VOID thread_0_entry(ULONG thread_input);
static NX_SECURE_TLS_SESSION session_0;

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_coverage_3_test_application_define(void *first_unused_memory)
#endif
{
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
        first_unused_memory, 4096,
        8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);
}

static VOID thread_0_entry(ULONG thread_input)
{
UINT status;
UCHAR buffer[100];
USHORT id;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS 1.3 Coverage 3 Test............................");

    _nx_secure_tls_get_signature_algorithm_id(NX_SECURE_TLS_SIGNATURE_RSA_MD5, &id);
    EXPECT_EQ(NX_SECURE_TLS_X509_TYPE_RSA_MD5, id);

    _nx_secure_tls_get_signature_algorithm_id(NX_SECURE_TLS_SIGNATURE_RSA_SHA1, &id);
    EXPECT_EQ(NX_SECURE_TLS_X509_TYPE_RSA_SHA_1, id);

    _nx_secure_tls_get_signature_algorithm_id(NX_SECURE_TLS_SIGNATURE_RSA_SHA384, &id);
    EXPECT_EQ(NX_SECURE_TLS_X509_TYPE_RSA_SHA_384, id);

    _nx_secure_tls_get_signature_algorithm_id(NX_SECURE_TLS_SIGNATURE_RSA_SHA512, &id);
    EXPECT_EQ(NX_SECURE_TLS_X509_TYPE_RSA_SHA_512, id);

    _nx_secure_tls_get_signature_algorithm_id(NX_SECURE_TLS_SIGNATURE_ECDSA_SHA224, &id);
    EXPECT_EQ(NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_224, id);

    _nx_secure_tls_get_signature_algorithm_id(NX_SECURE_TLS_SIGNATURE_ECDSA_SHA384, &id);
    EXPECT_EQ(NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_384, id);

    _nx_secure_tls_get_signature_algorithm_id(NX_SECURE_TLS_SIGNATURE_ECDSA_SHA512, &id);
    EXPECT_EQ(NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_512, id);

    id = 0;
    _nx_secure_tls_get_signature_algorithm_id(0, &id);
    EXPECT_EQ(0, id);

    /* Tests for 4-byte alignment. */
    _nx_secure_tls_session_packet_buffer_set(&session_0, &buffer[1], 7);
    EXPECT_EQ(session_0.nx_secure_tls_packet_buffer, &buffer[4]);
    EXPECT_EQ(session_0.nx_secure_tls_packet_buffer_size, 4);

    printf("SUCCESS!\n");
    test_control_return(0);
};
