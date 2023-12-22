#include "tls_test_frame.h"

typedef struct
{
    UINT sig_alg_index;
    UINT session_succ;
    CHAR *key;
    CHAR *cert;
    CHAR *ca;
    UINT verify;
} OPENSSLTEST;

static CHAR *signature_algorithms[] = 
{
    "RSA+SHA256",
    "RSA+SHA384",
    "RSA+SHA512",
    "RSA+SHA1",
    "ECDSA+SHA256",
    "ECDSA+SHA384",
    "ECDSA+SHA512",
    "ECDSA+SHA1",
};

CHAR* external_cmd[] = { "openssl", "s_server", "-rev", 
                         "-key", "4-key",
                         "-cert", "6-cert",
                         "-CAfile", "8-ca",
                         "-sigalgs", "10-sigalg",
                         "-naccept", "1", "-tls1_2",
                         "-port", DEVICE_SERVER_PORT_STRING,
                         "14-Verify", "10",
                        (CHAR*)NULL};

OPENSSLTEST tests[] =
{

    /* Test RSA. */
    {0, NX_TRUE, "../certificates/test_server.key", "../certificates/test_server.crt", "../certificates/test.crt", NX_FALSE},
    {1, NX_TRUE, "../certificates/test_server.key", "../certificates/test_server.crt", "../certificates/test.crt", NX_FALSE},
    {2, NX_TRUE, "../certificates/test_server.key", "../certificates/test_server.crt", "../certificates/test.crt", NX_FALSE},
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    {3, NX_FALSE, "../certificates/test_server.key", "../certificates/test_server.crt", "../certificates/test.crt", NX_FALSE},
#else
    {3, NX_TRUE, "../certificates/test_server.key", "../certificates/test_server.crt", "../certificates/test.crt", NX_FALSE},
#endif

    /* Test ECDSA. */
    {4, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {5, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {6, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    {7, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
#else
    {7, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
#endif

    /* No shared signature algorithms. */
    {5, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
};

extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;
/* Openssl echo server entry. */
INT openssl_echo_server_entry(TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)

INT status, exit_status, i;

    for (i = 0; i < sizeof(tests) / sizeof(OPENSSLTEST); i++)
    {
        external_cmd[4] = tests[i].key;
        external_cmd[6] = tests[i].cert;
        external_cmd[8] = tests[i].ca;
        external_cmd[10] = signature_algorithms[tests[i].sig_alg_index];
        if (tests[i].verify)
        {
            external_cmd[16] = "-Verify";
        }
        else
        {
            external_cmd[16] = NULL;
        }

        /* Post the semaphore to notify that the reverse echo server is prepared. */
        tls_test_semaphore_post(semaphore_echo_server_prepared);

        /* Launch the openssl server. */
        tls_test_launch_external_test_process(&exit_status, external_cmd);

#if 0 /* openssl exit with 0 no matter TLS session is established or not. */
        /* Check for the exit status of external program. */
        return_value_if_fail(0 == exit_status, TLS_TEST_INSTANCE_EXTERNAL_PROGRAM_FAILED);
#endif
        
    }

    return TLS_TEST_SUCCESS;

#else /* ifndef NX_SECURE_TLS_CLIENT_DISABLED */

    return TLS_TEST_NOT_AVAILABLE;

#endif /* ifndef NX_SECURE_TLS_CLIENT_DISABLED */

}
