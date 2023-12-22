#include "tls_test_frame.h"

typedef struct
{
    UINT curves_index;
    UINT session_succ;
    CHAR *key;
    CHAR *cert;
    CHAR *ca;
    UINT verify;
} OPENSSLTEST;

static CHAR *curves[] =
{
    "prime192v1:secp224r1:prime256v1:secp384r1:secp521r1",
    "prime192v1",
    "secp224r1",
    "prime256v1",
    "secp384r1",
    "secp521r1",
    "prime192v1:prime256v1",
    "secp224r1:prime256v1",
};

CHAR* external_cmd[] = { "openssl", "s_server", "-rev", 
                         "-key", "4-key",
                         "-cert", "6-cert",
                         "-CAfile", "8-ca",
                         "-curves", "10-curves",
                         "-naccept", "1", "-tls1_2",
                         "-cipher", "ECDH-ECDSA-AES128-SHA256",
                         "-port", DEVICE_SERVER_PORT_STRING,
                         "16-Verify", "10",
                        (CHAR*)NULL};

OPENSSLTEST tests[] =
{
    /* Select curve by certificate. */
    {0, NX_TRUE, "../ecc_certificates/ECTestServer9_192.key", "../ecc_certificates/ECTestServer9_192.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer8_224.key", "../ecc_certificates/ECTestServer8_224.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer4.key", "../ecc_certificates/ECTestServer4.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer3.key", "../ecc_certificates/ECTestServer3.crt", "../ecc_certificates/ECCA3.crt", NX_FALSE},

    /* Specify curve from client. */
    {0, NX_TRUE, "../ecc_certificates/ECTestServer9_192.key", "../ecc_certificates/ECTestServer9_192.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer8_224.key", "../ecc_certificates/ECTestServer8_224.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer4.key", "../ecc_certificates/ECTestServer4.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer3.key", "../ecc_certificates/ECTestServer3.crt", "../ecc_certificates/ECCA3.crt", NX_FALSE},

    /* Specify curve from server. */
    {1, NX_TRUE, "../ecc_certificates/ECTestServer9_192.key", "../ecc_certificates/ECTestServer9_192.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {2, NX_TRUE, "../ecc_certificates/ECTestServer8_224.key", "../ecc_certificates/ECTestServer8_224.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {3, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {4, NX_TRUE, "../ecc_certificates/ECTestServer4.key", "../ecc_certificates/ECTestServer4.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE},
    {5, NX_TRUE, "../ecc_certificates/ECTestServer3.key", "../ecc_certificates/ECTestServer3.crt", "../ecc_certificates/ECCA3.crt", NX_FALSE},

    /* Configure invalid curves at server side. */
    {2, NX_FALSE, "../ecc_certificates/ECTestServer9_192.key", "../ecc_certificates/ECTestServer9_192.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {3, NX_FALSE, "../ecc_certificates/ECTestServer9_192.key", "../ecc_certificates/ECTestServer9_192.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {4, NX_FALSE, "../ecc_certificates/ECTestServer9_192.key", "../ecc_certificates/ECTestServer9_192.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {5, NX_FALSE, "../ecc_certificates/ECTestServer9_192.key", "../ecc_certificates/ECTestServer9_192.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},

    /* Multiple curves used by server and CA cert. */
    {0, NX_FALSE, "../ecc_certificates/ECTestServer9_192.key", "../ecc_certificates/ECTestServer9_192.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {0, NX_FALSE, "../ecc_certificates/ECTestServer8_224.key", "../ecc_certificates/ECTestServer8_224.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},

    /* Client curve not supported by server. */
    {1, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {2, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* Specify curve from client. */
    {0, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer4.key", "../ecc_certificates/ECTestServer4.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer3.key", "../ecc_certificates/ECTestServer3.crt", "../ecc_certificates/ECCA3.crt", NX_FALSE},

    /* Specify curve from server. */
    {3, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {4, NX_TRUE, "../ecc_certificates/ECTestServer4.key", "../ecc_certificates/ECTestServer4.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE},
    {5, NX_TRUE, "../ecc_certificates/ECTestServer3.key", "../ecc_certificates/ECTestServer3.crt", "../ecc_certificates/ECCA3.crt", NX_FALSE},

    /* Client curves not suitable for signature. */
    {0, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {0, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},

    /* Client curve not supported by server. */
    {3, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE},
    {4, NX_FALSE, "../ecc_certificates/ECTestServer4.key", "../ecc_certificates/ECTestServer4.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE},
#endif

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
        external_cmd[10] = curves[tests[i].curves_index];
        if (tests[i].verify)
        {
            external_cmd[18] = "-Verify";
        }
        else
        {
            external_cmd[18] = NULL;
        }

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
        if (i == 23)
        {
            external_cmd[0] = "openssl-1.1";
            external_cmd[13] = "-tls1_3";
            external_cmd[14] = "-ciphersuites";
            external_cmd[15] = "TLS_AES_128_GCM_SHA256";
        }
#endif

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
