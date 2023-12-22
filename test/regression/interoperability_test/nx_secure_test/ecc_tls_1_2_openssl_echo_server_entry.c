#include "tls_test_frame.h"

typedef struct
{
    UINT cipher_index;
    UINT session_succ;
    CHAR *key;
    CHAR *cert;
    CHAR *ca;
    UINT verify;
    UCHAR *version;
} OPENSSLTEST;

static CHAR *ciphers[] =
{
    "ALL",
    "ECDH-ECDSA-AES128-SHA",
    "ECDH-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA",
    "ECDH-ECDSA-AES256-SHA256",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDH-RSA-AES256-SHA256",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDH-ECDSA-AES128-SHA256",
    "ECDH-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA384",
    "ECDH-RSA-AES128-SHA256",
    "ECDH-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDH-ECDSA-AES128-GCM-SHA256",
    "ECDH-RSA-AES128-GCM-SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
};

CHAR* external_cmd[] = { "openssl", "s_server", "-rev", 
                         "-key", "4-key",
                         "-cert", "6-cert",
                         "-CAfile", "8-ca",
                         "-cipher", "10-cipher",
                         "-naccept", "1", "-tls1_2",
                         "-port", DEVICE_SERVER_PORT_STRING,
                         "14-Verify", "10",
                        (CHAR*)NULL};

OPENSSLTEST tests[] =
{
    /* Select ciphersuite according to certificate. */
    {0, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1_2"},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1_2"},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer10.key", "../ecc_certificates/ECTestServer10.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},

    /* Select ciphersuite according to certificate.
     * The order of client ciphersuites are reversed of server. */
    {0, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1_2"},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},
    {0, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1_2"},

    /* Specified ciphersuites. */
    /* {1, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"}, */
    /* {2, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1_2"}, */
    {3, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},
    {4, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1_2"},

    /* The Server cert supports ECDH_ECDSA and ECDHE_ECDSA. */
    /* {0, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"}, */
    /* {0, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"}, */
    {0, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},
    {0, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},

    /* Let the server pickup supported ciphersuite. */
    /* {1, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"}, */
    /* {2, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1_2"}, */
    {3, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},
    {4, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1_2"},

    /* {6, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"}, */
    /* {7, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"}, */
    /* {8, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1_2"}, */
    /* {9, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1_2"}, */
    {10, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},
    /*{11, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},*/
    /*{12, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},*/
    /*{13, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},*/
    {14, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1_2"},
    /*{15, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1_2"},*/
    /*{16, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1_2"},*/
    /*{17, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1_2"},*/

#ifdef NX_SECURE_TLS_ENABLE_TLS_1_0

    /* Specified ciphersuites. */
    /*{1, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1"},*/
    /*{2, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1"},*/
    {7, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1"},
    {9, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1"},
#endif /* NX_SECURE_TLS_ENABLE_TLS_1_0 */

#ifdef NX_SECURE_TLS_ENABLE_TLS_1_1

    /* Specified ciphersuites. */
    /*{1, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_1"},*/
    /*{2, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1_1"},*/
    {7, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_1"},
    {9, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1_1"},
#endif /* NX_SECURE_TLS_ENABLE_TLS_1_1 */

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    /* AES128-GCM ciphersuites. */
    {18, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},
    {19, NX_TRUE, "../ecc_certificates/ECTestServer6.key", "../ecc_certificates/ECTestServer6.crt", "../ecc_certificates/ECCA4.crt", NX_FALSE, "-tls1_2"},
    /*{20, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_2"},*/
    /*{21, NX_TRUE, "../ecc_certificates/ECTest.key", "../ecc_certificates/ECTest.crt", "../ecc_certificates/ECCA.crt", NX_FALSE, "-tls1_2"},*/

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* Test TLS 1.3 ciphersuites. */
    {22, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_3"},
    {24, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_3"},
    {25, NX_TRUE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_3"},

    /* Client sends ciphersuites not supported by server. */
    {23, NX_FALSE, "../ecc_certificates/ECTestServer2.key", "../ecc_certificates/ECTestServer2.crt", "../ecc_certificates/ECCA2.crt", NX_FALSE, "-tls1_3"},
#endif
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
        external_cmd[10] = ciphers[tests[i].cipher_index];
        external_cmd[13] = tests[i].version;
        if (tests[i].verify)
        {
            external_cmd[16] = "-Verify";
        }
        else
        {
            external_cmd[16] = NULL;
        }

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
        if (tests[i].cipher_index == 22)
        {
            external_cmd[0] = "openssl-1.1";
            external_cmd[9] = "-ciphersuites";
            external_cmd[13] = "-tls1_3";
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
