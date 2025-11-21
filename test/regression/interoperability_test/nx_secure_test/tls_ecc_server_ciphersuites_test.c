#include "tls_test_frame.h"

INT nx_secure_ecc_server_ciphersuites_entry(TLS_TEST_INSTANCE* instance_ptr);
INT openssl_ecc_client_entry(TLS_TEST_INSTANCE* instance_ptr);
extern UINT ciphersuites_server_count;

/* Global demo semaphore. */
TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;

INT main( INT argc, CHAR* argv[])
{
INT status, exit_status[2];
TLS_TEST_INSTANCE *ins0;
TLS_TEST_INSTANCE *ins1;

    /* Create two test instances. */
    status = tls_test_instance_create(&ins0,                                    /* test instance ptr */
                                      "nx_secure_ecc_server_ciphersuites_entry",/* instance name */
                                      nx_secure_ecc_server_ciphersuites_entry,  /* test entry */
                                      0,                                        /* delay(seconds) */
                                      60,                                       /* timeout(seconds) */
                                      1024,                                     /* shared buffer size */
                                      NULL);                                    /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_create(&ins1,
                                      "openssl_ecc_client_entry",
                                      openssl_ecc_client_entry,
                                      0,
                                      60,
                                      1024,
                                      NULL);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Create a semaphore and set the initial value as 0. */
    status = tls_test_semaphore_create(&semaphore_echo_server_prepared, 0);

    /* Create the test director. */
    TLS_TEST_DIRECTOR *director;
    status = tls_test_director_create(&director, NULL /* reserved */);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Register test instances to the director. */
    status = tls_test_director_register_test_instance(director, ins0);
    status += tls_test_director_register_test_instance(director, ins1);
    return_value_if_fail(TLS_TEST_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Launch test. */
    status = tls_test_director_test_start(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Collect exit code. */
    tls_test_instance_show_exit_status(ins0);
    tls_test_instance_show_exit_status(ins1);

    /* Call the verify method to determine whether the test is passed. */
    status = tls_test_instance_get_exit_status(ins0, &exit_status[0]);
    show_error_message_if_fail(TLS_TEST_SUCCESS == status);
    status = tls_test_instance_get_exit_status(ins1, &exit_status[1]);
    show_error_message_if_fail(TLS_TEST_SUCCESS == status);

    /* Destroy registered test instances and the director. */
    tls_test_director_clean_all(director);

    /* Destroy the semaphore. */
    tls_test_semaphore_destroy(semaphore_echo_server_prepared);

    /* Return error if get unexpected test results. */
    if ((TLS_TEST_NOT_AVAILABLE == exit_status[0]) || (TLS_TEST_NOT_AVAILABLE == exit_status[1]))
        return TLS_TEST_NOT_AVAILABLE;

    /* Return the result of verification. */
    return exit_status[0] | exit_status[1];
}

typedef struct
{
    UINT cipher_index;
    UINT session_succ;
} CIPHERSUITE;

static CHAR *ciphers[] =
{
    "ALL",
    "ECDH-ECDSA-AES128-SHA",
    "ECDH-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDH-ECDSA-AES128-GCM-SHA256",
    "ECDH-RSA-AES128-GCM-SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
};

static CIPHERSUITE ciphersuites_client[] =
{

    /* Select ciphersuite according to certificate. */
    {0, NX_TRUE},
    {0, NX_TRUE},
    {0, NX_TRUE},
    {0, NX_TRUE},

    /* Select ciphersuite according to certificate.
     * The order of client ciphersuites are reversed of server. */
    {5, NX_TRUE},
    {5, NX_TRUE},
    {5, NX_TRUE},

    /* Specified ciphersuites. */
    /* {1, NX_TRUE}, */
    /* {2, NX_TRUE}, */
    {3, NX_TRUE},
    {4, NX_TRUE},

    /* The Server cert supports ECDH_ECDSA and ECDHE_ECDSA. */
    /* {1, NX_TRUE}, */
    /* {2, NX_FALSE},*/    /* ECDH_RSA not supported. */
    {3, NX_TRUE},
    {4, NX_FALSE},    /* ECDHE_RSA not supported. */

    /* Let the server pickup supported ciphersuite. */
    {0, NX_TRUE},
    {0, NX_TRUE},
    {0, NX_TRUE},
    {0, NX_TRUE},
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/
    /*{0, NX_TRUE},*/

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    /* AES128-GCM ciphersuites. */
    {6, NX_TRUE},
    {7, NX_TRUE},
    /*{8, NX_TRUE},*/
    /*{9, NX_TRUE},*/

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* Test TLS 1.3 ciphersuites. */
    {10, NX_TRUE},
    {12, NX_TRUE},
    {13, NX_TRUE},

    /* Client sends ciphersuites not supported by server. */
    {11, NX_FALSE},
#endif
#endif
};

/* Instance two test entry. */
INT openssl_ecc_client_entry( TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)

/* Just use TLSv1.2 */
CHAR* external_cmd[] = { "openssl_echo_client.sh", TLS_TEST_IP_ADDRESS_STRING, DEVICE_SERVER_PORT_STRING,
                         "-cipher", "", (CHAR*)NULL};
INT status, exit_status, instance_status = TLS_TEST_SUCCESS, i = 0;

    for ( ; i < sizeof(ciphersuites_client) / sizeof(CIPHERSUITE); i++)
    {

        print_error_message("Connection %d: waiting for semaphore.\n", i);
        tls_test_semaphore_wait(semaphore_echo_server_prepared);
        tls_test_sleep(1);
        print_error_message("Connection %d: client get semaphore. Launch a external test program.\n", i);

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
        if (ciphersuites_client[i].cipher_index == 10)
        {
            external_cmd[0] = "openssl_1_1_echo_client.sh";
            external_cmd[3] = "-ciphersuites";
        }
#endif

        /* Call an external program to connect to tls server. */
        external_cmd[4] = ciphers[ciphersuites_client[i].cipher_index];
        status = tls_test_launch_external_test_process(&exit_status, external_cmd);
        return_value_if_fail(TLS_TEST_SUCCESS == status, status);

        /* Check for exit_status. */
        if ((exit_status && ciphersuites_client[i].session_succ) ||
            (!exit_status && !ciphersuites_client[i].session_succ))
        {

            /* Record errors. */
            instance_status = TLS_TEST_INSTANCE_EXTERNAL_PROGRAM_FAILED;
        }
    }
    return instance_status;

#else /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

    return TLS_TEST_NOT_AVAILABLE;

#endif /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

}
