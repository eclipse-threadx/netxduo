#include "tls_test_frame.h"

INT nx_secure_ecc_server_curves_entry(TLS_TEST_INSTANCE* instance_ptr);
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
                                      "nx_secure_ecc_server_curves_entry",      /* instance name */
                                      nx_secure_ecc_server_curves_entry,        /* test entry */
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
    UINT curve_index;
    UINT ca_index;
    UINT session_succ;
} TEST_CASE;

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

static UCHAR *cas[] =
{
    "../../ecc_certificates/ECCA2.crt",
    "../../ecc_certificates/ECCA3.crt",
    "../../ecc_certificates/ECCA4.crt",
};

static TEST_CASE curves_client[] =
{

    /* Select curve by certificate. */
    {0, 0, NX_TRUE},
    {0, 0, NX_TRUE},
    {0, 0, NX_TRUE},
    {0, 2, NX_TRUE},
    {0, 1, NX_TRUE},

    /* Specify curve from client. */
    {6, 0, NX_TRUE},
    {7, 0, NX_TRUE},
    {3, 0, NX_TRUE},
    {4, 2, NX_TRUE},
    {5, 1, NX_TRUE},

    /* Specify curve from server. */
    {0, 0, NX_TRUE},
    {0, 0, NX_TRUE},
    {0, 0, NX_TRUE},
    {0, 2, NX_TRUE},
    {0, 1, NX_TRUE},

    /* Configure invalid curves at server side. */
    {0, 0, NX_FALSE},
    {0, 0, NX_FALSE},
    {0, 0, NX_FALSE},
    {0, 0, NX_FALSE},

#if 0
    /* Though the P256 is not in supported list, openssl is still able to verify the issuer. */
    /* Multiple curves used by server and CA cert. */
    {1, 0, NX_FALSE},  /* ECCA2_der uses P256 which is not supported. */
    {2, 0, NX_FALSE},  /* ECCA2_der uses P256 which is not supported. */
#endif

    /* Client curve not supported by server. */
    {3, 0, NX_FALSE},
    {3, 0, NX_FALSE},

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    /* Specify curve from client. */
    {3, 0, NX_TRUE},
    {4, 2, NX_TRUE},
    {5, 1, NX_TRUE},

    /* Specify curve from server. */
    {0, 0, NX_TRUE},
    {0, 2, NX_TRUE},
    {0, 1, NX_TRUE},

    /* Configure invalid curves at server side. */
    {0, 0, NX_FALSE},
    {0, 0, NX_FALSE},

    /* Client curve not supported by server. */
    {5, 1, NX_FALSE},
    {5, 1, NX_FALSE},
#endif
};

/* Instance two test entry. */
INT openssl_ecc_client_entry( TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)

/* Just use TLSv1.2 */
CHAR* external_cmd[] = { "openssl_echo_client.sh", TLS_TEST_IP_ADDRESS_STRING, DEVICE_SERVER_PORT_STRING,
                         "-curves", "", "-CAfile", "", (CHAR*)NULL};
INT status, exit_status, instance_status = TLS_TEST_SUCCESS, i = 0;

    for ( ; i < sizeof(curves_client) / sizeof(TEST_CASE); i++)
    {

        print_error_message("Connection %d: waiting for semaphore.\n", i);
        tls_test_semaphore_wait(semaphore_echo_server_prepared);
        tls_test_sleep(1);
        print_error_message("Connection %d: client get semaphore. Launch a external test program.\n", i);

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
        if (i == 21)
        {
            external_cmd[0] = "openssl_1_1_echo_client.sh";
        }
#endif

        /* Call an external program to connect to tls server. */
        external_cmd[4] = curves[curves_client[i].curve_index];
        external_cmd[6] = cas[curves_client[i].ca_index];
        status = tls_test_launch_external_test_process(&exit_status, external_cmd);
        return_value_if_fail(TLS_TEST_SUCCESS == status, status);

        /* Check for exit_status. */
        if ((exit_status && curves_client[i].session_succ) ||
            (!exit_status && !curves_client[i].session_succ))
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
