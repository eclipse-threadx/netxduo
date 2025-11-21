#include "tls_test_frame.h"

INT nx_secure_ecc_server_cert_entry(TLS_TEST_INSTANCE* instance_ptr);
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
                                      "nx_secure_ecc_server_cert_entry",        /* instance name */
                                      nx_secure_ecc_server_cert_entry,          /* test entry */
                                      0,                                        /* delay(seconds) */
                                      30,                                       /* timeout(seconds) */
                                      1024,                                     /* shared buffer size */
                                      NULL);                                    /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_create(&ins1,
                                      "openssl_ecc_client_entry",
                                      openssl_ecc_client_entry,
                                      0,
                                      30,
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

/* Instance two test entry. */
INT openssl_ecc_client_entry( TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)

/* Just use TLSv1.2 */
CHAR* external_cmd[] = { "openssl_echo_client.sh", TLS_TEST_IP_ADDRESS_STRING, DEVICE_SERVER_PORT_STRING,
                         "-cert", "../../ecc_certificates/ECTestServer7_256.crt",
                         "-key", "../../ecc_certificates/ECTestServer7_256.key", (CHAR*)NULL};
INT status, exit_status;

    tls_test_semaphore_wait(semaphore_echo_server_prepared);
    tls_test_sleep(1);

    /* Call an external program to connect to tls server. */
    status = tls_test_launch_external_test_process(&exit_status, external_cmd);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    return exit_status;

#else /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

    return TLS_TEST_NOT_AVAILABLE;

#endif /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

}
