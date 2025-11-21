#include "tls_test_frame.h"

INT openssl_echo_server_entry(TLS_TEST_INSTANCE* instance_ptr);
INT nx_secure_echo_client_entry(TLS_TEST_INSTANCE* instance_ptr);

/* Global demo semaphore. */
TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;

INT main( INT argc, CHAR* argv[])
{
INT status, exit_status[2], i;
TLS_TEST_INSTANCE *ins0;
TLS_TEST_INSTANCE *ins1;

    /* Create two test instances. */
    status = tls_test_instance_create(&ins0,                                /* test instance ptr */
                                      "openssl_echo_server",                /* instance name */
                                      openssl_echo_server_entry,            /* test entry */
                                      0,                                    /* delay(seconds) */
                                      1200,                                   /* timeout(seconds) */
                                      1024,                                 /* shared buffer size */
                                      NULL);                                /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_create(&ins1, 
                                      "nx_secure_echo_client",
                                      nx_secure_echo_client_entry,
                                      0,
                                      1200,
                                      1024,
                                      NULL);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Create a semaphore and set the initial value as 0. */
    status = tls_test_semaphore_create(&semaphore_echo_server_prepared, 0);
    show_error_message_if_fail(TLS_TEST_SUCCESS == status);

    /* Create the test director. */
    TLS_TEST_DIRECTOR *director;
    status = tls_test_director_create(&director, NULL /* reserved */);
    show_error_message_if_fail(TLS_TEST_SUCCESS == status);

    /* Register test instances to the director. */
    status = tls_test_director_register_test_instance(director, ins0);
    status += tls_test_director_register_test_instance(director, ins1);
    show_error_message_if_fail(TLS_TEST_SUCCESS == status);

    /* Launch test. */
    status = tls_test_director_test_start(director);
    show_error_message_if_fail(TLS_TEST_SUCCESS == status);

    /* Error checking. */
    status = tls_test_instance_show_exit_status(ins0);
    show_error_message_if_fail(TLS_TEST_SUCCESS == status);
    status = tls_test_instance_show_exit_status(ins1);
    show_error_message_if_fail(TLS_TEST_SUCCESS == status);

    /* Verify the exit status of the test instance of nx_secure echo client. */
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

    return exit_status[0] | exit_status[1];
}
