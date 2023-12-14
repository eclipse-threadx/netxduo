#include "tls_test_frame.h"

INT demo_timeout_test_entry(TLS_TEST_INSTANCE* instance_ptr);

INT main(INT argc, CHAR* argv[])
{
INT status, exit_status;
UINT offset, length;
VOID* shared_buffer;
TLS_TEST_INSTANCE *ins0;
TLS_TEST_DIRECTOR *director;

    /* Create a test instance. */
    status = tls_test_instance_create(&ins0,                          /* test instance ptr */
                                      "timeout_test_instance",        /* instance name */
                                      demo_timeout_test_entry,        /* test entry */
                                      0,                              /* delay(seconds) */
                                      3,                             /* timeout(seconds) */
                                      1024,                           /* shared buffer size */
                                      NULL);                          /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Launch the test instance. */
    status = tls_test_director_create(&director, NULL);
    status += tls_test_director_register_test_instance(director, ins0);
    status += tls_test_director_test_start(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Get exit status. */
    status = tls_test_instance_get_exit_status(ins0, &exit_status);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_show_exit_status(ins0);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);

    /* Destroy the test director and registered test instances. */
    status = tls_test_director_clean_all(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Check exit status. */
    return_value_if_fail( -SIGALRM == exit_status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    return 0;
}

INT demo_timeout_test_entry(TLS_TEST_INSTANCE* instance_ptr)
{
INT status, exit_status;
CHAR* external_cmd[] = { "sleep_5_secs_then_echo_hello.sh", NULL};

    status = tls_test_launch_external_test_process( &exit_status, external_cmd);
    return exit_status;
}
