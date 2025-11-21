#include "tls_test_frame.h"

INT demo_background_test_process_test_entry(TLS_TEST_INSTANCE* instance_ptr);

INT main(INT argc, CHAR* argv[])
{
INT status, exit_status;
UINT offset, length;
VOID* shared_buffer;
TLS_TEST_INSTANCE *ins0;
TLS_TEST_DIRECTOR *director;

    /* Create a test instance. */
    status = tls_test_instance_create(&ins0,                                    /* test instance ptr */
                                      "background_test_process_test_instance",  /* instance name */
                                      demo_background_test_process_test_entry,            /* test entry */
                                      0,                                        /* delay(seconds) */
                                      10,                                       /* timeout(seconds) */
                                      1024,                                     /* shared buffer size */
                                      NULL);                                    /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Launch the test instance. */
    status = tls_test_director_create(&director, NULL);
    status += tls_test_director_register_test_instance(director, ins0);
    status += tls_test_director_test_start(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Check exit status. */
    status = tls_test_instance_get_exit_status(ins0, &exit_status);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Destroy the test director and registered test instances. */
    status = tls_test_director_clean_all(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    return_value_if_fail(-SIGALRM == exit_status, TLS_TEST_INSTANCE_FAILED);
    return 0;
}

INT demo_background_test_process_test_entry(TLS_TEST_INSTANCE* instance_ptr)
{
INT exit_status, status;
UINT length;
TLS_TEST_EXTERNAL_TEST_PROCESS ext_p;

/* Sleep for 10 seconds and then echo "hello". */
CHAR* external_cmd[] = { "sleep.sh", "10", (CHAR*)NULL};

    /* Launch the test program in background. */
    status = tls_test_launch_external_test_process_in_background( &ext_p, external_cmd);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);

    /* Kill the external test process before termination. */
    tls_test_sleep(3);
    status = tls_test_kill_external_test_process( &ext_p);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);

    /* Get the exit status of the test process which is kill by SIGTERM. */
    status = tls_test_wait_external_test_process( &ext_p, &exit_status);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);
    return_value_if_fail( -SIGTERM == exit_status, TLS_TEST_INSTANCE_FAILED);

    /* Sleep for only 1 seconds this time. */
    external_cmd[1] = "1";
    status = tls_test_launch_external_test_process_in_background( &ext_p, external_cmd);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);

    /* Get the exit status of the test process. */
    status = tls_test_wait_external_test_process( &ext_p, &exit_status);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);
    return_value_if_fail( 0 == exit_status, TLS_TEST_INSTANCE_FAILED);

    /* The test instance will be killed by SIGALRM this time. */
    external_cmd[1] = "10";
    status = tls_test_launch_external_test_process_in_background( &ext_p, external_cmd);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);

    status = tls_test_wait_external_test_process( &ext_p, &exit_status);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);

    return exit_status;
}
