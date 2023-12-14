#include "tls_test_frame.h"

INT demo_background_test_process_test_entry(TLS_TEST_INSTANCE* instance_ptr);

INT main(INT argc, CHAR* argv[])
{
INT status, exit_status;
UINT offset, length;
VOID* shared_buffer;
TLS_TEST_INSTANCE *ins0;
TLS_TEST_DIRECTOR *director;
TLS_TEST_EXTERNAL_TEST_PROCESS ext_p;

    /* Create a test instance. */
    status = tls_test_instance_create(&ins0,                                    /* test instance ptr */
                                      "background_test_process_test_instance",  /* instance name */
                                      demo_background_test_process_test_entry,  /* test entry */
                                      0,                                        /* delay(seconds) */
                                      10,                                        /* timeout(seconds) */
                                      1024,                                     /* shared buffer size */
                                      NULL);                                    /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Launch the test instance. */
    status = tls_test_director_create(&director, NULL);
    status += tls_test_director_register_test_instance(director, ins0);
    status += tls_test_director_test_start(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Show exit status. */
    status = tls_test_instance_show_exit_status(ins0);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Get the shared buffer of the test instance. */
    status = tls_test_instance_get_shared_buffer(ins0, &shared_buffer);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Get external test process control block. */
    memcpy(&ext_p, shared_buffer, sizeof(ext_p));

    /* Make sure that the test frame has been terminated. */
    return_value_if_fail( ( -1 == kill( ext_p.tls_test_external_test_process_id, 0)) && ( errno == ESRCH), TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Destroy the test director and registered test instances. */
    status = tls_test_director_clean_all(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    return 0;
}

INT demo_background_test_process_test_entry(TLS_TEST_INSTANCE* instance_ptr)
{
INT exit_status, status;
UINT length;
TLS_TEST_EXTERNAL_TEST_PROCESS ext_p;

/* Sleep for 10 seconds and then echo "hello". */
CHAR* external_cmd[] = { "sleep.sh", "20", (CHAR*)NULL};

    /* Launch the test program in background. */
    status = tls_test_launch_external_test_process_in_background( &ext_p, external_cmd);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);

    /* Store the structure of external test process control block in shared buffer. */
    length = sizeof(ext_p);
    status = tls_test_instance_append_data_to_shared_buffer(instance_ptr, &ext_p, &length);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);

    /* Exit from the test instance entry without waiting for the launched external process. */
    return 0;
}
