#include "tls_test_frame.h"

INT demo_server_entry(TLS_TEST_INSTANCE* instance_ptr);
INT demo_client_entry(TLS_TEST_INSTANCE* instance_ptr);

/* Global demo semaphore. */
TLS_TEST_SEMAPHORE* demo_semaphore;

INT main( INT argc, CHAR* argv[])
{
INT status, exit_status[2];
TLS_TEST_INSTANCE *ins0;
TLS_TEST_INSTANCE *ins1;

    /* Create two test instances. */
    status = tls_test_instance_create(&ins0,              /* test instance ptr */
                                      "demo_server",      /* instance name */
                                      demo_server_entry,  /* test entry */
                                      0,                  /* delay(seconds) */
                                      20,                 /* timeout(seconds) */
                                      1024,               /* shared buffer size */
                                      NULL);              /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_create(&ins1, 
                                      "demo_client",
                                      demo_client_entry,
                                      0,
                                      20,
                                      1024,
                                      NULL);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Create a semaphore and set the initial value as 0. */
    status = tls_test_semaphore_create(&demo_semaphore, 0);

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
    tls_test_instance_get_exit_status(ins0, &(exit_status[0]));
    tls_test_instance_get_exit_status(ins1, &(exit_status[1]));
    tls_test_instance_show_exit_status(ins0);
    tls_test_instance_show_exit_status(ins1);

    /* Destroy registered test instances and the director. */
    tls_test_director_clean_all(director);

    /* Destroy the semaphore. */
    tls_test_semaphore_destroy(demo_semaphore);

    /* Is this test point disabled? */
    if ((TLS_TEST_NOT_AVAILABLE == exit_status[0]) || (TLS_TEST_NOT_AVAILABLE == exit_status[1]))
        return TLS_TEST_NOT_AVAILABLE;

    return exit_status[0] | exit_status[1];
}

/* Instance two test entry. */
INT demo_client_entry( TLS_TEST_INSTANCE* instance_ptr)
{
CHAR* external_cmd[] = { "demo_openssl_client.sh", TLS_TEST_IP_ADDRESS_STRING, DEVICE_SERVER_PORT_STRING, "-dtls1_2", (CHAR*)NULL};
INT status, exit_status, instance_status = TLS_TEST_SUCCESS, i = 0;

    for ( ; i < 1; i++)
    {
        print_error_message("Client connection %d: waiting for semaphore.\n", i);
        tls_test_semaphore_wait(demo_semaphore);
        tls_test_sleep(1);
        print_error_message("Client connection %d: client get semaphore. Launch a external test program.\n", i);

        /* Call an external program to connect to tls server. */
        status = tls_test_launch_external_test_process(&exit_status, external_cmd);
        return_value_if_fail(TLS_TEST_SUCCESS == status, status);

        /* Check for exit_status. */
        if (exit_status)
        {
            /* Record errors. */
            instance_status = TLS_TEST_INSTANCE_EXTERNAL_PROGRAM_FAILED;
        }
    }
    return instance_status;
}

/* The definition of demo_server_entry is located at demo_tls_test_server.c */
