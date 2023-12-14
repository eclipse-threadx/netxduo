#include "tls_test_frame.h"

/* Declare the test entries of two test instances. */
INT demo_func_entry_0(TLS_TEST_INSTANCE* instance_ptr);
INT demo_func_entry_1(TLS_TEST_INSTANCE* instance_ptr);

/* Declare a global variable for demo semaphore. */
TLS_TEST_SEMAPHORE* demo_semaphore;

INT main( INT argc, CHAR* argv[])
{
INT status;
TLS_TEST_INSTANCE *ins0, *ins1;
INT exit_status[2];
TLS_TEST_DIRECTOR *director;

    /* Create two test instances. */
    status = tls_test_instance_create(&ins0,                          /* test instance ptr */
                                      "semaphore_wait_instance",      /* instance name */
                                      demo_func_entry_0,              /* test entry */
                                      0,                              /* delay(seconds) */
                                      10,                             /* timeout(seconds) */
                                      1024,                           /* shared buffer size */
                                      NULL);                          /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_create(&ins1, 
                                      "semaphore_post_instance",
                                      demo_func_entry_1,
                                      0,
                                      10,
                                      1024,
                                      NULL);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Create a semaphore and set the initial value as 0. */
    status = tls_test_semaphore_create(&demo_semaphore, 0);
    print_error_message("semaphore address: %p\n", demo_semaphore);

    /* Create the test director. */
    status = tls_test_director_create(&director, NULL /* reserved */);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Register test instances to the director. */
    status = tls_test_director_register_test_instance(director, ins0);
    status += tls_test_director_register_test_instance(director, ins1);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Launch test. */
    status = tls_test_director_test_start(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Collect exit code. */
    tls_test_instance_get_exit_status(ins0, &(exit_status[0]));
    tls_test_instance_get_exit_status(ins1, &(exit_status[1]));

    /* Destroy all created instances. */
    tls_test_director_clean_all(director);

    /* Destroy the semaphore. */
    tls_test_semaphore_destroy(demo_semaphore);

    /* Check the exit codes of two instances. */
    return_value_if_fail((0 == exit_status[0]) && (0 == exit_status[1]), TLS_TEST_UNKNOWN_TYPE_ERROR);
    return TLS_TEST_SUCCESS;
}

/* Wait for a semaphore and exit. */
INT demo_func_entry_0(TLS_TEST_INSTANCE* instance_ptr)
{  
CHAR* name;
INT status;

    /* Get the name of the instance. */
    status = tls_test_instance_get_name(instance_ptr, &name);

    /* Get semaphore address from the shared buffer. */
    print_error_message("%s: get semaphore address: %p\n", name, demo_semaphore);

    /* Output debug messages to stderr(no buffer). */
    print_error_message("%s: wait for semaphore...\n", name);

    /* Wait for the semaphore. */
    status += tls_test_semaphore_wait(demo_semaphore);
    print_error_message("%s: get semaphore...\n", name);

    /* Error checking. */
    return_value_if_fail(TLS_TEST_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    return TLS_TEST_SUCCESS;
}

/* Sleep for 5 seconds and then post a semaphore. */
INT demo_func_entry_1( TLS_TEST_INSTANCE* instance_ptr)
{
CHAR* name;
INT status;

    /* Get the name of the instance. */
    status = tls_test_instance_get_name(instance_ptr, &name);

    /* Get semaphore address from the shared buffer. */
    print_error_message("%s: get semaphore address: %p\n", name, demo_semaphore);

    /* Sleep for 5 seconds. */
    /* tls_test_sleep will be woke up by SIGUSR1 immediately in the threads manipulated by ThreadX. */
    /* Please use tx_thread_sleep after calling tx_kernel_enter */
    print_error_message("%s: sleeping...\n", name);
    tls_test_sleep(5);

    /* Post the semaphore. */
    print_error_message("%s: post semaphore...\n", name);
    status += tls_test_semaphore_post(demo_semaphore);

    /* Error checking. */
    return_value_if_fail(TLS_TEST_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    return TLS_TEST_SUCCESS;
}
