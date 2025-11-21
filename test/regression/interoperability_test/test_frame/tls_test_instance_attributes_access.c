#include "tls_test_frame.h"

/* Get the name of the instance. */
INT tls_test_instance_get_name( TLS_TEST_INSTANCE* instance_ptr, CHAR** name_ptr)
{
    *name_ptr = instance_ptr -> tls_test_instance_name;
    return_value_if_fail(NULL != *name_ptr, TLS_TEST_UNKNOWN_TYPE_ERROR);
    return TLS_TEST_SUCCESS;
}

/* Get the exit code of the instance. */
INT tls_test_instance_get_exit_status( TLS_TEST_INSTANCE* instance_ptr, INT* exit_status_ptr)
{
    *exit_status_ptr = instance_ptr -> tls_test_instance_exit_status;
    return TLS_TEST_SUCCESS;
}

/* Print the comments of the exit status of test instances. */
INT tls_test_instance_show_exit_status(TLS_TEST_INSTANCE* instance_ptr)
{
INT         status, exit_status;
CHAR        *name;

    /* Check instance pointer. */
    return_value_if_fail(NULL != instance_ptr, TLS_TEST_INVALID_POINTER);

    /* Ensure that the test instance is exited or signaled. */
    return_value_if_fail(instance_ptr -> tls_test_instance_status & (TLS_TEST_INSTANCE_STATUS_EXITED | TLS_TEST_INSTANCE_STATUS_SIGNALED), TLS_TEST_INSTANCE_UNEXITED);

    status = tls_test_instance_get_exit_status(instance_ptr, &exit_status);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_get_name(instance_ptr, &name);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    if (0 <= exit_status)
    {
        print_error_message("Instance %s exited with return code %d.\n", name, exit_status);
    }
    else if (0 > exit_status)
    {
        print_error_message("Instance %s is killed by signal %d.\n", name, -exit_status);
    }
    return TLS_TEST_SUCCESS;
}
