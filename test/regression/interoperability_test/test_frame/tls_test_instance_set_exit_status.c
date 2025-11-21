#include "tls_test_frame.h"

/* Set the exit status of the test instance. */
/* The argument of exit_status must be set by system call of wait or waitpid. */
INT tls_test_instance_set_exit_status( TLS_TEST_INSTANCE* instance_ptr, INT exit_status)
{

    /* Check for pointers. */
    return_value_if_fail( NULL != instance_ptr, TLS_TEST_INVALID_POINTER);

    /* Clear running flag. */
    instance_ptr -> tls_test_instance_status &= ~TLS_TEST_INSTANCE_STATUS_RUNNING;
    instance_ptr -> tls_test_instance_exit_status = 0;

    /* Set the exit_status member of the test instance. */
    if ( WIFEXITED( exit_status))
    {
        instance_ptr -> tls_test_instance_status |= TLS_TEST_INSTANCE_STATUS_EXITED;
        instance_ptr -> tls_test_instance_exit_status = WEXITSTATUS( exit_status);
    }
    else if ( WIFSIGNALED( exit_status))
    {
        instance_ptr -> tls_test_instance_status |= TLS_TEST_INSTANCE_STATUS_SIGNALED;
        instance_ptr -> tls_test_instance_exit_status = -WTERMSIG( exit_status);
    }
    else
    {
        /* unresolvable exit status. */
        return TLS_TEST_UNKNOWN_TYPE_ERROR;
    }

    return TLS_TEST_SUCCESS;
}
