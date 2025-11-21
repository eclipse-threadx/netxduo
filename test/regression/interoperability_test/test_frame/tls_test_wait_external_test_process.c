#include "tls_test_frame.h"

/* Call external program without output redirecting. */
INT tls_test_wait_external_test_process( TLS_TEST_EXTERNAL_TEST_PROCESS* test_process_ptr, INT* exit_status_ptr)
{
    /* Validate pointers. */
    return_value_if_fail( NULL != test_process_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != exit_status_ptr, TLS_TEST_INVALID_POINTER);

    INT process_status = 0, status;
    status = waitpid( test_process_ptr -> tls_test_external_test_process_id, &process_status, 0);
    return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);

    *exit_status_ptr = 0;
    if ( WIFEXITED( process_status))
    {
        *exit_status_ptr = WEXITSTATUS( process_status);
    }
    else if ( WIFSIGNALED( process_status))
    {
        *exit_status_ptr = -WTERMSIG( process_status);
    }
    return TLS_TEST_SUCCESS;
}
