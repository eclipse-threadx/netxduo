#include "tls_test_frame.h"

/* Call external program without output redirecting. */
INT tls_test_launch_external_test_process_in_background( TLS_TEST_EXTERNAL_TEST_PROCESS* test_process_ptr, CHAR* argv[])
{
    /* Validate pointers. */
    return_value_if_fail( NULL != test_process_ptr, TLS_TEST_INVALID_POINTER);

    pid_t pid;

    pid = fork();
    return_value_if_fail( -1 != pid, TLS_TEST_SYSTEM_CALL_FAILED);

    if ( 0 == pid)
    {
        /* Child process. */

        INT exec_status = execvp( argv[0], argv);
        exit_if_fail( -1 != exec_status, TLS_TEST_SYSTEM_CALL_FAILED);
    }
    else
    {
        /* Parent process. */

        test_process_ptr -> tls_test_external_test_process_id = pid;
        return TLS_TEST_SUCCESS;
    }
}

