#include "tls_test_frame.h"

/* Call external program without output redirecting. */
INT tls_test_launch_external_test_process( INT* exit_status_ptr, CHAR* argv[])
{
    /* Validate pointers. */
    return_value_if_fail( NULL != exit_status_ptr, TLS_TEST_INVALID_POINTER);

    INT status, process_status;
    pid_t pid;

    pid = fork();
    return_value_if_fail( -1 != pid, TLS_TEST_SYSTEM_CALL_FAILED);

    if ( 0 == pid)
    {
        /* Child process. */

        /* Enable the timer in child process which will not be inherited by forked child process. */
        INT exec_status = execvp( argv[0], argv);
        return_value_if_fail( -1 != exec_status, TLS_TEST_SYSTEM_CALL_FAILED);
    }
    else
    {
        /* Parent process. */

        status = waitpid( pid, &process_status, 0);
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
}

