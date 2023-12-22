#include "tls_test_frame.h"

/* Launch an external test process and redirect the output to a given buffer. */
INT tls_test_get_external_test_process_output( INT* exit_status_ptr, CHAR* argv[], VOID* output_buffer, ULONG* length_ptr)
{
    /* Check pointer arguments. */
    return_value_if_fail( NULL != exit_status_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != output_buffer, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != length_ptr, TLS_TEST_INVALID_POINTER);

    ULONG length_limitation = *length_ptr;
    INT status;

    /* Create a pipe to get the output of external test process. */
    int pipe_fd[2];
    status = pipe( pipe_fd);
    return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);
    
    /* Fork a child process to execute external command. */
    pid_t pid = fork();
    return_value_if_fail( -1 != pid, TLS_TEST_SYSTEM_CALL_FAILED);

    if ( 0 == pid)
    {
        /* Child process. */

        /* Closed unused read end. */
        close( pipe_fd[0]);

        /* Redirect stdout and stderr to write end. */
        status = dup2( pipe_fd[1], 1);
        exit_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);

        /* Call the system call of exec to execute test programs under $PATH. */
        status = execvp( argv[0], argv);
        exit_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);
        exit( status);
    }
    else
    {
        /* Parent process. */

        /* Closed unused write end. */
        close( pipe_fd[1]);

        UINT len = 0;

        /* Read data from pipe. */
        len = read( pipe_fd[0], output_buffer, length_limitation);
        return_value_if_fail( -1 != len, TLS_TEST_SYSTEM_CALL_FAILED);

        /* Return bytes actually read. */
        *length_ptr = len;

        /* Close the pipe. */
        close( pipe_fd[0]);

        /* Wait for external test process. */
        status = waitpid( pid, exit_status_ptr, 0);
        return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);

        return TLS_TEST_SUCCESS;
    }
}
