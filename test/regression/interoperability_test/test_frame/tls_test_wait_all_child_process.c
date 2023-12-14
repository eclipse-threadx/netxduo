#include "tls_test_frame.h"

/* Wait until all child processes terminated. */
INT tls_test_wait_all_child_process( void* reserved_ptr)
{
    pid_t pid;
    INT exit_status;

    while ( TLS_TEST_SUCCESS == tls_test_uninterruptable_wait( &pid, &exit_status));

    return TLS_TEST_SUCCESS;
}
