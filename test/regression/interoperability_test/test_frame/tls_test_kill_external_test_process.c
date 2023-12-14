#include "tls_test_frame.h"

/* Call external program without output redirecting. */
INT tls_test_kill_external_test_process( TLS_TEST_EXTERNAL_TEST_PROCESS* test_process_ptr)
{
    /* Validate pointers. */
    return_value_if_fail( NULL != test_process_ptr, TLS_TEST_INVALID_POINTER);

    INT status;
    status = kill( test_process_ptr -> tls_test_external_test_process_id, SIGTERM);
    return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);

    return TLS_TEST_SUCCESS;
}
