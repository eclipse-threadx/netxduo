#include "tls_test_frame.h"

/* Destroy test instance. */
INT tls_test_instance_destroy( TLS_TEST_INSTANCE* instance_ptr)
{
    return_value_if_fail( NULL != instance_ptr, TLS_TEST_INVALID_POINTER);

    /* Release the shared memory occupied by the test intance. */
    INT status = munmap( instance_ptr, instance_ptr -> tls_test_shared_buffer_size + sizeof(TLS_TEST_INSTANCE));
    return_value_if_fail( TLS_TEST_SUCCESS == status, TLS_TEST_SYSTEM_CALL_FAILED);
    return TLS_TEST_SUCCESS;
}
