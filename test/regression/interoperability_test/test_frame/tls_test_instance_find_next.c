#include "tls_test_frame.h"

/* Find next instance. */
INT tls_test_instance_find_next( TLS_TEST_INSTANCE* instance_ptr, TLS_TEST_INSTANCE** next_instance_ptr_ptr)
{
    return_value_if_fail( NULL != instance_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != next_instance_ptr_ptr, TLS_TEST_INVALID_POINTER);

    *next_instance_ptr_ptr = instance_ptr -> tls_test_next_instance_ptr;
    return TLS_TEST_SUCCESS;
}
