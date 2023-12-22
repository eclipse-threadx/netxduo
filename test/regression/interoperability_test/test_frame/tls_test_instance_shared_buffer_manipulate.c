#include "tls_test_frame.h"

/* Get offset of the shared buffer. */
INT tls_test_instance_get_shared_buffer_offset( TLS_TEST_INSTANCE* instance_ptr, UINT* offset)
{
    /* Validate pointers. */
    return_value_if_fail( NULL != instance_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != offset, TLS_TEST_INVALID_POINTER);

    /* Return shared buffer offset. */
    *offset = instance_ptr -> tls_test_shared_buffer_offset;
    return TLS_TEST_SUCCESS;
}

/* Set offset of the shared buffer preparing for appending data. */
INT tls_test_instance_set_shared_buffer_offset( TLS_TEST_INSTANCE* instance_ptr, UINT offset)
{
    /* Validate pointers. */
    return_value_if_fail( NULL != instance_ptr, TLS_TEST_INVALID_POINTER);

    /* Avoid offset exceeding shared_buffer_size. */
    return_value_if_fail( offset <= instance_ptr -> tls_test_shared_buffer_size, TLS_TEST_ILLEGAL_SHARED_BUFFER_ACCESS);

    /* Set shared buffer offset. */
    instance_ptr -> tls_test_shared_buffer_offset = offset;
    return TLS_TEST_SUCCESS;
}

/* Append data to the shared buffer after offset. */
INT tls_test_instance_append_data_to_shared_buffer( TLS_TEST_INSTANCE* instance_ptr, VOID* data, UINT* length)
{
    /* Validate pointers. */
    return_value_if_fail( NULL != instance_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != instance_ptr -> tls_test_shared_buffer, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != data, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != length, TLS_TEST_INVALID_POINTER);

    INT status;
    UINT shared_buffer_offset;
    status = tls_test_instance_get_shared_buffer_offset( instance_ptr, &shared_buffer_offset);
    return_value_if_fail( TLS_TEST_SUCCESS == status, status);

    /* Write data as long as possible. */
    if ( shared_buffer_offset + *length > instance_ptr -> tls_test_shared_buffer_size)
    {

        /* Return actual copy size. */
        *length = instance_ptr -> tls_test_shared_buffer_size - shared_buffer_offset;

        /* Set return code. */
        status = TLS_TEST_ILLEGAL_SHARED_BUFFER_ACCESS;
    }
    else
    {

        /* Set return code. */
        status = TLS_TEST_SUCCESS;
    }

    /* Append all data. */
    memcpy( (CHAR*)instance_ptr -> tls_test_shared_buffer + shared_buffer_offset, data, *length);

    /* Update shared buffer offset. */
    tls_test_instance_set_shared_buffer_offset( instance_ptr, shared_buffer_offset + *length);

    return status;
}

/* Get shared buffer. */
INT tls_test_instance_get_shared_buffer( TLS_TEST_INSTANCE* instance_ptr, VOID** shared_buffer_ptr)
{

    /* Validate pointers. */
    return_value_if_fail( NULL != instance_ptr, TLS_TEST_INVALID_POINTER);

    /* Return shared buffer. */
    *shared_buffer_ptr = instance_ptr -> tls_test_shared_buffer;
    return_value_if_fail( NULL != *shared_buffer_ptr, TLS_TEST_ILLEGAL_SHARED_BUFFER_ACCESS);
    return TLS_TEST_SUCCESS;
}
