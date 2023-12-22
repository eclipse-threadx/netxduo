#include "tls_test_frame.h"

/* Construct a tls test instance. */
INT tls_test_instance_create( TLS_TEST_INSTANCE** instance_ptr_ptr, CHAR* instance_name, InstanceTestEntryFunc test_entry, UINT delay, UINT timeout, UINT shared_buffer_size, VOID* reserved)
{
    /* Check parameters. */
    return_value_if_fail( NULL != instance_ptr_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != instance_name, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != test_entry, TLS_TEST_INVALID_POINTER);

    /* Allocate shared memory of this test instance and its shared buffer. */
    TLS_TEST_INSTANCE* instance_ptr;
    instance_ptr = mmap( NULL, sizeof(TLS_TEST_INSTANCE) + shared_buffer_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
    return_value_if_fail( NULL != instance_ptr, TLS_TEST_UNABLE_TO_CREATE_SHARED_MEMORY);

    /* Return instance ptr. */
    *instance_ptr_ptr = instance_ptr;

    /* Initialize members related to shared buffer. */
    instance_ptr -> tls_test_shared_buffer_size = shared_buffer_size;
    instance_ptr -> tls_test_shared_buffer_offset = 0;
    if ( shared_buffer_size)
    {
        instance_ptr -> tls_test_shared_buffer = (VOID*)( (CHAR*)instance_ptr + sizeof(TLS_TEST_INSTANCE));
    }
    else
    {
        instance_ptr -> tls_test_shared_buffer = NULL;
    }

    /* Initialize other members. */
    instance_ptr -> tls_test_instance_name = instance_name;
    instance_ptr -> tls_test_entry = test_entry;
    instance_ptr -> tls_test_delay = delay;
    if ( !timeout)
    {
        /* Assign timeout as default value, if timeout is 0. */
        instance_ptr -> tls_test_timeout = TLS_TEST_PROCESS_DEFAULT_TIMEOUT;
    }
    else
    {
        instance_ptr -> tls_test_timeout = timeout;
    }

    instance_ptr -> tls_test_instance_identify = 0;
    instance_ptr -> tls_test_instance_status = TLS_TEST_INSTANCE_STATUS_INITIALIZED;
    instance_ptr -> tls_test_next_instance_ptr = NULL;

    return TLS_TEST_SUCCESS;
}
