#include "tls_test_frame.h"

INT demo_shared_buffer_test_entry(TLS_TEST_INSTANCE* instance_ptr);

INT main(INT argc, CHAR* argv[])
{
INT status, exit_status;
UINT offset, length;
VOID* shared_buffer;
TLS_TEST_INSTANCE *ins0;
TLS_TEST_DIRECTOR *director;

    /* Create a test instance. */
    status = tls_test_instance_create(&ins0,                          /* test instance ptr */
                                      "shared_buffer_test_instance",  /* instance name */
                                      demo_shared_buffer_test_entry,  /* test entry */
                                      0,                              /* delay(seconds) */
                                      10,                             /* timeout(seconds) */
                                      1024,                           /* shared buffer size */
                                      NULL);                          /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_get_shared_buffer_offset(ins0, &offset);
    return_value_if_fail((TLS_TEST_SUCCESS == status) && (0 == offset), TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Get shared buffer. */
    status = tls_test_instance_get_shared_buffer(ins0, &shared_buffer);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Write some data in the shared buffer. */
    length = 5;
    status = tls_test_instance_append_data_to_shared_buffer(ins0, "hello", &length);
    return_value_if_fail((TLS_TEST_SUCCESS == status) && (5 == length), status);

    /* Get current offset. */
    status = tls_test_instance_get_shared_buffer_offset(ins0, &offset);
    return_value_if_fail((TLS_TEST_SUCCESS == status) && (5 == offset), TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Launch the test instance. */
    status = tls_test_director_create(&director, NULL);
    status += tls_test_director_register_test_instance(director, ins0);
    status += tls_test_director_test_start(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Check exit status. */
    status = tls_test_instance_get_exit_status(ins0, &(exit_status));
    return_value_if_fail((0 == exit_status), status);

    /* Get shared buffer. */
    status = tls_test_instance_get_shared_buffer(ins0, &shared_buffer);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Attempt to get the data written by demo_shared_buffer_test_entry. */
    return_value_if_fail('h' == ((CHAR*)shared_buffer)[1023], TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Get current offset. */
    status = tls_test_instance_get_shared_buffer_offset(ins0, &offset);
    return_value_if_fail((TLS_TEST_SUCCESS == status) && (1024 == offset), TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Destroy the test director and registered test instances. */
    status = tls_test_director_clean_all(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    return 0;
}

INT demo_shared_buffer_test_entry(TLS_TEST_INSTANCE* instance_ptr)
{
INT offset, status;
UINT length;

    /* Get current offset. */
    status = tls_test_instance_get_shared_buffer_offset(instance_ptr, &offset);
    return_value_if_fail((TLS_TEST_SUCCESS == status) && (5 == offset), TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Set offset. */
    status = tls_test_instance_set_shared_buffer_offset(instance_ptr, 10);
    status += tls_test_instance_get_shared_buffer_offset(instance_ptr, &offset);
    return_value_if_fail((TLS_TEST_SUCCESS == status) && (10 == offset), TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Exceed the size of shared buffer. */
    status = tls_test_instance_set_shared_buffer_offset(instance_ptr, 1025);
    return_value_if_fail(TLS_TEST_ILLEGAL_SHARED_BUFFER_ACCESS == status, status);
    status = tls_test_instance_get_shared_buffer_offset(instance_ptr, &offset);
    return_value_if_fail((TLS_TEST_SUCCESS == status) && (10 == offset), status);

    /* Set the offset as the maximum. */
    status = tls_test_instance_set_shared_buffer_offset(instance_ptr, 1024);
    status += tls_test_instance_get_shared_buffer_offset(instance_ptr, &offset);
    return_value_if_fail((TLS_TEST_SUCCESS == status) && (1024 == offset), TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Overflow the shared buffer.. */
    status = tls_test_instance_set_shared_buffer_offset(instance_ptr, 1023);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);
    length = 5;
    status = tls_test_instance_append_data_to_shared_buffer(instance_ptr, "hello", &length);

    /* The length appended actually will be stored in the variable of length. */
    return_value_if_fail((1 == length) && (status == TLS_TEST_ILLEGAL_SHARED_BUFFER_ACCESS), status);

    /* Now the offset is equal to the shared buffer size. */
    status = tls_test_instance_get_shared_buffer_offset(instance_ptr, &offset);
    return_value_if_fail((offset == 1024) && (status == TLS_TEST_SUCCESS), status);
    return 0;
}
