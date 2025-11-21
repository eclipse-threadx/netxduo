#include "tls_test_frame.h"

/* Construct tls test director. */
INT tls_test_director_create(TLS_TEST_DIRECTOR** director_ptr_ptr, VOID* description)
{
TLS_TEST_DIRECTOR* director_ptr;

    /* Check parameters. */
    return_value_if_fail(NULL != director_ptr_ptr, TLS_TEST_INVALID_POINTER);

    /* Atempt to allocate the space of test_director. */
    director_ptr = (TLS_TEST_DIRECTOR*)malloc(sizeof(TLS_TEST_DIRECTOR));
    return_value_if_fail(NULL != director_ptr, TLS_TEST_INSTANTIATION_FAILED);

    /* Return director. */
    *director_ptr_ptr = director_ptr;

    /* Intialize the members of the new director instance. */
    director_ptr -> tls_test_registered_test_instances = 0;
    director_ptr -> tls_test_first_instance_ptr = NULL;
    return TLS_TEST_SUCCESS;
}

/* Stub function to avoid link issue. */
void tx_application_define(void *first_unused_memory)
{
}