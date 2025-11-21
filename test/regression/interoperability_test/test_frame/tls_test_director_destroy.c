#include "tls_test_frame.h"

/* Destroy test director. */
INT tls_test_director_destroy(TLS_TEST_DIRECTOR* director_ptr)
{
    return_value_if_fail(NULL != director_ptr, TLS_TEST_INVALID_POINTER);
    free(director_ptr);
    return TLS_TEST_SUCCESS;
}
