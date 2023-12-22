#include "tls_test_frame.h"

/* Destroy both registered instances and director. */
INT tls_test_director_clean_all(TLS_TEST_DIRECTOR* director_ptr)
{
INT status = 0;

    /* Clear registered test instances. */
    status = tls_test_director_cleanup_registered_instances(director_ptr);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Destroy the test director. */
    status = tls_test_director_destroy(director_ptr);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);
    return TLS_TEST_SUCCESS;
}
