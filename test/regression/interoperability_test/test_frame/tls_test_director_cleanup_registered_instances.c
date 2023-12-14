#include "tls_test_frame.h"

/* Cleanup registered instances. */
INT tls_test_director_cleanup_registered_instances(TLS_TEST_DIRECTOR* director_ptr)
{
TLS_TEST_INSTANCE* iter; 
INT status;

    /* While there is a registered instance. */
    while (NULL != director_ptr -> tls_test_first_instance_ptr)
    {
        /* Store the pointer to the second instance. */
        iter = director_ptr -> tls_test_first_instance_ptr -> tls_test_next_instance_ptr;

        /* Destroy the first instance. */
        status = tls_test_instance_destroy(director_ptr -> tls_test_first_instance_ptr);

        /* Maintain the number of existed instances and the pointer to the firster registered instance. */
        director_ptr -> tls_test_registered_test_instances--;
        director_ptr -> tls_test_first_instance_ptr = iter;
        return_value_if_fail(TLS_TEST_SUCCESS == status, status);
    }
    return TLS_TEST_SUCCESS;
}
