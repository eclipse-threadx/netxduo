#include "tls_test_frame.h"

/* Register tlst test instance to tls test director. */
INT tls_test_director_register_test_instance(TLS_TEST_DIRECTOR* director_ptr, TLS_TEST_INSTANCE* instance_ptr)
{
TLS_TEST_INSTANCE *iter, *iter2;
INT status = TLS_TEST_SUCCESS;
UINT id = 0;

    /* Check parameters. */
    return_value_if_fail(NULL != director_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail(NULL != instance_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail(director_ptr -> tls_test_registered_test_instances < TLS_TEST_MAX_TEST_INSTANCE_NUMBER, TLS_TEST_TOO_MANY_TEST_INSTANCES);

    /* Check test instance status. */
    return_value_if_fail(instance_ptr -> tls_test_instance_status & TLS_TEST_INSTANCE_STATUS_INITIALIZED, TLS_TEST_INSTANCE_UNINITIALIZED);
    return_value_if_fail(!(instance_ptr -> tls_test_instance_status & TLS_TEST_INSTANCE_STATUS_REGISTERED), TLS_TEST_ALREADY_REGISTERED);

    /* No instances has been registered. */
    if (NULL == director_ptr -> tls_test_first_instance_ptr)
    {
        director_ptr -> tls_test_first_instance_ptr = instance_ptr;
        director_ptr -> tls_test_registered_test_instances = 1;
        instance_ptr -> tls_test_instance_identify = 0;
        return TLS_TEST_SUCCESS;
    }

    /* Initialize instance iterator. */
    iter = director_ptr -> tls_test_first_instance_ptr;
    iter2 = NULL;

    /* Loop to find last instance. */
    while(1)
    {
        /* Ensure id to be the max identify. */
        id = id > iter -> tls_test_instance_identify? id : iter -> tls_test_instance_identify;
        tls_test_instance_find_next(iter, &iter2);
        if (NULL == iter2)
        {
            break;
        }
        iter = iter2;
    }

    /* Append the new instance. */
    status = tls_test_instance_append(iter, instance_ptr);
    instance_ptr -> tls_test_instance_identify = id + 1;
    instance_ptr -> tls_test_instance_status |= TLS_TEST_INSTANCE_STATUS_REGISTERED;
    director_ptr -> tls_test_registered_test_instances++;
    return TLS_TEST_SUCCESS;
}
