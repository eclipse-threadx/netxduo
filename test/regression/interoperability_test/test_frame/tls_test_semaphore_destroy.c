#include "tls_test_frame.h"

/* Release the shared memory of the semaphore. */
INT tls_test_semaphore_destroy(TLS_TEST_SEMAPHORE* semaphore_ptr)
{
    INT status = sem_destroy(semaphore_ptr);
    return_value_if_fail(-1 != status, TLS_TEST_SYSTEM_CALL_FAILED);
    return TLS_TEST_SUCCESS;
}
