#include "tls_test_frame.h"

/* Create semaphore. */
INT tls_test_semaphore_create( TLS_TEST_SEMAPHORE** semaphore_ptr_ptr, UINT initial_value)
{
    INT status;
    TLS_TEST_SEMAPHORE* semaphore_ptr = *semaphore_ptr_ptr;
    semaphore_ptr = mmap( NULL, sizeof(TLS_TEST_SEMAPHORE), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
    return_value_if_fail( NULL != semaphore_ptr, TLS_TEST_UNABLE_TO_CREATE_SHARED_MEMORY);

    status = sem_init( semaphore_ptr, 1, initial_value);
    if ( -1 == status)
    {
        munmap( semaphore_ptr, sizeof(TLS_TEST_SEMAPHORE));
    }
    return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);

    *semaphore_ptr_ptr = semaphore_ptr;
    return TLS_TEST_SUCCESS;
}
