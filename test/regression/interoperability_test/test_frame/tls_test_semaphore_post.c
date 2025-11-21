#include "tls_test_frame.h"

/* Post semaphore. */
INT tls_test_semaphore_post( TLS_TEST_SEMAPHORE* semaphore_ptr)
{
    return sem_post( semaphore_ptr);
}

