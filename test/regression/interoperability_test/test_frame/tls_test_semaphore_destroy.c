/***************************************************************************/
/* Copyright (c) 2024 Microsoft Corporation                                */
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

#include "tls_test_frame.h"

/* Release the shared memory of the semaphore. */
INT tls_test_semaphore_destroy(TLS_TEST_SEMAPHORE* semaphore_ptr)
{
    INT status = sem_destroy(semaphore_ptr);
    return_value_if_fail(-1 != status, TLS_TEST_SYSTEM_CALL_FAILED);
    return TLS_TEST_SUCCESS;
}
