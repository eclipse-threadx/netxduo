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

/* Wait the system call return success regardless of signals that do not cause test process to terminate. */
INT tls_test_semaphore_wait( TLS_TEST_SEMAPHORE* semaphore_ptr)
{
    INT ret;

    /* Wait for the semaphore ignoring signals. */
    while ( -1 == ( ret = sem_wait( semaphore_ptr)) && ( errno == EINTR));

    /* Check for return value of the system call. */
    return_value_if_fail( -1 != ret, TLS_TEST_SYSTEM_CALL_FAILED);
    return TLS_TEST_SUCCESS;
}
