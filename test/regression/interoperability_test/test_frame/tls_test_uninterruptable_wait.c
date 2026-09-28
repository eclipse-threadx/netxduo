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

/* Wait for child processed ignoring signals. */
INT tls_test_uninterruptable_wait( pid_t* pid_ptr, INT* exit_status_ptr)
{
    /* Check for pointers. */
    return_value_if_fail( NULL != pid_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( NULL != exit_status_ptr, TLS_TEST_INVALID_POINTER);

    /* Wait for child process terminations and restart wait if interrupted by signals. */
    while ( ( *pid_ptr = wait( exit_status_ptr)) == -1 && (errno == EINTR));

    /* Check for return value. */
    if ( -1 == *pid_ptr)
        return TLS_TEST_SYSTEM_CALL_FAILED;

    return TLS_TEST_SUCCESS;
}
