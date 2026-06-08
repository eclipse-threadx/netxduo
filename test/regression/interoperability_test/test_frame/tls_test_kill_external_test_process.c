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

/* Call external program without output redirecting. */
INT tls_test_kill_external_test_process( TLS_TEST_EXTERNAL_TEST_PROCESS* test_process_ptr)
{
    /* Validate pointers. */
    return_value_if_fail( NULL != test_process_ptr, TLS_TEST_INVALID_POINTER);

    INT status;
    status = kill( test_process_ptr -> tls_test_external_test_process_id, SIGTERM);
    return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);

    return TLS_TEST_SUCCESS;
}
