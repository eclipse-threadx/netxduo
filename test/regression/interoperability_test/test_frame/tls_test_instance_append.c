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

/* Appended next_instance_ptr to instance_ptr. */
INT tls_test_instance_append(TLS_TEST_INSTANCE* instance_ptr, TLS_TEST_INSTANCE* next_instance_ptr)
{
    return_value_if_fail(NULL != instance_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail(NULL != next_instance_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail(instance_ptr != next_instance_ptr, TLS_TEST_INVALID_POINTER);
    
    /* Store original next instance. */
    next_instance_ptr -> tls_test_next_instance_ptr = instance_ptr -> tls_test_next_instance_ptr;

    /* Insert next_instance_ptr. */
    instance_ptr -> tls_test_next_instance_ptr = next_instance_ptr;
    return TLS_TEST_SUCCESS;
}
