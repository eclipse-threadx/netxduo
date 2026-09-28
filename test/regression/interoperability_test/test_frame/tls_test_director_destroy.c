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

/* Destroy test director. */
INT tls_test_director_destroy(TLS_TEST_DIRECTOR* director_ptr)
{
    return_value_if_fail(NULL != director_ptr, TLS_TEST_INVALID_POINTER);
    free(director_ptr);
    return TLS_TEST_SUCCESS;
}
