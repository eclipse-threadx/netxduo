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



#ifndef SRC_NX_SECURE_USER_H
#define SRC_NX_SECURE_USER_H

UINT nx_crypto_hash_clone_test_clone(VOID *dest_metadata, VOID *source_metadata, ULONG length);
#define NX_SECURE_HASH_METADATA_CLONE nx_crypto_hash_clone_test_clone

UINT nx_crypto_clone_cleanup(VOID *metadata, ULONG length);
#define NX_SECURE_HASH_CLONE_CLEANUP nx_crypto_clone_cleanup



#endif /* SRC_NX_SECURE_USER_H */