/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation 
 * 
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 * 
 * SPDX-License-Identifier: MIT
 **************************************************************************/

#include "nx_api.h"

/* Device certificate.  */
#ifndef DEVICE_CERT
#define DEVICE_CERT                                 {0x00}
#endif /* DEVICE_CERT */

/* Device Private Key.  */
#ifndef DEVICE_PRIVATE_KEY
#define DEVICE_PRIVATE_KEY                          {0x00}
#endif /* DEVICE_PRIVATE_KEY */

const UCHAR sample_device_cert_ptr[] = DEVICE_CERT;
const UINT sample_device_cert_len = sizeof(sample_device_cert_ptr);
const UCHAR sample_device_private_key_ptr[] = DEVICE_PRIVATE_KEY;
const UINT sample_device_private_key_len = sizeof(sample_device_private_key_ptr);
