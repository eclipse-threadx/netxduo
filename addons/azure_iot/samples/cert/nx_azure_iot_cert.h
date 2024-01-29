/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation 
 * 
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 * 
 * SPDX-License-Identifier: MIT
 **************************************************************************/

#ifndef NX_AZURE_IOT_CERT_H
#define NX_AZURE_IOT_CERT_H

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */

#ifdef __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif


/* Users can use this root certificate as sample, and also can build the root certificate by themself.  */
extern const unsigned char _nx_azure_iot_root_cert[];
extern const unsigned int _nx_azure_iot_root_cert_size;
extern const unsigned char _nx_azure_iot_root_cert_2[];
extern const unsigned int _nx_azure_iot_root_cert_size_2;
extern const unsigned char _nx_azure_iot_root_cert_3[];
extern const unsigned int _nx_azure_iot_root_cert_size_3;


/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */

#ifdef __cplusplus
}
#endif

#endif /* NX_AZURE_IOT_CERT_H */
