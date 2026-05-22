/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 * Copyright (c) 2025-present Eclipse ThreadX Contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Secure Component                                                 */
/**                                                                       */
/**    Transport Layer Security (TLS)                                     */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SECURE_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_secure_tls.h"

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_tls_server_certificate_find              PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function finds a local server certificate based upon its       */
/*    unique identifier assigned when the certificate was added with      */
/*    nx_secure_tls_server_certificate_add.                               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    tls_session                           Pointer to TLS Session        */
/*    certificate                           Return certificate pointer    */
/*    cert_id                               Certificate identifier        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_local_certificate_find                              */
/*                                          Find certificate in local     */
/*                                            store                       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
UINT  _nx_secure_tls_server_certificate_find(NX_SECURE_TLS_SESSION *tls_session,
                                             NX_SECURE_X509_CERT **certificate, UINT cert_id)
{
#ifndef NX_SECURE_DISABLE_X509
UINT status;

    /* Find and return the certificate based on its ID. */
    status =  _nx_secure_x509_local_certificate_find(&tls_session -> nx_secure_tls_credentials.nx_secure_tls_certificate_store, certificate, cert_id);

    /* Translate some X.509 return values into TLS return values. */
    if (status == NX_SECURE_X509_CERTIFICATE_NOT_FOUND)
    {
        return(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND);
    }

    /* Return completion status.  */
    return(status);
#else
    NX_PARAMETER_NOT_USED(tls_session);
    NX_PARAMETER_NOT_USED(certificate);
    NX_PARAMETER_NOT_USED(cert_id);

    return(NX_NOT_SUPPORTED);
#endif
}

