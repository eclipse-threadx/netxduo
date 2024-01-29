/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation 
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
/**    X.509 Digital Certificates                                         */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SECURE_SOURCE_CODE

#include "nx_secure_x509.h"

/* Bring in externs for caller checking code.  */

NX_SECURE_CALLER_CHECKING_EXTERNS


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_secure_x509_extension_find                     PORTABLE C      */
/*                                                           6.1.6        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors when attempting to parse through an */
/*    X.509 certificate for a specific extension.                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    certificate                           Certificate to search         */
/*    extension                             Return instruction data       */
/*    extension_id                          Extension to search for       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_extension_find        Actual extensions find call   */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  05-19-2020     Timothy Stapko           Initial Version 6.0           */
/*  09-30-2020     Timothy Stapko           Modified comment(s),          */
/*                                            resulting in version 6.1    */
/*  04-02-2021     Timothy Stapko           Modified comment(s),          */
/*                                            removed dependency on TLS,  */
/*                                            resulting in version 6.1.6  */
/*                                                                        */
/**************************************************************************/
UINT _nxe_secure_x509_extension_find(NX_SECURE_X509_CERT *certificate,
                                     NX_SECURE_X509_EXTENSION *extension, USHORT extension_id)
{
UINT status;

    if (certificate == NX_CRYPTO_NULL || extension == NX_CRYPTO_NULL)
    {
#ifdef NX_CRYPTO_STANDALONE_ENABLE
        return(NX_CRYPTO_PTR_ERROR);
#else
        return(NX_PTR_ERROR);
#endif /* NX_CRYPTO_STANDALONE_ENABLE */
    }

    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    status = _nx_secure_x509_extension_find(certificate, extension, extension_id);

    return(status);
}

