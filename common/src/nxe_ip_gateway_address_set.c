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
/** NetX Component                                                        */
/**                                                                       */
/**   Internet Protocol (IP)                                              */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ip.h"


/* Bring in externs for caller checking code.  */

NX_CALLER_CHECKING_EXTERNS

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ip_gateway_address_set                         PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in the IP gateway address set       */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP control block pointer      */
/*    ip_address                            Gateway IP address            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_gateway_address_set            Actual IP gateway address     */
/*                                            set function call           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  05-19-2020     Yuxin Zhou               Initial Version 6.0           */
/*  09-30-2020     Yuxin Zhou               Modified comment(s),          */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
UINT  _nxe_ip_gateway_address_set(NX_IP *ip_ptr, ULONG ip_address)
{

#ifndef NX_DISABLE_IPV4
UINT status;

    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Determine if this is a valid gateway address.  */
    /*lint -e{835} -e{845} suppress operating on zero. */
    if (ip_address == IP_ADDRESS(0, 0, 0, 0))
    {
        return(NX_IP_ADDRESS_ERROR);
    }

    /* Check for appropriate caller.  */
    NX_INIT_AND_THREADS_CALLER_CHECKING

    /* Call actual IP gateway address set function.  */
    status =  _nx_ip_gateway_address_set(ip_ptr, ip_address);

    /* Return completion status.  */
    return(status);
#else /* NX_DISABLE_IPV4  */
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(ip_address);

    return(NX_NOT_SUPPORTED);
#endif /* !NX_DISABLE_IPV4  */
}

