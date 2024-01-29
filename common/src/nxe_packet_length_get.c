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
/**   Packet Pool Management (Packet)                                     */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_packet_length_get                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in the packet length get            */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer of packet             */
/*    length                                Destination for the length    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_length_get                 Actual packet length get      */
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
UINT  _nxe_packet_length_get(NX_PACKET *packet_ptr, ULONG *length)
{

UINT status;


    /* Simple integrity check on the packet.  */
    if ((packet_ptr == NX_NULL) || (packet_ptr -> nx_packet_pool_owner == NX_NULL) ||
        ((packet_ptr -> nx_packet_pool_owner) -> nx_packet_pool_id != NX_PACKET_POOL_ID) ||
        (length == NX_NULL))
    {

        /* Return an error!  */
        return(NX_PTR_ERROR);
    }

    /* Call actual packet length get function.  */
    status =  _nx_packet_length_get(packet_ptr, length);

    /* Return completion status.  */
    return(status);
}

