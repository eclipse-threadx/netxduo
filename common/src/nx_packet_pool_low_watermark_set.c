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
/*    _nx_packet_pool_low_watermark_set                   PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the low watermark for the specified packet pool. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    pool_ptr                              Pointer to packet pool        */
/*    low_watermark                         Low watermark of packet pool  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
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
UINT  _nx_packet_pool_low_watermark_set(NX_PACKET_POOL *pool_ptr, ULONG low_watermark)
{
#ifdef NX_ENABLE_LOW_WATERMARK

TX_INTERRUPT_SAVE_AREA

    /* Disable interrupts to get a packet from the pool.  */
    TX_DISABLE

    /* Set low watermark to packet pool. */
    pool_ptr -> nx_packet_pool_low_watermark = low_watermark;

    /* Restore interrupts.  */
    TX_RESTORE

    /* Return completion status.  */
    return(NX_SUCCESS);

#else /* !NX_ENABLE_LOW_WATERMARK */
    NX_PARAMETER_NOT_USED(pool_ptr);
    NX_PARAMETER_NOT_USED(low_watermark);

    return(NX_NOT_SUPPORTED);

#endif /* NX_ENABLE_LOW_WATERMARK */
}

