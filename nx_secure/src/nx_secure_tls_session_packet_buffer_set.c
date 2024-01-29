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
/*    _nx_secure_tls_session_packet_buffer_set            PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the buffer TLS uses to reassemble incoming       */
/*    messages which may span multiple TCP packets.                       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session_ptr                           TLS control block             */
/*    buffer_ptr                            Pointer to buffer             */
/*    buffer_size                           Buffer area size              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  05-19-2020     Timothy Stapko           Initial Version 6.0           */
/*  09-30-2020     Timothy Stapko           Modified comment(s),          */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
UINT  _nx_secure_tls_session_packet_buffer_set(NX_SECURE_TLS_SESSION *session_ptr,
                                               UCHAR *buffer_ptr, ULONG buffer_size)
{

    /* For machines that don't auto-align, check and adjust for four byte alignment. */
    if (((ULONG)buffer_ptr) & 0x3)
    {
        buffer_ptr = (UCHAR *)(((((ULONG)buffer_ptr) & 0xFFFFFFFC) + 4) & 0xFFFFFFFF);
        buffer_size -= (((ULONG)buffer_ptr) & 0x3);
    }

    /* Check size of buffer for alignment after above adjustment. */
    if (buffer_size & 0x3)
    {
        buffer_size = buffer_size & 0xFFFFFFFC;
    }


    /* Set the buffer and its size. */
    session_ptr -> nx_secure_tls_packet_buffer = buffer_ptr;
    session_ptr -> nx_secure_tls_packet_buffer_size = buffer_size;
    
    /* Save off the original size of the buffer. */
    session_ptr -> nx_secure_tls_packet_buffer_original_size = buffer_size;

    return(NX_SUCCESS);
}

