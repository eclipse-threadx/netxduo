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

#include "nx_secure_tls.h"



/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_tls_process_handshake_header             PORTABLE C      */
/*                                                           6.1.11       */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes a TLS Handshake record header, which is     */
/*    at the beginning of each TLS Handshake message, encapsulated within */
/*    the TLS record itself.                                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_buffer                         Pointer to incoming packet    */
/*    message_type                          Return message type value     */
/*    header_size                           Input size of packet buffer   */
/*                                            Return size of header       */
/*    message_length                        Return length of message      */
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
/*    _nx_secure_tls_client_handshake       TLS client state machine      */
/*    _nx_secure_tls_server_handshake       TLS server state machine      */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_tls_process_handshake_header(UCHAR *packet_buffer, USHORT *message_type,
                                             UINT *header_size, UINT *message_length)
{

    /* Check buffer length. */
    if (*header_size < 4)
    {
        return(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH);
    }

    /* The message being passed in to this function should already be stripped of the TLS header
       so the first byte in the packet/record is our handshake message type. */
    *message_type = packet_buffer[0];
    packet_buffer++;

    /* Get the length of the TLS data. */
    *message_length = (UINT)((packet_buffer[0] << 16) + (packet_buffer[1] << 8) + packet_buffer[2]);

    /* We have extracted 4 bytes of the header. */
    *header_size = 4;

    return(NX_SECURE_TLS_SUCCESS);
}

