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
/**   User Datagram Protocol (UDP)                                        */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_udp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_udp_socket_port_get                             PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function retrieves the bound port of the specified socket,     */
/*    which is especially useful in situations where NX_ANY_PORT was      */
/*    used to bind.                                                       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to UDP socket         */
/*    port_ptr                              Destination for port bound to */
/*                                            this socket                 */
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
/*  05-19-2020     Yuxin Zhou               Initial Version 6.0           */
/*  09-30-2020     Yuxin Zhou               Modified comment(s),          */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
UINT  _nx_udp_socket_port_get(NX_UDP_SOCKET *socket_ptr, UINT *port_ptr)
{
TX_INTERRUPT_SAVE_AREA


    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_UDP_SOCKET_PORT_GET, socket_ptr -> nx_udp_socket_ip_ptr, socket_ptr, socket_ptr -> nx_udp_socket_port, 0, NX_TRACE_UDP_EVENTS, 0, 0);

    /* Lockout interrupts.  */
    TX_DISABLE

    /* Determine if the socket is currently bound.  */
    if (!socket_ptr ->  nx_udp_socket_bound_next)
    {

        /* Restore interrupts.  */
        TX_RESTORE

        /* Socket is not bound, return an error message.  */
        return(NX_NOT_BOUND);
    }

    /* Pickup the bound port for the UDP socket.  */
    *port_ptr =  socket_ptr -> nx_udp_socket_port;

    /* Restore interrupts.  */
    TX_RESTORE

    /* Return a successful status.  */
    return(NX_SUCCESS);
}

