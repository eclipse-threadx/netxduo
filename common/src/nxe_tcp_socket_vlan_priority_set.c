/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   Transmission Control Protocol (TCP)                                 */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_tcp.h"

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_tcp_socket_vlan_priority_set                   PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in tcp socket vlan priority set     */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to tcp socket         */
/*    vlan_priority                         Vlan priority                 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Actual completion status      */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_socket_vlan_priority_set      Actual tcp socket vlan        */
/*                                            priority set function       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_tcp_socket_vlan_priority_set(NX_TCP_SOCKET *socket_ptr, UINT vlan_priority)
{
#ifdef NX_ENABLE_VLAN
UINT status;

    /* Check for invalid input pointers.  */
    if ((socket_ptr == NX_NULL) || (socket_ptr -> nx_tcp_socket_id != NX_TCP_ID))
    {

        return(NX_PTR_ERROR);
    }

    if (vlan_priority > NX_VLAN_PRIORITY_MAX)
    {

        return(NX_INVALID_PARAMETERS);
    }

    /* Call actual tcp vlan priority set function.  */
    status =  _nx_tcp_socket_vlan_priority_set(socket_ptr, vlan_priority);

    return(status);
#else
    NX_PARAMETER_NOT_USED(socket_ptr);
    NX_PARAMETER_NOT_USED(vlan_priority);

    return(NX_NOT_SUPPORTED);
#endif /* NX_ENABLE_VLAN */
}

