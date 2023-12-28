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
/*    _nxe_packet_vlan_priority_set                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in packet vlan priority set call.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer of packet             */
/*    vlan_priority                         Vlan priority                 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Actual completion status      */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_vlan_priority_set          Actual packet vlan priority   */
/*                                            set function                */
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
UINT _nxe_packet_vlan_priority_set(NX_PACKET *packet_ptr, UINT vlan_priority)
{
#ifdef NX_ENABLE_VLAN
UINT status;

    /* Simple integrity check on the packet.  */
    if ((packet_ptr == NX_NULL) || (packet_ptr -> nx_packet_pool_owner == NX_NULL) ||
        ((packet_ptr -> nx_packet_pool_owner) -> nx_packet_pool_id != NX_PACKET_POOL_ID))
    {
        return(NX_PTR_ERROR);
    }

    if (vlan_priority > NX_VLAN_PRIORITY_MAX)
    {

        return(NX_INVALID_PARAMETERS);
    }

    /* Call actual packet vlan priority set function.  */
    status =  _nx_packet_vlan_priority_set(packet_ptr, vlan_priority);

    return(status);
#else
    NX_PARAMETER_NOT_USED(packet_ptr);
    NX_PARAMETER_NOT_USED(vlan_priority);

    return(NX_NOT_SUPPORTED);
#endif /* NX_ENABLE_VLAN */
}

