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

/* Portions of this file were generated with AI assistance. */


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
#include "nx_ipv6.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxd_ip_raw_packet_send                             PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a raw IP packet to the specified destination.   */
/*    IPv6 selects a source address appropriate for the destination.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to send     */
/*    destination_ip                        Destination IP address        */
/*    protocol                              Value for the protocol field  */
/*    ttl                                   Value for ttl or hop limit    */
/*    tos                                   Value for tos or traffic      */
/*                                            class and flow label        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Actual completion status      */
/*    NX_NOT_ENABLED                        Raw IP processing not enabled */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nxd_ip_raw_packet_source_send        Core raw packet send service  */
/*    _nxd_ipv6_interface_find              Find an IPv6 source address   */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/**************************************************************************/
UINT  _nxd_ip_raw_packet_send(NX_IP *ip_ptr, NX_PACKET *packet_ptr,
                              NXD_ADDRESS *destination_ip, ULONG protocol, UINT ttl, ULONG tos)
{

UINT              status;
#ifdef FEATURE_NX_IPV6
NXD_IPV6_ADDRESS *source_address;
#endif /* FEATURE_NX_IPV6 */

#ifdef FEATURE_NX_IPV6
    if (destination_ip -> nxd_ip_version == NX_IP_VERSION_V6)
    {
        /* Hold the protection mutex from source selection through the send
           so that the selected address cannot be deleted in between.  */
        tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

        status = _nxd_ipv6_interface_find(ip_ptr, destination_ip -> nxd_ip_address.v6,
                                          &source_address, NX_NULL);
        if (status == NX_SUCCESS)
        {
            status = _nxd_ip_raw_packet_source_send(ip_ptr, packet_ptr, destination_ip,
                                                     source_address -> nxd_ipv6_address_index,
                                                     protocol, ttl, tos);
        }

        tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        return(status);
    }
#endif /* FEATURE_NX_IPV6 */

    status = _nxd_ip_raw_packet_source_send(ip_ptr, packet_ptr, destination_ip, 0, protocol, ttl, tos);

    return(status);
}

