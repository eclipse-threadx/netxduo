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
/** NetX Link Layer                                                       */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/
#define NX_SOURCE_CODE

#include "nx_link.h"
#include "nx_ip.h"
#include "nx_arp.h"
#include "nx_rarp.h"
#include "nx_packet.h"

#ifdef NX_ENABLE_VLAN
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_vlan_set                                    PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets VLAN tag to interface. VLAN tag is comprised the */
/*    PCP and VLAN ID, encoded in host byte order. See example below.     */
/*      VLAN tag: 0x0002                                                  */
/*      PCP: 0x00                                                         */
/*      VLAN ID: 0x02                                                     */
/*    When the priority of a packet is set either to packet directly or   */
/*    through the socket, the PCP from VLAN tag is override.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       IP Interface Index            */
/*    vlan_tag                              VLAN tag to set               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_vlan_set(NX_IP *ip_ptr, UINT interface_index, UINT vlan_tag)
{

    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for valid interface ID */
    if (interface_index >= NX_MAX_PHYSICAL_INTERFACES)
    {
        return(NX_INVALID_INTERFACE);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    ip_ptr -> nx_ip_interface[interface_index].nx_interface_vlan_tag = (USHORT)(vlan_tag & 0xFFFF);
    ip_ptr -> nx_ip_interface[interface_index].nx_interface_vlan_valid = NX_TRUE;
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_vlan_get                                    PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets VLAN tag from interface. VLAN tag is comprised   */
/*    the PCP and VLAN ID, encoded in host byte order. See example below. */
/*      VLAN tag: 0x0002                                                  */
/*      PCP: 0x00                                                         */
/*      VLAN ID: 0x02                                                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       IP Interface Index            */
/*    vlan_tag                              Return VLAN tag               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_vlan_get(NX_IP *ip_ptr, UINT interface_index, USHORT *vlan_tag)
{

    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID) || (vlan_tag == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for valid interface ID */
    if (interface_index >= NX_MAX_PHYSICAL_INTERFACES)
    {
        return(NX_INVALID_INTERFACE);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    if (ip_ptr -> nx_ip_interface[interface_index].nx_interface_vlan_valid)
    {
        *vlan_tag = ip_ptr -> nx_ip_interface[interface_index].nx_interface_vlan_tag;
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        return(NX_SUCCESS);
    }
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_NOT_FOUND);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_vlan_clear                                  PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function clears VLAN tag from interface.                       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       IP Interface Index            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_vlan_clear(NX_IP *ip_ptr, UINT interface_index)
{

    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for valid interface ID */
    if (interface_index >= NX_MAX_PHYSICAL_INTERFACES)
    {
        return(NX_INVALID_INTERFACE);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    ip_ptr -> nx_ip_interface[interface_index].nx_interface_vlan_tag = 0;
    ip_ptr -> nx_ip_interface[interface_index].nx_interface_vlan_valid = NX_FALSE;
    ip_ptr -> nx_ip_interface[interface_index].nx_interface_parent_ptr = NX_NULL;
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_multicast_join                              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the request to join the specified multicast   */
/*    group on a specified network device.                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Index to the interface        */
/*    physical_address_msw                  Physical address MSW          */
/*    physical_address_lsw                  Physical address LSW          */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_multicast_join(NX_IP *ip_ptr, UINT interface_index,
                            ULONG physical_address_msw, ULONG physical_address_lsw)
{
NX_IP_DRIVER driver_request;


    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for interface being valid. */
    if (!ip_ptr -> nx_ip_interface[interface_index].nx_interface_valid)
    {
        return(NX_INVALID_INTERFACE);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Build driver command to join multicast.  */
    driver_request.nx_ip_driver_ptr = ip_ptr;
    driver_request.nx_ip_driver_command = NX_LINK_MULTICAST_JOIN;
    driver_request.nx_ip_driver_physical_address_msw = physical_address_msw;
    driver_request.nx_ip_driver_physical_address_lsw = physical_address_lsw;
    driver_request.nx_ip_driver_interface = &(ip_ptr -> nx_ip_interface[interface_index]);

    /* Send out link packet.  */
    (ip_ptr -> nx_ip_interface[interface_index].nx_interface_link_driver_entry)(&driver_request);
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(driver_request.nx_ip_driver_status);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_multicast_leave                             PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the request to leave the specified multicast  */
/*    group on a specified network device.                                */
/*                                                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Index to the interface        */
/*    physical_address_msw                  Physical address MSW          */
/*    physical_address_lsw                  Physical address LSW          */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_multicast_leave(NX_IP *ip_ptr, UINT interface_index,
                             ULONG physical_address_msw, ULONG physical_address_lsw)
{
NX_IP_DRIVER driver_request;


    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for interface being valid. */
    if (!ip_ptr -> nx_ip_interface[interface_index].nx_interface_valid)
    {
        return(NX_INVALID_INTERFACE);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Build driver command to leave multicast.  */
    driver_request.nx_ip_driver_ptr = ip_ptr;
    driver_request.nx_ip_driver_command = NX_LINK_MULTICAST_LEAVE;
    driver_request.nx_ip_driver_physical_address_msw = physical_address_msw;
    driver_request.nx_ip_driver_physical_address_lsw = physical_address_lsw;
    driver_request.nx_ip_driver_interface = &(ip_ptr -> nx_ip_interface[interface_index]);

    /* Send out link packet.  */
    (ip_ptr -> nx_ip_interface[interface_index].nx_interface_link_driver_entry)(&driver_request);
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(driver_request.nx_ip_driver_status);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_ethernet_packet_send                        PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends out a link packet with layer 3 header already   */
/*    constructed or raw packet. Ethernet header will be added in this    */
/*    function.                                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Index to the interface        */
/*    packet_ptr                            Packet to send                */
/*    physical_address_msw                  Physical address MSW          */
/*    physical_address_lsw                  Physical address LSW          */
/*    packet_type                           Packet type of link layer     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*    nx_link_ethernet_header_add           Add Ethernet header           */
/*    nx_link_raw_packet_send               Send link layer raw packet    */
/*    _nx_packet_transmit_release           Release transmit packet       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_ethernet_packet_send(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                  ULONG physical_address_msw, ULONG physical_address_lsw, UINT packet_type)
{
UINT          status;


    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID) || (packet_ptr == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for interface being valid. */
    if (!ip_ptr -> nx_ip_interface[interface_index].nx_interface_valid)
    {
        return(NX_INVALID_INTERFACE);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Add Ethernet header.  */
    status = nx_link_ethernet_header_add(ip_ptr, interface_index, packet_ptr,
                                         physical_address_msw, physical_address_lsw,
                                         packet_type);
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Check return status.  */
    if (status)
    {

        /* Release the packet.  */
        _nx_packet_transmit_release(packet_ptr);
        return(status);
    }

    /* Send out the packet.  */
    return(nx_link_raw_packet_send(ip_ptr, interface_index, packet_ptr));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_raw_packet_send                             PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends out a link packet with layer 2 header already   */
/*    constructed or raw packet.                                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Index to the interface        */
/*    packet_ptr                            Packet to send                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_raw_packet_send(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr)
{
NX_IP_DRIVER driver_request;


    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID) || (packet_ptr == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for interface being valid. */
    if (!ip_ptr -> nx_ip_interface[interface_index].nx_interface_valid)
    {
        return(NX_INVALID_INTERFACE);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Build driver command to send out raw packet.  */
    driver_request.nx_ip_driver_ptr = ip_ptr;
    driver_request.nx_ip_driver_command = NX_LINK_RAW_PACKET_SEND;
    driver_request.nx_ip_driver_packet = packet_ptr;
    driver_request.nx_ip_driver_interface = &(ip_ptr -> nx_ip_interface[interface_index]);

    /* Send out link packet.  */
    (ip_ptr -> nx_ip_interface[interface_index].nx_interface_link_driver_entry)(&driver_request);
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(driver_request.nx_ip_driver_status);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_packet_receive_callback_add                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function adds a receive callback function to specified         */
/*    interface. Multiple callbacks callback functions can be added       */
/*    to each interface. They will be invoked one by one until the packet */
/*    is consumed. Only packet matching registered packet_type will be    */
/*    passed to callback function. NX_LINK_PACKET_TYPE_ALL can be used    */
/*    to handle all types except TCP/IP ones.                             */
/*                                                                        */
/*    Note, only unknown packet type is passed to callback functions.     */
/*    TCP/IP packet will be received by internal function directly.       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Index to the interface        */
/*    queue_ptr                             Pointer to queue instance     */
/*    packet_type                           Packet type to be handled     */
/*    callback_ptr                          Pointer to callback function  */
/*    context                               Pointer to context            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_packet_receive_callback_add(NX_IP *ip_ptr, UINT interface_index, NX_LINK_RECEIVE_QUEUE *queue_ptr,
                                         UINT packet_type, nx_link_packet_receive_callback *callback_ptr, VOID *context)
{
NX_INTERFACE *interface_ptr;

    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID) ||
        (queue_ptr == NX_NULL) || (callback_ptr == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for interface being valid. */
    if (!ip_ptr -> nx_ip_interface[interface_index].nx_interface_valid)
    {
        return(NX_INVALID_INTERFACE);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);
    interface_ptr = &(ip_ptr -> nx_ip_interface[interface_index]);

    /* Initialize receive queue.  */
    queue_ptr -> packet_type = (USHORT)(packet_type & 0xFFFF);
    queue_ptr -> context = context;
    queue_ptr -> callback = callback_ptr;

    /* Add receive queue to interface.  */
    if (interface_ptr -> nx_interface_link_receive_queue_head)
    {

        /* Add to the tail.  */
        queue_ptr -> previous_ptr = interface_ptr -> nx_interface_link_receive_queue_head -> previous_ptr;
        interface_ptr -> nx_interface_link_receive_queue_head -> previous_ptr -> next_ptr = queue_ptr;
    }
    else
    {

        /* Queue is empty. Add to the head.  */
        queue_ptr -> previous_ptr = queue_ptr;
        interface_ptr -> nx_interface_link_receive_queue_head = queue_ptr;
    }
    queue_ptr -> next_ptr = interface_ptr -> nx_interface_link_receive_queue_head;
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_packet_receive_callback_remove              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function removes a receive callback function to specified      */
/*    interface.                                                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Index to the interface        */
/*    queue_ptr                             Pointer to queue instance     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_packet_receive_callback_remove(NX_IP *ip_ptr, UINT interface_index, NX_LINK_RECEIVE_QUEUE *queue_ptr)
{
NX_INTERFACE *interface_ptr;

    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID) || (queue_ptr == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for interface being valid. */
    if (!ip_ptr -> nx_ip_interface[interface_index].nx_interface_valid)
    {
        return(NX_INVALID_INTERFACE);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);
    interface_ptr = &(ip_ptr -> nx_ip_interface[interface_index]);

    if (queue_ptr -> next_ptr == queue_ptr)
    {

        /* This is the only entry in the queue.  */
        interface_ptr -> nx_interface_link_receive_queue_head = NX_NULL;
    }
    else
    {

        /* Queue is not empty.  */
        queue_ptr -> previous_ptr -> next_ptr = queue_ptr -> next_ptr;
        queue_ptr -> next_ptr -> previous_ptr = queue_ptr -> previous_ptr;

        if (interface_ptr -> nx_interface_link_receive_queue_head == queue_ptr)
        {

            /* Remove from the head.  */
            interface_ptr -> nx_interface_link_receive_queue_head = queue_ptr -> next_ptr;
        }
    }
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_ethernet_header_parse                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses Ethernet packet and return each file of header.*/
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Packet to parse header        */
/*    destination_msb                       Destination address MSW       */
/*    destination_lsb                       Destination address LSW       */
/*    source_msb                            Source address MSW            */
/*    source_lsb                            Source address LSW            */
/*    ether_type                            Ethernet type                 */
/*    vlan_tag                              VLAN tag                      */
/*    vlan_tag_valid                        Contain VLAN tag or not       */
/*    header_size                           Size of Ethernet header       */
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
/*    nx_link_ethernet_packet_received      Process received packet       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_ethernet_header_parse(NX_PACKET *packet_ptr, ULONG *destination_msb, ULONG *destination_lsb,
                                   ULONG *source_msb, ULONG *source_lsb, USHORT *ether_type, USHORT *vlan_tag,
                                   UCHAR *vlan_tag_valid, UINT *header_size)
{
UCHAR *data_ptr = packet_ptr -> nx_packet_prepend_ptr;

    /* Get destination address.  */
    if (destination_msb && destination_lsb)
    {
        *destination_msb = (ULONG)((data_ptr[0] << 8) | data_ptr[1]);
        *destination_lsb = (ULONG)((data_ptr[2] << 24) | (data_ptr[3] << 16) | (data_ptr[4] << 8) | data_ptr[5]);
    }

    /* Get source address.  */
    if (source_msb && source_lsb)
    {
        *source_msb = (ULONG)((data_ptr[6] << 8) | data_ptr[7]);
        *source_lsb = (ULONG)((data_ptr[8] << 24) | (data_ptr[9] << 16) | (data_ptr[10] << 8) | data_ptr[11]);
    }

    /* Check VLAN tag.  */
    if (((data_ptr[12] << 8) | data_ptr[13]) == NX_LINK_ETHERNET_TPID)
    {

        /* VLAN tag is present.  */
        if (vlan_tag)
        {

            /* Get VLAN tag.  */
            *vlan_tag = (USHORT)((data_ptr[14] << 8) | data_ptr[15]);
        }

        if (vlan_tag_valid)
        {
            *vlan_tag_valid = NX_TRUE;
        }

        /* Get ethernet type.  */
        if (ether_type)
        {
            *ether_type = (USHORT)((data_ptr[16] << 8) | data_ptr[17]);
        }

        if (header_size)
        {
            *header_size = NX_LINK_ETHERNET_HEADER_SIZE + NX_LINK_VLAN_HEADER_SIZE;
        }
    }
    else
    {
        if (vlan_tag)
        {

            /* Reset VLAN tag.  */
            *vlan_tag = 0;
        }

        if (vlan_tag_valid)
        {
            *vlan_tag_valid = NX_FALSE;
        }

        /* Get ethernet type.  */
        if (ether_type)
        {
            *ether_type = (USHORT)((data_ptr[12] << 8) | data_ptr[13]);
        }

        if (header_size)
        {
            *header_size = NX_LINK_ETHERNET_HEADER_SIZE;
        }
    }
    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_ethernet_header_add                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function adds Ethernet header to packet. If VLAN tag is valid  */
/*    in current interface, it will be added to Ethernet header.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Index to the interface        */
/*    packet_ptr                            Packet to send                */
/*    physical_address_msw                  Physical address MSW          */
/*    physical_address_lsw                  Physical address LSW          */
/*    packet_type                           Packet type of link layer     */
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
/*    nx_link_ethernet_packet_send          Send Ethernet packet          */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_ethernet_header_add(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                 ULONG physical_address_msw, ULONG physical_address_lsw, UINT packet_type)
{
ULONG         header_length;
ULONG        *ethernet_frame_ptr;
NX_INTERFACE *interface_ptr;
USHORT        vlan_tag;

    interface_ptr = &(ip_ptr -> nx_ip_interface[interface_index]);

    /* Calculate the header length.  */
    if (interface_ptr -> nx_interface_vlan_valid)
    {
        header_length = NX_LINK_ETHERNET_HEADER_SIZE + NX_LINK_VLAN_HEADER_SIZE;
    }
    else
    {
        header_length = NX_LINK_ETHERNET_HEADER_SIZE;
    }

    /* Check available space in packet.  */
    if ((ULONG)(packet_ptr -> nx_packet_prepend_ptr - packet_ptr -> nx_packet_data_start) < header_length)
    {

        /* Not enough space in packet.  */
        return(NX_PACKET_OFFSET_ERROR);
    }

    /* Adjust packet pointer and length.  */
    packet_ptr -> nx_packet_prepend_ptr -= header_length;
    packet_ptr -> nx_packet_length += header_length;

    /* Setup the ethernet frame pointer to build the ethernet frame.  Backup another 2
        bytes to get 32-bit word alignment.  */
    ethernet_frame_ptr =  (ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 2);

    /* Build the ethernet frame.  */
    *ethernet_frame_ptr       = physical_address_msw;
    NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));
    *(++ethernet_frame_ptr) = physical_address_lsw;
    NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));
    *(++ethernet_frame_ptr) = (interface_ptr -> nx_interface_physical_address_msw << 16) |
        (interface_ptr -> nx_interface_physical_address_lsw >> 16);
    NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));
    *(++ethernet_frame_ptr) = (interface_ptr -> nx_interface_physical_address_lsw << 16);
    if (interface_ptr -> nx_interface_vlan_valid)
    {
        /* Build VLAN tag.  */
        *(ethernet_frame_ptr) |= NX_LINK_ETHERNET_TPID;
        NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));

        if (packet_ptr -> nx_packet_vlan_priority != NX_VLAN_PRIORITY_INVALID)
        {
            vlan_tag = (USHORT)((interface_ptr -> nx_interface_vlan_tag & (~NX_LINK_VLAN_PCP_MASK)) |
                                ((packet_ptr -> nx_packet_vlan_priority << NX_LINK_VLAN_PCP_SHIFT) & NX_LINK_VLAN_PCP_MASK));
        }
        else
        {
            vlan_tag = interface_ptr -> nx_interface_vlan_tag;
        }

        *(++ethernet_frame_ptr) = (ULONG)(vlan_tag << 16);
    }
    *(ethernet_frame_ptr) |= (USHORT)(packet_type & 0xFFFF);
    NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_packet_transmitted                          PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles event when a packet is transmitted from       */
/*    network driver. Packet will be released.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Index to the interface        */
/*    packet_ptr                            Pointer to packet             */
/*    time_ptr                              Timestamp of packet           */
/*                                            transmitted (not used)      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*    _nx_packet_transmit_release           Release transmit packet       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Network driver                                                      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
VOID nx_link_packet_transmitted(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr, NX_LINK_TIME *time_ptr)
{
ULONG header_length;

    NX_PARAMETER_NOT_USED(time_ptr);

    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID) || (packet_ptr == NX_NULL))
    {
        return;
    }

    /* Check for interface being valid. */
    if (!ip_ptr -> nx_ip_interface[interface_index].nx_interface_valid)
    {
        return;
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Calculate the header length.  */
    if (ip_ptr -> nx_ip_interface[interface_index].nx_interface_vlan_valid)
    {
        header_length = NX_LINK_ETHERNET_HEADER_SIZE + NX_LINK_VLAN_HEADER_SIZE;
    }
    else
    {
        header_length = NX_LINK_ETHERNET_HEADER_SIZE;
    }
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Remove the Ethernet header.  */
    packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + header_length;

    /* Adjust the packet length.  */
    packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - header_length;

    /* Release the packet.  */
    _nx_packet_transmit_release(packet_ptr);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_ethernet_packet_received                    PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles event when an Ethernet packet is received     */
/*    from network driver. The packet will be dispatch to VLAN interface  */
/*    when VLAN tag is found. For registered raw packet type, the packet  */
/*    will be passed to callback functions for further processing.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Index to the interface        */
/*    packet_ptr                            Pointer to packet             */
/*    time_ptr                              Timestamp of packet received  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_release                    Release packet                */
/*    nx_link_ethernet_header_parse         Parse Ethernet header         */
/*    _nx_ip_packet_deferred_receive        IP packet receive             */
/*    _nx_arp_packet_deferred_receive       ARP packet receive            */
/*    _nx_rarp_packet_deferred_receive      RARP packet receive           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Network driver                                                      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
VOID nx_link_ethernet_packet_received(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                      NX_LINK_TIME *time_ptr)
{
USHORT                 packet_type;
UINT                   header_size;
USHORT                 vlan_tag;
UCHAR                  vlan_tag_valid;
ULONG                  physical_address_msw;
ULONG                  physical_address_lsw;
UINT                   i;
NX_INTERFACE          *interface_ptr;
NX_LINK_RECEIVE_QUEUE *queue_ptr;

    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID) || (packet_ptr == NX_NULL))
    {
        _nx_packet_release(packet_ptr);
        return;
    }

    /* Check for interface being valid. */
    if (!ip_ptr -> nx_ip_interface[interface_index].nx_interface_valid)
    {
        _nx_packet_release(packet_ptr);
        return;
    }

    interface_ptr = &(ip_ptr -> nx_ip_interface[interface_index]);
    queue_ptr = interface_ptr -> nx_interface_link_receive_queue_head;

    /* Get packet type and header size.  */
    nx_link_ethernet_header_parse(packet_ptr, &physical_address_msw, &physical_address_lsw,
                                  NULL, NULL, &packet_type, &vlan_tag, &vlan_tag_valid, &header_size);

    /* Match VLAN ID.  */
    if (vlan_tag_valid == NX_FALSE)
    {

        /* No VLAN tag for incoming packet.  */
        if (interface_ptr -> nx_interface_vlan_valid)
        {

            /* Current interface is tagged.  */
            /* Try to redirect packet to parent interface.  */
            if ((interface_ptr -> nx_interface_parent_ptr) &&
                (interface_ptr -> nx_interface_parent_ptr -> nx_interface_vlan_valid == NX_FALSE))
            {

                /* This packet is actually for parent interface.  */
                interface_ptr = interface_ptr -> nx_interface_parent_ptr;
                interface_index = interface_ptr -> nx_interface_index;
            }
            else
            {

                /* Drop the packet.  */
                _nx_packet_release(packet_ptr);

                return;
            }
        }
    }
    else
    {

        /* VLAN tag is found in incoming packet.  */
        /* Match VLAN ID on current interface first.  */
        if (interface_ptr -> nx_interface_vlan_valid)
        {
            if ((vlan_tag & NX_LINK_VLAN_ID_MASK) != (interface_ptr -> nx_interface_vlan_tag & NX_LINK_VLAN_ID_MASK))
            {

                /* Drop the packet.  */
                _nx_packet_release(packet_ptr);

                return;
            }
        }
        else
        {

            /* This packet may be received from child VLAN interface.  */
            for (i = 0; i < NX_MAX_PHYSICAL_INTERFACES; i++)
            {
                if (ip_ptr -> nx_ip_interface[i].nx_interface_parent_ptr != interface_ptr)
                {

                    /* This is not one of current child interface.  */
                    continue;
                }

                if ((vlan_tag & NX_LINK_VLAN_ID_MASK) ==
                    (ip_ptr -> nx_ip_interface[i].nx_interface_vlan_tag & NX_LINK_VLAN_ID_MASK))
                {

                    /* This packet is actually for current child interface.  */
                    interface_ptr = &(ip_ptr -> nx_ip_interface[i]);
                    interface_index = i;
                    break;
                }
            }

            if (i == NX_MAX_PHYSICAL_INTERFACES)
            {

                /* Drop the packet.  */
                _nx_packet_release(packet_ptr);

                return;
            }
        }
    }

    /* Setup interface pointer.  */
    packet_ptr -> nx_packet_address.nx_packet_interface_ptr = interface_ptr;

    /* Route the incoming packet according to its ethernet type.  */
    /* The RAM driver accepts both IPv4 and IPv6 frames. */
    if ((packet_type == NX_LINK_ETHERNET_IP) || (packet_type == NX_LINK_ETHERNET_IPV6))
    {

        /* Store the PTP timestamp at the start of the packet (replacing Ethernet header)
           in case of PTP over UDP. */
        if (time_ptr)
        {
            ((ULONG *)packet_ptr -> nx_packet_data_start)[0] = time_ptr -> nano_second;
            ((ULONG *)packet_ptr -> nx_packet_data_start)[1] = time_ptr -> second_low;
            ((ULONG *)packet_ptr -> nx_packet_data_start)[2] = time_ptr -> second_high;
        }

        /* Note:  The length reported by some Ethernet hardware includes bytes after the packet
           as well as the Ethernet header.  In some cases, the actual packet length after the
           Ethernet header should be derived from the length in the IP header (lower 16 bits of
           the first 32-bit word).  */

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + header_size;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - header_size;

        /* Route to the ip receive function.  */
        _nx_ip_packet_deferred_receive(ip_ptr, packet_ptr);
    }
#ifndef NX_DISABLE_IPV4
    else if (packet_type == NX_LINK_ETHERNET_ARP)
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + header_size;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - header_size;

        /* Route to the ARP receive function.  */
        _nx_arp_packet_deferred_receive(ip_ptr, packet_ptr);
    }
    else if (packet_type == NX_LINK_ETHERNET_RARP)
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + header_size;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - header_size;

        /* Route to the RARP receive function.  */
        _nx_rarp_packet_deferred_receive(ip_ptr, packet_ptr);
    }
#endif /* !NX_DISABLE_IPV4  */
    else
    {

        /* Store the PTP timestamp at the start of the packet (replacing Ethernet header)
           in case of PTP over ETH. */
        if ((packet_type == NX_LINK_ETHERNET_PTP) && (time_ptr != NX_NULL))
        {
            ((ULONG *)packet_ptr -> nx_packet_data_start)[0] = time_ptr -> nano_second;
            ((ULONG *)packet_ptr -> nx_packet_data_start)[1] = time_ptr -> second_low;
            ((ULONG *)packet_ptr -> nx_packet_data_start)[2] = time_ptr -> second_high;
        }

        queue_ptr = interface_ptr -> nx_interface_link_receive_queue_head;
        while (queue_ptr)
        {

            /* Match packet type.  */
            if ((queue_ptr -> packet_type == packet_type) || (queue_ptr -> packet_type == NX_LINK_PACKET_TYPE_ALL))
            {

                /* Call the packet receive handler.  */
                if (queue_ptr -> callback(ip_ptr, interface_index, packet_ptr,
                                          physical_address_msw, physical_address_lsw,
                                          packet_type, header_size, queue_ptr -> context, time_ptr) == NX_SUCCESS)
                {

                    /* Packet was consumed.  */
                    return;
                }
            }

            /* Move to the next queue.  */
            queue_ptr = queue_ptr -> next_ptr;
            if (queue_ptr == interface_ptr -> nx_interface_link_receive_queue_head)
            {

                /* We have reached the end of the queue.  */
                break;
            }
        }

        /* Invalid ethernet header... release the packet.  */
        _nx_packet_release(packet_ptr);
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_vlan_interface_create                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates a VLAN interface and bind to parent           */
/*    interface. Any packet received from parent interface will be        */
/*    dispatched to right interface according to the match of VLAN ID.    */
/*    VLAN tag is comprised the PCP and VLAN ID, encoded in host byte     */
/*    order. See example below.                                           */
/*      VLAN tag: 0x0002                                                  */
/*      PCP: 0x00                                                         */
/*      VLAN ID: 0x02                                                     */
/*    When the priority of a packet is set either to packet directly or   */
/*    through the socket, the PCP from VLAN tag is override.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    interface_name                        Interface name                */
/*    ip_address                            IPv4 address                  */
/*    network_mask                          IPv4 network mask             */
/*    vlan_tag                              VLAN tag to set               */
/*    parent_interface_index                Index of parent interface     */
/*    interface_index_ptr                   Index of created interface    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_vlan_interface_create(NX_IP *ip_ptr, CHAR *interface_name, ULONG ip_address, ULONG network_mask,
                                   UINT vlan_tag, UINT parent_interface_index, UINT *interface_index_ptr)
{
UINT          i;
NX_INTERFACE *interface_ptr = NX_NULL;

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);
#ifdef NX_DISABLE_IPV4
    NX_PARAMETER_NOT_USED(ip_address);
    NX_PARAMETER_NOT_USED(network_mask);
#else
    /* Perform duplicate address detection.  */
    for (i = 0; i < NX_MAX_PHYSICAL_INTERFACES; i++)
    {
        if ((ip_ptr -> nx_ip_interface[i].nx_interface_ip_address == ip_address) &&
            (ip_address != 0))
        {

            /* The IPv4 address already exists.  */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));
            return(NX_DUPLICATED_ENTRY);
        }

        if ((ip_ptr -> nx_ip_interface[i].nx_interface_vlan_tag & NX_LINK_VLAN_ID_MASK) ==
            (vlan_tag & NX_LINK_VLAN_ID_MASK))
        {

            /* The VLAN already exists, only one PCP for one VLAN ID is supported */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));
            return(NX_DUPLICATED_ENTRY);
        }
    }
#endif /* !NX_DISABLE_IPV4  */

    for (i = 0; i < NX_MAX_PHYSICAL_INTERFACES; i++)
    {

        interface_ptr = &(ip_ptr -> nx_ip_interface[i]);

        if (!(interface_ptr -> nx_interface_valid))
        {

            /* Find a valid entry. */
            break;
        }
    }

    if (i == NX_MAX_PHYSICAL_INTERFACES)
    {

        /* No more free entry.  return. */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        return(NX_NO_MORE_ENTRIES);
    }

    if (parent_interface_index >= NX_MAX_PHYSICAL_INTERFACES)
    {
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        return(NX_INVALID_PARAMETERS);
    }

    /* Inherit the driver properties from parent interface */
    memcpy(interface_ptr, &(ip_ptr -> nx_ip_interface[parent_interface_index]), /* Use case of memcpy is verified. */
           sizeof(NX_INTERFACE));

    interface_ptr -> nx_interface_parent_ptr = &(ip_ptr -> nx_ip_interface[parent_interface_index]);

    *interface_index_ptr = i;

    interface_ptr -> nx_interface_index = (UCHAR)i;

    /* Mark the entry as valid. */
    interface_ptr -> nx_interface_valid = NX_TRUE;

    /* Fill in the interface information. */
#ifndef NX_DISABLE_IPV4
    interface_ptr -> nx_interface_ip_address        = ip_address;
    interface_ptr -> nx_interface_ip_network_mask   = network_mask;
    interface_ptr -> nx_interface_ip_network        = ip_address & network_mask;
#endif /* !NX_DISABLE_IPV4  */
    interface_ptr -> nx_interface_name              = interface_name;
    interface_ptr -> nx_interface_vlan_tag          = (USHORT)(vlan_tag & 0xFFFF);
    interface_ptr -> nx_interface_vlan_valid        = NX_TRUE;
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_driver_request_preprocess                   PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles generic driver request. When the packet is    */
/*    sent through VLAN interface, parent interface will be returned.     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    driver_request                        Pointer to driver request     */
/*    actual_interface                      Pointer to actual interface   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_transmit_release           Release transmit packet       */
/*    [nx_interface_link_header_add]        Add link layer header         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    TCP/IP layer                                                        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_link_driver_request_preprocess(NX_IP_DRIVER *driver_request, NX_INTERFACE **actual_interface)
{

    /* Set actual interface to the one from driver request by default.  */
    *actual_interface = driver_request -> nx_ip_driver_interface;

    if (driver_request -> nx_ip_driver_interface == NX_NULL)
    {

        /* Unsupported driver request.  Let caller handle it.  */
        return(NX_SUCCESS);
    }

    if (driver_request -> nx_ip_driver_interface -> nx_interface_parent_ptr == NX_NULL)
    {

        /* This is a driver request from parent interface. Nothing to do in this function.  */
        return(NX_SUCCESS);
    }

    /* This driver request is for VLAN interface.  */
    *actual_interface = driver_request -> nx_ip_driver_interface -> nx_interface_parent_ptr;

    switch (driver_request -> nx_ip_driver_command)
    {
    case NX_LINK_ARP_SEND: /* fallthrough */
    case NX_LINK_ARP_RESPONSE_SEND: /* fallthrough */
    case NX_LINK_PACKET_BROADCAST: /* fallthrough */
    case NX_LINK_RARP_SEND: /* fallthrough */
    case NX_LINK_PACKET_SEND: /* fallthrough */
#ifdef NX_ENABLE_PPPOE
    case NX_LINK_PPPOE_DISCOVERY_SEND: /* fallthrough */
    case NX_LINK_PPPOE_SESSION_SEND: /* fallthrough */
#endif
    case NX_LINK_RAW_PACKET_SEND: /* fallthrough */
    case NX_LINK_GET_STATUS: /* fallthrough */
    case NX_LINK_GET_SPEED: /* fallthrough */
    case NX_LINK_GET_DUPLEX_TYPE: /* fallthrough */
    case NX_LINK_GET_ERROR_COUNT: /* fallthrough */
    case NX_LINK_GET_RX_COUNT: /* fallthrough */
    case NX_LINK_GET_TX_COUNT: /* fallthrough */
    case NX_LINK_GET_ALLOC_ERRORS: /* fallthrough */
    case NX_INTERFACE_CAPABILITY_GET: /* fallthrough */
    case NX_LINK_FACTORY_ADDRESS_GET: /* fallthrough */
    case NX_LINK_GET_INTERFACE_TYPE: /* fallthrough */
    case NX_LINK_USER_COMMAND:
        break;

    case NX_LINK_INTERFACE_ATTACH: /* fallthrough */
    case NX_LINK_INTERFACE_DETACH: /* fallthrough */
    case NX_LINK_INITIALIZE: /* fallthrough */
    /* As parent interface is set, the link interface is already initialized */
    case NX_LINK_UNINITIALIZE: /* fallthrough */
    case NX_LINK_MULTICAST_JOIN: /* fallthrough */
    case NX_LINK_MULTICAST_LEAVE:
        driver_request -> nx_ip_driver_status = NX_SUCCESS;
        return(NX_CONTINUE);

    case NX_LINK_ENABLE: /* fallthrough */
    case NX_LINK_DISABLE: /* fallthrough */
    /* The link status of virtual interface should be same with its parent physical interface */
    case NX_LINK_SET_PHYSICAL_ADDRESS: /* fallthrough */
    /* Set mac address is not supported for virtual interface */
    case NX_LINK_RX_ENABLE: /* fallthrough */
    case NX_LINK_RX_DISABLE: /* fallthrough */
    /* Directly control RX in driver is not supported for virtual interface */
    case NX_LINK_DEFERRED_PROCESSING: /* fallthrough */
    case NX_INTERFACE_CAPABILITY_SET: /* fallthrough */
    case NX_LINK_6LOWPAN_COMMAND: /* fallthrough */
    default:

        /* For virtual interface, no need to send the commands to driver layer */
        driver_request -> nx_ip_driver_status = NX_UNHANDLED_COMMAND;
        return(NX_CONTINUE);
    }

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_link_vlan_interface_status_change                PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function dispatched link status change event from parent       */
/*    interface to VLAN interfaces.                                       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    interface_index                       Index to the interface        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Obtain protection mutex       */
/*    tx_mutex_put                          Release protection mutex      */
/*    [nx_ip_link_status_change_callback]   User provided callback        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ip_deferred_link_status_process   Process link status event     */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
void nx_link_vlan_interface_status_change(NX_IP *ip_ptr, UINT interface_index)
{
UINT          i;
NX_INTERFACE *nx_interface = NX_NULL;

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);
    for (i = 0; i < NX_MAX_PHYSICAL_INTERFACES; i++)
    {
        nx_interface = &(ip_ptr -> nx_ip_interface[i]);

        if ((nx_interface -> nx_interface_valid) &&
            (nx_interface -> nx_interface_parent_ptr != NX_NULL) &&
            (nx_interface -> nx_interface_parent_ptr -> nx_interface_index == interface_index))
        {
            nx_interface -> nx_interface_link_up =  nx_interface -> nx_interface_parent_ptr -> nx_interface_link_up;

            /* Reset the flag. */
            nx_interface -> nx_interface_link_status_change = NX_FALSE;

            /* Invoke the callback function. */
            /*lint -e{644} suppress variable might not be initialized, since "link_up" was initialized in nx_interface_link_driver_entry. */
            ip_ptr -> nx_ip_link_status_change_callback(ip_ptr, i, nx_interface -> nx_interface_link_up);
        }
    }
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));
}
#endif /* NX_ENABLE_VLAN */
