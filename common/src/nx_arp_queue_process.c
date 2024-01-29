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
/**   Address Resolution Protocol (ARP)                                   */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_arp.h"

#ifndef NX_DISABLE_IPV4
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_arp_queue_process                               PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes the received ARP messages on the ARP        */
/*    queue placed there by nx_arp_deferred_receive.                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP instance        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_arp_packet_receive                Process received ARP packet   */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ip_thread_entry                   IP helper thread              */
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
VOID  _nx_arp_queue_process(NX_IP *ip_ptr)
{

TX_INTERRUPT_SAVE_AREA

NX_PACKET *packet_ptr;


    /* Loop to process all ARP deferred packet requests.  */
    while (ip_ptr -> nx_ip_arp_deferred_received_packet_head)
    {

        /* Remove the first packet and process it!  */

        /* Disable interrupts.  */
        TX_DISABLE

        /* Pickup the first packet.  */
        packet_ptr =  ip_ptr -> nx_ip_arp_deferred_received_packet_head;

        /* Move the head pointer to the next packet.  */
        ip_ptr -> nx_ip_arp_deferred_received_packet_head =  packet_ptr -> nx_packet_queue_next;

        /* Check for end of ARP deferred processing queue.  */
        if (ip_ptr -> nx_ip_arp_deferred_received_packet_head == NX_NULL)
        {

            /* Yes, the ARP deferred queue is empty.  Set the tail pointer to NULL.  */
            ip_ptr -> nx_ip_arp_deferred_received_packet_tail =  NX_NULL;
        }

        /* Restore interrupts.  */
        TX_RESTORE

        /* Call the actual ARP packet receive function.  */
        _nx_arp_packet_receive(ip_ptr, packet_ptr);
    }
}
#endif /* !NX_DISABLE_IPV4  */

