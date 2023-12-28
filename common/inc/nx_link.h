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


/**************************************************************************/
/*                                                                        */
/*  COMPONENT DEFINITION                                   RELEASE        */
/*                                                                        */
/*    nx_link.h                                           PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file defines the NetX link layer component.                    */
/*                                                                        */
/*    Note: Require driver support to use APIs from this file.            */
/*          A quick check in driver is to search for                      */
/*          NX_LINK_RAW_PACKET_SEND. APIs are not supported if not found. */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou               Initial Version 6.4.0        */
/*                                                                        */
/**************************************************************************/


#ifndef _NX_LINK_H_
#define _NX_LINK_H_

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */
#ifdef __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

#include "nx_api.h"

/* Define link layer constants.  */

/* All packet types for receive filter.  */
#ifndef NX_LINK_PACKET_TYPE_ALL
#define NX_LINK_PACKET_TYPE_ALL      0xFFFF
#endif /* NX_LINK_PACKET_TYPE_ALL */

#ifndef NX_LINK_ETHERNET_HEADER_SIZE
#define NX_LINK_ETHERNET_HEADER_SIZE 14
#endif /* NX_LINK_ETHERNET_HEADER_SIZE */

#ifndef NX_LINK_VLAN_HEADER_SIZE
#define NX_LINK_VLAN_HEADER_SIZE     4
#endif /* NX_LINK_VLAN_HEADER_SIZE */

#define NX_LINK_ETHERNET_TPID        (0x8100)
#define NX_LINK_ETHERNET_IP          (0x0800)
#define NX_LINK_ETHERNET_ARP         (0x0806)
#define NX_LINK_ETHERNET_RARP        (0x8035)
#define NX_LINK_ETHERNET_IPV6        (0x86DD)
#define NX_LINK_ETHERNET_PTP         (0x88F7)

#define NX_LINK_ETHERNET_MVRP        (0x88f5)
#define NX_LINK_ETHERNET_MMRP        (0x88f6)
#define NX_LINK_ETHERNET_MSRP        (0x22ea)
#define NX_LINK_ETHERNET_OPCUA       (0xb62c)

#define NX_LINK_VLAN_ID_MASK         (0x0FFF)
#define NX_LINK_VLAN_PCP_MASK        (0xE000)
#define NX_LINK_VLAN_PCP_SHIFT       (13)

struct NX_LINK_TIME_STRUCT;

/* Define function pointer for incoming packet received notify.  */
typedef UINT nx_link_packet_receive_callback(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                             ULONG physical_address_msw, ULONG physical_address_lsw,
                                             UINT packet_type, UINT header_size, VOID *context,
                                             struct NX_LINK_TIME_STRUCT *time_ptr);

/* Define structures.  */
/* Link layer time structure.  */
typedef struct NX_LINK_TIME_STRUCT
{
    ULONG second_high;
    ULONG second_low;
    ULONG nano_second;
} NX_LINK_TIME;

/* Receive queue structure for processing raw packets.  */
typedef struct NX_LINK_RECEIVE_QUEUE_STRUCT
{
    nx_link_packet_receive_callback     *callback;
    VOID                                *context;
    USHORT                               packet_type;
    USHORT                               reserved;
    struct NX_LINK_RECEIVE_QUEUE_STRUCT *next_ptr;
    struct NX_LINK_RECEIVE_QUEUE_STRUCT *previous_ptr;
} NX_LINK_RECEIVE_QUEUE;

/* Define APIs for application.  */
UINT nx_link_vlan_set(NX_IP *ip_ptr, UINT interface_index, UINT vlan_tag);
UINT nx_link_vlan_get(NX_IP *ip_ptr, UINT interface_index, USHORT *vlan_tag);
UINT nx_link_vlan_clear(NX_IP *ip_ptr, UINT interface_index);
UINT nx_link_multicast_join(NX_IP *ip_ptr, UINT interface_index,
                            ULONG physical_address_msw, ULONG physical_address_lsw);
UINT nx_link_multicast_leave(NX_IP *ip_ptr, UINT interface_index,
                             ULONG physical_address_msw, ULONG physical_address_lsw);
UINT nx_link_ethernet_packet_send(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                  ULONG physical_address_msw, ULONG physical_address_lsw, UINT packet_type);
UINT nx_link_raw_packet_send(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr);
UINT nx_link_packet_receive_callback_add(NX_IP *ip_ptr, UINT interface_index, NX_LINK_RECEIVE_QUEUE *queue_ptr,
                                         UINT packet_type, nx_link_packet_receive_callback *callback_ptr, VOID *context);
UINT nx_link_packet_receive_callback_remove(NX_IP *ip_ptr, UINT interface_index, NX_LINK_RECEIVE_QUEUE *queue_ptr);
UINT nx_link_ethernet_header_parse(NX_PACKET *packet_ptr, ULONG *destination_msb, ULONG *destination_lsb,
                                   ULONG *source_msb, ULONG *source_lsb, USHORT *ether_type, USHORT *vlan_tag,
                                   UCHAR *vlan_tag_valid, UINT *header_size);
UINT nx_link_vlan_interface_create(NX_IP *ip_ptr, CHAR *interface_name, ULONG ip_address, ULONG network_mask,
                                   UINT vlan_tag, UINT parent_interface_index, UINT *interface_index_ptr);


/* APIs for network driver.  */
UINT nx_link_ethernet_header_add(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                 ULONG physical_address_msw, ULONG physical_address_lsw, UINT packet_type);
VOID nx_link_packet_transmitted(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr, NX_LINK_TIME *time_ptr);
VOID nx_link_ethernet_packet_received(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                      NX_LINK_TIME *time_ptr);
UINT nx_link_driver_request_preprocess(NX_IP_DRIVER *driver_request, NX_INTERFACE **actual_interface);

/* Internal functions.  */
void nx_link_vlan_interface_status_change(NX_IP *ip_ptr, UINT interface_index);

#ifdef __cplusplus
}
#endif
#endif /* _NX_LINK_H_ */

