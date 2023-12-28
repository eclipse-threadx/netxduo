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
/**   Multiple VLAN Registration Protocol (MVRP)                          */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  COMPONENT DEFINITION                                   RELEASE        */
/*                                                                        */
/*    nx_mvrp.h                                              Generic      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file defines the NetX TSN MVRP component.                      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia               Initial Version 6.4.0          */
/*                                                                        */
/**************************************************************************/

#ifndef NX_MVRP_H
#define NX_MVRP_H

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */
#ifdef __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

#include "nx_api.h"
#include "nx_mrp.h"

/* Define MVRP constants. */
#define NX_MRP_MVRP_PROTOCOL_VERSION     (0)

#define NX_MVRP_MAD_INDICATION_JOIN      (1)
#define NX_MVRP_MAD_INDICATION_LEAVE     (2)

#define NX_MVRP_ATTRIBUTE_ARRAY_MAX_SIZE (10)

#define NX_MVRP_ATTRIBUTE_TYPE_VLAN_ID   (1)
#define NX_MVRP_ATTRIBUTE_LENGTH_VLAN_ID (2)

#define NX_MVRP_ATTRIBUTE_END_MARK_SIZE  (2)

#define NX_MVRP_ACTION_NEW               (NX_MRP_INDICATION_NEW)
#define NX_MVRP_ACTION_TYPE_JOIN         (NX_MRP_INDICATION_JOIN)
#define NX_MVRP_ACTION_TYPE_LEAVE        (NX_MRP_INDICATION_LV)

typedef UINT (*NX_MVRP_EVENT_CALLBACK)(NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR event, VOID *callback_data);

/* MVRP structure.  */
typedef struct NX_MVRP_ATTRIBUTE_STRUCT
{
    NX_MRP_ATTRIBUTE mrp_attribute;
    USHORT           vlan_id;
    UCHAR            reserved[2];
} NX_MVRP_ATTRIBUTE;

typedef struct NX_MVRP_STRUCT
{
    NX_MRP_PARTICIPANT     participant;
    NX_MVRP_EVENT_CALLBACK mvrp_event_callback;
} NX_MVRP;

/* Internal functions.  */
UINT nx_mvrp_indication_process(struct NX_MRP_STRUCT *mrp, struct NX_MRP_PARTICIPANT_STRUCT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type);

UINT nx_mvrp_mrpdu_pack(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_PACKET *packet_ptr);

UINT nx_mvrp_mrpdu_unpack(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_PACKET *packet_ptr);

UINT nx_mvrp_attribute_find(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE **attribute_ptr, USHORT vlan_id);
void nx_mvrp_attribute_insert(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute);
UINT nx_mvrp_attribute_get(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE **attribute_ptr, USHORT vlan_id);
UINT nx_mvrp_action_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, USHORT vlan_id, UCHAR action_type);
UINT nx_mvrp_init(NX_MVRP *mvrp_ptr);

#ifdef __cplusplus
}
#endif

#endif /* NX_MVRP_H */

