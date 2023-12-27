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
/** NetX SRP Component                                                    */
/**                                                                       */
/**   Stream Reservation Protocol (SRP)                                   */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/
#ifndef NX_SRP_H
#define NX_SRP_H

#include "nx_api.h"

#include "nx_mrp.h"
#include "nx_mvrp.h"
#include "nx_msrp.h"
#include "nx_shaper.h"
/* Define the structure of SRP Service */
#define NX_SRP_PARAMETER_NULL   (1)

typedef UINT (*NX_SRP_EVENT_CALLBACK)(NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR event, VOID *callback_data);

#ifndef NX_SRP_TALKER_NUM
#define NX_SRP_TALKER_NUM       (NX_MAX_PHYSICAL_INTERFACES)
#endif

#define NX_SRP_CLASS_A_INTERVAL (125)   /* us */
#define NX_SRP_CLASS_B_INTERVAL (250)   /* us */

#define NX_SRP_SR_CLASS_A       (6)
#define NX_SRP_SR_CLASS_B       (5)

/* Define the structure of SRP talker. */
typedef struct NX_SRP_TALKER_STRUCT
{
    UCHAR                   stream_id[8];
    UCHAR                   in_used;
    UCHAR                   class_id;
    UCHAR                   class_priority;
    USHORT                  class_vid;
    UINT                    interval;
    UINT                    max_interval_frames;
    UINT                    max_frame_size;

    ULONG                   physical_address_msw;
    ULONG                   physical_address_lsw;

    UINT                    vlan_interface_index;

    NX_SHAPER_CBS_PARAMETER cbs_parameters;
} NX_SRP_TALKER;

/* Define the structure of SRP Service. */
typedef struct NX_SRP_STRUCT
{
    NX_MRP  nx_mrp;

    NX_MSRP nx_msrp;

    NX_MVRP nx_mvrp;

    NX_SRP_TALKER talker[NX_SRP_TALKER_NUM];
} NX_SRP;

/* Define APIs. */
UINT nx_srp_init(NX_SRP *srp_ptr, NX_IP *ip_ptr, UINT interface_index, NX_PACKET_POOL *pkt_pool_ptr,
                 VOID *stack_ptr, ULONG stack_size, UINT priority);
UINT nx_srp_talker_start(NX_SRP *srp_ptr, NX_MSRP_DOMAIN *srp_domain, UCHAR *stream_id, UCHAR *dest_addr,
                         UINT max_frame_size, UINT max_interval_frames, NX_MRP_EVENT_CALLBACK event_callback);
UINT nx_srp_talker_stop(NX_SRP *srp_ptr, UCHAR *stream_id, NX_MSRP_DOMAIN *domain);
UINT nx_srp_listener_start(NX_SRP *srp_ptr, NX_MRP_EVENT_CALLBACK event_callback, UCHAR *wait_stream_id);
UINT nx_srp_listener_stop(NX_SRP *srp_ptr, UCHAR *stream_id, NX_MSRP_DOMAIN *domain);

/* Define internal functions */
UINT nx_srp_cbs_config_get(UINT sr_class, INT port_rate, UINT interval, UINT frames_per_interval, UINT max_frame_size, UINT non_sr_frame_size, INT idle_slope_a, UINT max_frame_size_a, NX_SHAPER_CBS_PARAMETER *cbs_param);
UINT nx_srp_talker_cbs_set(NX_SRP *srp_ptr, UINT index);
#endif

