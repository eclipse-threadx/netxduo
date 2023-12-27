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
/** NetX MSRP Component                                                   */
/**                                                                       */
/**   Multiple Stream Registration Protocol (MSRP)                        */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#ifndef NX_MSRP_H
#define NX_MSRP_H

#include "nx_api.h"
#include "nx_mrp.h"

#define NX_MRP_MSRP_PROTOCOL_VERSION      0

/* MSRP protocal verison index in packet*/
#define NX_MSRP_PROTOCAL_VERSION_INDEX    16

/* MSRP return value*/
#define NX_MSRP_SUCCESS                   0
#define NX_MSRP_EVENT_TYPE_ERROR          1
#define NX_MSRP_ATTRIBUTE_TYPE_ERROR      2
#define NX_MSRP_INDICATION_TYPE_ERROR     3
#define NX_MSRP_NOT_SUPPORTED             4
#define NX_MSRP_VERSION_NOT_SUPPORTED     5
#define NX_MSRP_EVENT_NOT_SUPPORTED       6
#define NX_MSRP_LISENER_NOT_READY         7
#define NX_MSRP_LISTENER_NOT_ENABLED      8
#define NX_MSRP_ATTRIBUTE_FIND_ERROR      9
#define NX_MSRP_ATTRIBUTE_FOUND           10
#define NX_MSRP_ATTRIBUTE_NEW             11
#define NX_MSRP_WAIT                      12
#define NX_MSRP_REGISTRAR_STATE_ERROR     13
#define NX_MSRP_PARAMETER_ERROR           14

#define NX_MSRP_ATTRIBUTE_END_MASK        0

#define NX_MSRP_ACTION_NEW           1

#define NX_MSRP_TALKER_ADVERTISE_ATTRIBUTE_LENGTH 25
#define NX_MSRP_TALKER_FAILED_ATTRIBUTE_LENGTH    34
#define NX_MSRP_LISTENER_ATTRIBUTE_LENGTH         8
#define NX_MSRP_DOMAIN_ATTRIBUTE_LENGTH           4

/* MSRP stream ID size.*/
#define STREAM_ID_SIZE                    8

/* MSRP attribute type*/
typedef enum
{
    NX_MSRP_TALKER_ADVERTISE_VECTOR = 1,
    NX_MSRP_TALKER_FAILED_VECTOR    = 2,
    NX_MSRP_TALKER_LISTENER_VECTOR  = 3,
    NX_MSRP_TALKER_DOMAIN_VECTOR    = 4,
} AttributeType_t;

/* Fourpacked_event value.*/
typedef enum
{
    NX_MSRP_FOURPACKED_IGNORE           = 0,
    NX_MSRP_FOURPACKED_ASKING_FAILED    = 1,
    NX_MSRP_FOURPACKED_READY            = 2,
    NX_MSRP_FOURPACKED_READY_FAILED     = 3,
} FourPackedEvent_t;

/* Talker advertise data structure*/
typedef struct
{

    UCHAR  stream_id[8];
    UCHAR  dest_addr[6];
    /* Same with mvrp vlan id*/
    USHORT vlan_identifier;
    USHORT max_frame_size;
    USHORT max_interval_frames;
    UCHAR  priority : 3;
    UCHAR  rank     : 1;
    UCHAR  reserved : 4;
    UINT   accumulated_latency;
} NX_MSRP_TALKER_ADVERTISE;

/* Talker failed data structure*/
typedef struct
{

    UCHAR  stream_id[8];
    UCHAR  des_addr[6];
    USHORT vlan_identifier;
    USHORT max_frame_size;
    USHORT max_interval_frames;
    UCHAR  priority : 3;
    UCHAR  rank     : 1;
    UCHAR  reserved : 4;
    UINT   accumulated_latency;
    UCHAR  system_id[8];
    UCHAR  failure_code;
} NX_MSRP_TALKER_FAILED;

/* Listener data structure*/
typedef struct
{

    UCHAR stream_id[8];
    UCHAR fourpacked_event;
} NX_MSRP_LISTENER;

typedef struct
{
    /* 6: classA, 5:class B*/
    UCHAR  sr_class_id;
    UCHAR  sr_class_priority;
    USHORT sr_class_vid;
} NX_MSRP_DOMAIN;

typedef union
{

    NX_MSRP_TALKER_ADVERTISE talker_advertise;
    NX_MSRP_TALKER_FAILED    talker_failed;
    NX_MSRP_LISTENER         listener;
    NX_MSRP_DOMAIN           domain;
} NX_MSRP_ATTRIBUTE_UNION;

typedef struct
{

    NX_MRP_ATTRIBUTE        mrp_attribute;
    NX_MSRP_ATTRIBUTE_UNION msrp_attribute_union;
    UCHAR                   indication_flag;
    UCHAR                   direction;
} NX_MSRP_ATTRIBUTE;

#define NX_MSRP_ATTRIBUTE_ARRAY_MAX_SIZE 10

typedef UINT (*NX_MRP_EVENT_CALLBACK)(NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR mrp_event, VOID *callback_data);

typedef struct nx_msrp
{
    NX_MRP_PARTICIPANT    nx_msrp_participant;
    NX_MRP_EVENT_CALLBACK msrp_event_callback;
    VOID                 *msrp_callback_data;
    UCHAR                 listener_enable;
} NX_MSRP;

/* Internal functions.  */
UINT nx_msrp_init(NX_MSRP *nx_msrp_ptr);
/*set as callback function*/
UINT nx_msrp_indication_process(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type);
UINT nx_msrp_mrpdu_parse();
UINT nx_msrp_mrpdu_pack();
/* Send talker advertise.*/
UINT nx_msrp_register_stream_request(NX_MRP * mrp, NX_MRP_PARTICIPANT * participant, NX_MSRP_TALKER_ADVERTISE * talker_advertise, UINT new_request);
/* Send talker withdraw.*/
UINT nx_msrp_deregister_stream_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, UCHAR *stream_id);
/* Send listener ready.*/
UINT nx_msrp_register_attach_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, UCHAR *stream_id, UINT event, UCHAR fourpacked_value);
/* Send listener withdraw.*/
UINT nx_msrp_deregister_attach_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, UCHAR *stream_id);
/* Recevie talker register request.*/
UINT nx_msrp_register_stream_indication(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UINT indication_event);
/* Recevie talker deregister request.*/
UINT nx_msrp_deregister_stream_indication(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type);
/* Recevie listener register attach.*/
UINT nx_msrp_register_attach_indication(NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type);
/* Recevie listener deregister attach.*/
UINT nx_msrp_deregister_attach_indication(NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type);
UINT nx_msrp_register_domain_request(NX_MRP * mrp, NX_MRP_PARTICIPANT * participant, NX_MSRP_DOMAIN * domain, UINT new_request);
UINT nx_msrp_register_domain_indication(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type);
UINT nx_msrp_deregister_domain_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MSRP_DOMAIN *domain);
UINT nx_msrp_deregister_domain_indication(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type);
UINT nx_msrp_attribute_find(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE **attribute_ptr, UCHAR attribute_type, UCHAR *attribute_value);
UINT nx_msrp_mrpdu_pack_attribute(NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, USHORT num_of_value,
                                  UCHAR *threepacked_event, UCHAR *fourpacked_event, UCHAR *data_ptr, UINT *length_ptr);
#endif

