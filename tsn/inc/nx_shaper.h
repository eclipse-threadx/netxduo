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
/** NetX shaper                                                           */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  COMPONENT DEFINITION                                   RELEASE        */
/*                                                                        */
/*    nx_shaper.h                                            Generic      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file defines the NetX shaper component.                        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia               Initial Version 6.4.0          */
/*                                                                        */
/**************************************************************************/

#ifndef NX_SHAPER_H
#define NX_SHAPER_H

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */
#ifdef __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

#include "nx_api.h"

/* Define shaper constants. */
#define NX_SHAPER_CLASS_A_PCP                           (3)
#define NX_SHAPER_CLASS_B_PCP                           (2)
#define NX_SHAPER_PCP_MAX                               (7)

#define NX_SHAPER_MAPPING_LIST_SIZE                     (8)

#define NX_SHAPER_HW_QUEUE_NONE                         (0)
#define NX_SHAPER_HW_QUEUE_NORMAL                       (1u << 0)
#define NX_SHAPER_HW_QUEUE_CBS                          (1u << 1)

#define NX_SHAPER_TYPE_CBS                              (0)
#define NX_SHAPER_TYPE_TAS                              (1)
#define NX_SHAPER_TYPE_FP                               (2)
#define NX_SHAPER_TYPE_MAX                              (3)

#define NX_SHAPER_NUMBERS                               (3)

#define NX_SHAPER_INVALID_INDEX                         (0xFF)

#define NX_SHAPER_CAPABILITY_CBS_SUPPORTED              (1U << 1)
#define NX_SHAPER_CAPABILITY_TAS_SUPPORTED              (1U << 2)
#define NX_SHAPER_CAPABILITY_PREEMPTION_SUPPORTED       (1U << 3)

#define NX_SHAPER_COMMAND_INIT                          (0x01)
#define NX_SHAPER_COMMAND_CONFIG                        (0x02)
#define NX_SHAPER_COMMAND_PARAMETER_SET                 (0x03)

#define NX_SHAPER_MAX_SPA_QUEUE_NUM                     (8)

#define NX_SHAPER_GATE_OPERATION_SET                    (0)
#define NX_SHAPER_GATE_OPERATION_HOLD                   (1)
#define NX_SHAPER_GATE_OPERATION_RELEASE                (2)

#define NX_SHAPER_GCL_LENGTH_MAX                        (32)

#define NX_SHAPER_TRAFFIC_OPEN                          (1)
#define NX_SHAPER_TRAFFIC_CLOSE                         (0)

#define NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_DISABLED     (0)
#define NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_WITH_OPEN    (1)
#define NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_WITH_CLOSE   (2)

#define NX_SHAPER_GCL_AUTO_FILL_FLAG                    (0x80000000)

#define NX_SHAPER_DEFAULT_MIN_FRAGMENTABLE_SDU_SIZE     (123)
#define NX_SHAPER_DEFAULT_MIN_SDU_SIZE                  (64)

#define NX_SHAPER_FP_DEFAULT_HA                         (0)
#define NX_SHAPER_FP_DEFAULT_RA                         (0xFFFFFFFF)

/* Shaper structure.  */
struct NX_SHAPER_DRIVER_PARAMETER_STRUCT;
typedef UINT (*NX_SHAPER_DRIVER)(struct NX_SHAPER_DRIVER_PARAMETER_STRUCT *parameter);
typedef UINT (*NX_SHAPER_DEFAULT_MAPPING_GET)(NX_INTERFACE *interface_ptr, UCHAR *pcp_list, UCHAR *queue_id_list, UCHAR list_size);

typedef struct NX_SHAPER_HW_QUEUE_STRUCT
{
    UCHAR hw_queue_id;
    UCHAR priority;
    UCHAR type;
    UCHAR reserved;
} NX_SHAPER_HW_QUEUE;

typedef struct NX_SHAPER_STRUCT
{
    UCHAR            shaper_type;
    UCHAR            reserved[3];
    NX_SHAPER_DRIVER shaper_driver;
    void            *cfg_pointer;
} NX_SHAPER;

typedef struct NX_SHAPER_CONTAINER_STRUCT
{
    UINT               port_rate;         /* Mbps */
    UCHAR              shaper_capability; /* cbs/tas/preemption control */
    UCHAR              hw_queue_number;   /* total number of hardware queues */
    UCHAR              shaper_number;     /* total number of shapers */
    UCHAR              reserved;
    NX_SHAPER_HW_QUEUE hw_queue[NX_SHAPER_MAX_SPA_QUEUE_NUM];
    UCHAR              queue_map[NX_SHAPER_MAX_SPA_QUEUE_NUM];
    NX_SHAPER         *shaper[NX_SHAPER_NUMBERS];
} NX_SHAPER_CONTAINER;

typedef struct NX_SHAPER_CBS_PARAMETER_STRUCT
{
    INT   idle_slope;   /* Mbps */
    INT   send_slope;   /* Mbps */
    INT   hi_credit;
    INT   low_credit;
    UCHAR hw_queue_id;
    UCHAR reserved[3];
} NX_SHAPER_CBS_PARAMETER;

typedef struct NX_SHAPER_DRIVER_PARAMETER_STRUCT
{
    UINT          nx_shaper_driver_command;
    UCHAR         shaper_type;
    UCHAR         reserved[3];
    void         *shaper_parameter;
    NX_INTERFACE *nx_ip_driver_interface;
} NX_SHAPER_DRIVER_PARAMETER;

typedef struct NX_SHAPER_TAS_GCL_STRUCT
{
    UINT  gate_control;    /* max 8 queues */
    UINT  duration;
    UCHAR operation;
    UCHAR reserved[3];
} NX_SHAPER_TAS_GCL;

typedef struct NX_SHAPER_TAS_PARAMETER_STRUCT
{
    ULONG64           base_time;
    UINT              cycle_time;
    UINT              cycle_time_extension;
    UINT              gcl_length;
    NX_SHAPER_TAS_GCL gcl[NX_SHAPER_GCL_LENGTH_MAX];
    void             *fp_parameter; /* Configured by shaper */
} NX_SHAPER_TAS_PARAMETER;

typedef struct NX_SHAPER_TAS_TRAFFIC_CONFIG_STRUCT
{
    UCHAR pcp;
    UCHAR traffic_control;
    UCHAR reserved[2];
    UINT  time_offset;    /* slot start offset of each cycle */
    UINT  duration;
} NX_SHAPER_TAS_TRAFFIC_CONFIG;

typedef struct NX_SHAPER_TAS_CONFIG_STRUCT
{
    ULONG64                      base_time;  /* (nano seconds) 0 means current cycle finish time */
    UINT                         cycle_time; /* (nano seconds) */
    UINT                         auto_fill_status;
    UINT                         traffic_count;
    NX_SHAPER_TAS_TRAFFIC_CONFIG traffic[NX_SHAPER_GCL_LENGTH_MAX];
} NX_SHAPER_TAS_CONFIG;

typedef struct NX_SHAPER_FP_PARAMETER_STRUCT
{
    UCHAR verification_enable;          /* Enable/Disable fp verification (Application/Driver) */
    UCHAR express_queue_bitmap;         /* Bitmap of express queues */
    UCHAR express_guardband_enable;     /* Enable/Disable guard band on express queue */
    UCHAR reserved;
    UINT  ha;                           /* Hold advance time */
    UINT  ra;                           /* Release advance time */
} NX_SHAPER_FP_PARAMETER;

/* APIs for network driver.  */
UINT nx_shaper_config(NX_INTERFACE *interface_ptr, UINT port_rate, UCHAR shaper_capability,
                      UCHAR hw_queue_number, NX_SHAPER_HW_QUEUE *hw_queue);
UINT nx_shaper_hw_queue_set(NX_INTERFACE *interface_ptr, UCHAR hw_queue_id, UCHAR priority, UCHAR type);
UINT nx_shaper_hw_queue_id_get(NX_INTERFACE *interface_ptr, NX_PACKET *packet_ptr, UCHAR *hw_queue_id);

/* Define APIs for application.  */
UINT nx_shaper_create(NX_INTERFACE *interface_ptr, NX_SHAPER_CONTAINER *shaper_container, NX_SHAPER *shaper, UCHAR shaper_type, NX_SHAPER_DRIVER shaper_driver);
UINT nx_shaper_delete(NX_INTERFACE *interface_ptr, NX_SHAPER *shaper);
UINT nx_shaper_current_mapping_get(NX_INTERFACE *interface_ptr, UCHAR *pcp_list, UCHAR *queue_id_list, UCHAR list_size);
UINT nx_shaper_default_mapping_get(NX_INTERFACE *interface_ptr, UCHAR *pcp_list, UCHAR *queue_id_list, UCHAR list_size);
UINT nx_shaper_mapping_set(NX_INTERFACE *interface_ptr, UCHAR *pcp_list, UCHAR *queue_id_list, UCHAR list_size);
UINT nx_shaper_cbs_parameter_set(NX_INTERFACE *interface_ptr, NX_SHAPER_CBS_PARAMETER *cbs_parameter, UCHAR pcp);
UINT nx_shaper_fp_parameter_set(NX_INTERFACE *interface_ptr, NX_SHAPER_FP_PARAMETER *fp_parameter);
UINT nx_shaper_tas_parameter_set(NX_INTERFACE *interface_ptr, NX_SHAPER_TAS_CONFIG *tas_config);

/* Internal functions. */
UINT nx_shaper_hw_queue_number_get(NX_INTERFACE *interface_ptr, UCHAR *hw_queue_number);
UINT nx_shaper_hw_cbs_queue_number_get(NX_INTERFACE *interface_ptr, UCHAR *hw_cbs_queue_number);
UINT nx_shaper_port_rate_get(NX_INTERFACE *interface_ptr, UINT *port_rate);
UINT nx_shaper_sdu_tx_time_get(NX_INTERFACE *interface_ptr, UINT sdu_size, UINT *tx_time);
UINT nx_shaper_express_queue_set(NX_INTERFACE *interface_ptr, UCHAR *express_queue_bitmap, UCHAR pcp);

#ifdef __cplusplus
}
#endif

#endif /* NX_SHAPER_H */

