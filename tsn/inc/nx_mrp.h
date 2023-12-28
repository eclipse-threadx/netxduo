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
/**   Multiple Registration Protocol (MRP)                                */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  COMPONENT DEFINITION                                   RELEASE        */
/*                                                                        */
/*    nx_mrp.h                                               Generic      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file defines the NetX TSN MRP component.                       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia               Initial Version 6.4.0          */
/*                                                                        */
/**************************************************************************/

#ifndef _NX_MRP_H_
#define _NX_MRP_H_

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */
#ifdef __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

#include "nx_api.h"
#include "nx_link.h"
#include "tx_timer.h"
#include "tx_port.h"

/* Define shaper constants. */

/* Event input for FSM */
#define NX_MRP_EVENT_RNEW                       (0) /* Receive New message (10.7.5.14) */
#define NX_MRP_EVENT_RJOININ                    (1) /* Receive JoinIn message (10.7.5.15) */
#define NX_MRP_EVENT_RIN                        (2) /* Receive In message (10.7.5.18) */
#define NX_MRP_EVENT_RJOINMT                    (3) /* Receive JoinEmpty message (10.7.5.16) */
#define NX_MRP_EVENT_RMT                        (4) /* Receive Empty message (10.7.5.19) */
#define NX_MRP_EVENT_RLV                        (5) /* Receive Leave message (10.7.5.17) */
#define NX_MRP_EVENT_RLA                        (6) /* Receive a LeaveAll message (10.7.5.20) */
#define NX_MRP_EVENT_BEGIN                      (7) /* Initialize state machine (10.7.5.1) */
#define NX_MRP_EVENT_NEW                        (8) /* A new declaration (10.7.5.4) */
#define NX_MRP_EVENT_JOIN                       (9) /* Declaration without signaling new registration (10.7.5.5) */
#define NX_MRP_EVENT_LV                         (10)/* Withdraw a declaration (10.7.5.6) */
#define NX_MRP_EVENT_TX                         (11)/* Transmission opportunity without a LeaveAll (10.7.5.7) */
#define NX_MRP_EVENT_TXLA                       (12)/* Transmission opportunity with a LeaveAll (10.7.5.8) */
#define NX_MRP_EVENT_TXLAF                      (13)/* Transmission opportunity with a LeaveAll, and with no room (Full) (10.7.5.9) */
#define NX_MRP_EVENT_FLUSH                      (14)/* Port role changes from Root Port or Alternate Port to Designated Port (10.7.5.2) */
#define NX_MRP_EVENT_REDECLARE                  (15)/* Port role changes from Designated to Root Port or Alternate Port (10.7.5.3) */
#define NX_MRP_EVENT_PERIODIC                   (16)/* A periodic transmission event occurs (10.7.5.10) */
#define NX_MRP_EVENT_LEAVETIMER                 (17)/* Leavetimer has expired (10.7.5.21) */
#define NX_MRP_EVENT_LEAVEALLTIMER              (18)/* Leavealltimer! leavealltimer has expired. (10.7.5.22) */
#define NX_MRP_EVENT_PERIODICTIMER              (19)/* Periodictimer has expired. (10.7.5.23) */
#define NX_MRP_EVENT_PERIODICENABLED            (20)/* Periodic Transmission state machine has been enabled */
#define NX_MRP_EVENT_PERIODICDISABLED           (21)/* Periodic Transmission state machine has been disabled */

/* State definition */
#define NX_MRP_APPLICANT_STATE_VO               (0) /* Very anxious Observer */
#define NX_MRP_APPLICANT_STATE_VP               (1) /* Very anxious Passive */
#define NX_MRP_APPLICANT_STATE_VN               (2) /* Very anxious New */
#define NX_MRP_APPLICANT_STATE_AN               (3) /* Anxious New */
#define NX_MRP_APPLICANT_STATE_AA               (4) /* Anxious Active */
#define NX_MRP_APPLICANT_STATE_QA               (5) /* Quiet Active */
#define NX_MRP_APPLICANT_STATE_LA               (6) /* Leaving Active */
#define NX_MRP_APPLICANT_STATE_AO               (7) /* Anxious Observer */
#define NX_MRP_APPLICANT_STATE_QO               (8) /* Quiet Observer */
#define NX_MRP_APPLICANT_STATE_AP               (9) /* Anxious Passive */
#define NX_MRP_APPLICANT_STATE_QP               (10)/* Quiet Passive */
#define NX_MRP_APPLICANT_STATE_LO               (11)/* Leaving Observer */
#define NX_MRP_REGISTRAR_STATE_IN               (12)/* In */
#define NX_MRP_REGISTRAR_STATE_LV               (13)/* Leaving */
#define NX_MRP_REGISTRAR_STATE_MT               (14)/* Empty */
#define NX_MRP_LA_STATE_ACTIVE                  (15)/* LeaveAll state Active */
#define NX_MRP_LA_STATE_PASSIVE                 (16)/* LeaveAll state Passive */
#define NX_MRP_PT_STATE_ACTIVE                  (17)/* PeriodicTransmission state Active */
#define NX_MRP_PT_STATE_PASSIVE                 (18)/* PeriodicTransmission state Passive */

/* Action definition */
#define NX_MRP_ACTION_NULL                      (0)
#define NX_MRP_ACTION_SN                        (1)
#define NX_MRP_ACTION_SJ                        (2)
#define NX_MRP_ACTION_SJ_OPT                    (3)
#define NX_MRP_ACTION_SL                        (4)
#define NX_MRP_ACTION_S                         (5)
#define NX_MRP_ACTION_S_OPT                     (6)
#define NX_MRP_ACTION_SLA                       (7)
#define NX_MRP_ACTION_PERIODIC                  (8)
#define NX_MRP_ACTION_START_LEAVETIMER          (9)
#define NX_MRP_ACTION_STOP_LEAVETIMER           (10)
#define NX_MRP_ACTION_START_LEAVEALLTIMER       (11)
#define NX_MRP_ACTION_START_PERIODICTIMER       (12)

/* Timer definition */
#define NX_MRP_TIMER_JOIN                       (200)   /* msec */
#define NX_MRP_TIMER_LEAVE                      (1000)  /* range 600-1000 msec */
#define NX_MRP_TIMER_LEAVEALL                   (10000) /* msec */
#define NX_MRP_TIMER_PERIODIC                   (1000)  /* The Periodic Transmission timer is set to one second when it is started */
#define NX_MRP_TIMEOUT_INTERVAL                 (200)   /* msec */

#define NX_MRP_TIMER_TICKS_PER_SECOND           (20)    /* tick: 200 ms */

/* Attribute event in attribute */
#define NX_MRP_ATTRIBUTE_EVENT_NEW              (0)
#define NX_MRP_ATTRIBUTE_EVENT_JOININ           (1)
#define NX_MRP_ATTRIBUTE_EVENT_IN               (2)
#define NX_MRP_ATTRIBUTE_EVENT_JOINMT           (3)
#define NX_MRP_ATTRIBUTE_EVENT_MT               (4)
#define NX_MRP_ATTRIBUTE_EVENT_LV               (5)

#define NX_MRP_INDICATION_NULL                  (0)
#define NX_MRP_INDICATION_NEW                   (NX_MRP_EVENT_NEW)
#define NX_MRP_INDICATION_JOIN                  (NX_MRP_EVENT_JOIN)
#define NX_MRP_INDICATION_LV                    (NX_MRP_EVENT_LV)
#define NX_MRP_INDICATION_EVICT                 (30)

#define NX_MRP_PARTICIPANT_MSRP                 (NX_LINK_ETHERNET_MSRP)
#define NX_MRP_PARTICIPANT_MMRP                 (NX_LINK_ETHERNET_MMRP)
#define NX_MRP_PARTICIPANT_MVRP                 (NX_LINK_ETHERNET_MVRP)

#define NX_MRP_MRP_ETH_MULTICAST_ADDR_MSB       (0x0180)
#define NX_MRP_MSRP_ETH_MULTICAST_ADDR_LSB      (0xC200000E)
#define NX_MRP_MMRP_ETH_MULTICAST_ADDR_LSB      (0xC2000020)
#define NX_MRP_MVRP_ETH_MULTICAST_ADDR_LSB      (0xC2000021)

#define NX_MRP_DEFAULT_OPER_P2P_MAC             (0)

#define NX_MRP_RX_EVENT                         (0x00000001u)
#define NX_MRP_TIMER_EVENT                      (0x00000002u)
#define NX_MRP_ALL_EVENTS                       (0xFFFFFFFFu) /* All event flags. */

/* MRP structure.  */
typedef struct NX_MRP_PERIODIC_TRANSMISSION_STRUCT
{
    UCHAR state;
    UCHAR reserved[3];
} NX_MRP_PERIODIC_TRANSMISSION;

typedef struct NX_MRP_LEAVEALL_STRUCT
{
    UCHAR state;
    UCHAR action;
    UCHAR reserved[2];
} NX_MRP_LEAVEALL;

/* Attribute struct */
typedef struct NX_MRP_ATTRIBUTE_APPLICANT_STRUCT
{
    UCHAR state;      /* applicant state */
    UCHAR action;     /* attribute event value would be encapsulated in next msg */
    UCHAR reserved[2];
} NX_MRP_ATTRIBUTE_APPLICANT;

typedef struct NX_MRP_ATTRIBUTE_REGISTRAR_STRUCT
{
    UCHAR state;     /* registrar state */
    UCHAR reserved[3];
} NX_MRP_ATTRIBUTE_REGISTRAR;

typedef struct NX_MRP_ATTRIBUTE_STRUCT
{
    UCHAR                           attribute_type;
    UCHAR                           in_use;
    UCHAR                           reserved[2];
    UINT                            leave_timer; /* leave timer is per attribute, when created, the timeout function with param (pointer to attribute) need to be registered */
    NX_MRP_ATTRIBUTE_APPLICANT      applicant;
    NX_MRP_ATTRIBUTE_REGISTRAR      registrar;
    struct NX_MRP_ATTRIBUTE_STRUCT *pre;
    struct NX_MRP_ATTRIBUTE_STRUCT *next;
} NX_MRP_ATTRIBUTE;

struct NX_MRP_PARTICIPANT_STRUCT;

struct NX_MRP_STRUCT;

typedef UINT (*NX_MRP_INDICATION)(struct NX_MRP_STRUCT *mrp, struct NX_MRP_PARTICIPANT_STRUCT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type);
typedef UINT (*NX_MRP_RX_PACKET_PROCESS)(struct NX_MRP_STRUCT *mrp, struct NX_MRP_PARTICIPANT_STRUCT *participant, NX_PACKET *packet);
typedef UINT (*NX_MRP_TX_PACKET_PROCESS)(struct NX_MRP_STRUCT *mrp, struct NX_MRP_PARTICIPANT_STRUCT *participant, NX_PACKET *packet);     /* TBD, interface consideration */

/* Participant struct */
typedef struct NX_MRP_PARTICIPANT_STRUCT
{
    UINT                              participant_type; /* MVRP/MSRP/MMRP */
    UINT                              join_timer;
    UINT                              leaveall_timer;
    NX_MRP_LEAVEALL                   leaveall;
    NX_MRP_INDICATION                 indication_function;
    NX_MRP_RX_PACKET_PROCESS          unpack_function; /* inform participant to pack */
    NX_MRP_TX_PACKET_PROCESS          pack_function;   /* inform participant to pack */
    struct NX_MRP_PARTICIPANT_STRUCT *next;            /* participant list */
    NX_MRP_ATTRIBUTE                 *inused_head;     /* attribute list */
    UCHAR                            *buffer;          /* save the attribute array pointer */
    USHORT                            buffer_size;     /* save the attribute array size */
    UCHAR                             protocol_version;
    UCHAR                             reserved;
} NX_MRP_PARTICIPANT;

typedef struct NX_MRP_STRUCT
{
    NX_MRP_PARTICIPANT   *list_head;
    UINT                  periodic_timer;       /* periodic timer is per port */
    TX_TIMER              mrp_timer;            /* Main timer expires for each 100ms */
    TX_THREAD             mrp_thread;
    NX_LINK_RECEIVE_QUEUE receive_queue;        /* need to insert the packet into list and trigger event in related callback function */
    NX_PACKET            *received_packet_head; /* new added, need to be discussed*/
    NX_PACKET            *received_packet_tail;
    NX_PACKET_POOL       *pkt_pool;             /* Pool used for send packet */
    TX_EVENT_FLAGS_GROUP  mrp_events;           /* packet event and timer event, the timeout function just set the event flag of timeout */
    TX_MUTEX              mrp_mutex;
    NX_IP                *ip_ptr;
    UINT                  interface_index;
    UCHAR                 oper_p2p_mac; /* operPointToPointMAC */
    UCHAR                 reserved[3];
} NX_MRP;

UINT nx_mrp_applicant_event_process(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR mrp_event);
UINT nx_mrp_registrar_event_process(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR mrp_event);
UINT nx_mrp_leaveall_event_process(NX_MRP_PARTICIPANT *participant, UCHAR mrp_event);
NX_MRP_ATTRIBUTE *nx_mrp_attribute_new(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant,
                                       NX_MRP_ATTRIBUTE *attribute_array, UINT unit_size,
                                       UINT unit_number);
UINT nx_mrp_attribute_evict(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *target);
UINT nx_mrp_ethernet_receive_notify(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                    ULONG physical_address_msw, ULONG physical_address_lsw,
                                    UINT packet_type, UINT header_size, VOID *context,
                                    struct NX_LINK_TIME_STRUCT *time_ptr);
UINT nx_mrp_participant_add(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant);
UINT nx_mrp_init(NX_MRP *mrp, NX_IP *ip_ptr, UINT interface_index, NX_PACKET_POOL *pkt_pool_ptr,
                 CHAR *thread_name, VOID *stack_ptr, ULONG stack_size, UINT priority);

UINT nx_mrp_event_process(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR mrp_event);
UINT nx_mrp_attribute_event_get(NX_MRP_ATTRIBUTE *attribute, UCHAR *event_ptr);
void nx_mrp_rcv_pkt_process(NX_MRP *mrp);
void nx_mrp_periodic_timeout_process(NX_MRP *mrp);
void nx_mrp_join_timeout_process(NX_MRP *mrp);
void nx_mrp_leaveall_timeout_process(NX_MRP *mrp);
void nx_mrp_leave_timeout_process(NX_MRP *mrp);
void nx_mrp_timeout_process(NX_MRP *mrp);
void nx_mrp_thread_entry(ULONG mrp_instance);
void nx_mrp_timer_handle(ULONG mrp_instance);

NX_MRP_PARTICIPANT *nx_mrp_participant_search(NX_MRP *mrp, UINT participant_type);

/* Determine if a C++ compiler is being used.  If so, complete the standard
   C conditional started above.  */
#ifdef __cplusplus
}
#endif

#endif /* _NX_MRP_H_ */

