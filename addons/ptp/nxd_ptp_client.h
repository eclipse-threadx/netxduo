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
/** NetX PTP Client Component                                             */
/**                                                                       */
/**   Precision Time Protocol (PTP)                                       */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

/**************************************************************************/
/*                                                                        */
/*  APPLICATION INTERFACE DEFINITION                       RELEASE        */
/*                                                                        */
/*    nxd_ptp_client.h                                    PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file defines the NetX Precision Time Protocol (PTP)            */
/*    Client component, including all data types and external references. */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*  12-31-2023     Tiejun Zhou              Modified comment(s), and      */
/*                                            supported gPTP profile,     */
/*                                            supported master clock,     */
/*                                            resulting in version 6.4.0  */
/*                                                                        */
/**************************************************************************/

#ifndef NXD_PTP_CLIENT_H
#define NXD_PTP_CLIENT_H


/* Include NetX and ThreadX definitions */

#include "nx_api.h"


/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */

#ifdef   __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif


/* Define the PTP Client ID */

#define NX_PTP_CLIENT_ID 0x50545001UL

/* PTP Client configurable options.  */
/* Enable GPTP configuration as per IEEE 802.1AS. PTP messages are transmitted over Ethernet with peer delay request mechanism.
   If not enabled by default, PTP messages are transmitted over UDP with delay request mechanism. */
/*
#define NX_ENABLE_GPTP
*/

/* Enable PTP master feature. The role can be selected at runtime. Supported roles,
   * NX_PTP_CLIENT_ROLE_SLAVE_ONLY
   * NX_PTP_CLIENT_ROLE_MASTER_ONLY
   * NX_PTP_CLIENT_ROLE_SLAVE_AND_MASTER */
/*
#define NX_PTP_ENABLE_MASTER
*/

/* Disable PTP slave feature. Only master can be supported.  */
/*
#define NX_PTP_DISABLE_SLAVE
*/

/* Enable sending reverse sync when the role of PTP clock becomes slave. This will allow master clock
   to be aware of the offset from slave to master. Reverse SYNC may be ignored by master clock.  */
/*
#define NX_PTP_ENABLE_REVERSE_SYNC
*/

/* PTP Client packet type. By default, UDP is used as transport.  */
#ifndef NX_PTP_CLIENT_TRANSPORT_UDP
#ifdef NX_ENABLE_GPTP
#define NX_PTP_CLIENT_TRANSPORT_UDP      0
#else
#define NX_PTP_CLIENT_TRANSPORT_UDP      1
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP  */

#ifndef NX_PTP_CLIENT_TRANSPORT_ETHERNET
#ifdef NX_ENABLE_GPTP
#define NX_PTP_CLIENT_TRANSPORT_ETHERNET 1
#else
#define NX_PTP_CLIENT_TRANSPORT_ETHERNET 0
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET  */

#if NX_PTP_CLIENT_TRANSPORT_UDP && NX_PTP_CLIENT_TRANSPORT_ETHERNET
#error "Only one of NX_PTP_CLIENT_TRANSPORT_UDP and NX_PTP_CLIENT_TRANSPORT_ETHERNET can be enabled"
#endif

#if !NX_PTP_CLIENT_TRANSPORT_UDP && !NX_PTP_CLIENT_TRANSPORT_ETHERNET
#error "At least one of NX_PTP_CLIENT_TRANSPORT_UDP or NX_PTP_CLIENT_TRANSPORT_ETHERNET must be enabled"
#endif

#if (NX_PTP_CLIENT_TRANSPORT_ETHERNET == 1) && !defined(NX_ENABLE_VLAN)
#error "NX_ENABLE_VLAN must be enabled for NX_PTP_CLIENT_TRANSPORT_ETHERNET"
#endif

#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
#include "nx_link.h"
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET  */

/* Set the client thread time slice.  */

#ifndef NX_PTP_CLIENT_THREAD_TIME_SLICE
#define NX_PTP_CLIENT_THREAD_TIME_SLICE          TX_NO_TIME_SLICE
#endif



/* Define the PTP client internal timer frequency */

#ifndef NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND
#define NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND     100
#endif


/* Define the maximum number of missing Announce packets before timeout */

#ifndef NX_PTP_CLIENT_ANNOUNCE_RECEIPT_TIMEOUT
#define NX_PTP_CLIENT_ANNOUNCE_RECEIPT_TIMEOUT   3
#endif


/* Define the time interval between successive Announce packet, expressed as log 2.
   This value should be uniform throughout a domain. The default value is 1=2s. */

#ifndef NX_PTP_CLIENT_LOG_ANNOUNCE_INTERVAL
#define NX_PTP_CLIENT_LOG_ANNOUNCE_INTERVAL      1
#endif

/* Define the time interval between successive Sync packet, expressed as log 2.
   This value should be uniform throughout a domain. The default value is -3=125ms. */

#ifndef NX_PTP_CLIENT_LOG_SYNC_INTERVAL
#define NX_PTP_CLIENT_LOG_SYNC_INTERVAL          -3
#endif

/* Define the time interval between successive Pdelay_Req packet, expressed as log 2.
   This value should be uniform throughout a domain. The default value is 0=1s. */

#ifndef NX_PTP_CLIENT_LOG_PDELAY_REQ_INTERVAL
#define NX_PTP_CLIENT_LOG_PDELAY_REQ_INTERVAL    0
#endif

/* Define the interval for sending Delay request packets */

#ifndef NX_PTP_CLIENT_DELAY_REQ_INTERVAL
#define NX_PTP_CLIENT_DELAY_REQ_INTERVAL         (2 * NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND)
#endif

/* Set maximum queue depth for client socket.*/

#ifndef NX_PTP_CLIENT_MAX_QUEUE_DEPTH    
#define NX_PTP_CLIENT_MAX_QUEUE_DEPTH            5
#endif

/* Define the meanLinkDelayThresh as per 802.1AS-2020, 11.2.2.  The default value is 800ns for 100BASE-TX, 1000BASE-T. */
#ifndef NX_PTP_CLIENT_DELAY_THRESH
#define NX_PTP_CLIENT_DELAY_THRESH               800
#endif /* NX_PTP_CLIENT_DELAY_THRESH */


/* Define the interval for sending Sync packets */
#if (NX_PTP_CLIENT_LOG_SYNC_INTERVAL >= 0)
#define NX_PTP_CLIENT_SYNC_INTERVAL              ((1 << NX_PTP_CLIENT_LOG_SYNC_INTERVAL) * \
                                                NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND)
#else
#define NX_PTP_CLIENT_SYNC_INTERVAL              (NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND >> \
                                                (-(NX_PTP_CLIENT_LOG_SYNC_INTERVAL)))
#endif

/* Define the interval for sending Announce packets */
#if (NX_PTP_CLIENT_LOG_ANNOUNCE_INTERVAL >= 0)
#define NX_PTP_CLIENT_ANNOUNCE_INTERVAL          ((1 << NX_PTP_CLIENT_LOG_ANNOUNCE_INTERVAL) * \
                                                NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND)
#else
#define NX_PTP_CLIENT_ANNOUNCE_INTERVAL          (NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND >> \
                                                (-(NX_PTP_CLIENT_LOG_ANNOUNCE_INTERVAL)))
#endif

/* Define the interval for sending Peer Delay request packets */

#if (NX_PTP_CLIENT_LOG_PDELAY_REQ_INTERVAL >= 0)
#define NX_PTP_CLIENT_PDELAY_REQ_INTERVAL        ((1 << NX_PTP_CLIENT_LOG_PDELAY_REQ_INTERVAL) * \
                                                 NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND)
#else
#define NX_PTP_CLIENT_PDELAY_REQ_INTERVAL        (NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND >> \
                                                 (-(NX_PTP_CLIENT_LOG_PDELAY_REQ_INTERVAL)))
#endif


/* Define the maximum size of a PTP message */

#define NX_PTP_CLIENT_PACKET_DATA_SIZE           64

/* Define Announce receipt timeout expire value */
#define NX_PTP_CLIENT_ANNOUNCE_EXPIRATION        (NX_PTP_CLIENT_ANNOUNCE_RECEIPT_TIMEOUT *     \
                                                (1 << NX_PTP_CLIENT_LOG_ANNOUNCE_INTERVAL) * \
                                                NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND)


/* Define the default priority for local PTP clock running as master mode. */
#define NX_PTP_CLIENT_MASTER_PRIORITY            248

/* Define the default clock class for local PTP clock running as master mode. */
#define NX_PTP_CLIENT_MASTER_CLOCK_CLASS         248

/* Define the default accuracy for local PTP clock running as master mode. 
   The default value 0x22 means the time is accurate to within 250ns.  */
#define NX_PTP_CLIENT_MASTER_ACCURACY            0x22

/* Define  the default clock variance for local PTP clock running as master mode. */
#define NX_PTP_CLIENT_MASTER_CLOCK_VARIANCE      17258

/* Define  the default clock steps removed for local PTP clock running as master mode. */
#define NX_PTP_CLIENT_MASTER_CLOCK_STEPS_REMOVED 0

/* Implementations based on IEEE Std 1588-2008 and any implementations based on this edition
   where the expanded profile isolation capabilities of option 16.5 are not required */
#define NX_PTP_TRANSPORT_SPECIFIC_NON_802        0

/* Implementations based on PTP Profiles developed by the IEEE 802.1 Working Group */
#define NX_PTP_TRANSPORT_SPECIFIC_802            1


/* Define a PTP Time */

typedef struct NX_PTP_TIME_STRUCT
{
    /* The MSB of the number of seconds */
    LONG  second_high;

    /* The LSB of the number of seconds */
    ULONG second_low;

    /* The number of nanoseconds */
    LONG  nanosecond;
} NX_PTP_TIME;


/* Define the PTP Date Time structure.  */

typedef struct NX_PTP_DATE_TIME_STRUCT
{
    UINT  year;
    UCHAR month;
    UCHAR day;
    UCHAR hour;
    UCHAR minute;
    UCHAR second;
    UCHAR weekday;
    UCHAR reserved[2];
    ULONG nanosecond;
} NX_PTP_DATE_TIME;


/* Internal PTP error processing codes.  */

#define NX_PTP_ERROR_CONSTANT                      0xD00
/* Client side errors.  */
#define NX_PTP_CLIENT_NOT_STARTED                  (NX_PTP_ERROR_CONSTANT | 0x01) /* PTP Client task is not running */
#define NX_PTP_CLIENT_ALREADY_STARTED              (NX_PTP_ERROR_CONSTANT | 0x02) /* PTP Client task is already running */
#define NX_PTP_PARAM_ERROR                         (NX_PTP_ERROR_CONSTANT | 0x03) /* Invalid non pointer parameter.  */
#define NX_PTP_CLIENT_INSUFFICIENT_PACKET_PAYLOAD  (NX_PTP_ERROR_CONSTANT | 0x04) /* Client not properly initialized to receive time data.  */
#define NX_PTP_CLIENT_CLOCK_CALLBACK_FAILURE       (NX_PTP_ERROR_CONSTANT | 0x05) /* PTP clock callback returns error.  */


/* PTP Protocol Definitions */

/* Define the size of the PTP Clock Identity field */
#define NX_PTP_CLOCK_IDENTITY_SIZE                 8

/* Define the size of the PTP Clock Port and Identity field */
#define NX_PTP_CLOCK_PORT_IDENTITY_SIZE            (NX_PTP_CLOCK_IDENTITY_SIZE + 2)

/* PTP Master Definitions */

#define NX_PTP_MASTER_CLOCK_ANNOUNCE_RATE          10 //(every 10 ptp ticks)

/* Master time sources */
#define NX_PTP_MASTER_TIME_SRC_ATOMIC_CLOCK        0x10
#define NX_PTP_MASTER_TIME_SRC_GPS                 0x20
#define NX_PTP_MASTER_TIME_SRC_TERRESTRIAL_RADIO   0x30
#define NX_PTP_MASTER_TIME_SRC_PTP                 0x40
#define NX_PTP_MASTER_TIME_SRC_NTP                 0x50
#define NX_PTP_MASTER_TIME_SRC_HAND_SET            0x60
#define NX_PTP_MASTER_TIME_SRC_OTHER               0x90
#define NX_PTP_MASTER_TIME_SRC_INTERNAL_OSCILLATOR 0xa0


/* PTP event callback */

struct NX_PTP_CLIENT_STRUCT;

typedef UINT (*NX_PTP_CLIENT_EVENT_CALLBACK)(struct NX_PTP_CLIENT_STRUCT *client_ptr, UINT event,
                                             VOID *event_data, VOID *callback_data);

#define NX_PTP_CLIENT_EVENT_MASTER                 0
#define NX_PTP_CLIENT_EVENT_SYNC                   1
#define NX_PTP_CLIENT_EVENT_TIMEOUT                2


/* PTP clock callback operations  */

typedef UINT (*NX_PTP_CLIENT_CLOCK_CALLBACK)(struct NX_PTP_CLIENT_STRUCT *client_ptr, UINT operation,
                                             NX_PTP_TIME *time_ptr, NX_PACKET *packet_ptr, VOID *callback_data);

#define NX_PTP_CLIENT_CLOCK_INIT                   0                                     /* Initialization */
#define NX_PTP_CLIENT_CLOCK_SET                    1                                     /* Set the PTP clock */
#define NX_PTP_CLIENT_CLOCK_GET                    2                                     /* Get the PTP clock */
#define NX_PTP_CLIENT_CLOCK_ADJUST                 3                                     /* Adjust the PTP clock */
#define NX_PTP_CLIENT_CLOCK_PACKET_TS_EXTRACT      4                                     /* Extract timestamp from packet */
#define NX_PTP_CLIENT_CLOCK_PACKET_TS_PREPARE      5                                     /* Prepare timestamp for packet */
#define NX_PTP_CLIENT_CLOCK_SOFT_TIMER_UPDATE      6                                     /* Update timer for soft implementation */
#define NX_PTP_CLIENT_CLOCK_TS_EXTRACT_ETHERNET    NX_PTP_CLIENT_CLOCK_PACKET_TS_EXTRACT /* Record timestamp of received packet from Ethernet layer */


/* Master messages data */
typedef struct NX_PTP_CLIENT_MASTER_STRUCT
{
    NXD_ADDRESS *nx_ptp_client_master_address;
    UCHAR       *nx_ptp_client_master_port_identity;
    UCHAR        nx_ptp_client_master_priority1;
    UCHAR        nx_ptp_client_master_priority2;
    UCHAR        nx_ptp_client_master_clock_class;
    UCHAR        nx_ptp_client_master_clock_accuracy;
    USHORT       nx_ptp_client_master_offset_scaled_log_variance;
    USHORT       nx_ptp_client_master_steps_removed;
    UCHAR       *nx_ptp_client_master_grandmaster_identity;
    UCHAR        nx_ptp_client_master_time_source;
    UCHAR        nx_ptp_client_master_reserved[3];
#ifdef NX_PTP_ENABLE_MASTER
    USHORT       nx_ptp_client_master_sequenceId;
    USHORT       nx_ptp_client_master_sync_sequenceId;
    /* The announce interval timer */
    INT          nx_ptp_client_master_announce_timer;
#endif
} NX_PTP_CLIENT_MASTER;

/* Sync flags */
#define NX_PTP_CLIENT_SYNC_CALIBRATED     (1 << 0)
#define NX_PTP_CLIENT_SYNC_UTC_REASONABLE (1 << 1)
#define NX_PTP_CLIENT_SYNC_LEAP59         (1 << 2)
#define NX_PTP_CLIENT_SYNC_LEAP61         (1 << 3)

/* Sync message data */
typedef struct NX_PTP_CLIENT_SYNC_STRUCT
{
    USHORT nx_ptp_client_sync_flags;
    SHORT  nx_ptp_client_sync_utc_offset;
} NX_PTP_CLIENT_SYNC;


/* Define the Type of messages */

#define NX_PTP_CLIENT_ALL_EVENTS                 0xFFFFFFFF /* all events of PTP client */
#define NX_PTP_CLIENT_STOP_EVENT                 0x00000001 /* stop the PTP client */
#define NX_PTP_CLIENT_RX_EVENT                   0x00000002 /* received UDP packet */
#define NX_PTP_CLIENT_TIMER_EVENT                0x00000004 /* timer tick */
#define NX_PTP_CLIENT_SYNC_FOLLOW_EVENT          0x00000008 /* send Sync follow up packet */
#define NX_PTP_CLIENT_PDELAY_FOLLOW_EVENT        0x00000010 /* send pdelay response follow up packet */

/* Define the size of the PTP client message queue */

#define NX_PTP_CLIENT_MESSAGE_QUEUE_SIZE         16


/* Define the state of the PTP Client thread */

#define NX_PTP_CLIENT_THREAD_IDLE                0
#define NX_PTP_CLIENT_THREAD_RUNNING             1
#define NX_PTP_CLIENT_THREAD_STOPPING            2
#define NX_PTP_CLIENT_THREAD_STOPPED             3


/* Define the state of the PTP Client clock */

#define NX_PTP_CLIENT_STATE_LISTENING            0
#define NX_PTP_CLIENT_STATE_WAIT_SYNC            1
#define NX_PTP_CLIENT_STATE_WAIT_FOLLOW_UP       2
#define NX_PTP_CLIENT_STATE_SLAVE                3
#define NX_PTP_CLIENT_STATE_MASTER               4


/* Define the state of the delay measurement process */

#define NX_PTP_CLIENT_DELAY_IDLE                 0
#define NX_PTP_CLIENT_DELAY_WAIT_REQ_TS          1
#define NX_PTP_CLIENT_DELAY_WAIT_RESP            2


/* Define the state of the peer delay initiator process */

#define NX_PTP_CLIENT_PDELAY_IDLE                0
#define NX_PTP_CLIENT_PDELAY_WAIT_REQ_TS         1
#define NX_PTP_CLIENT_PDELAY_WAIT_RESP           2
#define NX_PTP_CLIENT_PDELAY_WAIT_RESP_FOLLOW_UP 3

/* Define the state of the peer delay receiver process */

#define NX_PTP_CLIENT_PDELAY_WAIT_SYNC           0
#define NX_PTP_CLIENT_PDELAY_WAIT_REQ            1
#define NX_PTP_CLIENT_PDELAY_SEND_RESP_ONESTEP   2
#define NX_PTP_CLIENT_PDELAY_SEND_RESP_TWOSTEP   3
#define NX_PTP_CLIENT_PDELAY_SEND_FOLLOW_UP      4

/* Define PTP roles.  */
#define NX_PTP_CLIENT_ROLE_SLAVE_ONLY            0
#define NX_PTP_CLIENT_ROLE_MASTER_ONLY           1
#define NX_PTP_CLIENT_ROLE_SLAVE_AND_MASTER      2

/* Define the structure of a PTP Client */

typedef struct NX_PTP_CLIENT_STRUCT
{
    /* PTP Client ID */
    ULONG                        nx_ptp_client_id;

    /* Pointer to the Client IP instance.  */
    NX_IP                       *nx_ptp_client_ip_ptr;

    /* Index to PTP network interface  */
    UINT                         nx_ptp_client_interface_index;

    /* Pointer to the Client packet pool.  */
    NX_PACKET_POOL              *nx_ptp_client_packet_pool_ptr;

    /* PTP Domain Number */
    UCHAR                        nx_ptp_client_domain;

    /* PTP Transport Specific */
    UCHAR                        nx_ptp_client_transport_specific;

    /* PTP Client Port and Identity */
    UCHAR                        nx_ptp_client_port_identity[NX_PTP_CLOCK_PORT_IDENTITY_SIZE];

    /* PTP event handler callback */
    NX_PTP_CLIENT_EVENT_CALLBACK nx_ptp_client_event_callback;
    VOID                        *nx_ptp_client_event_callback_data;

    /* PTP clock callback */
    NX_PTP_CLIENT_CLOCK_CALLBACK nx_ptp_client_clock_callback;
    VOID                        *nx_ptp_client_clock_callback_data;

    /* The message queue */
    TX_EVENT_FLAGS_GROUP         nx_ptp_client_events;

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* PTP General Messages UDP Socket */
    NX_UDP_SOCKET                nx_ptp_client_general_socket;

    /* PTP Event Messages UDP Socket */
    NX_UDP_SOCKET                nx_ptp_client_event_socket;

    /* Set if IPv4 multicast group has been joined */
    UCHAR                        nx_ptp_client_ipv4_group_joined;

#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    /* Set if IPv6 multicast group has been joined */
    UCHAR                        nx_ptp_client_ipv6_group_joined;

    /* Reserved filed.  */
    UCHAR                        nx_ptp_client_reserved1[2];
#else

    /* Reserved filed.  */
    UCHAR                        nx_ptp_client_reserved1[3];
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    /* PTP Ethernet receive queue */
    NX_PACKET                   *nx_ptp_client_received_packet_head;
    NX_PACKET                   *nx_ptp_client_received_packet_tail;

    /* Link layer receive queue */
    NX_LINK_RECEIVE_QUEUE        nx_ptp_client_link_queue;
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */

    /* The software clock value */
    NX_PTP_TIME                  nx_ptp_client_soft_clock;

    /* The state of the PTP client */
    UCHAR                        nx_ptp_client_state;

    /* The state of the delay measurement */
    UCHAR                        nx_ptp_client_delay_state;

    /* Define supported PTP roles: slave-only, master-only or slave-master. */
    UCHAR                        nx_ptp_client_role;

    /* Reserved filed.  */
    UCHAR                        nx_ptp_client_reserved2;

    /* The current UTC offset flags */
    USHORT                       nx_ptp_client_sync_flags;

    /* The current UTC offset */
    SHORT                        nx_ptp_client_utc_offset;

    /* The address of the master clock */
    NXD_ADDRESS                  nx_ptp_client_master_addr;

    /* The identity of the master clock */
    UCHAR                        nx_ptp_client_master_port_identity[NX_PTP_CLOCK_PORT_IDENTITY_SIZE];

    /* The previous sync master timestamp */
    NX_PTP_TIME                  nx_ptp_client_prev_sync;

    /* The previous sync client timestamp */
    NX_PTP_TIME                  nx_ptp_client_prev_sync_ts;

    /* The current sync master timestamp */
    NX_PTP_TIME                  nx_ptp_client_sync;

    /* The current sync client timestamp */
    NX_PTP_TIME                  nx_ptp_client_sync_ts;

    /* Delay between slave and master */
    NX_PTP_TIME                  nx_ptp_client_delay;

    /* The id of the sync message */
    USHORT                       nx_ptp_client_sync_id;

    /* The id of the last delay_req message */
    USHORT                       nx_ptp_client_delay_req_id;

    /* The delay request interval timer */
    INT                          nx_ptp_client_delay_req_timer;

    /* The Announce timeout */
    INT                          nx_ptp_client_announce_timeout;

    /* The delay request flag */
    UINT                         nx_ptp_client_delay_req_flag;

    /* The delay request client timestamp */
    NX_PTP_TIME                  nx_ptp_client_delay_ts;

    /* The delay request packet pointer */
    NX_PACKET                   *nx_ptp_client_delay_req_packet_ptr;

#if defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC)
    /* The local Sync timestamp */
    NX_PTP_TIME                 nx_ptp_client_sync_ts_local;

    /* The sync packet pointer */
    NX_PACKET                   *nx_ptp_client_sync_packet_ptr;

    /* The sequence ID of Sync */
    USHORT                       nx_ptp_client_sync_sequenceId;
    USHORT                       nx_ptp_client_reserved3;

    /* The sync interval timer */
    INT                         nx_ptp_client_sync_timer;
#endif /* defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC) */

    /* The PTP client timer */
    TX_TIMER                     nx_ptp_client_timer;

    /* The current state of the PTP Client thread */
    UINT                         nx_ptp_client_thread_state;

    /* The PTP client processing thread */
    TX_THREAD                    nx_ptp_client_thread;

#if defined (NX_PTP_ENABLE_MASTER)

    NX_PTP_CLIENT_MASTER         ptp_master;
#endif /* NX_PTP_ENABLE_MASTER */

#if defined(NX_ENABLE_GPTP)

    /* The peer delay request interval timer */
    INT                          nx_ptp_client_pdelay_req_timer;

    /* The current pdelay_req nodeA timestamp (t1) */
    NX_PTP_TIME                  nx_ptp_client_pdelay_req_ts;

    /* The current pdelay_resp from nodeB timestamp (t4) */
    NX_PTP_TIME                  nx_ptp_client_pdelay_resp_ts;

    /* The request receipt timestamp (t2) */
    NX_PTP_TIME                  nx_ptp_client_pdelay_req_receipt_ts;

    /* The response origin timestamp (t3) may not need */
    NX_PTP_TIME                  nx_ptp_client_pdelay_resp_origin_ts;

    /* The request receipt timestamp (t2) used for pdelay_resp */
    NX_PTP_TIME                  nx_ptp_client_pdelay_req_receipt;

    /* The response origin timestamp (t3) used for pdelay_resp_follow_up */
    NX_PTP_TIME                  nx_ptp_client_pdelay_resp_origin;

    /* responder sequenceID from received pdelay_req */
    USHORT                       nx_ptp_client_pdelay_responder_id;

    /* initiator sequence ID to send in pdelay_req */
    USHORT                       nx_ptp_client_pdelay_req_id;

    /* The delay request packet pointer */
    NX_PACKET                   *nx_ptp_client_pdelay_req_packet_ptr;
    
    /* The delay response packet pointer */
    NX_PACKET                   *nx_ptp_client_pdelay_resp_packet_ptr;

    /* The state of the peer delay mechanism in initiator mode */
    UCHAR                        nx_ptp_client_pdelay_initiator_state;

    /* The state of the peer delay mechanism in responder mode */
    UCHAR                        nx_ptp_client_pdelay_responder_state;

    /* PTP Client Port and Identity */
    UCHAR                        nx_ptp_client_request_port_identity[NX_PTP_CLOCK_PORT_IDENTITY_SIZE];
#endif /* NX_ENABLE_GPTP */
} NX_PTP_CLIENT;


#ifndef NX_PTP_SOURCE_CODE

/* Define the system API mappings based on the error checking selected by the user.   */

/* Determine if error checking is desired.  If so, map API functions
   to the appropriate error checking front-ends.  Otherwise, map API
   functions to the core functions that actually perform the work.
   Note: error checking is enabled by default.  */


#ifdef NX_PTP_DISABLE_ERROR_CHECKING

/* Services without error checking.  */

#define nx_ptp_client_create                       _nx_ptp_client_create
#define nx_ptp_client_delete                       _nx_ptp_client_delete
#define nx_ptp_client_start                        _nx_ptp_client_start
#define nx_ptp_client_stop                         _nx_ptp_client_stop
#define nx_ptp_client_time_get                     _nx_ptp_client_time_get
#define nx_ptp_client_time_set                     _nx_ptp_client_time_set
#define nx_ptp_client_master_info_get              _nx_ptp_client_master_info_get
#define nx_ptp_client_sync_info_get                _nx_ptp_client_sync_info_get
#define nx_ptp_client_packet_timestamp_notify      _nx_ptp_client_packet_timestamp_notify
#define nx_ptp_client_soft_clock_callback          _nx_ptp_client_soft_clock_callback
#define nx_ptp_client_utility_time_diff            _nx_ptp_client_utility_time_diff
#define nx_ptp_client_utility_convert_time_to_date _nx_ptp_client_utility_convert_time_to_date

#ifdef NX_PTP_ENABLE_MASTER
#define nx_ptp_client_master_enable                _nx_ptp_client_master_enable
#endif /* NX_PTP_ENABLE_MASTER */

#else

/* Services with error checking.  */

#define nx_ptp_client_create                       _nxe_ptp_client_create
#define nx_ptp_client_delete                       _nxe_ptp_client_delete
#define nx_ptp_client_start                        _nxe_ptp_client_start
#define nx_ptp_client_stop                         _nxe_ptp_client_stop
#define nx_ptp_client_time_get                     _nxe_ptp_client_time_get
#define nx_ptp_client_time_set                     _nxe_ptp_client_time_set
#define nx_ptp_client_master_info_get              _nxe_ptp_client_master_info_get
#define nx_ptp_client_sync_info_get                _nxe_ptp_client_sync_info_get
#define nx_ptp_client_packet_timestamp_notify      _nx_ptp_client_packet_timestamp_notify
#define nx_ptp_client_soft_clock_callback          _nx_ptp_client_soft_clock_callback
#define nx_ptp_client_utility_time_diff            _nxe_ptp_client_utility_time_diff
#define nx_ptp_client_utility_convert_time_to_date _nxe_ptp_client_utility_convert_time_to_date

#ifdef NX_PTP_ENABLE_MASTER
#define nx_ptp_client_master_enable                _nxe_ptp_client_master_enable
#endif /* NX_PTP_ENABLE_MASTER */

#endif

#endif


/* Define the function prototypes of the PTP Client API */

UINT _nx_ptp_client_create(NX_PTP_CLIENT *client_ptr, NX_IP *ip_ptr, UINT interface_index,
                           NX_PACKET_POOL *packet_pool_ptr, UINT thread_priority, UCHAR *thread_stack, UINT stack_size,
                           NX_PTP_CLIENT_CLOCK_CALLBACK clock_callback, VOID *clock_callback_data);
UINT _nx_ptp_client_delete(NX_PTP_CLIENT *client_ptr);
UINT _nx_ptp_client_start(NX_PTP_CLIENT *client_ptr, UCHAR *client_port_identity_ptr, UINT client_port_identity_length,
                          UINT domain, UINT transport_specific, NX_PTP_CLIENT_EVENT_CALLBACK event_callback,
                          VOID *event_callback_data);
UINT _nx_ptp_client_stop(NX_PTP_CLIENT *client_ptr);
UINT _nx_ptp_client_time_get(NX_PTP_CLIENT *client_ptr, NX_PTP_TIME *time_ptr);
UINT _nx_ptp_client_time_set(NX_PTP_CLIENT *client_ptr, NX_PTP_TIME *time_ptr);
UINT _nx_ptp_client_master_info_get(NX_PTP_CLIENT_MASTER *master_ptr, NXD_ADDRESS *address, UCHAR **port_identity,
                                    UINT *port_identity_length, UCHAR *priority1, UCHAR *priority2, UCHAR *clock_class,
                                    UCHAR *clock_accuracy, USHORT *clock_variance, UCHAR **grandmaster_identity,
                                    UINT *grandmaster_identity_length, USHORT *steps_removed, UCHAR *time_source);
UINT _nx_ptp_client_sync_info_get(NX_PTP_CLIENT_SYNC *sync_ptr, USHORT *flags, SHORT *utc_offset);
UINT _nx_ptp_client_utility_time_diff(NX_PTP_TIME *time1_ptr, NX_PTP_TIME *time2_ptr, NX_PTP_TIME *result_ptr);
UINT _nx_ptp_client_utility_time_sum(NX_PTP_TIME *time1_ptr, NX_PTP_TIME *time2_ptr, NX_PTP_TIME *result_ptr);
UINT _nx_ptp_client_utility_convert_time_to_date(NX_PTP_TIME *time_ptr, LONG offset, NX_PTP_DATE_TIME *date_time_ptr);
VOID _nx_ptp_client_packet_timestamp_notify(NX_PTP_CLIENT *client_ptr, NX_PACKET *packet_ptr, NX_PTP_TIME *timestamp_ptr);
UINT _nx_ptp_client_soft_clock_callback(NX_PTP_CLIENT *client_ptr, UINT operation,
                                        NX_PTP_TIME *time_ptr, NX_PACKET *packet_ptr,
                                        VOID *callback_data);
#ifdef NX_PTP_ENABLE_MASTER
UINT _nx_ptp_client_master_enable(NX_PTP_CLIENT *client_ptr, UCHAR role, UCHAR priority1, UCHAR priority2,
                                  UCHAR clock_class, UCHAR clock_accuracy, USHORT clock_variance,
                                  USHORT steps_removed, UCHAR time_source);
#endif /* NX_PTP_ENABLE_MASTER */

UINT _nxe_ptp_client_create(NX_PTP_CLIENT *client_ptr, NX_IP *ip_ptr, UINT interface_index,
                            NX_PACKET_POOL *packet_pool_ptr, UINT thread_priority, UCHAR *thread_stack, UINT stack_size,
                            NX_PTP_CLIENT_CLOCK_CALLBACK clock_callback, VOID *clock_callback_data);
UINT _nxe_ptp_client_delete(NX_PTP_CLIENT *client_ptr);
UINT _nxe_ptp_client_start(NX_PTP_CLIENT *client_ptr, UCHAR *client_port_identity_ptr, UINT client_port_identity_length,
                           UINT domain, UINT transport_specific, NX_PTP_CLIENT_EVENT_CALLBACK event_callback,
                           VOID *event_callback_data);
UINT _nxe_ptp_client_stop(NX_PTP_CLIENT *client_ptr);
UINT _nxe_ptp_client_time_get(NX_PTP_CLIENT *client_ptr, NX_PTP_TIME *time_ptr);
UINT _nxe_ptp_client_time_set(NX_PTP_CLIENT *client_ptr, NX_PTP_TIME *time_ptr);
UINT _nxe_ptp_client_master_info_get(NX_PTP_CLIENT_MASTER *master_ptr, NXD_ADDRESS *address, UCHAR **port_identity,
                                     UINT *port_identity_length, UCHAR *priority1, UCHAR *priority2, UCHAR *clock_class,
                                     UCHAR *clock_accuracy, USHORT *clock_variance, UCHAR **grandmaster_identity,
                                     UINT *grandmaster_identity_length, USHORT *steps_removed, UCHAR *time_source);
UINT _nxe_ptp_client_sync_info_get(NX_PTP_CLIENT_SYNC *sync_ptr, USHORT *flags, SHORT *utc_offset);
UINT _nxe_ptp_client_utility_time_diff(NX_PTP_TIME *time1_ptr, NX_PTP_TIME *time2_ptr, NX_PTP_TIME *result_ptr);
UINT _nxe_ptp_client_utility_time_sum(NX_PTP_TIME *time1_ptr, NX_PTP_TIME *time2_ptr, NX_PTP_TIME *result_ptr);
UINT _nxe_ptp_client_utility_convert_time_to_date(NX_PTP_TIME *time_ptr, LONG offset, NX_PTP_DATE_TIME *date_time_ptr);
#ifdef NX_PTP_ENABLE_MASTER
UINT _nxe_ptp_client_master_enable(NX_PTP_CLIENT *client_ptr, UCHAR role, UCHAR priority1, UCHAR priority2,
                                   UCHAR clock_class, UCHAR clock_accuracy, USHORT clock_variance,
                                   USHORT steps_removed, UCHAR time_source);
#endif /* NX_PTP_ENABLE_MASTER */


/* Define the function prototypes of the private utility functions */

VOID _nx_ptp_client_utility_time_div_by_2(NX_PTP_TIME *time_ptr);
VOID _nx_ptp_client_utility_add64(LONG *a_hi, ULONG *a_lo, LONG b_hi, ULONG b_lo);
VOID _nx_ptp_client_utility_sub64(LONG *a_hi, ULONG *a_lo, LONG b_hi, ULONG b_lo);
VOID _nx_ptp_client_utility_inc64(LONG *a_hi, ULONG *a_lo);
VOID _nx_ptp_client_utility_dec64(LONG *a_hi, ULONG *a_lo);
VOID _nx_ptp_client_utility_neg64(LONG *a_hi, ULONG *a_lo);


/* Determine if a C++ compiler is being used.  If so, complete the standard
   C conditional started above.  */
#ifdef __cplusplus
}
#endif

#endif  /* NX_PTP_CLIENT_H */

