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
/**   Real Time Transport Protocol (RTP)                                  */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  APPLICATION INTERFACE DEFINITION                       RELEASE        */
/*                                                                        */
/*    nx_rtp_sender.h                                     PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file defines the NetX RTP Sender component, including all      */
/*    data types and external references.                                 */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao             Initial Version 6.3.0         */
/*  12-31-2023     Haiqing Zhao             Modified comments(s),         */
/*                                            supported VLAN,             */
/*                                            resulting in version 6.4.0  */
/*                                                                        */
/**************************************************************************/

#ifndef _NX_RTP_SENDER_H_
#define _NX_RTP_SENDER_H_

#include "tx_api.h"
#include "nx_api.h"

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */

#ifdef __cplusplus
/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

#ifdef NX_DISABLE_PACKET_CHAIN
#error "NX_DISABLE_PACKET_CHAIN must not be defined"
#endif /* NX_DISABLE_PACKET_CHAIN */

/* Define UDP socket create options.  */
#ifndef NX_RTP_SENDER_TYPE_OF_SERVICE
#define NX_RTP_SENDER_TYPE_OF_SERVICE                   NX_IP_NORMAL
#endif /* NX_RTP_SENDER_TYPE_OF_SERVICE */

#ifndef NX_RTP_SENDER_FRAGMENT_OPTION
#define NX_RTP_SENDER_FRAGMENT_OPTION                   NX_FRAGMENT_OKAY
#endif /* NX_RTP_SENDER_FRAGMENT_OPTION */

#ifndef NX_RTP_SENDER_TIME_TO_LIVE
#define NX_RTP_SENDER_TIME_TO_LIVE                      0x80
#endif /* NX_RTP_SENDER_TIME_TO_LIVE */

#ifndef NX_RTP_SENDER_QUEUE_DEPTH
#define NX_RTP_SENDER_QUEUE_DEPTH                       5
#endif /* NX_RTP_SENDER_QUEUE_DEPTH */

#ifndef NX_RTP_SENDER_PACKET_TIMEOUT
#define NX_RTP_SENDER_PACKET_TIMEOUT                    (1 * NX_IP_PERIODIC_RATE)
#endif /* NX_RTP_SENDER_PACKET_TIMEOUT */

/* 5 seconds is the recommended minimum interval by RFC 3550, Chapter 6.2. */
#ifndef NX_RTCP_INTERVAL
#define NX_RTCP_INTERVAL                                5
#endif /* NX_RTCP_INTERVAL */

/* RTP Payload Type Table - Reference RFC 3551, Page33-34, Table 4-5 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_PCMU           0       /* G.711 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_GSM            3
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_G723           4
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_DVI4_8000HZ    5
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_DVI4_16000HZ   6
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_LPC            7
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_PCMA           8       /* G.711 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_G722           9
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_L16_2_CHANNELS 10
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_L16_1_CHANNEL  11
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_QCELP          12
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_CN             13
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_MPA            14      /* RFC 2250 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_G728           15
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_DVI4_11025HZ   16
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_DVI4_22050HZ   17
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_G729           18
#define NX_RTP_SENDER_PAYLOAD_TYPE_VIDEO_CELB           25      /* RFC 2029 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_VIDEO_JPEG           26      /* RFC 2435 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_VIDEO_NV             28
#define NX_RTP_SENDER_PAYLOAD_TYPE_VIDEO_H261           31      /* RFC 2032 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_VIDEO_MPV            32      /* RFC 2250 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_AUDIO_VIDEO_MP2T     33      /* RFC 2250 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_VIDEO_H263           34      /* RFC 2190 */
#define NX_RTP_SENDER_PAYLOAD_TYPE_DYNAMIC_MIN          96
#define NX_RTP_SENDER_PAYLOAD_TYPE_DYNAMIC_MAX          127

/* Use the string "RTPS" as a magic number for RTP sender */
#define NX_RTP_SENDER_ID                                0x52545053
#define NX_RTP_SESSION_ID                               0x52545054

/* The initial target rtp port to use - Reference RFC3551, section 8, p35 */
#define NX_RTP_SENDER_INITIAL_RTP_PORT                  5004

/* The rtp header length and corresponding rtp packet header size */
#define NX_RTP_HEADER_LENGTH                            12
#define NX_RTP_PACKET                                   (NX_UDP_PACKET + NX_RTP_HEADER_LENGTH)

/* Define RTP protocol version.  */
#define NX_RTP_VERSION                                  2

/* Define RTP header field(s) */
#define NX_RTP_HEADER_MARKER_BIT                        0x80

/* Define RTCP packet types.  */
#define NX_RTCP_TYPE_SR                                 200
#define NX_RTCP_TYPE_RR                                 201
#define NX_RTCP_TYPE_SDES                               202

/* Define SDES types.  */
#define NX_RTCP_SDES_TYPE_CNAME                         1

/* Define mask for version and padding bit pair. */
#define NX_RTCP_COUNT_MASK                              0x1F
#define NX_RTCP_VERSION_MASK                            0xC0
#define NX_RTCP_PAD_MASK                                0x20
#define NX_RTCP_TYPE_MASK                               0xFE
#define NX_RTCP_VERSION_VALUE                           (NX_RTP_VERSION << 6)
#define NX_RTCP_PAD_VALUE                               0

/* Define receiver report structure for user callback. */
typedef struct NX_RTCP_RECEIVER_REPORT_STRUCT
{
    UINT receiver_ssrc;
    UINT fraction_loss;
    INT  packet_loss;
    UINT extended_max;
    UINT jitter;
    UINT last_sr;
    UINT delay;
} NX_RTCP_RECEIVER_REPORT;

/* Define SDES information structure for user callback. */
typedef struct NX_RTCP_SDES_INFO_STRUCT
{
    UINT   ssrc;
    UCHAR *cname;
    ULONG  cname_length;
} NX_RTCP_SDES_INFO;

/* Define RTCP packet header structure for internal packet processing.  */
typedef struct NX_RTCP_HEADER_STRUCT
{
    /* V(2), P(1), RC(5). */
    UCHAR nx_rtcp_byte0;

    /* RTCP packet type. */
    UCHAR nx_rtcp_packet_type;

    /* Packet length in words. */
    USHORT nx_rtcp_length;
} NX_RTCP_HEADER;

/* Define RTCP report block structure for internal packet processing. */
typedef struct NX_RTCP_REPORT_STRUCT
{

    /* Data source being reported. */
    ULONG nx_rtcp_report_ssrc;

    /* Fraction loss + cumulative number of packets lost. */
    ULONG nx_rtcp_report_loss;

    /* Extended hightest sequence number received. */
    ULONG nx_rtcp_report_extended_max;

    /* Data packet inter-arrival time. */
    ULONG nx_rtcp_report_jitter;

    /* The middle 32 bits out of 64 in the NTP timestamp. */
    ULONG nx_rtcp_report_last_sr;

    /* Delay since last SR timestamp. */
    ULONG nx_rtcp_report_delay;
} NX_RTCP_REPORT;

/* Define RTCP RR block for internal packet processing. */
typedef struct NX_RTCP_RR_STRUCT
{
    /* Packet header. */
    NX_RTCP_HEADER nx_rtcp_rr_header;

    /* RTCP packet type. */
    ULONG nx_rtcp_rr_ssrc;

    /* Reception report block. */
    NX_RTCP_REPORT nx_rtcp_rr_report;
} NX_RTCP_RR;

/* Define RTCP SR structure for internal packet processing. */
typedef struct NX_RTCP_SR_STRUCT
{
    NX_RTCP_HEADER nx_rtcp_sr_header;
    ULONG          nx_rtcp_sr_ssrc;
    ULONG          nx_rtcp_sr_ntp_timestamp_msw;
    ULONG          nx_rtcp_sr_ntp_timestamp_lsw;
    ULONG          nx_rtcp_sr_rtp_timestamp;
    ULONG          nx_rtcp_sr_rtp_packet_count;
    ULONG          nx_rtcp_sr_rtp_octet_count;
} NX_RTCP_SR;

/* Define RTCP SDES item structure for internal packet processing. */
typedef struct NX_RTCP_SDES_ITEM_STRUCT
{
    UCHAR nx_rtcp_sdes_type; /* Chunk type. */
    UCHAR nx_rtcp_sdes_length;
    UCHAR nx_rtcp_sdes_data[1];
} NX_RTCP_SDES_ITEM;

/* Define RTCP SDES chunk structure for internal packet processing. */
typedef struct NX_RTCP_SDES_CHUNK_STRUCT
{
    ULONG             nx_rtcp_sdes_ssrc;
    NX_RTCP_SDES_ITEM nx_rtcp_sdes_item[1];
} NX_RTCP_SDES_CHUNK;

typedef struct NX_RTP_SESSION_STRUCT NX_RTP_SESSION;

typedef struct NX_RTP_SENDER_STRUCT
{

    /* Store the magic number for RTP sender service */
    ULONG           nx_rtp_sender_id;

    /* Pointer to IP structure of the corresponding IP instance. */
    NX_IP          *nx_rtp_sender_ip_ptr;

    /* Pointer to RTP sender packet pool   */
    NX_PACKET_POOL *nx_rtp_sender_packet_pool_ptr;

    /* Mutex to protect critical section such as sequence number and so on */
    TX_MUTEX        nx_rtp_sender_protection;

    /* Local RTP/RTCP port & socket */
    USHORT          nx_rtp_sender_rtp_port;
    USHORT          nx_rtp_sender_rtcp_port;
    NX_UDP_SOCKET   nx_rtp_sender_rtp_socket;
    NX_UDP_SOCKET   nx_rtp_sender_rtcp_socket;

    /* Callback function to process rtcp messages. */
    UINT          (*nx_rtp_sender_rtcp_receiver_report_cb)(NX_RTP_SESSION *rtp_session, NX_RTCP_RECEIVER_REPORT *rtcp_receiver_report);
    UINT          (*nx_rtp_sender_rtcp_sdes_cb)(NX_RTCP_SDES_INFO *sdes_info);

    /* RTP sender name */
    CHAR           *nx_rtp_sender_cname;
    UCHAR           nx_rtp_sender_cname_length;

    NX_RTP_SESSION *nx_rtp_sender_session_created_ptr;
} NX_RTP_SENDER;

struct NX_RTP_SESSION_STRUCT
{

    /* Store the pointer for the corresponding rtp sender */
    NX_RTP_SENDER                *nx_rtp_sender;

    /* Store the magic number for the specific RTP session */
    ULONG                         nx_rtp_session_id;

    /* Store the ip interface index when session created. */
    UINT                          nx_rtp_session_interface_index;


    /* Store the vlan priority for the rtp packets transferred in the session */
    UINT                          nx_rtp_session_vlan_priority;

    /* Receiver's IP address and port number */
    NXD_ADDRESS                   nx_rtp_session_peer_ip_address;
    USHORT                        nx_rtp_session_peer_rtp_port;
    USHORT                        nx_rtp_session_peer_rtcp_port;

    /* RTP header */
    UCHAR                         nx_rtp_session_reserved;         /* Alignment */
    UCHAR                         nx_rtp_session_payload_type;     /* Type, to be programmed into payload type field in RTP header */
    USHORT                        nx_rtp_session_sequence_number;  /* Session sequence number */
    ULONG                         nx_rtp_session_ssrc;

    /* The maximum frame packet size computed corresponding to mtu. */
    ULONG                         nx_rtp_session_max_packet_size;

    /* None zero value: sample-based encoding
       Default zero value: frame-based encoding */
    ULONG                         nx_rtp_session_sample_factor;

    /* RTCP statistics */

    /* The total number of RTP data packets transmitted by the sender. */
    ULONG                         nx_rtp_session_packet_count;

    /* The total number of payload octets transmitted by the sender. */
    ULONG                         nx_rtp_session_octet_count;

    /* The timestamp of last sent RTP packet. */
    ULONG                         nx_rtp_session_rtp_timestamp;

    /* The most significant word of the NTP timestamp corresponds to the same time as the RTP timestamp. */
    ULONG                         nx_rtp_session_ntp_timestamp_msw;

    /* The least significant word of the NTP timestamp corresponds to the same time as the RTP timestamp. */
    ULONG                         nx_rtp_session_ntp_timestamp_lsw;

    /* The last time an RTCP packet was transmitted. */
    ULONG                         nx_rtp_session_rtcp_time;

    struct NX_RTP_SESSION_STRUCT *nx_rtp_session_next;
};

typedef struct NX_RTP_HEADER_STRUCT
{
    UCHAR  nx_rtp_header_field0;
    UCHAR  nx_rtp_header_field1;
    USHORT nx_rtp_header_sequence_number;
    ULONG  nx_rtp_header_timestamp;
    ULONG  nx_rtp_header_ssrc;
} NX_RTP_HEADER;


#ifndef NX_RTP_SENDER_SOURCE_CODE

/* Application caller is present, perform API mapping.  */

/* Determine if error checking is desired.  If so, map API functions
   to the appropriate error checking front-ends.  Otherwise, map API
   functions to the core functions that actually perform the work.
   Note: error checking is enabled by default.  */
#ifdef NX_DISABLE_ERROR_CHECKING

/* Services without error checking.  */
#define nx_rtp_sender_create                            _nx_rtp_sender_create
#define nx_rtp_sender_delete                            _nx_rtp_sender_delete
#define nx_rtp_sender_port_get                          _nx_rtp_sender_port_get
#define nx_rtp_sender_session_create                    _nx_rtp_sender_session_create
#define nx_rtp_sender_session_delete                    _nx_rtp_sender_session_delete
#define nx_rtp_sender_session_sample_factor_set         _nx_rtp_sender_session_sample_factor_set
#define nx_rtp_sender_session_packet_allocate           _nx_rtp_sender_session_packet_allocate
#define nx_rtp_sender_session_packet_send               _nx_rtp_sender_session_packet_send
#define nx_rtp_sender_session_jpeg_send                 _nx_rtp_sender_session_jpeg_send
#define nx_rtp_sender_session_h264_send                 _nx_rtp_sender_session_h264_send
#define nx_rtp_sender_session_aac_send                  _nx_rtp_sender_session_aac_send
#define nx_rtp_sender_session_sequence_number_get       _nx_rtp_sender_session_sequence_number_get
#define nx_rtp_sender_session_ssrc_get                  _nx_rtp_sender_session_ssrc_get
#define nx_rtp_sender_session_vlan_priority_set         _nx_rtp_sender_session_vlan_priority_set

#define nx_rtp_sender_rtcp_receiver_report_callback_set _nx_rtp_sender_rtcp_receiver_report_callback_set
#define nx_rtp_sender_rtcp_sdes_callback_set            _nx_rtp_sender_rtcp_sdes_callback_set

#else

/* Services with error checking.  */
#define nx_rtp_sender_create                            _nxe_rtp_sender_create
#define nx_rtp_sender_delete                            _nxe_rtp_sender_delete
#define nx_rtp_sender_port_get                          _nxe_rtp_sender_port_get
#define nx_rtp_sender_session_create                    _nxe_rtp_sender_session_create
#define nx_rtp_sender_session_delete                    _nxe_rtp_sender_session_delete
#define nx_rtp_sender_session_sample_factor_set         _nxe_rtp_sender_session_sample_factor_set
#define nx_rtp_sender_session_packet_allocate           _nxe_rtp_sender_session_packet_allocate
#define nx_rtp_sender_session_packet_send               _nxe_rtp_sender_session_packet_send
#define nx_rtp_sender_session_jpeg_send                 _nxe_rtp_sender_session_jpeg_send
#define nx_rtp_sender_session_h264_send                 _nxe_rtp_sender_session_h264_send
#define nx_rtp_sender_session_aac_send                  _nxe_rtp_sender_session_aac_send
#define nx_rtp_sender_session_sequence_number_get       _nxe_rtp_sender_session_sequence_number_get
#define nx_rtp_sender_session_ssrc_get                  _nxe_rtp_sender_session_ssrc_get
#define nx_rtp_sender_session_vlan_priority_set         _nxe_rtp_sender_session_vlan_priority_set

#define nx_rtp_sender_rtcp_receiver_report_callback_set _nxe_rtp_sender_rtcp_receiver_report_callback_set
#define nx_rtp_sender_rtcp_sdes_callback_set            _nxe_rtp_sender_rtcp_sdes_callback_set

#endif /* NX_DISABLE_ERROR_CHECKING */

/* Define the prototypes accessible to the application software.  */

/* Initiate RTP sender service, create UDP sockets. */
UINT nx_rtp_sender_create(NX_RTP_SENDER *rtp_sender, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, CHAR *cname, UCHAR cname_length);

/* Terminate the RTP service */
UINT nx_rtp_sender_delete(NX_RTP_SENDER *rtp_sender);

/* Obtain RTP/RTCP port numbers.  The port numbers may be used by RTSP */
UINT nx_rtp_sender_port_get(NX_RTP_SENDER *rtp_sender, UINT *rtp_port, UINT *rtcp_port);

/* Setup a session, find and bind to available ports. */
UINT nx_rtp_sender_session_create(NX_RTP_SENDER *rtp_sender, NX_RTP_SESSION *session, ULONG payload_type,
                                  UINT interface_index, NXD_ADDRESS *receiver_ip_address,
                                  UINT receiver_rtp_port_number, UINT receiver_rtcp_port_number);

/* Delete a session, and then it is available to re-setup the session */
UINT nx_rtp_sender_session_delete(NX_RTP_SESSION *session);

/* Set the sample factor for sample-based mode inside the specific session. */
UINT nx_rtp_sender_session_sample_factor_set(NX_RTP_SESSION *session, UINT factor);

/* Allocate and obtain a rtp session packet. */
UINT nx_rtp_sender_session_packet_allocate(NX_RTP_SESSION *session, NX_PACKET **packet_ptr, ULONG wait_option);

/* Send payload data through a specific session. */
UINT nx_rtp_sender_session_packet_send(NX_RTP_SESSION *session, NX_PACKET *packet_ptr, ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);

/* API functions for sending video payload over rtp. */
UINT nx_rtp_sender_session_jpeg_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                     ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);
UINT nx_rtp_sender_session_h264_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                     ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);

/* API functions for sending audio payload over rtp. */
UINT nx_rtp_sender_session_aac_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size, ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);

/* Obtain the current sequence number inside the specific session. */
UINT nx_rtp_sender_session_sequence_number_get(NX_RTP_SESSION *session, UINT *sequence_number);

/* Obtain the current ssrc inside the specific session. */
UINT nx_rtp_sender_session_ssrc_get(NX_RTP_SESSION *session, ULONG *ssrc);

/* Set the vlan priority inside the specific session. */
UINT nx_rtp_sender_session_vlan_priority_set(NX_RTP_SESSION *session, UINT vlan_priority);

/* Set a callback function to handle incoming RTCP message. */
UINT nx_rtp_sender_rtcp_receiver_report_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_rr_cb)(NX_RTP_SESSION *, NX_RTCP_RECEIVER_REPORT *));
UINT nx_rtp_sender_rtcp_sdes_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_sdes_cb)(NX_RTCP_SDES_INFO *));

/* Set VLAN priority of RTP session. */
UINT nx_rtp_sender_session_vlan_priority_set(NX_RTP_SESSION *session, UINT vlan_priority);

#else

/* Define the prototypes accessible to the application software.  */

UINT _nxe_rtp_sender_create(NX_RTP_SENDER *rtp_sender, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, CHAR *cname, UCHAR cname_length);
UINT _nx_rtp_sender_create(NX_RTP_SENDER *rtp_sender, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, CHAR *cname, UCHAR cname_length);
UINT _nxe_rtp_sender_delete(NX_RTP_SENDER *rtp_sender);
UINT _nx_rtp_sender_delete(NX_RTP_SENDER *rtp_sender);
UINT _nxe_rtp_sender_port_get(NX_RTP_SENDER *rtp_sender, UINT *rtp_port, UINT *rtcp_port);
UINT _nx_rtp_sender_port_get(NX_RTP_SENDER *rtp_sender, UINT *rtp_port, UINT *rtcp_port);
UINT _nxe_rtp_sender_session_create(NX_RTP_SENDER *rtp_sender, NX_RTP_SESSION *session, ULONG payload_type,
                                    UINT interface_index, NXD_ADDRESS *receiver_ip_address,
                                    UINT receiver_rtp_port_number, UINT receiver_rtcp_port_number);
UINT _nx_rtp_sender_session_create(NX_RTP_SENDER *rtp_sender, NX_RTP_SESSION *session, ULONG payload_type,
                                   UINT interface_index, NXD_ADDRESS *receiver_ip_address,
                                   UINT receiver_rtp_port_number, UINT receiver_rtcp_port_number);
UINT _nxe_rtp_sender_session_delete(NX_RTP_SESSION *session);
UINT _nx_rtp_sender_session_delete(NX_RTP_SESSION *session);
UINT _nxe_rtp_sender_session_sample_factor_set(NX_RTP_SESSION *session, UINT factor);
UINT _nx_rtp_sender_session_sample_factor_set(NX_RTP_SESSION *session, UINT factor);
UINT _nxe_rtp_sender_session_packet_allocate(NX_RTP_SESSION *session, NX_PACKET **packet_ptr, ULONG wait_option);
UINT _nx_rtp_sender_session_packet_allocate(NX_RTP_SESSION *session, NX_PACKET **packet_ptr, ULONG wait_option);
UINT _nxe_rtp_sender_session_packet_send(NX_RTP_SESSION *session, NX_PACKET *packet_ptr, ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);
UINT _nx_rtp_sender_session_packet_send(NX_RTP_SESSION *session, NX_PACKET *packet_ptr, ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);
UINT _nxe_rtp_sender_session_sequence_number_get(NX_RTP_SESSION *session, UINT *sequence_number);
UINT _nx_rtp_sender_session_sequence_number_get(NX_RTP_SESSION *session, UINT *sequence_number);
UINT _nxe_rtp_sender_session_jpeg_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                       ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);
UINT _nx_rtp_sender_session_jpeg_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                       ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);
UINT _nxe_rtp_sender_session_h264_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                       ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);
UINT _nx_rtp_sender_session_h264_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                      ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);
UINT _nxe_rtp_sender_session_aac_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                      ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);
UINT _nx_rtp_sender_session_aac_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                     ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker);
UINT _nxe_rtp_sender_session_ssrc_get(NX_RTP_SESSION *session, ULONG *ssrc);
UINT _nx_rtp_sender_session_ssrc_get(NX_RTP_SESSION *session, ULONG *ssrc);
UINT _nxe_rtp_sender_session_vlan_priority_set(NX_RTP_SESSION *session, UINT vlan_priority);
UINT _nx_rtp_sender_session_vlan_priority_set(NX_RTP_SESSION *session, UINT vlan_priority);

UINT _nxe_rtp_sender_rtcp_receiver_report_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_rr_cb)(NX_RTP_SESSION *, NX_RTCP_RECEIVER_REPORT *));
UINT _nx_rtp_sender_rtcp_receiver_report_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_rr_cb)(NX_RTP_SESSION *, NX_RTCP_RECEIVER_REPORT *));
UINT _nxe_rtp_sender_rtcp_sdes_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_sdes_cb)(NX_RTCP_SDES_INFO *));
UINT _nx_rtp_sender_rtcp_sdes_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_sdes_cb)(NX_RTCP_SDES_INFO *));

#endif /* NX_RTP_SENDER_SOURCE_CODE */

/* Determine if a C++ compiler is being used.  If so, complete the standard
   C conditional started above.  */
#ifdef __cplusplus
}
#endif

#endif /* _NX_RTP_SENDER_H_ */

