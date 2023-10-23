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
/**   Real Time Streaming Protocol (RTSP)                                 */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  APPLICATION INTERFACE DEFINITION                       RELEASE        */
/*                                                                        */
/*    nx_rtsp_server.h                                    PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file defines the NetX RTSP Server component, including all     */
/*    data types and external references.                                 */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/

#ifndef NX_RTSP_SERVER_H
#define NX_RTSP_SERVER_H

#include "tx_api.h"
#include "nx_api.h"

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */

#ifdef __cplusplus
/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

/* Define the RTSP Server ID.  */
#define NX_RTSP_SERVER_ID                                       0x52545350UL

/* Define the RTSP protocol version of the RTSP Server.  */
#define NX_RTSP_VERSION_STRING                                  "RTSP/1.0"

/* Define the RTSP SDP content type.  */
#define NX_RTSP_SERVER_CONTENT_TYPE_SDP                         "application/sdp"

/* Define the RTSP status code.  */
#define NX_RTSP_STATUS_CODE_OK                                  200
#define NX_RTSP_STATUS_CODE_CREATED                             201
#define NX_RTSP_STATUS_CODE_LOW_ON_STORAGE_SPACE                250
#define NX_RTSP_STATUS_CODE_MULTIPLE_CHOICES                    300
#define NX_RTSP_STATUS_CODE_MOVED_PERMANENTLY                   301
#define NX_RTSP_STATUS_CODE_MOVED_TEMPORARILY                   302
#define NX_RTSP_STATUS_CODE_SEE_OTHER                           303
#define NX_RTSP_STATUS_CODE_NOT_MODIFIED                        304
#define NX_RTSP_STATUS_CODE_USE_PROXY                           305
#define NX_RTSP_STATUS_CODE_GOING_AWAY                          350
#define NX_RTSP_STATUS_CODE_LOAD_BALANCING                      351
#define NX_RTSP_STATUS_CODE_BAD_REQUEST                         400
#define NX_RTSP_STATUS_CODE_UNAUTHORIZED                        401
#define NX_RTSP_STATUS_CODE_PAYMENT_REQUIRED                    402
#define NX_RTSP_STATUS_CODE_FORBIDDEN                           403
#define NX_RTSP_STATUS_CODE_NOT_FOUND                           404
#define NX_RTSP_STATUS_CODE_METHOD_NOT_ALLOWED                  405
#define NX_RTSP_STATUS_CODE_NOT_ACCEPTABLE                      406
#define NX_RTSP_STATUS_CODE_PROXY_AUTHENTICATION_REQUIRED       407
#define NX_RTSP_STATUS_CODE_REQUEST_TIMEOUT                     408
#define NX_RTSP_STATUS_CODE_GONE                                410
#define NX_RTSP_STATUS_CODE_LENGTH_REQUIRED                     411
#define NX_RTSP_STATUS_CODE_PRECONDITION_FAILED                 412
#define NX_RTSP_STATUS_CODE_REQUEST_ENTITY_TOO_LARGE            413
#define NX_RTSP_STATUS_CODE_REQUESTURI_TOO_LARGE                414
#define NX_RTSP_STATUS_CODE_UNSUPPORTED_MEDIA_TYPE              415
#define NX_RTSP_STATUS_CODE_PARAMETER_NOT_UNDERSTOOD            451
#define NX_RTSP_STATUS_CODE_RESERVED                            452
#define NX_RTSP_STATUS_CODE_NOT_ENOUGH_BANDWIDTH                453
#define NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND                   454
#define NX_RTSP_STATUS_CODE_METHOD_NOT_VALID_IN_THIS_STATE      455
#define NX_RTSP_STATUS_CODE_HEADER_FIELD_NOT_VALID_FOR_RESOURCE 456
#define NX_RTSP_STATUS_CODE_INVALID_RANGE                       457
#define NX_RTSP_STATUS_CODE_PARAMETER_IS_READONLY               458
#define NX_RTSP_STATUS_CODE_AGGREGATE_OPERATION_NOT_ALLOWED     459
#define NX_RTSP_STATUS_CODE_ONLY_AGGREGATE_OPERATION_ALLOWED    460
#define NX_RTSP_STATUS_CODE_UNSUPPORTED_TRANSPORT               461
#define NX_RTSP_STATUS_CODE_DESTINATION_UNREACHABLE             462
#define NX_RTSP_STATUS_CODE_INTERNAL_SERVER_ERROR               500
#define NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED                     501
#define NX_RTSP_STATUS_CODE_BAD_GATEWAY                         502
#define NX_RTSP_STATUS_CODE_SERVICE_UNAVAILABLE                 503
#define NX_RTSP_STATUS_CODE_GATEWAY_TIMEOUT                     504
#define NX_RTSP_STATUS_CODE_RTSP_VERSION_NOT_SUPPORTED          505
#define NX_RTSP_STATUS_CODE_OPTION_NOT_SUPPORTED                551

/* Define the RTSP Server error code.  */
#define NX_RTSP_SERVER_ALREADY_STARTED                          0x7000
#define NX_RTSP_SERVER_NOT_STARTED                              0x7001
#define NX_RTSP_SERVER_INTERNAL_ERROR                           0x7002
#define NX_RTSP_SERVER_NO_PACKET                                0x7003
#define NX_RTSP_SERVER_NOT_IMPLEMENTED                          0x7004
#define NX_RTSP_SERVER_MISSING_REQUIRED_CALLBACKS               0x7005
#define NX_RTSP_SERVER_INVALID_REQUEST                          0x7006
#define NX_RTSP_SERVER_INVALID_PARAMETER                        0x7007
#define NX_RTSP_SERVER_UNSUPPORTED                              0x7008
#define NX_RTSP_SERVER_FAILED                                   0x7009

/* Define the max number of concurrent Clients the Server supports.  */
#ifndef NX_RTSP_SERVER_MAX_CLIENTS
#define NX_RTSP_SERVER_MAX_CLIENTS                              2
#endif /* NX_RTSP_SERVER_MAX_CLIENTS */

/* Define the RTSP Server time slice.  */
#ifndef NX_RTSP_SERVER_TIME_SLICE
#define NX_RTSP_SERVER_TIME_SLICE                               TX_NO_TIME_SLICE
#endif /* NX_RTSP_SERVER_TIME_SLICE */

/* Define the timeout for the packet allocation and data appending.  */
#ifndef NX_RTSP_SERVER_PACKET_TIMEOUT
#define NX_RTSP_SERVER_PACKET_TIMEOUT                           (1 * NX_IP_PERIODIC_RATE)
#endif /* NX_RTSP_SERVER_PACKET_TIMEOUT */

/* Define the timeout for the RTSP Server socket accepting.  */
#ifndef NX_RTSP_SERVER_ACCEPT_TIMEOUT
#define NX_RTSP_SERVER_ACCEPT_TIMEOUT                           (10 * NX_IP_PERIODIC_RATE)
#endif /* NX_RTSP_SERVER_ACCEPT_TIMEOUT */

/* Define the timeout for the packet sending.  */
#ifndef NX_RTSP_SERVER_SEND_TIMEOUT
#define NX_RTSP_SERVER_SEND_TIMEOUT                             (1 * NX_IP_PERIODIC_RATE)
#endif /* NX_RTSP_SERVER_SEND_TIMEOUT */

/* Define the timeout in seconds for Client activity.  */
#ifndef NX_RTSP_SERVER_ACTIVITY_TIMEOUT
#define NX_RTSP_SERVER_ACTIVITY_TIMEOUT                         60
#endif /* NX_RTSP_SERVER_ACTIVITY_TIMEOUT */

/* Define the type of service.  */
#ifndef NX_RTSP_SERVER_TYPE_OF_SERVICE
#define NX_RTSP_SERVER_TYPE_OF_SERVICE                          NX_IP_NORMAL
#endif /* NX_RTSP_SERVER_TYPE_OF_SERVICE */

/* Define the fragment option.  */
#ifndef NX_RTSP_SERVER_FRAGMENT_OPTION
#define NX_RTSP_SERVER_FRAGMENT_OPTION                          NX_FRAGMENT_OKAY
#endif /* NX_RTSP_SERVER_FRAGMENT_OPTION */

/* Define the TTL.  */
#ifndef NX_RTSP_SERVER_TIME_TO_LIVE
#define NX_RTSP_SERVER_TIME_TO_LIVE                             NX_IP_TIME_TO_LIVE
#endif /* NX_RTSP_SERVER_TIME_TO_LIVE */

/* Define the window size.  */
#ifndef NX_RTSP_SERVER_WINDOW_SIZE
#define NX_RTSP_SERVER_WINDOW_SIZE                              8192
#endif /* NX_RTSP_SERVER_WINDOW_SIZE */

/* Define the RTSP Server events.  */
#define NX_RTSP_SERVER_ALL_EVENTS                               0xFFFFFFFF
#define NX_RTSP_SERVER_CONNECT_EVENT                            0x00000001
#define NX_RTSP_SERVER_DISCONNECT_EVENT                         0x00000002
#define NX_RTSP_SERVER_REQUEST_EVENT                            0x00000004
#define NX_RTSP_SERVER_TIMEOUT_EVENT                            0x00000008

/* Define the RTSP state.  */
#define NX_RTSP_STATE_INIT                                      1
#define NX_RTSP_STATE_READY                                     2
#define NX_RTSP_STATE_PLAYING                                   3

/* Define the transport type.  */
#define NX_RTSP_TRANSPORT_TYPE_UDP                              0x00
#define NX_RTSP_TRANSPORT_TYPE_TCP                              0x01

/* There are several modes of transport, see https://www.rfc-editor.org/rfc/rfc2326#section-1.6
   1. unicast.
   2. multicast, Server chooses address.
   3. multicast, Client chooses address.  */
#define NX_RTSP_TRANSPORT_MODE_UNICAST                          0x00
#define NX_RTSP_TRANSPORT_MODE_MULTICAST_SERVER                 0x01
#define NX_RTSP_TRANSPORT_MODE_MULTICAST_CLIENT                 0x02

/* Define Server capabilities.  */
#define NX_RTSP_METHOD_OPTIONS                                  0x00
#define NX_RTSP_METHOD_DESCRIBE                                 0x01
#define NX_RTSP_METHOD_SETUP                                    0x02
#define NX_RTSP_METHOD_PLAY                                     0x03
#define NX_RTSP_METHOD_PAUSE                                    0x04
#define NX_RTSP_METHOD_TEARDOWN                                 0x05
#define NX_RTSP_METHOD_SET_PARAMETER                            0x06
#define NX_RTSP_METHOD_NOT_SUPPORT                              0xFF

/* Define the transport structure.  */
typedef struct NX_RTSP_TRANSPORT_STRUCT
{
    UCHAR       transport_type;    /* UDP or TCP.  */

    UCHAR       transport_mode;    /* Unicast or multicast(Server or Client chooses address).  */

    USHORT      multicast_ttl;     /* TTL for multicast.  */

    ULONG       rtp_ssrc;          /* RTP SSRC.  */

    USHORT      client_rtp_port;   /* Client RTP port.  */

    USHORT      client_rtcp_port;  /* Client RTCP port.  */

    USHORT      server_rtp_port;   /* Server RTP port.  */

    USHORT      server_rtcp_port;  /* Server RTCP port.  */

    NXD_ADDRESS client_ip_address; /* Client IP address.  */

    NXD_ADDRESS server_ip_address; /* Server IP address.  */

    UINT        interface_index;   /* IP interface index.  */
} NX_RTSP_TRANSPORT;

/* Define the response status code and description.  */
typedef struct NX_RTSP_RESPONSE_STRCUT
{
    UINT  nx_rtsp_response_code;        /* The value of the response status code.  */

    CHAR *nx_rtsp_response_description; /* The description of the response status code.  */
} NX_RTSP_RESPONSE;

/* Define the Client request structure.  */
typedef struct NX_RTSP_CLIENT_REQUEST_STRUCT
{
    UINT              nx_rtsp_client_request_method;                 /* OPTION/SETUP/DESCRIBE/PLAY/PAUSE/TEARDOWN/SET_PARAMETER.  */

    UINT              nx_rtsp_client_request_sequence_number;        /* Current Client sequence number.  */

    UCHAR            *nx_rtsp_client_request_uri_ptr;                /* Request URI name.  */
    UINT              nx_rtsp_client_request_uri_length;             /* Request URI length.  */

    UCHAR            *nx_rtsp_client_request_range_ptr;              /* Range field, needed for holding the PLAY and PAUSE method.  */
    UINT              nx_rtsp_client_request_range_length;           /* Range field length.  */

    ULONG             nx_rtsp_client_request_session_id;             /* Session id for request method.  */

    UINT              nx_rtsp_client_request_response_code;          /* Response status code.  */

    NX_RTSP_TRANSPORT nx_rtsp_client_request_transport;              /* Transport structure.  */
} NX_RTSP_CLIENT_REQUEST;

/* Define the Client data structure.  */
typedef struct NX_RTSP_CLIENT_STRUCT
{
    UCHAR                         nx_rtsp_client_valid;                    /* This entry is valid or not.  */

    UCHAR                         nx_rtsp_client_state;                    /* The state a Client is in: INIT/READY/PLAYING. See page 77 RFC 2326.  */

    UCHAR                         nx_rtsp_client_reserved[2];              /* Reserved.  */

    NX_TCP_SOCKET                 nx_rtsp_client_socket;                   /* The socket for incoming request.  */

    ULONG                         nx_rtsp_client_request_activity_timeout; /* Timeout for Client activity.  */

    ULONG                         nx_rtsp_client_session_id;               /* Session ID, assigned by RTSP, in host byte order.  */

    struct NX_RTSP_SERVER_STRUCT *nx_rtsp_client_server_ptr;               /* Pointer to the RTSP Server.  */

    NX_RTSP_CLIENT_REQUEST       *nx_rtsp_client_request_ptr;              /* Pointer to the current Client request.  */

    NX_RTSP_CLIENT_REQUEST        nx_rtsp_client_request;                  /* The stored client request. */

    NX_PACKET                    *nx_rtsp_client_request_packet;           /* The request packet received from Client.  */

    UINT                          nx_rtsp_client_request_bytes_total;      /* The total bytes of the request.  */

    UINT                          nx_rtsp_client_request_content_length;   /* The content length of the request.  */

    NX_PACKET                    *nx_rtsp_client_response_packet;          /* The response packet will be send to Client.  */

    UINT                          nx_rtsp_client_npt_start;                /* The start time in milliseconds of the NPT.  */
    UINT                          nx_rtsp_client_npt_end;                  /* The end time in milliseconds of the NPT.  */
} NX_RTSP_CLIENT;

/* Define the method callbacks structure.  */
typedef struct NX_RTSP_SERVER_METHOD_CALLBACKS_STRUCT
{
    UINT (*nx_rtsp_server_method_describe_callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);

    UINT (*nx_rtsp_server_method_setup_callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr);

    UINT (*nx_rtsp_server_method_play_callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);

    UINT (*nx_rtsp_server_method_teardown_callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);

    UINT (*nx_rtsp_server_method_pause_callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);

    UINT (*nx_rtsp_server_method_set_parameter_callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length);
} NX_RTSP_SERVER_METHOD_CALLBACKS;

/* Define the Server structure.  */
typedef struct NX_RTSP_SERVER_STRUCT
{
    ULONG                    nx_rtsp_server_id;                 /* The ID of RTSP Server.  */

    CHAR                    *nx_rtsp_server_name;               /* The name of RTSP Server.  */

    UINT                     nx_rtsp_server_name_length;        /* The length of RTSP Server's name.  */

    TX_THREAD                nx_rtsp_server_thread;             /* RTSP Server thread.  */

    TX_TIMER                 nx_rtsp_server_timer;              /* Timer for Client activity.  */

    TX_EVENT_FLAGS_GROUP     nx_rtsp_server_event_flags;        /* Event flags.  */

    NX_IP                   *nx_rtsp_server_ip_ptr;             /* Pointer to the IP instance.  */

    USHORT                   nx_rtsp_server_port;               /* RTSP Server port.  */

    UCHAR                    nx_rtsp_server_started;            /* The RTSP Server is started or not.  */

    UCHAR                    nx_rtsp_server_reserved;           /* Reserved.  */

    NX_PACKET_POOL          *nx_rtsp_server_packet_pool;        /* Packet Pool for packet allocation.  */

    /* Infos recorded in RTSP Server procedures.  */
    ULONG                    nx_rtsp_server_allocation_errors;
    ULONG                    nx_rtsp_server_relisten_errors;
    ULONG                    nx_rtsp_server_disconnection_requests;
    UINT                     nx_rtsp_server_connected_client_count;

    /* Data structure for all the Clients connected to the RTSP Server.  */
    NX_RTSP_CLIENT           nx_rtsp_server_client_list[NX_RTSP_SERVER_MAX_CLIENTS];

    /* The callbacks for the received methods and disconnection.  */
    UINT                     (*nx_rtsp_server_disconnect_callback)(NX_RTSP_CLIENT *rtsp_client_ptr);
    NX_RTSP_SERVER_METHOD_CALLBACKS nx_rtsp_server_method_callbacks;
} NX_RTSP_SERVER;

#ifndef NX_RTSP_SERVER_SOURCE_CODE

/* Application caller is present, perform API mapping.  */

/* Determine if error checking is desired.  If so, map API functions
   to the appropriate error checking front-ends.  Otherwise, map API
   functions to the core functions that actually perform the work.
   Note: error checking is enabled by default.  */
#ifdef NX_DISABLE_ERROR_CHECKING

/* Services without error checking.  */
#define nx_rtsp_server_create                        _nx_rtsp_server_create
#define nx_rtsp_server_delete                        _nx_rtsp_server_delete
#define nx_rtsp_server_start                         _nx_rtsp_server_start
#define nx_rtsp_server_stop                          _nx_rtsp_server_stop

#define nx_rtsp_server_describe_callback_set         _nx_rtsp_server_describe_callback_set
#define nx_rtsp_server_setup_callback_set            _nx_rtsp_server_setup_callback_set
#define nx_rtsp_server_play_callback_set             _nx_rtsp_server_play_callback_set
#define nx_rtsp_server_pause_callback_set            _nx_rtsp_server_pause_callback_set
#define nx_rtsp_server_teardown_callback_set         _nx_rtsp_server_teardown_callback_set
#define nx_rtsp_server_set_parameter_callback_set    _nx_rtsp_server_set_parameter_callback_set

#define nx_rtsp_server_sdp_set                       _nx_rtsp_server_sdp_set
#define nx_rtsp_server_rtp_info_set                  _nx_rtsp_server_rtp_info_set
#define nx_rtsp_server_range_npt_set                 _nx_rtsp_server_range_npt_set

#define nx_rtsp_server_keepalive_update              _nx_rtsp_server_keepalive_update
#define nx_rtsp_server_error_response_send           _nx_rtsp_server_error_response_send

#else

/* Services with error checking.  */
#define nx_rtsp_server_create                        _nxe_rtsp_server_create
#define nx_rtsp_server_delete                        _nxe_rtsp_server_delete
#define nx_rtsp_server_start                         _nxe_rtsp_server_start
#define nx_rtsp_server_stop                          _nxe_rtsp_server_stop

#define nx_rtsp_server_describe_callback_set         _nxe_rtsp_server_describe_callback_set
#define nx_rtsp_server_setup_callback_set            _nxe_rtsp_server_setup_callback_set
#define nx_rtsp_server_play_callback_set             _nxe_rtsp_server_play_callback_set
#define nx_rtsp_server_pause_callback_set            _nxe_rtsp_server_pause_callback_set
#define nx_rtsp_server_teardown_callback_set         _nxe_rtsp_server_teardown_callback_set
#define nx_rtsp_server_set_parameter_callback_set    _nxe_rtsp_server_set_parameter_callback_set

#define nx_rtsp_server_sdp_set                       _nxe_rtsp_server_sdp_set
#define nx_rtsp_server_rtp_info_set                  _nxe_rtsp_server_rtp_info_set
#define nx_rtsp_server_range_npt_set                 _nxe_rtsp_server_range_npt_set

#define nx_rtsp_server_keepalive_update              _nxe_rtsp_server_keepalive_update
#define nx_rtsp_server_error_response_send           _nxe_rtsp_server_error_response_send

#endif /* NX_DISABLE_ERROR_CHECKING */

/* Define the prototypes accessible to the application software.  */

UINT nx_rtsp_server_describe_callback_set(NX_RTSP_SERVER * rtsp_server,
                                          UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length));

UINT nx_rtsp_server_setup_callback_set(NX_RTSP_SERVER * rtsp_server,
                                       UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr));

UINT nx_rtsp_server_play_callback_set(NX_RTSP_SERVER * rtsp_server,
                                      UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length));

UINT nx_rtsp_server_teardown_callback_set(NX_RTSP_SERVER * rtsp_server,
                                          UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length));


UINT nx_rtsp_server_pause_callback_set(NX_RTSP_SERVER * rtsp_server,
                                       UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length));

UINT nx_rtsp_server_set_parameter_callback_set(NX_RTSP_SERVER * rtsp_server,
                                               UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length));

UINT nx_rtsp_server_create(NX_RTSP_SERVER *rtsp_server_ptr, CHAR *server_name, UINT server_name_length,
                           NX_IP *ip_ptr, NX_PACKET_POOL *rtsp_packet_pool, VOID *stack_ptr, ULONG stack_size, UINT priority, UINT server_port,
                           UINT (*disconnect_callback)(NX_RTSP_CLIENT *rtsp_client_ptr));

UINT nx_rtsp_server_delete(NX_RTSP_SERVER *rtsp_server);

UINT nx_rtsp_server_start(NX_RTSP_SERVER *rtsp_server);

UINT nx_rtsp_server_stop(NX_RTSP_SERVER *rtsp_server);

/* Called in DESCRIBE callback function to set SDP string.  */
UINT nx_rtsp_server_sdp_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *sdp_string, UINT sdp_length);

/* Called in PLAY callback function to set RTP-Info field, including the RTP sequence number and RTP timestamp.  */
UINT nx_rtsp_server_rtp_info_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *track_id, UINT track_id_len, UINT rtp_seq, UINT rtp_time);

/* Called in PLAY and PAUSE callback functions to set the NPT start and end time in Range field.  */
UINT nx_rtsp_server_range_npt_set(NX_RTSP_CLIENT *rtsp_client_ptr, UINT npt_start, UINT npt_end);

/* If received RTCP reports, call this API to update the keepalive timeout. https://www.rfc-editor.org/rfc/rfc2326#appendix-A.2.  */
UINT nx_rtsp_server_keepalive_update(NX_RTSP_CLIENT *rtsp_client_ptr);

UINT nx_rtsp_server_error_response_send(NX_RTSP_CLIENT *rtsp_client_ptr, UINT status_code);

#else

/* Define the prototypes accessible to the application software.  */

UINT _nx_rtsp_server_describe_callback_set(NX_RTSP_SERVER * rtsp_server,
                                           UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length));
UINT _nxe_rtsp_server_describe_callback_set(NX_RTSP_SERVER * rtsp_server,
                                            UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length));

UINT _nx_rtsp_server_setup_callback_set(NX_RTSP_SERVER * rtsp_server,
                                        UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr));
UINT _nxe_rtsp_server_setup_callback_set(NX_RTSP_SERVER * rtsp_server,
                                         UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr));

UINT _nx_rtsp_server_play_callback_set(NX_RTSP_SERVER * rtsp_server,
                                       UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length));
UINT _nxe_rtsp_server_play_callback_set(NX_RTSP_SERVER * rtsp_server,
                                        UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length));

UINT _nx_rtsp_server_teardown_callback_set(NX_RTSP_SERVER * rtsp_server,
                                           UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length));
UINT _nxe_rtsp_server_teardown_callback_set(NX_RTSP_SERVER * rtsp_server,
                                            UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length));

UINT _nx_rtsp_server_pause_callback_set(NX_RTSP_SERVER * rtsp_server,
                                        UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length));
UINT _nxe_rtsp_server_pause_callback_set(NX_RTSP_SERVER * rtsp_server,
                                         UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length));


UINT _nx_rtsp_server_set_parameter_callback_set(NX_RTSP_SERVER * rtsp_server,
                                                UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length));
UINT _nxe_rtsp_server_set_parameter_callback_set(NX_RTSP_SERVER * rtsp_server,
                                                 UINT (*)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length));

UINT _nx_rtsp_server_create(NX_RTSP_SERVER *rtsp_server_ptr, CHAR *server_name, UINT server_name_length,
                            NX_IP *ip_ptr, NX_PACKET_POOL *rtsp_packet_pool, VOID *stack_ptr, ULONG stack_size, UINT priority, UINT server_port,
                            UINT (*disconnect_callback)(NX_RTSP_CLIENT *rtsp_client_ptr));
UINT _nxe_rtsp_server_create(NX_RTSP_SERVER *rtsp_server_ptr, CHAR *server_name, UINT server_name_length,
                             NX_IP *ip_ptr, NX_PACKET_POOL *rtsp_packet_pool, VOID *stack_ptr, ULONG stack_size, UINT priority, UINT server_port,
                             UINT (*disconnect_callback)(NX_RTSP_CLIENT *rtsp_client_ptr));

UINT _nx_rtsp_server_delete(NX_RTSP_SERVER *rtsp_server);
UINT _nxe_rtsp_server_delete(NX_RTSP_SERVER *rtsp_server);

UINT _nx_rtsp_server_start(NX_RTSP_SERVER *rtsp_server);
UINT _nxe_rtsp_server_start(NX_RTSP_SERVER *rtsp_server);

UINT _nx_rtsp_server_stop(NX_RTSP_SERVER *rtsp_server);
UINT _nxe_rtsp_server_stop(NX_RTSP_SERVER *rtsp_server);

/* Called in DESCRIBE callback function to set SDP string.  */
UINT _nx_rtsp_server_sdp_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *sdp_string, UINT sdp_length);
UINT _nxe_rtsp_server_sdp_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *sdp_string, UINT sdp_length);

/* Called in PLAY callback function to set RTP-Info field, including the RTP sequence number and RTP timestamp.  */
UINT _nx_rtsp_server_rtp_info_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *track_id, UINT track_id_len, UINT rtp_seq, UINT rtp_time);
UINT _nxe_rtsp_server_rtp_info_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *track_id, UINT track_id_len, UINT rtp_seq, UINT rtp_time);

/* Called in PLAY and PAUSE callback functions to set the NPT start and end time in Range field.  */
UINT _nx_rtsp_server_range_npt_set(NX_RTSP_CLIENT *rtsp_client_ptr, UINT npt_start, UINT npt_end);
UINT _nxe_rtsp_server_range_npt_set(NX_RTSP_CLIENT *rtsp_client_ptr, UINT npt_start, UINT npt_end);

/* If received RTCP reports, call this API to update the keepalive timeout. https://www.rfc-editor.org/rfc/rfc2326#appendix-A.2.  */
UINT _nx_rtsp_server_keepalive_update(NX_RTSP_CLIENT *rtsp_client_ptr);
UINT _nxe_rtsp_server_keepalive_update(NX_RTSP_CLIENT *rtsp_client_ptr);

UINT _nx_rtsp_server_error_response_send(NX_RTSP_CLIENT *rtsp_client_ptr, UINT status_code);
UINT _nxe_rtsp_server_error_response_send(NX_RTSP_CLIENT *rtsp_client_ptr, UINT status_code);

#endif /* NX_RTSP_SERVER_SOURCE_CODE */


/* Determine if a C++ compiler is being used.  If so, complete the standard
   C conditional started above.  */
#ifdef __cplusplus
}
#endif

#endif /* NX_RTSP_SERVER_H */

