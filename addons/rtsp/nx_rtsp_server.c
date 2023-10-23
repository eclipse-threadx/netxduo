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
#define NX_RTSP_SERVER_SOURCE_CODE

/* Force error checking to be disabled in this module.  */

#ifndef NX_DISABLE_ERROR_CHECKING
#define NX_DISABLE_ERROR_CHECKING
#endif

/* Include necessary system files.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_ip.h"
#ifdef FEATURE_NX_IPV6
#include    "nx_ipv6.h"
#endif /* #ifdef FEATURE_NX_IPV6 */
#include    "nx_rtsp_server.h"

/* Define the internal functions.  */

static VOID _nx_rtsp_server_thread_entry(ULONG);

static VOID _nx_rtsp_server_connect_present(NX_TCP_SOCKET *request_socket_ptr, UINT port);
static VOID _nx_rtsp_server_connect_process(NX_RTSP_SERVER *rtsp_server_ptr);

static VOID _nx_rtsp_server_disconnect_present(NX_TCP_SOCKET *request_socket_ptr);
static VOID _nx_rtsp_server_disconnect_process(NX_RTSP_SERVER *rtsp_server_ptr);

static VOID _nx_rtsp_server_request_present(NX_TCP_SOCKET *request_socket_ptr);
static VOID _nx_rtsp_server_request_process(NX_RTSP_SERVER *rtsp_server_ptr);

static VOID _nx_rtsp_server_timeout(ULONG rtsp_server_address);
static VOID _nx_rtsp_server_timeout_process(NX_RTSP_SERVER *rtsp_server_ptr);

static UINT _nx_rtsp_server_request_receive(NX_RTSP_SERVER *rtsp_server_ptr, NX_RTSP_CLIENT *rtsp_client_ptr);
static UINT _nx_rtsp_server_request_parse(NX_RTSP_CLIENT *rtsp_client_ptr, NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr);
static UINT _nx_rtsp_server_request_line_parse(NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr, UCHAR **request_buffer, UCHAR *request_buffer_end);
static UINT _nx_rtsp_server_request_header_parse(NX_RTSP_CLIENT *rtsp_client_ptr, NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr, UCHAR **request_buffer, UCHAR *request_buffer_end);
static UINT _nx_rtsp_server_response_create(NX_RTSP_SERVER *rtsp_server_ptr, NX_RTSP_CLIENT *rtsp_client_ptr, NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr);
static UINT _nx_rtsp_server_response_send(NX_RTSP_SERVER *rtsp_server_ptr, NX_RTSP_CLIENT *rtsp_client_ptr, NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr);

static VOID _nx_rtsp_server_disconnect(NX_RTSP_SERVER *rtsp_server_ptr, NX_RTSP_CLIENT *rtsp_client_ptr);

static UINT _nx_rtsp_server_memicmp(UCHAR *src, ULONG src_length, UCHAR *dest, ULONG dest_length);
static UCHAR *_nx_rtsp_server_strstr(UCHAR *src, ULONG src_length, UCHAR *dest, ULONG dest_length);

/* Define macros.  */

#define NX_RTSP_SERVER_STRING_SIZE(str)         sizeof(str) - 1
#define NX_RTSP_SERVER_STRING_WITH_SIZE(str)    (UCHAR *)str, NX_RTSP_SERVER_STRING_SIZE(str)

/* Bring in externs for caller checking code.  */

NX_CALLER_CHECKING_EXTERNS

/* Define description table for the RTSP response status code.  */

const NX_RTSP_RESPONSE nx_rtsp_server_response_description_table[] =
{
    { NX_RTSP_STATUS_CODE_OK                                  , "OK" },
    { NX_RTSP_STATUS_CODE_CREATED                             , "CREATED" },
    { NX_RTSP_STATUS_CODE_LOW_ON_STORAGE_SPACE                , "LOW ON STORAGE SPACE" },
    { NX_RTSP_STATUS_CODE_MULTIPLE_CHOICES                    , "MULTIPLE CHOICES" },
    { NX_RTSP_STATUS_CODE_MOVED_PERMANENTLY                   , "MOVED PERMANENTLY" },
    { NX_RTSP_STATUS_CODE_MOVED_TEMPORARILY                   , "MOVED TEMPORARILY" },
    { NX_RTSP_STATUS_CODE_SEE_OTHER                           , "SEE OTHER" },
    { NX_RTSP_STATUS_CODE_NOT_MODIFIED                        , "NOT MODIFIED" },
    { NX_RTSP_STATUS_CODE_USE_PROXY                           , "USE PROXY" },
    { NX_RTSP_STATUS_CODE_GOING_AWAY                          , "GOING AWAY" },
    { NX_RTSP_STATUS_CODE_LOAD_BALANCING                      , "LOAD BALANCING" },
    { NX_RTSP_STATUS_CODE_BAD_REQUEST                         , "BAD REQUEST" },
    { NX_RTSP_STATUS_CODE_UNAUTHORIZED                        , "UNAUTHORIZED" },
    { NX_RTSP_STATUS_CODE_PAYMENT_REQUIRED                    , "PAYMENT REQUIRED" },
    { NX_RTSP_STATUS_CODE_FORBIDDEN                           , "FORBIDDEN" },
    { NX_RTSP_STATUS_CODE_NOT_FOUND                           , "NOT FOUND" },
    { NX_RTSP_STATUS_CODE_METHOD_NOT_ALLOWED                  , "METHOD NOT ALLOWED" },
    { NX_RTSP_STATUS_CODE_NOT_ACCEPTABLE                      , "NOT ACCEPTABLE" },
    { NX_RTSP_STATUS_CODE_PROXY_AUTHENTICATION_REQUIRED       , "PROXY AUTHENTICATION REQUIRED" },
    { NX_RTSP_STATUS_CODE_REQUEST_TIMEOUT                     , "REQUEST TIMEOUT" },
    { NX_RTSP_STATUS_CODE_GONE                                , "GONE" },
    { NX_RTSP_STATUS_CODE_LENGTH_REQUIRED                     , "LENGTH REQUIRED" },
    { NX_RTSP_STATUS_CODE_PRECONDITION_FAILED                 , "PRECONDITION FAILED" },
    { NX_RTSP_STATUS_CODE_REQUEST_ENTITY_TOO_LARGE            , "REQUEST ENTITY TOO LARGE" },
    { NX_RTSP_STATUS_CODE_REQUESTURI_TOO_LARGE                , "REQUESTURI TOO LARGE" },
    { NX_RTSP_STATUS_CODE_UNSUPPORTED_MEDIA_TYPE              , "UNSUPPORTED MEDIA TYPE" },
    { NX_RTSP_STATUS_CODE_PARAMETER_NOT_UNDERSTOOD            , "PARAMETER NOT UNDERSTOOD" },
    { NX_RTSP_STATUS_CODE_RESERVED                            , "RESERVED" },
    { NX_RTSP_STATUS_CODE_NOT_ENOUGH_BANDWIDTH                , "NOT ENOUGH BANDWIDTH" },
    { NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND                   , "SESSION NOT FOUND" },
    { NX_RTSP_STATUS_CODE_METHOD_NOT_VALID_IN_THIS_STATE      , "METHOD NOT VALID IN THIS STATE" },
    { NX_RTSP_STATUS_CODE_HEADER_FIELD_NOT_VALID_FOR_RESOURCE , "HEADER FIELD NOT VALID FOR RESOURCE" },
    { NX_RTSP_STATUS_CODE_INVALID_RANGE                       , "INVALID RANGE" },
    { NX_RTSP_STATUS_CODE_PARAMETER_IS_READONLY               , "PARAMETER IS READONLY" },
    { NX_RTSP_STATUS_CODE_AGGREGATE_OPERATION_NOT_ALLOWED     , "AGGREGATE OPERATION NOT ALLOWED" },
    { NX_RTSP_STATUS_CODE_ONLY_AGGREGATE_OPERATION_ALLOWED    , "ONLY AGGREGATE OPERATION ALLOWED" },
    { NX_RTSP_STATUS_CODE_UNSUPPORTED_TRANSPORT               , "UNSUPPORTED TRANSPORT" },
    { NX_RTSP_STATUS_CODE_DESTINATION_UNREACHABLE             , "DESTINATION UNREACHABLE" },
    { NX_RTSP_STATUS_CODE_INTERNAL_SERVER_ERROR               , "INTERNAL SERVER ERROR" },
    { NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED                     , "NOT IMPLEMENTED" },
    { NX_RTSP_STATUS_CODE_BAD_GATEWAY                         , "BAD GATEWAY" },
    { NX_RTSP_STATUS_CODE_SERVICE_UNAVAILABLE                 , "SERVICE UNAVAILABLE" },
    { NX_RTSP_STATUS_CODE_GATEWAY_TIMEOUT                     , "GATEWAY TIMEOUT" },
    { NX_RTSP_STATUS_CODE_RTSP_VERSION_NOT_SUPPORTED          , "RTSP VERSION NOT SUPPORTED" },
    { NX_RTSP_STATUS_CODE_OPTION_NOT_SUPPORTED                , "OPTION NOT SUPPORTED" },
    { NX_NULL                                                 , "" }
};

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_create                             PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in RTSP server create function call.*/
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    server_name                           Name of RTSP server           */
/*    server_name_length                    Length of RTSP server name    */
/*    ip_ptr                                Pointer to IP instance        */
/*    rtsp_packet_pool                      Pointer to packet pool        */
/*    stack_ptr                             Server thread's stack pointer */
/*    stack_size                            Server thread's stack size    */
/*    priority                              The priority of the thread    */
/*    server_port                           Listening port                */
/*    disconnect_callback                   Disconnect callback function  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_create                Create RTSP server            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_create(NX_RTSP_SERVER *rtsp_server_ptr, CHAR *server_name, UINT server_name_length,
                             NX_IP *ip_ptr, NX_PACKET_POOL *rtsp_packet_pool,
                             VOID *stack_ptr, ULONG stack_size, UINT priority, UINT server_port,
                             UINT (*disconnect_callback)(NX_RTSP_CLIENT *rtsp_client_ptr))
{
UINT status;


    /* Check for invalid input pointers.  */
    if ((ip_ptr == NX_NULL) || (ip_ptr -> nx_ip_id != NX_IP_ID) ||
        (rtsp_server_ptr == NX_NULL) || (stack_ptr == NX_NULL) ||
        (rtsp_packet_pool == NX_NULL) || rtsp_server_ptr -> nx_rtsp_server_id == NX_RTSP_SERVER_ID)
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTSP server create function.  */
    status = _nx_rtsp_server_create(rtsp_server_ptr,server_name, server_name_length, ip_ptr, rtsp_packet_pool,
                                    stack_ptr, stack_size, priority,  server_port, disconnect_callback);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_create                              PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates a RTSP server on the specified IP and port.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    server_name                           Name of RTSP server           */
/*    server_name_length                    Length of RTSP server name    */
/*    ip_ptr                                Pointer to IP instance        */
/*    rtsp_packet_pool                      Pointer to packet pool        */
/*    stack_ptr                             Server thread's stack pointer */
/*    stack_size                            Server thread's stack size    */
/*    priority                              The priority of the thread    */
/*    server_port                           Listening port                */
/*    disconnect_callback                   Disconnect callback function  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                                Reset memory                  */
/*    tx_event_flags_create                 Create thread event flags     */
/*    tx_thread_create                      Create the server thread      */
/*    tx_timer_create                       Create the timeout timer      */
/*    tx_event_flags_delete                 Delete thread event flags     */
/*    tx_thread_delete                      Delete the server thread      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_create(NX_RTSP_SERVER *rtsp_server_ptr, CHAR *server_name, UINT server_name_length,
                            NX_IP *ip_ptr, NX_PACKET_POOL *rtsp_packet_pool,
                            VOID *stack_ptr, ULONG stack_size, UINT priority, UINT server_port,
                            UINT (*disconnect_callback)(NX_RTSP_CLIENT *rtsp_client_ptr))
{
UINT status;


    /* Clear RTSP server object.  */
    memset((VOID *)rtsp_server_ptr, 0, sizeof(NX_RTSP_SERVER));

    /* Set the RTSP server name.  */
    rtsp_server_ptr -> nx_rtsp_server_name = server_name;
    rtsp_server_ptr -> nx_rtsp_server_name_length = server_name_length;

    /* Record our packet pool.  */
    rtsp_server_ptr -> nx_rtsp_server_packet_pool = rtsp_packet_pool;

    /* Create the ThreadX event flags. These will be used to drive the RTSP server thread.  */
    status = tx_event_flags_create(&(rtsp_server_ptr -> nx_rtsp_server_event_flags), "RTSP Server Thread Events");

    if (status)
    {
        return(status);
    }

    /* Create the RTSP server thread and start the RTSP server.  */
    status = tx_thread_create(&(rtsp_server_ptr -> nx_rtsp_server_thread), server_name,
                              _nx_rtsp_server_thread_entry, (ULONG)rtsp_server_ptr,
                              stack_ptr, stack_size, priority, priority,
                              NX_RTSP_SERVER_TIME_SLICE, TX_NO_ACTIVATE);

    if (status)
    {

        /* Delete the event flag.  */
        tx_event_flags_delete(&(rtsp_server_ptr -> nx_rtsp_server_event_flags));
        return(status);
    }

    /* Create the timeout timer.  */
    status = tx_timer_create(&(rtsp_server_ptr -> nx_rtsp_server_timer), "RTSP Server Timer",
                             _nx_rtsp_server_timeout, (ULONG)rtsp_server_ptr,
                             NX_IP_PERIODIC_RATE, NX_IP_PERIODIC_RATE, TX_NO_ACTIVATE);

    if (status)
    {

        /* Delete the thread.  */
        tx_thread_delete(&(rtsp_server_ptr -> nx_rtsp_server_thread));

        /* Delete the event flag.  */
        tx_event_flags_delete(&(rtsp_server_ptr -> nx_rtsp_server_event_flags));

        return(status);
    }

    /* Set the IP pointer.  */
    rtsp_server_ptr -> nx_rtsp_server_ip_ptr = ip_ptr;

    /* Set the TCP port of RTSP server.  */
    rtsp_server_ptr -> nx_rtsp_server_port = (USHORT)server_port;

    /* Set disconnect callback function.  */
    rtsp_server_ptr -> nx_rtsp_server_disconnect_callback = disconnect_callback;

    /* Set the RTSP server ID.  */
    rtsp_server_ptr -> nx_rtsp_server_id = NX_RTSP_SERVER_ID;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_delete                             PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in RTSP server delete function call.*/
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_delete                Delete the RTSP server        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_delete(NX_RTSP_SERVER *rtsp_server_ptr)
{
UINT status;


    /* Check for invalid input pointers.  */
    if ((rtsp_server_ptr == NX_NULL) || (rtsp_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTSP server delete function.  */
    status = _nx_rtsp_server_delete(rtsp_server_ptr);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_delete                              PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deletes a previously created RTSP server on specified */
/*    IP and port.                                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_stop                  Stop the RTSP server          */
/*    tx_thread_terminate                   Terminate server thread       */
/*    tx_event_flags_delete                 Delete thread event flags     */
/*    tx_thread_delete                      Delete the server thread      */
/*    tx_timer_delete                       Delete the timeout timer      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_delete(NX_RTSP_SERVER *rtsp_server_ptr)
{


    /* Stop the RTSP server if not done yet. */
    if (rtsp_server_ptr -> nx_rtsp_server_started)
    {
        _nx_rtsp_server_stop(rtsp_server_ptr);
    }

    /* Terminate server thread. */
    tx_thread_terminate(&(rtsp_server_ptr -> nx_rtsp_server_thread));

    /* Delete server thread.  */
    tx_thread_delete(&(rtsp_server_ptr -> nx_rtsp_server_thread));

    /* Delete the server event flags.  */
    tx_event_flags_delete(&(rtsp_server_ptr -> nx_rtsp_server_event_flags));

    /* Delete the timer.  */
    tx_timer_delete(&(rtsp_server_ptr -> nx_rtsp_server_timer));

    /* Clear the RTSP server ID.  */
    rtsp_server_ptr -> nx_rtsp_server_id = 0;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_start                              PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in RTSP server start function call. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_start                 Start the RTSP server         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_start(NX_RTSP_SERVER *rtsp_server_ptr)
{
UINT   status;


    /* Check for invalid input pointers.  */
    if ((rtsp_server_ptr == NX_NULL) || (rtsp_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTSP server start function.  */
    status = _nx_rtsp_server_start(rtsp_server_ptr);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_start                               PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function starts a previously created RTSP server.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_tcp_socket_create                  Create TCP socket             */
/*    nx_tcp_socket_receive_notify          Set TCP notification callback */
/*    nx_tcp_socket_delete                  Delete TCP socket             */
/*    nx_tcp_server_socket_listen           Listen on free TCP socket     */
/*    tx_thread_resume                      Resume the RTSP server thread */
/*    tx_timer_activate                     Activate the timeout timer    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_start(NX_RTSP_SERVER *rtsp_server_ptr)
{
UINT   status;
int    i, j;


    /* Check if the RTSP server is started.  */
    if (rtsp_server_ptr -> nx_rtsp_server_started)
    {
        return(NX_RTSP_SERVER_ALREADY_STARTED);
    }

    /* Check if the required method callbacks are set.  */
    if ((rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_setup_callback == NX_NULL) ||
        (rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_play_callback == NX_NULL) ||
        (rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_teardown_callback == NX_NULL))
    {
        return(NX_RTSP_SERVER_MISSING_REQUIRED_CALLBACKS);
    }

    /* Loop to create all the RTSP client control sockets.  */
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {

        /* Create an RTSP client control socket.  */
        status =  nx_tcp_socket_create(rtsp_server_ptr -> nx_rtsp_server_ip_ptr, &(rtsp_server_ptr -> nx_rtsp_server_client_list[i].nx_rtsp_client_socket),
                                       "RTSP Client Control Socket", NX_RTSP_SERVER_TYPE_OF_SERVICE, NX_RTSP_SERVER_FRAGMENT_OPTION,
                                       NX_RTSP_SERVER_TIME_TO_LIVE, NX_RTSP_SERVER_WINDOW_SIZE, NX_NULL,
                                       _nx_rtsp_server_disconnect_present);

        /* If no error is present, register the receive notify function.  */
        if (status == NX_SUCCESS)
        {

            /* Register the receive function.  */
            nx_tcp_socket_receive_notify(&(rtsp_server_ptr -> nx_rtsp_server_client_list[i].nx_rtsp_client_socket),
                                         _nx_rtsp_server_request_present);
        }
        else
        {
            break;
        }

        /* Make sure each socket points to the RTSP server.  */
        rtsp_server_ptr -> nx_rtsp_server_client_list[i].nx_rtsp_client_socket.nx_tcp_socket_reserved_ptr = rtsp_server_ptr;
    }

    /* Determine if an error has occurred.  */
    if (status)
    {

        /* Loop to delete any created sockets.  */
        for (j = 0; j < i; j++)
        {

            /* Delete the RTSP socket.  */
            nx_tcp_socket_delete(&(rtsp_server_ptr -> nx_rtsp_server_client_list[j].nx_rtsp_client_socket));
        }

        /* Return an error.  */
        return(status);
    }


    /* Start listening on the RTSP socket.  */
    status =  nx_tcp_server_socket_listen(rtsp_server_ptr -> nx_rtsp_server_ip_ptr, rtsp_server_ptr -> nx_rtsp_server_port,
                                          &(rtsp_server_ptr -> nx_rtsp_server_client_list[0].nx_rtsp_client_socket),
                                          NX_RTSP_SERVER_MAX_CLIENTS, _nx_rtsp_server_connect_present);

    if (status)
    {
        return(status);
    }

    /* Start thread. */
    tx_thread_resume(&rtsp_server_ptr -> nx_rtsp_server_thread);

    /* Activate timer.  */
    tx_timer_activate(&rtsp_server_ptr -> nx_rtsp_server_timer);

    rtsp_server_ptr -> nx_rtsp_server_started = NX_TRUE;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_stop                               PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in RTSP server stop function call.  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_stop                  Stop the RTSP server          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_stop(NX_RTSP_SERVER *rtsp_server_ptr)
{
UINT status;


    /* Check for invalid input pointers.  */
    if ((rtsp_server_ptr == NX_NULL) || (rtsp_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTSP server stop function.  */
    status = _nx_rtsp_server_stop(rtsp_server_ptr);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_stop                                PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function stops a previously started RTSP server.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_thread_suspend                     Suspend server thread         */
/*    tx_timer_deactivate                   Stop server timeout timer     */
/*    nx_tcp_socket_disconnect              Disconnect TCP socket         */
/*    nx_tcp_server_socket_unaccept         Clear accepted socket         */
/*    nx_tcp_socket_delete                  Delete TCP socket             */
/*    nx_tcp_server_socket_unlisten         Stop listening on TCP socket  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_stop(NX_RTSP_SERVER *rtsp_server_ptr)
{
UINT client_index;


    /* Check if the server is started.  */
    if (rtsp_server_ptr -> nx_rtsp_server_started != NX_TRUE)
    {
        return(NX_RTSP_SERVER_NOT_STARTED);
    }

    /* Suspend thread. */
    tx_thread_suspend(&(rtsp_server_ptr -> nx_rtsp_server_thread));

    /* Deactivate the timer.  */
    tx_timer_deactivate(&(rtsp_server_ptr -> nx_rtsp_server_timer));

    /* Walk through to close the sockets.  */
    for (client_index = 0; client_index < NX_RTSP_SERVER_MAX_CLIENTS; client_index++)
    {

        /* Disconnect the socket.  */
        nx_tcp_socket_disconnect(&(rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_socket), NX_NO_WAIT);

        /* Unaccept the socket.  */
        nx_tcp_server_socket_unaccept(&(rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_socket));

        /* Delete the socket.  */
        nx_tcp_socket_delete(&(rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_socket));

        /* Check to see if a packet is queued up.  */
        if (rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_request_packet)
        {

            /* Yes, release it!  */
            nx_packet_release(rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_request_packet);
            rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_request_packet = NX_NULL;
            rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_request_bytes_total = 0;
        }

        /* Check to see if a packet is queued up.  */
        if (rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_response_packet)
        {

            /* Yes, release it!  */
            nx_packet_release(rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_response_packet);
            rtsp_server_ptr -> nx_rtsp_server_client_list[client_index].nx_rtsp_client_response_packet = NX_NULL;
        }
    }

    /* Unlisten for the RTSP server port.  */
    nx_tcp_server_socket_unlisten(rtsp_server_ptr -> nx_rtsp_server_ip_ptr, rtsp_server_ptr -> nx_rtsp_server_port);

    /* Clear the RTSP server started flag.  */
    rtsp_server_ptr -> nx_rtsp_server_started = NX_FALSE;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_sdp_set                            PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in SDP set function call.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    sdp_string                            Pointer to SDP string         */
/*    sdp_length                            The length of the SDP string  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_sdp_set               Set SDP string in response    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_sdp_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *sdp_string, UINT sdp_length)
{
UINT status;


    /* Check for invalid input pointers.  */
    if ((rtsp_client_ptr == NX_NULL) || (sdp_string == NX_NULL) || (sdp_length == 0) ||
        (rtsp_client_ptr -> nx_rtsp_client_server_ptr == NX_NULL) ||
        (rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual SDP set function.  */
    status = _nx_rtsp_server_sdp_set(rtsp_client_ptr, sdp_string, sdp_length);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_sdp_set                             PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the SDP string to the response packet. This      */
/*    function can only be called in DESCRIBE callback function.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    sdp_string                            Pointer to SDP string         */
/*    sdp_length                            The length of the SDP string  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_data_append                 Append packet data            */
/*    _nx_utility_uint_to_string            Convert integer to string     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_sdp_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *sdp_string, UINT sdp_length)
{
UINT       status;
CHAR       temp_buffer[11];
UINT       temp_length;
NX_PACKET *response_packet_ptr = rtsp_client_ptr -> nx_rtsp_client_response_packet;


    /* Check if the packet is valid.  */
    if (!response_packet_ptr)
    {
        return(NX_RTSP_SERVER_NO_PACKET);
    }

    /* Check the request method.  */
    if ((!rtsp_client_ptr -> nx_rtsp_client_request_ptr) ||
        (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_method != NX_RTSP_METHOD_DESCRIBE))
    {
        return(NX_RTSP_SERVER_INVALID_REQUEST);
    }

    /* Add "Content-Type" header.  */
    status = nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("Content-Type: "),
                                   rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(NX_RTSP_SERVER_CONTENT_TYPE_SDP),
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n"),
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);

    /* Add "Content-Length" header.  */
    status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("Content-Length: "),
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    temp_length = _nx_utility_uint_to_string(sdp_length, 10, temp_buffer, sizeof(temp_buffer));
    status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length,
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n\r\n"),
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);

    /* Add sdp string.  */
    status += nx_packet_data_append(response_packet_ptr, sdp_string, sdp_length,
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_rtp_info_set                       PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in RTP-Info set function call.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    track_id                              The track ID of the media     */
/*    track_id_len                          The length of the track ID    */
/*    rtp_seq                               The RTP sequence number       */
/*    rtp_time                              The RTP timestamp             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_rtp_info_set          Set RTP-Info in response      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_rtp_info_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *track_id, UINT track_id_len, UINT rtp_seq, UINT rtp_time)
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_client_ptr == NX_NULL) || (track_id == NX_NULL) || (track_id_len == 0) ||
        (rtsp_client_ptr -> nx_rtsp_client_server_ptr == NX_NULL) ||
        (rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP-Info set function.  */
    status = _nx_rtsp_server_rtp_info_set(rtsp_client_ptr, track_id, track_id_len, rtp_seq, rtp_time);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_rtp_info_set                        PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the RTP-Info to the response packet. This        */
/*    function can only be called in PLAY callback function.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    track_id                              The track ID of the media     */
/*    track_id_len                          The length of the track ID    */
/*    rtp_seq                               The RTP sequence number       */
/*    rtp_time                              The RTP timestamp             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_data_append                 Append packet data            */
/*    _nx_utility_uint_to_string            Convert integer to string     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_rtp_info_set(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *track_id, UINT track_id_len, UINT rtp_seq, UINT rtp_time)
{
UINT       status;
CHAR       temp_buffer[11];
UINT       temp_length;
NX_PACKET *response_packet_ptr = rtsp_client_ptr -> nx_rtsp_client_response_packet;


    /* Check if the packet is valid.  */
    if (!response_packet_ptr)
    {
        return(NX_RTSP_SERVER_NO_PACKET);
    }

    /* Check the request method.  */
    if ((!rtsp_client_ptr -> nx_rtsp_client_request_ptr) ||
        rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_method != NX_RTSP_METHOD_PLAY)
    {
        return(NX_RTSP_SERVER_INVALID_REQUEST);
    }

    /* Add "RTP-Info" header.  */
    status = nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("url="),
                                   rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr, rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_length,
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("/"),
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, track_id, track_id_len,
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(";seq="),
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    temp_length = _nx_utility_uint_to_string(rtp_seq, 10, temp_buffer, sizeof(temp_buffer));
    status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length,
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(";rtptime="),
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    temp_length = _nx_utility_uint_to_string(rtp_time, 10, temp_buffer, sizeof(temp_buffer));
    status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length,
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(","),
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_range_npt_set                      PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in NPT set function call.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    npt_start                             The NPT start time in         */
/*                                            milliseconds                */
/*    npt_end                               The NPT end time in           */
/*                                            milliseconds                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_range_npt_set         Set NPT start and end time    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_range_npt_set(NX_RTSP_CLIENT *rtsp_client_ptr, UINT npt_start, UINT npt_end)
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_client_ptr == NX_NULL) || (rtsp_client_ptr -> nx_rtsp_client_server_ptr == NX_NULL) ||
        (rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual NPT set function.  */
    status = _nx_rtsp_server_range_npt_set(rtsp_client_ptr, npt_start, npt_end);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_range_npt_set                       PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the NPT start and end time in Range field. This  */
/*    function can only be called in PLAY and PAUSE callback function.    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    npt_start                             The NPT start time in         */
/*                                            milliseconds                */
/*    npt_end                               The NPT end time in           */
/*                                            milliseconds                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_range_npt_set(NX_RTSP_CLIENT *rtsp_client_ptr, UINT npt_start, UINT npt_end)
{

    /* Check the request method.  */
    if ((!rtsp_client_ptr -> nx_rtsp_client_request_ptr) ||
        ((rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_method != NX_RTSP_METHOD_PLAY) &&
         (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_method != NX_RTSP_METHOD_PAUSE)))
    {
        return(NX_RTSP_SERVER_INVALID_REQUEST);
    }

    /* Check start and end time.  */
    if (npt_end < npt_start)
    {
        return(NX_RTSP_SERVER_INVALID_PARAMETER);
    }

    /* Set the NPT start and end time in milliseconds.  */
    rtsp_client_ptr -> nx_rtsp_client_npt_start = npt_start;
    rtsp_client_ptr -> nx_rtsp_client_npt_end = npt_end;

    return(NX_SUCCESS);
}
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_error_response_send                PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in error response send call.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    status_code                           The status code of response   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_error_response_send   Send error response           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_error_response_send(NX_RTSP_CLIENT *rtsp_client_ptr, UINT status_code)
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_client_ptr == NX_NULL) || (rtsp_client_ptr -> nx_rtsp_client_server_ptr == NX_NULL) ||
        (rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual error response send function.  */
    status = _nx_rtsp_server_error_response_send(rtsp_client_ptr, status_code);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_error_response_send                 PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends the error response packet.                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    status_code                           The status code of response   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_release                     Release the packet            */
/*    nx_packet_data_append                 Append packet data            */
/*    _nx_utility_uint_to_string            Convert integer to string     */
/*    _nx_utility_string_length_check       Check string length           */
/*    nx_tcp_socket_send                    Send TCP packet               */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_error_response_send(NX_RTSP_CLIENT *rtsp_client_ptr, UINT status_code)
{
UINT       status;
UINT       i;
CHAR       temp_buffer[11];
UINT       temp_length;
NX_PACKET *response_packet_ptr = rtsp_client_ptr -> nx_rtsp_client_response_packet;
NX_PACKET_POOL *pool_ptr = rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool;


    if (!response_packet_ptr)
    {
        return(NX_RTSP_SERVER_NO_PACKET);
    }

    /* Loop to find the corresponding description.  */
    for (i = 0; nx_rtsp_server_response_description_table[i].nx_rtsp_response_code != NX_NULL; i++)
    {
        if (nx_rtsp_server_response_description_table[i].nx_rtsp_response_code == status_code)
        {
            break;
        }
    }

    if (nx_rtsp_server_response_description_table[i].nx_rtsp_response_code == NX_NULL)
    {
        return(NX_RTSP_SERVER_INVALID_PARAMETER);
    }

#ifndef NX_DISABLE_PACKET_CHAIN
    /* Reuse the response packet to append the error message.
       If user has already appended data to this packet and there are packets chained,
       remove and release the chained packets. */
    if (response_packet_ptr -> nx_packet_next)
    {
        nx_packet_release(response_packet_ptr -> nx_packet_next);
        response_packet_ptr -> nx_packet_next = NX_NULL;
        response_packet_ptr -> nx_packet_last = NX_NULL;
    }
#endif /* NX_DISABLE_PACKET_CHAIN */

    /* Reset the packet.  */
    response_packet_ptr -> nx_packet_append_ptr = response_packet_ptr -> nx_packet_prepend_ptr;
    response_packet_ptr -> nx_packet_length = 0;

    /* Add version.  */
    status = nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(NX_RTSP_VERSION_STRING),
                                   pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, " ", 1, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

    /* Add status code.  */
    temp_length = _nx_utility_uint_to_string(status_code, 10, temp_buffer, sizeof(temp_buffer));
    status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(response_packet_ptr, " ", 1, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
    _nx_utility_string_length_check(nx_rtsp_server_response_description_table[i].nx_rtsp_response_description, &temp_length, NX_MAX_STRING_LENGTH);
    status += nx_packet_data_append(response_packet_ptr, nx_rtsp_server_response_description_table[i].nx_rtsp_response_description,
                                    temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n"), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

    /* Add "CSeq" header.  */
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("CSeq: "), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
    temp_length = _nx_utility_uint_to_string(rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_sequence_number, 10, temp_buffer, sizeof(temp_buffer));
    status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n"), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

    /* Add "Server" header.  */
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("Server: "), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_name,
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_name_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n\r\n"), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

    if (status == NX_SUCCESS)
    {

        /* Send the response message back.  */
        status =  nx_tcp_socket_send(&rtsp_client_ptr -> nx_rtsp_client_socket, response_packet_ptr, NX_RTSP_SERVER_SEND_TIMEOUT);
    }

    /* Determine if the send was unsuccessful.  */
    if (status)
    {

        /* Release the packet.  */
        nx_packet_release(response_packet_ptr);
    }

    /* Clear the response packet pointer.  */
    rtsp_client_ptr -> nx_rtsp_client_response_packet = NX_NULL;

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_keepalive_update                   PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in keepalive update function call.  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_keepalive_update      Update the timeout timer      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_keepalive_update(NX_RTSP_CLIENT *rtsp_client_ptr)
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_client_ptr == NX_NULL) || (rtsp_client_ptr -> nx_rtsp_client_server_ptr == NX_NULL) ||
        (rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual keep-alive update function.  */
    status = _nx_rtsp_server_keepalive_update(rtsp_client_ptr);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_keepalive_update                    PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function updates the timeout timer of the client. If RTP is    */
/*    used for media transport, RTCP is used to show liveness of client.  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_keepalive_update(NX_RTSP_CLIENT *rtsp_client_ptr)
{

    /* Reset the client request activity timeout.  */
    if (rtsp_client_ptr -> nx_rtsp_client_request_activity_timeout)
    {
        rtsp_client_ptr -> nx_rtsp_client_request_activity_timeout = NX_RTSP_SERVER_ACTIVITY_TIMEOUT;
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_describe_callback_set              PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in DESCRIBE callback set.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of DESCRIBE request  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_describe_callback_set Set DESCRIBE callback         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_describe_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                            UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length))
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_server_ptr == NX_NULL) || (callback == NX_NULL) ||
         (rtsp_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual DESCRIBE callback set function.  */
    status = _nx_rtsp_server_describe_callback_set(rtsp_server_ptr, callback);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_describe_callback_set               PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function installs callback function for DESCRIBE request.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of DESCRIBE request  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_describe_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                           UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length))
{

    /* Set callback for DESCRIBE method.  */
    rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_describe_callback = callback;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_setup_callback_set                 PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in SETUP callback set.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of SETUP request     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_setup_callback_set    Set SETUP callback            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_setup_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                         UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr))
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_server_ptr == NX_NULL) || (callback == NX_NULL) ||
         (rtsp_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual SETUP callback set function.  */
    status = _nx_rtsp_server_setup_callback_set(rtsp_server_ptr, callback);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_setup_callback_set                  PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function installs callback function for SETUP request.         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of SETUP request     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_setup_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                        UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr))
{

    /* Set callback for SETUP method.  */
    rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_setup_callback = callback;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_play_callback_set                  PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in PLAY callback set.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of PLAY request      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_play_callback_set     Set PLAY callback             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_play_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                        UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length))
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_server_ptr == NX_NULL) || (callback == NX_NULL) ||
         (rtsp_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual PLAY callback set function.  */
    status = _nx_rtsp_server_play_callback_set(rtsp_server_ptr, callback);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_play_callback_set                   PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function installs callback function for PLAY request.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of PLAY request      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_play_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                       UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length))
{

    /* Set callback for PLAY method.  */
    rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_play_callback = callback;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_teardown_callback_set              PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in TEARDOWN callback set.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of TEARDOWN request  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_teardown_callback_set Set TEARDOWN callback         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_teardown_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                            UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length))
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_server_ptr == NX_NULL) || (callback == NX_NULL) ||
         (rtsp_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual TEARDOWN callback set function.  */
    status = _nx_rtsp_server_teardown_callback_set(rtsp_server_ptr, callback);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_teardown_callback_set               PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function installs callback function for TEARDOWN request.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of TEARDOWN request  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_teardown_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                           UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length))
{

    /* Set callback for TEARDOWN method.  */
    rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_teardown_callback = callback;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_pause_callback_set                 PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in PAUSE callback set.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of PAUSE request     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_pause_callback_set    Set PAUSE callback            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_pause_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                        UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length))
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_server_ptr == NX_NULL) || (callback == NX_NULL) ||
         (rtsp_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual PAUSE callback set function.  */
    status = _nx_rtsp_server_pause_callback_set(rtsp_server_ptr, callback);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_pause_callback_set                  PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function installs callback function for PAUSE request.         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of PAUSE request     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_pause_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                        UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length))
{

    /* Set callback for PAUSE method.  */
    rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_pause_callback = callback;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtsp_server_set_parameter_callback_set         PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors in SET_PARAMETER callback set.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of SET_PARAMETER     */
/*                                            request                     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_set_parameter_callback_set                          */
/*                                          Set SET_PARAMETER callback    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtsp_server_set_parameter_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                                 UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length))
{
UINT       status;


    /* Check for invalid input pointers.  */
    if ((rtsp_server_ptr == NX_NULL) || (callback == NX_NULL) ||
         (rtsp_server_ptr -> nx_rtsp_server_id != NX_RTSP_SERVER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual SET_PARAMETER callback set function.  */
    status = _nx_rtsp_server_set_parameter_callback_set(rtsp_server_ptr, callback);

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_set_parameter_callback_set          PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function installs callback function for SET_PARAMETER request. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    callback                              Callback of SET_PARAMETER     */
/*                                            request                     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtsp_server_set_parameter_callback_set(NX_RTSP_SERVER *rtsp_server_ptr,
                                                UINT (*callback)(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length))
{

    /* Set callback for SET_PARAMETER method.  */
    rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_set_parameter_callback = callback;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_thread_entry                        PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles events of RTSP server thread.                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_address                   Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_get                    Get event flags               */
/*    _nx_rtsp_server_connect_process       Process connect event         */
/*    _nx_rtsp_server_request_process       Process request event         */
/*    _nx_rtsp_server_disconnect_process    Process disconnect event      */
/*    _nx_rtsp_server_timeout_process       Process timeout event         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    ThreadX                                                             */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_rtsp_server_thread_entry(ULONG rtsp_server_address)
{
NX_RTSP_SERVER *rtsp_server_ptr;
UINT            status;
ULONG           events;


    /* Setup the server pointer.  */
    rtsp_server_ptr = (NX_RTSP_SERVER *)rtsp_server_address;

    /* Loop to process RTSP Server requests.  */
    while (1)
    {

        /* Wait for an RTSP client activity.  */
        status = tx_event_flags_get(&(rtsp_server_ptr -> nx_rtsp_server_event_flags), NX_RTSP_SERVER_ALL_EVENTS, TX_OR_CLEAR, &events, TX_WAIT_FOREVER);

        /* Check the return status.  */
        if (status)
        {

            /* If an error occurs, simply continue the loop.  */
            continue;
        }

        /* Otherwise, an event is present.  Process according to the event.  */

        /* Check for a client connection event.  */
        if (events & NX_RTSP_SERVER_CONNECT_EVENT)
        {

            /* Call the connect process.  */
            _nx_rtsp_server_connect_process(rtsp_server_ptr);
        }

        /* Check for a client request event.  */
        if (events & NX_RTSP_SERVER_REQUEST_EVENT)
        {

            /* Call the request process.  */
            _nx_rtsp_server_request_process(rtsp_server_ptr);
        }

        /* Check for a client disconnect event.  */
        if (events & NX_RTSP_SERVER_DISCONNECT_EVENT)
        {

            /* Call the disconnect process.  */
            _nx_rtsp_server_disconnect_process(rtsp_server_ptr);
        }

        /* Check for a client activity timeout event.  */
        if (events & NX_RTSP_SERVER_TIMEOUT_EVENT)
        {

            /* Call the activity timeout process.  */
            _nx_rtsp_server_timeout_process(rtsp_server_ptr);
        }
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_request_receive                     PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function receives the entire request from client including the */
/*    request header and message body.                                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_tcp_socket_receive                 Receive TCP packet            */
/*    _nx_rtsp_server_memicmp               Compare two strings           */
/*    nx_packet_data_append                 Append packet data            */
/*    nx_packet_release                     Release the packet            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_request_process                                     */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_rtsp_server_request_receive(NX_RTSP_SERVER *rtsp_server_ptr, NX_RTSP_CLIENT *rtsp_client_ptr)
{
NX_PACKET *head_packet_ptr = rtsp_client_ptr -> nx_rtsp_client_request_packet;
NX_PACKET *new_packet_ptr;
NX_PACKET *work_ptr;
NX_PACKET *tmp_ptr;
UCHAR     *buffer_ptr;
UINT       crlf_found = 0;
UINT       content_length_found = 0;
UINT       content_length = 0;
UINT       header_length = 0;
UINT       status = NX_SUCCESS;


    if (head_packet_ptr == NX_NULL)
    {

        /* Receive a request from RTSP client.  */
        status = nx_tcp_socket_receive(&(rtsp_client_ptr -> nx_rtsp_client_socket), &head_packet_ptr, NX_NO_WAIT);

        /* Check the return status.  */
        if (status == NX_NO_PACKET)
        {
            return(NX_IN_PROGRESS);
        }
        else if (status != NX_SUCCESS)
        {

            /* Return an error condition.  */
            return(status);
        }

        rtsp_client_ptr -> nx_rtsp_client_request_packet = head_packet_ptr;
    }

    work_ptr = head_packet_ptr;

    /* Build a pointer to the buffer area.  */
    buffer_ptr = work_ptr -> nx_packet_prepend_ptr;

    while (status == NX_SUCCESS)
    {

        /* nx_rtsp_client_request_bytes_total is not zero means the receiving of request header is complete.  */
        if (rtsp_client_ptr -> nx_rtsp_client_request_bytes_total == 0)
        {

            /* See if there is a blank line present in the buffer.  */
            /* Search the buffer for a cr/lf pair.  */
            while ((buffer_ptr < work_ptr -> nx_packet_append_ptr) &&
                   (crlf_found < 4))
            {
                if (!(crlf_found & 1) && (*buffer_ptr == '\r'))
                {

                    /* Found CR.  */
                    crlf_found++;
                }
                else if ((crlf_found & 1) && (*buffer_ptr == '\n'))
                {

                    /* Found LF.  */
                    crlf_found++;
                }
                else
                {

                    /* Reset the CRLF marker.  */
                    crlf_found = 0;
                }

                if ((content_length_found == NX_FALSE) && ((buffer_ptr + 14) < work_ptr -> nx_packet_append_ptr) &&
                    (_nx_rtsp_server_memicmp(buffer_ptr, 15, NX_RTSP_SERVER_STRING_WITH_SIZE("Content-length:")) == NX_SUCCESS))
                {

                    /* Set the found flag.  */
                    content_length_found = NX_TRUE;
                    buffer_ptr += 15;
                    header_length += 15;

                    /* Now skip over white space.  */
                    while ((buffer_ptr < work_ptr -> nx_packet_append_ptr) && (*buffer_ptr == ' '))
                    {
                        buffer_ptr++;
                        header_length++;
                    }

                    /* Now convert the length into a numeric value.  */
                    while ((buffer_ptr < work_ptr -> nx_packet_append_ptr) && (*buffer_ptr >= '0') && (*buffer_ptr <= '9'))
                    {

                        /* Update the content length.  */
                        content_length =  content_length * 10;
                        content_length = content_length + (UINT)(*buffer_ptr) - '0';

                        /* Move the buffer pointer forward.  */
                        buffer_ptr++;
                        header_length++;
                    }
                }

                /* Move the buffer pointer up.  */
                buffer_ptr++;
                header_length++;
            }

            if (crlf_found == 4)
            {

                /* Store content length and total bytes need to be received.  */
                rtsp_client_ptr -> nx_rtsp_client_request_content_length = content_length;
                rtsp_client_ptr -> nx_rtsp_client_request_bytes_total = content_length + header_length;

                /* Yes, we have found the end of the HTTP request header. Continue to receive content  */
                continue;
            }

#ifndef NX_DISABLE_PACKET_CHAIN

            /* Determine if the packet has already overflowed into another packet.  */
            if (work_ptr -> nx_packet_next != NX_NULL)
            {

                /* Get the next packet in the chain.  */
                work_ptr  = work_ptr -> nx_packet_next;
                buffer_ptr = work_ptr -> nx_packet_prepend_ptr;

                continue;
            }
#endif /* NX_DISABLE_PACKET_CHAIN */
        }
        else
        {

            /* Check if we have received the total bytes of the request.  */
            if (head_packet_ptr -> nx_packet_length == rtsp_client_ptr -> nx_rtsp_client_request_bytes_total)
            {
                break;
            }
            else if (head_packet_ptr -> nx_packet_length > rtsp_client_ptr -> nx_rtsp_client_request_bytes_total)
            {
                status = NX_INVALID_PACKET;
                break;
            }
        }

        /* Receive another packet from the RTSP Client.  */
        status = nx_tcp_socket_receive(&(rtsp_client_ptr -> nx_rtsp_client_socket), &new_packet_ptr, NX_NO_WAIT);

        /* Check the return status.  */
        if (status == NX_NO_PACKET)
        {
            return(NX_IN_PROGRESS);
        }
        else if (status != NX_SUCCESS)
        {
            break;
        }

        /* Successfully received another packet. Its contents now need to be placed in the head packet.  */
        tmp_ptr = new_packet_ptr;

#ifndef NX_DISABLE_PACKET_CHAIN
        while (tmp_ptr)
#endif /* NX_DISABLE_PACKET_CHAIN */
        {

            /* Copy the contents of the current packet into the head packet.  */
            status = nx_packet_data_append(head_packet_ptr, (VOID *) tmp_ptr -> nx_packet_prepend_ptr,
                                            (ULONG)(tmp_ptr -> nx_packet_append_ptr - tmp_ptr -> nx_packet_prepend_ptr),
                                            rtsp_server_ptr -> nx_rtsp_server_packet_pool, NX_NO_WAIT);

#ifndef NX_DISABLE_PACKET_CHAIN

            /* Determine if an error occurred.  */
            if (status != NX_SUCCESS)
            {
                break;
            }
            else
            {
                tmp_ptr = tmp_ptr -> nx_packet_next;
            }
#endif /* NX_DISABLE_PACKET_CHAIN */
        }

        /* Release the new packet.  */
        nx_packet_release(new_packet_ptr);

        /* If we haven't received all the request header, and haven't found the content length field.  */
        if ((rtsp_client_ptr -> nx_rtsp_client_request_bytes_total == 0) && (content_length_found == NX_FALSE))
        {

            /* Search again from the start of the packet.  */
            work_ptr = head_packet_ptr;

            /* Build a pointer to the buffer area.  */
            buffer_ptr = work_ptr -> nx_packet_prepend_ptr;

            /* Reset the header length.  */
            header_length = 0;
        }
    }

    if (status)
    {

        /* Release the packet.  */
        nx_packet_release(head_packet_ptr);
        rtsp_client_ptr -> nx_rtsp_client_request_packet = NX_NULL;
        rtsp_client_ptr -> nx_rtsp_client_request_bytes_total = 0;
    }

    /* Return status.  */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_request_parse                       PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses incoming request packet.                       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    rtsp_client_request_ptr               Pointer to request structure  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                                Reset memory                  */
/*    _nx_rtsp_server_request_line_parse    Parse request line            */
/*    _nx_rtsp_server_request_header_parse  Parse request header          */
/*    nx_packet_allocate                    Allocate a packet             */
/*    _nx_rtsp_server_error_response_send   Send error response           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_request_process                                     */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_rtsp_server_request_parse(NX_RTSP_CLIENT *rtsp_client_ptr, NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr)
{
UINT   status;
UCHAR *rtsp_client_request_buf;
UCHAR *rtsp_client_request_buf_ptr;
UCHAR *rtsp_client_request_buf_end;
NX_PACKET *rtsp_client_request_packet = rtsp_client_ptr -> nx_rtsp_client_request_packet;


#ifndef NX_DISABLE_PACKET_CHAIN

    /* Check if the packet is chained. Chained packet isn't supported now.  */
    if (rtsp_client_request_packet -> nx_packet_next)
    {
        return(NX_INVALID_PACKET);
    }
#endif /* NX_DISABLE_PACKET_CHAIN */

    /* Reset the request info.  */
    memset(rtsp_client_request_ptr, 0, sizeof(NX_RTSP_CLIENT_REQUEST));

    /* Set the buffer pointer.  */
    rtsp_client_request_buf = rtsp_client_request_packet -> nx_packet_prepend_ptr;
    rtsp_client_request_buf_end = rtsp_client_request_packet -> nx_packet_append_ptr - rtsp_client_ptr -> nx_rtsp_client_request_content_length;
    rtsp_client_request_buf_ptr = rtsp_client_request_buf;

    /* Parse the request line.  */
    status = _nx_rtsp_server_request_line_parse(rtsp_client_request_ptr, &rtsp_client_request_buf_ptr, rtsp_client_request_buf_end);

    if (status == NX_SUCCESS)
    {

        /* Continue parse headers.  */
        while (rtsp_client_request_buf_ptr < rtsp_client_request_buf_end)
        {

            /* Parse the headers.  */
            status = _nx_rtsp_server_request_header_parse(rtsp_client_ptr, rtsp_client_request_ptr,
                                                          &rtsp_client_request_buf_ptr, rtsp_client_request_buf_end);

            if (status)
            {
                break;
            }
        }
    }

    if (status)
    {

        /* Send error response packet.  */
        if (nx_packet_allocate(rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool,
                               &(rtsp_client_ptr -> nx_rtsp_client_response_packet),
                               NX_TCP_PACKET, NX_RTSP_SERVER_PACKET_TIMEOUT) == NX_SUCCESS)
        {
            _nx_rtsp_server_error_response_send(rtsp_client_ptr, status);
        }
        else
        {

            /* There is nothing we can do here. Ideally log this error event.  */
            rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_allocation_errors++;
        }
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_request_line_parse                  PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses request method, URI and version.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_request_ptr               Pointer to request structure  */
/*    request_buffer                        Start of request buffer       */
/*    request_buffer_end                    End to request buffer         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memcmp                                Compare two strings           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_request_parse                                       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_rtsp_server_request_line_parse(NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr, UCHAR **request_buffer, UCHAR *request_buffer_end)
{
UCHAR *request_buffer_ptr;
UCHAR *temp_ptr;
UINT   temp_length = 0;


    /* Set the buffer pointer.  */
    request_buffer_ptr = *request_buffer;

    /* We assume the client request is well formatted. */
    /* Parse the request line.  */

    /* Trim the spaces before the method.  */
    while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr == ' '))
    {
        request_buffer_ptr++;
    }

    /* Return error if no more data.  */
    if (request_buffer_ptr == request_buffer_end)
    {
        return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
    }

    /* Set the method pointer.  */
    temp_ptr = request_buffer_ptr;

    /* Find the ending point of the method.  */
    while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr != ' ') &&
           (*request_buffer_ptr != '\r') && (*request_buffer_ptr != '\n'))
    {
        request_buffer_ptr++;
    }

    /* Must has space before URI.  */
    if ((request_buffer_ptr == request_buffer_end) || (*request_buffer_ptr != ' '))
    {
        return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
    }

    /* Calculate method length.  */
    temp_length = (UINT)(request_buffer_ptr - temp_ptr);

    /* The method is case-sensitive.  */
    if ((temp_length == NX_RTSP_SERVER_STRING_SIZE("OPTIONS")) && (memcmp(temp_ptr, "OPTIONS", temp_length) == 0))
    {
        rtsp_client_request_ptr -> nx_rtsp_client_request_method = NX_RTSP_METHOD_OPTIONS;
    }
    else if ((temp_length == NX_RTSP_SERVER_STRING_SIZE("DESCRIBE")) && (memcmp(temp_ptr, "DESCRIBE", temp_length) == 0))
    {
        rtsp_client_request_ptr -> nx_rtsp_client_request_method = NX_RTSP_METHOD_DESCRIBE;
    }
    else if ((temp_length == NX_RTSP_SERVER_STRING_SIZE("SETUP")) && (memcmp(temp_ptr, "SETUP", temp_length) == 0))
    {
        rtsp_client_request_ptr -> nx_rtsp_client_request_method = NX_RTSP_METHOD_SETUP;
    }
    else if ((temp_length == NX_RTSP_SERVER_STRING_SIZE("PLAY")) && (memcmp(temp_ptr, "PLAY", temp_length) == 0))
    {
        rtsp_client_request_ptr -> nx_rtsp_client_request_method = NX_RTSP_METHOD_PLAY;
    }
    else if ((temp_length == NX_RTSP_SERVER_STRING_SIZE("PAUSE")) && (memcmp(temp_ptr, "PAUSE", temp_length) == 0))
    {
        rtsp_client_request_ptr -> nx_rtsp_client_request_method = NX_RTSP_METHOD_PAUSE;
    }
    else if ((temp_length == NX_RTSP_SERVER_STRING_SIZE("TEARDOWN")) && (memcmp(temp_ptr, "TEARDOWN", temp_length) == 0))
    {
        rtsp_client_request_ptr -> nx_rtsp_client_request_method = NX_RTSP_METHOD_TEARDOWN;
    }
    else if ((temp_length == NX_RTSP_SERVER_STRING_SIZE("SET_PARAMETER")) && (memcmp(temp_ptr, "SET_PARAMETER", temp_length) == 0))
    {
        rtsp_client_request_ptr -> nx_rtsp_client_request_method = NX_RTSP_METHOD_SET_PARAMETER;
    }
    else
    {
        rtsp_client_request_ptr -> nx_rtsp_client_request_method = NX_RTSP_METHOD_NOT_SUPPORT;

        return(NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED);
    }

    /* Trim the spaces.  */
    while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr == ' '))
    {
        request_buffer_ptr++;
    }

    /* Return error if no more data.  */
    if (request_buffer_ptr == request_buffer_end)
    {
        return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
    }

    /* Set the URI pointer.  */
    rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr = request_buffer_ptr;

    /* Find the ending point of the URI.  */
    while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr != ' ') &&
           (*request_buffer_ptr != '\r') && (*request_buffer_ptr != '\n'))
    {
        request_buffer_ptr++;
    }

    /* Must has space before version.  */
    if ((request_buffer_ptr == request_buffer_end) || (*request_buffer_ptr != ' '))
    {
        return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
    }

    /* Calculate the URI length.  */
    rtsp_client_request_ptr -> nx_rtsp_client_request_uri_length = (UINT)(request_buffer_ptr - rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr);

    /* Trim the spaces.  */
    while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr == ' '))
    {
        request_buffer_ptr++;
    }

    /* Return error if no more data.  */
    if (request_buffer_ptr == request_buffer_end)
    {
        return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
    }

    /* Set the version pointer.  */
    temp_ptr = request_buffer_ptr;

    /* Find the ending point of the version.  */
    while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr != ' ') &&
           (*request_buffer_ptr != '\r') && (*request_buffer_ptr != '\n'))
    {
        request_buffer_ptr++;
    }

    /* Calculate version length.  */
    temp_length = (UINT)(request_buffer_ptr - temp_ptr);

    /* Check version.  */
    if ((temp_length != (sizeof(NX_RTSP_VERSION_STRING) - 1)) ||
        memcmp(temp_ptr, NX_RTSP_VERSION_STRING, temp_length) != 0)
    {
        return(NX_RTSP_STATUS_CODE_RTSP_VERSION_NOT_SUPPORTED);
    }

    /* Trim the spaces.  */
    while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr == ' '))
    {
        request_buffer_ptr++;
    }

    /* Move to next line.  */
    /* RFC: https://www.rfc-editor.org/rfc/rfc2326#section-4
       Lines are terminated by CRLF, but receivers should be prepared
       to also interpret CR and LF by themselves as line terminators. */
    if (((request_buffer_ptr + 1) < request_buffer_end) &&
        (*request_buffer_ptr == '\r') && (*(request_buffer_ptr + 1) == '\n'))
    {
        request_buffer_ptr += 2;
    }
    else if ((request_buffer_ptr < request_buffer_end) &&
             ((*request_buffer_ptr == '\r') || (*request_buffer_ptr == '\n')))
    {
        request_buffer_ptr++;
    }
    else
    {
        return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
    }

    *request_buffer = request_buffer_ptr;

    /* Terminate the URI string.  */
    *(rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr + rtsp_client_request_ptr -> nx_rtsp_client_request_uri_length) = NX_NULL;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_request_header_parse                PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses headers in request packet.                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    rtsp_client_request_ptr               Pointer to request structure  */
/*    request_buffer                        Start of request buffer       */
/*    request_buffer_end                    End to request buffer         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_memicmp               Compare two strings           */
/*    _nx_utility_string_to_uint            Convert string to integer     */
/*    _nx_rtsp_server_strstr                Search substring              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_request_parse                                       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_rtsp_server_request_header_parse(NX_RTSP_CLIENT *rtsp_client_ptr, NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr, UCHAR **request_buffer, UCHAR *request_buffer_end)
{
UCHAR *request_buffer_ptr;
UCHAR *field_name_ptr;
UCHAR *field_value_ptr;
UINT   field_name_length = 0;
UINT   field_value_length = 0;
UINT   port_length = 0;
UINT   status;
NXD_ADDRESS *receiver_ip_address;


    /* Set the buffer pointer.  */
    request_buffer_ptr = *request_buffer;

    /* We assume the client request is well formatted.  */
    /* Parse a header line.  */

    /* Trim the spaces.  */
    while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr == ' '))
    {
        request_buffer_ptr++;
    }

    if (request_buffer_ptr == request_buffer_end)
    {

        /* Ignore empty line */
        return(NX_SUCCESS);
    }

    /* Set the pointer of field name.  */
    field_name_ptr = request_buffer_ptr;

    /* Find the ending point of the header name.  */
    while ((request_buffer_ptr < request_buffer_end) &&
           (*request_buffer_ptr != ':') && (*request_buffer_ptr != ' ') &&
           (*request_buffer_ptr != '\r') && (*request_buffer_ptr != '\n'))
    {
        request_buffer_ptr++;
    }

    /* Calculate the length of the field name.  */
    field_name_length = (UINT)(request_buffer_ptr - field_name_ptr);

    if (field_name_length)
    {

        /* Trim the colon and spaces.  */
        while ((request_buffer_ptr < request_buffer_end) &&
               ((*request_buffer_ptr == ':') || (*request_buffer_ptr == ' ')))
        {
            request_buffer_ptr++;
        }

        /* Set the pointer of the field value.  */
        field_value_ptr = request_buffer_ptr;

        /* Find the end of the field value.  */
        while ((request_buffer_ptr < request_buffer_end) &&
                (*request_buffer_ptr != '\r') && (*request_buffer_ptr != '\n'))
        {
            request_buffer_ptr++;
        }

        /* Calculate the length of the field value.  */
        field_value_length = (UINT)(request_buffer_ptr - field_value_ptr);

        if (_nx_rtsp_server_memicmp(field_name_ptr, field_name_length, NX_RTSP_SERVER_STRING_WITH_SIZE("cseq")) == NX_SUCCESS)
        {

            /* Parse CSeq.  */

            /* Convert string to integer.  */
            status = _nx_utility_string_to_uint((CHAR *)field_value_ptr, field_value_length, &(rtsp_client_request_ptr -> nx_rtsp_client_request_sequence_number));
            if (status)
            {
                return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
            }
        }
        else if (_nx_rtsp_server_memicmp(field_name_ptr, field_name_length, NX_RTSP_SERVER_STRING_WITH_SIZE("range")) == NX_SUCCESS)
        {

            /* Parse Range.  */

            /* Set the range pointer and length.  */
            rtsp_client_request_ptr -> nx_rtsp_client_request_range_ptr = field_value_ptr;
            rtsp_client_request_ptr -> nx_rtsp_client_request_range_length = field_value_length;
        }
        else if (_nx_rtsp_server_memicmp(field_name_ptr, field_name_length, NX_RTSP_SERVER_STRING_WITH_SIZE("session")) == NX_SUCCESS)
        {

            /* Parse Session.  */

            /* Convert string to integer.  */
            status = _nx_utility_string_to_uint((CHAR *)field_value_ptr, field_value_length, (UINT *)&(rtsp_client_request_ptr -> nx_rtsp_client_request_session_id));
            if (status)
            {
                return(status);
            }
        }
        else if (_nx_rtsp_server_memicmp(field_name_ptr, field_name_length, NX_RTSP_SERVER_STRING_WITH_SIZE("transport")) == NX_SUCCESS)
        {

            /* Parse Transport.  */

            /* RTP/AVP/TCP is not supported. https://www.rfc-editor.org/rfc/rfc2326#section-10.4.  */
            if (_nx_rtsp_server_strstr(field_value_ptr, field_value_length, NX_RTSP_SERVER_STRING_WITH_SIZE("RTP/AVP/TCP")))
            {
                rtsp_client_request_ptr -> nx_rtsp_client_request_transport.transport_type = NX_RTSP_TRANSPORT_TYPE_TCP;
                return(NX_RTSP_STATUS_CODE_UNSUPPORTED_TRANSPORT);
            }
            else
            {
                rtsp_client_request_ptr -> nx_rtsp_client_request_transport.transport_type = NX_RTSP_TRANSPORT_TYPE_UDP;
            }

            receiver_ip_address = &(rtsp_client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_connect_ip);

            /* Check multicast/unicast field.  */
            if (_nx_rtsp_server_strstr(field_value_ptr, field_value_length, NX_RTSP_SERVER_STRING_WITH_SIZE("unicast")))
            {

                /* For unicast mode, set the client IP address and return to user.  */
                rtsp_client_request_ptr -> nx_rtsp_client_request_transport.transport_mode = NX_RTSP_TRANSPORT_MODE_UNICAST;

                if (receiver_ip_address -> nxd_ip_version == NX_IP_VERSION_V4)
                {
#ifndef NX_DISABLE_IPV4
                    /* Set client IP address. */
                    rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
                    rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_ip_address.nxd_ip_address.v4 = receiver_ip_address -> nxd_ip_address.v4;

                    /* Set default server IP address.  */
                    rtsp_client_request_ptr -> nx_rtsp_client_request_transport.server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
                    rtsp_client_request_ptr -> nx_rtsp_client_request_transport.server_ip_address.nxd_ip_address.v4 = rtsp_client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_connect_interface -> nx_interface_ip_address;

                    /* Record the transport ip interface in order to know where the packet is from.  */
                    rtsp_client_request_ptr -> nx_rtsp_client_request_transport.interface_index = rtsp_client_ptr -> nx_rtsp_client_request_packet -> nx_packet_address.nx_packet_interface_ptr -> nx_interface_index;
#else
                    return(NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED);
#endif /* NX_DISABLE_IPV4 */
                }
                else if (receiver_ip_address -> nxd_ip_version == NX_IP_VERSION_V6)
                {
#ifdef FEATURE_NX_IPV6
                    /* Set client IP address. */
                    rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
                    COPY_IPV6_ADDRESS(receiver_ip_address -> nxd_ip_address.v6, rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_ip_address.nxd_ip_address.v6);

                    /* Set default server IP address.  */
                    rtsp_client_request_ptr -> nx_rtsp_client_request_transport.server_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
                    COPY_IPV6_ADDRESS(rtsp_client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_ipv6_addr -> nxd_ipv6_address,
                                      rtsp_client_request_ptr -> nx_rtsp_client_request_transport.server_ip_address.nxd_ip_address.v6);

                    /* Record the transport ip interface in order to know where the packet is from.  */
                    rtsp_client_request_ptr -> nx_rtsp_client_request_transport.interface_index = rtsp_client_ptr -> nx_rtsp_client_request_packet -> nx_packet_address.nx_packet_ipv6_address_ptr -> nxd_ipv6_address_attached -> nx_interface_index;
#else
                    return(NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED);
#endif /* FEATURE_NX_IPV6 */
                }
                else
                {
                    return(NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED);
                }

                request_buffer_ptr = _nx_rtsp_server_strstr(field_value_ptr, field_value_length, NX_RTSP_SERVER_STRING_WITH_SIZE("client_port"));
                port_length = NX_RTSP_SERVER_STRING_SIZE("client_port");
            }
            else
            {

                /* FIXME: Support that client chooses multicast address. Get destination field and convert to IP address.  */
                if (_nx_rtsp_server_strstr(field_value_ptr, field_value_length, NX_RTSP_SERVER_STRING_WITH_SIZE("destination")) != NX_NULL)
                {
                    rtsp_client_request_ptr -> nx_rtsp_client_request_transport.transport_mode = NX_RTSP_TRANSPORT_MODE_MULTICAST_CLIENT;
                    return(NX_RTSP_STATUS_CODE_UNSUPPORTED_TRANSPORT);
                }

                /* Set multicast mode and server will choose multicast address.  */
                rtsp_client_request_ptr -> nx_rtsp_client_request_transport.transport_mode = NX_RTSP_TRANSPORT_MODE_MULTICAST_SERVER;
                request_buffer_ptr = _nx_rtsp_server_strstr(field_value_ptr, field_value_length, NX_RTSP_SERVER_STRING_WITH_SIZE("port"));
                port_length = NX_RTSP_SERVER_STRING_SIZE("port");
            }

            /* Get client port pair.  */
            if (request_buffer_ptr)
            {

                /* Find the port value.  */
                request_buffer_ptr = request_buffer_ptr + port_length;
                while ((request_buffer_ptr < request_buffer_end) &&
                       ((*request_buffer_ptr == ' ') || (*request_buffer_ptr == '=')))
                {
                    request_buffer_ptr++;
                }

                /* Get pointer of the RTP port.  */
                field_value_ptr = request_buffer_ptr;

                while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr != '-') &&
                       (*request_buffer_ptr != '\r') && (*request_buffer_ptr != '\n'))
                {
                    request_buffer_ptr++;
                }

                /* Check the format.  */
                if (*request_buffer_ptr != '-')
                {
                    return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
                }

                /* Calculate the length of the RTP port.  */
                field_value_length = (UINT)(request_buffer_ptr - field_value_ptr);

                /* Convert string to integer.  */
                status = _nx_utility_string_to_uint((CHAR *)field_value_ptr, field_value_length, (UINT *)&(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_rtp_port));
                if (status)
                {
                    return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
                }

                /* Get pointer of the RTCP port.  */
                request_buffer_ptr++;
                field_value_ptr = request_buffer_ptr;

                while ((request_buffer_ptr < request_buffer_end) && (*request_buffer_ptr != ';') &&
                       (*request_buffer_ptr != '\r') && (*request_buffer_ptr != '\n'))
                {
                    request_buffer_ptr++;
                }

                /* Calculate the length of the RTCP port.  */
                field_value_length = (UINT)(request_buffer_ptr - field_value_ptr);

                /* Convert string to integer.  */
                status = _nx_utility_string_to_uint((CHAR *)field_value_ptr, field_value_length, (UINT *)&(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_rtcp_port));
                if (status)
                {
                    return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
                }
            }
            else
            {

                /* If no client port, move to the end of transport field.  */
                request_buffer_ptr = field_value_ptr + field_value_length;
            }
        }
    }

    /* Move to next line.  */
    /* RFC: https://www.rfc-editor.org/rfc/rfc2326#section-4
       Lines are terminated by CRLF, but receivers should be prepared
       to also interpret CR and LF by themselves as line terminators. */
    if (((request_buffer_ptr + 1) < request_buffer_end) &&
        (*request_buffer_ptr == '\r') && (*(request_buffer_ptr + 1) == '\n'))
    {

        /* Terminate the header line.  */
        *request_buffer_ptr = NX_NULL;
        request_buffer_ptr += 2;
    }
    else if ((request_buffer_ptr < request_buffer_end) &&
             ((*request_buffer_ptr == '\r') || (*request_buffer_ptr == '\n')))
    {

        /* Terminate the header line.  */
        *request_buffer_ptr = NX_NULL;
        request_buffer_ptr++;
    }
    else
    {
        return(NX_RTSP_STATUS_CODE_BAD_REQUEST);
    }

    *request_buffer = request_buffer_ptr;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_memicmp                             PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function compares two pieces of memory case insensitive.       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    src                                   Pointer to source             */
/*    src_length                            Length of source              */
/*    dest                                  Pointer to destination        */
/*    dest_length                           Length of destination         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_request_header_parse                                */
/*    _nx_rtsp_server_request_receive                                     */
/*    _nx_rtsp_server_strstr                                              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_rtsp_server_memicmp(UCHAR *src, ULONG src_length, UCHAR *dest, ULONG dest_length)
{
UCHAR ch;


    /* Compare the length. */
    if(src_length != dest_length)
        return(NX_RTSP_SERVER_FAILED);

    while(src_length)
    {

        /* Is src lowercase? */
        if((*src >= 'a') && (*src <= 'z'))
            ch = (UCHAR)(*src - 'a' + 'A');

        /* Is src uppercase? */
        else if((*src >= 'A') && (*src <= 'Z'))
            ch = (UCHAR)(*src - 'A' + 'a');
        else
            ch = *src;

        /* Compare case insensitive. */
        if((*src != *dest) && (ch != *dest))
            return(NX_RTSP_SERVER_FAILED);

        /* Pickup next character. */
        src_length--;
        src++;
        dest++;
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_strstr                              PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function searches the substring and returns the pointer.       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    src                                   Pointer to source             */
/*    src_length                            Length of source              */
/*    dest                                  Pointer to destination        */
/*    dest_length                           Length of destination         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    pointer                               Pointer to the substring      */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_memicmp               Compare two strings           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_request_header_parse                                */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static UCHAR *_nx_rtsp_server_strstr(UCHAR *src, ULONG src_length, UCHAR *dest, ULONG dest_length)
{
UINT index = 0;


    /* Check the src and dest length.  */
    if (src_length < dest_length)
    {
        return(NX_NULL);
    }

    /* Loop to search the dest string.  */
    while ((index + dest_length <= src_length) &&
           (_nx_rtsp_server_memicmp(src + index, dest_length, dest, dest_length) != NX_SUCCESS))
    {
        index++;
    }

    /* Return the pointer.  */
    if ((index + dest_length) <= src_length)
    {
        return(src + index);
    }
    else
    {
        return(NX_NULL);
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_response_create                     PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates a response packet with common lines.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    rtsp_client_request_ptr               Pointer to request structure  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nx_packet_data_append                 Append packet data            */
/*    nx_packet_release                     Release the packet            */
/*    _nx_utility_uint_to_string            Convert integer to string     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_request_process                                     */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_rtsp_server_response_create(NX_RTSP_SERVER *rtsp_server_ptr, NX_RTSP_CLIENT *rtsp_client_ptr, NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr)
{
UINT  status;
CHAR  temp_buffer[11];
UINT  temp_length;


    /* Allocate response packet.  */
    status = nx_packet_allocate(rtsp_server_ptr -> nx_rtsp_server_packet_pool, &(rtsp_client_ptr -> nx_rtsp_client_response_packet), NX_TCP_PACKET, NX_RTSP_SERVER_PACKET_TIMEOUT);
    if (status)
    {
        return(status);
    }

    /* Generate the common response lines.  */

    /* Set default status as 200 OK.  */
    status = nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE(NX_RTSP_VERSION_STRING),
                                   rtsp_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE(" 200 OK\r\n"),
                                    rtsp_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);

    /* Add "CSeq" header.  */
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("CSeq: "),
                                    rtsp_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    temp_length = _nx_utility_uint_to_string(rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_sequence_number, 10, temp_buffer, sizeof(temp_buffer));
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, temp_buffer, temp_length,
                                    rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n"),
                                    rtsp_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);

    /* Add "Server" header.  */
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("Server: "),
                                    rtsp_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, rtsp_server_ptr -> nx_rtsp_server_name, rtsp_server_ptr -> nx_rtsp_server_name_length,
                                    rtsp_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n"),
                                    rtsp_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);

    /* If the request method is PLAY, add RTP-Info header.  */
    if (rtsp_client_request_ptr -> nx_rtsp_client_request_method == NX_RTSP_METHOD_PLAY)
    {

        /* Add "RTP-Info" header.  */
        status += nx_packet_data_append(rtsp_client_ptr -> nx_rtsp_client_response_packet, NX_RTSP_SERVER_STRING_WITH_SIZE("RTP-Info: "),
                                        rtsp_server_ptr -> nx_rtsp_server_packet_pool, NX_RTSP_SERVER_PACKET_TIMEOUT);
    }

    /* Check if error occurs.  */
    if (status)
    {
        nx_packet_release(rtsp_client_ptr -> nx_rtsp_client_response_packet);
        rtsp_client_ptr -> nx_rtsp_client_response_packet = NX_NULL;
    }

    return(status);
}

#ifdef FEATURE_NX_IPV6
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_ipv6_address_to_string              PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function converts an ipv6 address from ULONG array format into */
/*    standard ipv6 address string format.                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ipv6_addr                            Pointer to ULONG array address */
/*    buffer                               Pointer to output string buffer*/
/*    buffer_length                        Max length of output buffer    */
/*    size                                 Real size of output buffer     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                               Reset memory                   */
/*    memcpy                               Copy data memory               */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_response_send                                       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao             Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_rtsp_server_ipv6_address_to_string(ULONG *ipv6_addr, CHAR *buffer, UINT buffer_length, UINT *size)
{
UINT    i, j;
UCHAR   c;
ULONG   val;
CHAR   *cur_pos = buffer;


    /* Check if the buffer is large enough to contain the ipv6 address in string format. An example ipv6 address string
       like "2001:0001:0002:0003:0004:0005:0006:1234" shows that 39 bytes data space is needed for the return buffer.
       Overall, the return buffer shall be 40 bytes to include the end '\0' for the output string. */
    if (buffer_length < 40)
    {
        return(NX_SIZE_ERROR);
    }

    /* Go through each 4 ULONG values in ipv6 address. */
    for (i = 0; i < 4; i++)
    {

        /* Get the current ULONG value. */
        val = ipv6_addr[i];

        /* Go through each bit of the ULONG to convert. */
        for (j = 0; j <= 7; j++)
        {

            /* Save the bit off the most significant end. */
            c = (UCHAR)((val & 0xF0000000) >> 28);

            /* Make it the most significant byte. */
            val = val << 4;

            /* Convert the digit to an ascii character. */
            if (c < 10)
            {
                *cur_pos = (CHAR)('0' + c);
            }
            else /* Handle HEX digits... */
            {
                *cur_pos = (CHAR)('A' + (c - 10));
            }

            /* Move past the digit. */
            cur_pos++;

            /* Determine if we need to add a colon. */
            if ((j == 3) || (j == 7))
            {

                /* Yes, append the colon and move the pointer past it. */
                *cur_pos = ':';
                cur_pos++;
            }
        }
    }

    /* Assign the last byte to make a complete string.  */
    buffer[39] = '\0';

    /* Assign a constant string size 39 as the returned real output buffer size. So far, the returned real size
       will always be 39 even if an example ipv6 address string is like "2004:0000:0000:0000:0000:0000:0000:0001"
       since ipv6 abbreviation expression is not supported.  */
    *size = 39;

    return(NX_SUCCESS);
}
#endif /* FEATURE_NX_IPV6 */

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_response_send                       PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends the response to the client.                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*    rtsp_client_request_ptr               Pointer to request structure  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_data_append                 Append packet data            */
/*    _nx_utility_uint_to_string            Convert integer to string     */
/*    nx_packet_release                     Release the packet            */
/*    nx_tcp_socket_send                    Send TCP packet               */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_request_process                                     */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_rtsp_server_response_send(NX_RTSP_SERVER *rtsp_server_ptr, NX_RTSP_CLIENT *rtsp_client_ptr, NX_RTSP_CLIENT_REQUEST *rtsp_client_request_ptr)
{
UINT       status = NX_SUCCESS;
#ifdef FEATURE_NX_IPV6
CHAR       temp_buffer[40]; /* The size for buffer to store an IPv6 address represented in ASCII. */
#else
CHAR       temp_buffer[11];
#endif /* FEATURE_NX_IPV6 */
UINT       temp_length;
NX_PACKET *temp_packet_ptr;
NX_PACKET *response_packet_ptr = rtsp_client_ptr -> nx_rtsp_client_response_packet;
NX_PACKET_POOL *pool_ptr = rtsp_client_ptr -> nx_rtsp_client_server_ptr -> nx_rtsp_server_packet_pool;
NXD_ADDRESS *source_ip_address;

    if (!response_packet_ptr)
    {
        return(NX_RTSP_SERVER_NO_PACKET);
    }

    switch (rtsp_client_request_ptr -> nx_rtsp_client_request_method)
    {
    case NX_RTSP_METHOD_OPTIONS:
    {

        /* Always support "OPTIONS, SETUP, PLAY, TEARDOWN".  */
        status = nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("Public: OPTIONS, SETUP, PLAY, TEARDOWN"),
                                       pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

        /* Check if other methods are supported.  */
        if (rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_describe_callback != NX_NULL)
        {
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(", DESCRIBE"),
                                            pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        }

        if (rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_pause_callback != NX_NULL)
        {
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(", PAUSE"),
                                            pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        }

        if (rtsp_server_ptr -> nx_rtsp_server_method_callbacks.nx_rtsp_server_method_set_parameter_callback != NX_NULL)
        {
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(", SET_PARAMETER"),
                                            pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        }

        /* Add terminators.  */
        status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n\r\n"),
                                        pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

        break;
    }
    case NX_RTSP_METHOD_DESCRIBE:
    {

        /* The details in DESCRIBE method are fulfilled in the function _nx_rtsp_server_sdp_set
           which is normally called in the function nx_rtsp_server_method_describe_callback.
           So, directly break here in order to skip adding terminators in the default branch.  */
        break;
    }
    case NX_RTSP_METHOD_SETUP:
    {

        /* Add "Session" header.  */
        status = nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("Session: "),
                                       pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        temp_length = _nx_utility_uint_to_string(rtsp_client_ptr -> nx_rtsp_client_session_id, 10, temp_buffer, sizeof(temp_buffer));
        status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(";timeout="),
                                        pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        temp_length = _nx_utility_uint_to_string(NX_RTSP_SERVER_ACTIVITY_TIMEOUT, 10, temp_buffer, sizeof(temp_buffer));
        status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

        /* Add "Transport" header.  */
        status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\nTransport: RTP/AVP;"),
                                        pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

        /* Add unicast/multicast start words.  */
        if (rtsp_client_request_ptr -> nx_rtsp_client_request_transport.transport_mode == NX_RTSP_TRANSPORT_MODE_UNICAST)
        {
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("unicast;source="),
                                            pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

            source_ip_address = &(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.server_ip_address);
        }
        else
        {
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("multicast;destination="),
                                            pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

            source_ip_address = &(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_ip_address);
        }

        /* Add source/destination IP address.  */
        if (rtsp_client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V4)
        {
#ifndef NX_DISABLE_IPV4
            temp_length = _nx_utility_uint_to_string(source_ip_address -> nxd_ip_address.v4 >> 24, 10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            status += nx_packet_data_append(response_packet_ptr, ".", 1, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string((source_ip_address -> nxd_ip_address.v4 >> 16) & 0xFF, 10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            status += nx_packet_data_append(response_packet_ptr, ".", 1, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string((source_ip_address -> nxd_ip_address.v4 >> 8) & 0xFF, 10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            status += nx_packet_data_append(response_packet_ptr, ".", 1, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string((source_ip_address -> nxd_ip_address.v4) & 0xFF, 10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
#else
            status = NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED;
            break;
#endif /* NX_DISABLE_IPV4 */
        }
        else if (rtsp_client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6)
        {
#ifdef FEATURE_NX_IPV6
            _nx_rtsp_server_ipv6_address_to_string(source_ip_address -> nxd_ip_address.v6, temp_buffer, sizeof(temp_buffer), &temp_length);
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
#else
            status = NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED;
            break;
#endif /* FEATURE_NX_IPV6 */
        }

        if (rtsp_client_request_ptr -> nx_rtsp_client_request_transport.transport_mode == NX_RTSP_TRANSPORT_MODE_UNICAST)
        {
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(";client_port="), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_rtp_port,
                                                     10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("-"), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_rtcp_port,
                                                     10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(";server_port="), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.server_rtp_port,
                                                     10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("-"), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.server_rtcp_port,
                                                     10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(";ssrc="), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.rtp_ssrc,
                                                     10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        }
        else
        {
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(";port="), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_rtp_port,
                                                     10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("-"), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_rtcp_port,
                                                     10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(";ttl="), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string(rtsp_client_request_ptr -> nx_rtsp_client_request_transport.multicast_ttl,
                                                     10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        }

        /* Add terminators.  */
        status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n\r\n"),
                                        pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

        break;
    }
    case NX_RTSP_METHOD_PLAY:
    {

        /* If user has called nx_rtsp_server_rtp_info_set to set RTP-Info field,
           there is an extra character ',' appended to the end of the packet.  */
        temp_packet_ptr = response_packet_ptr;

#ifndef NX_DISABLE_PACKET_CHAIN
        /* If the packet is chained, move to the last packet.  */
        if (response_packet_ptr -> nx_packet_last)
        {
            temp_packet_ptr = response_packet_ptr -> nx_packet_last;
        }
#endif /* NX_DISABLE_PACKET_CHAIN */

        /* Remove the last character ','.  */
        if (*(temp_packet_ptr -> nx_packet_append_ptr - 1) == ',')
        {
            temp_packet_ptr -> nx_packet_append_ptr--;
            temp_packet_ptr -> nx_packet_length--;
        }

        /* Add terminators.  */
        status = nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n"),
                                       pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
    }
    /* fallthrough */
    case NX_RTSP_METHOD_PAUSE:
    {
        if ((rtsp_client_request_ptr -> nx_rtsp_client_request_method == NX_RTSP_METHOD_PLAY) ||
            (rtsp_client_ptr -> nx_rtsp_client_npt_start) || (rtsp_client_ptr -> nx_rtsp_client_npt_end))
        {

            /* Add "Range" header.  */
            status = nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("Range: npt="),
                                           pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string((rtsp_client_ptr -> nx_rtsp_client_npt_start / 1000), 10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("."), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            temp_length = _nx_utility_uint_to_string((rtsp_client_ptr -> nx_rtsp_client_npt_start % 1000), 10, temp_buffer, sizeof(temp_buffer));
            status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("-"), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

            if (rtsp_client_ptr -> nx_rtsp_client_npt_end)
            {
                temp_length = _nx_utility_uint_to_string((rtsp_client_ptr -> nx_rtsp_client_npt_end / 1000), 10, temp_buffer, sizeof(temp_buffer));
                status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
                status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("."), pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
                temp_length = _nx_utility_uint_to_string((rtsp_client_ptr -> nx_rtsp_client_npt_end % 1000), 10, temp_buffer, sizeof(temp_buffer));
                status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
            }

            /* Add terminators.  */
            status = nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n"),
                                           pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        }

        /* Add "Session" header.  */
        status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("Session: "),
                                        pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        temp_length = _nx_utility_uint_to_string(rtsp_client_ptr -> nx_rtsp_client_session_id, 10, temp_buffer, sizeof(temp_buffer));
        status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE(";timeout="),
                                        pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);
        temp_length = _nx_utility_uint_to_string(NX_RTSP_SERVER_ACTIVITY_TIMEOUT, 10, temp_buffer, sizeof(temp_buffer));
        status += nx_packet_data_append(response_packet_ptr, temp_buffer, temp_length, pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

        /* Add terminators.  */
        status += nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n\r\n"),
                                        pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

        break;
    }
    default:
    {

        /* Add terminators.  */
        status = nx_packet_data_append(response_packet_ptr, NX_RTSP_SERVER_STRING_WITH_SIZE("\r\n"),
                                       pool_ptr, NX_RTSP_SERVER_PACKET_TIMEOUT);

        break;
    }
    }

    if (status == NX_SUCCESS)
    {

        /* Send the response message back.  */
        status = nx_tcp_socket_send(&rtsp_client_ptr -> nx_rtsp_client_socket, response_packet_ptr, NX_RTSP_SERVER_SEND_TIMEOUT);
    }

    /* Determine if the send was unsuccessful.  */
    if (status)
    {

        /* Release the packet.  */
        nx_packet_release(response_packet_ptr);
    }

    /* Clear the response packet pointer.  */
    rtsp_client_ptr -> nx_rtsp_client_response_packet = NX_NULL;

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_request_process                     PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes RTSP requests.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_request_receive       Receive client request        */
/*    _nx_rtsp_server_request_parse         Parse client request          */
/*    _nx_rtsp_server_response_create       Create common response        */
/*    _nx_rtsp_server_error_response_send   Send error response           */
/*    _nx_rtsp_server_response_send         Send common response          */
/*    nx_packet_release                     Release the packet            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_thread_entry                                        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_rtsp_server_request_process(NX_RTSP_SERVER *rtsp_server_ptr)
{
UINT                   i;
UINT                   status;
NX_RTSP_CLIENT        *rtsp_client_ptr;
NX_RTSP_SERVER_METHOD_CALLBACKS method_callbacks = rtsp_server_ptr -> nx_rtsp_server_method_callbacks;


    /* Now look for a socket that has receive data.  */
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {

        /* Setup pointer to client structure.  */
        rtsp_client_ptr = &(rtsp_server_ptr -> nx_rtsp_server_client_list[i]);

        /* Now see if this socket has data.  */
        if (rtsp_client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_receive_queue_count)
        {

            /* Attempt to read a packet from this socket.  */
            status = _nx_rtsp_server_request_receive(rtsp_server_ptr, rtsp_client_ptr);

            /* Check for no data present.  */
            if (status != NX_SUCCESS)
            {

                /* Just continue the loop and look at the next socket.  */
                continue;
            }

            /* Reset the client request activity timeout.  */
            rtsp_client_ptr -> nx_rtsp_client_request_activity_timeout = NX_RTSP_SERVER_ACTIVITY_TIMEOUT;

            /* Set the pointer to the current Client request.  */
            rtsp_client_ptr -> nx_rtsp_client_request_ptr = &(rtsp_client_ptr -> nx_rtsp_client_request);

            /* Parse the client request.  */
            status = _nx_rtsp_server_request_parse(rtsp_client_ptr, rtsp_client_ptr -> nx_rtsp_client_request_ptr);

            /* Check for error status.  */
            if (status != NX_SUCCESS)
            {

                /* Release the request packet.  */
                nx_packet_release(rtsp_client_ptr -> nx_rtsp_client_request_packet);
                rtsp_client_ptr -> nx_rtsp_client_request_packet = NX_NULL;
                rtsp_client_ptr -> nx_rtsp_client_request_bytes_total = 0;

                /* Clear the pointer of Client request.  */
                rtsp_client_ptr -> nx_rtsp_client_request_ptr = NX_NULL;

                /* Just continue the loop and look at the next socket.  */
                continue;
            }

            /* Create the response packet.  */
            status = _nx_rtsp_server_response_create(rtsp_server_ptr, rtsp_client_ptr, rtsp_client_ptr -> nx_rtsp_client_request_ptr);

            /* Packet allocation failure.  */
            if (status != NX_SUCCESS)
            {

                /* There is nothing we can do here. Ideally log this error event.  */
                rtsp_server_ptr -> nx_rtsp_server_allocation_errors++;

                /* Release the request packet.  */
                nx_packet_release(rtsp_client_ptr -> nx_rtsp_client_request_packet);
                rtsp_client_ptr -> nx_rtsp_client_request_packet = NX_NULL;
                rtsp_client_ptr -> nx_rtsp_client_request_bytes_total = 0;

                /* Clear the pointer of Client request.  */
                rtsp_client_ptr -> nx_rtsp_client_request_ptr = NX_NULL;

                /* At this point, just continue the loop and look at the next socket.  */
                continue;
            }

            /* Set default response status code to 200 OK.  */
            rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_OK;

            switch (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_method)
            {
            case NX_RTSP_METHOD_OPTIONS:
            {

                /* OPTIONS is always allowed and supported.  */
                break;
            }
            case NX_RTSP_METHOD_DESCRIBE:
            {
                if (method_callbacks.nx_rtsp_server_method_describe_callback == NX_NULL)
                {

                    /* Method not installed, so we return "method not supported".  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED;

                    break;
                }

                /* Invoke the actual callback routine.  */
                status = method_callbacks.nx_rtsp_server_method_describe_callback
                         (rtsp_client_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_length);

                if (status != NX_SUCCESS)
                {

                    /* Internal error occurs.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_INTERNAL_SERVER_ERROR;
                }

                break;
            }
            case NX_RTSP_METHOD_SETUP:
            {

                /* The callbacks for SETUP, PLAY and TEARDOWN are required to be set and
                   we have checked this in _nx_rtsp_server_start() function.  */

                /* If session ID is present, we need to verify session ID.  */
                if (rtsp_client_ptr -> nx_rtsp_client_session_id &&
                    (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_session_id != rtsp_client_ptr -> nx_rtsp_client_session_id))
                {

                    /* Session not found.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;
                    break;
                }

                if (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr == NX_NULL)
                {

                    /* No media specified in the request. Invalid case.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;
                    break;
                }
                else if ((rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_transport.transport_mode == NX_RTSP_TRANSPORT_MODE_UNICAST) &&
                         ((rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_rtp_port == 0) ||
                          (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_transport.client_rtcp_port == 0)))
                {

                    /* Invalid client port.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_UNSUPPORTED_TRANSPORT;
                    break;
                }

                status = method_callbacks.nx_rtsp_server_method_setup_callback
                         (rtsp_client_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_length,
                          &(rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_transport));

                /* If callback returns "SUCCESS".  */
                if (status == NX_SUCCESS)
                {
                    if (rtsp_client_ptr -> nx_rtsp_client_state == NX_RTSP_STATE_INIT)
                    {

                        /* Set client state to ready.  */
                        rtsp_client_ptr -> nx_rtsp_client_state = NX_RTSP_STATE_READY;
                    }

                    if (rtsp_client_ptr -> nx_rtsp_client_session_id == 0)
                    {

                        /* Remember the session ID for future validation.  */
                        rtsp_client_ptr -> nx_rtsp_client_session_id = (ULONG)NX_RAND();
                    }
                }
                else
                {

                    /* Internal error occurs.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_INTERNAL_SERVER_ERROR;
                }

                break;
            }
            case NX_RTSP_METHOD_PLAY:
            {

                /* The callbacks for SETUP, PLAY and TEARDOWN are required to be set and
                   we have checked this in _nx_rtsp_server_start() function.  */

                if (!(rtsp_client_ptr -> nx_rtsp_client_session_id) ||
                    (rtsp_client_ptr -> nx_rtsp_client_session_id != rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_session_id))
                {

                    /* Session not found.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;

                    break;
                }

                if (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr == NX_NULL)
                {

                    /* No media specified in the request. Invalid case.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;
                    break;
                }

                /* Reset the npt start and end time.  */
                rtsp_client_ptr -> nx_rtsp_client_npt_start = 0;
                rtsp_client_ptr -> nx_rtsp_client_npt_end = 0;

                status = method_callbacks.nx_rtsp_server_method_play_callback
                         (rtsp_client_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_length,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_range_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_range_length);

                /* If callback returns "SUCCESS".  */
                if (status == NX_SUCCESS)
                {

                    /* Set client state to playing.  */
                    rtsp_client_ptr -> nx_rtsp_client_state = NX_RTSP_STATE_PLAYING;
                }
                else
                {

                    /* Internal error occurs.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_INTERNAL_SERVER_ERROR;
                }

                break;
            }
            case NX_RTSP_METHOD_PAUSE:
            {
                if (method_callbacks.nx_rtsp_server_method_pause_callback == NX_NULL)
                {

                    /* Method not installed, so we return "method not supported".  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED;

                    break;
                }

                /* Validate Session ID.  */
                if (!(rtsp_client_ptr -> nx_rtsp_client_session_id) ||
                    (rtsp_client_ptr -> nx_rtsp_client_session_id != rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_session_id))
                {

                    /* Session not found.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;

                    break;
                }

                if (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr == NX_NULL)
                {

                    /* No media specified in the request. Invalid case.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;
                    break;
                }

                /* Reset the npt start and end time.  */
                rtsp_client_ptr -> nx_rtsp_client_npt_start = 0;
                rtsp_client_ptr -> nx_rtsp_client_npt_end = 0;

                status = method_callbacks.nx_rtsp_server_method_pause_callback
                         (rtsp_client_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_length,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_range_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_range_length);

                /* If callback returns "SUCCESS".  */
                if (status == NX_SUCCESS)
                {

                    /* Set client state to ready.  */
                    rtsp_client_ptr -> nx_rtsp_client_state = NX_RTSP_STATE_READY;
                }
                else
                {

                    /* Internal error occurs.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_INTERNAL_SERVER_ERROR;
                }

                break;
            }
            case NX_RTSP_METHOD_TEARDOWN:
            {

                /* The callbacks for SETUP, PLAY and TEARDOWN are required to be set and
                   we have checked this in _nx_rtsp_server_start() function.  */

                /* Validate session ID.  */
                if (!(rtsp_client_ptr -> nx_rtsp_client_session_id) ||
                    (rtsp_client_ptr -> nx_rtsp_client_session_id != rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_session_id))
                {

                    /* Session not found.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;

                    break;
                }

                if (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr == NX_NULL)
                {

                    /* No media specified in the request. Invalid case.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;
                    break;
                }

                status = method_callbacks.nx_rtsp_server_method_teardown_callback
                         (rtsp_client_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_length);


                /* If got positive response from media handler.  */
                if (status == NX_SUCCESS)
                {

                    /* Set client state to init.  */
                    rtsp_client_ptr -> nx_rtsp_client_state = NX_RTSP_STATE_INIT;

                    /* Clear the session ID.  */
                    rtsp_client_ptr -> nx_rtsp_client_session_id = 0;
                }
                else
                {

                    /* Internal error occurs.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_INTERNAL_SERVER_ERROR;
                }

                break;
            }
            case NX_RTSP_METHOD_SET_PARAMETER:
            {
                if (method_callbacks.nx_rtsp_server_method_set_parameter_callback == NULL)
                {

                    /* Method not installed, so we return "method not supported".  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED;

                    break;
                }

                /* Validate session ID.  */
                if (!(rtsp_client_ptr -> nx_rtsp_client_session_id) ||
                    (rtsp_client_ptr -> nx_rtsp_client_session_id != rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_session_id))
                {

                    /* Session not found.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;

                    break;
                }

                if (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr == NX_NULL)
                {

                    /* No media specified in the request. Invalid case.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_SESSION_NOT_FOUND;
                    break;
                }

                status = method_callbacks.nx_rtsp_server_method_set_parameter_callback
                         (rtsp_client_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_ptr,
                          rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_uri_length,
                          (rtsp_client_ptr -> nx_rtsp_client_request_packet -> nx_packet_append_ptr - rtsp_client_ptr -> nx_rtsp_client_request_content_length),
                          rtsp_client_ptr -> nx_rtsp_client_request_content_length);

                /* If callback returns "SUCCESS".  */
                if (status)
                {

                    /* Internal error occurs.  */
                    rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_INTERNAL_SERVER_ERROR;
                }

                break;
            }
            default:
            {

                /* Method not installed, so we return "NOT IMPLEMENTED".  */
                rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code = NX_RTSP_STATUS_CODE_NOT_IMPLEMENTED;

                break;
            }
            }

            /* Send the response.  */
            if (rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code >= 300)
            {

                /* Handle error response.  */
                _nx_rtsp_server_error_response_send(rtsp_client_ptr, rtsp_client_ptr -> nx_rtsp_client_request_ptr -> nx_rtsp_client_request_response_code);
            }
            else
            {
                _nx_rtsp_server_response_send(rtsp_server_ptr, rtsp_client_ptr, rtsp_client_ptr -> nx_rtsp_client_request_ptr);
            }

            /* Release the request packet.  */
            nx_packet_release(rtsp_client_ptr -> nx_rtsp_client_request_packet);
            rtsp_client_ptr -> nx_rtsp_client_request_packet = NX_NULL;
            rtsp_client_ptr -> nx_rtsp_client_request_bytes_total = 0;

            /* Clear the pointer of Client request.  */
            rtsp_client_ptr -> nx_rtsp_client_request_ptr = NX_NULL;
        }
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_connect_process                     PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes connections for multiple sessions.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_tcp_server_socket_accept           Accept incoming TCP request   */
/*    nx_tcp_server_socket_unaccept         Clear accepted socket         */
/*    nx_tcp_server_socket_relisten         Re-listen on free socket      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_thread_entry                                        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_rtsp_server_connect_process(NX_RTSP_SERVER *rtsp_server_ptr)
{
UINT            i;
UINT            status;
NX_RTSP_CLIENT *client_ptr;


    /* One of the control ports is in the processing of connection.
       Search the connections to see which one.  */
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {

        /* Setup pointer to client structure.  */
        client_ptr =  &(rtsp_server_ptr -> nx_rtsp_server_client_list[i]);

        /* Now see if this socket was the one that is in being connected.  */
        if ((client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_state > NX_TCP_CLOSED) &&
            (client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_state < NX_TCP_ESTABLISHED) &&
            (client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_connect_port))
        {

            /* Yes, we have found the socket being connected.  */

            /* Attempt to accept on this socket.  */
            status = nx_tcp_server_socket_accept(&(client_ptr -> nx_rtsp_client_socket), NX_RTSP_SERVER_ACCEPT_TIMEOUT);

            /* Determine if it is successful.  */
            if (status)
            {

                /* Not successful, simply unaccept on this socket.  */
                nx_tcp_server_socket_unaccept(&(client_ptr -> nx_rtsp_client_socket));
            }
            else
            {

                /* Reset the client request activity timeout.  */
                client_ptr -> nx_rtsp_client_request_activity_timeout =  NX_RTSP_SERVER_ACTIVITY_TIMEOUT;

                /* Set the client as valid.  */
                client_ptr -> nx_rtsp_client_valid = NX_TRUE;

                /* Store the RTSP server pointer.  */
                client_ptr -> nx_rtsp_client_server_ptr = rtsp_server_ptr;

                /* Update the connected client count.  */
                rtsp_server_ptr -> nx_rtsp_server_connected_client_count++;
            }

            /* In any case break out of the loop when we find a connection - there can only be one
               at a time!  */
            break;
        }
    }

    /* Now look for a client that is valid to relisten on.  */
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {

        /* Setup pointer to client request structure.  */
        client_ptr =  &(rtsp_server_ptr -> nx_rtsp_server_client_list[i]);

        /* Now see if this socket is closed.  */
        if ((client_ptr -> nx_rtsp_client_valid == NX_FALSE) &&
            (client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_state == NX_TCP_CLOSED))
        {

            /* Relisten on this socket.  */
            status =  nx_tcp_server_socket_relisten(rtsp_server_ptr -> nx_rtsp_server_ip_ptr, rtsp_server_ptr -> nx_rtsp_server_port,
                                                    &(client_ptr -> nx_rtsp_client_socket));

            /* Check for bad status.  */
            if ((status != NX_SUCCESS) && (status != NX_CONNECTION_PENDING))
            {

                /* Increment the error count and keep trying.  */
                rtsp_server_ptr -> nx_rtsp_server_relisten_errors++;
                continue;
            }

            /* Break out of loop.  */
            break;
        }
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_disconnect_process                  PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes disconnect for multiple sessions.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_disconnect             Disconnect from client       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_thread_entry                                        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_rtsp_server_disconnect_process(NX_RTSP_SERVER *rtsp_server_ptr)
{
UINT            i;
NX_RTSP_CLIENT *rtsp_client_ptr;


    /* Examine all the client structures.  */
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {

        /* Setup pointer to client structure.  */
        rtsp_client_ptr =  &(rtsp_server_ptr -> nx_rtsp_server_client_list[i]);

        /* Determine if this socket is in a disconnect state.  */
        if (rtsp_client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_state > NX_TCP_ESTABLISHED)
        {

            /* Yes, this socket needs to be torn down.  */

            /* Increment the number of disconnection requests.  */
            rtsp_server_ptr -> nx_rtsp_server_disconnection_requests++;

            /* Disconnect the socket.  */
            _nx_rtsp_server_disconnect(rtsp_server_ptr, rtsp_client_ptr);
        }
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_timeout_process                     PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes timeout event.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtsp_server_disconnect             Disconnect from client       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_thread_entry                                        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_rtsp_server_timeout_process(NX_RTSP_SERVER *rtsp_server_ptr)
{
UINT            i;
NX_RTSP_CLIENT *rtsp_client_ptr;


    /* Examine all the client structures.  */
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {

        /* Setup pointer to client structure.  */
        rtsp_client_ptr =  &(rtsp_server_ptr -> nx_rtsp_server_client_list[i]);

        /* Skip the socket that is not used.  */
        if (rtsp_client_ptr -> nx_rtsp_client_socket.nx_tcp_socket_state <= NX_TCP_LISTEN_STATE)
        {
            continue;
        }

        /* Skip the inactive client.  */
        if (rtsp_client_ptr -> nx_rtsp_client_request_activity_timeout == 0)
        {
            continue;
        }

        /* Decrease the timer count.  */
        rtsp_client_ptr -> nx_rtsp_client_request_activity_timeout--;

        /* Check if the client is timeout.  */
        if (rtsp_client_ptr -> nx_rtsp_client_request_activity_timeout == 0)
        {

            /* Disconnect the socket.  */
            _nx_rtsp_server_disconnect(rtsp_server_ptr, rtsp_client_ptr);
        }
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_request_present                      PORTABLE C     */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles all RTSP client commands received on          */
/*    the control socket.                                                 */
/*                                                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    request_socket_ptr                    Socket event occurred         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_set                    Set events for server thread  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX                                  NetX receive packet callback  */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_rtsp_server_request_present(NX_TCP_SOCKET *request_socket_ptr)
{

NX_RTSP_SERVER *server_ptr;


    /* Pickup server pointer.  This is setup in the reserved field of the TCP socket.  */
    server_ptr = request_socket_ptr -> nx_tcp_socket_reserved_ptr;

    /* Set the request event flag.  */
    tx_event_flags_set(&(server_ptr -> nx_rtsp_server_event_flags), NX_RTSP_SERVER_REQUEST_EVENT, TX_OR);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_connect_present                      PORTABLE C     */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles all RTSP client connections received on       */
/*    the control socket.                                                 */
/*                                                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    request_socket_ptr                    Socket event occurred         */
/*    port                                  Port the connection occurred  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_set                    Set events for server thread  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX                                  NetX connect callback         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID  _nx_rtsp_server_connect_present(NX_TCP_SOCKET *request_socket_ptr, UINT port)
{
NX_RTSP_SERVER *server_ptr;


    NX_PARAMETER_NOT_USED(port);

    /* Pickup server pointer.  This is setup in the reserved field of the TCP socket.  */
    server_ptr =  request_socket_ptr -> nx_tcp_socket_reserved_ptr;

    /* Set the connect event flag.  */
    tx_event_flags_set(&(server_ptr -> nx_rtsp_server_event_flags), NX_RTSP_SERVER_CONNECT_EVENT, TX_OR);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_disconnect_present                   PORTABLE C     */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function notifies the RTSP server thread of client disconnects */
/*    of the control socket.                                              */
/*                                                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    request_socket_ptr                    Socket event occurred         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_set                    Set events for server thread  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX                                  NetX connect callback         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_rtsp_server_disconnect_present(NX_TCP_SOCKET *request_socket_ptr)
{
NX_RTSP_SERVER *server_ptr;


    /* Pickup server pointer.  This is setup in the reserved field of the TCP socket.  */
    server_ptr =  request_socket_ptr -> nx_tcp_socket_reserved_ptr;

    /* Set the disconnect event flag.  */
    tx_event_flags_set(&(server_ptr -> nx_rtsp_server_event_flags), NX_RTSP_SERVER_DISCONNECT_EVENT, TX_OR);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_timeout                              PORTABLE C     */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This internal function is invoked whenever the internal timeout     */
/*    timer expires, and is passed into tx_timer_create as the callback.  */
/*                                                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_address                   Pointer to RTSP server        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_set                    Set events for server thread  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    ThreadX                                                             */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_rtsp_server_timeout(ULONG rtsp_server_address)
{
NX_RTSP_SERVER *rtsp_server_ptr = (NX_RTSP_SERVER *)rtsp_server_address;


    /* Set the timeout event flag. */
    tx_event_flags_set(&(rtsp_server_ptr -> nx_rtsp_server_event_flags), NX_RTSP_SERVER_TIMEOUT_EVENT, TX_OR);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtsp_server_disconnect                           PORTABLE C     */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function disconnects a client which is disconnected or timeout.*/
/*                                                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtsp_server_ptr                       Pointer to RTSP server        */
/*    rtsp_client_ptr                       Pointer to RTSP client        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_tcp_socket_disconnect              Disconnect TCP socket         */
/*    nx_tcp_server_socket_unaccept         Clear accepted socket         */
/*    nx_packet_release                     Release the packet            */
/*    nx_tcp_server_socket_relisten         Re-listen on free socket      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtsp_server_disconnect_process                                  */
/*    _nx_rtsp_server_timeout_process                                     */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Wenhui Xie               Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_rtsp_server_disconnect(NX_RTSP_SERVER *rtsp_server_ptr, NX_RTSP_CLIENT *rtsp_client_ptr)
{

    /* Disable the client request activity timeout.  */
    rtsp_client_ptr -> nx_rtsp_client_request_activity_timeout = 0;

    /* Now disconnect the socket.  */
    nx_tcp_socket_disconnect(&(rtsp_client_ptr -> nx_rtsp_client_socket), NX_NO_WAIT);

    /* Unaccept the server socket.  */
    nx_tcp_server_socket_unaccept(&(rtsp_client_ptr -> nx_rtsp_client_socket));

    /* Check to see if a packet is queued up.  */
    if (rtsp_client_ptr -> nx_rtsp_client_request_packet)
    {

        /* Yes, release it!  */
        nx_packet_release(rtsp_client_ptr -> nx_rtsp_client_request_packet);
        rtsp_client_ptr -> nx_rtsp_client_request_packet = NX_NULL;
        rtsp_client_ptr -> nx_rtsp_client_request_bytes_total = 0;
    }

    /* Check to see if a packet is queued up.  */
    if (rtsp_client_ptr -> nx_rtsp_client_response_packet)
    {

        /* Yes, release it!  */
        nx_packet_release(rtsp_client_ptr -> nx_rtsp_client_response_packet);
        rtsp_client_ptr -> nx_rtsp_client_response_packet = NX_NULL;
    }

    /* Invoke the disconnect callback.  */
    if ((rtsp_server_ptr -> nx_rtsp_server_disconnect_callback) &&
        (rtsp_client_ptr -> nx_rtsp_client_state > NX_RTSP_STATE_INIT))
    {
        rtsp_server_ptr -> nx_rtsp_server_disconnect_callback(rtsp_client_ptr);
    }

    /* Relisten on this socket.  */
    nx_tcp_server_socket_relisten(rtsp_server_ptr -> nx_rtsp_server_ip_ptr, rtsp_server_ptr -> nx_rtsp_server_port,
                                  &(rtsp_client_ptr -> nx_rtsp_client_socket));

    /* Clear the session ID.  */
    rtsp_client_ptr -> nx_rtsp_client_session_id = 0;

    /* Reset client valid status.  */
    rtsp_client_ptr -> nx_rtsp_client_valid = NX_FALSE;

    /* Reset client state.  */
    rtsp_client_ptr -> nx_rtsp_client_state = NX_RTSP_STATE_INIT;

    /* Update the connected client count.  */
    rtsp_server_ptr -> nx_rtsp_server_connected_client_count--;
}

