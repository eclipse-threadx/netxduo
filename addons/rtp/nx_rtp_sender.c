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

#define NX_RTP_SENDER_SOURCE_CODE

/* Include necessary system files.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_ip.h"
#ifdef FEATURE_NX_IPV6
#include    "nx_ipv6.h"
#endif /* FEATURE_NX_IPV6 */
#include    "nx_udp.h"
#include    "nx_rtp_sender.h"


/* Define JPEG quantization table parameters. */
#define NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_MAX_NUM       (4)
#define NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_LENGTH        (64)

/* Define H264 parameters. */
#define NX_RTP_SENDER_H264_NRI_MASK_BITS                    (0x60)  /* The mask bits of relative transport priority. */
#define NX_RTP_SENDER_H264_TYPE_MASK_BITS                   (0x1F)  /* The mask bits of NAL unit type.*/
#define NX_RTP_SENDER_H264_TYPE_SEI                         (6)
#define NX_RTP_SENDER_H264_TYPE_SPS                         (7)
#define NX_RTP_SENDER_H264_TYPE_PPS                         (8)
#define NX_RTP_SENDER_H264_TYPE_FU_A                        (28)
#define NX_RTP_SENDER_H264_FU_A_S_MASK_BIT                  (0x80)
#define NX_RTP_SENDER_H264_FU_A_E_MASK_BIT                  (0x40)

/* Define AAC parameters. */
#define NX_RTP_SENDER_AAC_HBR_MODE_MAX_DATA_SIZE            (8191) /* RFC 3640, p25, section 3.3.6. */
#define NX_RTP_SENDER_AAC_FRAME_DATA_LENGTH_HIGH_BITS_MASK  (0x1FE0)
#define NX_RTP_SENDER_AAC_FRAME_DATA_LENGTH_LOW_BITS_MASK   (0x1F)

/* Declare rtp sender internal functions */
static UINT _nx_rtp_sender_cleanup(NX_RTP_SENDER *rtp_sender);
static UINT _nx_rtp_sender_session_find(NX_RTP_SENDER *rtp_sender, UINT ssrc, NX_RTP_SESSION **session);
static VOID _nx_rtp_sender_session_link(NX_RTP_SENDER *rtp_sender, NX_RTP_SESSION *session);
static UINT _nx_rtp_sender_session_unlink(NX_RTP_SENDER *rtp_sender, NX_RTP_SESSION *session);

static UINT _nx_rtcp_packet_process(NX_RTP_SENDER *rtp_sender, NX_PACKET *packet_ptr);
static UINT _nx_rtcp_packet_rr_process(NX_RTP_SENDER *rtp_sender, NX_RTCP_HEADER *header);
static UINT _nx_rtcp_packet_sdes_process(NX_RTP_SENDER *rtp_sender, NX_RTCP_HEADER *header);
static UINT _nx_rtcp_sr_data_append(NX_RTP_SESSION *session, NX_PACKET *packet_ptr);
static UINT _nx_rtcp_sdes_data_append(NX_RTP_SESSION *session, NX_PACKET *packet_ptr);
static UINT _nx_rtcp_packet_send(NX_RTP_SESSION *session);
static VOID _nx_rtcp_packet_receive_notify(NX_UDP_SOCKET *socket_ptr);


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_create                             PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender create function call. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                           Pointer to RTP Sender instance */
/*    ip_ptr                               Pointer to IP instance         */
/*    pool_ptr                             Pointer to the packet pool     */
/*    cname                                Pointer to the name string     */
/*                                           shown in rtcp SDES report    */
/*    cname_length                         The length of the name string  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_create                Create rtp sender              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_create(NX_RTP_SENDER *rtp_sender, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, CHAR *cname, UCHAR cname_length)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((rtp_sender == NX_NULL) || (ip_ptr == NX_NULL) || (pool_ptr == NX_NULL) || (rtp_sender -> nx_rtp_sender_id == NX_RTP_SENDER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender create service. */
    status = _nx_rtp_sender_create(rtp_sender, ip_ptr, pool_ptr, cname, cname_length);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_create                               PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates a RTP sender on the specified IP.             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                           Pointer to RTP Sender instance */
/*    ip_ptr                               Pointer to IP instance         */
/*    pool_ptr                             Pointer to the packet pool     */
/*    cname                                Pointer to the name string     */
/*                                           shown in rtcp SDES report    */
/*    cname_length                         The length of the name string  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                               Reset memory                   */
/*    tx_mutex_create                      Create RTP sender mutex        */
/*    tx_mutex_delete                      Delete RTP sender mutex        */
/*    nx_udp_socket_create                 Create RTP sender UDP socket   */
/*    nx_udp_socket_delete                 Delete RTP sender UDP socket   */
/*    nx_udp_free_port_find                Find a free UDP port for RTP   */
/*                                           or RTCP socket               */
/*    nx_udp_socket_bind                   Bind a UDP port for RTP        */
/*                                           or RTCP socket               */
/*    nx_udp_socket_unbind                 Unbind UDP port for RTP socket */
/*    _nx_rtp_sender_cleanup               Clean-up resources             */
/*    nx_udp_socket_receive_notify         Set callback function for UDP  */
/*                                           data receive notify          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_create(NX_RTP_SENDER *rtp_sender, NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, CHAR *cname, UCHAR cname_length)
{

UINT status;
UINT free_port;


    /* Reset the rtp_sender data structure. */
    memset(rtp_sender, 0, sizeof(NX_RTP_SENDER));

    /* Create mutex protection. */
    status = tx_mutex_create(&(rtp_sender -> nx_rtp_sender_protection), "RTP sender protection", TX_INHERIT);
    if (status)
    {
        return(status);
    }

    /* Create RTP UDP socket. */
    status = nx_udp_socket_create(ip_ptr, &(rtp_sender -> nx_rtp_sender_rtp_socket), "RTP Socket",
                                  NX_RTP_SENDER_TYPE_OF_SERVICE, NX_RTP_SENDER_FRAGMENT_OPTION,
                                  NX_RTP_SENDER_TIME_TO_LIVE, NX_RTP_SENDER_QUEUE_DEPTH);
    if (status)
    {

        /* Delete already created resources and return error status. */
        tx_mutex_delete(&(rtp_sender -> nx_rtp_sender_protection));
        return(status);
    }

    /* Create RTCP UDP socket. */
    status = nx_udp_socket_create(ip_ptr, &(rtp_sender -> nx_rtp_sender_rtcp_socket), "RTCP Socket",
                                  NX_RTP_SENDER_TYPE_OF_SERVICE, NX_RTP_SENDER_FRAGMENT_OPTION,
                                  NX_RTP_SENDER_TIME_TO_LIVE, NX_RTP_SENDER_QUEUE_DEPTH);
    if (status)
    {

        /* Delete already created resources and return error status. */
        tx_mutex_delete(&(rtp_sender -> nx_rtp_sender_protection));
        nx_udp_socket_delete(&(rtp_sender -> nx_rtp_sender_rtp_socket));
        return(status);
    }

    /* Start from the suggested default port number. */
    rtp_sender -> nx_rtp_sender_rtp_port = NX_RTP_SENDER_INITIAL_RTP_PORT;

    while (1)
    {

        /* Try to find an available port for RTP. */
        status = nx_udp_free_port_find(ip_ptr, rtp_sender -> nx_rtp_sender_rtp_port, &free_port);
        if (status)
        {
            break;
        }
        else if (rtp_sender -> nx_rtp_sender_rtp_port > free_port)
        {

            /* Return since there will be no even number port obtained. */
            status = NX_NO_FREE_PORTS;
            break;
        }

        /* Check if free_port is an odd number. */
        if ((free_port & 1) != 0)
        {

            /* Check if the found free port reaches maximum. */
            if (free_port == NX_MAX_PORT)
            {

                /* Return since there will be no even number port obtained. */
                status = NX_NO_FREE_PORTS;
                break;
            }

            /* Free UDP port is not the one we expected for RTP. Move to the next port number and try again. */
            rtp_sender -> nx_rtp_sender_rtp_port = (USHORT)(free_port + 1);
        }
        else
        {

            /* Set RTP port. */
            rtp_sender -> nx_rtp_sender_rtp_port = (USHORT)free_port;
        }

        /* Both RTP and RTCP ports are available. Now do a real RTP bind. */
        status = nx_udp_socket_bind(&(rtp_sender -> nx_rtp_sender_rtp_socket), rtp_sender -> nx_rtp_sender_rtp_port, NX_NO_WAIT);
        if (status == NX_SUCCESS)
        {

            /* RTP socket was bound successfully. Now try RTCP socket. */

            /* Set RTCP port to be the next odd port of RTP port and bind. */
            rtp_sender -> nx_rtp_sender_rtcp_port = (USHORT)(rtp_sender -> nx_rtp_sender_rtp_port + 1);
            status = nx_udp_socket_bind(&(rtp_sender -> nx_rtp_sender_rtcp_socket), rtp_sender -> nx_rtp_sender_rtcp_port, NX_NO_WAIT);
            if (status == NX_SUCCESS)
            {

                /* Jump out since both ports are found. */
                break;
            }

            /* RTCP port is unavailable. Unbind the RTP port and try again. */
            nx_udp_socket_unbind(&(rtp_sender -> nx_rtp_sender_rtp_socket));
        }

        /* Move and check next possible even port. */
        rtp_sender -> nx_rtp_sender_rtp_port = (USHORT)(rtp_sender -> nx_rtp_sender_rtp_port + 2);
        if (rtp_sender -> nx_rtp_sender_rtp_port == 0)
        {
            status = NX_NO_FREE_PORTS;
            break;
        }
    }

    /* Clean-up generated resources if fails to find a rtp/rtcp port pair. */
    if (status)
    {
        _nx_rtp_sender_cleanup(rtp_sender);
        return(status);
    }

    /* Store pool pointer. */
    rtp_sender -> nx_rtp_sender_packet_pool_ptr = pool_ptr;

    /* Set application-specific filed indicating the socket is associated with this RTP sender instance. */
    rtp_sender -> nx_rtp_sender_rtcp_socket.nx_udp_socket_reserved_ptr = (void *)rtp_sender;

    /* Install RTCP callback. */
    nx_udp_socket_receive_notify(&(rtp_sender -> nx_rtp_sender_rtcp_socket), _nx_rtcp_packet_receive_notify);

    /* Update rtp variables. */
    rtp_sender -> nx_rtp_sender_id = NX_RTP_SENDER_ID;
    rtp_sender -> nx_rtp_sender_ip_ptr = ip_ptr;
    rtp_sender -> nx_rtp_sender_cname = cname;
    rtp_sender -> nx_rtp_sender_cname_length = cname_length;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_delete                             PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender delete function call. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                           Pointer to RTP Sender instance */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_delete                Delete RTP sender              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_delete(NX_RTP_SENDER *rtp_sender)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((rtp_sender == NX_NULL) || (rtp_sender -> nx_rtp_sender_id != NX_RTP_SENDER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender delete service. */
    status = _nx_rtp_sender_delete(rtp_sender);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_delete                              PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deletes a previous created RTP sender                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                           Pointer to RTP Sender instance */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_DELETE_ERROR                      Fail to delete RTP sender      */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                         Obtain protection mutex        */
/*    tx_mutex_put                         Release protection mutex       */
/*    _nx_rtp_sender_cleanup               Clean-up resources             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_delete(NX_RTP_SENDER *rtp_sender)
{

    /* Obtain the mutex. */
    tx_mutex_get(&(rtp_sender -> nx_rtp_sender_protection), TX_WAIT_FOREVER);

    /* rtp sender can only be deleted when all sessions have been deleted. */
    if (rtp_sender -> nx_rtp_sender_session_created_ptr)
    {

        /* Release the mutex and return error status. */
        tx_mutex_put(&(rtp_sender -> nx_rtp_sender_protection));
        return(NX_DELETE_ERROR);
    }

    /* Set the id to be 0 to make sure other api functions (except create) cannot execute after deleting. */
    rtp_sender -> nx_rtp_sender_id = 0;

    /* Release the mutex */
    tx_mutex_put(&(rtp_sender -> nx_rtp_sender_protection));

    /* Clean-up all generated resources. */
    _nx_rtp_sender_cleanup(rtp_sender);

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_port_get                           PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender port get function     */
/*    call.                                                               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                           Pointer to RTP Sender instance */
/*    rtp_port                             Pointer to returned RTP port   */
/*    rtcp_port                            Pointer to returned RTCP port  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_port_get              Get the bound RTP port and     */
/*                                           RTCP port in RTP sender      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_port_get(NX_RTP_SENDER *rtp_sender, UINT *rtp_port, UINT *rtcp_port)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((rtp_sender == NX_NULL) || (rtp_sender -> nx_rtp_sender_id != NX_RTP_SENDER_ID) ||
        (rtp_port == NX_NULL) || (rtcp_port == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender port get service. */
    status = _nx_rtp_sender_port_get(rtp_sender, rtp_port, rtcp_port);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_port_get                            PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function returns bound RTP and RTCP port pair in RTP sender.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                           Pointer to RTP Sender instance */
/*    rtp_port                             Pointer to returned RTP port   */
/*    rtcp_port                            Pointer to returned RTCP port  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                           Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_port_get              Get the bound RTP port and     */
/*                                           RTCP port in RTP sender      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_port_get(NX_RTP_SENDER *rtp_sender, UINT *rtp_port, UINT *rtcp_port)
{

    /* Set RTP port and RTCP port. */
    *rtp_port = rtp_sender -> nx_rtp_sender_rtp_port;
    *rtcp_port = rtp_sender -> nx_rtp_sender_rtcp_port;

    /* All done. Return success code. */
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_create                     PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session create        */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                           Pointer to RTP Sender instance */
/*    session                              Pointer to RTP session         */
/*    payload_type                         Payload type number            */
/*    interface_index                      IP interface index             */
/*    receiver_ip_address                  The receiver's IP address      */
/*    receiver_rtp_port_number             The receiver's RTP port        */
/*    receiver_rtcp_port_number            The receiver's RTCP port       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_create        Create RTP session with        */
/*                                           specific arguments           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_create(NX_RTP_SENDER *rtp_sender, NX_RTP_SESSION *session, ULONG payload_type,
                                    UINT interface_index, NXD_ADDRESS *receiver_ip_address,
                                    UINT receiver_rtp_port_number, UINT receiver_rtcp_port_number)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((rtp_sender == NX_NULL) || (rtp_sender -> nx_rtp_sender_id != NX_RTP_SENDER_ID) ||
        (session == NX_NULL) || (session -> nx_rtp_session_id == NX_RTP_SESSION_ID) ||
        (receiver_ip_address == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    if (interface_index >= NX_MAX_PHYSICAL_INTERFACES)
    {
        return(NX_INVALID_INTERFACE);
    }

    /* Call actual RTP sender session create service. */
    status = _nx_rtp_sender_session_create(rtp_sender, session, payload_type,
                                           interface_index, receiver_ip_address,
                                           receiver_rtp_port_number, receiver_rtcp_port_number);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_create                      PORTABLE C       */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates a RTP session with specific arguments.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                           Pointer to RTP Sender instance */
/*    session                              Pointer to RTP session         */
/*    payload_type                         Payload type number            */
/*    interface_index                      IP interface index             */
/*    receiver_ip_address                  The receiver's IP address      */
/*    receiver_rtp_port_number             The receiver's RTP port        */
/*    receiver_rtcp_port_number            The receiver's RTCP port       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                           Completion status              */
/*    NX_INVALID_PARAMETERS                Payload type out of range      */
/*    NX_IP_ADDRESS_ERROR                  Unsupported IP version         */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                               Reset memory                   */
/*    COPY_IPV6_ADDRESS                    Make a copy of an IPv6 address */
/*    NX_RAND                              Generate a random number       */
/*    tx_mutex_get                         Obtain protection mutex        */
/*    tx_mutex_put                         Release protection mutex       */
/*    _nx_rtp_sender_session_link          Link the created session into  */
/*                                           RTP sender control block     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*  12-31-2023     Haiqing Zhao            Modified comments(s),          */
/*                                           supported VLAN,              */
/*                                           resulting in version 6.4.0   */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_create(NX_RTP_SENDER *rtp_sender, NX_RTP_SESSION *session, ULONG payload_type,
                                   UINT interface_index, NXD_ADDRESS *receiver_ip_address,
                                   UINT receiver_rtp_port_number, UINT receiver_rtcp_port_number)
{

    /* Check and validate rtp payload type with valid range from 0 to 127 (7 bits). */
    if (payload_type > 127)
    {
        return(NX_INVALID_PARAMETERS);
    }

    /* Reset rtp session members. */
    memset(session, 0, sizeof(NX_RTP_SESSION));

    /* Record peer's ip address and rtp/rtcp port pair. */
    session -> nx_rtp_session_peer_ip_address.nxd_ip_version = receiver_ip_address -> nxd_ip_version;

    /* Store the receiver's ip interface index into the session. */
    session -> nx_rtp_session_interface_index = interface_index;

    if (receiver_ip_address -> nxd_ip_version == NX_IP_VERSION_V4)
    {
#ifndef NX_DISABLE_IPV4
        session -> nx_rtp_session_peer_ip_address.nxd_ip_address.v4 = receiver_ip_address -> nxd_ip_address.v4;

        /* Compute the maximum frame packet length based on mtu size. */
        session -> nx_rtp_session_max_packet_size = rtp_sender -> nx_rtp_sender_ip_ptr -> nx_ip_interface[interface_index].nx_interface_ip_mtu_size
                                                  - sizeof(NX_UDP_HEADER) - NX_RTP_HEADER_LENGTH - sizeof(NX_IPV4_HEADER);
#else
        return(NX_IP_ADDRESS_ERROR);
#endif /* NX_DISABLE_IPV4 */
    }
    else if (receiver_ip_address -> nxd_ip_version == NX_IP_VERSION_V6)
    {
#ifdef FEATURE_NX_IPV6
        COPY_IPV6_ADDRESS(receiver_ip_address -> nxd_ip_address.v6, session -> nx_rtp_session_peer_ip_address.nxd_ip_address.v6);

        /* Compute the maximum frame packet length based on mtu size. */
        session -> nx_rtp_session_max_packet_size = rtp_sender -> nx_rtp_sender_ip_ptr -> nx_ip_interface[interface_index].nx_interface_ip_mtu_size
                                                  - sizeof(NX_UDP_HEADER) - NX_RTP_HEADER_LENGTH - sizeof(NX_IPV6_HEADER);
#else
        return(NX_IP_ADDRESS_ERROR);
#endif /* #ifdef FEATURE_NX_IPV6 */
    }
    else
    {
        return(NX_IP_ADDRESS_ERROR);
    }

    /* Store the receiver's rtp/rtcp ports number. */
    session -> nx_rtp_session_peer_rtp_port = (USHORT)receiver_rtp_port_number;
    session -> nx_rtp_session_peer_rtcp_port = (USHORT)receiver_rtcp_port_number;

    /* Record session payload type. */
    session -> nx_rtp_session_payload_type = (UCHAR)(payload_type);

    /* Generate random values for the ssrc and sequence number. */
    session -> nx_rtp_session_ssrc = (ULONG)NX_RAND();
    session -> nx_rtp_session_sequence_number = (USHORT)NX_RAND();

    /* Record the rtp sender pointer in the session. */
    session -> nx_rtp_sender = rtp_sender;

    /* Obtain the mutex */
    tx_mutex_get(&(rtp_sender -> nx_rtp_sender_protection), TX_WAIT_FOREVER);

    _nx_rtp_sender_session_link(rtp_sender, session);

    /* Release the mutex and return success status. */
    tx_mutex_put(&(rtp_sender -> nx_rtp_sender_protection));

#ifdef NX_ENABLE_VLAN
    /* Initialize session vlan priority. */
    session -> nx_rtp_session_vlan_priority = NX_VLAN_PRIORITY_INVALID;
#endif /* NX_ENABLE_VLAN */

    /* Set session magic number to indicate the session is created successfully. */
    session -> nx_rtp_session_id = NX_RTP_SESSION_ID;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_delete                     PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the rtp sender session delete        */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_delete        Delete RTP session             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_delete(NX_RTP_SESSION *session)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_sender == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender session delete service. */
    status = _nx_rtp_sender_session_delete(session);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_delete                      PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deletes a RTP session.                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                           Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                         Obtain protection mutex        */
/*    tx_mutex_put                         Release protection mutex       */
/*    _nx_rtp_sender_session_unlink        Unlink the session from        */
/*                                           RTP sender control block     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_delete(NX_RTP_SESSION *session)
{

    /* Reset the rtp session id. */
    session -> nx_rtp_session_id = 0;

    /* Obtain the mutex. */
    tx_mutex_get(&(session -> nx_rtp_sender -> nx_rtp_sender_protection), TX_WAIT_FOREVER);

    _nx_rtp_sender_session_unlink(session -> nx_rtp_sender, session);

    /* Release the mutex and return success status. */
    tx_mutex_put(&(session -> nx_rtp_sender -> nx_rtp_sender_protection));
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_rtcp_receiver_report_callback_set   PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in rtcp receiver report callback set    */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    rtcp_rr_cb                            Application specified         */
/*                                            callback function           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_rtcp_receiver_report_callback_set                    */
/*                                          Set RTCP RR packet receive    */
/*                                            notify function             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_rtcp_receiver_report_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_rr_cb)(NX_RTP_SESSION *, NX_RTCP_RECEIVER_REPORT *))
{

UINT status;


    /* Validate user input parameter. */
    if ((rtp_sender == NX_NULL) || (rtp_sender -> nx_rtp_sender_id != NX_RTP_SENDER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender rtcp receiver report callback service. */
    status = _nx_rtp_sender_rtcp_receiver_report_callback_set(rtp_sender, rtcp_rr_cb);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_rtcp_receiver_report_callback_set    PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets a callback routine for RTCP RR packet receive    */
/*    notification. If a NULL pointer is supplied the receive notify      */
/*    function is disabled. Note that this callback function is invoked   */
/*    from the IP thread, Application shall not block the thread.         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    rtcp_rr_cb                            Application specified         */
/*                                            callback function           */
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
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_rtcp_receiver_report_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_rr_cb)(NX_RTP_SESSION *, NX_RTCP_RECEIVER_REPORT *))
{
    rtp_sender -> nx_rtp_sender_rtcp_receiver_report_cb = rtcp_rr_cb;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_rtcp_sdes_callback_set              PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in rtcp sdes callback set function call.*/
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    rtcp_sdes_cb                          Application specified         */
/*                                            callback function           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_rtcp_sdes_callback_set Set RTCP SDES packet receive  */
/*                                            notify function             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_rtcp_sdes_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_sdes_cb)(NX_RTCP_SDES_INFO *))
{

UINT status;


    /* Validate user input parameter. */
    if ((rtp_sender == NX_NULL) || (rtp_sender -> nx_rtp_sender_id != NX_RTP_SENDER_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender rtcp sdes callback service. */
    status = _nx_rtp_sender_rtcp_sdes_callback_set(rtp_sender, rtcp_sdes_cb);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_rtcp_sdes_callback_set               PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets a callback routine for RTCP SDES packet receive  */
/*    notification. If a NULL pointer is supplied the receive notify      */
/*    function is disabled. Note that this callback function is invoked   */
/*    from the IP thread, Application shall not block the thread.         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    rtcp_sdes_cb                          Application specified         */
/*                                            callback function           */
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
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_rtcp_sdes_callback_set(NX_RTP_SENDER *rtp_sender, UINT (*rtcp_sdes_cb)(NX_RTCP_SDES_INFO *))
{
    rtp_sender -> nx_rtp_sender_rtcp_sdes_cb = rtcp_sdes_cb;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_packet_allocate            PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session packet        */
/*    allocate function call.                                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    packet_ptr                           Pointer to allocated packet    */
/*    wait_option                          Suspension option              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_packet_allocate                              */
/*                                         Allocate a packet for the user */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_packet_allocate(NX_RTP_SESSION *session, NX_PACKET **packet_ptr, ULONG wait_option)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_sender == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID) || (packet_ptr == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender session packet allocate service. */
    status = _nx_rtp_sender_session_packet_allocate(session, packet_ptr, wait_option);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_packet_allocate             PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function allocate a RTP packet from the packet pool given      */
/*    by rtp_sender_create, and returns this packet to the user.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    packet_ptr                           Pointer to allocated packet    */
/*    wait_option                          Suspension option              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                   Allocate a new packet          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_packet_allocate(NX_RTP_SESSION *session, NX_PACKET **packet_ptr, ULONG wait_option)
{

UINT status;


    /* Allocate and get the packet from IP default packet pool. */
    status = nx_packet_allocate(session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, packet_ptr, NX_RTP_PACKET, wait_option);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_packet_send                PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session packet send   */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    packet_ptr                           Pointer to packet data to send */
/*    timestamp                            RTP timestamp for current data */
/*    ntp_msw                              Most significant word of       */
/*                                           network time                 */
/*    ntp_lsw                              Least significant word of      */
/*                                           network time                 */
/*    marker                               Marker bit for significant     */
/*                                           event such as frame boundary */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_packet_send   Send packet data               */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_packet_send(NX_RTP_SESSION *session, NX_PACKET *packet_ptr, ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_sender == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID) || (packet_ptr == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Check for an invalid packet prepend pointer.  */
    if ((INT)(packet_ptr -> nx_packet_prepend_ptr - packet_ptr -> nx_packet_data_start) < (INT)(NX_RTP_PACKET))
    {
        return(NX_UNDERFLOW);
    }

    /* Call actual RTP sender session packet send service. */
    status = _nx_rtp_sender_session_packet_send(session, packet_ptr, timestamp, ntp_msw, ntp_lsw, marker);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_packet_send                 PORTABLE C       */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends passed packet data in RTP format, and calls     */
/*    RTP sender rctp send function as the entry to send RTCP report      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    packet_ptr                           Pointer to packet data to send */
/*    timestamp                            RTP timestamp for current data */
/*    ntp_msw                              Most significant word of       */
/*                                           network time                 */
/*    ntp_lsw                              Least significant word of      */
/*                                           network time                 */
/*    marker                               Marker bit for significant     */
/*                                           event such as frame boundary */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    NX_CHANGE_USHORT_ENDIAN              Adjust USHORT variable endian  */
/*    _nx_rtcp_packet_send                 Send RTCP report               */
/*    nxd_udp_socket_source_send           Send RTP packet through UDP    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*  12-31-2023     Haiqing Zhao            Modified comments(s),          */
/*                                           supported VLAN,              */
/*                                           resulting in version 6.4.0   */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_packet_send(NX_RTP_SESSION *session, NX_PACKET *packet_ptr, ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker)
{

UINT           status;
NX_RTP_HEADER *rtp_header_ptr;
NX_PACKET     *send_packet;
NX_PACKET     *data_packet = packet_ptr;
UCHAR         *data_ptr = data_packet -> nx_packet_prepend_ptr;
UINT           sample_factor = session -> nx_rtp_session_sample_factor;
ULONG          fragment_size = session -> nx_rtp_session_max_packet_size;
ULONG          remaining_bytes = packet_ptr -> nx_packet_length;
ULONG          payload_data_length;
ULONG          copy_size;
UINT           fragmentation = NX_FALSE;


    /* Transfer marker bit into rtp header field. */
    if (marker)
    {
        marker = (UINT)NX_RTP_HEADER_MARKER_BIT;
    }

    /* Compare and set the fragmentation flag. */
    if (packet_ptr -> nx_packet_length > fragment_size)
    {
        fragmentation = NX_TRUE;
    }

    while (remaining_bytes)
    {
        if (fragmentation == NX_FALSE)
        {

            /* No fragmentation needed, set send packet to user passed packet directly. */
            send_packet = packet_ptr;
        }
        else
        {

            /* Allocate a rtp packet for fragmentation. */
            status = _nx_rtp_sender_session_packet_allocate(session, &send_packet, NX_RTP_SENDER_PACKET_TIMEOUT);
            if (status)
            {
                return(status);
            }

            /* Copy data. */
            while (send_packet -> nx_packet_length < fragment_size)
            {

                /* Compute how many data bytes to copy in the current packet. */
                copy_size = (ULONG)(data_packet -> nx_packet_append_ptr - data_ptr);
                if ((send_packet -> nx_packet_length + copy_size) > fragment_size)
                {

                    /* Compute copy size with the remaining packet space in the send packet. */
                    copy_size = fragment_size - send_packet -> nx_packet_length;
                }

                /* Copy data into the send packet. */
                status = nx_packet_data_append(send_packet, data_ptr, copy_size, session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_RTP_SENDER_PACKET_TIMEOUT);
                if (status)
                {

                    /* Release the allocated send packet and return error status. */
                    nx_packet_release(send_packet);
                    return(status);
                }

                /* Move the data pointer after a success copy. */
                data_ptr += copy_size;

                /* Make sure all data in current packet finish copying. */
                if (data_ptr >= data_packet -> nx_packet_append_ptr)
                {
                    if (data_packet -> nx_packet_next == NX_NULL)
                    {

                        /* Jump out current while loop when finding all data packets finish copying. */
                        break;
                    }
                    else
                    {

                        /* Move to the next packet. */
                        data_packet = data_packet -> nx_packet_next;

                        /* Move the data pointer to the initial position of the next packet. */
                        data_ptr = data_packet -> nx_packet_prepend_ptr;
                    }
                }
            }
        }

        /* Obtain payload data length and decrease remaining bytes with it. */
        payload_data_length = send_packet -> nx_packet_length;
        remaining_bytes -= payload_data_length;

        /* Add rtp header information.
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |V=2|P|X|  CC   |M|     PT      | sequence number               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                           timestamp                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           synchronization source (SSRC) identifier            |
            +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
        */

        /* Update the overall packet length, assign rtp_header pointer to the initial position. */
        send_packet -> nx_packet_length += NX_RTP_HEADER_LENGTH;
        send_packet -> nx_packet_prepend_ptr -= NX_RTP_HEADER_LENGTH;
        rtp_header_ptr = (NX_RTP_HEADER *)(send_packet -> nx_packet_prepend_ptr);

        /* Fill field 0 which contains following 4 sub-fields (3 of them are considered no need to support so far).
        1) The RTP protocol version number is always 2.
        2) The padding feature is ignored (i.e not supported) by using lower level padding if required (e.g. tls)
        3) The extension bit/feature is set to zero (i.e. not supported)
        4) The contributing source identifiers count is set to zero (i.e. not supported) */
        rtp_header_ptr -> nx_rtp_header_field0 = (NX_RTP_VERSION << 6);

        /* Fill the second byte by the payload type recorded in the session context. */
        rtp_header_ptr -> nx_rtp_header_field1 = session -> nx_rtp_session_payload_type;

        /* Set the marker bit which is intended to allow significant events such as frame boundaries to be marked in the packet stream.
           This is a user selectable flag and allow the user to choose whether to set it. */
        if ((remaining_bytes == 0) || (sample_factor))
        {
            rtp_header_ptr -> nx_rtp_header_field1 |= (UCHAR)marker;
        }

        /* Fill the sequence number from the session context, convert it from host byte order to network byte order. Increase recorded sequence number by 1. */
        rtp_header_ptr -> nx_rtp_header_sequence_number = session -> nx_rtp_session_sequence_number;
        NX_CHANGE_USHORT_ENDIAN(rtp_header_ptr -> nx_rtp_header_sequence_number);
        session -> nx_rtp_session_sequence_number++;

        /* Fill the timestamp passed as an argument from the user, convert it from host byte order to network byte order. */
        rtp_header_ptr -> nx_rtp_header_timestamp = timestamp;
        NX_CHANGE_ULONG_ENDIAN(rtp_header_ptr -> nx_rtp_header_timestamp);

        /* Fill the ssrc from the session context, convert it from host byte order to network byte order. */
        rtp_header_ptr -> nx_rtp_header_ssrc = session -> nx_rtp_session_ssrc;
        NX_CHANGE_ULONG_ENDIAN(rtp_header_ptr -> nx_rtp_header_ssrc);

        /* Store timestamps for rtcp send report. */
        session -> nx_rtp_session_rtp_timestamp = timestamp;
        session -> nx_rtp_session_ntp_timestamp_msw = ntp_msw;
        session -> nx_rtp_session_ntp_timestamp_lsw = ntp_lsw;

        _nx_rtcp_packet_send(session);

#ifdef NX_ENABLE_VLAN
        /* If user has configured vlan priority with valid value, set vlan priority for the rtp data packet to sent.  */
        if (session -> nx_rtp_session_vlan_priority != NX_VLAN_PRIORITY_INVALID)
        {
            status = nx_packet_vlan_priority_set(send_packet, session -> nx_rtp_session_vlan_priority);
            if (status)
            {
                return(status);
            }
        }
#endif /* NX_ENABLE_VLAN */

        /* Send out rtp packet */
        status = nxd_udp_socket_source_send(&(session -> nx_rtp_sender -> nx_rtp_sender_rtp_socket), send_packet,
                                            &(session -> nx_rtp_session_peer_ip_address), session -> nx_rtp_session_peer_rtp_port,
                                            session -> nx_rtp_session_interface_index);
        if (status)
        {
            if (fragmentation)
            {

                /* Release the send packet when fragmentation applied. */
                nx_packet_release(send_packet);
            }
            else
            {

                /* Reset the user packet prepend pointer and the total packet length. */
                packet_ptr -> nx_packet_prepend_ptr += NX_RTP_HEADER_LENGTH;
                packet_ptr -> nx_packet_length -= NX_RTP_HEADER_LENGTH;
            }

            /* Return error status and let the user to determine when to release the packet. */
            return(status);
        }

        /* Update sender report statistic. */
        session -> nx_rtp_session_packet_count++;
        session -> nx_rtp_session_octet_count += payload_data_length;

        /* Update timestamp when sample-based mode enabled and there are more data bytes to transmit. */
        if (sample_factor && remaining_bytes)
        {
            timestamp += payload_data_length / sample_factor;
        }
    }

    if (fragmentation)
    {

        /* Release the user passed packet when fragmentation applied. */
        nx_packet_release(packet_ptr);
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_sequence_number_get        PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session sequence      */
/*    number get function call.                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    sequence_number                      Pointer to the sequence number */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_sequence_number_get                          */
/*                                         Get the sequence number value  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_sequence_number_get(NX_RTP_SESSION *session, UINT *sequence_number)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID) || (sequence_number == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender session sequence number get service. */
    status = _nx_rtp_sender_session_sequence_number_get(session, sequence_number);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_sequence_number_get         PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function provides the current sequence number value.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    sequence_number                      Pointer to the sequence number */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                           Completion status              */
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
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_sequence_number_get(NX_RTP_SESSION *session, UINT *sequence_number)
{

    /* Assign return value with the current sequence number of the session. */
    *sequence_number = session -> nx_rtp_session_sequence_number;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_sample_factor_set          PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session sampling      */
/*    factor set function call.                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    factor                               The sampling factor            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_sample_factor_set                          */
/*                                         Set the sampling factor value  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_sample_factor_set(NX_RTP_SESSION *session, UINT factor)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender session sampling factor set service. */
    status = _nx_rtp_sender_session_sample_factor_set(session, factor);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_sample_factor_set           PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the sample factor value for sample-based payload */
/*    in rtp. The sample factor determines the timestamp increasing rate  */
/*    in the function _nx_rtp_sender_session_packet_send when the         */
/*    fragmentation feature triggered in sample-based mode since timestamp*/
/*    shall be increased in a pace for each fragmentation packet.         */
/*                                                                        */
/*    The default sample factor value 0, representing frame-based mode.   */
/*    User can use this function to set a non-zero sample factor, with    */
/*    automatically triggering sample-based mode.                         */
/*    Examples about how the sample factor is computed for audio:         */
/*    1) sample bits:  8, channel number: 1, factor = 1 * (8/8) = 1       */
/*    2) sample bits: 16, channel number: 1, factor = 1 * (16/8) = 2      */
/*    3) sample bits: 16, channel number: 2, factor = 2 * (16/8) = 4      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    factor                               The sampling factor            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                           Completion status              */
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
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_sample_factor_set(NX_RTP_SESSION *session, UINT factor)
{

    /* Store the factor value into the session. */
    session -> nx_rtp_session_sample_factor = factor;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_ssrc_get                   PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session ssrc get      */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    ssrc                                 Pointer to ssrc                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_ssrc_get      Get ssrc value                 */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_ssrc_get(NX_RTP_SESSION *session, ULONG *ssrc)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID) || (ssrc == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender session ssrc get service. */
    status = _nx_rtp_sender_session_ssrc_get(session, ssrc);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_ssrc_get                    PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function provides the current ssrc value.                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    ssrc                                 Pointer to ssrc                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                           Completion status              */
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
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_ssrc_get(NX_RTP_SESSION *session, ULONG *ssrc)
{

    /* Assign return value with the current ssrc of the session */
    *ssrc = session -> nx_rtp_session_ssrc;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_vlan_priority_set          PORTABLE C       */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session vlan priority */
/*    set function call.                                                  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    vlan_priority                        The vlan priority              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_vlan_priority_set                            */
/*                                         Set the vlan priority value    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Haiqing Zhao            Initial Version 6.4.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_vlan_priority_set(NX_RTP_SESSION *session, UINT vlan_priority)
{

#ifdef NX_ENABLE_VLAN
UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender session vlan priority set service. */
    status = _nx_rtp_sender_session_vlan_priority_set(session, vlan_priority);

    /* Return status. */
    return(status);
#else
    NX_PARAMETER_NOT_USED(session);
    NX_PARAMETER_NOT_USED(vlan_priority);

    return(NX_NOT_SUPPORTED);
#endif /* NX_ENABLE_VLAN */
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_vlan_priority_set          PORTABLE C       */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the vlan priority value for the RTP data packets */
/*    transferred in the specific session.                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    vlan_priority                        The vlan priority              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_vlan_priority_set                            */
/*                                         Set the vlan priority value    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Haiqing Zhao            Initial Version 6.4.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_vlan_priority_set(NX_RTP_SESSION *session, UINT vlan_priority)
{
#ifdef NX_ENABLE_VLAN

    /* Store the vlan priority value into the session. */
    session -> nx_rtp_session_vlan_priority = vlan_priority;

    return(NX_SUCCESS);
#else
    NX_PARAMETER_NOT_USED(session);
    NX_PARAMETER_NOT_USED(vlan_priority);

    return(NX_NOT_SUPPORTED);
#endif /* NX_ENABLE_VLAN */
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_cleanup                             PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function cleans up resources created in rtp sender.            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                           Pointer to RTP sender instance */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                           Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_udp_socket_unbind                 Unbind RTP/RTCP sockets        */
/*    nx_udp_socket_delete                 Delete RTP/RTCP sockets        */
/*    tx_mutex_delete                      Delete RTP sender mutex        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtp_sender_create                Create RTP sender              */
/*    _nx_rtp_sender_delete                Delete RTP sender              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_cleanup(NX_RTP_SENDER *rtp_sender)
{

    /* Unbind and delete created rtp and rtcp sockets */
    nx_udp_socket_unbind(&(rtp_sender -> nx_rtp_sender_rtp_socket));
    nx_udp_socket_delete(&(rtp_sender -> nx_rtp_sender_rtp_socket));
    nx_udp_socket_unbind(&(rtp_sender -> nx_rtp_sender_rtcp_socket));
    nx_udp_socket_delete(&(rtp_sender -> nx_rtp_sender_rtcp_socket));

    /* Delete generated mutex */
    tx_mutex_delete(&(rtp_sender -> nx_rtp_sender_protection));

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_find                         PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function finds a RTP session through the specified ssrc.       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    ssrc                                  The specified session ssrc    */
/*    session                               Pointer to RTP session        */
/*                                            destination                 */
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
/*    _nx_rtcp_packet_rr_process            Handle RTCP RR packet         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_find(NX_RTP_SENDER *rtp_sender, UINT ssrc, NX_RTP_SESSION **session)
{

NX_RTP_SESSION *start = rtp_sender -> nx_rtp_sender_session_created_ptr;


    while (start)
    {
        if (start -> nx_rtp_session_ssrc == ssrc)
        {
            *session = start;
            return(NX_SUCCESS);
        }
        start = start -> nx_rtp_session_next;
    }

    return(NX_NOT_FOUND);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_link                         PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function links a RTP session to the RTP sender control block.  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    session                               Pointer to RTP session        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtp_sender_session_create         Create RTP session            */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
VOID _nx_rtp_sender_session_link(NX_RTP_SENDER *rtp_sender, NX_RTP_SESSION *session)
{

NX_RTP_SESSION *tail;


    if (rtp_sender -> nx_rtp_sender_session_created_ptr)
    {

        /* Search the tail ptr. */
        tail = rtp_sender -> nx_rtp_sender_session_created_ptr;

        while (tail -> nx_rtp_session_next)
        {
            tail = tail -> nx_rtp_session_next;
        }

        /* Put the session at the end of the list. */
        tail -> nx_rtp_session_next = session;
    }
    else
    {

        /* The created session list is empty, simply add the session. */
        rtp_sender -> nx_rtp_sender_session_created_ptr = session;
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_unlink                       PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function unlinks a RTP session from the RTP sender control     */
/*    block.                                                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    session                               Pointer to RTP session        */
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
/*    _nx_rtp_sender_session_delete         Delete RTP session            */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_unlink(NX_RTP_SENDER *rtp_sender, NX_RTP_SESSION *session)
{

NX_RTP_SESSION *current;
NX_RTP_SESSION *pre;


    /* Find the session and unlink it from the list. */
    if (rtp_sender -> nx_rtp_sender_session_created_ptr == session)
    {
        rtp_sender -> nx_rtp_sender_session_created_ptr = session -> nx_rtp_session_next;
    }
    else
    {
        pre = rtp_sender -> nx_rtp_sender_session_created_ptr;
        current = pre -> nx_rtp_session_next;

        while (current)
        {
            if (current == session)
            {
                pre -> nx_rtp_session_next = current -> nx_rtp_session_next;
                break;
            }

            pre = current;
            current = pre -> nx_rtp_session_next;
        }
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtcp_packet_process                             PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles reception of RTCP packet.                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    packet_ptr                            Pointer to packet             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtcp_packet_rr_process            Handle RR packet              */
/*    _nx_rtcp_packet_sdes_process          Handle SDES packet            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtcp_packet_receive_notify        RTCP packet receive notify    */
/*                                             service                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtcp_packet_process(NX_RTP_SENDER *rtp_sender, NX_PACKET *packet_ptr)
{

UINT            status = NX_SUCCESS;
NX_RTCP_HEADER *header;
NX_RTCP_HEADER *next;
UCHAR          *end;


    if (rtp_sender -> nx_rtp_sender_id != NX_RTP_SENDER_ID)
    {

        /* Not valid RTP sender. */
        return(NX_PTR_ERROR);
    }

#ifndef NX_DISABLE_PACKET_CHAIN
    if (packet_ptr -> nx_packet_next)
    {

        /* Chained packet, not supported. */
        return(NX_NOT_SUPPORTED);
    }
#endif /* NX_DISABLE_PACKET_CHAIN */

    header = (NX_RTCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);
    end = packet_ptr -> nx_packet_append_ptr;

    if ((UCHAR *)header + sizeof(NX_RTCP_HEADER) > end)
    {
        return(NX_INVALID_PACKET);
    }

    /* Check the first RTCP packet header:
       1) The Padding bit should be zero for the first packet of a compound RTCP packet.
       2) The payload type field of the first RTCP packet in a compound packet must be equal to SR or RR.
     */
    if (((header -> nx_rtcp_byte0 & NX_RTCP_PAD_MASK) != NX_RTCP_PAD_VALUE) ||
        ((header -> nx_rtcp_packet_type & NX_RTCP_TYPE_MASK) != NX_RTCP_TYPE_SR))
    {

        /* Wrong packet format. */
        return(NX_INVALID_PACKET);
    }

    do
    {
        NX_CHANGE_USHORT_ENDIAN(header -> nx_rtcp_length);

        next = (NX_RTCP_HEADER *)((ULONG *)header + header -> nx_rtcp_length + 1);

        /* RTP version field must equal 2. */
        if (((header -> nx_rtcp_byte0 & NX_RTCP_VERSION_MASK) != NX_RTCP_VERSION_VALUE) || ((UCHAR *)next > end))
        {
            status = NX_INVALID_PACKET;
            break;
        }

        switch (header -> nx_rtcp_packet_type)
        {
        case NX_RTCP_TYPE_RR:

            /* Process rr packet. */
            status = _nx_rtcp_packet_rr_process(rtp_sender, header);
            break;

        case NX_RTCP_TYPE_SDES:

            /* Process sdes packet. */
            status = _nx_rtcp_packet_sdes_process(rtp_sender, header);
            break;
        }

        if (status != NX_SUCCESS)
        {
            break;
        }

        header = next;
    } while ((UCHAR *)header + sizeof(NX_RTCP_HEADER) <= end);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtcp_packet_rr_process                          PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles RTCP RR packet.                               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    header                                Pointer to RTCP packet header */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_find           Find rtp session              */
/*    tx_mutex_get                          Get mutex                     */
/*    tx_mutex_put                          Release mutex                 */
/*    nx_rtp_sender_rtcp_receiver_report_cb Application's RTCP RR packet  */
/*                                            notify callback             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtcp_packet_process                Handle RTCP packet           */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtcp_packet_rr_process(NX_RTP_SENDER *rtp_sender, NX_RTCP_HEADER *header)
{

UINT                    status;
NX_RTCP_RR             *rtcp_rr;
NX_RTCP_RECEIVER_REPORT report;
UINT                    (*rr_callback)(struct NX_RTP_SESSION_STRUCT *, NX_RTCP_RECEIVER_REPORT *);
NX_RTP_SESSION         *session;


    rr_callback = rtp_sender -> nx_rtp_sender_rtcp_receiver_report_cb;
    if (rr_callback == NX_NULL)
    {

        /* No RTCP receiver report callback set. */
        return(NX_SUCCESS);
    }

    if ((header -> nx_rtcp_byte0 & NX_RTCP_COUNT_MASK) &&
        ((sizeof(NX_RTCP_RR) >> 2) <= (UINT)((header -> nx_rtcp_length + 1))))
    {
        rtcp_rr = (NX_RTCP_RR *)header;

        /* Take care of endian-ness. */
        NX_CHANGE_ULONG_ENDIAN(rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_ssrc);

        /* Obtain the mutex. */
        status = tx_mutex_get(&(rtp_sender -> nx_rtp_sender_protection), TX_NO_WAIT);

        if (status != NX_SUCCESS)
        {
            return(status);
        }

        if (_nx_rtp_sender_session_find(rtp_sender, rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_ssrc, &session) == NX_SUCCESS)
        {
            NX_CHANGE_ULONG_ENDIAN(rtcp_rr -> nx_rtcp_rr_ssrc);
            NX_CHANGE_ULONG_ENDIAN(rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_loss);
            NX_CHANGE_ULONG_ENDIAN(rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_extended_max);
            NX_CHANGE_ULONG_ENDIAN(rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_jitter);
            NX_CHANGE_ULONG_ENDIAN(rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_last_sr);
            NX_CHANGE_ULONG_ENDIAN(rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_delay);

            /* Copy the values out for the callback function. */
            report.receiver_ssrc = rtcp_rr -> nx_rtcp_rr_ssrc;
            report.fraction_loss = rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_loss >> 24;
            report.packet_loss = ((((INT)rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_loss) << 8) >> 8);
            report.extended_max = rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_extended_max;
            report.jitter = rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_jitter;
            report.last_sr = rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_last_sr;
            report.delay = rtcp_rr -> nx_rtcp_rr_report.nx_rtcp_report_delay;

            /* Invoke the callback function to process data inside the RTCP RR packet. */
            rr_callback(session, &report);
        }

        /* Release the mutex. */
        tx_mutex_put(&(rtp_sender -> nx_rtp_sender_protection));
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtcp_packet_sdes_process                        PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles RTCP SDES packet.                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    rtp_sender                            Pointer to RTP sender         */
/*    header                                Pointer to RTCP packet header */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_rtp_sender_rtcp_sdes_cb            Application's RTCP SDES       */
/*                                            packet notify callback      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtcp_packet_process                Handle RTCP packet           */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtcp_packet_sdes_process(NX_RTP_SENDER *rtp_sender, NX_RTCP_HEADER *header)
{

UINT                (*sdes_callback)(NX_RTCP_SDES_INFO *);
NX_RTCP_SDES_CHUNK *chunk;
NX_RTCP_SDES_ITEM  *item;
UCHAR              *end;
NX_RTCP_SDES_INFO   sdes_info;
INT                 count;


    sdes_callback = rtp_sender -> nx_rtp_sender_rtcp_sdes_cb;
    if (sdes_callback == NX_NULL)
    {

        /* No RTCP receiver report callback set. */
        return(NX_SUCCESS);
    }

    chunk = (NX_RTCP_SDES_CHUNK *)((UCHAR *)header + sizeof(NX_RTCP_HEADER));
    count = (header -> nx_rtcp_byte0 & NX_RTCP_COUNT_MASK);

    end = (UCHAR *)((ULONG *)header + header -> nx_rtcp_length + 1);

    while (((UCHAR *)chunk + sizeof(NX_RTCP_SDES_CHUNK) <= end) && (count-- > 0))
    {
        item = &chunk -> nx_rtcp_sdes_item[0];

        NX_CHANGE_ULONG_ENDIAN(chunk -> nx_rtcp_sdes_ssrc);

        while (((UCHAR *)item + sizeof(NX_RTCP_SDES_ITEM) <= end) && item -> nx_rtcp_sdes_type)
        {

            if (item -> nx_rtcp_sdes_data + item -> nx_rtcp_sdes_length > end)
            {
                return(NX_INVALID_PACKET);
            }

            if (item -> nx_rtcp_sdes_type == NX_RTCP_SDES_TYPE_CNAME)
            {

                /* Copy the values out for the callback function. */
                sdes_info.ssrc = chunk -> nx_rtcp_sdes_ssrc;
                sdes_info.cname_length = item -> nx_rtcp_sdes_length;

                /* CNAME string is UTF-8 encoded and is not null terminated. */
                sdes_info.cname = &item -> nx_rtcp_sdes_data[0];

                /* Invoke the callback function to process data inside the RTCP SDES packet. */
                sdes_callback(&sdes_info);

                break;
            }

            /* Advance to the next item. */
            item = (NX_RTCP_SDES_ITEM *)((UCHAR *)item + 2 + item -> nx_rtcp_sdes_length);
        }

        /* RFC 3550, chapter 6.5.
           The list of items in each chunk MUST be terminated by one or more null octets,
           the first of which is interpreted as an item type of zero to denote the end of the list. */
        chunk = (NX_RTCP_SDES_CHUNK *)((UCHAR *)chunk + (((UCHAR *)item - (UCHAR *)chunk) >> 2) + 1);
    }

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtcp_sr_data_append                             PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function generates an RTCP SR packet and copies it to the end  */
/*    of the specifed RTCP packet.                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                               Pointer to RTP session        */
/*    packet_ptr                            Pointer to RTCP packet        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_data_append                 Copy the specified data to    */
/*                                            the end of specified packet */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtcp_packet_send                  Send RTCP packet              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtcp_sr_data_append(NX_RTP_SESSION *session, NX_PACKET *packet_ptr)
{

NX_RTCP_SR rtcp_sr;


    /* Pack SR packet. */
    rtcp_sr.nx_rtcp_sr_header.nx_rtcp_byte0 = (NX_RTP_VERSION << 6);                   /* Version 2 */
    rtcp_sr.nx_rtcp_sr_header.nx_rtcp_packet_type = NX_RTCP_TYPE_SR;
    rtcp_sr.nx_rtcp_sr_header.nx_rtcp_length = sizeof(NX_RTCP_SR) / sizeof(ULONG) - 1; /* RTCP SR size. */
    rtcp_sr.nx_rtcp_sr_ssrc = session -> nx_rtp_session_ssrc;
    rtcp_sr.nx_rtcp_sr_ntp_timestamp_msw = session -> nx_rtp_session_ntp_timestamp_msw;
    rtcp_sr.nx_rtcp_sr_ntp_timestamp_lsw = session -> nx_rtp_session_ntp_timestamp_lsw;
    rtcp_sr.nx_rtcp_sr_rtp_timestamp = session -> nx_rtp_session_rtp_timestamp;
    rtcp_sr.nx_rtcp_sr_rtp_packet_count = session -> nx_rtp_session_packet_count;
    rtcp_sr.nx_rtcp_sr_rtp_octet_count = session -> nx_rtp_session_octet_count;

    /* Take care of endian-ness. */
    NX_CHANGE_USHORT_ENDIAN(rtcp_sr.nx_rtcp_sr_header.nx_rtcp_length);
    NX_CHANGE_ULONG_ENDIAN(rtcp_sr.nx_rtcp_sr_ssrc);
    NX_CHANGE_ULONG_ENDIAN(rtcp_sr.nx_rtcp_sr_ntp_timestamp_msw);
    NX_CHANGE_ULONG_ENDIAN(rtcp_sr.nx_rtcp_sr_ntp_timestamp_lsw);
    NX_CHANGE_ULONG_ENDIAN(rtcp_sr.nx_rtcp_sr_rtp_timestamp);
    NX_CHANGE_ULONG_ENDIAN(rtcp_sr.nx_rtcp_sr_rtp_packet_count);
    NX_CHANGE_ULONG_ENDIAN(rtcp_sr.nx_rtcp_sr_rtp_octet_count);

    /* Append SR packet.  */
    nx_packet_data_append(packet_ptr, &rtcp_sr, sizeof(rtcp_sr), session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_RTP_SENDER_PACKET_TIMEOUT);

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtcp_sdes_data_append                           PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function generates an RTCP SDES packet and copies it to the    */
/*    end of the specifed RTCP packet.                                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                               Pointer to RTP session        */
/*    packet_ptr                            Pointer to RTCP packet        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_data_append                 Copy the specified data to    */
/*                                            the end of specified packet */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtcp_packet_send                  Send RTCP packet              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtcp_sdes_data_append(NX_RTP_SESSION *session, NX_PACKET *packet_ptr)
{

UINT               status;
NX_RTCP_HEADER     header;
NX_RTCP_SDES_CHUNK sdes_chunk;
NX_PACKET_POOL    *packet_pool = session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr;
NX_RTP_SENDER     *sender = session -> nx_rtp_sender;
ULONG              pad = 0;
UCHAR              pad_value[] = {0, 0, 0};
UINT               length;


/*
SDES packet format:
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    SC   |  PT=SDES=202  |             length            |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
chunk  |                          SSRC/CSRC_1                          |
  1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           SDES items                          |
       |                              ...                              |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
chunk  |                          SSRC/CSRC_2                          |
  2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           SDES items                          |
       |                              ...                              |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

SDES item format for CNAME:
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    CNAME=1    |     length    | user and domain name        ...
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

    /* packet size = rtcp header size + 4 bytes ssrc + 1 byte type + 1 byte length + data length. */
    length = sizeof(NX_RTCP_HEADER) + 6 + sender -> nx_rtp_sender_cname_length;

    if (length & 0x3)
    {
        pad = 4 - (length & 0x3);
    }

    /* Pack SDES packet header. */
    header.nx_rtcp_byte0 = (NX_RTP_VERSION << 6) | 1; /* Sender Desc with 1 item */
    header.nx_rtcp_packet_type = NX_RTCP_TYPE_SDES;
    header.nx_rtcp_length = (USHORT)(((length + pad) / sizeof(ULONG)) - 1);

    NX_CHANGE_USHORT_ENDIAN(header.nx_rtcp_length);

    /* Append SDES packet header. */
    status = nx_packet_data_append(packet_ptr, &header, sizeof(header), packet_pool, NX_RTP_SENDER_PACKET_TIMEOUT);
    if (status)
    {
        return(status);
    }

    /* Pack CNAME item. */
    sdes_chunk.nx_rtcp_sdes_ssrc = session -> nx_rtp_session_ssrc;
    sdes_chunk.nx_rtcp_sdes_item[0].nx_rtcp_sdes_type = NX_RTCP_SDES_TYPE_CNAME;
    sdes_chunk.nx_rtcp_sdes_item[0].nx_rtcp_sdes_length = sender -> nx_rtp_sender_cname_length;

    NX_CHANGE_ULONG_ENDIAN(sdes_chunk.nx_rtcp_sdes_ssrc);

    /* Append 4 bytes ssrc + 1 byte item type + 1 byte data length. */
    status = nx_packet_data_append(packet_ptr, &sdes_chunk, 6, packet_pool, NX_RTP_SENDER_PACKET_TIMEOUT);
    if (status)
    {
        return(status);
    }

    /* Append cname string. */
    status = nx_packet_data_append(packet_ptr, sender -> nx_rtp_sender_cname, sender -> nx_rtp_sender_cname_length, packet_pool, NX_RTP_SENDER_PACKET_TIMEOUT);
    if (status)
    {
        return(status);
    }

    if (pad)
    {
        status = nx_packet_data_append(packet_ptr, pad_value, pad, packet_pool, NX_RTP_SENDER_PACKET_TIMEOUT);
        if (status)
        {
            return(status);
        }
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtcp_packet_send                                PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a compound RTCP packet through the UDP layer to */
/*    the supplied IP address and rtcp port.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                               Pointer to RTP session        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_time_get                           Get current system clock      */
/*    nx_packet_allocate                    Allocate packet               */
/*    nx_packet_release                     Release packet                */
/*    nxd_udp_socket_source_send            Send a UDP packet             */
/*    _nx_rtcp_sr_data_append               Append SR packet              */
/*    _nx_rtcp_sdes_data_append             Append SDES packet            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtp_sender_session_packet_send    Send rtp packet               */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtcp_packet_send(NX_RTP_SESSION *session)
{

UINT       status = NX_SUCCESS;
NX_PACKET *packet_ptr;
UINT       current_time = tx_time_get();


    if (session -> nx_rtp_session_rtcp_time &&
        ((current_time - session -> nx_rtp_session_rtcp_time) / TX_TIMER_TICKS_PER_SECOND < NX_RTCP_INTERVAL))
    {
        return(NX_SUCCESS);
    }

    status = nx_packet_allocate(session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, &packet_ptr, NX_UDP_PACKET, NX_RTP_SENDER_PACKET_TIMEOUT);

    if (status != NX_SUCCESS)
    {
        return(status);
    }

    /* Chain rtcp packets into one compound packet. */
    status = _nx_rtcp_sr_data_append(session, packet_ptr);

    if (status == NX_SUCCESS)
    {
        status = _nx_rtcp_sdes_data_append(session, packet_ptr);
    }

    if (status == NX_SUCCESS)
    {

        /* Send the packet. */
        status = nxd_udp_socket_source_send(&session -> nx_rtp_sender -> nx_rtp_sender_rtcp_socket, packet_ptr,
                                            &(session -> nx_rtp_session_peer_ip_address), session -> nx_rtp_session_peer_rtcp_port,
                                            session -> nx_rtp_session_interface_index);
    }

    /* Check the status.  */
    if (status == NX_SUCCESS)
    {
        session -> nx_rtp_session_rtcp_time = tx_time_get();
    }
    else
    {
        nx_packet_release(packet_ptr);
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtcp_packet_receive_notify                      PORTABLE C      */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Ting Zhu, Microsoft Corporation                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function serves as RTCP packet receive notify routine, which   */
/*    is called whenever a packet is received on the rtcp port.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to RTCP port          */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_udp_socket_receive                 Check for UDP packet on the   */
/*                                            specified port              */
/*    nx_packet_release                     Release packet                */
/*    _nx_rtcp_packet_process               Handle rtcp packet            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_rtp_sender_create                 Create RTP sender             */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Ting Zhu                 Initial Version 6.3.0         */
/*                                                                        */
/**************************************************************************/
VOID _nx_rtcp_packet_receive_notify(NX_UDP_SOCKET *socket_ptr)
{

/* Drain the packet */
NX_PACKET *packet_ptr;
NX_RTP_SENDER *rtp_sender;


    /* Get packet(s) from the passed socket. */
    if (nx_udp_socket_receive(socket_ptr, &packet_ptr, NX_NO_WAIT) != NX_SUCCESS)
    {
        return;
    }

    /* Check and determine whether to process received rtcp packet. */
    rtp_sender = (NX_RTP_SENDER *)socket_ptr -> nx_udp_socket_reserved_ptr;
    if ((rtp_sender) &&
        (rtp_sender -> nx_rtp_sender_rtcp_receiver_report_cb || rtp_sender -> nx_rtp_sender_rtcp_sdes_cb))
    {
        _nx_rtcp_packet_process(rtp_sender, packet_ptr);
    }

    /* Release the packet and return. */
    nx_packet_release(packet_ptr);
    return;
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_jpeg_send                  PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session jpeg send     */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    frame_data                           Pointer to data buffer to send */
/*    frame_data_size                      Size of data to send           */
/*    timestamp                            RTP timestamp for current data */
/*    ntp_msw                              Most significant word of       */
/*                                           network time                 */
/*    ntp_lsw                              Least significant word of      */
/*                                           network time                 */
/*    marker                               Marker bit for significant     */
/*                                           event such as frame boundary */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_jpeg_send     Send packet data               */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_jpeg_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                       ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_sender == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID) || (frame_data == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender session packet send service. */
    status = _nx_rtp_sender_session_jpeg_send(session, frame_data, frame_data_size, timestamp, ntp_msw, ntp_lsw, marker);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_jpeg_send                   PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses and makes the passed data in RTP/JPEG format,  */
/*    and then calls RTP session send function to send these data in RTP  */
/*    packet.                                                             */
/*    The function references RFC 2435 as the standard with below notes:  */
/*    1) A complete jpeg scan file inside frame data buffer is required.  */
/*    2) Use dynamic quantization table mapping.                          */
/*    3) The provided jpeg scan file shall be 8-bit sample precision,     */
/*       YUV420 or YUV422 type, and encoded with standard huffman tables. */
/*    4) Restart marker is not supported.                                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    frame_data                           Pointer to data buffer to send */
/*    frame_data_size                      Size of data to send           */
/*    timestamp                            RTP timestamp for current data */
/*    ntp_msw                              Most significant word of       */
/*                                           network time                 */
/*    ntp_lsw                              Least significant word of      */
/*                                           network time                 */
/*    marker                               Marker bit for significant     */
/*                                           event such as frame boundary */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_packet_allocate                              */
/*                                         Allocate a packet for the user */
/*    nx_packet_data_append                Copy the specified data to     */
/*                                            the end of specified packet */
/*    nx_packet_data_release               Release the packet             */
/*    _nx_rtp_sender_session_packet_send   Send RTP packet                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_jpeg_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                      ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker)
{

UINT       status;
UCHAR     *data_ptr;
UCHAR     *data_end_ptr;
UCHAR      jpeg_header[8];
UCHAR      quantization_header[4];
USHORT     section_length;
UCHAR      type = 255; /* type field for main jpeg header. */
UCHAR      marker_code; /* jpeg marker code to indicate different sections. */
USHORT     width = 0, height = 0; /* resolution information for main jpeg header. */
ULONG      q_table_num = 0;
ULONG      q_overall_table_num = 0;
UCHAR     *q_table_ptr[NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_MAX_NUM];
ULONG      data_payload_length = 0;
ULONG      transferred_data_size = 0;
ULONG      single_frame_length;
ULONG      copy_length;
UINT       temp_rtp_marker = NX_FALSE;
NX_PACKET *send_packet = NX_NULL;


    /* In current design, the marker bit shall be always 1 (i.e. a complete jpeg scan file required to be passed). */
    if (marker != NX_TRUE)
    {
        return(NX_NOT_SUPPORTED);
    }

    /* Initialize local variables for searching. */
    data_ptr = frame_data;
    data_end_ptr = frame_data + frame_data_size;

    /* Check jpeg constant file header. */
    if ((frame_data_size < 2) || ((data_ptr[0] != 0xFF) || (data_ptr[1] != 0xD8)))
    {
        return(NX_NOT_SUCCESSFUL);
    }

    /* Skip the 2 bytes jpeg file header. */
    data_ptr += 2;

    do
    {

        /* Check there are enough bytes remaining in the data buffer for 2 bytes section marker and 2 bytes section length. */
        if ((data_ptr + 4) > data_end_ptr)
        {
            return(NX_SIZE_ERROR);
        }

        /* Check the first byte for section marker. */
        if (data_ptr[0] != 0xFF)
        {
            return(NX_NOT_SUCCESSFUL);
        }

        /* Update the marker code. */
        marker_code = data_ptr[1];

        /* Update and skip the whole 2 bytes section marker. */
        data_ptr += 2;

        /* Compute data length in this section. */
        section_length = (USHORT)((data_ptr[0] << 8) | data_ptr[1]);

        /* Check there are enough bytes remaining in the data buffer. */
        if ((data_ptr + section_length) > data_end_ptr)
        {
            return(NX_SIZE_ERROR);
        }

        /* Now it is time to parse the marker code and its corresponding section. */
        switch (marker_code)
        {

            /* SOF0: image baseline information. */
            case 0xC0:
            {

                /* For a standard RTP/JPEG image baseline information, this section length shall be
                   at least 17, in order to contain enough baseline information for the image. */
                if (section_length < 17)
                {
                    return(NX_SIZE_ERROR);
                }

                /* Skip 2 bytes section length. */
                data_ptr += 2;

                /* 8-bit sample precision is required. */
                if (data_ptr[0] != 8)
                {
                    return(NX_NOT_SUPPORTED);
                }

                /* Check the number of image components which shall be 3 for YUV. */
                if (data_ptr[5] != 3)
                {
                    return(NX_NOT_SUPPORTED);
                }

                /* Check the quantization table number for all YUV dimensions. */
                if ((data_ptr[8] != 0x00) || (data_ptr[11] != 0x01) || (data_ptr[14] != 0x01))
                {
                    return(NX_NOT_SUPPORTED);
                }

                /* Check the horizontal and vertical sampling factor for both U dimension and V dimension. */
                if ((data_ptr[10] != 0x11) || (data_ptr[13] != 0x11))
                {
                    return(NX_NOT_SUPPORTED);
                }

                /* Determine the RTP/JPEG type in jpeg main header through different vertical sampling factor of Y dimension. */
                if (data_ptr[7] == 0x21)
                {
                    type = 0; /* YUV420. */
                }
                else if (data_ptr[7] == 0x22)
                {
                    type = 1; /* YUV422. */
                }
                else
                {
                    return(NX_NOT_SUPPORTED);
                }

                /* Compute width and height. */
                height = (USHORT)((data_ptr[1] << 8) | data_ptr[2]);
                width = (USHORT)((data_ptr[3] << 8) | data_ptr[4]);

                /* Skip the current section. */
                data_ptr += 15; /* 15 bytes section data. */
                break;
            }

            /* DQT: define quantization table. */
            case 0xDB:
            {

                /* Skip 2 bytes section length. */
                data_ptr += 2;

                /* Compute the number of quantization tables (each table shall contain 65 bytes). */
                q_table_num = section_length / (NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_LENGTH + 1);

                /* Check current table number. */
                if ((q_table_num == 0) || ((q_table_num + q_overall_table_num) > NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_MAX_NUM))
                {
                    return(NX_NOT_SUCCESSFUL);
                }

                for (UINT i = q_overall_table_num; i < (q_overall_table_num + q_table_num); i++)
                {

                    /* Skip the first no meaning byte. */
                    data_ptr++;

                    /* Record the current table position. */
                    q_table_ptr[i] = data_ptr;

                    /* Move to the next table position. */
                    data_ptr += NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_LENGTH;
                }

                /* Update overall number of tables. This variable is introduced because there may be more than 1 DQT come. */
                q_overall_table_num += q_table_num;
                break;
            }

            /* SOS: the start of the scan. */
            case 0xDA:
            {

                /* Skip the scan header. */
                data_ptr += section_length;

                /* Move the end pointer to the last 2 byte to make the check easier */
                data_end_ptr -= 2;

                /* Search and try to find EOI in current packet. */
                while (data_ptr < data_end_ptr)
                {
                    if ((data_end_ptr[0] == 0xFF) && (data_end_ptr[1] == 0xD9))
                    {
                        break;
                    }
                    else
                    {
                        data_end_ptr--;
                    }
                }

                /* Check if EOI has been found. */
                if (data_ptr < data_end_ptr)
                {
                    data_payload_length = (ULONG)(data_end_ptr - data_ptr);
                }
                else /* data_ptr == data_end_ptr */
                {

                    /* If EOI has not been found, consider all remaining data are scan data. */
                    data_payload_length = frame_data_size - (ULONG)(data_ptr - frame_data);
                }

                /* When SOS found, the while loop will also be jumped out. */
                break;
            }

            /* EOI */
            case 0xD9:
            {

                /* SOS shall be found before EOI. */
                return(NX_NOT_SUCCESSFUL);
            }

            /* Unsupported SOFs or other markers. */
            case 0xC1: /* Extended sequential DCT */
            case 0xC2: /* Progressive DCT */
            case 0xC3: /* Lossless (sequential) */
            case 0xC5: /* Differential sequential DCT */
            case 0xC6: /* Differential progressive DCT */
            case 0xC7: /* Differential lossless (sequential) */
            case 0xC8: /* Reserved for JPEG extensions */
            case 0xC9: /* Extended sequential DCT */
            case 0xCA: /* Progressive DCT */
            case 0xCB: /* Lossless (sequential) */
            case 0xCC: /* Define arithmetic coding conditionings */
            case 0xCD: /* Differential sequential DCT */
            case 0xCE: /* Differential progressive DCT */
            case 0xCF: /* Differential lossless (sequential) */
            case 0xDD: /* DRI */
            {
                return(NX_NOT_SUPPORTED);
            }

            /* Possible sections in default:
            1) APP0 ~ APPn: define exchange format and image identifications.
            2) Huffman table: it is assumed that standard Huffman table applied. */
            default:
            {

                /* Marker code 0x01 is not supported. Marker codes inside 0x02 ~ 0xBF are reserved. */
                if (marker_code < 0xC0)
                {
                    return(NX_NOT_SUPPORTED);
                }

                /* Move the data_ptr and offset to skip the whole section. */
                data_ptr += section_length;
                break;
            }
        }

    } while (marker_code != 0xDA); /* Jump out when find SOS. */

    /* Check the type has been confirmed, and quantization. */
    if (((type != 0) && (type != 1)) || (q_overall_table_num == 0))
    {
        return(NX_NOT_SUCCESSFUL);
    }

    /* Check there is any scan data to send. */
    if (data_payload_length == 0)
    {
        return(NX_SIZE_ERROR);
    }

    /* Allocate a packet for the first data packet to transmit. */
    status = _nx_rtp_sender_session_packet_allocate(session, &send_packet, NX_RTP_SENDER_PACKET_TIMEOUT);
    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    /* Initialize main JPEG header, and append it into the send packet. */
    jpeg_header[0] = 0; /* Always 0 since no interpretation is specified. */
    jpeg_header[1] = 0; /* High byte of 24 bytes size offset. */
    jpeg_header[2] = 0; /* Middle byte 24 bytes size offset. */
    jpeg_header[3] = 0; /* Low byte of 24 bytes size offset. */
    jpeg_header[4] = type;
    jpeg_header[5] = 255; /* Q values 255 indicates the quantization table header appears after the main JPEG header,
                             and the quantization table is allowed to be changeable among different frames. */
    jpeg_header[6] = (UCHAR)(width >> 3);  /* Maximum width: 2040 pixels. */
    jpeg_header[7] = (UCHAR)(height >> 3); /* Maximum height: 2040 pixels. */

    status = nx_packet_data_append(send_packet, (void *)jpeg_header, sizeof(jpeg_header),
                                   session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_RTP_SENDER_PACKET_TIMEOUT);
    if (status)
    {
        nx_packet_release(send_packet);
        return(NX_NOT_SUCCESSFUL);
    }

    /* Update quantization table header, and append it into the send packet. */
    quantization_header[0] = 0; /* MBZ. */
    quantization_header[1] = 0; /* Precision: 8 bits. */
    quantization_header[2] = (UCHAR)((NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_LENGTH * q_overall_table_num) >> 8); /* High byte if tables length. */
    quantization_header[3] = (UCHAR)(NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_LENGTH * q_overall_table_num); /* Low byte if tables length. */

    status = nx_packet_data_append(send_packet, (void *)quantization_header, sizeof(quantization_header),
                                   session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_RTP_SENDER_PACKET_TIMEOUT);
    if (status)
    {
        nx_packet_release(send_packet);
        return(NX_NOT_SUCCESSFUL);
    }

    /* Copy quantization table(s) into the packet. It is assume that these table(s) are not in different packets of a chain packet. */
    for (UINT i = 0; i < q_overall_table_num; i++)
    {
        status = nx_packet_data_append(send_packet, (void *)(q_table_ptr[i]), NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_LENGTH,
                                       session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_RTP_SENDER_PACKET_TIMEOUT);
        if (status)
        {
            nx_packet_release(send_packet);
            return(NX_NOT_SUCCESSFUL);
        }
    }

    /* Compute the current single frame length and check if mtu size match the requirement for putting all jpeg header info into one packet. */
    single_frame_length = sizeof(jpeg_header) + sizeof(quantization_header) + NX_RTP_SENDER_JPEG_QUANTIZATION_TABLE_LENGTH * q_overall_table_num;
    if (single_frame_length > session -> nx_rtp_session_max_packet_size)
    {
        nx_packet_release(send_packet);
        return(NX_NOT_SUPPORTED);
    }

    /* Begin data frame(s) transmit. */
    while (1)
    {

        /* Check and execute packet fragmentation. */
        copy_length = session -> nx_rtp_session_max_packet_size - single_frame_length;
        if (data_payload_length <= copy_length)
        {
            copy_length = data_payload_length;
            temp_rtp_marker = NX_TRUE;
        }

        /* Copy payload data into the packet. */
        status = nx_packet_data_append(send_packet, (void *)data_ptr, copy_length,
                                       session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_RTP_SENDER_PACKET_TIMEOUT);
        if (status)
        {
            nx_packet_release(send_packet);
            return(status);
        }

        /* Send the data packet. */
        status = _nx_rtp_sender_session_packet_send(session, send_packet, timestamp, ntp_msw, ntp_lsw, temp_rtp_marker);
        if (status)
        {
            nx_packet_release(send_packet);
            return(status);
        }

        /* Decrease transmitted data payload length and check whether all data finish transmitting. */
        data_payload_length -= copy_length;
        if (data_payload_length == 0)
        {

            /* Jump out the while loop when all data finish transmitting. */
            break;
        }

        /* Move data pointer to the begin of remaining data. */
        data_ptr += copy_length;

        /* Update 24-bit transferred data offset with bytes order. */
        transferred_data_size += copy_length;
        jpeg_header[1] = (UCHAR)(transferred_data_size >> 16);
        jpeg_header[2] = (UCHAR)(transferred_data_size >> 8);
        jpeg_header[3] = (UCHAR)(transferred_data_size);

        /* Allocate a packet for next packet. */
        status = _nx_rtp_sender_session_packet_allocate(session, &send_packet, NX_RTP_SENDER_PACKET_TIMEOUT);
        if (status)
        {
            return(status);
        }

        /* Copy jpeg header into the packet. */
        status = nx_packet_data_append(send_packet, (void *)jpeg_header, sizeof(jpeg_header),
                                       session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_RTP_SENDER_PACKET_TIMEOUT);
        if (status)
        {
            nx_packet_release(send_packet);
            return(status);
        }

        /* Update single frame length. */
        single_frame_length = sizeof(jpeg_header);
    }

    /* Return success status. */
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_h264_send                  PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session h264 send     */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    frame_data                           Pointer to data buffer to send */
/*    frame_data_size                      Size of data to send           */
/*    timestamp                            RTP timestamp for current data */
/*    ntp_msw                              Most significant word of       */
/*                                           network time                 */
/*    ntp_lsw                              Least significant word of      */
/*                                           network time                 */
/*    marker                               Marker bit for significant     */
/*                                           event such as frame boundary */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_h264_send     Send h264 frame data           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_h264_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                       ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_sender == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID) || (frame_data == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender session frame send service. */
    status = _nx_rtp_sender_session_h264_send(session, frame_data, frame_data_size, timestamp, ntp_msw, ntp_lsw, marker);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_h264_send                   PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses and separates the passed data into h264 frames */
/*    or slices, and processes each frame/slice from VCL format to NAL    */
/*    format, and finally calls RTP session send function to send these   */
/*    frame/slice(s) in RTP packet.                                       */
/*    The function references RFC 6184 as the standard with below notes:  */
/*    1) A complete h264 data frame shall be inside the frame data buffer.*/
/*    2) Special frame(s) such as SEI, SPS and PPS can be inside the      */
/*       frame data buffer.                                               */
/*    3) Each H264 frame/slice inside the frame data buffer shall be in   */
/*       VCL (video coding layer) format.                                 */
/*    4) SDP shall indicate that non-interleaved mode is applied (i.e.    */
/*       packetization-mode=1), which supports the use of single NAL unit */
/*       packet and FU-A packets.                                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    frame_data                           Pointer to data buffer to send */
/*    frame_data_size                      Size of data to send           */
/*    timestamp                            RTP timestamp for current data */
/*    ntp_msw                              Most significant word of       */
/*                                           network time                 */
/*    ntp_lsw                              Least significant word of      */
/*                                           network time                 */
/*    marker                               Marker bit for significant     */
/*                                           event such as frame boundary */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_packet_allocate                              */
/*                                         Allocate a packet for the user */
/*    nx_packet_data_append                Copy the specified data to     */
/*                                            the end of specified packet */
/*    nx_packet_data_release               Release the packet             */
/*    _nx_rtp_sender_session_packet_send   Send RTP packet                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_h264_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                      ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker)
{

UINT       status;
UINT       i;
ULONG      nal_unit_size;
ULONG      max_packet_length;
ULONG      send_packet_length;
UCHAR     *frame_end;
UCHAR     *nal_unit_start;
UCHAR     *data_ptr = frame_data;
UINT       send_marker = NX_FALSE;
UINT       temp_marker = NX_FALSE;
UCHAR      nal_unit_type;
UCHAR      fu_a_header[2];
ULONG      packet_num;
ULONG      last_packet_size;
NX_PACKET *send_packet = NX_NULL;


    /* In current design, the marker bit shall be always 1 (i.e. a complete h264 frame required to be passed). */
    if (marker != NX_TRUE)
    {
        return(NX_NOT_SUPPORTED);
    }

    /* Obtain the maximum frame packet length. */
    max_packet_length = session -> nx_rtp_session_max_packet_size;

    /* Check frame minimum length. */
    if (frame_data_size <= 4)
    {
        return(NX_SIZE_ERROR);
    }

    /* Record frame end position. */
    frame_end = frame_data + frame_data_size - 1;

    /* Is the h264 4 bytes or 3 bytes header found. */
    if ((data_ptr[0] == 0x00) && (data_ptr[1] == 0x00) && (data_ptr[2] == 0x00) && (data_ptr[3] == 0x01))
    {

        /* Yes, skip the 4 bytes header. */
        data_ptr += 4;
    }
    else if ((data_ptr[0] == 0x00) && (data_ptr[1] == 0x00) && (data_ptr[2] == 0x01))
    {

        /* Yes, skip the 3 bytes header. */
        data_ptr += 3;
    }
    else
    {

        /* Wrong h264 header, return not successful. */
        return(NX_NOT_SUCCESSFUL);
    }

    /* There are conditions requiring below while loop to guarantee the procedure of separation and transmission:
       1) Special frame(s) such as SEI, SPS and PPS are passed with a data frame.
       2) The data frame is composed of several slices
    */
    while (data_ptr <= (frame_end - 4))
    {

        /* Set the start position and reset the single frame size. */
        nal_unit_start = data_ptr;
        nal_unit_size = 0;

        /* Extract a complete frame from the raw source file through finding the next 4/3 bytes header or the end of data buffer. */
        while (1)
        {

            /* Check if there is a new slice header found */
            if ((data_ptr[0] == 0x00) && (data_ptr[1] == 0x00))
            {

                if ((data_ptr[2] == 0x00) && (data_ptr[3] == 0x01))
                {

                    /* Jump out if 4 bytes header of next frame/slice found. */
                    nal_unit_size = (ULONG)(data_ptr - nal_unit_start + 1);
                    data_ptr += 4;
                    break;
                }
                else if (data_ptr[2] == 0x01)
                {

                    /* Jump out if 3 bytes header of next frame/slice found. */
                    nal_unit_size = (ULONG)(data_ptr - nal_unit_start + 1);
                    data_ptr += 3;
                    break;
                }
            }

            /* Skip the check last 4 bytes if no header found is current position. */
            if (data_ptr >= (frame_end - 4))
            {

                /* Compute nal unit size and move data pointer to the end. */
                nal_unit_size = (ULONG)(frame_end - nal_unit_start + 1);
                data_ptr = frame_end;

                /* Set the send marker and jump out. */
                send_marker = NX_TRUE;
                break;
            }

            /* Move and check next byte. */
            data_ptr++;
        }

        /* Initialize NAL unit type with the first byte after the h264 header. */
        nal_unit_type = nal_unit_start[0];

        /* Check NAL unit type. */
        if (((nal_unit_type & NX_RTP_SENDER_H264_TYPE_MASK_BITS) == NX_RTP_SENDER_H264_TYPE_SEI) ||
            ((nal_unit_type & NX_RTP_SENDER_H264_TYPE_MASK_BITS) == NX_RTP_SENDER_H264_TYPE_SPS) ||
            ((nal_unit_type & NX_RTP_SENDER_H264_TYPE_MASK_BITS) == NX_RTP_SENDER_H264_TYPE_PPS))
        {

            /* Clear the send marker for special frames. */
            send_marker = NX_FALSE;
        }

        /* Check the frame size and determine if more than 1 packet are needed. */
        if (nal_unit_size <= max_packet_length)
        {

            /* RTP payload format for single NAL unit packet (in this case, the NAL header byte is the same as VCL header byte):
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |F|NRI|  Type   |                                               |
            +-+-+-+-+-+-+-+-+                                               |
            |                                                               |
            |              Bytes 2..n of a single NAL unit                  |
            |                                                               |
            |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                               :...OPTIONAL RTP padding        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            */

            /* Allocate a rtp packet */
            status = _nx_rtp_sender_session_packet_allocate(session, &send_packet, NX_RTP_SENDER_PACKET_TIMEOUT);
            if (status)
            {
                return(status);
            }

            /* Copy payload data into the packet. */
            status = nx_packet_data_append(send_packet, (void*)nal_unit_start, nal_unit_size,
                                           session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr,
                                           NX_RTP_SENDER_PACKET_TIMEOUT);
            if (status)
            {
                nx_packet_release(send_packet);
                return(status);
            }

            /* Send packet data */
            status = _nx_rtp_sender_session_packet_send(session, send_packet, timestamp, ntp_msw, ntp_lsw, send_marker);
            if (status)
            {
                nx_packet_release(send_packet);
                return(status);
            }
        }
        else
        {

            /* RTP payload format for FU-A packets (in this case, 1 byte VCL header extends to 2 bytes NAL header):
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | FU indicator |    FU header   |                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
            |                                                               |
            |                         FU payload                            |
            |                                                               |
            |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                               :...OPTIONAL RTP padding        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            1) Format for FU indicator octet:        2) Format for FU header:
               +---------------+                        +---------------+
               |0|1|2|3|4|5|6|7|                        |0|1|2|3|4|5|6|7|
               +-+-+-+-+-+-+-+-+                        +-+-+-+-+-+-+-+-+
               |F|NRI|  Type   |                        |S|E|R|  Type   |
               +---------------+                        +---------------+
            */

            /* Reserve the bytes space for fu-a header. */
            max_packet_length -= sizeof(fu_a_header);

            /* Compute the number of packets with the size of the last packet. */
            packet_num = ((nal_unit_size - 1) / max_packet_length) + 1;
            last_packet_size = nal_unit_size % max_packet_length;

            /* Initialize fu-a header's first byte with the source priority and fu-a type. */
            fu_a_header[0] = (UCHAR)((nal_unit_type & NX_RTP_SENDER_H264_NRI_MASK_BITS) | NX_RTP_SENDER_H264_TYPE_FU_A);

            /* Initialize fu-a header's second byte with the source nal unit type. */
            fu_a_header[1] = (UCHAR)(nal_unit_type & NX_RTP_SENDER_H264_TYPE_MASK_BITS);

            for (i = 0; i < packet_num; i++)
            {

                /* Check which packet to transmit and execute different corresponding logic. */
                if (i == 0)
                {

                    /* Set the fu-a start bit for the first frame fragment. */
                    fu_a_header[1] |= NX_RTP_SENDER_H264_FU_A_S_MASK_BIT;

                    /* Set the send marker as false. */
                    temp_marker = NX_FALSE;

                    /* Skip the first NAL unit type byte, and update the send packet length. */
                    nal_unit_start++;
                    send_packet_length = max_packet_length - 1;
                }
                else if (i == (packet_num - 1))
                {

                    /* Clear the fu-a start bit and set fu-a end bit for the last frame fragment. */
                    fu_a_header[1] &= (UCHAR)(~NX_RTP_SENDER_H264_FU_A_S_MASK_BIT);
                    fu_a_header[1] |= NX_RTP_SENDER_H264_FU_A_E_MASK_BIT;

                    /* Update send marker by the final data frame flag. */
                    temp_marker = send_marker;

                    /* Update packet length based on whether the last packet size is not zero. */
                    send_packet_length = last_packet_size ? last_packet_size : max_packet_length;
                }
                else
                {

                    /* Clear the fu-a start bit for middle slices. */
                    fu_a_header[1] &= (UCHAR)(~NX_RTP_SENDER_H264_FU_A_S_MASK_BIT);

                    /* Update the send packet length. */
                    send_packet_length = max_packet_length;
                }

                /* Allocate a packet */
                status = _nx_rtp_sender_session_packet_allocate(session, &send_packet, NX_RTP_SENDER_PACKET_TIMEOUT);
                if (status)
                {
                    return(status);
                }

                /* Copy fu-a header into the packet. */
                status = nx_packet_data_append(send_packet, (void *)fu_a_header, sizeof(fu_a_header),
                                               session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr,
                                               NX_RTP_SENDER_PACKET_TIMEOUT);
                if (status)
                {
                    nx_packet_release(send_packet);
                    return(status);
                }

                /* Copy payload data into the packet. */
                status = nx_packet_data_append(send_packet, (void *)nal_unit_start, send_packet_length,
                                               session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr,
                                               NX_RTP_SENDER_PACKET_TIMEOUT);
                if (status)
                {
                    nx_packet_release(send_packet);
                    return(status);
                }

                /* Send packet data */
                status = _nx_rtp_sender_session_packet_send(session, send_packet, timestamp, ntp_msw, ntp_lsw, temp_marker);
                if (status)
                {
                    nx_packet_release(send_packet);
                    return(status);
                }

                /* Move start pointer to following position. */
                nal_unit_start += send_packet_length;
            }
        }
    }

    /* Return success status. */
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_rtp_sender_session_aac_send                   PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks errors in the RTP sender session aac send      */
/*    function call.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    frame_data                           Pointer to data buffer to send */
/*    frame_data_size                      Size of data to send           */
/*    timestamp                            RTP timestamp for current data */
/*    ntp_msw                              Most significant word of       */
/*                                           network time                 */
/*    ntp_lsw                              Least significant word of      */
/*                                           network time                 */
/*    marker                               Marker bit for significant     */
/*                                           event such as frame boundary */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*    NX_PTR_ERROR                         Invalid pointer input          */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_aac_send      Send aac frame data            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nxe_rtp_sender_session_aac_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                      ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker)
{

UINT status;


    /* Check for invalid input pointers. */
    if ((session == NX_NULL) || (session -> nx_rtp_sender == NX_NULL) || (session -> nx_rtp_session_id != NX_RTP_SESSION_ID) || (frame_data == NX_NULL))
    {
        return(NX_PTR_ERROR);
    }

    /* Call actual RTP sender session frame send service. */
    status = _nx_rtp_sender_session_aac_send(session, frame_data, frame_data_size, timestamp, ntp_msw, ntp_lsw, marker);

    /* Return status. */
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rtp_sender_session_aac_send                    PORTABLE C       */
/*                                                           6.3.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Haiqing Zhao, Microsoft Corporation                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses and makes the passed data in RTP/AAC format,   */
/*    and then calls RTP session send function to send these data in RTP  */
/*    packet, with AAC-HBR mode.                                          */
/*    The function references RFC 3640 as the standard with below notes:  */
/*    1) A complete aac frame data shall be inside frame data buffer      */
/*    2) SDP shall indicate that aac-hbr mode is applied, with SizeLength */
/*       field to be 13 since 13-bit frame length is applied for          */
/*       computing the length in AU header.                               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    session                              Pointer to RTP session         */
/*    frame_data                           Pointer to data buffer to send */
/*    frame_data_size                      Size of data to send           */
/*    timestamp                            RTP timestamp for current data */
/*    ntp_msw                              Most significant word of       */
/*                                           network time                 */
/*    ntp_lsw                              Least significant word of      */
/*                                           network time                 */
/*    marker                               Marker bit for significant     */
/*                                           event such as frame boundary */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                               Completion status              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_rtp_sender_session_packet_allocate                              */
/*                                         Allocate a packet for the user */
/*    nx_packet_data_append                Copy the specified data to     */
/*                                            the end of specified packet */
/*    nx_packet_data_release               Release the packet             */
/*    _nx_rtp_sender_session_packet_send   Send RTP packet                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  10-31-2023     Haiqing Zhao            Initial Version 6.3.0          */
/*                                                                        */
/**************************************************************************/
UINT _nx_rtp_sender_session_aac_send(NX_RTP_SESSION *session, UCHAR *frame_data, ULONG frame_data_size,
                                     ULONG timestamp, ULONG ntp_msw, ULONG ntp_lsw, UINT marker)
{

UINT       status;
UCHAR      au_header[4] = {0x00, 0x10, 0x00, 0x00}; /* First 2 bytes represent au header length, with default 16 bits. */
ULONG      send_packet_length;
ULONG      max_packet_length = session -> nx_rtp_session_max_packet_size - sizeof(au_header);
NX_PACKET *send_packet = NX_NULL;
UCHAR     *data_ptr;
UINT       temp_marker;


    /* In current design, the marker bit shall be always 1 (i.e. a complete aac frame required to be passed). */
    if (marker != NX_TRUE)
    {
        return(NX_NOT_SUPPORTED);
    }

    /* When frame data exceeds maximum defined value, it requires access unit fragment feature which is not supported so far.
       This check is specific for aac-hbr mode. */
    if (frame_data_size > NX_RTP_SENDER_AAC_HBR_MODE_MAX_DATA_SIZE)
    {
        return(NX_NOT_SUPPORTED);
    }

    /* Initialize data_ptr to where data bytes begin. */
    data_ptr = frame_data;

    while (frame_data_size > 0)
    {

        /* Allocate a rtp packet. */
        status = _nx_rtp_sender_session_packet_allocate(session, &send_packet, NX_RTP_SENDER_PACKET_TIMEOUT);
        if (status)
        {
            return(status);
        }

        /* Check if fragmentation needed, and assign data length. */
        if (frame_data_size > max_packet_length)
        {
            send_packet_length = max_packet_length;
            temp_marker = NX_FALSE;
        }
        else
        {
            send_packet_length = frame_data_size;
            temp_marker = NX_TRUE;
        }

        /* Compute the data length inside the current packet. */
        au_header[2] = (UCHAR)((send_packet_length & NX_RTP_SENDER_AAC_FRAME_DATA_LENGTH_HIGH_BITS_MASK) >> 5);
        au_header[3] = (UCHAR)((send_packet_length & NX_RTP_SENDER_AAC_FRAME_DATA_LENGTH_LOW_BITS_MASK) << 3);

        /* Copy aac header data into the packet. */
        status = nx_packet_data_append(send_packet, (void *)au_header, sizeof(au_header),
                                       session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_RTP_SENDER_PACKET_TIMEOUT);
        if (status)
        {
            nx_packet_release(send_packet);
            return(status);
        }

        /* Copy payload data into the packet. */
        status = nx_packet_data_append(send_packet, (void *)data_ptr, send_packet_length,
                                       session -> nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_RTP_SENDER_PACKET_TIMEOUT);
        if (status)
        {
            nx_packet_release(send_packet);
            return(status);
        }

        /* Send AAC frame through rtp; passed marker bit with true when this is the last frame packet. */
        status = _nx_rtp_sender_session_packet_send(session, send_packet, timestamp, ntp_msw, ntp_lsw, temp_marker);
        if (status)
        {
            nx_packet_release(send_packet);
            return(status);
        }

        /* Compute remaining frame length and move data pointer. */
        frame_data_size -= send_packet_length;
        data_ptr += send_packet_length;
    }

    /* Return success status. */
    return(NX_SUCCESS);
}
