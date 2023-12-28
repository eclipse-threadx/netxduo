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
/*    nxd_ptp_client.c                                    PORTABLE C      */
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


/* Force error checking to be disabled in this module */

#ifndef NX_DISABLE_ERROR_CHECKING
#define NX_DISABLE_ERROR_CHECKING
#endif

#define NX_PTP_SOURCE_CODE

#include "nxd_ptp_client.h"
#if NX_PTP_CLIENT_TRANSPORT_UDP
#include "nx_udp.h"
#include "nx_ipv4.h"
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
#include "nx_ipv6.h"
#endif
#endif
#include "tx_timer.h"

/* #define NX_PTP_DEBUG */
/* #define NX_PTP_DEBUG_OFFSET */
/* #define NX_PTP_DEBUG_DELAY */
/* #define NX_PTP_DEBUG_RATE_RATIO */
#if defined(NX_PTP_DEBUG) || defined(NX_PTP_DEBUG_OFFSET) || defined(NX_PTP_DEBUG_DELAY) || defined(NX_PTP_DEBUG_RATE_RATIO)
#include <stdio.h>
#endif
#ifdef NX_PTP_DEBUG
#ifndef NX_PTP_DEBUG_PRINTF
#define NX_PTP_DEBUG_PRINTF(x) printf x
#endif
#else
#define NX_PTP_DEBUG_PRINTF(x)
#endif

/* Bring in externs for caller checking code.  */

NX_CALLER_CHECKING_EXTERNS

/* number of nanoseconds per second */
#define NX_PTP_NANOSECONDS_PER_SEC             1000000000L

/* Define the PTP version */
#define NX_PTP_VERSION                         2

/* Define the UDP ports */
#define NX_PTP_EVENT_UDP_PORT                  319
#define NX_PTP_GENERAL_UDP_PORT                320

/* Define the TTL of PTP packets */
#define NX_PTP_TIME_TO_LIVE                    1

/* Define the IPv4 multicast address "224.0.1.129" */
#define NX_PTP_IPV4_MULTICAST_ADDR             IP_ADDRESS(224, 0, 1, 129)

/* Define the IPv4 P2P multicast address "224.0.0.107" */
#define NX_PTP_IPV4_P2P_MULTICAST_ADDR         IP_ADDRESS(224, 0, 0, 107)

/* Define the IPv6 multicast address "ff0e::181" */
#define NX_PTP_IPV6_MULTICAST_ADDR_SET(x)      {    \
        (x) -> nxd_ip_version = NX_IP_VERSION_V6;   \
        (x) -> nxd_ip_address.v6[0] = 0xff0e0000UL; \
        (x) -> nxd_ip_address.v6[1] = 0;            \
        (x) -> nxd_ip_address.v6[2] = 0;            \
        (x) -> nxd_ip_address.v6[3] = 0x181; }

/* Define the IPv6 multicast address "ff02::6b" */
#define NX_PTP_IPV6_P2P_MULTICAST_ADDR_SET(x)  {    \
        (x) -> nxd_ip_version = NX_IP_VERSION_V6;   \
        (x) -> nxd_ip_address.v6[0] = 0xff020000UL; \
        (x) -> nxd_ip_address.v6[1] = 0;            \
        (x) -> nxd_ip_address.v6[2] = 0;            \
        (x) -> nxd_ip_address.v6[3] = 0x6b; }

/* Define Ethernet type for PTPv2 over Ethernet */
#define NX_PTP_ETHERNET_TYPE                   0x88F7

/* Define Ethernet multicast address for PTPv2 over Ethernet */
#define NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_MSB 0x0180
#define NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_LSB 0xC200000E

/* Define Ethernet multicast address for all except peer delay messages */
#define NX_PTP_ETHERNET_ALL_MULTICAST_ADDR_MSB 0x011b
#define NX_PTP_ETHERNET_ALL_MULTICAST_ADDR_LSB 0x19000000


#if NX_PTP_CLIENT_TRANSPORT_UDP
#define NX_PTP_PACKET                          NX_UDP_PACKET
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
#define NX_PTP_PACKET                          NX_PHYSICAL_HEADER
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */

/* Length of PTP message header */
#define NX_PTP_MSG_HDR_LEN                     34

/* Length of PTP messages (without header) */
#define NX_PTP_MSG_ANNOUNCE_LEN                30
#define NX_PTP_MSG_SYNC_LEN                    10
#define NX_PTP_MSG_FOLLOW_UP_LEN               10
#define NX_PTP_MSG_DELAY_RESP_LEN              20

/* Length of PTP messages gPTP (without header) */
#define NX_PTP_MSG_PDELAY_REQ_LEN              20
#define NX_PTP_MSG_PDELAY_RESP_LEN             20
#define NX_PTP_MSG_PDELAY_RESP_FOLLOW_UP_LEN   20
#define NX_PTP_MSG_PDELAY_RESERVED_LEN         10

/* Length of PTP timestamp */
#define NX_PTP_MSG_TIMESTAMP_LEN               10

/* Length of PTP correctionField */
#define NX_PTP_MSG_CFIELD_TIMESTAMP_LEN        8

/* Get version number */
#define NX_PTP_MSG_VERSION(p_)                 ((p_)[1] & 0xf)

/* Get domain number */
#define NX_PTP_MSG_DOMAIN(p_)                  ((p_)[4])

/* Type of messages */
#define NX_PTP_MSG_TYPE_SYNC                   0
#define NX_PTP_MSG_TYPE_DELAY_REQ              1
#define NX_PTP_MSG_TYPE_PDELAY_REQ             2
#define NX_PTP_MSG_TYPE_PDELAY_RESP            3
#define NX_PTP_MSG_TYPE_FOLLOW_UP              8
#define NX_PTP_MSG_TYPE_DELAY_RESP             9
#define NX_PTP_MSG_TYPE_PDELAY_RESP_FOLLOW_UP  10
#define NX_PTP_MSG_TYPE_ANNOUNCE               11

/* Message flags */
#define NX_PTP_MSG_HDR_FLAG_LEAP61             (1 << 0)
#define NX_PTP_MSG_HDR_FLAG_LEAP59             (1 << 1)
#define NX_PTP_MSG_HDR_FLAG_UTC_REASONABLE     (1 << 2)
#define NX_PTP_MSG_HDR_FLAG_TWO_STEP           (1 << 9)

/* Common Message Header */
typedef struct NX_PTP_MSG_HEADER_STRUCT
{
    UCHAR  transportSpecific;
    UCHAR  messageType;
    UCHAR  versionPTP;
    UCHAR  domainNumber;
    USHORT messageLength;
    USHORT flagField;
    ULONG  cFieldHigh;
    ULONG  cFieldLow;
    UCHAR *sourcePortIdentity;
    USHORT sequenceId;
    UCHAR  logMessageInterval;
} NX_PTP_MSG_HEADER;

/* Get UTC offset from announce message */
#define NX_PTP_MSG_UTC_OFFSET(p_) ((SHORT)((p_[10] << 8) | p_[11]))

/* Macros for reading PTP packet fields */
#define NX_PTP_RD16(p_, v_)       { \
        USHORT t_;                  \
        t_ = *p_++;                 \
        t_ = (USHORT)(t_ << 8);     \
        v_ = (USHORT)(t_ | *p_++); }

#define NX_PTP_RD32(p_, v_)       { \
        ULONG t_;                   \
        t_ = *p_++;                 \
        t_ <<= 8;                   \
        t_ |= *p_++;                \
        t_ <<= 8;                   \
        t_ |= *p_++;                \
        t_ <<= 8;                   \
        v_ = t_ |= *p_++; }

#if defined(NX_ENABLE_GPTP) || defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC)
static VOID  _nx_ptp_utility_32_unsigned_write(UCHAR *dest_ptr, ULONG value)
{

    *(dest_ptr)     = (UCHAR)((value >> 24) & 0xFF);
    *(dest_ptr + 1) = (UCHAR)((value >> 16) & 0xFF);
    *(dest_ptr + 2) = (UCHAR)((value >> 8) & 0xFF);
    *(dest_ptr + 3) = (UCHAR)(value & 0xFF);
}
#endif

#define NX_PTP_TS_RESET(ts) (ts).second_high = 0; \
                            (ts).second_low = 0;  \
                            (ts).nanosecond = 0;  \

#define NX_PTP_TS_COPY(ts1, ts2) (ts1).second_high = (ts2).second_high; \
                                 (ts1).second_low = (ts2).second_low;   \
                                 (ts1).nanosecond = (ts2).nanosecond;   \

#define NX_PTP_TS_EQUAL(ts1, ts2) ((ts1).second_high == (ts2).second_high && \
                                   (ts1).second_low == (ts2).second_low &&   \
                                   (ts1).nanosecond == (ts2).nanosecond)

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_msg_parse_timestamp                         PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses timestamp field of a PTP message.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ptr                                   Pointer to PTP message        */
/*    time_ptr                              Pointer to PTP time for output*/
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
/*    _nx_ptp_client_sync_received          Process Sync message          */
/*    _nx_ptp_client_delay_resp_received    Process delay response        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_msg_parse_timestamp(UCHAR *ptr, NX_PTP_TIME *time_ptr)
{
ULONG nanoseconds = (ULONG)time_ptr -> nanosecond;

    NX_PTP_RD16(ptr, time_ptr -> second_high);
    NX_PTP_RD32(ptr, time_ptr -> second_low);
    NX_PTP_RD32(ptr, nanoseconds);
    time_ptr -> nanosecond = (LONG)nanoseconds;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_msg_parse_hdr                               PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses the header of a PTP packet.                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    packet_ptr                            Pointer to PTP packet         */
/*    hdr                                   Parsed PTP header for output  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nxd_udp_packet_info_extract           Extract UDP packet information*/
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_process_event_packet   Process PTP event packet      */
/*    _nx_ptp_client_process_general_packet Process PTP general packet    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*  12-31-2023     Tiejun Zhou              Modified comment(s), and      */
/*                                            supported gPTP profile,     */
/*                                            resulting in version 6.4.0  */
/*                                                                        */
/**************************************************************************/
static UINT _nx_ptp_msg_parse_hdr(NX_PTP_CLIENT *client_ptr, NX_PACKET *packet_ptr, NX_PTP_MSG_HEADER *hdr)
{
UCHAR  b;
UCHAR *ptr;
UINT   len;
#if NX_PTP_CLIENT_TRANSPORT_UDP
UINT   status;
NXD_ADDRESS src_addr;
UINT   interface_index;
#endif

#ifndef NX_DISABLE_PACKET_CHAIN
    if (packet_ptr -> nx_packet_next)
    {

        /* Chained packet is not supported */
        return(NX_NOT_SUPPORTED);
    }
#endif /* NX_DISABLE_PACKET_CHAIN */

    /* get pointer to PTP message */
    ptr = packet_ptr -> nx_packet_prepend_ptr;

    /* get length of PTP message */
    len = packet_ptr -> nx_packet_length;

    /* check packet validity: */
    /* - length >= PTP header length */
    /* - PTP version */
    /* - domain number */
    if ((len < NX_PTP_MSG_HDR_LEN) ||
        (NX_PTP_MSG_VERSION(ptr) != NX_PTP_VERSION) ||
        (NX_PTP_MSG_DOMAIN(ptr) != client_ptr -> nx_ptp_client_domain))
    {

        /* discard invalid packet */
        return(NX_INVALID_PACKET);
    }

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* get info about sender and check packet validity: */
    /* - network interface */
    /* - IP version */
    status = nxd_udp_packet_info_extract(packet_ptr, &src_addr, NX_NULL, NX_NULL, &interface_index);
    if ((status != NX_SUCCESS) ||
        (interface_index != client_ptr -> nx_ptp_client_interface_index)
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
        || ((src_addr.nxd_ip_version == NX_IP_VERSION_V4) &&
            !client_ptr -> nx_ptp_client_ipv4_group_joined) ||
        ((src_addr.nxd_ip_version == NX_IP_VERSION_V6) &&
            !client_ptr -> nx_ptp_client_ipv6_group_joined)
#endif
        )
    {

        /* discard invalid packet */
        return(NX_INVALID_PACKET);
    }

    /* Save source address in listening state */
    if (client_ptr -> nx_ptp_client_state == NX_PTP_CLIENT_STATE_LISTENING)
    {
        client_ptr -> nx_ptp_client_master_addr = src_addr;
    }
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    b = *ptr++;
    hdr -> transportSpecific = b >> 4;
    hdr -> messageType = b & 0xf;
    b = *ptr++;
    hdr -> versionPTP = b & 0xf;
    NX_PTP_RD16(ptr, hdr -> messageLength);
    hdr -> domainNumber = *ptr++;
    ptr++;      /* reserved */
    NX_PTP_RD16(ptr, hdr -> flagField);
    NX_PTP_RD32(ptr, hdr -> cFieldHigh);
    NX_PTP_RD32(ptr, hdr -> cFieldLow);
    ptr += 4;   /* reserved */
    hdr -> sourcePortIdentity = ptr;
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;
    NX_PTP_RD16(ptr, hdr -> sequenceId);
    ptr++;      /* controlField - ignore */
    hdr -> logMessageInterval = *ptr;

    /* adjust message length */
    if (len > hdr -> messageLength)
    {
        if (hdr -> messageLength < NX_PTP_MSG_HDR_LEN)
        {

            /* invalid length */
            return(NX_INVALID_PACKET);
        }
        len = hdr -> messageLength;
    }

    /* Adjust packet. */
    packet_ptr -> nx_packet_prepend_ptr += NX_PTP_MSG_HDR_LEN;
    packet_ptr -> nx_packet_length = len - NX_PTP_MSG_HDR_LEN;

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_msg_parse_announce                          PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses PTP Announce message.                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ptr                                   Pointer to PTP message        */
/*    master_ptr                            Parsed PTP master for output  */
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
/*    _nx_ptp_client_init_packet_received   Process Announce message      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_msg_parse_announce(UCHAR *ptr, NX_PTP_CLIENT_MASTER *master)
{
    ptr += NX_PTP_MSG_TIMESTAMP_LEN + 2 + 1; /* originTimestamp, utcOffset, reserved */
    master -> nx_ptp_client_master_priority1 = *ptr++;
    master -> nx_ptp_client_master_clock_class = *ptr++;
    master -> nx_ptp_client_master_clock_accuracy = *ptr++;
    NX_PTP_RD16(ptr, master -> nx_ptp_client_master_offset_scaled_log_variance);
    master -> nx_ptp_client_master_priority2 = *ptr++;
    master -> nx_ptp_client_master_grandmaster_identity = ptr;
    ptr += NX_PTP_CLOCK_IDENTITY_SIZE;
    NX_PTP_RD16(ptr, master -> nx_ptp_client_master_steps_removed);
    master -> nx_ptp_client_master_time_source = *ptr;
}

#ifdef NX_PTP_ENABLE_MASTER
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_master_clock_compare                    PORTABLE C   */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function compares two clocks for master1 and master2.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    master1                               Pointer to first master clock */
/*    master2                               Pointer to second master clock*/
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    Compare result.                                                      */
/*    Return positive if master1 is better than master2.                  */
/*    Return zero if master1 is identical to master2.                     */
/*    Return negative if master1 is worse than master2.                   */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memcmp                                Compare memory                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_init_packet_received   Process PTP announce message  */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
static INT _nx_ptp_client_master_clock_compare(NX_PTP_CLIENT_MASTER *master1, NX_PTP_CLIENT_MASTER *master2)
{
INT result;
INT gm_compare;

    gm_compare = memcmp(master2 -> nx_ptp_client_master_grandmaster_identity,
                        master1 -> nx_ptp_client_master_grandmaster_identity,
                        NX_PTP_CLOCK_IDENTITY_SIZE);
    if (gm_compare == 0)
    {

        /* Clock identical.  */
        return(0);
    }

    result = (INT)master2 -> nx_ptp_client_master_priority1 -
             (INT)master1 -> nx_ptp_client_master_priority1;
    if (result != 0)
    {
        return(result);
    }

    result = (INT)master2 -> nx_ptp_client_master_clock_class -
             (INT)master1 -> nx_ptp_client_master_clock_class;
    if (result != 0)
    {
        return(result);
    }

    result = (INT)master2 -> nx_ptp_client_master_clock_accuracy -
             (INT)master1 -> nx_ptp_client_master_clock_accuracy;
    if (result != 0)
    {
        return(result);
    }

    result = (INT)master2 -> nx_ptp_client_master_offset_scaled_log_variance -
             (INT)master1 -> nx_ptp_client_master_offset_scaled_log_variance;
    if (result != 0)
    {
        return(result);
    }

    result = (INT)master2 -> nx_ptp_client_master_priority2 -
             (INT)master1 -> nx_ptp_client_master_priority2;
    if (result != 0)
    {
        return(result);
    }

    return(gm_compare);
}
#endif /* NX_PTP_ENABLE_MASTER */


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_soft_clock_adjust                    PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function adjusts the value of the soft PTP clock.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ptp_instance                          Pointer to PTP client         */
/*    offset_ns                             Signed number of nanoseconds  */
/*                                            to add to the PTP clock     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_utility_inc64          Increment a 64-bit number     */
/*    _nx_ptp_client_utility_dec64          Decrement a 64-bit number     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_soft_clock_callback    Soft PTP clock                */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_soft_clock_adjust(VOID *ptp_instance, LONG offset_ns)
{
NX_PTP_CLIENT *client_ptr = (NX_PTP_CLIENT *)ptp_instance;
TX_INTERRUPT_SAVE_AREA

    /* enforce min/max values of offset */
    if (offset_ns > NX_PTP_NANOSECONDS_PER_SEC)
    {
        offset_ns = NX_PTP_NANOSECONDS_PER_SEC;
    }
    else if (offset_ns < -NX_PTP_NANOSECONDS_PER_SEC)
    {
        offset_ns = -NX_PTP_NANOSECONDS_PER_SEC;
    }

    /* add the number of nanosecond to the current time */
    TX_DISABLE
    client_ptr -> nx_ptp_client_soft_clock.nanosecond += offset_ns;
    if (client_ptr -> nx_ptp_client_soft_clock.nanosecond >= NX_PTP_NANOSECONDS_PER_SEC)
    {
        client_ptr -> nx_ptp_client_soft_clock.nanosecond -= NX_PTP_NANOSECONDS_PER_SEC;
        _nx_ptp_client_utility_inc64(&client_ptr -> nx_ptp_client_soft_clock.second_high,
                                     &client_ptr -> nx_ptp_client_soft_clock.second_low);
    }
    else if (client_ptr -> nx_ptp_client_soft_clock.nanosecond < 0)
    {
        client_ptr -> nx_ptp_client_soft_clock.nanosecond += NX_PTP_NANOSECONDS_PER_SEC;
        _nx_ptp_client_utility_dec64(&client_ptr -> nx_ptp_client_soft_clock.second_high,
                                     &client_ptr -> nx_ptp_client_soft_clock.second_low);
    }
    TX_RESTORE
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_timer_handler                        PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function implements the PTP client timer handler.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ptp_instance                          Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_set                    Set PTP timer event           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    ThreadX Timer                                                       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_timer_handler(ULONG ptp_instance)
{
NX_PTP_CLIENT *client_ptr = (NX_PTP_CLIENT *)ptp_instance;

    /* Update soft timer.  */
    client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_SOFT_TIMER_UPDATE,
                                               &client_ptr -> nx_ptp_client_soft_clock, NX_NULL,
                                               client_ptr -> nx_ptp_client_clock_callback_data);

    /* set timer event */
    tx_event_flags_set(&(client_ptr -> nx_ptp_client_events), NX_PTP_CLIENT_TIMER_EVENT, TX_OR);
}


#if NX_PTP_CLIENT_TRANSPORT_UDP
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_socket_receive_notify                PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function is invoked when UDP packet is received.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to general socket     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_set                    Set UDP receive event         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX UDP                                                            */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_socket_receive_notify(NX_UDP_SOCKET *socket_ptr)
{
NX_PTP_CLIENT *client_ptr = (NX_PTP_CLIENT *)(socket_ptr -> nx_udp_socket_reserved_ptr);

    /* set timer event */
    tx_event_flags_set(&(client_ptr -> nx_ptp_client_events), NX_PTP_CLIENT_RX_EVENT, TX_OR);
}
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */


#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_ethernet_receive_notify              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function is invoked when a packet is received.                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*                                                                        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_set                    Set receive event             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX link layer                                                     */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_ptp_client_ethernet_receive_notify(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                                   ULONG physical_address_msw, ULONG physical_address_lsw,
                                                   UINT packet_type, UINT header_size, VOID *context,
                                                   struct NX_LINK_TIME_STRUCT *time_ptr)
{
TX_INTERRUPT_SAVE_AREA
NX_PTP_CLIENT *client_ptr = (NX_PTP_CLIENT *)context;

    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(interface_index);
    NX_PARAMETER_NOT_USED(physical_address_msw);
    NX_PARAMETER_NOT_USED(physical_address_lsw);
    NX_PARAMETER_NOT_USED(packet_type);
    NX_PARAMETER_NOT_USED(time_ptr);

    /* Clean off the Ethernet header.  */
    packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + header_size;

    /* Adjust the packet length.  */
    packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - header_size;

    /* Disable interrupts.  */
    TX_DISABLE

    /* Check to see if the receive queue is empty.  */
    if (client_ptr -> nx_ptp_client_received_packet_head)
    {

        /* Not empty, just place the packet at the end of the queue.  */
        (client_ptr -> nx_ptp_client_received_packet_tail) -> nx_packet_queue_next =  packet_ptr;
        packet_ptr -> nx_packet_queue_next =  NX_NULL;
        client_ptr -> nx_ptp_client_received_packet_tail =  packet_ptr;

        /* Restore interrupts.  */
        TX_RESTORE
    }
    else
    {

        /* Empty receive processing queue.  */
        client_ptr -> nx_ptp_client_received_packet_head =  packet_ptr;
        client_ptr -> nx_ptp_client_received_packet_tail =  packet_ptr;
        packet_ptr -> nx_packet_queue_next =             NX_NULL;

        /* Restore interrupts.  */
        TX_RESTORE

        /* set timer event */
        tx_event_flags_set(&(client_ptr -> nx_ptp_client_events), NX_PTP_CLIENT_RX_EVENT, TX_OR);
    }
    return(NX_SUCCESS);
}
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */


#ifndef NX_PTP_DISABLE_SLAVE
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_clock_adjust                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Adjust the PTP clock with the given offset                          */
/*    If the offset is greater than one second, the clock is updated,     */
/*    otherwise it is adjusted with the number of nanoseconds.            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    offset_ptr                            Pointer to time offset        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_utility_inc64          Increment a 64-bit number     */
/*    _nx_ptp_client_utility_dec64          Decrement a 64-bit number     */
/*    _nx_ptp_client_utility_add64          Add two 64-bit number         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_delay_resp_received    Process delay response        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*  12-31-2023     Tiejun Zhou              Modified comment(s), and      */
/*                                            supported master clock,     */
/*                                            resulting in version 6.4.0  */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_clock_adjust(NX_PTP_CLIENT *client_ptr, NX_PTP_TIME *offset_ptr)
{
NX_PTP_TIME current;

    if ((offset_ptr -> second_high == 0) && (offset_ptr -> second_low == 0))
    {

        /* offset less than 1s, adjust clock */
        client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_ADJUST, offset_ptr, NX_NULL,
                                                   client_ptr -> nx_ptp_client_clock_callback_data);
        NX_PTP_DEBUG_PRINTF(("PTP: adjust clock %d ns\r\n", (INT)offset_ptr -> nanosecond));
    }
    else
    {

        /* offset greater than 1s, set new clock value */
        /* get current clock value */
        client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_GET, &current, NX_NULL,
                                                   client_ptr -> nx_ptp_client_clock_callback_data);

        /* add nanoseconds offset */
        current.nanosecond += offset_ptr -> nanosecond;

        /* ensure nanosecond field is in range 0-999999999 */
        if (current.nanosecond < 0)
        {
            current.nanosecond += NX_PTP_NANOSECONDS_PER_SEC;
            _nx_ptp_client_utility_dec64(&current.second_high, &current.second_low);
        }
        else if (current.nanosecond >= NX_PTP_NANOSECONDS_PER_SEC)
        {
            current.nanosecond -= NX_PTP_NANOSECONDS_PER_SEC;
            _nx_ptp_client_utility_inc64(&current.second_high, &current.second_low);
        }

        /* add seconds offset */
        _nx_ptp_client_utility_add64(&current.second_high, &current.second_low,
                                     offset_ptr -> second_high, offset_ptr -> second_low);

        /* set new clock value */
        client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_SET, &current, NX_NULL,
                                                   client_ptr -> nx_ptp_client_clock_callback_data);

        NX_PTP_DEBUG_PRINTF(("PTP: set clock %u.%d\r\n",
                            (UINT)current.second_low,
                            (INT)current.nanosecond));
    }

#if defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC)
    if (client_ptr -> nx_ptp_client_sync_timer == 0)
    {

        /* Set timer values */
        client_ptr -> nx_ptp_client_sync_timer = NX_PTP_CLIENT_SYNC_INTERVAL;
    }
#endif /* defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC) */
}
#endif

#if NX_PTP_CLIENT_TRANSPORT_UDP
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_send_delay_req                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a PTP Delay Request message.                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nxd_udp_socket_source_send            Send a UDP packet             */
/*    nx_packet_release                     Release a packet              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_sync_received          Process Sync message          */
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
static VOID _nx_ptp_client_send_delay_req(NX_PTP_CLIENT *client_ptr)
{
NX_PACKET        *packet_ptr;
UINT              status = NX_NOT_SUCCESSFUL;
UCHAR            *ptr;
#if NX_PTP_CLIENT_TRANSPORT_UDP
NXD_ADDRESS       addr;
UINT              addr_index = 0;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_IPV6_ADDRESS *ipv6_addr;
NX_IP            *ip_ptr;
NX_INTERFACE     *if_ptr;
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* allocate a packet from the pool */
    status = nx_packet_allocate(client_ptr -> nx_ptp_client_packet_pool_ptr, &packet_ptr, NX_PTP_PACKET, NX_NO_WAIT);
    if (status != NX_SUCCESS)
    {
        /* Failed to allocate the packet */
        return;
    }

    /* start of message */
    ptr = packet_ptr -> nx_packet_prepend_ptr;

#define PTP_MSG_DELAY_REQ_TOTAL_LEN (NX_PTP_MSG_HDR_LEN + NX_PTP_MSG_TIMESTAMP_LEN)
#define PTP_MSG_DELAY_REQ_ZERO1_LEN (1 + 2 + 8 + 4) /* reserved(1) | flagField(2) | correctionField(8) | reserved(4) */

    /* write header */
    *ptr++ = NX_PTP_MSG_TYPE_DELAY_REQ;
    *ptr++ = NX_PTP_VERSION;
    *ptr++ = PTP_MSG_DELAY_REQ_TOTAL_LEN >> 8;
    *ptr++ = (UCHAR)PTP_MSG_DELAY_REQ_TOTAL_LEN;
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_transport_specific << 4) | client_ptr -> nx_ptp_client_domain;
    memset(ptr, 0, PTP_MSG_DELAY_REQ_ZERO1_LEN); /* reserved/flags/correction/reserved */
    ptr += PTP_MSG_DELAY_REQ_ZERO1_LEN;
    memcpy(ptr, client_ptr -> nx_ptp_client_port_identity,
           NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;
    client_ptr -> nx_ptp_client_delay_req_id++;
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_delay_req_id >> 8);
    *ptr++ = (UCHAR)client_ptr -> nx_ptp_client_delay_req_id;
    *ptr++ = 0; /* control */
    *ptr++ = 0; /* XXX */

    /* write timestamp (0) */
    memset(ptr, 0, NX_PTP_MSG_TIMESTAMP_LEN);
    ptr += NX_PTP_MSG_TIMESTAMP_LEN;

    /* set final length of message */
    packet_ptr -> nx_packet_length = (ULONG)(ptr - packet_ptr -> nx_packet_prepend_ptr);
    packet_ptr -> nx_packet_append_ptr = ptr;

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* set source and destination addresses */
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    if (client_ptr -> nx_ptp_client_master_addr.nxd_ip_version == NX_IP_VERSION_V6)
    {
        NX_PTP_IPV6_MULTICAST_ADDR_SET(&addr);

        /* Use first IPv6 address as source address. */
        ip_ptr = client_ptr -> nx_ptp_client_ip_ptr;
        if_ptr = &ip_ptr -> nx_ip_interface[client_ptr -> nx_ptp_client_interface_index];
        ipv6_addr = if_ptr -> nxd_interface_ipv6_address_list_head;
        if (ipv6_addr == NX_NULL)
        {

            /* No available IPv6 address.  */
            /* Release packet.  */
            nx_packet_release(packet_ptr);

            /* Reset state.  */
            client_ptr -> nx_ptp_client_delay_state = NX_PTP_CLIENT_DELAY_IDLE;
            client_ptr -> nx_ptp_client_delay_req_packet_ptr = NX_NULL;

            return;
        }
        addr_index = ipv6_addr -> nxd_ipv6_address_index;
    }
    else
#endif
    {
#ifndef NX_DISABLE_IPV4
        addr.nxd_ip_version = NX_IP_VERSION_V4;
        addr.nxd_ip_address.v4 = NX_PTP_IPV4_MULTICAST_ADDR;
        addr_index = client_ptr -> nx_ptp_client_interface_index;
#endif
    }
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* Prepare timestamp for current packet  */
    client_ptr -> nx_ptp_client_delay_state = NX_PTP_CLIENT_DELAY_WAIT_REQ_TS;
    client_ptr -> nx_ptp_client_delay_req_packet_ptr = packet_ptr;
    client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_PACKET_TS_PREPARE,
                                               &client_ptr -> nx_ptp_client_delay_ts, packet_ptr,
                                               client_ptr -> nx_ptp_client_clock_callback_data);

    /* Send delay request  */
#if NX_PTP_CLIENT_TRANSPORT_UDP
    status = nxd_udp_socket_source_send((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_event_socket,
                                        packet_ptr, &addr, NX_PTP_EVENT_UDP_PORT, addr_index);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    nx_link_ethernet_packet_send(client_ptr -> nx_ptp_client_ip_ptr,
                                 client_ptr -> nx_ptp_client_interface_index, packet_ptr,
                                 NX_PTP_ETHERNET_ALL_MULTICAST_ADDR_MSB,
                                 NX_PTP_ETHERNET_ALL_MULTICAST_ADDR_LSB,
                                 NX_PTP_ETHERNET_TYPE);
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */
    if (status)
    {

        /* release packet in case of error */
        nx_packet_release(packet_ptr);

        /* reset state */
        client_ptr -> nx_ptp_client_delay_state = NX_PTP_CLIENT_DELAY_IDLE;
        client_ptr -> nx_ptp_client_delay_req_packet_ptr = NX_NULL;

        return;
    }

    /* rearm delay req timer */
    client_ptr -> nx_ptp_client_delay_req_timer = NX_PTP_CLIENT_DELAY_REQ_INTERVAL;
    client_ptr -> nx_ptp_client_delay_req_flag = 0;
}
#endif

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_sync_received                        PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes a received PTP Sync message.                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    ts_ptr                                Pointer to the timestamp      */
/*                                           delivered by the Sync message*/
/*    hdr                                   Pointer to PTP header         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_msg_parse_timestamp           Parse timestamp field         */
/*    _nx_ptp_client_send_delay_req         Send delay request            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_process_event_packet   Process PTP event packet      */
/*    _nx_ptp_client_process_general_packet Process PTP general packet    */
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
static VOID _nx_ptp_client_sync_received(NX_PTP_CLIENT *client_ptr, VOID *ts_ptr, NX_PTP_MSG_HEADER *hdr)
{
#if defined NX_ENABLE_GPTP
NX_PTP_TIME offset;
#ifndef NX_PTP_DISABLE_SLAVE
NX_PTP_CLIENT_SYNC sync;
#endif /* NX_PTP_DISABLE_SLAVE */
#if defined(NX_PTP_DEBUG) || defined(NX_PTP_DEBUG_OFFSET)
double      rate_ratio;
NX_PTP_TIME delta_t1, delta_t2;
#endif 
#endif /* NX_ENABLE_GPTP */
NX_PTP_TIME correction;
ULONG64     correctionNS = (hdr -> cFieldHigh << 16) | (hdr -> cFieldLow >> 16);

    /* store Sync master timestamp */
    _nx_ptp_msg_parse_timestamp(ts_ptr, &client_ptr -> nx_ptp_client_sync);

    if (correctionNS != 0)
    {

        /* add correction field to offset.  */
        correction.second_high = 0;
        correction.second_low = (ULONG)(correctionNS / 1000000000);
        correction.nanosecond = (LONG)(correctionNS % 1000000000);
        _nx_ptp_client_utility_time_sum(&client_ptr -> nx_ptp_client_sync, &correction,
                                        &client_ptr -> nx_ptp_client_sync);
    }

#if defined NX_ENABLE_GPTP

    if ((client_ptr -> nx_ptp_client_delay.nanosecond > NX_PTP_CLIENT_DELAY_THRESH) ||
        (client_ptr -> nx_ptp_client_delay.second_low != 0) ||
        (client_ptr -> nx_ptp_client_delay.second_high != 0))
    {

        /* Not as capable. IEEE802.1AS-202, 11.2.2. */
        return;
    }

#if defined(NX_PTP_DEBUG) || defined(NX_PTP_DEBUG_OFFSET)
    /* Compute neighbor rate ratio.  
       neighborRateRatio = (t1 - prev_t1) / (t2 - prev_t2) */
    _nx_ptp_client_utility_time_diff(&client_ptr -> nx_ptp_client_sync,
                                     &client_ptr -> nx_ptp_client_prev_sync, &delta_t1);
    _nx_ptp_client_utility_time_diff(&client_ptr -> nx_ptp_client_sync_ts,
                                     &client_ptr -> nx_ptp_client_prev_sync_ts, &delta_t2);
    if ((delta_t1.second_low == 0) && (delta_t1.second_high == 0) &&
        (delta_t2.second_low == 0) && (delta_t2.second_high == 0))
    {
        rate_ratio = (double)delta_t1.nanosecond / (double)delta_t2.nanosecond;
    }
    else
    {
        rate_ratio = 1.0;
    }
    NX_PTP_DEBUG_PRINTF(("PTP: neighborRateRatio = %lu/%lu = %f\n",
                         delta_t1.nanosecond, delta_t2.nanosecond, rate_ratio));
#endif

    /* compute offset = sync_ts - sync_received_ts + delay */
    _nx_ptp_client_utility_time_diff(&client_ptr -> nx_ptp_client_sync, &client_ptr -> nx_ptp_client_sync_ts, &offset);
    _nx_ptp_client_utility_time_sum(&offset, &client_ptr -> nx_ptp_client_delay, &offset);

#if defined(NX_PTP_DEBUG) || defined(NX_PTP_DEBUG_OFFSET)
    if ((offset.second_low == 0) && (offset.second_high == 0))
    {
        if ((offset.nanosecond > -1000) && (offset.nanosecond < 1000))
        {
            NX_PTP_DEBUG_PRINTF(("PTP: offset = %ld ns\n", offset.nanosecond));
        }
        else if ((offset.nanosecond > -1000000) && (offset.nanosecond < 1000000))
        {
            NX_PTP_DEBUG_PRINTF(("PTP: offset = %ld us\n", offset.nanosecond / 1000));
        }
        else
        {
            NX_PTP_DEBUG_PRINTF(("PTP: offset = %ld ms\n", offset.nanosecond / 1000000));
        }
    }
    else
    {
        NX_PTP_DEBUG_PRINTF(("PTP: offset > 1s\n"));
    }
#endif

#ifndef NX_PTP_DISABLE_SLAVE
    if (client_ptr -> nx_ptp_client_state == NX_PTP_CLIENT_STATE_SLAVE)
    {
        
        /* add the time offset the client clock */
        _nx_ptp_client_clock_adjust(client_ptr, &offset);

        /* set calibrated flag */
        if (!(client_ptr -> nx_ptp_client_sync_flags & NX_PTP_CLIENT_SYNC_CALIBRATED))
        {
            client_ptr -> nx_ptp_client_sync_flags |= NX_PTP_CLIENT_SYNC_CALIBRATED;

            /* application callback */
            if (client_ptr -> nx_ptp_client_event_callback)
            {
                sync.nx_ptp_client_sync_flags = client_ptr -> nx_ptp_client_sync_flags;
                sync.nx_ptp_client_sync_utc_offset = client_ptr -> nx_ptp_client_utc_offset;
                client_ptr -> nx_ptp_client_event_callback(client_ptr, NX_PTP_CLIENT_EVENT_SYNC, &sync,
                                                        client_ptr -> nx_ptp_client_event_callback_data);
            }
        }
    }
#endif /* NX_PTP_DISABLE_SLAVE */

    /* update pdelay responder state */
    client_ptr -> nx_ptp_client_pdelay_responder_state = NX_PTP_CLIENT_PDELAY_WAIT_REQ;
#else
    /* delay and offset determination */
    if (client_ptr -> nx_ptp_client_delay_req_flag)
    {

        /* send delay request message */
        /* (delay_req_flag is cleared by this function) */
        _nx_ptp_client_send_delay_req(client_ptr);
    }
#endif
}

#if NX_PTP_CLIENT_TRANSPORT_UDP
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_delay_resp_received                  PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes a received PTP Delay Response message.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    ts_ptr                                Pointer to the timestamp      */
/*                                           delivered by the Delay Resp  */
/*                                           message                      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_clock_adjust           Adjust PTP clock              */
/*    _nx_ptp_msg_parse_timestamp           Parse timestamp field         */
/*    _nx_ptp_client_utility_time_diff      Diff two PTP times            */
/*    _nx_ptp_client_utility_time_div_by_2  Divide a PTP time by 2        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_process_general_packet Process PTP general packet    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*  03-02-2021     Yuxin Zhou               Modified comment(s), and      */
/*                                            fixed compiler warnings,    */
/*                                            resulting in version 6.1.5  */
/*  12-31-2023     Tiejun Zhou              Modified comment(s), and      */
/*                                            simplified debug output,    */
/*                                            resulting in version 6.4.0  */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_delay_resp_received(NX_PTP_CLIENT *client_ptr, VOID *ts_ptr)
{
NX_PTP_TIME        t4, a, b;
NX_PTP_CLIENT_SYNC sync;

    /*
     * The following timestamps are used for delay/offset determination:
     *
     * t1 = nx_ptp_client_sync
     * t2 = nx_ptp_client_sync_ts
     * t3 = nx_ptp_client_delay_ts
     * t4 = timestamp in Delay_Resp message (ts_ptr)
     *
     * A = t2 - t1
     * B = t4 - t3
     *
     * delay  = (A + B) / 2
     * offset = (B - A) / 2
     */

    /* check for valid timestamp t1 */
    if ((client_ptr -> nx_ptp_client_sync.second_low == 0) &&
        (client_ptr -> nx_ptp_client_sync.second_high == 0))
    {
        return;
    }

    /* get master clock timestamp */
    _nx_ptp_msg_parse_timestamp(ts_ptr, &t4);

    /* compute A = t2 - t1 */
    _nx_ptp_client_utility_time_diff(&client_ptr -> nx_ptp_client_sync_ts, &client_ptr -> nx_ptp_client_sync, &a);

    /* compute B = t4 - t3 */
    _nx_ptp_client_utility_time_diff(&t4, &client_ptr -> nx_ptp_client_delay_ts, &b);

    /* compute offset = (B - A) / 2 */
    _nx_ptp_client_utility_time_diff(&b, &a, &a);
    _nx_ptp_client_utility_time_div_by_2(&a);

#if defined(NX_PTP_DEBUG) || defined(NX_PTP_DEBUG_OFFSET)
    if ((a.second_low == 0) && (a.second_high == 0))
    {
        if ((a.nanosecond > -1000) && (a.nanosecond < 1000))
        {
            NX_PTP_DEBUG_PRINTF(("PTP: offset = %ld ns\n", a.nanosecond));
        }
        else if ((a.nanosecond > -1000000) && (a.nanosecond < 1000000))
        {
            NX_PTP_DEBUG_PRINTF(("PTP: offset = %ld us\n", a.nanosecond / 1000));
        }
        else
        {
            NX_PTP_DEBUG_PRINTF(("PTP: offset = %ld ms\n", a.nanosecond / 1000000));
        }
    }
    else
    {
        NX_PTP_DEBUG_PRINTF(("PTP: offset > 1s\n"));
    }
#endif

    /* add the time offset the client clock */
    _nx_ptp_client_clock_adjust(client_ptr, &a);

    /* set calibrated flag */
    if (!(client_ptr -> nx_ptp_client_sync_flags & NX_PTP_CLIENT_SYNC_CALIBRATED))
    {

        client_ptr -> nx_ptp_client_sync_flags |= NX_PTP_CLIENT_SYNC_CALIBRATED;

        /* application callback */
        if (client_ptr -> nx_ptp_client_event_callback)
        {
            sync.nx_ptp_client_sync_flags = client_ptr -> nx_ptp_client_sync_flags;
            sync.nx_ptp_client_sync_utc_offset = client_ptr -> nx_ptp_client_utc_offset;
            client_ptr -> nx_ptp_client_event_callback(client_ptr, NX_PTP_CLIENT_EVENT_SYNC, &sync,
                                                       client_ptr -> nx_ptp_client_event_callback_data);
        }
    }

    /* update delay req state */
    client_ptr -> nx_ptp_client_delay_state = NX_PTP_CLIENT_DELAY_IDLE;
}
#endif

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_init_packet_received                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes a received PTP Announce message.            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    hdr                                   Pointer to PTP header         */
/*    ptr                                   Pointer to PTP message        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_msg_parse_announce            Parse Announce message        */
/*    memcpy                                Copy memory                   */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_process_general_packet Process PTP general packet    */
/*    _nx_ptp_client_master_clock_compare   Compare two master clocks     */
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
static VOID _nx_ptp_client_init_packet_received(NX_PTP_CLIENT *client_ptr,
                                             NX_PTP_MSG_HEADER *hdr,
                                             UCHAR *ptr)
{
NX_PTP_CLIENT_SYNC   sync;
NX_PTP_CLIENT_MASTER master;
#ifdef NX_PTP_ENABLE_MASTER
INT compare_result;

    if (client_ptr -> nx_ptp_client_role == NX_PTP_CLIENT_ROLE_MASTER_ONLY)
    {

        /* ignore announce packet for master only mode */
        return;
    }
#endif /* NX_PTP_ENABLE_MASTER */

    /* parse Sync information */
    sync.nx_ptp_client_sync_flags = 0;
    if (hdr -> flagField & NX_PTP_MSG_HDR_FLAG_UTC_REASONABLE)
    {
        sync.nx_ptp_client_sync_flags |=  NX_PTP_CLIENT_SYNC_UTC_REASONABLE;
    }
    if (hdr -> flagField & NX_PTP_MSG_HDR_FLAG_LEAP59)
    {
        sync.nx_ptp_client_sync_flags |=  NX_PTP_CLIENT_SYNC_LEAP59;
    }
    if (hdr -> flagField & NX_PTP_MSG_HDR_FLAG_LEAP61)
    {
        sync.nx_ptp_client_sync_flags |=  NX_PTP_CLIENT_SYNC_LEAP61;
    }
    sync.nx_ptp_client_sync_utc_offset = NX_PTP_MSG_UTC_OFFSET(ptr);

    /* parse announce message */
    _nx_ptp_msg_parse_announce(ptr, &master);

#ifdef NX_PTP_ENABLE_MASTER
    if (client_ptr -> nx_ptp_client_role == NX_PTP_CLIENT_ROLE_SLAVE_AND_MASTER)
    {

        /* compare local clock with incoming master */
        compare_result = _nx_ptp_client_master_clock_compare(&client_ptr -> ptp_master, &master);
        if (compare_result == 0)
        {

            /* error, ignore current announce message */
            return;
        }
        else if (compare_result > 0)
        {

            /* recommend local clock to be master */
            if (client_ptr -> nx_ptp_client_state != NX_PTP_CLIENT_STATE_MASTER)
            {

                /* set timeout for announce and sync */
                client_ptr -> ptp_master.nx_ptp_client_master_announce_timer = NX_PTP_CLIENT_ANNOUNCE_INTERVAL;
                client_ptr -> nx_ptp_client_sync_timer = NX_PTP_CLIENT_SYNC_INTERVAL;
                client_ptr -> nx_ptp_client_state = NX_PTP_CLIENT_STATE_MASTER;
                NX_PTP_DEBUG_PRINTF(("PTP: recommend local clock to be master\r\n"));
                    
                client_ptr -> nx_ptp_client_event_callback(client_ptr, NX_PTP_CLIENT_EVENT_MASTER,
                                                           &client_ptr -> ptp_master,
                                                           client_ptr -> nx_ptp_client_event_callback_data);
            }
            return;
        }
        else
        {
            /* recommend local clock to be slave */
            if (client_ptr -> nx_ptp_client_state == NX_PTP_CLIENT_STATE_MASTER)
            {

                /* disable timers for announce and sync */
                client_ptr -> ptp_master.nx_ptp_client_master_announce_timer = -1;
                client_ptr -> nx_ptp_client_sync_timer = -1;

                /* change the state to listening and then slave */
                client_ptr -> nx_ptp_client_state = NX_PTP_CLIENT_STATE_LISTENING;
            }
        }
    }
#endif /* NX_PTP_ENABLE_MASTER */

    /* check for new master */
    if (client_ptr -> nx_ptp_client_state == NX_PTP_CLIENT_STATE_LISTENING)
    {

        /* first announce message, save master clock parameters */
        client_ptr -> nx_ptp_client_sync_flags = sync.nx_ptp_client_sync_flags;
        client_ptr -> nx_ptp_client_utc_offset = sync.nx_ptp_client_sync_utc_offset;
        memcpy(client_ptr -> nx_ptp_client_master_port_identity, hdr -> sourcePortIdentity,
               NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */

        /* wait for Sync message */
        client_ptr -> nx_ptp_client_state = NX_PTP_CLIENT_STATE_SLAVE;
        client_ptr -> nx_ptp_client_delay_state = NX_PTP_CLIENT_DELAY_IDLE;
#ifdef NX_ENABLE_GPTP
        client_ptr -> nx_ptp_client_pdelay_initiator_state = NX_PTP_CLIENT_PDELAY_IDLE;
        client_ptr -> nx_ptp_client_pdelay_responder_state = NX_PTP_CLIENT_PDELAY_WAIT_SYNC;
#endif
        client_ptr -> nx_ptp_client_delay_req_timer = -1;
        client_ptr -> nx_ptp_client_delay_req_flag = 1;

        if (hdr -> messageType == NX_PTP_MSG_TYPE_ANNOUNCE)
        {
            /* call application callback */
            if (client_ptr -> nx_ptp_client_event_callback)
            {
                master.nx_ptp_client_master_address = &(client_ptr -> nx_ptp_client_master_addr);
                master.nx_ptp_client_master_port_identity = hdr -> sourcePortIdentity;
                client_ptr -> nx_ptp_client_event_callback(client_ptr, NX_PTP_CLIENT_EVENT_MASTER, &master,
                                                        client_ptr -> nx_ptp_client_event_callback_data);
            }
        }

        /* Reset previous sync timestamp.  */
        NX_PTP_TS_RESET(client_ptr -> nx_ptp_client_prev_sync);
        NX_PTP_TS_RESET(client_ptr -> nx_ptp_client_prev_sync_ts);
        NX_PTP_TS_RESET(client_ptr -> nx_ptp_client_sync);
        NX_PTP_TS_RESET(client_ptr -> nx_ptp_client_sync_ts);
    }
    else
    {

        /* check for UTC offset update or flags changes */
        if (((client_ptr -> nx_ptp_client_sync_flags & ~NX_PTP_CLIENT_SYNC_CALIBRATED) !=
              sync.nx_ptp_client_sync_flags) ||
             (client_ptr -> nx_ptp_client_utc_offset != sync.nx_ptp_client_sync_utc_offset))
        {
            client_ptr -> nx_ptp_client_sync_flags =
                (USHORT)((client_ptr -> nx_ptp_client_sync_flags & NX_PTP_CLIENT_SYNC_CALIBRATED) |
                            sync.nx_ptp_client_sync_flags);
            client_ptr -> nx_ptp_client_utc_offset = sync.nx_ptp_client_sync_utc_offset;

            /* call application callback */
            if ((client_ptr -> nx_ptp_client_sync_flags & NX_PTP_CLIENT_SYNC_CALIBRATED) &&
                (client_ptr -> nx_ptp_client_event_callback))
            {
                client_ptr -> nx_ptp_client_event_callback(client_ptr, NX_PTP_CLIENT_EVENT_SYNC, &sync,
                                                           client_ptr -> nx_ptp_client_event_callback_data);
            }
        }
    }

    /* reset announce timer */
    client_ptr -> nx_ptp_client_announce_timeout = NX_PTP_CLIENT_ANNOUNCE_EXPIRATION;
}

#ifdef NX_ENABLE_GPTP
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_send_pdelay_req                      PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a PTP Pdelay Request message.                   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nxd_udp_socket_source_send            Send a UDP packet             */
/*    nx_packet_release                     Release a packet              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_thread_entry           PTP thread entry              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_send_pdelay_req(NX_PTP_CLIENT *client_ptr)
{
NX_PACKET *packet_ptr;
UINT       status = NX_NOT_SUCCESSFUL;
UCHAR     *ptr;
#if NX_PTP_CLIENT_TRANSPORT_UDP
NXD_ADDRESS       addr;
UINT              addr_index = 0;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_IPV6_ADDRESS *ipv6_addr;
NX_IP            *ip_ptr;
NX_INTERFACE     *if_ptr;
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* Allocate a packet from the pool */
    status = nx_packet_allocate(client_ptr -> nx_ptp_client_packet_pool_ptr, &packet_ptr, NX_PTP_PACKET, NX_NO_WAIT);
    if (status != NX_SUCCESS)
    {
        /* Failed to allocate the packet */
        return;
    }

    /* Start of message */
    ptr = packet_ptr -> nx_packet_prepend_ptr;

#define PTP_MSG_PDELAY_REQ_TOTAL_LEN (NX_PTP_MSG_HDR_LEN + NX_PTP_MSG_TIMESTAMP_LEN + NX_PTP_MSG_PDELAY_RESERVED_LEN)

    /* Write header IEEE Std 1588-2008 Section 13.3.1*/
    /* messageType */
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_transport_specific << 4) | NX_PTP_MSG_TYPE_PDELAY_REQ;
    /* versionPTP */
    *ptr++ = NX_PTP_VERSION;
    /* messageLength */
    *ptr++ = PTP_MSG_PDELAY_REQ_TOTAL_LEN >> 8;
    *ptr++ = (UCHAR)PTP_MSG_PDELAY_REQ_TOTAL_LEN;
    /* domainNumber */
    *ptr++ = client_ptr -> nx_ptp_client_domain;

    /* reserved 1 octets */
    *ptr++ = 0;

    /* flags 2 octets */
    *ptr++ = 0;
    *ptr++ = 0;

    /* correction + reserved 8 + 4 */
    memset(ptr, 0, 12); 
    ptr += 12;

    /* sourcePortIdentity */
    memcpy(ptr, client_ptr -> nx_ptp_client_port_identity, NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;
    /* sequenceID */
    client_ptr -> nx_ptp_client_pdelay_req_id++;
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_pdelay_req_id >> 8);
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_pdelay_req_id);
    /* control */
    *ptr++ = 5; /* other message */
    /* XXX */
    *ptr++ = 0; 

    /* write timestamp */
    memset(ptr, 0, NX_PTP_MSG_TIMESTAMP_LEN);
    ptr += NX_PTP_MSG_TIMESTAMP_LEN;

    /* write space for reserved space to align size with pdelay_resp */
    memset(ptr, 0, NX_PTP_MSG_PDELAY_RESERVED_LEN);
    ptr += NX_PTP_MSG_PDELAY_RESERVED_LEN;

    /* set final message length */
    packet_ptr -> nx_packet_length = (ULONG)(ptr - (packet_ptr -> nx_packet_prepend_ptr));
    packet_ptr -> nx_packet_append_ptr = ptr;

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* set source and destination addresses */
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    if (client_ptr -> nx_ptp_client_master_addr.nxd_ip_version == NX_IP_VERSION_V6)
    {
        NX_PTP_IPV6_P2P_MULTICAST_ADDR_SET(&addr);

        /* Use first IPv6 address as source address. */
        ip_ptr = client_ptr -> nx_ptp_client_ip_ptr;
        if_ptr = &ip_ptr -> nx_ip_interface[client_ptr -> nx_ptp_client_interface_index];
        ipv6_addr = if_ptr -> nxd_interface_ipv6_address_list_head;
        if (ipv6_addr == NX_NULL)
        {

            /* No available IPv6 address.  */
            /* Release packet.  */
            nx_packet_release(packet_ptr);

            /* Reset state.  */
            client_ptr -> nx_ptp_client_pdelay_initiator_state = NX_PTP_CLIENT_PDELAY_IDLE;
            client_ptr -> nx_ptp_client_pdelay_req_packet_ptr = NX_NULL;

            return;
        }
        addr_index = ipv6_addr -> nxd_ipv6_address_index;
    }
    else
#endif
    {
#ifndef NX_DISABLE_IPV4
        addr.nxd_ip_version = NX_IP_VERSION_V4;
        addr.nxd_ip_address.v4 = NX_PTP_IPV4_P2P_MULTICAST_ADDR;
        addr_index = client_ptr -> nx_ptp_client_interface_index;
#endif
    }
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* Prepare timestamp for current packet */
    client_ptr -> nx_ptp_client_pdelay_initiator_state = NX_PTP_CLIENT_PDELAY_WAIT_REQ_TS;
    client_ptr -> nx_ptp_client_pdelay_req_packet_ptr = packet_ptr;
    client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_PACKET_TS_PREPARE,
                                               &client_ptr -> nx_ptp_client_pdelay_req_ts, packet_ptr,
                                               client_ptr -> nx_ptp_client_clock_callback_data);

    /* Send Pdelay_Req */
#if NX_PTP_CLIENT_TRANSPORT_UDP
    status = nxd_udp_socket_source_send((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_event_socket,
                                        packet_ptr, &addr, NX_PTP_EVENT_UDP_PORT, addr_index);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    nx_link_ethernet_packet_send(client_ptr -> nx_ptp_client_ip_ptr,
                                 client_ptr -> nx_ptp_client_interface_index, packet_ptr,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_MSB,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_LSB,
                                 NX_PTP_ETHERNET_TYPE);
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */
    if (status)
    {

        /* release packet in case of error */
        nx_packet_release(packet_ptr);

        /* reset state */
        client_ptr -> nx_ptp_client_pdelay_initiator_state = NX_PTP_CLIENT_PDELAY_IDLE;
        client_ptr -> nx_ptp_client_pdelay_req_packet_ptr = NX_NULL;

        return;
    }

    /* rearm delay req timer (use the client timer) */ 
    client_ptr -> nx_ptp_client_pdelay_req_timer = NX_PTP_CLIENT_PDELAY_REQ_INTERVAL;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_pdelay_resp_received                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes a received PTP Pdelay Response message.     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    ts_ptr                                Pointer to the timestamp      */
/*                                           delivered by the Pdelay Resp */
/*                                           message                      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_clock_adjust           Adjust PTP clock              */
/*    _nx_ptp_msg_parse_timestamp           Parse timestamp field         */
/*    _nx_ptp_client_utility_time_diff      Diff two PTP times            */
/*    _nx_ptp_client_utility_time_div_by_2  Divide a PTP time by 2        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_process_general_packet Process PTP general packet    */
/*    _nx_ptp_client_process_event_packet   Process PTP event packet      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_pdelay_resp_received(NX_PTP_CLIENT *client_ptr, VOID *ts_ptr)
{
NX_PTP_TIME a, b, c, d, t3;

    /*
    * The following timestamps are used to calculate the mean link delay using P2P
    * t1 = nx_ptp_client_pdelay_req_ts
    * t2 = nx_ptp_client_pdelay_req_receipt_ts (within pdelay_resp)
    * t3 = nx_ptp_client_pdelay_resp_origin_ts (within pdelay_resp_follow_up or ts_ptr)
    * t4 = (onestep: nx_ptp_client_pdelay_req_receipt_ts)/(twostep:nx_ptp_client_pdelay_resp_ts)
    * 
    * C = t2 - t1
    * D = t4 - t3
    *  
    * <meanLinkDelay> = [(t2 – t1) + (t4 – t3)]/2
    * 
    * A = t1 - t2
    * B = t3 - t4
    * 
    * offset = [(t1 - t2) - (t3 - t4)]/2 
    *        = [B - A]/2
    * 
    * 
    * onestep: <meanLinkDelay> = [(t4 − t1) − <correctedPdelayRespCorrectionField>]/2
    * correctedPDelayRespCorrectionField = t3-t2 (turnaround time)
    * 
    * onestep offset = (t4 + t1 - (nx_ptp_client_pdelay_req_receipt_ts * 2))/2
    * - the multiply by 2 is here because we are not yet parsing the correction field
    * 
    * twostep offset = (t4 + t1 - (nx_ptp_client_pdelay_req_receipt_ts + ts_ptr))/2
    * 
    * We will set <delayAsymmetry> to 0 unless a value is provided by the user
    *
    * delay_asymmetry = 0;
    * corrected_pdelay_resp = ingress <delayAsymmetry> + pdelay_resp_correction_field
    * corrected_pdelay_resp = delay_asymmetry + pdelay_resp_correction_field
    */

    /* get message timestamp */
    _nx_ptp_msg_parse_timestamp(ts_ptr, &t3);

    /* compute A = t1 - t2 */
    _nx_ptp_client_utility_time_diff(&client_ptr -> nx_ptp_client_pdelay_req_ts, &client_ptr -> nx_ptp_client_pdelay_req_receipt_ts, &a);

    /* compute B = t3 - t4 */
    _nx_ptp_client_utility_time_diff(&t3, &client_ptr -> nx_ptp_client_pdelay_resp_ts, &b);

    /* compute C = t2 - t1 */
    _nx_ptp_client_utility_time_diff(&client_ptr -> nx_ptp_client_pdelay_req_receipt_ts, &client_ptr -> nx_ptp_client_pdelay_req_ts, &c);

    /* compute D = t4 - t3 */
    _nx_ptp_client_utility_time_diff(&client_ptr -> nx_ptp_client_pdelay_resp_ts, &t3, &d);

    /* compute delay = (D + C) / 2 */
    _nx_ptp_client_utility_time_sum(&d, &c, &client_ptr -> nx_ptp_client_delay);
    _nx_ptp_client_utility_time_div_by_2(&client_ptr -> nx_ptp_client_delay);

#if defined(NX_PTP_DEBUG) || defined(NX_PTP_DEBUG_DELAY)
    if ((client_ptr -> nx_ptp_client_delay.second_low == 0) && (client_ptr -> nx_ptp_client_delay.second_high == 0))
    {
        if ((client_ptr -> nx_ptp_client_delay.nanosecond > -1000) &&
            (client_ptr -> nx_ptp_client_delay.nanosecond < 1000))
        {
            NX_PTP_DEBUG_PRINTF(("PTP: delay = %ld ns", client_ptr -> nx_ptp_client_delay.nanosecond));
        }
        else if ((client_ptr -> nx_ptp_client_delay.nanosecond > -1000000) &&
                 (client_ptr -> nx_ptp_client_delay.nanosecond < 1000000))
        {
            NX_PTP_DEBUG_PRINTF(("PTP: delay = %ld us", client_ptr -> nx_ptp_client_delay.nanosecond / 1000));
        }
        else
        {
            NX_PTP_DEBUG_PRINTF(("PTP: delay = %ld ms", client_ptr -> nx_ptp_client_delay.nanosecond / 1000000));
        }
    }
    else
    {
        NX_PTP_DEBUG_PRINTF(("PTP: delay > 1s"));
    }

    if (client_ptr -> nx_ptp_client_delay.nanosecond > NX_PTP_CLIENT_DELAY_THRESH)
    {
        NX_PTP_DEBUG_PRINTF((", asCapable is FALSE\n"));
    }
    else
    {
        NX_PTP_DEBUG_PRINTF((", asCapable is TRUE\n"));
    }
#endif

    /* update pdelay req state */
    client_ptr -> nx_ptp_client_pdelay_initiator_state = NX_PTP_CLIENT_PDELAY_IDLE;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_send_pdelay_resp_follow_up           PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a PTP Pdelay response follow up message.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nxd_udp_socket_source_send            Send a UDP packet             */
/*    nx_packet_release                     Release a packet              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_thread_entry           PTP thread entry              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_send_pdelay_resp_follow_up(NX_PTP_CLIENT *client_ptr)
{
NX_PACKET *packet_ptr;
UINT       status = NX_NOT_SUCCESSFUL;
UCHAR     *ptr;
#if NX_PTP_CLIENT_TRANSPORT_UDP
NXD_ADDRESS       addr;
UINT              addr_index = 0;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_IPV6_ADDRESS *ipv6_addr;
NX_IP            *ip_ptr;
NX_INTERFACE     *if_ptr;
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* Verify state */
    if (client_ptr -> nx_ptp_client_pdelay_responder_state != NX_PTP_CLIENT_PDELAY_SEND_FOLLOW_UP)
    {
        return;
    }

    /* Allocate a packet from the pool */
    status = nx_packet_allocate(client_ptr -> nx_ptp_client_packet_pool_ptr, &packet_ptr, NX_PTP_PACKET, NX_NO_WAIT);
    if (status != NX_SUCCESS)
    {
        /* Failed to allocate the packet */
        return;
    }

    /* Start of message */
    ptr = packet_ptr -> nx_packet_prepend_ptr;

#define PTP_MSG_PDELAY_RESP_TOTAL_LEN (NX_PTP_MSG_HDR_LEN + NX_PTP_MSG_TIMESTAMP_LEN + NX_PTP_MSG_PDELAY_RESERVED_LEN)

    /* Write header IEEE Std 1588-2008 Section 13.3.1*/
    /* messageType */
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_transport_specific << 4) | NX_PTP_MSG_TYPE_PDELAY_RESP_FOLLOW_UP;
    /* versionPTP */
    *ptr++ = NX_PTP_VERSION;
    /* messageLength */
    *ptr++ = PTP_MSG_PDELAY_RESP_TOTAL_LEN >> 8;
    *ptr++ = (UCHAR)PTP_MSG_PDELAY_RESP_TOTAL_LEN;
    /* domainNumber */
    *ptr++ = client_ptr -> nx_ptp_client_domain;
    /* reserved 1 octets */
    *ptr++ = 0;
    /* flags 2 octets */
    *ptr++ = 0;
    *ptr++ = 0;
    /* correction + reserved 8 + 4 (correction field to be updated with t3-t2 later) */
    memset(ptr, 0, 12); 
    ptr += 12;
    /* sourcePortIdentity */
    memcpy(ptr, client_ptr -> nx_ptp_client_port_identity, NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;
    /* sequenceID */
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_pdelay_responder_id >> 8);
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_pdelay_responder_id);
    /* control */
    *ptr++ = 5; /* other message */
    /* XXX */
    *ptr++ = 0;

    /* write timestamp t3 */
    *ptr++ = (UCHAR)((client_ptr -> nx_ptp_client_pdelay_resp_origin).second_high >> 8);
    *ptr++ = (UCHAR)((client_ptr -> nx_ptp_client_pdelay_resp_origin).second_high);
    _nx_ptp_utility_32_unsigned_write(ptr, (client_ptr -> nx_ptp_client_pdelay_resp_origin).second_low);
    ptr += 4;
    _nx_ptp_utility_32_unsigned_write(ptr, (ULONG)(client_ptr -> nx_ptp_client_pdelay_resp_origin.nanosecond));
    ptr += 4;

    /* write requestingPortIdentity */ 
    memcpy(ptr, client_ptr -> nx_ptp_client_request_port_identity, NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;

    /* set final message length */
    packet_ptr -> nx_packet_length = (ULONG)(ptr - (packet_ptr -> nx_packet_prepend_ptr));
    packet_ptr -> nx_packet_append_ptr = ptr;

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* set source and destination addresses */
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    if (client_ptr -> nx_ptp_client_master_addr.nxd_ip_version == NX_IP_VERSION_V6)
    {
        NX_PTP_IPV6_P2P_MULTICAST_ADDR_SET(&addr);

        /* Use first IPv6 address as source address. */
        ip_ptr = client_ptr -> nx_ptp_client_ip_ptr;
        if_ptr = &ip_ptr -> nx_ip_interface[client_ptr -> nx_ptp_client_interface_index];
        ipv6_addr = if_ptr -> nxd_interface_ipv6_address_list_head;
        if (ipv6_addr == NX_NULL)
        {

            /* No available IPv6 address.  */
            /* Release packet.  */
            nx_packet_release(packet_ptr);

            /* Reset state.  */
            client_ptr -> nx_ptp_client_pdelay_responder_state = NX_PTP_CLIENT_PDELAY_WAIT_REQ;
            client_ptr -> nx_ptp_client_pdelay_req_packet_ptr = NX_NULL;

            return;
        }
        addr_index = ipv6_addr -> nxd_ipv6_address_index;
    }
    else
#endif
    {
#ifndef NX_DISABLE_IPV4
        addr.nxd_ip_version = NX_IP_VERSION_V4;
        addr.nxd_ip_address.v4 = NX_PTP_IPV4_P2P_MULTICAST_ADDR;
        addr_index = client_ptr -> nx_ptp_client_interface_index;
#endif
    }

    /* Send Pdelay_Resp */
    status = nxd_udp_socket_source_send((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_general_socket,
                                        packet_ptr, &addr, NX_PTP_GENERAL_UDP_PORT, addr_index);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    nx_link_ethernet_packet_send(client_ptr -> nx_ptp_client_ip_ptr,
                                 client_ptr -> nx_ptp_client_interface_index, packet_ptr,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_MSB,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_LSB,
                                 NX_PTP_ETHERNET_TYPE);
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */
    if (status)
    {
        /* release packet in case of error */
        nx_packet_release(packet_ptr);

        /* reset state */
        client_ptr -> nx_ptp_client_pdelay_responder_state = NX_PTP_CLIENT_PDELAY_WAIT_REQ;
        client_ptr -> nx_ptp_client_pdelay_req_packet_ptr = NX_NULL;

        return;
    }

    client_ptr -> nx_ptp_client_pdelay_responder_state = NX_PTP_CLIENT_PDELAY_WAIT_REQ;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_send_pdelay_resp                     PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a PTP Pdelay response message.                  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nxd_udp_socket_source_send            Send a UDP packet             */
/*    nx_packet_release                     Release a packet              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_thread_entry           PTP thread entry              */
/*    _nx_ptp_client_process_event_packet   Process PTP event packet      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_send_pdelay_resp(NX_PTP_CLIENT *client_ptr)
{ 
NX_PACKET *packet_ptr;
UINT       status = NX_NOT_SUCCESSFUL;
UCHAR     *ptr;
#if NX_PTP_CLIENT_TRANSPORT_UDP
NXD_ADDRESS       addr;
UINT              addr_index = 0;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_IPV6_ADDRESS *ipv6_addr;
NX_IP            *ip_ptr;
NX_INTERFACE     *if_ptr;
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* Verify state */
    if (client_ptr -> nx_ptp_client_pdelay_responder_state != NX_PTP_CLIENT_PDELAY_SEND_RESP_TWOSTEP)
    {
        return;
    }

    /* Allocate a packet from the pool */
    status = nx_packet_allocate(client_ptr -> nx_ptp_client_packet_pool_ptr, &packet_ptr, NX_PTP_PACKET, NX_NO_WAIT);
    if (status != NX_SUCCESS)
    {
        /* Failed to allocate the packet */
        return;
    }

    /* Start of message */
    ptr = packet_ptr -> nx_packet_prepend_ptr;

#define PTP_MSG_PDELAY_RESP_TOTAL_LEN (NX_PTP_MSG_HDR_LEN + NX_PTP_MSG_TIMESTAMP_LEN + NX_PTP_MSG_PDELAY_RESERVED_LEN)

    /* Write header IEEE Std 1588-2008 Section 13.3.1*/
    /* messageType */
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_transport_specific << 4) | NX_PTP_MSG_TYPE_PDELAY_RESP;
    /* versionPTP */
    *ptr++ = NX_PTP_VERSION;
    /* messageLength */
    *ptr++ = PTP_MSG_PDELAY_REQ_TOTAL_LEN >> 8;
    *ptr++ = (UCHAR)PTP_MSG_PDELAY_REQ_TOTAL_LEN;
    /* domainNumber */
    *ptr++ = client_ptr -> nx_ptp_client_domain;
    /* reserved 1 octets */
    *ptr++ = 0;
    /* flags 2 octets */
    *ptr++ = 0x02;
    *ptr++ = 0x8;
    /* correction + reserved 8 + 4 */
    memset(ptr, 0, 12); 
    ptr += 12;
    /* sourcePortIdentity */
    memcpy(ptr, client_ptr -> nx_ptp_client_port_identity, NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;
    /* sequenceID */
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_pdelay_responder_id >> 8);
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_pdelay_responder_id);
    /* control */
    *ptr++ = 5; /* other message */
    /* XXX */
    *ptr++ = 0;

    /* write timestamp t2 */
    *ptr++ = (UCHAR)((client_ptr -> nx_ptp_client_pdelay_req_receipt).second_high >> 8);
    *ptr++ = (UCHAR)((client_ptr -> nx_ptp_client_pdelay_req_receipt).second_high);
    /* 4 octets for second low */
    _nx_ptp_utility_32_unsigned_write(ptr, (client_ptr -> nx_ptp_client_pdelay_req_receipt).second_low);
    ptr += 4;
    /* 4 for nanosecond */
    _nx_ptp_utility_32_unsigned_write(ptr, (ULONG)(client_ptr -> nx_ptp_client_pdelay_req_receipt.nanosecond));
    ptr += 4;

    /* write requestingPortIdentity */ 
    memcpy(ptr, client_ptr -> nx_ptp_client_request_port_identity, NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;

    /* set final message length */
    packet_ptr -> nx_packet_length = (ULONG)(ptr - (packet_ptr -> nx_packet_prepend_ptr));
    packet_ptr -> nx_packet_append_ptr = ptr;

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* set source and destination addresses */
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    if (client_ptr -> nx_ptp_client_master_addr.nxd_ip_version == NX_IP_VERSION_V6)
    {
        NX_PTP_IPV6_P2P_MULTICAST_ADDR_SET(&addr);

        /* Use first IPv6 address as source address. */
        ip_ptr = client_ptr -> nx_ptp_client_ip_ptr;
        if_ptr = &ip_ptr -> nx_ip_interface[client_ptr -> nx_ptp_client_interface_index];
        ipv6_addr = if_ptr -> nxd_interface_ipv6_address_list_head;
        if (ipv6_addr == NX_NULL)
        {

            /* No available IPv6 address.  */
            /* Release packet.  */
            nx_packet_release(packet_ptr);

            /* Reset state.  */
            client_ptr -> nx_ptp_client_pdelay_responder_state = NX_PTP_CLIENT_PDELAY_WAIT_REQ;
            client_ptr -> nx_ptp_client_pdelay_req_packet_ptr = NX_NULL;

            return;
        }
        addr_index = ipv6_addr -> nxd_ipv6_address_index;
    }
    else
#endif
    {
#ifndef NX_DISABLE_IPV4
        addr.nxd_ip_version = NX_IP_VERSION_V4;
        addr.nxd_ip_address.v4 = NX_PTP_IPV4_P2P_MULTICAST_ADDR;
        addr_index = client_ptr -> nx_ptp_client_interface_index;
#endif
    }
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    client_ptr -> nx_ptp_client_pdelay_resp_packet_ptr = packet_ptr;

     /* Prepare timestamp for current packet (generate t3) */
    client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_PACKET_TS_PREPARE,
                                               &client_ptr -> nx_ptp_client_pdelay_resp_origin, packet_ptr,
                                               client_ptr -> nx_ptp_client_clock_callback_data);
    

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* Send Pdelay_Resp */
    status = nxd_udp_socket_source_send((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_general_socket,
                                        packet_ptr, &addr, NX_PTP_GENERAL_UDP_PORT, addr_index);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    nx_link_ethernet_packet_send(client_ptr -> nx_ptp_client_ip_ptr,
                                 client_ptr -> nx_ptp_client_interface_index, packet_ptr,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_MSB,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_LSB,
                                 NX_PTP_ETHERNET_TYPE);
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */
    if (status)
    {
        /* release packet in case of error */
        nx_packet_release(packet_ptr);

        /* reset state */
        client_ptr -> nx_ptp_client_pdelay_responder_state = NX_PTP_CLIENT_PDELAY_WAIT_REQ;
        client_ptr -> nx_ptp_client_pdelay_req_packet_ptr = NX_NULL;

        return;
    }
}
#endif /* NX_ENABLE_GPTP*/


#if defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC)
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_send_follow_up                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a PTP follow up message.                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nxd_udp_socket_source_send            Send a UDP packet             */
/*    nx_packet_release                     Release a packet              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_thread_entry           PTP thread entry              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_send_follow_up(NX_PTP_CLIENT *client_ptr)
{
NX_PACKET *packet_ptr;
UINT       status = NX_NOT_SUCCESSFUL;
UCHAR     *ptr;
#if NX_PTP_CLIENT_TRANSPORT_UDP
NXD_ADDRESS       addr;
UINT              addr_index = 0;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_IPV6_ADDRESS *ipv6_addr;
NX_IP            *ip_ptr;
NX_INTERFACE     *if_ptr;
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* allocate a packet from the pool */
    status = nx_packet_allocate(client_ptr -> nx_ptp_client_packet_pool_ptr, &packet_ptr, NX_PTP_PACKET, NX_NO_WAIT);
    if (status != NX_SUCCESS)
    {
        /* Failed to allocate the packet */
        return;
    }

    /* start of message */
    ptr = packet_ptr -> nx_packet_prepend_ptr;
    
#define PTP_FOLLOW_UP_TLV_LENGTH    32
#define PTP_MSG_FOLLOW_UP_TOTAL_LEN (NX_PTP_MSG_HDR_LEN + NX_PTP_MSG_TIMESTAMP_LEN + PTP_FOLLOW_UP_TLV_LENGTH)

    /* write header */
    /* messageType */
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_transport_specific << 4) | NX_PTP_MSG_TYPE_FOLLOW_UP;
    /* versionPTP */
    *ptr++ = NX_PTP_VERSION;
    /* messageLength */
    *ptr++ = PTP_MSG_FOLLOW_UP_TOTAL_LEN >> 8;
    *ptr++ = (UCHAR)PTP_MSG_FOLLOW_UP_TOTAL_LEN;
    /* domainNumber */
    *ptr++ = client_ptr -> nx_ptp_client_domain;
    /* reserved 1 octets */
    *ptr++ = 0;
    /* flags 2 octets */
    *ptr++ = 0;
    *ptr++ = 0x08;
    /* correction + reserved 8 + 4 */
    memset(ptr, 0, 12); 
    ptr += 12;
    /* sourcePortIdentity */
    memcpy(ptr, client_ptr -> nx_ptp_client_port_identity, NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;
    /* sequenceID */
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_sync_sequenceId >> 8);
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_sync_sequenceId);
    /* control */
    *ptr++ = 2; /* follow up message */
    /* XXX */ 
    *ptr++ = 0;

    /* write preciseOriginTimestamp */
    *ptr++ = (UCHAR)((client_ptr -> nx_ptp_client_sync_ts_local).second_high >> 8);
    *ptr++ = (UCHAR)((client_ptr -> nx_ptp_client_sync_ts_local).second_high);
    /* 4 octets for second low */
    _nx_ptp_utility_32_unsigned_write(ptr, (client_ptr -> nx_ptp_client_sync_ts_local).second_low);
    ptr += 4;
    /* 4 for nanosecond */
    _nx_ptp_utility_32_unsigned_write(ptr, (ULONG)(client_ptr -> nx_ptp_client_sync_ts_local.nanosecond));
    ptr += 4;

    /* Follow_Up information TLV definition 801AS-2020 11.4.4.3. Required by 801AS-2020 Section 7.5 g) */
    /* tlvType */
    *ptr++ = 0;
    *ptr++ = 0x3;
    /* lengthField */
    *ptr++ = 0;
    *ptr++ = 28;
    /* organizationId(3): 00-80-C2 from 801AS-2020 11.4.4.3.4 */
    *ptr++ = 0x0;
    *ptr++ = 0x80;
    *ptr++ = 0xC2;
    /* organizationSubType(3): 1 */
    *ptr++ = 0x0;
    *ptr++ = 0x0;
    *ptr++ = 0x1;
    /* cumulativeScaledRateOffset(4) */
    /* gmTimeBaseIndicator(2) */
    /* lastGmPhaseChange(12) */
    /* scaledLastGmFreqChange(4) */
#define PTP_FOLLOW_UP_TLV_ZEROES 4 + 2 + 12 + 4
    memset(ptr, 0, PTP_FOLLOW_UP_TLV_ZEROES);
    ptr += PTP_FOLLOW_UP_TLV_ZEROES;

    /* set final length of message */
    packet_ptr -> nx_packet_length = (ULONG)(ptr - packet_ptr -> nx_packet_prepend_ptr);
    packet_ptr -> nx_packet_append_ptr = ptr;

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* set source and destination addresses */
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    if (client_ptr -> nx_ptp_client_master_addr.nxd_ip_version == NX_IP_VERSION_V6)
    {
        NX_PTP_IPV6_MULTICAST_ADDR_SET(&addr);

        /* Use first IPv6 address as source address. */
        ip_ptr = client_ptr -> nx_ptp_client_ip_ptr;
        if_ptr = &ip_ptr -> nx_ip_interface[client_ptr -> nx_ptp_client_interface_index];
        ipv6_addr = if_ptr -> nxd_interface_ipv6_address_list_head;
        if (ipv6_addr == NX_NULL)
        {

            /* No available IPv6 address.  */
            /* Release packet.  */
            nx_packet_release(packet_ptr);

            /* Reset state.  */
            client_ptr -> nx_ptp_client_sync_timer = NX_PTP_CLIENT_SYNC_INTERVAL;

            return;
        }
        addr_index = ipv6_addr -> nxd_ipv6_address_index;
    }
    else
#endif
    {
#ifndef NX_DISABLE_IPV4
        addr.nxd_ip_version = NX_IP_VERSION_V4;
        addr.nxd_ip_address.v4 = NX_PTP_IPV4_MULTICAST_ADDR;
        addr_index = client_ptr -> nx_ptp_client_interface_index;
#endif
    }
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* Send Pdelay_Resp */
    status = nxd_udp_socket_source_send((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_general_socket,
                                        packet_ptr, &addr, NX_PTP_GENERAL_UDP_PORT, addr_index);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    nx_link_ethernet_packet_send(client_ptr -> nx_ptp_client_ip_ptr,
                                 client_ptr -> nx_ptp_client_interface_index, packet_ptr,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_MSB,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_LSB,
                                 NX_PTP_ETHERNET_TYPE);
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */

    if (status)
    {

        /* release packet in case of error */
        nx_packet_release(packet_ptr);
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_send_sync                            PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a PTP sync message.                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nxd_udp_socket_source_send            Send a UDP packet             */
/*    nx_packet_release                     Release a packet              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_thread_entry           PTP thread entry              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_send_sync(NX_PTP_CLIENT *client_ptr)
{
NX_PACKET *packet_ptr;
UINT       status = NX_NOT_SUCCESSFUL;
UCHAR     *ptr;
#if NX_PTP_CLIENT_TRANSPORT_UDP
NXD_ADDRESS       addr;
UINT              addr_index = 0;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_IPV6_ADDRESS *ipv6_addr;
NX_IP            *ip_ptr;
NX_INTERFACE     *if_ptr;
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* allocate a packet from the pool */
    status = nx_packet_allocate(client_ptr -> nx_ptp_client_packet_pool_ptr, &packet_ptr, NX_PTP_PACKET, NX_NO_WAIT);
    if (status != NX_SUCCESS)
    {
        /* Failed to allocate the packet */
        return;
    }

    /* start of message */
    ptr = packet_ptr -> nx_packet_prepend_ptr;

#define PTP_MSG_SYNC_TOTAL_LEN (NX_PTP_MSG_HDR_LEN + NX_PTP_MSG_TIMESTAMP_LEN)

    /* write header */
    /* messageType */
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_transport_specific << 4) | NX_PTP_MSG_TYPE_SYNC;
    /* versionPTP */
    *ptr++ = NX_PTP_VERSION;
    /* messageLength */
    *ptr++ = PTP_MSG_SYNC_TOTAL_LEN >> 8;
    *ptr++ = (UCHAR)PTP_MSG_SYNC_TOTAL_LEN;
    /* domainNumber */
    *ptr++ = client_ptr -> nx_ptp_client_domain;
    /* reserved 1 octets */
    *ptr++ = 0;
    /* flags 2 octets */
    *ptr++ = 0x02;
    *ptr++ = 0x08;
    /* correction + reserved 8 + 4 */
    memset(ptr, 0, 12); 
    ptr += 12;
    /* sourcePortIdentity */
    memcpy(ptr, client_ptr -> nx_ptp_client_port_identity, NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;
    /* sequenceID */
    client_ptr -> nx_ptp_client_sync_sequenceId++;
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_sync_sequenceId >> 8);
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_sync_sequenceId);
    /* control */
    *ptr++ = 0; /* sync message */
    /* XXX */ 
    *ptr++ = (UCHAR)(NX_PTP_CLIENT_LOG_SYNC_INTERVAL);

    /* write timestamp (0) */
    memset(ptr, 0, NX_PTP_MSG_TIMESTAMP_LEN);
    ptr += NX_PTP_MSG_TIMESTAMP_LEN;

    /* set final length of message */
    packet_ptr -> nx_packet_length = (ULONG)(ptr - packet_ptr -> nx_packet_prepend_ptr);
    packet_ptr -> nx_packet_append_ptr = ptr;

    #if NX_PTP_CLIENT_TRANSPORT_UDP
    /* set source and destination addresses */
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    if (client_ptr -> nx_ptp_client_master_addr.nxd_ip_version == NX_IP_VERSION_V6)
    {
        NX_PTP_IPV6_MULTICAST_ADDR_SET(&addr);

        /* Use first IPv6 address as source address. */
        ip_ptr = client_ptr -> nx_ptp_client_ip_ptr;
        if_ptr = &ip_ptr -> nx_ip_interface[client_ptr -> nx_ptp_client_interface_index];
        ipv6_addr = if_ptr -> nxd_interface_ipv6_address_list_head;
        if (ipv6_addr == NX_NULL)
        {

            /* No available IPv6 address.  */
            /* Release packet.  */
            nx_packet_release(packet_ptr);

            return;
        }
        addr_index = ipv6_addr -> nxd_ipv6_address_index;
    }
    else
#endif
    {
#ifndef NX_DISABLE_IPV4
        addr.nxd_ip_version = NX_IP_VERSION_V4;
        addr.nxd_ip_address.v4 = NX_PTP_IPV4_MULTICAST_ADDR;
        addr_index = client_ptr -> nx_ptp_client_interface_index;
#endif
    }
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* Prepare timestamp for current packet  */
    client_ptr -> nx_ptp_client_sync_packet_ptr = packet_ptr;
    client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_PACKET_TS_PREPARE,
                                               &client_ptr -> nx_ptp_client_sync_ts_local, packet_ptr,
                                               client_ptr -> nx_ptp_client_clock_callback_data);

#if NX_PTP_CLIENT_TRANSPORT_UDP
    status = nxd_udp_socket_source_send((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_event_socket,
                                        packet_ptr, &addr, NX_PTP_EVENT_UDP_PORT, addr_index);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    nx_link_ethernet_packet_send(client_ptr -> nx_ptp_client_ip_ptr,
                                 client_ptr -> nx_ptp_client_interface_index, packet_ptr,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_MSB,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_LSB,
                                 NX_PTP_ETHERNET_TYPE);
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */

    if (status)
    {

        /* release packet in case of error */
        nx_packet_release(packet_ptr);
    }
}
#endif /* defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC) */


#ifdef NX_PTP_ENABLE_MASTER
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_send_announce                        PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a PTP announce message.                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nxd_udp_socket_source_send            Send a UDP packet             */
/*    nx_packet_release                     Release a packet              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_thread_entry           PTP thread entry              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
static VOID _nx_ptp_client_send_announce(NX_PTP_CLIENT *client_ptr)
{
NX_PACKET *packet_ptr;
UINT       status = NX_NOT_SUCCESSFUL;
UCHAR     *ptr;
#if NX_PTP_CLIENT_TRANSPORT_UDP
NXD_ADDRESS       addr;
UINT              addr_index = 0;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_IPV6_ADDRESS *ipv6_addr;
NX_IP            *ip_ptr;
NX_INTERFACE     *if_ptr;
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* Verify state */
    
    /* Allocate a packet from the pool */
    status = nx_packet_allocate(client_ptr -> nx_ptp_client_packet_pool_ptr, &packet_ptr, NX_PTP_PACKET, NX_NO_WAIT);
    if (status != NX_SUCCESS)
    {
        /* Failed to allocate the packet */
        return;
    }

    /* Start of message */
    ptr = packet_ptr -> nx_packet_prepend_ptr;

#define PTP_MSG_ANNOUNCE_PATH_TLV_LEN (2 + 2 + NX_PTP_CLOCK_IDENTITY_SIZE)
#define PTP_MSG_ANNOUNCE_TOTAL_LEN    (NX_PTP_MSG_HDR_LEN + NX_PTP_MSG_ANNOUNCE_LEN + PTP_MSG_ANNOUNCE_PATH_TLV_LEN)

    /* Write header IEEE Std 1588-2008 Section 13.3.1*/
    /* messageType */
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_transport_specific << 4) | NX_PTP_MSG_TYPE_ANNOUNCE;
    /* versionPTP */
    *ptr++ = NX_PTP_VERSION;
    /* messageLength */
    *ptr++ = PTP_MSG_ANNOUNCE_TOTAL_LEN >> 8;
    *ptr++ = (UCHAR)PTP_MSG_ANNOUNCE_TOTAL_LEN;
    /* domainNumber */
    *ptr++ = client_ptr -> nx_ptp_client_domain;
    /* reserved 1 octets */
    *ptr++ = 0;
    /* flags 2 octets */
    *ptr++ = 0;
    *ptr++ = 0x08;
    /* correction + reserved 8 + 4 */
    memset(ptr, 0, 12); 
    ptr += 12;
    /* sourcePortIdentity */
    memcpy(ptr, client_ptr -> nx_ptp_client_port_identity, NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_PORT_IDENTITY_SIZE;
    /* sequenceID */
    client_ptr -> nx_ptp_client_sync_sequenceId++;
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_sync_sequenceId >> 8);
    *ptr++ = (UCHAR)(client_ptr -> nx_ptp_client_sync_sequenceId);
    /* control */
    *ptr++ = 5; /* other message */
    /* XXX */ /* 13.3.2.14 logMessageInterval */
    *ptr++ = 0x0;

    /* Write announce message field IEEE Std 1588-2019 Section 13.5.2 */
    /* write originTimestamp */
    memset(ptr, 0, NX_PTP_MSG_TIMESTAMP_LEN);
    ptr += NX_PTP_MSG_TIMESTAMP_LEN;
    /* currentUtcOffset */
    *ptr++ = 0;
    *ptr++ = 0;
    /* reserved */
    *ptr++ = 0;
    /* grandmasterPriority1 */
    *ptr++ = (client_ptr -> ptp_master).nx_ptp_client_master_priority1;
    /* grandmasterClockQuality(4) = grandmasterClockClass(1) + grandmasterClockAccuracy(1) + grandmasterClockVariance(2) */
    *ptr++ = (client_ptr -> ptp_master).nx_ptp_client_master_clock_class;
    *ptr++ = (client_ptr -> ptp_master).nx_ptp_client_master_clock_accuracy;
    *ptr++ = (UCHAR)((client_ptr -> ptp_master).nx_ptp_client_master_offset_scaled_log_variance >> 8);
    *ptr++ = (UCHAR)((client_ptr -> ptp_master).nx_ptp_client_master_offset_scaled_log_variance);
    /* grandmasterPriority2 */
    *ptr++ = (client_ptr -> ptp_master).nx_ptp_client_master_priority2;
    /* grandmasterIdentity. Setting to client_port_identity because grandmaster */
    memcpy(ptr, client_ptr -> nx_ptp_client_port_identity, NX_PTP_CLOCK_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_IDENTITY_SIZE;
    /* stepsRemoved */
    *ptr++ = 0;
    *ptr++ = 0;
    /* timeSource */
    *ptr++ = (client_ptr -> ptp_master).nx_ptp_client_master_time_source;

    /* Path trace TLV */
    /* tlvType */
    *ptr++ = 0;
    *ptr++ = 0x8;
    /* lengthField */
    *ptr++ = 0;
    *ptr++ = 0x8;
    /* pathSequence */
    memcpy(ptr, client_ptr -> nx_ptp_client_port_identity, NX_PTP_CLOCK_IDENTITY_SIZE); /* use case of memcpy is verified. */
    ptr += NX_PTP_CLOCK_IDENTITY_SIZE;

    /* set final message length */
    packet_ptr -> nx_packet_length = (ULONG)(ptr - (packet_ptr -> nx_packet_prepend_ptr));
    packet_ptr -> nx_packet_append_ptr = ptr;

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* set source and destination addresses */
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    if (client_ptr -> nx_ptp_client_master_addr.nxd_ip_version == NX_IP_VERSION_V6)
    {
        NX_PTP_IPV6_MULTICAST_ADDR_SET(&addr);

        /* Use first IPv6 address as source address. */
        ip_ptr = client_ptr -> nx_ptp_client_ip_ptr;
        if_ptr = &ip_ptr -> nx_ip_interface[client_ptr -> nx_ptp_client_interface_index];
        ipv6_addr = if_ptr -> nxd_interface_ipv6_address_list_head;
        if (ipv6_addr == NX_NULL)
        {

            /* No available IPv6 address.  */
            /* Release packet.  */
            nx_packet_release(packet_ptr);

            return;
        }
        addr_index = ipv6_addr -> nxd_ipv6_address_index;
    }
    else
#endif
    {
#ifndef NX_DISABLE_IPV4
        addr.nxd_ip_version = NX_IP_VERSION_V4;
        addr.nxd_ip_address.v4 = NX_PTP_IPV4_MULTICAST_ADDR;
        addr_index = client_ptr -> nx_ptp_client_interface_index;
#endif
    }
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

#if NX_PTP_CLIENT_TRANSPORT_UDP
    status = nxd_udp_socket_source_send((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_event_socket,
                                        packet_ptr, &addr, NX_PTP_GENERAL_UDP_PORT, addr_index);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    nx_link_ethernet_packet_send(client_ptr -> nx_ptp_client_ip_ptr,
                                 client_ptr -> nx_ptp_client_interface_index, packet_ptr,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_MSB,
                                 NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_LSB,
                                 NX_PTP_ETHERNET_TYPE);
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */
    if (status)
    {
        /* release packet in case of error */
        nx_packet_release(packet_ptr);
    }
}
#endif /* NX_PTP_ENABLE_MASTER */

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_process_event_packet                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes PTP packet received through event socket.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    packet_ptr                            Pointer to PTP packet         */
/*    hdr                                   Pointer to PTP header         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_sync_received          Process Sync message          */
/*    _nx_ptp_msg_parse_hdr                 Parse PTP header              */
/*    memcmp                                Compare memory                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_thread_entry           PTP thread entry              */
/*    _nx_ptp_client_send_pdelay_resp       Send pdelay response          */
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
static VOID _nx_ptp_client_process_event_packet(NX_PTP_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                                NX_PTP_MSG_HEADER *hdr)
{

#if defined(NX_ENABLE_GPTP)
    if (hdr -> messageType == NX_PTP_MSG_TYPE_PDELAY_REQ)
    {

        if (packet_ptr -> nx_packet_length < NX_PTP_MSG_PDELAY_REQ_LEN)
        {
            /* not waiting for Pdelay_Req or invalid message */
            return;
        }     
        
        /* record timestamp of received message (t2) */
        client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_TS_EXTRACT_ETHERNET,
                                                &client_ptr -> nx_ptp_client_pdelay_req_receipt, packet_ptr,
                                                client_ptr -> nx_ptp_client_clock_callback_data);

        /* update request_id */
        client_ptr -> nx_ptp_client_pdelay_responder_id = hdr -> sequenceId;

        /* update nx_ptp_client_request_port_identity */
        memcpy(client_ptr -> nx_ptp_client_request_port_identity, hdr -> sourcePortIdentity,
               NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */

        client_ptr -> nx_ptp_client_pdelay_responder_state = NX_PTP_CLIENT_PDELAY_SEND_RESP_TWOSTEP;
        _nx_ptp_client_send_pdelay_resp(client_ptr);
    }
    else if (hdr -> messageType == NX_PTP_MSG_TYPE_PDELAY_RESP)
    {
        if ((client_ptr -> nx_ptp_client_pdelay_initiator_state != NX_PTP_CLIENT_PDELAY_WAIT_RESP) ||
            (client_ptr -> nx_ptp_client_pdelay_req_id != hdr -> sequenceId) ||
            (packet_ptr -> nx_packet_length < NX_PTP_MSG_PDELAY_RESP_LEN))
        {

            /* not waiting for Pdelay_resp or invalid message */
            return;
        }

        /* retrieve timestamp of event message */
        client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_TS_EXTRACT_ETHERNET,
                                                &client_ptr -> nx_ptp_client_pdelay_resp_ts, packet_ptr,
                                                client_ptr -> nx_ptp_client_clock_callback_data);
        
        /* get t2 timestamp */
        _nx_ptp_msg_parse_timestamp(packet_ptr -> nx_packet_prepend_ptr, &client_ptr -> nx_ptp_client_pdelay_req_receipt_ts);

        /* two-step message? */
        if (hdr -> flagField & NX_PTP_MSG_HDR_FLAG_TWO_STEP)
        {
            client_ptr -> nx_ptp_client_pdelay_initiator_state = NX_PTP_CLIENT_PDELAY_WAIT_RESP_FOLLOW_UP;
        }
        else
        {
            /* process Pdelay_Resp event */
            _nx_ptp_client_pdelay_resp_received(client_ptr, packet_ptr -> nx_packet_prepend_ptr);
        }
    }
#endif
    
    if (hdr -> messageType == NX_PTP_MSG_TYPE_SYNC)
    {
        if ((client_ptr -> nx_ptp_client_state != NX_PTP_CLIENT_STATE_SLAVE) ||
            (packet_ptr -> nx_packet_length < NX_PTP_MSG_SYNC_LEN))
        {

            /* not waiting for Sync or invalid message */
            return;
        }

        /* Store previous sync timestamp.  */
        NX_PTP_TS_COPY(client_ptr -> nx_ptp_client_prev_sync, client_ptr -> nx_ptp_client_sync);
        NX_PTP_TS_COPY(client_ptr -> nx_ptp_client_prev_sync_ts, client_ptr -> nx_ptp_client_sync_ts);

        /* retrieve timestamp of event message */
        client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_PACKET_TS_EXTRACT,
                                                &client_ptr -> nx_ptp_client_sync_ts, packet_ptr,
                                                client_ptr -> nx_ptp_client_clock_callback_data);

        /* two-step message? */
        if (hdr -> flagField & NX_PTP_MSG_HDR_FLAG_TWO_STEP)
        {

            /* wait for follow up message */
            client_ptr -> nx_ptp_client_sync_id = hdr -> sequenceId;
        }
        else
        {

            /* process Sync event */
            _nx_ptp_client_sync_received(client_ptr, packet_ptr -> nx_packet_prepend_ptr, hdr);
        }
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_process_general_packet               PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes PTP packet received through general socket. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    packet_ptr                            Pointer to PTP packet         */
/*    hdr                                   Pointer to PTP header         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_sync_received          Process Sync message          */
/*    _nx_ptp_msg_parse_hdr                 Parse PTP header              */
/*    _nx_ptp_client_delay_resp_received    Process delay response        */
/*    _nx_ptp_client_init_packet_received   Process Announce message      */
/*    memcmp                                Compare memory                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_thread_entry           PTP thread entry              */
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
static VOID _nx_ptp_client_process_general_packet(NX_PTP_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                                  NX_PTP_MSG_HEADER *hdr)
{

    /* process ANNOUNCE message */
    if (hdr -> messageType == NX_PTP_MSG_TYPE_ANNOUNCE)
    {
        if (packet_ptr -> nx_packet_length < NX_PTP_MSG_ANNOUNCE_LEN)
        {

            /* invalid message */
            return;
        }

        /* process announce message */
        _nx_ptp_client_init_packet_received(client_ptr, hdr, packet_ptr -> nx_packet_prepend_ptr);
    }
    /* process FOLLOW_UP message */
    else if (hdr -> messageType == NX_PTP_MSG_TYPE_FOLLOW_UP)
    {
        if ((client_ptr -> nx_ptp_client_state != NX_PTP_CLIENT_STATE_SLAVE) ||
            (client_ptr -> nx_ptp_client_sync_id != hdr -> sequenceId) ||
            (packet_ptr -> nx_packet_length < NX_PTP_MSG_FOLLOW_UP_LEN))
        {

            /* not a follow up for a previous Sync or invalid message */
            return;
        }

        /* process Sync message */
        _nx_ptp_client_sync_received(client_ptr, packet_ptr -> nx_packet_prepend_ptr, hdr);
    }
#if defined(NX_ENABLE_GPTP)
    if (hdr -> messageType == NX_PTP_MSG_TYPE_PDELAY_RESP_FOLLOW_UP)
    {
        if ((client_ptr -> nx_ptp_client_pdelay_initiator_state != NX_PTP_CLIENT_PDELAY_WAIT_RESP_FOLLOW_UP) ||
            (client_ptr -> nx_ptp_client_pdelay_req_id != hdr -> sequenceId) ||
            (packet_ptr -> nx_packet_length < NX_PTP_MSG_PDELAY_RESP_FOLLOW_UP_LEN))
        {

            /* not a follow up for a previous Pdelay_resp or invalid message */
            return;
        }

        /* process Pdelay_Resp event */
        _nx_ptp_client_pdelay_resp_received(client_ptr, packet_ptr -> nx_packet_prepend_ptr);
    }
#else
    else if (hdr -> messageType == NX_PTP_MSG_TYPE_DELAY_RESP)
    {
        if ((client_ptr -> nx_ptp_client_delay_state != NX_PTP_CLIENT_DELAY_WAIT_RESP) ||
            (client_ptr -> nx_ptp_client_delay_req_id != hdr -> sequenceId) ||
            (packet_ptr -> nx_packet_length < NX_PTP_MSG_DELAY_RESP_LEN) ||
            (memcmp(client_ptr -> nx_ptp_client_port_identity,
                    packet_ptr -> nx_packet_prepend_ptr + NX_PTP_MSG_TIMESTAMP_LEN,
                    NX_PTP_CLOCK_PORT_IDENTITY_SIZE) != 0))
        {

            /* not a delay_resp for a previous delay_req or invalid message */
            return;
        }

        /* process delay response message */
        _nx_ptp_client_delay_resp_received(client_ptr, packet_ptr -> nx_packet_prepend_ptr);
    }
#endif
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_thread_entry                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function implements the PTP client processing thread.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ptp_instance                          Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_process_general_packet Process PTP general packet    */
/*    _nx_ptp_client_process_event_packet   Process PTP event packet      */
/*    _nx_ptp_client_send_pdelay_resp_follow_up                           */
/*                                          Send pdelay response message  */
/*    _nx_ptp_client_send_follow_up         Send follow up message        */
/*    _nx_ptp_client_send_sync              Send sync message             */
/*    _nx_ptp_client_send_announce          Send announce message         */
/*    tx_event_flags_get                    Get PTP events                */
/*    nx_udp_socket_receive                 Receive a UDP packet          */
/*    nx_packet_release                     Release a packet              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    ThreadX                                                             */
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
static VOID _nx_ptp_client_thread_entry(ULONG ptp_instance)
{
TX_INTERRUPT_SAVE_AREA
NX_PTP_CLIENT    *client_ptr = (NX_PTP_CLIENT *)ptp_instance;
ULONG             ptp_events;
UINT              status;
NX_PACKET        *packet_ptr = NX_NULL;
NX_PTP_MSG_HEADER hdr;

#ifdef NX_PTP_ENABLE_MASTER
    if (client_ptr -> nx_ptp_client_role == NX_PTP_CLIENT_ROLE_MASTER_ONLY)
    {

        /* Set timer values */
        client_ptr -> ptp_master.nx_ptp_client_master_announce_timer = NX_PTP_CLIENT_ANNOUNCE_INTERVAL;
        client_ptr -> nx_ptp_client_sync_timer = NX_PTP_CLIENT_SYNC_INTERVAL;
        client_ptr -> nx_ptp_client_state = NX_PTP_CLIENT_STATE_MASTER;
                    
        client_ptr -> nx_ptp_client_event_callback(client_ptr, NX_PTP_CLIENT_EVENT_MASTER,
                                                   &client_ptr -> ptp_master,
                                                   client_ptr -> nx_ptp_client_event_callback_data);
    }
    else
    {

        /* Set timer values */
        client_ptr -> ptp_master.nx_ptp_client_master_announce_timer = -1;
        client_ptr -> nx_ptp_client_sync_timer = -1;
#endif /* NX_PTP_ENABLE_MASTER */
        client_ptr -> nx_ptp_client_delay_req_timer = -1;
        client_ptr -> nx_ptp_client_announce_timeout = NX_PTP_CLIENT_ANNOUNCE_EXPIRATION;
        
        /* start in listening state */
        client_ptr -> nx_ptp_client_state = NX_PTP_CLIENT_STATE_LISTENING;
#ifdef NX_PTP_ENABLE_MASTER
    }
#endif /* NX_PTP_ENABLE_MASTER */

#ifdef NX_ENABLE_GPTP
    client_ptr -> nx_ptp_client_pdelay_initiator_state = NX_PTP_CLIENT_PDELAY_IDLE;
    client_ptr -> nx_ptp_client_pdelay_req_timer = NX_PTP_CLIENT_PDELAY_REQ_INTERVAL;
#endif

    /* main loop */
    for (;;)
    {

        /* wait for message */
        status = tx_event_flags_get(&(client_ptr -> nx_ptp_client_events),
                                    NX_PTP_CLIENT_ALL_EVENTS, TX_OR_CLEAR,
                                    &ptp_events, TX_WAIT_FOREVER);
        if (status != TX_SUCCESS)
        {

            /* error while reading queue, abort thread */
            break;
        }

        if (ptp_events & NX_PTP_CLIENT_STOP_EVENT)
        {

            /* terminate thread */
            break;
        }

#ifdef NX_ENABLE_GPTP
        if (ptp_events & NX_PTP_CLIENT_PDELAY_FOLLOW_EVENT)
        {

            /* update state to send_pdelay_resp_follow_up */
            client_ptr -> nx_ptp_client_pdelay_responder_state = NX_PTP_CLIENT_PDELAY_SEND_FOLLOW_UP;

            /* call send follow up */
            _nx_ptp_client_send_pdelay_resp_follow_up(client_ptr);
        }
#endif

#if defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC)
        if (ptp_events & NX_PTP_CLIENT_SYNC_FOLLOW_EVENT)
        {

            /* call send follow up */
            _nx_ptp_client_send_follow_up(client_ptr);
        }
#endif /* defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC) */

        /*
         * PTP Message Received
         */
        if (ptp_events & NX_PTP_CLIENT_RX_EVENT)
        {

            /* Loop to receive all packets. */
            for (;;)
            {
#if NX_PTP_CLIENT_TRANSPORT_UDP
                if ((nx_udp_socket_receive(&(client_ptr -> nx_ptp_client_event_socket),
                                           &packet_ptr, NX_NO_WAIT) == NX_SUCCESS) ||
                    (nx_udp_socket_receive(&(client_ptr -> nx_ptp_client_general_socket),
                                           &packet_ptr, NX_NO_WAIT) == NX_SUCCESS))
                {
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
                if (client_ptr -> nx_ptp_client_received_packet_head)
                {

                    /* Remove the first packet and process it!  */

                    /* Disable interrupts.  */
                    TX_DISABLE

                    /* Pickup the first packet.  */
                    packet_ptr =  client_ptr -> nx_ptp_client_received_packet_head;

                    /* Move the head pointer to the next packet.  */
                    client_ptr -> nx_ptp_client_received_packet_head =  packet_ptr -> nx_packet_queue_next;

                    /* Check for end of deferred processing queue.  */
                    if (client_ptr -> nx_ptp_client_received_packet_head == NX_NULL)
                    {

                        /* Yes, the queue is empty.  Set the tail pointer to NULL.  */
                       client_ptr -> nx_ptp_client_received_packet_tail =  NX_NULL;
                    }

                    /* Restore interrupts.  */
                    TX_RESTORE

#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */
                    
                    /* Parse header first.  */
                    if (_nx_ptp_msg_parse_hdr(client_ptr, packet_ptr, &hdr))
                    {

                        /* Release packet. */
                        nx_packet_release(packet_ptr);
                        continue;
                    }

                    /* check origin of message */
                    if ((client_ptr -> nx_ptp_client_state == NX_PTP_CLIENT_STATE_SLAVE) &&
                        (memcmp(&client_ptr -> nx_ptp_client_master_port_identity,
                                hdr.sourcePortIdentity, NX_PTP_CLOCK_PORT_IDENTITY_SIZE) != 0))
                    {

                        /* not from our master clock */
                        nx_packet_release(packet_ptr);
                        continue;
                    }

                    if ((hdr.messageType == NX_PTP_MSG_TYPE_SYNC)
#ifdef NX_ENABLE_GPTP
                        || (hdr.messageType == NX_PTP_MSG_TYPE_PDELAY_REQ) 
                        || (hdr.messageType == NX_PTP_MSG_TYPE_PDELAY_RESP)
#endif /* NX_ENABLE_GPTP */
                       )
                    {
                        _nx_ptp_client_process_event_packet(client_ptr, packet_ptr, &hdr);
                    }
                    else
                    {
                        _nx_ptp_client_process_general_packet(client_ptr, packet_ptr, &hdr);
                    }

                    /* Release packet. */
                    nx_packet_release(packet_ptr);
                }
                else
                {
                    break;
                }
            }
        }

        /*
         * Timer Event
         */
        if (ptp_events & NX_PTP_CLIENT_TIMER_EVENT)
        {
#ifdef NX_ENABLE_GPTP
            /* pdelay_req interval timer */
            if ((client_ptr -> nx_ptp_client_pdelay_req_timer > 0) &&
                (--client_ptr -> nx_ptp_client_pdelay_req_timer == 0))
            {
                _nx_ptp_client_send_pdelay_req(client_ptr);
            }
#endif
#if defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC)
#ifdef NX_PTP_ENABLE_MASTER
            /* announce messages timeout */
            if (((client_ptr -> ptp_master).nx_ptp_client_master_announce_timer > 0) &&
                (--(client_ptr -> ptp_master).nx_ptp_client_master_announce_timer == 0))
            {
                _nx_ptp_client_send_announce(client_ptr);

                /* Reset timer.  */
                (client_ptr -> ptp_master).nx_ptp_client_master_announce_timer = NX_PTP_CLIENT_ANNOUNCE_INTERVAL;
            }
#endif /* NX_PTP_ENABLE_MASTER */
            /* Sync messages timeout */
            if ((client_ptr -> nx_ptp_client_sync_timer > 0) &&
                (--client_ptr -> nx_ptp_client_sync_timer == 0))
            {
                _nx_ptp_client_send_sync(client_ptr);

                /* Reset timer.  */
                client_ptr -> nx_ptp_client_sync_timer = NX_PTP_CLIENT_SYNC_INTERVAL;
            }
#endif /* defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC) */

#ifndef NX_PTP_DISABLE_SLAVE
            /* announce messages timeout */
            if ((client_ptr -> nx_ptp_client_announce_timeout > 0) &&
                (--client_ptr -> nx_ptp_client_announce_timeout == 0))
            {

#ifdef NX_PTP_ENABLE_MASTER
                if (client_ptr -> nx_ptp_client_role == NX_PTP_CLIENT_ROLE_SLAVE_ONLY)
#endif /* NX_PTP_ENABLE_MASTER */
                {

                    /* no Announce message received from master clock, back to listening state */
                    client_ptr -> nx_ptp_client_state = NX_PTP_CLIENT_STATE_LISTENING;
                    client_ptr -> nx_ptp_client_delay_req_timer = -1;
                    client_ptr -> nx_ptp_client_announce_timeout = -1;

                    /* call handler */
                    if (client_ptr -> nx_ptp_client_event_callback)
                    {
                        client_ptr -> nx_ptp_client_event_callback(client_ptr, NX_PTP_CLIENT_EVENT_TIMEOUT, NX_NULL,
                                                                client_ptr -> nx_ptp_client_event_callback_data);
                    }
                }
#ifdef NX_PTP_ENABLE_MASTER
                else
                {

                    /* no Announce message received from master clock, change to master clock. */
                    client_ptr -> nx_ptp_client_state = NX_PTP_CLIENT_STATE_MASTER;

                    /* set timeout for announce and sync */
                    client_ptr -> ptp_master.nx_ptp_client_master_announce_timer = NX_PTP_CLIENT_ANNOUNCE_INTERVAL;
                    client_ptr -> nx_ptp_client_sync_timer = NX_PTP_CLIENT_SYNC_INTERVAL;
                    NX_PTP_DEBUG_PRINTF(("PTP: recommend local clock to be master\r\n"));
                    
                    client_ptr -> nx_ptp_client_event_callback(client_ptr, NX_PTP_CLIENT_EVENT_MASTER,
                                                               &client_ptr -> ptp_master,
                                                               client_ptr -> nx_ptp_client_event_callback_data);
                }
#endif /* NX_PTP_ENABLE_MASTER */
            }

            /* delay req interval timer */
            if ((client_ptr -> nx_ptp_client_delay_req_timer > 0) &&
                (--client_ptr -> nx_ptp_client_delay_req_timer == 0))
            {

                /* set flag */
                client_ptr -> nx_ptp_client_delay_req_flag = 1;
            }
#endif
        }
    }

    /* set stopped state */
    TX_DISABLE
    client_ptr -> nx_ptp_client_thread_state = NX_PTP_CLIENT_THREAD_STOPPED;
    TX_RESTORE
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_create                              PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP client create service.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    ip_ptr                                Pointer to client IP instance */
/*    interface_index                       Index of PTP network interface*/
/*    packet_pool_ptr                       Pointer to client packet pool */
/*    thread_priority                       Priority of PTP thread        */
/*    thread_stack                          Pointer to thread stack       */
/*    stack_size                            Size of thread stack          */
/*    clock_callback                        PTP clock callback            */
/*    clock_callback_data                   Data for the clock callback   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_create                 Actual create service         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_create(NX_PTP_CLIENT *client_ptr, NX_IP *ip_ptr, UINT interface_index,
                            NX_PACKET_POOL *packet_pool_ptr, UINT thread_priority, UCHAR *thread_stack, UINT stack_size,
                            NX_PTP_CLIENT_CLOCK_CALLBACK clock_callback, VOID *clock_callback_data)
{

    /* Check input parameters.  */
    if ((client_ptr == NX_NULL) || (ip_ptr == NX_NULL) || (packet_pool_ptr == NX_NULL) ||
        (thread_stack == NX_NULL) || (stack_size == 0) || (clock_callback == NX_NULL))
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }

    /* Check for invalid network interface input. */
    if (interface_index >= NX_MAX_PHYSICAL_INTERFACES)
    {
        return(NX_INVALID_INTERFACE);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return _nx_ptp_client_create(client_ptr, ip_ptr, interface_index, packet_pool_ptr, thread_priority,
                                 thread_stack, stack_size, clock_callback, clock_callback_data);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_create                               PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates the PTP client.                               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    ip_ptr                                Pointer to client IP instance */
/*    interface_index                       Index of PTP network interface*/
/*    packet_pool_ptr                       Pointer to client packet pool */
/*    thread_priority                       Priority of PTP thread        */
/*    thread_stack                          Pointer to thread stack       */
/*    stack_size                            Size of thread stack          */
/*    clock_callback                        PTP clock callback            */
/*    clock_callback_data                   Data for the clock callback   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memset                                Reset memory                  */
/*    [clock_callback]                      Initialize clock              */
/*    tx_event_flags_create                 Create PTP event flags        */
/*    tx_event_flags_delete                 Delete PTP event flags        */
/*    nx_udp_socket_create                  Create a UDP socket           */
/*    nx_udp_socket_delete                  Delete a UDP socket           */
/*    nx_udp_socket_receive_notify          Set UDP receive notify        */
/*    tx_timer_create                       Create a timer                */
/*    tx_timer_delete                       Delete a timer                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*  12-31-2023     Tiejun Zhou              Modified comment(s), and      */
/*                                            supported gPTP profile,     */
/*                                            resulting in version 6.4.0  */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_create(NX_PTP_CLIENT *client_ptr, NX_IP *ip_ptr, UINT interface_index,
                           NX_PACKET_POOL *packet_pool_ptr, UINT thread_priority, UCHAR *thread_stack, UINT stack_size,
                           NX_PTP_CLIENT_CLOCK_CALLBACK clock_callback, VOID *clock_callback_data)
{
UINT status;

    /* Null the members of NX_PTP_CLIENT.  */
    memset(client_ptr, 0, sizeof(NX_PTP_CLIENT));

    /* Set the Client ID to indicate the PTP client thread is ready.  */
    client_ptr -> nx_ptp_client_id = NX_PTP_CLIENT_ID;

    /* Set the IP instance.  */
    client_ptr -> nx_ptp_client_ip_ptr = ip_ptr;

    /* Set the PTP network interface. */
    client_ptr -> nx_ptp_client_interface_index = interface_index;

    /* Set the packet pool, check for minimal packet size requirement. */
    if (packet_pool_ptr -> nx_packet_pool_payload_size <
        (NX_PTP_PACKET + NX_PTP_CLIENT_PACKET_DATA_SIZE))
    {
        return(NX_PTP_CLIENT_INSUFFICIENT_PACKET_PAYLOAD);
    }
    client_ptr -> nx_ptp_client_packet_pool_ptr = packet_pool_ptr;

    /* Initialize callback function.  */
    status = clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_INIT, NX_NULL, NX_NULL, clock_callback_data);
    if (status)
    {

        /* Fail to initialize clock in callback function.  */
        return(NX_PTP_CLIENT_CLOCK_CALLBACK_FAILURE);
    }

    /* Set the PTP clock callback */
    client_ptr -> nx_ptp_client_clock_callback = clock_callback;
    client_ptr -> nx_ptp_client_clock_callback_data = clock_callback_data;

    /* By default, the PTP client will run in slave only mode.  */
    client_ptr -> nx_ptp_client_role = NX_PTP_CLIENT_ROLE_SLAVE_ONLY;

    /* create the internal PTP event flag object.  */
    status = tx_event_flags_create(&(client_ptr -> nx_ptp_client_events), "NetX PTP event flag");
    if (status != TX_SUCCESS)
    {
        return(status);
    }

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* create the general socket */
    status = nx_udp_socket_create(ip_ptr, &client_ptr -> nx_ptp_client_general_socket,
                                 "NetX PTP Client general socket", NX_IP_NORMAL,
                                 NX_DONT_FRAGMENT, NX_PTP_TIME_TO_LIVE,
                                 NX_PTP_CLIENT_MAX_QUEUE_DEPTH);
    if (status != NX_SUCCESS)
    {
        tx_event_flags_delete(&client_ptr -> nx_ptp_client_events);
        return(status);
    }
    client_ptr -> nx_ptp_client_general_socket.nx_udp_socket_reserved_ptr = client_ptr;
    nx_udp_socket_receive_notify(&client_ptr -> nx_ptp_client_general_socket, _nx_ptp_client_socket_receive_notify);

    /* create the event socket */
    status = nx_udp_socket_create(ip_ptr, &client_ptr -> nx_ptp_client_event_socket,
                                  "NetX PTP Client event socket", NX_IP_NORMAL, NX_DONT_FRAGMENT,
                                  NX_PTP_TIME_TO_LIVE,
                                  NX_PTP_CLIENT_MAX_QUEUE_DEPTH);
    if (status != NX_SUCCESS)
    {
        nx_udp_socket_delete(&client_ptr -> nx_ptp_client_general_socket);
        tx_event_flags_delete(&client_ptr -> nx_ptp_client_events);
        return(status);
    }
    client_ptr -> nx_ptp_client_event_socket.nx_udp_socket_reserved_ptr = client_ptr;
    nx_udp_socket_receive_notify(&client_ptr -> nx_ptp_client_event_socket, _nx_ptp_client_socket_receive_notify);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* create the timer */
    status = tx_timer_create(&client_ptr -> nx_ptp_client_timer,
                                "NetX PTP Client timer",
                                _nx_ptp_client_timer_handler,
                                (ULONG)client_ptr,
                                TX_TIMER_TICKS_PER_SECOND / NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND,
                                TX_TIMER_TICKS_PER_SECOND / NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND,
                                TX_NO_ACTIVATE);
    if (status != TX_SUCCESS)
    {
#if NX_PTP_CLIENT_TRANSPORT_UDP
        nx_udp_socket_delete(&client_ptr -> nx_ptp_client_general_socket);
        nx_udp_socket_delete(&client_ptr -> nx_ptp_client_event_socket);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
        tx_event_flags_delete(&client_ptr -> nx_ptp_client_events);
        return(status);
    }

    /* create the Client thread */
    status = tx_thread_create(&client_ptr -> nx_ptp_client_thread,
                              "NetX PTP Client", _nx_ptp_client_thread_entry,
                              (ULONG)client_ptr, thread_stack, stack_size,
                              thread_priority, thread_priority,
                              NX_PTP_CLIENT_THREAD_TIME_SLICE, TX_DONT_START);
    if (status != TX_SUCCESS)
    {
#if NX_PTP_CLIENT_TRANSPORT_UDP
        nx_udp_socket_delete(&client_ptr -> nx_ptp_client_general_socket);
        nx_udp_socket_delete(&client_ptr -> nx_ptp_client_event_socket);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */
        tx_timer_delete(&client_ptr -> nx_ptp_client_timer);
        tx_event_flags_delete(&client_ptr -> nx_ptp_client_events);
        return(status);
    }

    /* return Success */
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_delete                              PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP client delete service.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_delete                 Actual delete service         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_delete(NX_PTP_CLIENT *client_ptr)
{

    /* Check input parameters.  */
    if (client_ptr == NX_NULL)
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return(_nx_ptp_client_delete(client_ptr));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_delete                               PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deletes the PTP client.                               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_stop                   Stop PTP service              */
/*    tx_thread_suspend                     Suspend PTP thread            */
/*    tx_thread_terminate                   Terminate PTP thread          */
/*    tx_thread_delete                      Delete PTP thread             */
/*    tx_event_flags_delete                 Delete PTP event flags        */
/*    nx_udp_socket_delete                  Delete a UDP socket           */
/*    tx_timer_delete                       Delete a timer                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*  12-31-2023     Tiejun Zhou              Modified comment(s), and      */
/*                                            supported gPTP profile,     */
/*                                            resulting in version 6.4.0  */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_delete(NX_PTP_CLIENT *client_ptr)
{

    /* Ensure the Client is stopped */
    _nx_ptp_client_stop(client_ptr);

    /* Suspend the Client thread.  */
    tx_thread_suspend(&client_ptr -> nx_ptp_client_thread);

    /* Terminate Client thread. */
    tx_thread_terminate(&client_ptr -> nx_ptp_client_thread);

    /* Delete Client thread.  */
    tx_thread_delete(&client_ptr -> nx_ptp_client_thread);

    /* Delete the timer */
    tx_timer_delete(&client_ptr -> nx_ptp_client_timer);

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* Delete the general socket */
    nx_udp_socket_delete((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_general_socket);

    /* Delete the event socket */
    nx_udp_socket_delete((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_event_socket);
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

    /* Delete the event flag */
    tx_event_flags_delete(&client_ptr -> nx_ptp_client_events);

    /* return Success */
    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_start                               PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP client start service.    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    client_port_identity_ptr              Pointer to client port and    */
/*                                            identity                    */
/*    client_port_identity_length           Length of client port and     */
/*                                            identity                    */
/*    domain                                PTP clock domain              */
/*    transport_specific                    Transport specific            */
/*    event_callback                        Event callback                */
/*    event_callback_data                   Data for the event callback   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_start                  Actual start service          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_start(NX_PTP_CLIENT *client_ptr, UCHAR *client_port_identity_ptr, UINT client_port_identity_length,
                           UINT domain, UINT transport_specific, NX_PTP_CLIENT_EVENT_CALLBACK event_callback,
                           VOID *event_callback_data)
{

    /* Check input parameters.  */
    if ((client_ptr == NX_NULL) ||
        ((client_port_identity_ptr == NX_NULL) && (client_port_identity_length != 0)) ||
        ((client_port_identity_ptr != NX_NULL) && (client_port_identity_length != NX_PTP_CLOCK_PORT_IDENTITY_SIZE)))
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return(_nx_ptp_client_start(client_ptr, client_port_identity_ptr, client_port_identity_length,
                                domain, transport_specific, event_callback, event_callback_data));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_start                                PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function starts the PTP client.                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    client_port_identity_ptr              Pointer to client port and    */
/*                                            identity                    */
/*    client_port_identity_length           Length of client port and     */
/*                                            identity                    */
/*    domain                                PTP clock domain              */
/*    transport_specific                    Transport specific            */
/*    event_callback                        Event callback                */
/*    event_callback_data                   Data for the event callback   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_thread_suspend                     Suspend PTP thread            */
/*    tx_thread_terminate                   Terminate PTP thread          */
/*    tx_thread_reset                       Reset PTP thread              */
/*    tx_thread_resume                      Resume PTP thread             */
/*    memcpy                                Copy memory                   */
/*    nx_ip_interface_physical_address_get  Get physical address          */
/*    nx_udp_socket_bind                    Bind UDP port                 */
/*    nx_ipv4_multicast_interface_join      Join IPv4 multicast group     */
/*    nxd_ipv6_multicast_interface_join     Join IPv6 multicast group     */
/*    tx_timer_activate                     Activate timer                */
/*    _nx_ptp_client_stop                   Stop PTP service              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
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
UINT _nx_ptp_client_start(NX_PTP_CLIENT *client_ptr, UCHAR *client_port_identity_ptr, UINT client_port_identity_length,
                          UINT domain, UINT transport_specific, NX_PTP_CLIENT_EVENT_CALLBACK event_callback,
                          VOID *event_callback_data)
{
TX_INTERRUPT_SAVE_AREA
UINT  state;
UINT  status;
ULONG msw, lsw;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_ADDRESS maddr;
#endif

    NX_PARAMETER_NOT_USED(client_port_identity_length);

    /* Check if Client is running */
    TX_DISABLE
    state = client_ptr -> nx_ptp_client_thread_state;
    if (state == NX_PTP_CLIENT_THREAD_IDLE)
    {
        client_ptr -> nx_ptp_client_thread_state = NX_PTP_CLIENT_THREAD_RUNNING;
    }
    TX_RESTORE
    if (state != NX_PTP_CLIENT_THREAD_IDLE)
    {

        /* Client is already running */
        return(NX_PTP_CLIENT_ALREADY_STARTED);
    }

    /* ensure the thread is terminated */
    tx_thread_suspend(&client_ptr -> nx_ptp_client_thread);
    tx_thread_terminate(&client_ptr -> nx_ptp_client_thread);

    /* save the client parameters */
    client_ptr -> nx_ptp_client_domain    = (UCHAR)domain;
    client_ptr -> nx_ptp_client_transport_specific = (UCHAR)transport_specific;
    client_ptr -> nx_ptp_client_event_callback = event_callback;
    client_ptr -> nx_ptp_client_event_callback_data = event_callback_data;
    client_ptr -> nx_ptp_client_delay.nanosecond = NX_PTP_CLIENT_DELAY_THRESH;

    /* reset and resume the thread */
    status = tx_thread_reset(&client_ptr -> nx_ptp_client_thread);
    if (status != TX_SUCCESS)
    {
        TX_DISABLE
        client_ptr -> nx_ptp_client_thread_state = NX_PTP_CLIENT_THREAD_IDLE;
        TX_RESTORE

        return(status);
    }
    tx_thread_resume(&client_ptr -> nx_ptp_client_thread);

    /* set the client port and identity */
    if (client_port_identity_ptr != NX_NULL)
    {

        /* copy provided identifier */
        memcpy(client_ptr -> nx_ptp_client_port_identity, client_port_identity_ptr,
               NX_PTP_CLOCK_PORT_IDENTITY_SIZE); /* use case of memcpy is verified. */
    }
    else
    {

        /* get MAC address of interface */
        status = nx_ip_interface_physical_address_get(client_ptr -> nx_ptp_client_ip_ptr,
                                                      client_ptr -> nx_ptp_client_interface_index,
                                                      &msw, &lsw);
        if (status == TX_SUCCESS)
        {
            /* convert 48-bit MAC address to 64-bit EUI */
            client_ptr -> nx_ptp_client_port_identity[0] = (UCHAR)(msw >> 8);
            client_ptr -> nx_ptp_client_port_identity[1] = (UCHAR)msw;
            client_ptr -> nx_ptp_client_port_identity[2] = (UCHAR)(lsw >> 24);
            client_ptr -> nx_ptp_client_port_identity[3] = 0xff;
            client_ptr -> nx_ptp_client_port_identity[4] = 0xfe;
            client_ptr -> nx_ptp_client_port_identity[5] = (UCHAR)(lsw >> 16);
            client_ptr -> nx_ptp_client_port_identity[6] = (UCHAR)(lsw >> 8);
            client_ptr -> nx_ptp_client_port_identity[7] = (UCHAR)lsw;

            /* set default port number (1) */
            client_ptr -> nx_ptp_client_port_identity[8] = 0;
            client_ptr -> nx_ptp_client_port_identity[9] = 1;
        }
    }

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* bind the general socket */
    if (status == TX_SUCCESS)
    {
        status = nx_udp_socket_bind((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_general_socket,
                                    NX_PTP_GENERAL_UDP_PORT, NX_NO_WAIT);
    }

    /* bind the event socket */
    if (status == TX_SUCCESS)
    {
        status = nx_udp_socket_bind((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_event_socket,
                                    NX_PTP_EVENT_UDP_PORT, NX_NO_WAIT);
    }

    /* join the multicast groups */
    if (status == TX_SUCCESS)
    {
        status = nx_ipv4_multicast_interface_join(client_ptr -> nx_ptp_client_ip_ptr,
                                                  NX_PTP_IPV4_MULTICAST_ADDR,
                                                  client_ptr -> nx_ptp_client_interface_index);
        if (status == TX_SUCCESS)
        {
            status = nx_ipv4_multicast_interface_join(client_ptr -> nx_ptp_client_ip_ptr,
                                                  NX_PTP_IPV4_P2P_MULTICAST_ADDR,
                                                  client_ptr -> nx_ptp_client_interface_index);
            if (status == TX_SUCCESS)
            {
                client_ptr -> nx_ptp_client_ipv4_group_joined = NX_TRUE;
            }
        }
    }
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    if (status == TX_SUCCESS)
    {
        NX_PTP_IPV6_MULTICAST_ADDR_SET(&maddr);
        status = nxd_ipv6_multicast_interface_join(client_ptr -> nx_ptp_client_ip_ptr,
                                                   &maddr, client_ptr -> nx_ptp_client_interface_index);
        if (status == TX_SUCCESS)
        {
            NX_PTP_IPV6_P2P_MULTICAST_ADDR_SET(&maddr);
            status = nxd_ipv6_multicast_interface_join(client_ptr -> nx_ptp_client_ip_ptr,
                                                   &maddr, client_ptr -> nx_ptp_client_interface_index);
            if (status == TX_SUCCESS)
            {
                NX_PTP_IPV6_MULTICAST_ADDR_SET(&maddr);
                status = nxd_ipv6_multicast_interface_join(client_ptr -> nx_ptp_client_ip_ptr,
                                                   &maddr, client_ptr -> nx_ptp_client_interface_index);

                if (status == TX_SUCCESS)
                {
                    client_ptr -> nx_ptp_client_ipv6_group_joined = NX_TRUE;
                }
            }
        }
        else if ((status == NX_NOT_SUPPORTED) && (client_ptr -> nx_ptp_client_ipv4_group_joined))
        {

            /* IPv6 not enabled, use IPv4 only */
            status = TX_SUCCESS;
        }
    }
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    /* set link layer receive notification */
    status = nx_link_packet_receive_callback_add(client_ptr -> nx_ptp_client_ip_ptr,
                                                 client_ptr -> nx_ptp_client_interface_index,
                                                 &(client_ptr -> nx_ptp_client_link_queue),
                                                 NX_PTP_ETHERNET_TYPE,
                                                 _nx_ptp_client_ethernet_receive_notify, client_ptr);
    if (status != NX_SUCCESS)
    {
        return(status);
    }

    status = nx_link_multicast_join(client_ptr -> nx_ptp_client_ip_ptr,
                                    client_ptr -> nx_ptp_client_interface_index,
                                    NX_PTP_ETHERNET_ALL_MULTICAST_ADDR_MSB,
                                    NX_PTP_ETHERNET_ALL_MULTICAST_ADDR_LSB);
    if (status != NX_SUCCESS)
    {
        return(status);
    }

    status = nx_link_multicast_join(client_ptr -> nx_ptp_client_ip_ptr,
                                    client_ptr -> nx_ptp_client_interface_index,
                                    NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_MSB,
                                    NX_PTP_ETHERNET_P2P_MULTICAST_ADDR_LSB);
    if (status != NX_SUCCESS)
    {
        return(status);
    }
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */

    /* activate the Client timer */
    if (status == TX_SUCCESS)
    {

        /* activate the timer */
        status = tx_timer_activate(&client_ptr -> nx_ptp_client_timer);
    }

    /* stop the client thread in case of error */
    if (status != TX_SUCCESS)
    {
        _nx_ptp_client_stop(client_ptr);

        /* return failure */
        return(status);
    }

    /* return Success */
    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_stop                                PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP client stop service.     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_stop                   Actual stop service           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_stop(NX_PTP_CLIENT *client_ptr)
{

    /* Check input parameters.  */
    if (client_ptr == NX_NULL)
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return(_nx_ptp_client_stop(client_ptr));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_stop                                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function stops the PTP client.                                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_timer_deactivate                   Deactivate timer              */
/*    nx_udp_socket_unbind                  Unbind UDP port               */
/*    nx_ipv4_multicast_interface_leave     Leave IPv4 multicast group    */
/*    nxd_ipv6_multicast_interface_leave    Leave IPv6 multicast group    */
/*    tx_event_flags_set                    Set PTP timer event           */
/*    tx_thread_sleep                       Thread sleep                  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*  12-31-2023     Tiejun Zhou              Modified comment(s), and      */
/*                                            supported gPTP profile,     */
/*                                            resulting in version 6.4.0  */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_stop(NX_PTP_CLIENT *client_ptr)
{
TX_INTERRUPT_SAVE_AREA
UINT state;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_ADDRESS maddr;
#endif

    /* Check if Client is running */
    TX_DISABLE
    state = client_ptr -> nx_ptp_client_thread_state;
    if (state == NX_PTP_CLIENT_THREAD_RUNNING)
    {
        client_ptr -> nx_ptp_client_thread_state = NX_PTP_CLIENT_THREAD_STOPPING;
    }
    TX_RESTORE
    if ((state != NX_PTP_CLIENT_THREAD_RUNNING) &&
        (state != NX_PTP_CLIENT_THREAD_STOPPED))
    {

        /* Client is not running */
        return(NX_PTP_CLIENT_NOT_STARTED);
    }

    /* deactivate the timer */
    tx_timer_deactivate(&client_ptr -> nx_ptp_client_timer);

#if NX_PTP_CLIENT_TRANSPORT_UDP
    /* unbind the sockets */
    nx_udp_socket_unbind((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_general_socket);
    nx_udp_socket_unbind((NX_UDP_SOCKET *)&client_ptr -> nx_ptp_client_event_socket);

    /* leave multicast groups */
    if (client_ptr -> nx_ptp_client_ipv4_group_joined)
    {
        nx_ipv4_multicast_interface_leave(client_ptr -> nx_ptp_client_ip_ptr,
                                          NX_PTP_IPV4_MULTICAST_ADDR,
                                          client_ptr -> nx_ptp_client_interface_index);
        nx_ipv4_multicast_interface_leave(client_ptr -> nx_ptp_client_ip_ptr,
                                          NX_PTP_IPV4_P2P_MULTICAST_ADDR,
                                          client_ptr -> nx_ptp_client_interface_index);
        client_ptr -> nx_ptp_client_ipv4_group_joined = NX_FALSE;
    }
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    if (client_ptr -> nx_ptp_client_ipv6_group_joined)
    {
        NX_PTP_IPV6_MULTICAST_ADDR_SET(&maddr);
        nxd_ipv6_multicast_interface_leave(client_ptr -> nx_ptp_client_ip_ptr,
                                           &maddr, client_ptr -> nx_ptp_client_interface_index);
        NX_PTP_IPV6_P2P_MULTICAST_ADDR_SET(&maddr);
        nxd_ipv6_multicast_interface_leave(client_ptr -> nx_ptp_client_ip_ptr,
                                           &maddr, client_ptr -> nx_ptp_client_interface_index);
        client_ptr -> nx_ptp_client_ipv6_group_joined = NX_FALSE;
    }
#endif
#endif /* NX_PTP_CLIENT_TRANSPORT_UDP */

#if NX_PTP_CLIENT_TRANSPORT_ETHERNET
    nx_link_packet_receive_callback_remove(client_ptr -> nx_ptp_client_ip_ptr,
                                           client_ptr -> nx_ptp_client_interface_index,
                                           &(client_ptr -> nx_ptp_client_link_queue));
#endif /* NX_PTP_CLIENT_TRANSPORT_ETHERNET */

    /* send STOP message */
    tx_event_flags_set(&(client_ptr -> nx_ptp_client_events), NX_PTP_CLIENT_STOP_EVENT, TX_OR);

    /* wait for thread termination */
    while (state != NX_PTP_CLIENT_THREAD_STOPPED)
    {
        tx_thread_sleep(1);
        TX_DISABLE
        state = client_ptr -> nx_ptp_client_thread_state;
        TX_RESTORE
    }

    /* set Idle state */
    TX_DISABLE
    client_ptr -> nx_ptp_client_thread_state = NX_PTP_CLIENT_THREAD_IDLE;
    TX_RESTORE

    /* return Success */
    return(NX_SUCCESS);
}

#ifdef NX_PTP_ENABLE_MASTER
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_master_enable                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function performs error checking for enabling master feature   */
/*    for local PTP clock.                                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    role                                  Role of PTP clock             */
/*                                            SLAVE_ONLY, MASTER_ONLY or  */
/*                                            SLAVE_AND_MASTER            */
/*    priority1                             Priority1 of master clock     */
/*    priority2                             Priority2 of master clock     */
/*    clock_class                           Class of master clock         */
/*    clock_accuracy                        Accuracy of master clock      */
/*    clock_variance                        Variance of master clock      */
/*    steps_removed                         Steps removed of master clock */
/*    time_source                           Time source of master clock   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    Completion status                                                   */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_master_enable          Actual master enable service  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_master_enable(NX_PTP_CLIENT *client_ptr, UCHAR role, UCHAR priority1, UCHAR priority2,
                                   UCHAR clock_class, UCHAR clock_accuracy, USHORT clock_variance,
                                   USHORT steps_removed, UCHAR time_source)
{
    /* Check input parameters.  */
    if (client_ptr == NX_NULL)
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }

    if ((role != NX_PTP_CLIENT_ROLE_MASTER_ONLY) &&
        (role != NX_PTP_CLIENT_ROLE_SLAVE_AND_MASTER))
    {

        /* Return error status.  */
        return(NX_INVALID_PARAMETERS);
    }

    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return(_nx_ptp_client_master_enable(client_ptr, role, priority1, priority2, clock_class,
                                        clock_accuracy, clock_variance, steps_removed, time_source));
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_master_enable                        PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function enables master feature for local PTP clock.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    role                                  Role of PTP clock             */
/*                                            SLAVE_ONLY, MASTER_ONLY or  */
/*                                            SLAVE_AND_MASTER            */
/*    priority1                             Priority1 of master clock     */
/*    priority2                             Priority2 of master clock     */
/*    clock_class                           Class of master clock         */
/*    clock_accuracy                        Accuracy of master clock      */
/*    clock_variance                        Variance of master clock      */
/*    steps_removed                         Steps removed of master clock */
/*    time_source                           Time source of master clock   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    Completion status                                                   */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_master_enable(NX_PTP_CLIENT *client_ptr, UCHAR role, UCHAR priority1, UCHAR priority2,
                                  UCHAR clock_class, UCHAR clock_accuracy, USHORT clock_variance,
                                  USHORT steps_removed, UCHAR time_source)
{

    /* 
     * nx_ptp_master_priority1:                     0 is reserved. Set at 1 for highest priority
     * nx_ptp_master_priority2:                     AS2020: 8.6.2.5 The default value for a PTP Relay Instance should be 247. 
     *                                              The default value for a PTP End Instance should be 248.
     * nx_ptp_master_clock_class:                   AS2020: 8.6.2.2 If the value that reflects the LocalClock and ClockSource entities is 
     *                                              not specified or not known, clockClass is set to 248 
     * nx_ptp_master_clock_accuracy:                User input. 
     *                                              AS2020:8.6.2.3 If the value that reflects the LocalClock and ClockSource entities is 
     *                                              not specified or unknown, clockAccuracy is set to 254 (FE16).
     *                                              1588-2019: 7.6.2.6 clockAccuracy reference Table 5 enumerations 
     * nx_ptp_master_offset_scaled_log_variance:    AS2020:8.6.2.4 If the value that reflects these entities is not specified or not known,
     *                                              offsetScaledLogVariance is set to 17258 (436A16)
     * nx_ptp_master_sequenceId                     Sequence ID for master starts at 0
     */

    client_ptr -> ptp_master.nx_ptp_client_master_address = NX_NULL; /* use client ptr */
    client_ptr -> ptp_master.nx_ptp_client_master_port_identity = client_ptr -> nx_ptp_client_port_identity; /* use client port */
    client_ptr -> ptp_master.nx_ptp_client_master_grandmaster_identity = client_ptr -> nx_ptp_client_port_identity; /* use client identity */

    client_ptr -> ptp_master.nx_ptp_client_master_priority1 = priority1;
    client_ptr -> ptp_master.nx_ptp_client_master_priority2 = priority2;
    client_ptr -> ptp_master.nx_ptp_client_master_clock_class = clock_class;
    client_ptr -> ptp_master.nx_ptp_client_master_clock_accuracy = clock_accuracy;
    client_ptr -> ptp_master.nx_ptp_client_master_offset_scaled_log_variance = clock_variance;
    client_ptr -> ptp_master.nx_ptp_client_master_steps_removed = steps_removed;
    client_ptr -> ptp_master.nx_ptp_client_master_time_source = time_source;
    client_ptr -> ptp_master.nx_ptp_client_master_sequenceId = 0xFFFF;
    client_ptr -> ptp_master.nx_ptp_client_master_sync_sequenceId = 0xFFFF;
    client_ptr -> nx_ptp_client_role = role;

    /* return Success */
    return(NX_SUCCESS);
}
#endif /* NX_PTP_ENABLE_MASTER */

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_time_get                            PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP time get service.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    time_ptr                              Pointer to PTP time           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_time_get               Actual time get service       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_time_get(NX_PTP_CLIENT *client_ptr, NX_PTP_TIME *time_ptr)
{

    /* Check input parameters.  */
    if ((client_ptr == NX_NULL) || (time_ptr == NX_NULL))
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return(_nx_ptp_client_time_get(client_ptr, time_ptr));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_time_get                             PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets the current value of the PTP clock.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    time_ptr                              Pointer to PTP time           */
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
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_time_get(NX_PTP_CLIENT *client_ptr, NX_PTP_TIME *time_ptr)
{

    /* Get the current PTP clock */
    client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_GET,
                                               time_ptr, NX_NULL,
                                               client_ptr -> nx_ptp_client_clock_callback_data);

    /* return Success */
    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_time_set                            PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP time set service.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    time_ptr                              Pointer to PTP time           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_time_set               Actual time set service       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_time_set(NX_PTP_CLIENT *client_ptr, NX_PTP_TIME *time_ptr)
{

    /* Check input parameters.  */
    if ((client_ptr == NX_NULL) || (time_ptr == NX_NULL))
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return(_nx_ptp_client_time_set(client_ptr, time_ptr));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_time_set                             PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the initial time of the PTP clock.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    time_ptr                              Pointer to PTP time           */
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
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_time_set(NX_PTP_CLIENT *client_ptr, NX_PTP_TIME *time_ptr)
{
TX_INTERRUPT_SAVE_AREA
UINT state;

    /* Check if Client is running */
    TX_DISABLE
    state = client_ptr -> nx_ptp_client_thread_state;
    TX_RESTORE

    if (state != NX_PTP_CLIENT_THREAD_IDLE)
    {

        /* Cannot set the clock when the client is running */
        return(NX_PTP_CLIENT_ALREADY_STARTED);
    }

    /* Set the current PTP clock */
    client_ptr -> nx_ptp_client_clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_SET,
                                               time_ptr, NX_NULL,
                                               client_ptr -> nx_ptp_client_clock_callback_data);

    /* return Success */
    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_master_info_get                     PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP master info get service. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    master_ptr                            Pointer to PTP master clock   */
/*    address                               Address of master clock       */
/*    port_identity                         PTP master port and identity  */
/*    port_identity_length                  Length of PTP master port and */
/*                                            identity                    */
/*    priority1                             Priority1 of PTP master clock */
/*    priority2                             Priority2 of PTP master clock */
/*    clock_class                           Class of PTP master clock     */
/*    clock_accuracy                        Accuracy of PTP master clock  */
/*    clock_variance                        Variance of PTP master clock  */
/*    grandmaster_identity                  Identity of grandmaster clock */
/*    grandmaster_identity_length           Length of grandmaster Identity*/
/*    steps_removed                         Steps removed from PTP header */
/*    time_source                           The source of timer used by   */
/*                                            grandmaster clock           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_master_info_get        Actual master info get service*/
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_master_info_get(NX_PTP_CLIENT_MASTER *master_ptr, NXD_ADDRESS *address, UCHAR **port_identity,
                                     UINT *port_identity_length, UCHAR *priority1, UCHAR *priority2, UCHAR *clock_class,
                                     UCHAR *clock_accuracy, USHORT *clock_variance, UCHAR **grandmaster_identity,
                                     UINT *grandmaster_identity_length, USHORT *steps_removed, UCHAR *time_source)
{
    if (master_ptr == NX_NULL)
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    return(_nx_ptp_client_master_info_get(master_ptr, address, port_identity, port_identity_length, priority1,
                                          priority2, clock_class, clock_accuracy, clock_variance, grandmaster_identity,
                                          grandmaster_identity_length, steps_removed, time_source));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_master_info_get                      PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets information of master clock.                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    master_ptr                            Pointer to PTP master clock   */
/*    address                               Address of master clock       */
/*    port_identity                         PTP master port and identity  */
/*    port_identity_length                  Length of PTP master port and */
/*                                            identity                    */
/*    priority1                             Priority1 of PTP master clock */
/*    priority2                             Priority2 of PTP master clock */
/*    clock_class                           Class of PTP master clock     */
/*    clock_accuracy                        Accuracy of PTP master clock  */
/*    clock_variance                        Variance of PTP master clock  */
/*    grandmaster_identity                  Identity of grandmaster clock */
/*    grandmaster_identity_length           Length of grandmaster Identity*/
/*    steps_removed                         Steps removed from PTP header */
/*    time_source                           The source of timer used by   */
/*                                            grandmaster clock           */
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
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_master_info_get(NX_PTP_CLIENT_MASTER *master_ptr, NXD_ADDRESS *address, UCHAR **port_identity,
                                    UINT *port_identity_length, UCHAR *priority1, UCHAR *priority2, UCHAR *clock_class,
                                    UCHAR *clock_accuracy, USHORT *clock_variance, UCHAR **grandmaster_identity,
                                    UINT *grandmaster_identity_length, USHORT *steps_removed, UCHAR *time_source)
{
 
    /* Set master information when the output pointer is provided.  */
    if (address)
    {
        *address = *(master_ptr -> nx_ptp_client_master_address);
    }

    if (port_identity && port_identity_length)
    {
        *port_identity = master_ptr -> nx_ptp_client_master_port_identity;
        *port_identity_length = NX_PTP_CLOCK_PORT_IDENTITY_SIZE;
    }

    if (priority1)
    {
        *priority1 = master_ptr -> nx_ptp_client_master_priority1;
    }

    if (priority2)
    {
        *priority2 = master_ptr -> nx_ptp_client_master_priority2;
    }

    if (clock_class)
    {
        *clock_class = master_ptr -> nx_ptp_client_master_clock_class;
    }

    if (clock_accuracy)
    {
        *clock_accuracy = master_ptr -> nx_ptp_client_master_clock_accuracy;
    }

    if (clock_variance)
    {
        *clock_variance = master_ptr -> nx_ptp_client_master_offset_scaled_log_variance;
    }

    if (grandmaster_identity && grandmaster_identity_length)
    {
        *grandmaster_identity = master_ptr -> nx_ptp_client_master_grandmaster_identity;
        *grandmaster_identity_length = NX_PTP_CLOCK_IDENTITY_SIZE;
    }

    if (steps_removed)
    {
        *steps_removed = master_ptr -> nx_ptp_client_master_steps_removed;
    }

    if (time_source)
    {
        *time_source = master_ptr -> nx_ptp_client_master_time_source;
    }

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_sync_info_get                       PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP Sync get service.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    flags                                 Flags in Sync message         */
/*    utc_offset                            Offset between TAI and UTC    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_sync_info_get          Actual Sync info get service  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_sync_info_get(NX_PTP_CLIENT_SYNC *sync_ptr, USHORT *flags, SHORT *utc_offset)
{
    if (sync_ptr == NX_NULL)
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    return(_nx_ptp_client_sync_info_get(sync_ptr, flags, utc_offset));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_sync_info_get                        PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets information of Sync message.                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    flags                                 Flags in Sync message         */
/*    utc_offset                            Offset between TAI and UTC    */
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
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_sync_info_get(NX_PTP_CLIENT_SYNC *sync_ptr, USHORT *flags, SHORT *utc_offset)
{

    /* Set SYNC information when the output pointer is provided.  */
    if (flags)
    {
        *flags = sync_ptr -> nx_ptp_client_sync_flags;
    }

    if (utc_offset)
    {
        *utc_offset = sync_ptr -> nx_ptp_client_sync_utc_offset;
    }

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_packet_timestamp_notify              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function notifies the PTP packet is transmitted with timestamp.*/
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    packet_ptr                            Pointer to PTP packet         */
/*    timestamp_ptr                         Pointer to timestamp          */
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
/*    Application                                                         */
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
VOID _nx_ptp_client_packet_timestamp_notify(NX_PTP_CLIENT *client_ptr, NX_PACKET *packet_ptr, NX_PTP_TIME *timestamp_ptr)
{
#ifdef NX_ENABLE_GPTP
    /* process t1 send time */
    if (client_ptr &&
        (client_ptr -> nx_ptp_client_pdelay_initiator_state == NX_PTP_CLIENT_PDELAY_WAIT_REQ_TS) &&
        (client_ptr -> nx_ptp_client_pdelay_req_packet_ptr == packet_ptr))
    {

        /* store timestamp */
        client_ptr -> nx_ptp_client_pdelay_req_ts = *timestamp_ptr;

        /* update state */
        client_ptr -> nx_ptp_client_pdelay_initiator_state = NX_PTP_CLIENT_PDELAY_WAIT_RESP;
    }
    
    /* process t3 response time */
    if (client_ptr &&
        (client_ptr -> nx_ptp_client_pdelay_resp_packet_ptr == packet_ptr))
    {

        /* store timestamp */
        client_ptr -> nx_ptp_client_pdelay_resp_origin = *timestamp_ptr;
        
         /* set timer event */
        tx_event_flags_set(&(client_ptr -> nx_ptp_client_events), NX_PTP_CLIENT_PDELAY_FOLLOW_EVENT, TX_OR);
        
        client_ptr -> nx_ptp_client_pdelay_resp_packet_ptr = NX_NULL;
    }

    
    
#endif /* NX_ENABLE_GPTP */

    /* get timestamp of previous delay_req message */
    if (client_ptr &&
        (client_ptr -> nx_ptp_client_delay_state == NX_PTP_CLIENT_DELAY_WAIT_REQ_TS) &&
        (client_ptr -> nx_ptp_client_delay_req_packet_ptr == packet_ptr))
    {

        /* store timestamp */
        client_ptr -> nx_ptp_client_delay_ts = *timestamp_ptr;

        /* update state */
        client_ptr -> nx_ptp_client_delay_state = NX_PTP_CLIENT_DELAY_WAIT_RESP;
    }

#if defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC)
    /* get timestamp of previous sync message */
    if (client_ptr && (client_ptr -> nx_ptp_client_sync_packet_ptr == packet_ptr))
    {

        client_ptr -> nx_ptp_client_sync_packet_ptr = NX_NULL;

        /* store timestamp */
        client_ptr -> nx_ptp_client_sync_ts_local = *timestamp_ptr;

         /* set follow up event */
        tx_event_flags_set(&(client_ptr -> nx_ptp_client_events), NX_PTP_CLIENT_SYNC_FOLLOW_EVENT, TX_OR);
    }
#endif /* defined(NX_PTP_ENABLE_MASTER) || defined(NX_PTP_ENABLE_REVERSE_SYNC) */
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_soft_clock_callback                  PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function implements soft PTP clock.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    client_ptr                            Pointer to PTP client         */
/*    operation                             PTP clock operation           */
/*    time_ptr                              Pointer to timestamp          */
/*    packet_ptr                            Pointer to PTP packet         */
/*    callback_data                         Pointer to callback data      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_soft_clock_adjust      Adjust soft PTP clock         */
/*    _nx_ptp_client_utility_inc64          Increment a 64-bit number     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    PTP internal                                                        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_soft_clock_callback(NX_PTP_CLIENT *client_ptr, UINT operation,
                                        NX_PTP_TIME *time_ptr, NX_PACKET *packet_ptr,
                                        VOID *callback_data)
{
TX_INTERRUPT_SAVE_AREA

    NX_PARAMETER_NOT_USED(callback_data);

    switch (operation)
    {

    /* Nothing to do for soft initialization.  */
    case NX_PTP_CLIENT_CLOCK_INIT:
        break;

    /* Set clock.  */
    case NX_PTP_CLIENT_CLOCK_SET:
        TX_DISABLE
        client_ptr -> nx_ptp_client_soft_clock = *time_ptr;
        TX_RESTORE
        break;

    /* Extract timestamp from packet.
       For soft implementation, simply fallthrough and return current timestamp.  */
    case NX_PTP_CLIENT_CLOCK_PACKET_TS_EXTRACT:

    /* Get clock.  */
    case NX_PTP_CLIENT_CLOCK_GET:
        TX_DISABLE
        *time_ptr = client_ptr -> nx_ptp_client_soft_clock;
        TX_RESTORE
        break;

    /* Adjust clock.  */
    case NX_PTP_CLIENT_CLOCK_ADJUST:
        _nx_ptp_client_soft_clock_adjust(client_ptr, time_ptr -> nanosecond);
        break;

    /* Prepare timestamp for current packet.
       For soft implementation, simply notify current timestamp.  */
    case NX_PTP_CLIENT_CLOCK_PACKET_TS_PREPARE:
        _nx_ptp_client_packet_timestamp_notify(client_ptr, packet_ptr, &(client_ptr -> nx_ptp_client_soft_clock));
        break;

    /* Update soft timer.  */
    case NX_PTP_CLIENT_CLOCK_SOFT_TIMER_UPDATE:
        TX_DISABLE

        /* increment the nanosecond field of the software clock */
        time_ptr -> nanosecond +=
            (LONG)(NX_PTP_NANOSECONDS_PER_SEC / NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND);

        /* update the second field */
        if (time_ptr -> nanosecond >= NX_PTP_NANOSECONDS_PER_SEC)
        {
            time_ptr -> nanosecond -= NX_PTP_NANOSECONDS_PER_SEC;
            _nx_ptp_client_utility_inc64(&(time_ptr -> second_high),
                                         &(time_ptr -> second_low));
        }
        TX_RESTORE
        break;

    default:
        return(NX_PTP_PARAM_ERROR);
    }

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_utility_time_diff                   PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP time difference service. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    time1_ptr                             Pointer to first PTP time     */
/*    time2_ptr                             Pointer to second PTP time    */
/*    result_ptr                            Pointer to result time1-time2 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_utility_time_diff      Actual time difference service*/
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_utility_time_diff(NX_PTP_TIME *time1_ptr, NX_PTP_TIME *time2_ptr, NX_PTP_TIME *result_ptr)
{

    /* Check input parameters.  */
    if ((time1_ptr == NX_NULL) || (time2_ptr == NX_NULL) || (result_ptr == NX_NULL))
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return(_nx_ptp_client_utility_time_diff(time1_ptr, time2_ptr, result_ptr));
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_utility_time_sum                    PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP time sum service.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    time1_ptr                             Pointer to first PTP time     */
/*    time2_ptr                             Pointer to second PTP time    */
/*    result_ptr                            Pointer to result time1+time2 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_utility_time_sum       Actual time sum service       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_utility_time_sum(NX_PTP_TIME *time1_ptr, NX_PTP_TIME *time2_ptr, NX_PTP_TIME *result_ptr)
{

    /* Check input parameters.  */
    if ((time1_ptr == NX_NULL) || (time2_ptr == NX_NULL) || (result_ptr == NX_NULL))
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return(_nx_ptp_client_utility_time_sum(time1_ptr, time2_ptr, result_ptr));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_utility_time_diff                    PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function computes the difference between two PTP times.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    time1_ptr                             Pointer to first PTP time     */
/*    time2_ptr                             Pointer to second PTP time    */
/*    result_ptr                            Pointer to result time1-time2 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_utility_sub64          Subtracts two 64-bit numbers  */
/*    _nx_ptp_client_utility_dec64          Decrement a 64-bit number     */
/*    _nx_ptp_client_utility_inc64          Increment a 64-bit number     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*    _nx_ptp_client_delay_resp_received    Process delay response        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_utility_time_diff(NX_PTP_TIME *time1_ptr, NX_PTP_TIME *time2_ptr, NX_PTP_TIME *result_ptr)
{
LONG  sec_hi;
ULONG sec_lo;
LONG  ns;

    /* compute difference of seconds */
    sec_hi = time1_ptr -> second_high;
    sec_lo = time1_ptr -> second_low;
    _nx_ptp_client_utility_sub64(&sec_hi, &sec_lo, time2_ptr -> second_high,
                                 time2_ptr -> second_low);

    /* compute difference of nanoseconds */
    /* note: this cannot overflow as nanosecond field is in range +/-0-999999999 */
    ns = time1_ptr -> nanosecond - time2_ptr -> nanosecond;

    /* keep nanoseconds in range +/-0-999999999 */
    if (ns <= -NX_PTP_NANOSECONDS_PER_SEC)
    {
        ns += NX_PTP_NANOSECONDS_PER_SEC;
        _nx_ptp_client_utility_dec64(&sec_hi, &sec_lo);
    }
    else if (ns >= NX_PTP_NANOSECONDS_PER_SEC)
    {
        ns -= NX_PTP_NANOSECONDS_PER_SEC;
        _nx_ptp_client_utility_inc64(&sec_hi, &sec_lo);
    }

    /* ensure the nanoseconds field has same sign as seconds field */
    if ((sec_hi >= 0) && ((sec_hi != 0) || (sec_lo != 0)))
    {
        /* positive number of seconds */
        if (ns < 0)
        {
            ns += NX_PTP_NANOSECONDS_PER_SEC;
            _nx_ptp_client_utility_dec64(&sec_hi, &sec_lo);
        }
    }
    else if (sec_hi < 0)
    {
        /* negative number of seconds */
        if (ns > 0)
        {
            ns -= NX_PTP_NANOSECONDS_PER_SEC;
            _nx_ptp_client_utility_inc64(&sec_hi, &sec_lo);
        }
    }

    /* return result time */
    result_ptr -> second_high = sec_hi;
    result_ptr -> second_low  = sec_lo;
    result_ptr -> nanosecond  = ns;

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_utility_time_sum                    PORTABLE C       */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tiejun Zhou, Microsoft Corporation                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function computes the sum of two PTP times.                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    time1_ptr                             Pointer to first PTP time     */
/*    time2_ptr                             Pointer to second PTP time    */
/*    result_ptr                            Pointer to result time1+time2 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_utility_add64          Adds two 64-bit numbers       */
/*    _nx_ptp_client_utility_dec64          Decrement a 64-bit number     */
/*    _nx_ptp_client_utility_inc64          Increment a 64-bit number     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*    _nx_ptp_client_pdelay_resp_received   Process pdelay response       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Tiejun Zhou              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_utility_time_sum(NX_PTP_TIME *time1_ptr, NX_PTP_TIME *time2_ptr, NX_PTP_TIME *result_ptr)
{
LONG  sec_hi;
ULONG sec_lo;
LONG  ns;

    /* compute sum of seconds */
    sec_hi = time1_ptr -> second_high;
    sec_lo = time1_ptr -> second_low;
    _nx_ptp_client_utility_add64(&sec_hi, &sec_lo, time2_ptr -> second_high,
                                 time2_ptr -> second_low);

    /* compute sum of nanoseconds */
    /* note: this cannot overflow as nanosecond field is in range +/-0-999999999 */
    ns = time1_ptr -> nanosecond + time2_ptr -> nanosecond;

    /* keep nanoseconds in range +/-0-999999999 */
    if (ns <= -NX_PTP_NANOSECONDS_PER_SEC)
    {
        ns += NX_PTP_NANOSECONDS_PER_SEC;
        _nx_ptp_client_utility_dec64(&sec_hi, &sec_lo);
    }
    else if (ns >= NX_PTP_NANOSECONDS_PER_SEC)
    {
        ns -= NX_PTP_NANOSECONDS_PER_SEC;
        _nx_ptp_client_utility_inc64(&sec_hi, &sec_lo);
    }

    /* ensure the nanoseconds field has same sign as seconds field */
    if ((sec_hi >= 0) && ((sec_hi != 0) || (sec_lo != 0)))
    {
        /* positive number of seconds */
        if (ns < 0)
        {
            ns += NX_PTP_NANOSECONDS_PER_SEC;
            _nx_ptp_client_utility_dec64(&sec_hi, &sec_lo);
        }
    }
    else if (sec_hi < 0)
    {
        /* negative number of seconds */
        if (ns > 0)
        {
            ns -= NX_PTP_NANOSECONDS_PER_SEC;
            _nx_ptp_client_utility_inc64(&sec_hi, &sec_lo);
        }
    }

    /* return result time */
    result_ptr -> second_high = sec_hi;
    result_ptr -> second_low  = sec_lo;
    result_ptr -> nanosecond  = ns;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_ptp_client_utility_convert_time_to_date        PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for errors on the PTP time conversion service. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    time_ptr                              Pointer to PTP time           */
/*    offset                                signed second offset to add   */
/*                                          the PTP time                  */
/*    date_time_ptr                         Pointer to resulting date     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_utility_convert_time_to_date                         */
/*                                          Actual time conversion service*/
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nxe_ptp_client_utility_convert_time_to_date(NX_PTP_TIME *time_ptr, LONG offset, NX_PTP_DATE_TIME *date_time_ptr)
{

    /* Check input parameters.  */
    if ((time_ptr == NX_NULL) || (date_time_ptr == NX_NULL))
    {

        /* Return error status.  */
        return(NX_PTR_ERROR);
    }
    
    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    /* Call the actual function.  */
    return(_nx_ptp_client_utility_convert_time_to_date(time_ptr, offset, date_time_ptr));
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_utility_convert_time_to_date         PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function converts a PTP time to a UTC date and time.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    time_ptr                              Pointer to PTP time           */
/*    offset                                Signed second offset to add   */
/*                                          the PTP time                  */
/*    date_time_ptr                         Pointer to resulting date     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_utility_add64          Add two 64-bit number         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
UINT _nx_ptp_client_utility_convert_time_to_date(NX_PTP_TIME *time_ptr, LONG offset, NX_PTP_DATE_TIME *date_time_ptr)
{
#define IS_LEAP(y)      (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))
#define SECS_PER_MINUTE 60
#define SECS_PER_HOUR   (60 * SECS_PER_MINUTE)
#define SECS_PER_DAY    (24 * SECS_PER_HOUR)
LONG  secs_high;
ULONG secs_low;
UINT  year, month, day, hour, minute;
ULONG secs_per_year, secs_per_month;
ULONG weekday;
UINT  is_leap;

    /* get number of seconds */
    secs_high = time_ptr -> second_high;
    secs_low  = time_ptr -> second_low;

    /* add local time offset */
    if (offset != 0)
    {
        _nx_ptp_client_utility_add64(&secs_high, &secs_low, offset < 0 ? -1 : 0, (ULONG)offset);
    }
    if (secs_high < 0)
    {

        /* invalid negative time */
        return(NX_PTP_PARAM_ERROR);
    }

    /* determine the current year from Epoch (January 1, 1970) */
    year = 1970;
    secs_per_year = 365 * SECS_PER_DAY;
    is_leap = 0;
    weekday = 4;  /* thursday */
    while ((secs_high > 0) || (secs_low >= secs_per_year))
    {
        if (secs_low < secs_per_year)
        {
            secs_high--;
        }
        secs_low -= secs_per_year;
        weekday += is_leap ? 366 : 365;
        year++;
        is_leap = IS_LEAP(year) ? 1 : 0;
        secs_per_year = is_leap ? 366 * SECS_PER_DAY : 365 * SECS_PER_DAY;
    }
    /* compute day of the week from remaining seconds */
    weekday = (weekday + secs_low / SECS_PER_DAY) % 7;

    /* determine current month */
    month = 1;
    secs_per_month = 31 * SECS_PER_DAY;
    while (secs_low >= secs_per_month)
    {
        secs_low -= secs_per_month;
        month++;
        if (month == 2)
        {

            /* february */
            secs_per_month = is_leap ? 29 * SECS_PER_DAY : 28 * SECS_PER_DAY;
        }
        else if ((month == 4) || (month == 6) || (month == 9) || (month == 11))
        {

            /* april, june, september, november */
            secs_per_month = 30 * SECS_PER_DAY;
        }
        else
        {

            /* the other months */
            secs_per_month = 31 * SECS_PER_DAY;
        }
    }

    /* determine current day of the month */
    day = secs_low / SECS_PER_DAY;
    secs_low -= day * SECS_PER_DAY;

    /* determine current hour */
    hour = secs_low / SECS_PER_HOUR;
    secs_low -= hour * SECS_PER_HOUR;

    /* determine current minute */
    minute = secs_low / SECS_PER_MINUTE;
    secs_low -= minute * SECS_PER_MINUTE;

    /* return date */
    date_time_ptr -> year         = year;
    date_time_ptr -> month        = (UCHAR)month;
    date_time_ptr -> day          = (UCHAR)(day + 1);
    date_time_ptr -> hour         = (UCHAR)hour;
    date_time_ptr -> minute       = (UCHAR)minute;
    date_time_ptr -> second       = (UCHAR)secs_low;
    date_time_ptr -> weekday      = (UCHAR)weekday;
    date_time_ptr -> nanosecond   = (ULONG)time_ptr -> nanosecond;

    return(NX_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_utility_add64                        PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function adds two 64-bit numbers: A = A + B.                   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    a_hi                                  Pointer to higher 32-bit of A */
/*    a_lo                                  Pointer to lower 32-bit of A  */
/*    b_hi                                  higher 32-bit of B            */
/*    b_lo                                  lower 32-bit of B             */
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
/*    _nx_ptp_client_clock_adjust           Adjust PTP clock              */
/*    _nx_ptp_client_utility_convert_time_to_date                         */
/*                                          Convert time to date          */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
VOID _nx_ptp_client_utility_add64(LONG *a_hi, ULONG *a_lo, LONG b_hi, ULONG b_lo)
{
LONG  r_hi;
ULONG r_lo;

    r_hi = *a_hi + b_hi;
    r_lo = *a_lo + b_lo;
    if ((r_lo < *a_lo) || (r_lo < b_lo))
    {
        r_hi++;     /* add carry */
    }
    *a_hi = r_hi;
    *a_lo = r_lo;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_utility_sub64                        PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function substracts two 64-bit numbers: A = A - B.             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    a_hi                                  Pointer to higher 32-bit of A */
/*    a_lo                                  Pointer to lower 32-bit of A  */
/*    b_hi                                  higher 32-bit of B            */
/*    b_lo                                  lower 32-bit of B             */
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
/*    _nx_ptp_client_utility_time_diff      Diff two PTP times            */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
VOID _nx_ptp_client_utility_sub64(LONG *a_hi, ULONG *a_lo, LONG b_hi, ULONG b_lo)
{
LONG  r_hi;
ULONG r_lo;

    r_hi = *a_hi - b_hi;
    r_lo = *a_lo - b_lo;
    if (*a_lo < b_lo)
    {
        r_hi--;     /* subtract carry */
    }
    *a_hi = r_hi;
    *a_lo = r_lo;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_utility_inc64                        PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function increments a 64-bit number: A = A + 1.                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    a_hi                                  Pointer to higher 32-bit of A */
/*    a_lo                                  Pointer to lower 32-bit of A  */
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
/*    _nx_ptp_client_soft_clock_adjust      Adjust soft PTP clock         */
/*    _nx_ptp_client_clock_adjust           Adjust PTP clock              */
/*    _nx_ptp_client_utility_time_diff      Diff two PTP times            */
/*    _nx_ptp_client_soft_clock_callback    Soft PTP clock                */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
VOID _nx_ptp_client_utility_inc64(LONG *a_hi, ULONG *a_lo)
{
ULONG r_lo;

    r_lo = *a_lo + 1;
    if (r_lo == 0)
    {
        *a_hi = *a_hi + 1;      /* add carry */
    }
    *a_lo = r_lo;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_utility_dec64                        PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function decrements a 64-bit number: A = A - 1.                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    a_hi                                  Pointer to higher 32-bit of A */
/*    a_lo                                  Pointer to lower 32-bit of A  */
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
/*    _nx_ptp_client_soft_clock_adjust      Adjust soft PTP clock         */
/*    _nx_ptp_client_clock_adjust           Adjust PTP clock              */
/*    _nx_ptp_client_utility_time_diff      Diff two PTP times            */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
VOID _nx_ptp_client_utility_dec64(LONG *a_hi, ULONG *a_lo)
{
ULONG r_lo;

    r_lo = *a_lo;
    if (r_lo == 0)
    {
        *a_hi = *a_hi - 1;      /* subtract carry */
    }
    *a_lo = r_lo - 1;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_utility_neg64                        PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function changes the sign of a 64-bit number: A = -A.          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    a_hi                                  Pointer to higher 32-bit of A */
/*    a_lo                                  Pointer to lower 32-bit of A  */
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
/*    _nx_ptp_client_utility_time_div_by_2  Divide a PTP time by 2        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
VOID _nx_ptp_client_utility_neg64(LONG *a_hi, ULONG *a_lo)
{
LONG r_hi;

    r_hi = -*a_hi;
    if (*a_lo != 0)
    {
        r_hi--;     /* subtract carry */
    }
    *a_hi = r_hi;
    *a_lo = -*a_lo;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ptp_client_utility_time_div_by_2                PORTABLE C      */
/*                                                           6.1.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function divides a PTP time by 2.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    time_ptr                          Pointer to PTP time               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ptp_client_utility_neg64          Change the sign of number     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ptp_client_delay_resp_received    Process delay response        */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2020     Yuxin Zhou               Initial Version 6.1.3         */
/*                                                                        */
/**************************************************************************/
VOID _nx_ptp_client_utility_time_div_by_2(NX_PTP_TIME *time_ptr)
{
UINT  neg;
LONG  sec_hi;
ULONG sec_lo;
LONG  ns;

    /* get current time value */
    sec_hi = time_ptr -> second_high;
    sec_lo = time_ptr -> second_low;
    ns     = time_ptr -> nanosecond;

    /* implement division on unsigned values */
    if ((sec_hi < 0) || (ns < 0))
    {
        _nx_ptp_client_utility_neg64(&sec_hi, &sec_lo);
        ns = -ns;
        neg = 1;
    }
    else
    {
        neg = 0;
    }

    /* divide nanoseconds by two */
    ns >>= 1;
    if (sec_lo & 1)
    {

        /* add rest of seconds division */
        ns += 500000000L;
    }

    /* divide seconds by two */
    sec_lo >>= 1;
    if (sec_hi & 1)
    {
        sec_lo |= 0x80000000UL;
    }
    sec_hi >>= 1;

    /* restore sign */
    if (neg)
    {
        _nx_ptp_client_utility_neg64(&sec_hi, &sec_lo);
        ns = -ns;
    }

    /* return result */
    time_ptr -> second_high = sec_hi;
    time_ptr -> second_low  = sec_lo;
    time_ptr -> nanosecond  = ns;
}
