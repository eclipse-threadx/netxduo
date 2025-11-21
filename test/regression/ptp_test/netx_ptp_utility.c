
#include "netx_ptp_utility.h"

#define NANOSECONDS_PER_SEC             1000000000L

extern VOID _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/*
Precision Time Protocol (IEEE1588)
    0000 .... = transportSpecific: 0x0
    .... 1011 = messageId: Announce Message (0xb)
    0000 .... = Reserved: 0
    .... 0010 = versionPTP: 2
    messageLength: 64
    subdomainNumber: 0
    Reserved: 0
    flags: 0x0000
    correction: 0.000000 nanoseconds
    Reserved: 0
    ClockIdentity: 0x46e7c8fffe7161a1
    SourcePortID: 1
    sequenceId: 61
    control: Other Message (5)
    logMessagePeriod: 1
    originTimestamp (seconds): 0
    originTimestamp (nanoseconds): 0
    originCurrentUTCOffset: 0
    priority1: 128
    grandmasterClockClass: 127
    grandmasterClockAccuracy: Accuracy Unknown (0xfe)
    grandmasterClockVariance: 28768
    priority2: 128
    grandmasterClockIdentity: 0x46e7c8fffe7161a1
    localStepsRemoved: 0
    TimeSource: INTERNAL_OSCILLATOR (0xa0)
*/
static UCHAR announce_data[] = \
"\x0b\x02\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x46\xe7\xc8\xff\xfe\x71\x61\xa1\x00\x01\x00\x3d" \
"\x05\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x22\x80" \
"\x7f\xfe\x70\x60\x80\x46\xe7\xc8\xff\xfe\x71\x61\xa1\x00\x00\xa0";

/*
Precision Time Protocol (IEEE1588)
    0000 .... = transportSpecific: 0x0
    .... 0000 = messageId: Sync Message (0x0)
    0000 .... = Reserved: 0
    .... 0010 = versionPTP: 2
    messageLength: 44
    subdomainNumber: 0
    Reserved: 0
    flags: 0x0200
    correction: 0.000000 nanoseconds
    Reserved: 0
    ClockIdentity: 0x46e7c8fffe7161a1
    SourcePortID: 1
    sequenceId: 123
    control: Sync Message (0)
    logMessagePeriod: 0
    originTimestamp (seconds): 1603784044
    originTimestamp (nanoseconds): 604899854
*/
static UCHAR sync_data[] = \
"\x00\x02\x00\x2c\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x46\xe7\xc8\xff\xfe\x71\x61\xa1\x00\x01\x00\x7b" \
"\x00\x00\x00\x00\x5f\x97\xcd\x6c\x24\x0e\x0a\x0e";

/*
Precision Time Protocol (IEEE1588)
    0000 .... = transportSpecific: 0x0
    .... 1000 = messageId: Follow_Up Message (0x8)
    0000 .... = Reserved: 0
    .... 0010 = versionPTP: 2
    messageLength: 44
    subdomainNumber: 0
    Reserved: 0
    flags: 0x0400
    correction: 0.000000 nanoseconds
    Reserved: 0
    ClockIdentity: 0x46e7c8fffe7161a1
    SourcePortID: 1
    sequenceId: 123
    control: Follow_Up Message (2)
    logMessagePeriod: 0
    preciseOriginTimestamp (seconds): 1603784044
    preciseOriginTimestamp (nanoseconds): 604908000
*/
static UCHAR follow_up_data[] = \
"\x08\x02\x00\x2c\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x46\xe7\xc8\xff\xfe\x71\x61\xa1\x00\x01\x00\x7b" \
"\x02\x00\x00\x00\x5f\x97\xcd\x6c\x24\x0e\x29\xe0";

/*
Precision Time Protocol (IEEE1588)
    0000 .... = transportSpecific: 0x0
    .... 1001 = messageId: Delay_Resp Message (0x9)
    0000 .... = Reserved: 0
    .... 0010 = versionPTP: 2
    messageLength: 54
    subdomainNumber: 0
    Reserved: 0
    flags: 0x0000
    correction: 0.000000 nanoseconds
    Reserved: 0
    ClockIdentity: 0x46e7c8fffe7161a1
    SourcePortID: 1
    sequenceId: 1
    control: Delay_Resp Message (3)
    logMessagePeriod: 0
    receiveTimestamp (seconds): 1603784044
    receiveTimestamp (nanoseconds): 613726000
    requestingSourcePortIdentity: 0x001122fffe334457
    requestingSourcePortId: 1
*/
static UCHAR delay_resp_data[] = \
"\x09\x02\x00\x36\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x46\xe7\xc8\xff\xfe\x71\x61\xa1\x00\x01\x00\x01" \
"\x03\x00\x00\x00\x5f\x97\xcd\x6c\x24\x94\xb7\x30\x00\x11\x22\xff" \
"\xfe\x33\x44\x57\x00\x01";

static UCHAR use_two_steps = NX_TRUE;
static NX_PTP_CLIENT *ptp_client_ptr = NX_NULL;
static NX_PTP_TIME ptp_timestamp = {0};
static UCHAR use_ipv4 = NX_TRUE;

static VOID send_udp_data(NX_UDP_SOCKET *socket_ptr, NX_PACKET_POOL *pool_ptr,
                          UINT port, UCHAR *data, UINT size)
{
NX_PACKET *packet_ptr;
UINT status;
#ifndef NX_DISABLE_IPV6
NXD_ADDRESS ipv6_addr;
#endif

    /* Allocate a packet.  */
    status =  nx_packet_allocate(pool_ptr, &packet_ptr, NX_UDP_PACKET, NX_NO_WAIT);
    ASSERT_SUCCESS(status);

    /* Append announce data.  */
    status = nx_packet_data_append(packet_ptr, data, size, pool_ptr, NX_NO_WAIT);
    ASSERT_SUCCESS(status);

    /* Send out the packet.  */
    if (use_ipv4)
    {
        status = nx_udp_socket_send(socket_ptr, packet_ptr, PTP_IPV4_MULTICAST_ADDR, port);
    }
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    else
    {
        PTP_IPV6_MULTICAST_ADDR_SET(&ipv6_addr);
        status = nxd_udp_socket_send(socket_ptr, packet_ptr, &ipv6_addr, port);
    }
#endif
    
    ASSERT_SUCCESS(status);
}

static VOID fill_timestamp(UCHAR *buffer, NX_PTP_TIME *ts)
{
    buffer[0] = (ts -> second_high >> 8) & 0xFF;
    buffer[1] = ts -> second_high & 0xFF;
    buffer[2] = (ts -> second_low >> 24) & 0xFF;
    buffer[3] = (ts -> second_low >> 16) & 0xFF;
    buffer[4] = (ts -> second_low >> 8) & 0xFF;
    buffer[5] = ts -> second_low & 0xFF;
    buffer[6] = (ts -> nanosecond >> 24) & 0xFF;
    buffer[7] = (ts -> nanosecond >> 16) & 0xFF;
    buffer[8] = (ts -> nanosecond >> 8) & 0xFF;
    buffer[9] = ts -> nanosecond & 0xFF;
}

VOID create_socket(NX_IP *ip_ptr, NX_UDP_SOCKET *socket_ptr, UINT port)
{
UINT status;
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_ADDRESS ipv6_addr;
#endif

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(ip_ptr, socket_ptr, "UDP Socket", NX_IP_NORMAL,
                                  NX_FRAGMENT_OKAY, 0x80, 5);
    ASSERT_SUCCESS(status);

    /* Bind the UDP socket to the IP port.  */
    status = nx_udp_socket_bind(socket_ptr, port, NX_NO_WAIT);
    ASSERT_SUCCESS(status);

    /* Join multicast group.  */
    status = nx_ipv4_multicast_interface_join(ip_ptr, PTP_IPV4_MULTICAST_ADDR, 0);
    ASSERT_SUCCESS(status);

#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    PTP_IPV6_MULTICAST_ADDR_SET(&ipv6_addr);
    status = nxd_ipv6_multicast_interface_join(ip_ptr, &ipv6_addr, 0);
    ASSERT_SUCCESS(status);
#endif
}

VOID send_announce(NX_UDP_SOCKET *socket_ptr, NX_PACKET_POOL *pool_ptr, USHORT utc_offset)
{

    /* Adjust utc offset.  */
    NX_CHANGE_USHORT_ENDIAN(utc_offset);
    memcpy(&announce_data[44], &utc_offset, sizeof(utc_offset));

    /* Send out announce packet.  */
    send_udp_data(socket_ptr, pool_ptr, PTP_GENERAL_UDP_PORT,
                  announce_data, sizeof(announce_data));
}

VOID send_sync(NX_UDP_SOCKET *socket_ptr, NX_PACKET_POOL *pool_ptr, NX_PTP_TIME *ts)
{
    if (use_two_steps)
    {
        sync_data[6] |= 0x2;
    }
    else
    {
        sync_data[6] &= 0xFD;
    }
    

    /* Adjust timestamp. */
    fill_timestamp(&sync_data[34], ts);

    /* Send out sync packet.  */
    send_udp_data(socket_ptr, pool_ptr, PTP_EVENT_UDP_PORT,
                  sync_data, sizeof(sync_data));
}

VOID send_follow_up(NX_UDP_SOCKET *socket_ptr, NX_PACKET_POOL *pool_ptr, NX_PTP_TIME *ts)
{

    /* Adjust timestamp. */
    fill_timestamp(&follow_up_data[34], ts);

    /* Send out follow up packet.  */
    send_udp_data(socket_ptr, pool_ptr, PTP_GENERAL_UDP_PORT,
                  follow_up_data, sizeof(follow_up_data));
}

VOID send_delay_response(NX_UDP_SOCKET *socket_ptr, NX_PACKET_POOL *pool_ptr,
                         DELAY_REQUEST_CONTEXT *context, NX_PTP_TIME *ts)
{

    /* Adjust timestamp. */
    fill_timestamp(&delay_resp_data[34], ts);

    /* Adjust clock ID and sequence ID.  */
    memcpy(&delay_resp_data[30], context -> sequence_id, 2);

    memcpy(&delay_resp_data[sizeof(delay_resp_data) - 11], context -> clock_id,
           NX_PTP_CLOCK_PORT_IDENTITY_SIZE);

    /* Send out delay resp packet.  */
    send_udp_data(socket_ptr, pool_ptr, PTP_GENERAL_UDP_PORT,
                  delay_resp_data, sizeof(delay_resp_data));
}

UINT receive_delay_request(NX_UDP_SOCKET *socket_ptr, DELAY_REQUEST_CONTEXT *context,
                           UINT wait_option)
{
NX_PACKET *packet_ptr;
NXD_ADDRESS ip_address;
ULONG bytes_copied;
UINT port;
UINT status;


    status = nx_udp_socket_receive(socket_ptr, &packet_ptr, wait_option);
    if (status)
    {
        return(status);
    }

    status = nxd_udp_source_extract(packet_ptr, &ip_address, &port);
    ASSERT_SUCCESS(status);
    ASSERT_TRUE(port == PTP_EVENT_UDP_PORT);

    status = nx_packet_data_extract_offset(packet_ptr, 20, context -> clock_id,
                                           NX_PTP_CLOCK_PORT_IDENTITY_SIZE,
                                           &bytes_copied);
    ASSERT_SUCCESS(status);
    ASSERT_TRUE(bytes_copied == NX_PTP_CLOCK_PORT_IDENTITY_SIZE);

    status = nx_packet_data_extract_offset(packet_ptr, 30, context -> sequence_id,
                                           2, &bytes_copied);
    ASSERT_SUCCESS(status);
    ASSERT_TRUE(bytes_copied == 2);

    return(NX_SUCCESS);
}


VOID set_two_steps(UCHAR two_steps)
{
    use_two_steps = two_steps;
}


VOID set_clock_id(UCHAR *clock_id)
{

    /* Adjust clock ID.  */
    memcpy(&announce_data[20], clock_id, NX_PTP_CLOCK_PORT_IDENTITY_SIZE);
    memcpy(&sync_data[20], clock_id, NX_PTP_CLOCK_PORT_IDENTITY_SIZE);
    memcpy(&follow_up_data[20], clock_id, NX_PTP_CLOCK_PORT_IDENTITY_SIZE);
    memcpy(&delay_resp_data[20], clock_id, NX_PTP_CLOCK_PORT_IDENTITY_SIZE);
}


VOID set_ip_version(UCHAR ip_version)
{
    if (ip_version == NX_IP_VERSION_V4)
    {
        use_ipv4 = NX_TRUE;
    }
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    else
    {
        use_ipv4 = NX_FALSE;
    }    
#endif
}


VOID calibrate_timestamp(TEST_TIMESTAMP *test_ts, NX_PTP_TIME *ts)
{
ULONG64 second_low;
ULONG64 carry;
long long nanosecond;
NX_PTP_TIME *t1;

    /* Means of following symbols,
         t1 is timestamp of Sync if two step is disabled,
            or else, it is timestamp of FollowUp.
         t2 is timestamp of Sync received.
         t3 is timestamp of DelayRequest sent. Also equals client_clock in the test
         t4 is timestamp of DelayRequest in DelayResponse packet.
         
       meanPathDelay between client and server is,
         [(t2-t1)+(t4-t3)]/2

       offsetFromMaster = client_clock - master_clock
                        = t2 - t1 - meanPathDelay - correctionField

        master_clock = [(t4+t3)-(t2-t1)]/2

        Note, The recommendation that the timestamps themselves be
        the best possible estimate of the time enables simple devices
        that only need approximate time to ignore the correctionField.
    */

    if ((test_ts -> follow_up.second_high == 0) && 
        (test_ts -> follow_up.second_low == 0) && 
        (test_ts -> follow_up.nanosecond == 0))
    {

        /* No FollowUp timestamp. Use Sync timestamp.  */
        t1 = &test_ts -> sync;
    }
    else
    {

        /* Use FollowUp timestamp.  */
        t1 = &test_ts -> follow_up;
    }

    ts -> second_high = (test_ts -> delay_response.second_high + test_ts -> delay_request.second_high) -
                        (test_ts -> sync_received.second_high - t1 -> second_high);
    if (ts -> second_high & 1)
    {
        carry = 0x100000000;
    }
    else
    {
        carry = 0;
    }
    ts -> second_high /= 2;
    
    second_low = carry + ((ULONG64)test_ts -> delay_response.second_low + (ULONG64)test_ts -> delay_request.second_low) -
                 ((ULONG64)test_ts -> sync_received.second_low - (ULONG64)t1 -> second_low);
    if (second_low & 1)
    {
        carry = NANOSECONDS_PER_SEC;
    }
    else
    {
        carry = 0;
    }
    second_low /= 2;
    
    nanosecond = (carry + ((long long)test_ts -> delay_response.nanosecond + (long long)test_ts -> delay_request.nanosecond) -
                  ((long long)test_ts -> sync_received.nanosecond - (long long)t1 -> nanosecond)) / 2;

    /* Adjust according to carry. */
    while (nanosecond >= NANOSECONDS_PER_SEC)
    {
        nanosecond -= NANOSECONDS_PER_SEC;
        second_low++;
    }

    if (nanosecond < 0)
    {
        nanosecond += NANOSECONDS_PER_SEC;
        if (second_low == 0)
        {
            ts -> second_high--;
            second_low = 0xFFFFFFFF;
        }
        else
        {
            second_low--;
        }
        
    }

    while (second_low > 0xFFFFFFFF)
    {
        second_low -= 0xFFFFFFFF;
        ts -> second_high++;
    }

    ts -> second_low = (ULONG)second_low;
    ts -> nanosecond = (LONG)nanosecond;
}

VOID _netx_ptp_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req)
{
NX_PACKET *packet_ptr;

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    if (driver_req -> nx_ip_driver_command == NX_LINK_PACKET_SEND)
    {
        packet_ptr = driver_req -> nx_ip_driver_packet;
        if (packet_ptr -> nx_packet_interface_capability_flag & NX_INTERFACE_CAPABILITY_PTP_TIMESTAMP)
        {

            /* call notification callback */
            nx_ptp_client_packet_timestamp_notify(ptp_client_ptr, packet_ptr, &ptp_timestamp);
        }
    }
#endif

    _nx_ram_network_driver(driver_req);
}

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
UINT _netx_ptp_clock_callback(NX_PTP_CLIENT *client_ptr, UINT operation,
                              NX_PTP_TIME *time_ptr, NX_PACKET *packet_ptr,
                              VOID *callback_data)
{

    NX_PARAMETER_NOT_USED(callback_data);

    switch (operation)
    {

    /* Save pointer to PTP client.  */
    case NX_PTP_CLIENT_CLOCK_INIT:
        ptp_client_ptr = client_ptr;
        break;

    /* Set clock.  */
    case NX_PTP_CLIENT_CLOCK_SET:
        ptp_timestamp = *time_ptr;
        break;

    /* Extract timestamp from packet.  */
    case NX_PTP_CLIENT_CLOCK_PACKET_TS_EXTRACT:
        *time_ptr = ptp_timestamp;
        break;

    /* Get clock.  */
    case NX_PTP_CLIENT_CLOCK_GET:
        *time_ptr = ptp_timestamp;
        break;

    /* Adjust clock.  */
    case NX_PTP_CLIENT_CLOCK_ADJUST:
        ptp_timestamp.nanosecond += time_ptr -> nanosecond;
        if (ptp_timestamp.nanosecond >= NANOSECONDS_PER_SEC)
        {
            ptp_timestamp.nanosecond -= NANOSECONDS_PER_SEC;
            if (ptp_timestamp.second_low == 0xFFFFFFFF)
            {
                ptp_timestamp.second_high++;
                ptp_timestamp.second_low = 0;
            }
            else
            {
                ptp_timestamp.second_low++;
            }
        }
        else if (ptp_timestamp.nanosecond < 0)
        {
            ptp_timestamp.nanosecond += NANOSECONDS_PER_SEC;
            if (ptp_timestamp.second_low == 0)
            {
                ptp_timestamp.second_high--;
                ptp_timestamp.second_low = 0xFFFFFFFF;
            }
            else
            {
                ptp_timestamp.second_low--;
            }
        }
        break;

    /* Prepare timestamp for current packet. */
    case NX_PTP_CLIENT_CLOCK_PACKET_TS_PREPARE:
        packet_ptr -> nx_packet_interface_capability_flag |= NX_INTERFACE_CAPABILITY_PTP_TIMESTAMP;
        break;

    /* Update soft timer.  */
    case NX_PTP_CLIENT_CLOCK_SOFT_TIMER_UPDATE:
        break;

    default:
        return(NX_PTP_PARAM_ERROR);
    }

    return(NX_SUCCESS);
}
#endif