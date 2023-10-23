/* This is the test control routine the NetX RTSP module.  All tests are dispatched from this routine.  */

#include "tx_api.h"
#include "nx_api.h"
#include "nx_rtsp_server.h"
#include "nx_rtp_sender.h"
#include "demo_rtsp_over_rtp.h"


/* Define the stack size for demo tasks. */
#define DEMO_TEST_STACK_SIZE              2048
#define DEMO_RTSP_SERVER_STACK_SIZE       2048
static UCHAR test_thread_stack[DEMO_TEST_STACK_SIZE];
static UCHAR rtsp_server_stack[DEMO_RTSP_SERVER_STACK_SIZE];

/* Define rtp cname which is typically used in rtcp sender report. */
#define DEMO_RTP_CNAME                    "AzureRTOS@microsoft.com"

/* Define multicast corresponding parameters. !Note: these parameters in sdp shall be changed with the same values. */
#ifdef DEMO_MULTICAST_ENABLED

#ifndef DEMO_MULTICAST_IP_ADDRESS
#define DEMO_MULTICAST_IP_ADDRESS         IP_ADDRESS(224, 1, 0, 55)
#endif /* DEMO_MULTICAST_IP_ADDRESS */

#ifndef DEMO_MULTICAST_RTP_PORT
#define DEMO_MULTICAST_RTP_PORT           6002
#endif /* DEMO_MULTICAST_RTP_PORT */

#ifndef DEMO_MULTICAST_RTCP_PORT
#define DEMO_MULTICAST_RTCP_PORT          6003
#endif /* DEMO_MULTICAST_RTCP_PORT */

#endif /* DEMO_MULTICAST_ENABLED */

/* The RTSP server listening port.  */
#ifndef DEMO_RTSP_SERVER_PORT
#define DEMO_RTSP_SERVER_PORT             554
#endif /* DEMO_RTSP_SERVER_PORT */

/* The RTSP server thread priority.  */
#ifndef DEMO_RTSP_SERVER_PRIORITY
#define DEMO_RTSP_SERVER_PRIORITY         3
#endif /* DEMO_RTSP_SERVER_PRIORITY */

/* File name shown in rtsp SETUP request */
#ifndef DEMO_RTSP_VIDEO_FILE_NAME
#define DEMO_RTSP_VIDEO_FILE_NAME         "trackID=0"
#endif /* DEMO_RTSP_VIDEO_FILE_NAME */

#ifndef DEMO_RTSP_AUDIO_FILE_NAME
#define DEMO_RTSP_AUDIO_FILE_NAME         "trackID=1"
#endif /* DEMO_RTSP_AUDIO_FILE_NAME */

/* Define RTP payload type for medias. !Note: payload type in sdp shall be changed with the same values */
#ifndef DEMO_RTP_PAYLOAD_TYPE_VIDEO
#if (DEMO_VIDEO_FORMAT == DEMO_VIDEO_FORMAT_MJPEG)
#define DEMO_RTP_PAYLOAD_TYPE_VIDEO       26
#else
#define DEMO_RTP_PAYLOAD_TYPE_VIDEO       96 /* Use dynamic type range from 96 to 127 */
#endif /* (DEMO_VIDEO_FORMAT == DEMO_VIDEO_FORMAT_MJPEG) */
#endif /* DEMO_RTP_PAYLOAD_TYPE_VIDEO */

#ifndef DEMO_RTP_PAYLOAD_TYPE_AUDIO
#if (DEMO_AUDIO_FORMAT == DEMO_AUDIO_FORMAT_AAC)
#define DEMO_RTP_PAYLOAD_TYPE_AUDIO       97
#else
#define DEMO_RTP_PAYLOAD_TYPE_AUDIO       11
#endif /* (DEMO_AUDIO_FORMAT == DEMO_AUDIO_FORMAT_AAC) */
#endif /* DEMO_RTP_PAYLOAD_TYPE_AUDIO */

/* Define video & audio play fps. !Note: this macro shall be the same as the real FPS to guarantee video playing normally */
#ifndef DEMO_VIDEO_FRAME_PER_SECOND
#define DEMO_VIDEO_FRAME_PER_SECOND       30
#endif /* DEMO_VIDEO_FRAME_PER_SECOND */

#ifndef DEMO_AUDIO_FRAME_PER_SECOND
#define DEMO_AUDIO_FRAME_PER_SECOND       43 /* Reference the comment of DEMO_RTP_AUDIO_SAMPLING_PERIOD
                                                to understand how this macro is calculated and defined. */
#endif /* DEMO_AUDIO_FRAME_PER_SECOND */

#ifndef DEMO_AUDIO_SAMPLE_SIZE
#define DEMO_AUDIO_SAMPLE_SIZE            16 /* Indicate the size in bits for each audio sample. */
#endif /* DEMO_AUDIO_SAMPLE_SIZE */

#ifndef DEMO_AUDIO_CHANNEL_NUM
#define DEMO_AUDIO_CHANNEL_NUM            1
#endif /* DEMO_AUDIO_CHANNEL_NUM */

/* The sampling periods define rtp timestamp increase rate for medias. */
#define DEMO_RTP_VIDEO_SAMPLING_PERIOD    (90000 / DEMO_VIDEO_FRAME_PER_SECOND)
#define DEMO_RTP_AUDIO_SAMPLING_PERIOD    (44100 / DEMO_AUDIO_FRAME_PER_SECOND)  /* Assume the default AAC sampling rate is 44100.
                                                                                    Normally, a single ACC frame contains 1024 samples;
                                                                                    So, there are 44100 / 1024 = 43 frames per second.
                                                                                    Therefore, sampling period is 44100 / 43 = 1025. */

/* Define frame play internal for medias */
#define DEMO_RTP_VIDEO_PLAY_INTERVAL      (1000 / DEMO_VIDEO_FRAME_PER_SECOND)
#define DEMO_RTP_AUDIO_PLAY_INTERVAL      (1000 / DEMO_AUDIO_FRAME_PER_SECOND)

#ifndef DEMO_PLAY_TIMER_INTERVAL
#define DEMO_PLAY_TIMER_INTERVAL          10 /* Per miliseconds */
#endif /* DEMO_PLAY_TIMER_INTERVAL */

/* Declare the prototypes for the test entry points. */
TX_THREAD            test_thread;
NX_RTSP_SERVER       rtsp_0;
NX_RTP_SENDER        rtp_0;

/* Declare events to use in threads. */
TX_EVENT_FLAGS_GROUP demo_test_events;

/* Declare the timer to trigger events (e.g., playing video/audio). */
TX_TIMER             demo_timer;

/* Declare the sample structure to support multiple clients interaction. */
typedef struct SAMPLE_CLIENT_STRUCT
{
    NX_RTSP_CLIENT   *rtsp_client_ptr;

    /* RTP sessions */
    NX_RTP_SESSION   rtp_session_video;
    NX_RTP_SESSION   rtp_session_audio;

    /* Count the number of clients setup in the specific rtp session */
    USHORT           rtp_session_video_client_count;
    USHORT           rtp_session_audio_client_count;

    /* RTP timestamp and NTP timestamp */
    ULONG            rtp_session_video_timestamp;
    ULONG            rtp_session_audio_timestamp;

#ifdef DEMO_PLAY_BY_TIMER
    /* Accumulated ticks for determining when to play a video/audio frame */
    volatile ULONG   video_play_time_ms;
    volatile ULONG   audio_play_time_ms;
#endif /* DEMO_PLAY_BY_TIMER */
} SAMPLE_CLIENT;

#ifdef DEMO_MULTICAST_ENABLED
SAMPLE_CLIENT        sample_client_multicast;
#else
SAMPLE_CLIENT        sample_client[NX_RTSP_SERVER_MAX_CLIENTS];
#endif  /* DEMO_MULTICAST_ENABLED */

/* Define an error counter.  */
ULONG                error_counter;


/* Internal functions prototype. */
static UINT rtsp_describe_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);
static UINT rtsp_setup_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr);
static UINT rtsp_play_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);
static UINT rtsp_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);
static UINT rtsp_pause_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);
static UINT rtsp_set_parameter_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length);
static UINT rtsp_disconnect_callback(NX_RTSP_CLIENT *rtsp_client_ptr);

static UINT test_rtcp_receiver_report_callback(NX_RTP_SESSION *session, NX_RTCP_RECEIVER_REPORT *report);
static UINT test_rtcp_sdes_callback(NX_RTCP_SDES_INFO *sdes_info);

static VOID (*demo_media_data_init_callback)(VOID) = DEMO_MEDIA_DATA_INIT;
static UINT (*demo_video_data_read_callback)(ULONG *ntp_msw, ULONG *ntp_lsw, UCHAR **data_ptr, ULONG *data_size) = DEMO_VIDEO_DATA_READ;
static UINT (*demo_audio_data_read_callback)(ULONG *ntp_msw, ULONG *ntp_lsw, UCHAR **data_ptr, ULONG *data_size) = DEMO_AUDIO_DATA_READ;


#ifdef DEMO_PLAY_BY_TIMER
static VOID demo_timer_entry(ULONG address)
{
SAMPLE_CLIENT *client_ptr;

#ifdef DEMO_MULTICAST_ENABLED
    client_ptr = &sample_client_multicast;
#else
    for (UINT i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {
        client_ptr = &sample_client[i];
#endif /* DEMO_MULTICAST_ENABLED */

        if (client_ptr -> rtp_session_video_client_count)
        {
            client_ptr -> video_play_time_ms += DEMO_PLAY_TIMER_INTERVAL;
            if (client_ptr -> video_play_time_ms >= DEMO_RTP_VIDEO_PLAY_INTERVAL)
            {

                /* Send the video ready event. */
                tx_event_flags_set(&demo_test_events, DEMO_VIDEO_DATA_READY_EVENT, TX_OR);
            }
        }
        if (client_ptr -> rtp_session_audio_client_count)
        {
            client_ptr -> audio_play_time_ms += DEMO_PLAY_TIMER_INTERVAL;
            if (client_ptr -> audio_play_time_ms >= DEMO_RTP_AUDIO_PLAY_INTERVAL)
            {

                /* Send the audio ready event. */
                tx_event_flags_set(&demo_test_events, DEMO_AUDIO_DATA_READY_EVENT, TX_OR);
            }
        }
#ifndef DEMO_MULTICAST_ENABLED
    }
#endif /* DEMO_MULTICAST_ENABLED */
}
#endif /* DEMO_PLAY_BY_TIMER */

/* Define what the initial system looks like.  */
void sample_entry(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, VOID *dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
UINT           i = 0;
UINT           status;
ULONG          events = 0;
UCHAR          initialized = NX_FALSE;
ULONG          ntp_msw, ntp_lsw;
UCHAR         *data;
ULONG          data_length;
#if (DEMO_AUDIO_FORMAT == DEMO_AUDIO_FORMAT_PCM)
NX_PACKET     *send_packet = NX_NULL;
#endif /* (DEMO_AUDIO_FORMAT == DEMO_AUDIO_FORMAT_PCM) */
#ifndef DEMO_MULTICAST_ENABLED
SAMPLE_CLIENT *client_ptr;
#else
SAMPLE_CLIENT *client_ptr = &sample_client_multicast;


    /* Enable IGMP.  */
    status = nx_igmp_enable(ip_ptr);

    /* Join multicast group. */
    status += nx_ipv4_multicast_interface_join(ip_ptr, DEMO_MULTICAST_IP_ADDRESS, 0);
    if (status)
        error_counter++;
#endif  /* DEMO_MULTICAST_ENABLED */

    status = nx_ip_fragment_enable(ip_ptr);
    if (status)
        error_counter++;

    /* Create RTP sender */
    nx_rtp_sender_create(&rtp_0, ip_ptr, pool_ptr, DEMO_RTP_CNAME, sizeof(DEMO_RTP_CNAME) - 1);
    nx_rtp_sender_rtcp_receiver_report_callback_set(&rtp_0, test_rtcp_receiver_report_callback);
    nx_rtp_sender_rtcp_sdes_callback_set(&rtp_0, test_rtcp_sdes_callback);

    /* Create RTSP server. */
    nx_rtsp_server_create(&rtsp_0, "RTSP Server", sizeof("RTSP Server") - 1, ip_ptr, pool_ptr,
                          rtsp_server_stack, DEMO_RTSP_SERVER_STACK_SIZE, DEMO_RTSP_SERVER_PRIORITY, DEMO_RTSP_SERVER_PORT, rtsp_disconnect_callback);

    /* Set callback functions. */
    nx_rtsp_server_describe_callback_set(&rtsp_0, rtsp_describe_callback);
    nx_rtsp_server_setup_callback_set(&rtsp_0, rtsp_setup_callback);
    nx_rtsp_server_play_callback_set(&rtsp_0, rtsp_play_callback);
    nx_rtsp_server_teardown_callback_set(&rtsp_0, rtsp_teardown_callback);
    nx_rtsp_server_pause_callback_set(&rtsp_0, rtsp_pause_callback);
    nx_rtsp_server_set_parameter_callback_set(&rtsp_0, rtsp_set_parameter_callback);

    /* Start RTSP server. */
    nx_rtsp_server_start(&rtsp_0);

    printf("RTSP server started!\r\n");

    /* Create event for the play thread */
    status = tx_event_flags_create(&demo_test_events, "Demo events");
    if (status)
        error_counter++;

#ifdef DEMO_PLAY_BY_TIMER
    /* Create the global timeout timer.  */
    status = tx_timer_create(&demo_timer, "Demo Timer", demo_timer_entry, 0,
                             (DEMO_PLAY_TIMER_INTERVAL * NX_IP_PERIODIC_RATE / 1000),
                             (DEMO_PLAY_TIMER_INTERVAL * NX_IP_PERIODIC_RATE / 1000),
                             TX_AUTO_ACTIVATE);
    if (status)
        error_counter++;
#endif /* DEMO_PLAY_BY_TIMER */

    /* Enter server test. */
    while (1)
    {

        tx_event_flags_get(&demo_test_events, DEMO_ALL_EVENTS, TX_OR_CLEAR, &events, TX_WAIT_FOREVER);

        /*********************************************
        ************** DEMO_PLAY_EVENT ***************
        *********************************************/
        if (events & DEMO_PLAY_EVENT)
        {
            if (initialized == NX_FALSE)
            {

                /* Call user registered callback function to initialize. */
                if (demo_media_data_init_callback)
                {
                    demo_media_data_init_callback();
                }

#ifdef DEMO_PLAY_BY_TIMER
                /* Set an initial value to eliminate too many ticks accumulation. */
#ifdef DEMO_MULTICAST_ENABLED
                client_ptr -> video_play_time_ms = 0;
                client_ptr -> audio_play_time_ms = 0;
#else
                for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
                {
                    client_ptr = &sample_client[i];
                    sample_client[i].video_play_time_ms = 0;
                    sample_client[i].audio_play_time_ms = 0;
                }
#endif /* DEMO_MULTICAST_ENABLED */
#endif /* DEMO_PLAY_BY_TIMER */
            }

            /* Set the initialized flag */
            initialized = NX_TRUE;
        }

        /*********************************************
        ************ DEMO_TEARDOWN_EVENT *************
        *********************************************/
        if (events & DEMO_TEARDOWN_EVENT)
        {
#ifdef DEMO_MULTICAST_ENABLED
            if ((client_ptr -> rtp_session_video_client_count == 0) &&
                (client_ptr -> rtp_session_audio_client_count == 0))
            {
                initialized = NX_FALSE;
            }

#ifdef DEMO_PLAY_BY_TIMER
            client_ptr -> video_play_time_ms = 0;
            client_ptr -> audio_play_time_ms = 0;
#endif /* DEMO_PLAY_BY_TIMER */
#else
            /* Check all client count to determine whether to clear the initialized flag */
            for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
            {
                client_ptr = &sample_client[i];
                if ((client_ptr -> rtp_session_video_client_count) ||
                    (client_ptr -> rtp_session_audio_client_count))
                {
                    break;
                }
            }
            if (i == NX_RTSP_SERVER_MAX_CLIENTS)
            {
                initialized = NX_FALSE;

#ifdef DEMO_PLAY_BY_TIMER
                for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
                {
                    client_ptr -> video_play_time_ms = 0;
                    client_ptr -> audio_play_time_ms = 0;
                }
#endif /* DEMO_PLAY_BY_TIMER */
            }
#endif
        }

        /*********************************************
        ******** DEMO_VIDEO_DATA_READY_EVENT *********
        *********************************************/
        if (events & DEMO_VIDEO_DATA_READY_EVENT)
        {

            /* Check if a play event has already triggered. */
            if (initialized == NX_TRUE)
            {

                /* Check if the user has redefined DEMO_VIDEO_DATA_READ which registers video data read callback function. */
                if (demo_video_data_read_callback == NX_NULL)
                {
                    printf("User must implement video data read function and redefine DEMO_VIDEO_DATA_READ\r\n");
                    continue;
                }

                /* Read video data and transmit it */
                data_length = 0;
                if ((demo_video_data_read_callback(&ntp_msw, &ntp_lsw, &data, &data_length) == NX_SUCCESS) && (data_length > 0))
                {
#ifndef DEMO_MULTICAST_ENABLED
                    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
                    {
                        client_ptr = &sample_client[i];
#endif /* DEMO_MULTICAST_ENABLED */

                        /* Make sure at least one client having setup the connection. */
                        if (client_ptr -> rtp_session_video_client_count == 0)
                        {
                            continue;
                        }

#if (DEMO_VIDEO_FORMAT == DEMO_VIDEO_FORMAT_H264)
                        status = nx_rtp_sender_session_h264_send(&(client_ptr -> rtp_session_video), data, data_length,
                                                                 client_ptr -> rtp_session_video_timestamp, ntp_msw, ntp_lsw, NX_TRUE);
#else
                        status = nx_rtp_sender_session_jpeg_send(&(client_ptr -> rtp_session_video), data, data_length,
                                                                 client_ptr -> rtp_session_video_timestamp, ntp_msw, ntp_lsw, NX_TRUE);
#endif /* (DEMO_VIDEO_FORMAT == DEMO_VIDEO_FORMAT_H264) */
                        if (status)
                        {
                            printf("Fail to send video frame: %d, %d\r\n", i, status);
                        }

                        /* Update rtp timestamp video sampling period. */
                        client_ptr -> rtp_session_video_timestamp += DEMO_RTP_VIDEO_SAMPLING_PERIOD;

#ifdef DEMO_PLAY_BY_TIMER
                        if (client_ptr -> video_play_time_ms >= DEMO_RTP_VIDEO_PLAY_INTERVAL)
                        {
                            client_ptr -> video_play_time_ms -= DEMO_RTP_VIDEO_PLAY_INTERVAL;
                        }
#endif /* DEMO_PLAY_BY_TIMER */
#ifndef DEMO_MULTICAST_ENABLED
                    }
#endif /* DEMO_MULTICAST_ENABLED */
                }
            }
        }

        /*********************************************
        ******** DEMO_AUDIO_DATA_READY_EVENT *********
        *********************************************/
        if (events & DEMO_AUDIO_DATA_READY_EVENT)
        {

            /* Check if a play event has already triggered. */
            if (initialized == NX_TRUE)
            {

                /* Check if the user has redefined DEMO_AUDIO_DATA_READ which registers audio data read callback function. */
                if (demo_audio_data_read_callback == NX_NULL)
                {
                    printf("User must implement audio data read function and redefine DEMO_AUDIO_DATA_READ\r\n");
                    continue;
                }

                /* Read audio data and transmit it */
                data_length = 0;
                if ((demo_audio_data_read_callback(&ntp_msw, &ntp_lsw, &data, &data_length) == NX_SUCCESS) && (data_length > 0))
                {
#ifndef DEMO_MULTICAST_ENABLED
                    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
                    {
                        client_ptr = &sample_client[i];
#endif /* DEMO_MULTICAST_ENABLED */

                        /* Make sure at least one client having setup the connection. */
                        if (client_ptr -> rtp_session_audio_client_count == 0)
                        {
                            continue;
                        }

#if (DEMO_AUDIO_FORMAT == DEMO_AUDIO_FORMAT_AAC)
                        status = nx_rtp_sender_session_aac_send(&(client_ptr -> rtp_session_audio), data, data_length,
                                                                client_ptr -> rtp_session_audio_timestamp, ntp_msw, ntp_lsw, NX_TRUE);
                        if (status)
                        {
                            printf("Fail to send audio frame: %d, %d\r\n", i, status);
                        }

                        client_ptr -> rtp_session_audio_timestamp += DEMO_RTP_AUDIO_SAMPLING_PERIOD;
#else
                        /* Allocate a rtp packet. */
                        nx_rtp_sender_session_packet_allocate(&(client_ptr -> rtp_session_audio), &send_packet, NX_WAIT_FOREVER);

                        /* Copy payload data into the packet. */
                        status = nx_packet_data_append(send_packet, (void *)data, data_length,
                                                    client_ptr -> rtp_session_audio.nx_rtp_sender -> nx_rtp_sender_packet_pool_ptr, NX_WAIT_FOREVER);
                        if (status)
                        {
                            nx_packet_release(send_packet);
                        }

                        /* Send audio data frame through rtp */
                        status = nx_rtp_sender_session_packet_send(&(client_ptr -> rtp_session_audio), send_packet,
                                                                client_ptr -> rtp_session_audio_timestamp, ntp_msw, ntp_lsw, NX_FALSE);
                        if (status)
                        {
                            nx_packet_release(send_packet);
                            printf("Fail to send audio data: %d, %d\r\n", i, status);
                        }

                        /* Update rtp timestamp by the number of sampling bytes. */
                        client_ptr -> rtp_session_audio_timestamp += (data_length / (DEMO_AUDIO_SAMPLE_SIZE / 8));
#endif /* (DEMO_AUDIO_FORMAT == DEMO_AUDIO_FORMAT_AAC) */

#ifdef DEMO_PLAY_BY_TIMER
                        if (client_ptr -> audio_play_time_ms >= DEMO_RTP_AUDIO_PLAY_INTERVAL)
                        {
                            client_ptr -> audio_play_time_ms -= DEMO_RTP_AUDIO_PLAY_INTERVAL;
                        }
#endif /* DEMO_PLAY_BY_TIMER */
#ifndef DEMO_MULTICAST_ENABLED
                    }
#endif /* DEMO_MULTICAST_ENABLED */
                }
            }
        }
    }
}


/* SDP string options. */
#ifdef DEMO_MULTICAST_ENABLED
#if (DEMO_VIDEO_FORMAT == DEMO_VIDEO_FORMAT_H264)
#define DEMO_SDP \
"v=0\r\ns=H264 video with AAC audio, streamed by the NetX RTSP Server\r\n"\
"m=video 6002 RTP/AVP 96\r\n"\
"c=IN IP4 224.1.0.55/128\r\n"\
"a=rtpmap:96 H264/90000\r\n"\
"a=fmtp:96 profile-level-id=42A01E; packetization-mode=1\r\n"\
"a=control:trackID=0\r\n"\
"m=audio 6002 RTP/AVP 97\r\n"\
"c=IN IP4 224.1.0.55/128\r\n"\
"a=rtpmap:97 mpeg4-generic/44100/1\r\n"\
"a=fmtp:97 mode=AAC-hbr; SizeLength=13\r\n"\
"a=control:trackID=1\r\n"
#else
#define DEMO_SDP \
"v=0\r\ns=MJPEG video with AAC audio, streamed by the NetX RTSP Server\r\n"\
"m=video 6002 RTP/AVP 26\r\n"\
"c=IN IP4 224.1.0.55/128\r\n"\
"a=rtpmap:26 JPEG/90000\r\n"\
"a=control:trackID=0\r\n"\
"m=audio 6002 RTP/AVP 11\r\n"\
"c=IN IP4 224.1.0.55/128\r\n"\
"a=rtpmap:11 L16/44100/1\r\n"\
"a=fmtp:11 emphasis=50-15\r\n"\
"a=ptime:5\r\n"\
"a=control:trackID=1\r\n"
#endif /* (DEMO_VIDEO_FORMAT == DEMO_VIDEO_FORMAT_H264) */
#else
#if (DEMO_VIDEO_FORMAT == DEMO_VIDEO_FORMAT_H264)
#define DEMO_SDP \
"v=0\r\ns=H264 video with AAC audio, streamed by the NetX RTSP Server\r\n"\
"m=video 0 RTP/AVP 96\r\n"\
"a=rtpmap:96 H264/90000\r\n"\
"a=fmtp:96 profile-level-id=42A01E; packetization-mode=1\r\n"\
"a=control:trackID=0\r\n"\
"m=audio 0 RTP/AVP 97\r\n"\
"a=rtpmap:97 mpeg4-generic/44100/1\r\n"\
"a=fmtp:97 mode=AAC-hbr; SizeLength=13\r\n"\
"a=control:trackID=1\r\n"
#else
#define DEMO_SDP \
"v=0\r\ns=MJPEG video with AAC audio, streamed by the NetX RTSP Server\r\n"\
"m=video 0 RTP/AVP 26\r\n"\
"a=rtpmap:26 JPEG/90000\r\n"\
"a=control:trackID=0\r\n"\
"m=audio 0 RTP/AVP 11\r\n"\
"a=rtpmap:11 L16/44100/1\r\n"\
"a=fmtp:11 emphasis=50-15\r\n"\
"a=ptime:5\r\n"\
"a=control:trackID=1\r\n"
#endif /* (DEMO_VIDEO_FORMAT == DEMO_VIDEO_FORMAT_H264) */
#endif /* DEMO_MULTICAST_ENABLED */


static UINT rtsp_describe_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length)
{
UINT status;


    status = nx_rtsp_server_sdp_set(rtsp_client_ptr, (UCHAR *)DEMO_SDP, sizeof(DEMO_SDP));
    printf("RTSP request received: DESCRIBE.\r\n");
    return(status);
}

static UINT rtsp_setup_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr)
{
UINT status;
UINT rtp_port, rtcp_port;
SAMPLE_CLIENT *client_ptr = NX_NULL;
#ifndef DEMO_MULTICAST_ENABLED
UINT i;
#endif /* DEMO_MULTICAST_ENABLED */


    /* Print information from the client */
    printf("RTSP request received: SETUP.\r\nuri: %s\r\nclient RTP port %d, RTCP port %d, IP %lu.%lu.%lu.%lu\r\n", uri,
           transport_ptr -> client_rtp_port, transport_ptr -> client_rtcp_port,
           (transport_ptr -> client_ip_address.nxd_ip_address.v4 >> 24),
           (transport_ptr -> client_ip_address.nxd_ip_address.v4 >> 16) & 0xFF,
           (transport_ptr -> client_ip_address.nxd_ip_address.v4 >> 8) & 0xFF,
           (transport_ptr -> client_ip_address.nxd_ip_address.v4 & 0xFF));

    /* Get the created and found ports */
    status = nx_rtp_sender_port_get(&rtp_0, &rtp_port, &rtcp_port);
    if (status)
    {
        return(status);
    }
    transport_ptr -> server_rtp_port = rtp_port;
    transport_ptr -> server_rtcp_port = rtcp_port;

#ifdef DEMO_MULTICAST_ENABLED
    /* Judge and change to multicast if received ip address is 0 */
    if (transport_ptr -> client_ip_address.nxd_ip_address.v4 != 0)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    /* Assign multicast ip address and rtp/rtcp ports */
    transport_ptr -> client_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    transport_ptr -> client_ip_address.nxd_ip_address.v4 = DEMO_MULTICAST_IP_ADDRESS;
    transport_ptr -> client_rtp_port = DEMO_MULTICAST_RTP_PORT;
    transport_ptr -> client_rtcp_port = DEMO_MULTICAST_RTCP_PORT;
    transport_ptr -> multicast_ttl = NX_RTP_SENDER_TIME_TO_LIVE;

    /* Directly use sample_client_multicast */
    client_ptr = &sample_client_multicast;
#else
    /* Find and store the RTSP client pointer.  */
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {

        /* Check if the client is already linked. */
        if (sample_client[i].rtsp_client_ptr == rtsp_client_ptr)
        {
            client_ptr = &(sample_client[i]);
            break;
        }

        if ((client_ptr == NX_NULL) && (sample_client[i].rtsp_client_ptr == NX_NULL))
        {

            /* Record the unused position. */
            client_ptr = &(sample_client[i]);
        }
    }

    /* Check and return error if reach max connected clients limitation. */
    if (client_ptr == NX_NULL)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    /* Link the client pointer if it is newly assigned. */
    if (i == NX_RTSP_SERVER_MAX_CLIENTS)
    {
        client_ptr -> rtsp_client_ptr = rtsp_client_ptr;
    }

#endif /* DEMO_MULTICAST_ENABLED */

    if (strstr((const char *)uri, DEMO_RTSP_VIDEO_FILE_NAME))
    {
        printf("Setup Video (track 0)..\r\n");

#ifdef DEMO_MULTICAST_ENABLED
        if (client_ptr -> rtp_session_video_client_count == 0)
        {
#endif /* DEMO_MULTICAST_ENABLED */

            /* Setup rtp sender video session */
            status = nx_rtp_sender_session_create(&rtp_0, &(client_ptr -> rtp_session_video), DEMO_RTP_PAYLOAD_TYPE_VIDEO,
                                                  transport_ptr -> interface_index, &(transport_ptr -> client_ip_address),
                                                  transport_ptr -> client_rtp_port, transport_ptr -> client_rtcp_port);
            if (status)
            {
                printf("Fail to create video session\r\n");

                /* Reset the client pointer if error status happens */
                client_ptr -> rtsp_client_ptr = NX_NULL;
                return(status);
            }

            /* Obtain generated ssrc */
            status = nx_rtp_sender_session_ssrc_get(&(client_ptr -> rtp_session_video), &(transport_ptr -> rtp_ssrc));
            if (status)
            {

                /* Reset the client pointer if error status happens */
                client_ptr -> rtsp_client_ptr = NX_NULL;
                return(status);
            }

            /* Reset corresponding variables */
            client_ptr -> rtp_session_video_timestamp = (ULONG)NX_RAND();
#ifdef DEMO_MULTICAST_ENABLED
        }
#endif /* DEMO_MULTICAST_ENABLED */

        /* Increase the number of setup client. */
        client_ptr -> rtp_session_video_client_count++;
    }
    else if (strstr((const char *)uri, DEMO_RTSP_AUDIO_FILE_NAME))
    {
        printf("Setup Audio (track 1)..\r\n");

#ifdef DEMO_MULTICAST_ENABLED
        if (client_ptr -> rtp_session_audio_client_count == 0)
        {
#endif /* DEMO_MULTICAST_ENABLED */

            /* Setup rtp sender audio session */
            status = nx_rtp_sender_session_create(&rtp_0, &(client_ptr -> rtp_session_audio), DEMO_RTP_PAYLOAD_TYPE_AUDIO,
                                                  transport_ptr -> interface_index, &(transport_ptr -> client_ip_address),
                                                  transport_ptr -> client_rtp_port, transport_ptr -> client_rtcp_port);
            if (status)
            {
                printf("Fail to create audio session\r\n");

                /* Reset the client pointer if error status happens */
                client_ptr -> rtsp_client_ptr = NX_NULL;
                return(status);
            }

            /* Obtain generated ssrc */
            status = nx_rtp_sender_session_ssrc_get(&(client_ptr -> rtp_session_audio), &(transport_ptr -> rtp_ssrc));
            if (status)
            {

                /* Reset the client pointer if error status happens */
                client_ptr -> rtsp_client_ptr = NX_NULL;
                return(status);
            }

            /* Reset corresponding variables */
            client_ptr -> rtp_session_audio_timestamp = (ULONG)NX_RAND();

#if (DEMO_AUDIO_FORMAT == DEMO_AUDIO_FORMAT_PCM)
            nx_rtp_sender_session_sample_factor_set(&(client_ptr -> rtp_session_audio), (DEMO_AUDIO_SAMPLE_SIZE / 8) * DEMO_AUDIO_CHANNEL_NUM);
#endif /* (DEMO_AUDIO_FORMAT == DEMO_AUDIO_FORMAT_PCM) */
#ifdef DEMO_MULTICAST_ENABLED
        }
#endif /* DEMO_MULTICAST_ENABLED */

        /* Increase the number of setup client. */
        client_ptr -> rtp_session_audio_client_count++;
    }
    else
    {
        printf("Invalid track ID!\r\n");
        return(NX_NOT_SUCCESSFUL);
    }

    return(NX_SUCCESS);
}

static UINT rtsp_play_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length)
{
UINT status;
UINT video_seq, audio_seq, video_rtptime, audio_rtptime;
SAMPLE_CLIENT *client_ptr;
#ifndef DEMO_MULTICAST_ENABLED
UINT i;
#endif


    printf("RTSP request received: PLAY.\r\n");

#ifndef DEMO_MULTICAST_ENABLED
    /* Search and find the RTSP client. */
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {
        if (sample_client[i].rtsp_client_ptr == rtsp_client_ptr)
        {
            client_ptr = &sample_client[i];
            break;
        }
    }
    if (i == NX_RTSP_SERVER_MAX_CLIENTS)
    {
        printf("Fail to find rtsp client!\r\n");
        return(NX_NOT_SUCCESSFUL);
    }
#else
    /* Directly use sample_client_multicast */
    client_ptr = &sample_client_multicast;
#endif /* DEMO_MULTICAST_ENABLED */

    if (client_ptr -> rtp_session_video_client_count)
    {

        /* Retrieve the sequence number through rtp sender functions */
        nx_rtp_sender_session_sequence_number_get(&(client_ptr -> rtp_session_video), &video_seq);

        /* Assign recorded timestamps */
        video_rtptime = client_ptr -> rtp_session_video_timestamp;

        /* Set rtp information into rtsp client */
        status = nx_rtsp_server_rtp_info_set(rtsp_client_ptr, DEMO_RTSP_VIDEO_FILE_NAME, sizeof(DEMO_RTSP_VIDEO_FILE_NAME) - 1, video_seq, video_rtptime);
        if (status)
        {
            return(status);
        }
    }

    if (client_ptr -> rtp_session_audio_client_count)
    {

        /* Retrieve the sequence number through rtp sender functions */
        nx_rtp_sender_session_sequence_number_get(&(client_ptr -> rtp_session_audio), &audio_seq);

        /* Assign recorded timestamps */
        audio_rtptime = client_ptr -> rtp_session_audio_timestamp;

        /* Set rtp information into rtsp client */
        status = nx_rtsp_server_rtp_info_set(rtsp_client_ptr, DEMO_RTSP_AUDIO_FILE_NAME, sizeof(DEMO_RTSP_AUDIO_FILE_NAME) - 1, audio_seq, audio_rtptime);
        if (status)
        {
            return(status);
        }
    }

    /* Trigger the play event */
    tx_event_flags_set(&demo_test_events, DEMO_PLAY_EVENT, TX_OR);

    return(NX_SUCCESS);
}

static UINT rtsp_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length)
{
SAMPLE_CLIENT *client_ptr;
#ifndef DEMO_MULTICAST_ENABLED
UINT i;


    printf("RTSP request received: TEARDOWN.\r\n");

    /* Find the RTSP client pointer.  */
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {
        if (sample_client[i].rtsp_client_ptr == rtsp_client_ptr)
        {
            client_ptr = &(sample_client[i]);
            break;
        }
    }
    if (i == NX_RTSP_SERVER_MAX_CLIENTS)
    {
        printf("Fail to find rtsp client!\r\n");
        return(NX_NOT_SUCCESSFUL);
    }
#else
    /* Directly use sample_client_multicast */
    client_ptr = &sample_client_multicast;
#endif /* DEMO_MULTICAST_ENABLED */

    /* Decrease session client count */
    if (client_ptr -> rtp_session_video_client_count > 0)
    {
        client_ptr -> rtp_session_video_client_count--;
#ifdef DEMO_MULTICAST_ENABLED
        if (client_ptr -> rtp_session_video_client_count == 0)
#endif
        {
            client_ptr -> rtsp_client_ptr = NX_NULL;
            nx_rtp_sender_session_delete(&(client_ptr -> rtp_session_video));
        }
    }
    if (client_ptr -> rtp_session_audio_client_count > 0)
    {
        client_ptr -> rtp_session_audio_client_count--;
#ifdef DEMO_MULTICAST_ENABLED
        if (client_ptr -> rtp_session_audio_client_count == 0)
#endif
        {
            client_ptr -> rtsp_client_ptr = NX_NULL;
            nx_rtp_sender_session_delete(&(client_ptr -> rtp_session_audio));
        }
    }

    /* Trigger the tear down event */
    tx_event_flags_set(&demo_test_events, DEMO_TEARDOWN_EVENT, TX_OR);

    return(NX_SUCCESS);
}

static UINT rtsp_pause_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length)
{
    printf("RTSP request received: PAUSE.\r\n");

    return(NX_SUCCESS);
}

static UINT rtsp_set_parameter_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length)
{
    printf("RTSP request received: SET PARAMETER.\r\n");

    return(NX_SUCCESS);
}

static UINT rtsp_disconnect_callback(NX_RTSP_CLIENT *rtsp_client_ptr)
{

    /* Trigger the tear down event */
    tx_event_flags_set(&demo_test_events, DEMO_TEARDOWN_EVENT, TX_OR);

    return(NX_SUCCESS);
}

static UINT test_rtcp_receiver_report_callback(NX_RTP_SESSION *session, NX_RTCP_RECEIVER_REPORT *report)
{
#ifndef DEMO_MULTICAST_ENABLED
UINT i;

    /* Search the rtsp client table and find which session it is*/
    for (i = 0; i < NX_RTSP_SERVER_MAX_CLIENTS; i++)
    {
        if (session == &(sample_client[i].rtp_session_video))
        {
            break;
        }
        else if (session == &(sample_client[i].rtp_session_audio))
        {
            break;
        }
    }
    if (i == NX_RTSP_SERVER_MAX_CLIENTS)
    {

        /* Unkown session, return directly. */
        return(NX_SUCCESS);
    }
#endif /* DEMO_MULTICAST_ENABLED */

    /*
        We can add user implementation code here..

        Note!: since this callback is invoked from the IP thread, the application should not block in this callback.

        Tip: in this callback, we can obtain and record below information:
            1) report -> receiver_ssrc: the ssrc of the receiver who sends the rr report
            2) report -> fraction_loss: the fraction lost of the receiver
            3) report -> packet_loss: the cumulative number of packets lost of the receiver
            4) report -> extended_max: the extended highest sequence number received of the receiver
            5) report -> jitter: the inter-arrival jitter of the receiver
            6) report -> last_sr: the last SR timestamp of the receiver
            7) report -> delay: the delay since last SR timestamp of the receiver.
    */

    /* Update the timeout of RTSP server since the RTCP message proves liveness.  */
#ifdef DEMO_MULTICAST_ENABLED
    nx_rtsp_server_keepalive_update(sample_client_multicast.rtsp_client_ptr);
#else
    nx_rtsp_server_keepalive_update(sample_client[i].rtsp_client_ptr);
#endif /* DEMO_MULTICAST_ENABLED */

    return(NX_SUCCESS);
}

static UINT test_rtcp_sdes_callback(NX_RTCP_SDES_INFO *sdes_info)
{
    /*
        We can add user implementation code here..

        Note!: since this callback is invoked from the IP thread, the application should not block in this callback.

        Tip: in this callback, we can obtain and record below information:
            1) sdes_info -> ssrc: the ssrc of the receiver who sends the sdes packet
            2) sdes_info -> cname_length: the length of the cname field
            3) sdes_info -> cname: the cname field
    */

    return NX_SUCCESS;
}
