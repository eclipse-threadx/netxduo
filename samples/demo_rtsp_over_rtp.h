/* This is an include file for the rtsp over rtp demo programs. It is not part of the official release of NetXDuo RTSP Server or RTP Sender.
   It is simply a convenience for the user to have a simple demo program to use as a starting point for their application.
   Please be carefully to read the Note! below and execute the corresponding actions before using this demo program. */

#ifndef DEMO_RTSP_OVER_RTP_H
#define DEMO_RTSP_OVER_RTP_H

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */

#ifdef   __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {
#endif

#include "tx_api.h"
#include "nx_api.h"


/* Note!: declare demo events to use in the threads.
   1. For event triggered RTP sending, user can use below example codes to trigger audio/video data reading and sending by rtp:
      1) Video data: tx_event_flags_set(&demo_test_events, DEMO_AUDIO_DATA_READY_EVENT, TX_OR);
      2) Audio data: tx_event_flags_set(&demo_test_events, DEMO_VIDEO_DATA_READY_EVENT, TX_OR);
   2. For timer timeout trigger RTP sending, user can define the macro DEMO_PLAY_BY_TIMER by uncomment it below.
*/
extern TX_EVENT_FLAGS_GROUP demo_test_events;

#define DEMO_ALL_EVENTS                   ((ULONG)0xFFFFFFFF)
#define DEMO_PLAY_EVENT                   ((ULONG)0x00000001)
#define DEMO_TEARDOWN_EVENT               ((ULONG)0x00000002)
#define DEMO_VIDEO_DATA_READY_EVENT       ((ULONG)0x00000004)
#define DEMO_AUDIO_DATA_READY_EVENT       ((ULONG)0x00000008)

/* Define user defined macros. */
/* Using unicast by default, if DEMO_MULTICAST_ENABLED is defined, using multicast. */
/*
#define DEMO_MULTICAST_ENABLED
*/

/* Using user triggered playing by default, if DEMO_PLAY_BY_TIMER is define, using timer timeout event to play medias. */
/*
#define DEMO_PLAY_BY_TIMER
*/

/* Define audio format options. */
#define DEMO_AUDIO_FORMAT_PCM             0
#define DEMO_AUDIO_FORMAT_AAC             1

/* Define video format options. */
#define DEMO_VIDEO_FORMAT_MJPEG           0
#define DEMO_VIDEO_FORMAT_H264            1

/* Using AAC by default, user can re-define this macro to one of the audio format options above. */
#ifndef DEMO_AUDIO_FORMAT
#define DEMO_AUDIO_FORMAT                 DEMO_AUDIO_FORMAT_AAC
#endif /* DEMO_AUDIO_FORMAT */

/* Using H.264 by default, user can re-define this macro to one of the video format options above. */
#ifndef DEMO_VIDEO_FORMAT
#define DEMO_VIDEO_FORMAT                 DEMO_VIDEO_FORMAT_H264
#endif /* DEMO_VIDEO_FORMAT */


/* Note!: Below are user implemented callback functions corresponding declarations. The program uses macros
      DEMO_MEDIA_DATA_INIT, DEMO_VIDEO_DATA_READ and DEMO_AUDIO_DATA_READ as default callback functions
      for media data initialization, video data reading and audio data reading separately.

   1. DEMO_MEDIA_DATA_INIT could be its default value NX_NULL if user does not need to execute any code after RTSP PLAY command is received.
      Otherwise, user can define a callback with the prototype "VOID (*demo_media_data_init_callback)(VOID)" and implement the callback function.

   2. DEMO_VIDEO_DATA_READ could be its default value NX_NULL if user does not implement video data reading and transmitting.
      Otherwise, user MUST! define a callback with the prototype "UINT (*demo_video_data_read_callback)(ULONG *ntp_msw, ULONG *ntp_lsw, UCHAR **data_ptr, ULONG *data_size)"
      and implement the callback function.
      Both MJPEG and H264 video formats are frame based, so the callback function should return a complete frame data each time. 

   3. DEMO_AUDIO_DATA_READ could be its default value NX_NULL if user does not implement audio data reading and transmitting.
      Otherwise, user MUST! define a callback with the prototype "UINT (*demo_audio_data_read_callback)(ULONG *ntp_msw, ULONG *ntp_lsw, UCHAR **data_ptr, ULONG *data_size)"
      and implement the callback function.
      By default, PCM audio format is data based, so there is no limitation for the data size returned by the callback function.
      If the macro DEMO_AAC_ENABLED is enabled, the callback function should return a complete AAC frame data each time.
*/
#ifndef DEMO_MEDIA_DATA_INIT
#define DEMO_MEDIA_DATA_INIT  NX_NULL
#endif /* DEMO_MEDIA_DATA_INIT */

#ifndef DEMO_VIDEO_DATA_READ
#define DEMO_VIDEO_DATA_READ  NX_NULL
#endif /* DEMO_VIDEO_DATA_READ */

#ifndef DEMO_AUDIO_DATA_READ
#define DEMO_AUDIO_DATA_READ  NX_NULL
#endif /* DEMO_AUDIO_DATA_READ */

#endif /* DEMO_RTSP_OVER_RTP_H */
