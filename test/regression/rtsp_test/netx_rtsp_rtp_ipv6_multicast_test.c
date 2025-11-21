/* This case tests RTSP with RTP in multicast mode. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "netxtestcontrol.h"

extern void test_control_return(UINT);

#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN)
#include    "nx_rtp_sender.h"
#include    "nx_rtsp_server.h"

#define     DEMO_STACK_SIZE         4096
#define     PACKET_SIZE             1536

/* Define device drivers.  */
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

static UCHAR rtsp_stack[DEMO_STACK_SIZE];

static TX_THREAD           client_thread_0;
static NX_PACKET_POOL      client_pool_0;
static NX_IP               client_ip_0;
static NX_TCP_SOCKET       rtsp_client_0;
static NX_UDP_SOCKET       rtp_client_0;

static TX_THREAD           client_thread_1;
static NX_PACKET_POOL      client_pool_1;
static NX_IP               client_ip_1;
static NX_TCP_SOCKET       rtsp_client_1;
static NX_UDP_SOCKET       rtp_client_1;

static TX_THREAD           server_thread;
static NX_PACKET_POOL      server_pool;
static NX_IP               server_ip;
static NX_RTSP_SERVER      rtsp_server;
static NX_RTP_SENDER       rtp_server;
static NX_RTP_SESSION      rtp_session_video;
static NX_RTP_SESSION      rtp_session_audio;

static UINT                error_counter;

static TX_SEMAPHORE        semaphore_server_start;
static TX_SEMAPHORE        semaphore_client_0_done;
static TX_SEMAPHORE        semaphore_client_1_done;
static TX_SEMAPHORE        semaphore_play;
static TX_SEMAPHORE        semaphore_rtp_send;

static NXD_ADDRESS         group_address[8];
static NXD_ADDRESS         server_ip_address;
static NXD_ADDRESS         client_0_ip_address;
static NXD_ADDRESS         client_1_ip_address;

static void thread_client_0_entry(ULONG thread_input);
static void thread_client_1_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);
static UINT rtsp_describe_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);
static UINT rtsp_setup_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr);
static UINT rtsp_play_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);
static UINT rtsp_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);
static UINT rtsp_pause_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);
static UINT rtsp_set_parameter_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length);
static UINT rtsp_disconnect_callback(NX_RTSP_CLIENT *rtsp_client_ptr);

/* Define ipv6 multicast group address. */
#define GROUP_ADDRESS_0         0xff020000
#define GROUP_ADDRESS_1         0x00000000
#define GROUP_ADDRESS_2         0x00000000
#define GROUP_ADDRESS_3         0x01020301

#define TEST_SERVER_ADDRESS     IP_ADDRESS(1,2,3,4)
#define TEST_CLIENT_0_ADDRESS   IP_ADDRESS(1,2,3,5)
#define TEST_CLIENT_1_ADDRESS   IP_ADDRESS(1,2,3,6)
#define RTSP_SERVER_PORT        554

#define RTSP_SESSION_ID      23754311
#define RTP_VIDEO_RTP_PORT   49752
#define RTP_VIDEO_RTCP_PORT  49753
#define RTP_AUDIO_RTP_PORT   49754
#define RTP_AUDIO_RTCP_PORT  49755

#define RTP_PAYLOAD_TYPE_VIDEO       96
#define RTP_PAYLOAD_TYPE_AUDIO       97
#define RTP_TIMESTAMP_INIT_VALUE     40
#define CNAME                        "AzureRTOS@microsoft.com"
#define TEST_MSW                     123
#define TEST_LSW                     456
#define TEST_TTL                     128

static UCHAR rtsp_option_request[] = "\
OPTIONS rtsp://[2001::4]:554/live.stream RTSP/1.0\r\n\
CSeq: 2\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\r\n\
";

static UCHAR rtsp_describe_request[] = "\
DESCRIBE rtsp://[2001::4]:554/live.stream RTSP/1.0\r\n\
CSeq: 3\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Accept: application/sdp\r\n\r\n\
";

static UCHAR rtsp_setup_request_0[] = "\
SETUP rtsp://[2001::4]:554/live.stream/trackID=0 RTSP/1.0\r\n\
CSeq: 4\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Transport: RTP/AVP;multicast;port=49752-49753\r\n\r\n\
";

static UCHAR rtsp_setup_request_1[] = "\
SETUP rtsp://[2001::4]:554/live.stream/trackID=1 RTSP/1.0\r\n\
CSeq: 5\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Transport: RTP/AVP;multicast;port=49754-49755\r\n\
Session: 23754311\r\n\r\n\
";

static UCHAR rtsp_play_request[] = "\
PLAY rtsp://[2001::4]:554/live.stream RTSP/1.0\r\n\
CSeq: 6\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754311\r\n\
Range: npt=0.000-\r\n\r\n\
";

static UCHAR rtsp_pause_request[] = "\
PAUSE rtsp://[2001::4]:554/live.stream RTSP/1.0\r\n\
CSeq: 7\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754311\r\n\r\n\
";

static UCHAR rtsp_teardown_request[] = "\
TEARDOWN rtsp://[2001::4]:554/live.stream RTSP/1.0\r\n\
CSeq: 8\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754311\r\n\r\n\
";

typedef enum
{
    OPTION_INDEX,
    DESCRIBE_INDEX,
    SETUP_0_INDEX,
    SETUP_1_INDEX,
    PLAY_INDEX,
    PAUSE_INDEX,
    TEARDOWN_INDEX
}REQUEST_INDEX;

static UCHAR *rtsp_request_list[] =
{
rtsp_option_request,
rtsp_describe_request,
rtsp_setup_request_0,
rtsp_setup_request_1,
rtsp_play_request,
rtsp_pause_request,
rtsp_teardown_request,
};

static UINT rtsp_request_size[] =
{
sizeof(rtsp_option_request) - 1,
sizeof(rtsp_describe_request) - 1,
sizeof(rtsp_setup_request_0) - 1,
sizeof(rtsp_setup_request_1) - 1,
sizeof(rtsp_play_request) - 1,
sizeof(rtsp_pause_request) - 1,
sizeof(rtsp_teardown_request) - 1,
};

static UINT rtsp_request_num = sizeof(rtsp_request_size) / sizeof(UINT);

static UCHAR rtp_data[] = "rtp data for test";

static CHAR *sdp="v=0\r\ns=MPEG-1 or 2 Audio, streamed by the NetX RTSP Server\r\n\
m=video 6002 RTP/AVP 96\r\n\
c=IN IP4 ff02:0000:0000:0000:0000:0000:0102:0301/20\r\n\
a=rtpmap:96 H264/90000\r\n\
a=fmtp:96 profile-level-id=42A01E; packetization-mode=1\r\n\
a=control:trackID=0\r\n\
m=audio 6002 RTP/AVP 97\r\n\
c=IN IP4 ff02:0000:0000:0000:0000:0000:0102:0301/20\r\n\
a=rtpmap:97 mpeg4-generic/44100/1\r\n\
a=fmtp:97 SizeLength=13\r\n\
a=control:trackID=1\r\n";

static UINT video_seq = 0, audio_seq = 0;

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtsp_rtp_multicast_test_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;


    error_counter = 0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&server_thread, "Test Server thread", thread_server_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "Test Server Packet Pool", PACKET_SIZE,
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    CHECK_STATUS(0, status);

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, "Test Server IP", TEST_SERVER_ADDRESS,
                          0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    CHECK_STATUS(0, status);

    /* Enable IPv6 */
    nxd_ipv6_enable(&server_ip);

    /* Set server ip primary link local address. */
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    server_ip_address.nxd_ip_address.v6[0] = 0x20010000;
    server_ip_address.nxd_ip_address.v6[1] = 0;
    server_ip_address.nxd_ip_address.v6[2] = 0;
    server_ip_address.nxd_ip_address.v6[3] = 4;
    status = nxd_ipv6_address_set(&server_ip, 0, &server_ip_address, 64, NULL);
    CHECK_STATUS(0, status);

    status = nxd_icmp_enable(&server_ip);
    CHECK_STATUS(0, status);

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status = nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    CHECK_STATUS(0, status);


     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&server_ip);
    CHECK_STATUS(0, status);

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&server_ip);
    CHECK_STATUS(0, status);

    /* Create the Test Client thread. */
    status = tx_thread_create(&client_thread_0, "Test Client 0", thread_client_0_entry, 0,
                              pointer, DEMO_STACK_SIZE,
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    CHECK_STATUS(0, status);

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool_0, "Test Client Packet Pool 0", PACKET_SIZE,
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    CHECK_STATUS(0, status);

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip_0, "Test Client IP 0", TEST_CLIENT_0_ADDRESS,
                          0xFFFFFF00UL, &client_pool_0, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    CHECK_STATUS(0, status);

    /* Enable IPv6 */
    nxd_ipv6_enable(&client_ip_0);

    /* Set client 0 ip primary link local address. */
    client_0_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    client_0_ip_address.nxd_ip_address.v6[0] = 0x20010000;
    client_0_ip_address.nxd_ip_address.v6[1] = 0;
    client_0_ip_address.nxd_ip_address.v6[2] = 0;
    client_0_ip_address.nxd_ip_address.v6[3] = 3;
    status = nxd_ipv6_address_set(&client_ip_0, 0, &client_0_ip_address, 64, NULL);
    CHECK_STATUS(0, status);

    status = nxd_icmp_enable(&client_ip_0);
    CHECK_STATUS(0, status);

    status  = nx_arp_enable(&client_ip_0, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    CHECK_STATUS(0, status);

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip_0);
    CHECK_STATUS(0, status);

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&client_ip_0);
    CHECK_STATUS(0, status);

    /* Create the Test Client thread. */
    status = tx_thread_create(&client_thread_1, "Test Client 1", thread_client_1_entry, 0,
                              pointer, DEMO_STACK_SIZE,
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    CHECK_STATUS(0, status);

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool_1, "Test Client Packet Pool 1", PACKET_SIZE,
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    CHECK_STATUS(0, status);

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip_1, "Test Client IP 1", TEST_CLIENT_1_ADDRESS,
                          0xFFFFFF00UL, &client_pool_1, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    CHECK_STATUS(0, status);

    /* Enable IPv6 */
    nxd_ipv6_enable(&client_ip_1);

    /* Set client 1 ip primary link local address. */
    client_1_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    client_1_ip_address.nxd_ip_address.v6[0] = 0x20010000;
    client_1_ip_address.nxd_ip_address.v6[1] = 0;
    client_1_ip_address.nxd_ip_address.v6[2] = 0;
    client_1_ip_address.nxd_ip_address.v6[3] = 2;
    status = nxd_ipv6_address_set(&client_ip_1, 0, &client_1_ip_address, 64, NULL);
    CHECK_STATUS(0, status);

    status = nxd_icmp_enable(&client_ip_1);
    CHECK_STATUS(0, status);

    status  = nx_arp_enable(&client_ip_1, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    CHECK_STATUS(0, status);

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip_1);
    CHECK_STATUS(0, status);

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&client_ip_1);
    CHECK_STATUS(0, status);

    /* Create semaphores.  */
    tx_semaphore_create(&semaphore_server_start, "semaphore server start", 0);
    tx_semaphore_create(&semaphore_client_0_done, "semaphore client 0 done", 0);
    tx_semaphore_create(&semaphore_client_1_done, "semaphore client 1 done", 0);
    tx_semaphore_create(&semaphore_play, "semaphore play", 0);
    tx_semaphore_create(&semaphore_rtp_send, "semaphore rtp send", 0);
}

void thread_client_0_entry(ULONG thread_input)
{
UINT            i, status;
NX_PACKET       *packet_ptr;
UCHAR           *buffer_ptr;
UCHAR           temp_string[256];


    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Enable IGMP & join in multicast group.  */
    status = nx_igmp_enable(&client_ip_0);
    status = nxd_ipv6_multicast_interface_join(&client_ip_0, &group_address[0],  0);
    CHECK_STATUS(0, status);

    status = nx_tcp_socket_create(&client_ip_0, &rtsp_client_0, "Test Client Socket 0",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    CHECK_STATUS(0, status);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&rtsp_client_0, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Create the rtp client socket.  */
    status = nx_udp_socket_create(&client_ip_0, &rtp_client_0, "RTCP Client Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    CHECK_STATUS(0, status);

    status =  nx_udp_socket_bind(&rtp_client_0, RTP_VIDEO_RTP_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Wait test server started.  */
    tx_semaphore_get(&semaphore_server_start, NX_WAIT_FOREVER);

    status = nxd_tcp_client_socket_connect(&rtsp_client_0, &server_ip_address, RTSP_SERVER_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    for ( i = 0; i < rtsp_request_num; i++)
    {

        /* Send RTSP request data.  */
        status = nx_packet_allocate(&client_pool_0, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, rtsp_request_list[i], rtsp_request_size[i], &client_pool_0, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_tcp_socket_send(&rtsp_client_0, packet_ptr, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Receive the response from RTSP server.  */
        status = nx_tcp_socket_receive(&rtsp_client_0, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Check response status code.  */
        status = memcmp(packet_ptr -> nx_packet_prepend_ptr, "RTSP/1.0 200 OK", sizeof("RTSP/1.0 200 OK") - 1);
        CHECK_STATUS(0, status);

        /* Terminate the string.  */
        *(packet_ptr -> nx_packet_append_ptr) = NX_NULL;
        memset(temp_string, 0, sizeof(temp_string));

        if (i == DESCRIBE_INDEX)
        {

            /* Check the SDP.  */
            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "\r\n\r\n");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr + 4, sdp, sizeof(sdp) - 1);
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else if (i == SETUP_0_INDEX)
        {

            sprintf(temp_string, "Transport: RTP/AVP;multicast;destination=FF02:0000:0000:0000:0000:0000:0102:0301;port=%d-%d;ttl=%d",
                    RTP_VIDEO_RTP_PORT, RTP_VIDEO_RTCP_PORT, TEST_TTL);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "Transport");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, temp_string, strlen(temp_string));
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else if (i == SETUP_1_INDEX)
        {

            sprintf(temp_string, "Transport: RTP/AVP;multicast;destination=FF02:0000:0000:0000:0000:0000:0102:0301;port=%d-%d;ttl=%d",
                    RTP_AUDIO_RTP_PORT, RTP_AUDIO_RTCP_PORT, TEST_TTL);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "Transport");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, temp_string, strlen(temp_string));
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else if (i == PLAY_INDEX)
        {

            sprintf(temp_string,
                    "RTP-Info: url=rtsp://[2001::4]:554/live.stream/trackID=0;seq=%d;rtptime=%d,url=rtsp://[2001::4]:554/live.stream/trackID=1;seq=%d;rtptime=%d",
                    video_seq, RTP_TIMESTAMP_INIT_VALUE, audio_seq, RTP_TIMESTAMP_INIT_VALUE);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "RTP-Info");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, temp_string, strlen(temp_string));
            CHECK_STATUS(0, status);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "Range");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, "Range: npt=0.0-", sizeof("Range: npt=0.0-") - 1);
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);

            tx_semaphore_get(&semaphore_rtp_send, NX_WAIT_FOREVER);

            /* Receive rtp data packet. */
            status = nx_udp_socket_receive(&rtp_client_0, &packet_ptr, 5 * TX_TIMER_TICKS_PER_SECOND);
            CHECK_STATUS(0, status);

            status = memcmp(packet_ptr -> nx_packet_prepend_ptr + 12, rtp_data, sizeof(rtp_data) - 1);
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else if (i == PAUSE_INDEX)
        {

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "Range");
            if (buffer_ptr != NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            nx_packet_release(packet_ptr);
        }
        else
        {
            nx_packet_release(packet_ptr);
        }
    }

    nx_tcp_socket_disconnect(&rtsp_client_0, NX_IP_PERIODIC_RATE);

    /* Set the flag.  */
    tx_semaphore_put(&semaphore_client_0_done);
    nx_tcp_client_socket_unbind(&rtsp_client_0);
    nx_tcp_socket_delete(&rtsp_client_0);
}

void thread_client_1_entry(ULONG thread_input)
{
UINT            i, status;
NX_PACKET       *packet_ptr;
UCHAR           *buffer_ptr;
UCHAR           temp_string[256];


    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Enable IGMP & join in multicast group.  */
    status = nx_igmp_enable(&client_ip_1);
    status = nxd_ipv6_multicast_interface_join(&client_ip_1, &group_address[0],  0);
    CHECK_STATUS(0, status);

    status = nx_tcp_socket_create(&client_ip_1, &rtsp_client_1, "Test Client Socket 1",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    CHECK_STATUS(0, status);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&rtsp_client_1, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Create the rtp client socket.  */
    status = nx_udp_socket_create(&client_ip_1, &rtp_client_1, "RTCP Client Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    CHECK_STATUS(0, status);

    status =  nx_udp_socket_bind(&rtp_client_1, RTP_VIDEO_RTP_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Wait test server started.  */
    tx_semaphore_get(&semaphore_server_start, NX_WAIT_FOREVER);

    status = nxd_tcp_client_socket_connect(&rtsp_client_1, &server_ip_address, RTSP_SERVER_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    for ( i = 0; i < rtsp_request_num; i++)
    {

        /* Send RTSP request data.  */
        status = nx_packet_allocate(&client_pool_1, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, rtsp_request_list[i], rtsp_request_size[i], &client_pool_1, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_tcp_socket_send(&rtsp_client_1, packet_ptr, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Receive the response from RTSP server.  */
        status = nx_tcp_socket_receive(&rtsp_client_1, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Check response status code.  */
        status = memcmp(packet_ptr -> nx_packet_prepend_ptr, "RTSP/1.0 200 OK", sizeof("RTSP/1.0 200 OK") - 1);
        CHECK_STATUS(0, status);

        /* Terminate the string.  */
        *(packet_ptr -> nx_packet_append_ptr) = NX_NULL;
        memset(temp_string, 0, sizeof(temp_string));

        if (i == DESCRIBE_INDEX)
        {

            /* Check the SDP.  */
            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "\r\n\r\n");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr + 4, sdp, sizeof(sdp) - 1);
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else if (i == SETUP_0_INDEX)
        {

            sprintf(temp_string, "Transport: RTP/AVP;multicast;destination=FF02:0000:0000:0000:0000:0000:0102:0301;port=%d-%d;ttl=%d",
                    RTP_VIDEO_RTP_PORT, RTP_VIDEO_RTCP_PORT, TEST_TTL);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "Transport");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, temp_string, strlen(temp_string));
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else if (i == SETUP_1_INDEX)
        {

            sprintf(temp_string, "Transport: RTP/AVP;multicast;destination=FF02:0000:0000:0000:0000:0000:0102:0301;port=%d-%d;ttl=%d",
                    RTP_AUDIO_RTP_PORT, RTP_AUDIO_RTCP_PORT, TEST_TTL);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "Transport");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, temp_string, strlen(temp_string));
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else if (i == PLAY_INDEX)
        {

            sprintf(temp_string,
                    "RTP-Info: url=rtsp://[2001::4]:554/live.stream/trackID=0;seq=%d;rtptime=%d,url=rtsp://[2001::4]:554/live.stream/trackID=1;seq=%d;rtptime=%d",
                    video_seq, RTP_TIMESTAMP_INIT_VALUE, audio_seq, RTP_TIMESTAMP_INIT_VALUE);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "RTP-Info");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, temp_string, strlen(temp_string));
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);

            tx_semaphore_get(&semaphore_rtp_send, NX_WAIT_FOREVER);

            /* Receive rtp data packet. */
            status = nx_udp_socket_receive(&rtp_client_1, &packet_ptr, 5 * TX_TIMER_TICKS_PER_SECOND);
            CHECK_STATUS(0, status);

            status = memcmp(packet_ptr -> nx_packet_prepend_ptr + 12, rtp_data, sizeof(rtp_data) - 1);
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else
        {
            nx_packet_release(packet_ptr);
        }
    }

    nx_tcp_socket_disconnect(&rtsp_client_1, NX_IP_PERIODIC_RATE);

    /* Set the flag.  */
    tx_semaphore_put(&semaphore_client_1_done);
    nx_tcp_client_socket_unbind(&rtsp_client_1);
    nx_tcp_socket_delete(&rtsp_client_1);
}

/* Define the helper Test server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT status;
NX_PACKET *packet_ptr;
NXD_ADDRESS client_ip_address;


    /* Print out test information banner.  */
    printf("NetX Test:   RTSP RTP Multicast Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Give NetX a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Set the group address .  */
    group_address[0].nxd_ip_version = NX_IP_VERSION_V6;
    group_address[0].nxd_ip_address.v6[0] = GROUP_ADDRESS_0;
    group_address[0].nxd_ip_address.v6[1] = GROUP_ADDRESS_1;
    group_address[0].nxd_ip_address.v6[2] = GROUP_ADDRESS_2;
    group_address[0].nxd_ip_address.v6[3] = GROUP_ADDRESS_3;

    /* Enable IGMP & join in multicast group.  */
    status = nx_igmp_enable(&server_ip);
    CHECK_STATUS(0, status);
    status = nxd_ipv6_multicast_interface_join(&server_ip, &group_address[0],  0);
    CHECK_STATUS(0, status);

    /* Create RTSP server.  */
    status = nx_rtsp_server_create(&rtsp_server, "RTSP Server", sizeof("RTSP Server") - 1,&server_ip, &server_pool, rtsp_stack, DEMO_STACK_SIZE, 3, RTSP_SERVER_PORT, rtsp_disconnect_callback);
    CHECK_STATUS(0, status);

    /* Set callback functions. */
    nx_rtsp_server_describe_callback_set(&rtsp_server, rtsp_describe_callback);
    nx_rtsp_server_setup_callback_set(&rtsp_server, rtsp_setup_callback);
    nx_rtsp_server_play_callback_set(&rtsp_server, rtsp_play_callback);
    nx_rtsp_server_teardown_callback_set(&rtsp_server, rtsp_teardown_callback);
    nx_rtsp_server_pause_callback_set(&rtsp_server, rtsp_pause_callback);
    nx_rtsp_server_set_parameter_callback_set(&rtsp_server, rtsp_set_parameter_callback);

    /* Create RTP sender.  */
    status = nx_rtp_sender_create(&rtp_server, &server_ip, &server_pool, CNAME, sizeof(CNAME) - 1);
    CHECK_STATUS(0, status);

    /* Setup rtp sender session.  */
    client_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    client_ip_address.nxd_ip_address.v6[0] = GROUP_ADDRESS_0;
    client_ip_address.nxd_ip_address.v6[1] = GROUP_ADDRESS_1;
    client_ip_address.nxd_ip_address.v6[2] = GROUP_ADDRESS_2;
    client_ip_address.nxd_ip_address.v6[3] = GROUP_ADDRESS_3;
    status = nx_rtp_sender_session_create(&rtp_server, &rtp_session_video, RTP_PAYLOAD_TYPE_VIDEO,
                                          0, &client_ip_address,
                                          RTP_VIDEO_RTP_PORT, RTP_VIDEO_RTCP_PORT);
    CHECK_STATUS(0, status);

    status = nx_rtp_sender_session_create(&rtp_server, &rtp_session_audio, RTP_PAYLOAD_TYPE_VIDEO,
                                          0, &client_ip_address,
                                          RTP_AUDIO_RTP_PORT, RTP_AUDIO_RTCP_PORT);
    CHECK_STATUS(0, status);

    /* Start RTSP server. */
    nx_rtsp_server_start(&rtsp_server);

    tx_semaphore_put(&semaphore_server_start);
    tx_semaphore_put(&semaphore_server_start);

    tx_semaphore_get(&semaphore_play, NX_WAIT_FOREVER);

    /* Allocate a packet */
    status = nx_rtp_sender_session_packet_allocate(&rtp_session_video, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Copy payload data into the packet. */
    status = nx_packet_data_append(packet_ptr, rtp_data, sizeof(rtp_data) - 1, rtp_server.nx_rtp_sender_ip_ptr -> nx_ip_default_packet_pool, 5 * NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Send packet.  */
    status = nx_rtp_sender_session_packet_send(&rtp_session_video, packet_ptr, RTP_TIMESTAMP_INIT_VALUE, TEST_MSW, TEST_LSW, 1);
    CHECK_STATUS(0, status);

    tx_semaphore_put(&semaphore_rtp_send);
    tx_semaphore_put(&semaphore_rtp_send);

    tx_semaphore_get(&semaphore_client_0_done, NX_WAIT_FOREVER);
    tx_semaphore_get(&semaphore_client_1_done, NX_WAIT_FOREVER);

    status = nx_rtsp_server_delete(&rtsp_server);
    CHECK_STATUS(0, status);

    /* Check packet pool.  */
    if (server_pool.nx_packet_pool_available != server_pool.nx_packet_pool_total)
    {
        error_counter++;
    }

    if (client_pool_0.nx_packet_pool_available != client_pool_0.nx_packet_pool_total)
    {
        error_counter++;
    }

    if (client_pool_1.nx_packet_pool_available != client_pool_1.nx_packet_pool_total)
    {
        error_counter++;
    }

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}

static UINT rtsp_describe_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length)
{
UINT status;

    status = nx_rtsp_server_sdp_set(rtsp_client_ptr, sdp, strlen(sdp));
    return(status);
}

static UINT rtsp_setup_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr)
{
UINT status;
UINT rtp_port, rtcp_port;

    /* Get the created and found ports */
    status = nx_rtp_sender_port_get(&rtp_server, &rtp_port, &rtcp_port);
    if (status)
    {
        return(status);
    }
    transport_ptr -> server_rtp_port = rtp_port;
    transport_ptr -> server_rtcp_port = rtcp_port;

    transport_ptr -> client_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    transport_ptr -> client_ip_address.nxd_ip_address.v6[0] = GROUP_ADDRESS_0;
    transport_ptr -> client_ip_address.nxd_ip_address.v6[1] = GROUP_ADDRESS_1;
    transport_ptr -> client_ip_address.nxd_ip_address.v6[2] = GROUP_ADDRESS_2;
    transport_ptr -> client_ip_address.nxd_ip_address.v6[3] = GROUP_ADDRESS_3;
    transport_ptr -> multicast_ttl = TEST_TTL;

    if (strstr(uri, "trackID=0"))
    {
        transport_ptr -> client_rtp_port = RTP_VIDEO_RTP_PORT;
        transport_ptr -> client_rtcp_port = RTP_VIDEO_RTCP_PORT;

        /* Set static session ID for test.  */
        rtsp_client_ptr -> nx_rtsp_client_session_id = RTSP_SESSION_ID;
    }
    else if (strstr(uri, "trackID=1"))
    {
        transport_ptr -> client_rtp_port = RTP_AUDIO_RTP_PORT;
        transport_ptr -> client_rtcp_port = RTP_AUDIO_RTCP_PORT;
    }
    else
    {
        status = NX_RTSP_SERVER_INVALID_REQUEST;
    }

    return(status);
}

static UINT rtsp_play_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length)
{
UINT status;

    /* Retrieve the sequence number through rtp sender functions */
    nx_rtp_sender_session_sequence_number_get(&rtp_session_video, &video_seq);
    nx_rtp_sender_session_sequence_number_get(&rtp_session_audio, &audio_seq);

    status = nx_rtsp_server_rtp_info_set(rtsp_client_ptr, "trackID=0", sizeof("trackID=0") - 1, video_seq, RTP_TIMESTAMP_INIT_VALUE);
    CHECK_STATUS(0, status);

    status = nx_rtsp_server_rtp_info_set(rtsp_client_ptr, "trackID=1", sizeof("trackID=1") - 1, audio_seq, RTP_TIMESTAMP_INIT_VALUE);
    CHECK_STATUS(0, status);

    tx_semaphore_put(&semaphore_play);

    return(status);
}

static UINT rtsp_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length)
{

    nx_rtp_sender_session_delete(&rtp_session_video);
    nx_rtp_sender_session_delete(&rtp_session_audio);

    return(NX_SUCCESS);
}

static UINT rtsp_pause_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length)
{
    return(NX_SUCCESS);
}

static UINT rtsp_set_parameter_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length)
{
    return(NX_SUCCESS);
}

static UINT rtsp_disconnect_callback(NX_RTSP_CLIENT *rtsp_client_ptr)
{
    return(NX_SUCCESS);
}


#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtsp_rtp_multicast_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RTSP RTP Multicast Test...................................N/A\n");

    test_control_return(3);
}
#endif

