/* This case tests RTSP with RTP. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "netxtestcontrol.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN) && (NX_MAX_PHYSICAL_INTERFACES > 1)
#include    "nx_rtp_sender.h"
#include    "nx_rtsp_server.h"

#define     DEMO_STACK_SIZE         4096
#define     PACKET_SIZE             1536

/* Define device drivers.  */
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

static UCHAR rtsp_stack[DEMO_STACK_SIZE];

static TX_THREAD           client_0_thread;
static TX_THREAD           client_1_thread;
static NX_PACKET_POOL      client_0_pool;
static NX_PACKET_POOL      client_1_pool;
static NX_IP               client_0_ip;
static NX_IP               client_1_ip;
static NX_TCP_SOCKET       rtsp_client_0;
static NX_TCP_SOCKET       rtsp_client_1;
static NX_UDP_SOCKET       rtp_client_0;
static NX_UDP_SOCKET       rtp_client_1;

static TX_THREAD           server_thread;
static NX_PACKET_POOL      server_pool;
static NX_IP               server_ip;
static NX_RTSP_SERVER      rtsp_server;
static NX_RTP_SENDER       rtp_server;
static NX_RTP_SESSION      rtp_session_0;
static NX_RTP_SESSION      rtp_session_1;

static UINT                error_counter;

static TX_SEMAPHORE        semaphore_client_0_start;
static TX_SEMAPHORE        semaphore_client_1_start;
static TX_SEMAPHORE        semaphore_rtp_send_0;
static TX_SEMAPHORE        semaphore_rtp_send_1;
static TX_EVENT_FLAGS_GROUP events_play;


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

#define TEST_SERVER_ADDRESS    IP_ADDRESS(1,2,3,4)
#define TEST_SERVER_1_ADDRESS  IP_ADDRESS(10,3,3,4)
#define TEST_CLIENT_0_ADDRESS  IP_ADDRESS(1,2,3,5)
#define TEST_CLIENT_1_ADDRESS  IP_ADDRESS(10,3,3,5)
#define RTSP_SERVER_PORT       554

#define RTSP_0_SESSION_ID    23754311
#define RTSP_1_SESSION_ID    23754312
#define RTP_0_RTP_PORT       49752
#define RTP_0_RTCP_PORT      49753
#define RTP_1_RTP_PORT       49754
#define RTP_1_RTCP_PORT      49755

#define RTP_PAYLOAD_TYPE_0           96
#define RTP_PAYLOAD_TYPE_1           97
#define RTP_TIMESTAMP_INIT_VALUE     40
#define CNAME                        "AzureRTOS@microsoft.com"
#define TEST_MSW                     123
#define TEST_LSW                     456

/* Define events for the server task */
#define ALL_EVENTS                   ((ULONG)0xFFFFFFFF)
#define PLAY_0_EVENT                 ((ULONG)0x00000001)
#define PLAY_1_EVENT                 ((ULONG)0x00000002)
#define DONE_0_EVENT                 ((ULONG)0x00000004)
#define DONE_1_EVENT                 ((ULONG)0x00000008)

static UCHAR rtsp_0_option_request[] = "\
OPTIONS rtsp://1.2.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 2\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\r\n\
";

static UCHAR rtsp_1_option_request[] = "\
OPTIONS rtsp://10.3.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 2\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\r\n\
";

static UCHAR rtsp_0_describe_request[] = "\
DESCRIBE rtsp://1.2.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 3\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Accept: application/sdp\r\n\r\n\
";

static UCHAR rtsp_1_describe_request[] = "\
DESCRIBE rtsp://10.3.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 3\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Accept: application/sdp\r\n\r\n\
";

static UCHAR rtsp_0_setup_request[] = "\
SETUP rtsp://1.2.3.4:554/live.stream/trackID=0 RTSP/1.0\r\n\
CSeq: 4\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Transport: RTP/AVP;unicast;client_port=49752-49753\r\n\r\n\
";

static UCHAR rtsp_1_setup_request[] = "\
SETUP rtsp://10.3.3.4:554/live.stream/trackID=1 RTSP/1.0\r\n\
CSeq: 4\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Transport: RTP/AVP;unicast;client_port=49754-49755\r\n\r\n\
";

static UCHAR rtsp_0_play_request[] = "\
PLAY rtsp://1.2.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 6\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754311\r\n\
Range: npt=0.000-\r\n\r\n\
";

static UCHAR rtsp_1_play_request[] = "\
PLAY rtsp://10.3.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 6\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754312\r\n\
Range: npt=0.000-\r\n\r\n\
";

static UCHAR rtsp_0_pause_request[] = "\
PAUSE rtsp://1.2.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 7\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754311\r\n\r\n\
";

static UCHAR rtsp_1_pause_request[] = "\
PAUSE rtsp://10.3.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 7\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754312\r\n\r\n\
";

static UCHAR rtsp_0_teardown_request[] = "\
TEARDOWN rtsp://1.2.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 8\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754311\r\n\r\n\
";

static UCHAR rtsp_1_teardown_request[] = "\
TEARDOWN rtsp://10.3.3.4:554/live.stream RTSP/1.0\r\n\
CSeq: 8\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754312\r\n\r\n\
";

typedef enum
{
    OPTION_INDEX,
    DESCRIBE_INDEX,
    SETUP_INDEX,
    PLAY_INDEX,
    TEARDOWN_INDEX
}REQUEST_INDEX;

static UCHAR *client_0_rtsp_request_list[] =
{
rtsp_0_option_request,
rtsp_0_describe_request,
rtsp_0_setup_request,
rtsp_0_play_request,
rtsp_0_teardown_request,
};

static UCHAR *client_1_rtsp_request_list[] =
{
rtsp_1_option_request,
rtsp_1_describe_request,
rtsp_1_setup_request,
rtsp_1_play_request,
rtsp_1_teardown_request,
};

static UINT client_0_rtsp_request_size[] =
{
sizeof(rtsp_0_option_request) - 1,
sizeof(rtsp_0_describe_request) - 1,
sizeof(rtsp_0_setup_request) - 1,
sizeof(rtsp_0_play_request) - 1,
sizeof(rtsp_0_teardown_request) - 1,
};

static UINT client_1_rtsp_request_size[] =
{
sizeof(rtsp_1_option_request) - 1,
sizeof(rtsp_1_describe_request) - 1,
sizeof(rtsp_1_setup_request) - 1,
sizeof(rtsp_1_play_request) - 1,
sizeof(rtsp_1_teardown_request) - 1,
};

static UINT client_0_rtsp_request_num = sizeof(client_0_rtsp_request_size) / sizeof(UINT);
static UINT client_1_rtsp_request_num = sizeof(client_1_rtsp_request_size) / sizeof(UINT);

static UCHAR rtp_data[] = "rtp data for test";

static CHAR *sdp="v=0\r\ns=MPEG-1 or 2 Audio, streamed by the NetX RTSP Server\r\n\
m=video 0 RTP/AVP 96\r\n\
a=rtpmap:96 H264/90000\r\n\
a=fmtp:96 profile-level-id=42A01E; packetization-mode=1\r\n\
a=control:trackID=0\r\n\
m=audio 0 RTP/AVP 97\r\n\
a=rtpmap:97 mpeg4-generic/44100/1\r\n\
a=fmtp:97 SizeLength=13\r\n\
a=control:trackID=1\r\n";

static UINT seq_0 = 0, seq_1 = 0;

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtp_multi_interfaces_test_application_define(void *first_unused_memory)
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

    /* Attach a new ip interface to server ip. */
    status = nx_ip_interface_attach(&server_ip, "Test Server IP 1 Interface", TEST_SERVER_1_ADDRESS,
                                    0xFFFFFF00UL, _nx_ram_network_driver_1024);
    pointer = pointer + 2048;
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
    status = tx_thread_create(&client_0_thread, "Test Client 0", thread_client_0_entry, 0,
                              pointer, DEMO_STACK_SIZE,
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    CHECK_STATUS(0, status);
    status = tx_thread_create(&client_1_thread, "Test Client 1", thread_client_1_entry, 0,
                              pointer, DEMO_STACK_SIZE,
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    CHECK_STATUS(0, status);

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_0_pool, "Test Client Packet Pool", PACKET_SIZE,
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    CHECK_STATUS(0, status);
    status =  nx_packet_pool_create(&client_1_pool, "Test Client Packet Pool", PACKET_SIZE,
                                    pointer, PACKET_SIZE * 8);
    pointer = pointer + PACKET_SIZE * 8;
    CHECK_STATUS(0, status);

    /* Create an IP instance.  */
    status = nx_ip_create(&client_0_ip, "Test Client IP 0", TEST_CLIENT_0_ADDRESS,
                          0xFFFFFF00UL, &client_0_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    CHECK_STATUS(0, status);

    /* Create an IP instance.  */
    status = nx_ip_create(&client_1_ip, "Test Client IP 1", TEST_CLIENT_1_ADDRESS,
                          0xFFFFFF00UL, &client_1_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    CHECK_STATUS(0, status);

    /* Enable arp */
    status  = nx_arp_enable(&client_0_ip, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    CHECK_STATUS(0, status);
    status  = nx_arp_enable(&client_1_ip, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    CHECK_STATUS(0, status);

    /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_0_ip);
    CHECK_STATUS(0, status);
    status = nx_tcp_enable(&client_1_ip);
    CHECK_STATUS(0, status);

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&client_0_ip);
    CHECK_STATUS(0, status);
    status = nx_udp_enable(&client_1_ip);
    CHECK_STATUS(0, status);

    /* Create semaphores and events group.  */
    tx_semaphore_create(&semaphore_client_0_start, "semaphore client 0 start", 0);
    tx_semaphore_create(&semaphore_client_1_start, "semaphore client 1 start", 0);
    tx_semaphore_create(&semaphore_rtp_send_0, "semaphore rtp send 0", 0);
    tx_semaphore_create(&semaphore_rtp_send_1, "semaphore rtp send 1", 0);
    status = tx_event_flags_create(&events_play, "events play");
    CHECK_STATUS(0, status);
}

void thread_client_0_entry(ULONG thread_input)
{
UINT            i, status;
NX_PACKET       *packet_ptr;
NXD_ADDRESS     server_ip_address;
UCHAR           *buffer_ptr;
UCHAR           temp_string[256];


    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = TEST_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    status = nx_tcp_socket_create(&client_0_ip, &rtsp_client_0, "Test Client 0 Socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    CHECK_STATUS(0, status);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&rtsp_client_0, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Create the rtp client socket.  */
    status = nx_udp_socket_create(&client_0_ip, &rtp_client_0, "RTCP Client 0 Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    CHECK_STATUS(0, status);

    status =  nx_udp_socket_bind(&rtp_client_0, RTP_0_RTP_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Wait test server started.  */
    tx_semaphore_get(&semaphore_client_0_start, NX_WAIT_FOREVER);

    status = nxd_tcp_client_socket_connect(&rtsp_client_0, &server_ip_address, RTSP_SERVER_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    for ( i = 0; i < client_0_rtsp_request_num; i++)
    {

        /* Send RTSP request data.  */
        status = nx_packet_allocate(&client_0_pool, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, client_0_rtsp_request_list[i], client_0_rtsp_request_size[i], &client_0_pool, NX_IP_PERIODIC_RATE);
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
        else if (i == SETUP_INDEX)
        {

            sprintf(temp_string, "Transport: RTP/AVP;unicast;source=1.2.3.4;client_port=%d-%d;server_port=%d-%d;ssrc=%ld",
                    RTP_0_RTP_PORT, RTP_0_RTCP_PORT,
                    rtp_server.nx_rtp_sender_rtp_port,
                    rtp_server.nx_rtp_sender_rtcp_port,
                    rtp_session_0.nx_rtp_session_ssrc);

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
                    "RTP-Info: url=rtsp://1.2.3.4:554/live.stream/trackID=0;seq=%d;rtptime=%d",
                    seq_0, RTP_TIMESTAMP_INIT_VALUE);

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

            tx_semaphore_get(&semaphore_rtp_send_0, NX_WAIT_FOREVER);

            /* Receive rtp data packet. */
            status = nx_udp_socket_receive(&rtp_client_0, &packet_ptr, 5 * TX_TIMER_TICKS_PER_SECOND);
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

    nx_tcp_socket_disconnect(&rtsp_client_0, NX_IP_PERIODIC_RATE);

    /* Set the flag.  */
    tx_event_flags_set(&events_play, DONE_0_EVENT, TX_OR);
    nx_tcp_client_socket_unbind(&rtsp_client_0);
    nx_tcp_socket_delete(&rtsp_client_0);
}

void thread_client_1_entry(ULONG thread_input)
{
UINT            i, status;
NX_PACKET       *packet_ptr;
NXD_ADDRESS     server_ip_address;
UCHAR           *buffer_ptr;
UCHAR           temp_string[256];


    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = TEST_SERVER_1_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    status = nx_tcp_socket_create(&client_1_ip, &rtsp_client_1, "Test Client 1 Socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    CHECK_STATUS(0, status);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&rtsp_client_1, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Create the rtp client socket.  */
    status = nx_udp_socket_create(&client_1_ip, &rtp_client_1, "RTCP Client 1 Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    CHECK_STATUS(0, status);

    status =  nx_udp_socket_bind(&rtp_client_1, RTP_1_RTP_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Wait test server started.  */
    tx_semaphore_get(&semaphore_client_1_start, NX_WAIT_FOREVER);

    status = nxd_tcp_client_socket_connect(&rtsp_client_1, &server_ip_address, RTSP_SERVER_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    for ( i = 0; i < client_1_rtsp_request_num; i++)
    {

        /* Send RTSP request data.  */
        status = nx_packet_allocate(&client_1_pool, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, client_1_rtsp_request_list[i], client_1_rtsp_request_size[i], &client_1_pool, NX_IP_PERIODIC_RATE);
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
        else if (i == SETUP_INDEX)
        {

            sprintf(temp_string, "Transport: RTP/AVP;unicast;source=10.3.3.4;client_port=%d-%d;server_port=%d-%d;ssrc=%ld",
                    RTP_1_RTP_PORT, RTP_1_RTCP_PORT,
                    rtp_server.nx_rtp_sender_rtp_port,
                    rtp_server.nx_rtp_sender_rtcp_port,
                    rtp_session_1.nx_rtp_session_ssrc);

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
                    "RTP-Info: url=rtsp://10.3.3.4:554/live.stream/trackID=1;seq=%d;rtptime=%d",
                    seq_1, RTP_TIMESTAMP_INIT_VALUE);

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

            tx_semaphore_get(&semaphore_rtp_send_1, NX_WAIT_FOREVER);

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
    tx_event_flags_set(&events_play, DONE_1_EVENT, TX_OR);
    nx_tcp_client_socket_unbind(&rtsp_client_1);
    nx_tcp_socket_delete(&rtsp_client_1);
}

/* Define the helper Test server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT status;
NX_PACKET *packet_ptr;
ULONG events = 0;
USHORT client_0_done = NX_FALSE;
USHORT client_1_done = NX_FALSE;

    /* Print out test information banner.  */
    printf("NetX Test:   RTSP RTP Multi Interfaces Test.......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Give NetX a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Create RTSP server.  */
    status = nx_rtsp_server_create(&rtsp_server, "RTSP Server", sizeof("RTSP Server") - 1,&server_ip, &server_pool, rtsp_stack, DEMO_STACK_SIZE, 3, RTSP_SERVER_PORT, rtsp_disconnect_callback);
    CHECK_STATUS(0, status);

    status = nx_rtsp_server_delete(&rtsp_server);
    CHECK_STATUS(0, status);

    status = nx_rtsp_server_create(&rtsp_server, "RTSP Server", sizeof("RTSP Server") - 1,&server_ip, &server_pool, rtsp_stack, DEMO_STACK_SIZE, 3, RTSP_SERVER_PORT, rtsp_disconnect_callback);
    CHECK_STATUS(0, status);

    /* Set callback functions. */
    nx_rtsp_server_describe_callback_set(&rtsp_server, rtsp_describe_callback);
    nx_rtsp_server_setup_callback_set(&rtsp_server, rtsp_setup_callback);
    nx_rtsp_server_play_callback_set(&rtsp_server, rtsp_play_callback);
    nx_rtsp_server_teardown_callback_set(&rtsp_server, rtsp_teardown_callback);
    nx_rtsp_server_pause_callback_set(&rtsp_server, rtsp_pause_callback);
    nx_rtsp_server_set_parameter_callback_set(&rtsp_server, rtsp_set_parameter_callback);

    /* Start RTSP server. */
    status = nx_rtsp_server_start(&rtsp_server);
    CHECK_STATUS(0, status);

    status = nx_rtsp_server_stop(&rtsp_server);
    CHECK_STATUS(0, status);

    status = nx_rtsp_server_start(&rtsp_server);
    CHECK_STATUS(0, status);

    /* Create RTP sender.  */
    status = nx_rtp_sender_create(&rtp_server, &server_ip, &server_pool, CNAME, sizeof(CNAME) - 1);
    CHECK_STATUS(0, status);

    tx_semaphore_put(&semaphore_client_0_start);
    tx_semaphore_put(&semaphore_client_1_start);

    while ((client_0_done) == (NX_FALSE) || (client_1_done == NX_FALSE))
    {

        /* Wait for events to do */
        tx_event_flags_get(&events_play, ALL_EVENTS, TX_OR_CLEAR, &events, TX_WAIT_FOREVER);

        if (events & PLAY_0_EVENT)
        {

            /* Allocate a packet */
            status = nx_rtp_sender_session_packet_allocate(&rtp_session_0, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
            CHECK_STATUS(0, status);

            /* Copy payload data into the packet. */
            status = nx_packet_data_append(packet_ptr, rtp_data, sizeof(rtp_data) - 1, rtp_server.nx_rtp_sender_ip_ptr -> nx_ip_default_packet_pool, 5 * NX_IP_PERIODIC_RATE);
            CHECK_STATUS(0, status);

            /* Send packet.  */
            status = nx_rtp_sender_session_packet_send(&rtp_session_0, packet_ptr, RTP_TIMESTAMP_INIT_VALUE, TEST_MSW, TEST_LSW, 1);
            CHECK_STATUS(0, status);

            tx_semaphore_put(&semaphore_rtp_send_0);
        }

        if (events & PLAY_1_EVENT)
        {

            /* Allocate a packet */
            status = nx_rtp_sender_session_packet_allocate(&rtp_session_1, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
            CHECK_STATUS(0, status);

            /* Copy payload data into the packet. */
            status = nx_packet_data_append(packet_ptr, rtp_data, sizeof(rtp_data) - 1, rtp_server.nx_rtp_sender_ip_ptr -> nx_ip_default_packet_pool, 5 * NX_IP_PERIODIC_RATE);
            CHECK_STATUS(0, status);

            /* Send packet.  */
            status = nx_rtp_sender_session_packet_send(&rtp_session_1, packet_ptr, RTP_TIMESTAMP_INIT_VALUE, TEST_MSW, TEST_LSW, 1);
            CHECK_STATUS(0, status);

            tx_semaphore_put(&semaphore_rtp_send_1);
        }

        if (events & DONE_0_EVENT)
        {
            client_0_done = NX_TRUE;
        }

        if (events & DONE_1_EVENT)
        {
            client_1_done = NX_TRUE;
        }
    }

    /* Stop and delete rtsp server */
    status = nx_rtsp_server_stop(&rtsp_server);
    CHECK_STATUS(0, status);
    status = nx_rtsp_server_delete(&rtsp_server);
    CHECK_STATUS(0, status);

    /* Check packet pool.  */
    CHECK_STATUS(server_pool.nx_packet_pool_available, server_pool.nx_packet_pool_total);
    CHECK_STATUS(client_0_pool.nx_packet_pool_available, client_0_pool.nx_packet_pool_total);
    CHECK_STATUS(client_1_pool.nx_packet_pool_available, client_1_pool.nx_packet_pool_total);

    if (error_counter)
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

    if (strstr(uri, "trackID=0"))
    {
        /* Setup rtp sender session */
        status = nx_rtp_sender_session_create(&rtp_server, &rtp_session_0, RTP_PAYLOAD_TYPE_0,
                                              transport_ptr -> interface_index, &(transport_ptr -> client_ip_address),
                                              transport_ptr -> client_rtp_port, transport_ptr -> client_rtcp_port);
        CHECK_STATUS(0, status);

        /* Obtain generated ssrc */
        status = nx_rtp_sender_session_ssrc_get(&rtp_session_0, &(transport_ptr -> rtp_ssrc));
        CHECK_STATUS(0, status);

        /* Set static session ID for test.  */
        rtsp_client_ptr -> nx_rtsp_client_session_id = RTSP_0_SESSION_ID;
    }
    else if (strstr(uri, "trackID=1"))
    {
        /* Setup rtp sender session */
        status = nx_rtp_sender_session_create(&rtp_server, &rtp_session_1, RTP_PAYLOAD_TYPE_1,
                                              transport_ptr -> interface_index, &(transport_ptr -> client_ip_address),
                                              transport_ptr -> client_rtp_port, transport_ptr -> client_rtcp_port);
        CHECK_STATUS(0, status);

        /* Obtain generated ssrc */
        status = nx_rtp_sender_session_ssrc_get(&rtp_session_1, &(transport_ptr -> rtp_ssrc));
        CHECK_STATUS(0, status);

        /* Set static session ID for test.  */
        rtsp_client_ptr -> nx_rtsp_client_session_id = RTSP_1_SESSION_ID;
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


    if (rtsp_client_ptr -> nx_rtsp_client_request_packet -> nx_packet_address.nx_packet_interface_ptr
        == &(server_ip.nx_ip_interface[0]))
    {

        /* Retrieve the sequence number through rtp sender functions */
        nx_rtp_sender_session_sequence_number_get(&rtp_session_0, &seq_0);

        status = nx_rtsp_server_rtp_info_set(rtsp_client_ptr, "trackID=0", sizeof("trackID=0") - 1, seq_0, RTP_TIMESTAMP_INIT_VALUE);
        CHECK_STATUS(0, status);

        status = nx_rtsp_server_range_npt_set(rtsp_client_ptr, 0, 30000);
        CHECK_STATUS(0, status);

        tx_event_flags_set(&events_play, PLAY_0_EVENT, TX_OR);
    }
    else if (rtsp_client_ptr -> nx_rtsp_client_request_packet -> nx_packet_address.nx_packet_interface_ptr
             == &(server_ip.nx_ip_interface[1]))
    {

        /* Retrieve the sequence number through rtp sender functions */
        nx_rtp_sender_session_sequence_number_get(&rtp_session_1, &seq_1);

        status = nx_rtsp_server_rtp_info_set(rtsp_client_ptr, "trackID=1", sizeof("trackID=1") - 1, seq_1, RTP_TIMESTAMP_INIT_VALUE);
        CHECK_STATUS(0, status);

        tx_event_flags_set(&events_play, PLAY_1_EVENT, TX_OR);
    }
    else
    {
        status = NX_RTSP_SERVER_INVALID_REQUEST;
    }

    return(status);
}

static UINT rtsp_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length)
{

    if (rtsp_client_ptr -> nx_rtsp_client_request_packet -> nx_packet_address.nx_packet_interface_ptr
        == &(server_ip.nx_ip_interface[0]))
    {
        nx_rtp_sender_session_delete(&rtp_session_0);
    }
    else if (rtsp_client_ptr -> nx_rtsp_client_request_packet -> nx_packet_address.nx_packet_interface_ptr
             == &(server_ip.nx_ip_interface[1]))
    {
        nx_rtp_sender_session_delete(&rtp_session_1);
    }
    else
    {
        return(NX_RTSP_SERVER_INVALID_REQUEST);
    }

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
void    netx_rtp_multi_interfaces_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RTSP RTP Multi Interfaces Test.......................................N/A\n");

    test_control_return(3);
}
#endif

