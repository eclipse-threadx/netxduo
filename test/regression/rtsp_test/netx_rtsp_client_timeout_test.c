/* This case tests:
   1. Client 0 and client 1 connect to RTSP server;
   2. CLient 2 tries to connect to RTSP server but fails because the NX_RTSP_SERVER_MAX_CLIENTS is 2;
   3. Client 0 is timeout after NX_RTSP_SERVER_ACTIVITY_TIMEOUT;
   4. Client 1 keeps alive by calling the nx_rtsp_server_keepalive_update();
   5. Client 2 connects to RTSP server successfully because client 0 is disconnected after timeout. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "netxtestcontrol.h"
#if defined(__PRODUCT_NETXDUO__)
#include    "nx_rtsp_server.h"
#endif

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(__PRODUCT_NETXDUO__) && (NX_RTSP_SERVER_MAX_CLIENTS == 2)

#define     DEMO_STACK_SIZE         4096
#define     PACKET_SIZE             1536

/* Define device drivers.  */
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

static UCHAR rtsp_stack[DEMO_STACK_SIZE];
static UCHAR thread_2_stack[DEMO_STACK_SIZE];

static TX_THREAD           client_thread_0;
static NX_PACKET_POOL      client_pool_0;
static NX_IP               client_ip_0;
static NX_TCP_SOCKET       rtsp_client_0;

static TX_THREAD           client_thread_1;
static NX_PACKET_POOL      client_pool_1;
static NX_IP               client_ip_1;
static NX_TCP_SOCKET       rtsp_client_1;

static TX_THREAD           client_thread_2;
static NX_TCP_SOCKET       rtsp_client_2;

static TX_THREAD           server_thread;
static NX_PACKET_POOL      server_pool;
static NX_IP               server_ip;
static NX_RTSP_SERVER      rtsp_server;

static UINT                error_counter;

static TX_SEMAPHORE        semaphore_server_start;
static TX_SEMAPHORE        semaphore_client_0_done;
static TX_SEMAPHORE        semaphore_client_1_done;
static TX_SEMAPHORE        semaphore_client_2_done;
static TX_SEMAPHORE        semaphore_client_connected;
static TX_SEMAPHORE        semaphore_client_disconnected;

static void thread_client_0_entry(ULONG thread_input);
static void thread_client_1_entry(ULONG thread_input);
static void thread_client_2_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);
static UINT rtsp_describe_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);
static UINT rtsp_setup_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr);
static UINT rtsp_play_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);
static UINT rtsp_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length);
static UINT rtsp_pause_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length);
static UINT rtsp_set_parameter_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length);
static UINT rtsp_disconnect_callback(NX_RTSP_CLIENT *rtsp_client_ptr);

#define TEST_SERVER_ADDRESS     IP_ADDRESS(1,2,3,4)
#define TEST_CLIENT_0_ADDRESS   IP_ADDRESS(1,2,3,5)
#define TEST_CLIENT_1_ADDRESS   IP_ADDRESS(1,2,3,6)
#define RTSP_SERVER_PORT        554

#define RTSP_SESSION_ID_0       23754311
#define RTSP_SESSION_ID_1       23754312
#define RTSP_SESSION_ID_2       23754313

#define RTP_SERVER_RTP_PORT     6002
#define RTP_SERVER_RTCP_PORT    6003
#define RTP_0_RTP_PORT          49752
#define RTP_0_RTCP_PORT         49753
#define RTP_1_RTP_PORT          49754
#define RTP_1_RTCP_PORT         49755
#define RTP_2_RTP_PORT          49756
#define RTP_2_RTCP_PORT         49757

#define RTP_0_SSRC               1111
#define RTP_1_SSRC               2222
#define RTP_2_SSRC               3333
#define RTP_0_VIDEO_SEQ          1234
#define RTP_1_VIDEO_SEQ          1235
#define RTP_2_VIDEO_SEQ          1236
#define RTP_TIMESTAMP_INIT_VALUE 40

static UCHAR rtsp_option_request_0[] = "\
OPTIONS rtsp://1.2.3.4:554/stream0 RTSP/1.0\r\n\
CSeq: 2\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\r\n\
";

static UCHAR rtsp_option_request_1[] = "\
OPTIONS rtsp://1.2.3.4:554/stream1 RTSP/1.0\r\n\
CSeq: 2\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\r\n\
";

static UCHAR rtsp_option_request_2[] = "\
OPTIONS rtsp://1.2.3.4:554/stream2 RTSP/1.0\r\n\
CSeq: 2\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\r\n\
";

static UCHAR rtsp_describe_request_0[] = "\
DESCRIBE rtsp://1.2.3.4:554/stream0 RTSP/1.0\r\n\
CSeq: 3\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Accept: application/sdp\r\n\r\n\
";

static UCHAR rtsp_describe_request_1[] = "\
DESCRIBE rtsp://1.2.3.4:554/stream1 RTSP/1.0\r\n\
CSeq: 3\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Accept: application/sdp\r\n\r\n\
";

static UCHAR rtsp_describe_request_2[] = "\
DESCRIBE rtsp://1.2.3.4:554/stream2 RTSP/1.0\r\n\
CSeq: 3\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Accept: application/sdp\r\n\r\n\
";

static UCHAR rtsp_setup_request_0[] = "\
SETUP rtsp://1.2.3.4:554/stream0/trackID=0 RTSP/1.0\r\n\
CSeq: 4\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Transport: RTP/AVP;unicast;client_port=49752-49753\r\n\r\n\
";

static UCHAR rtsp_setup_request_1[] = "\
SETUP rtsp://1.2.3.4:554/stream1/trackID=0 RTSP/1.0\r\n\
CSeq: 5\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Transport: RTP/AVP;unicast;client_port=49754-49755\r\n\r\n\
";

static UCHAR rtsp_setup_request_2[] = "\
SETUP rtsp://1.2.3.4:554/stream2/trackID=0 RTSP/1.0\r\n\
CSeq: 5\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Transport: RTP/AVP;unicast;client_port=49756-49757\r\n\r\n\
";

static UCHAR rtsp_play_request_0[] = "\
PLAY rtsp://1.2.3.4:554/stream0 RTSP/1.0\r\n\
CSeq: 6\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754311\r\n\
Range: npt=0.000-\r\n\r\n\
";

static UCHAR rtsp_play_request_1[] = "\
PLAY rtsp://1.2.3.4:554/stream1 RTSP/1.0\r\n\
CSeq: 6\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754312\r\n\
Range: npt=0.000-\r\n\r\n\
";

static UCHAR rtsp_play_request_2[] = "\
PLAY rtsp://1.2.3.4:554/stream2 RTSP/1.0\r\n\
CSeq: 6\r\n\
User-Agent: LibVLC/3.0.17.4 (LIVE555 Streaming Media v2016.11.28)\r\n\
Session: 23754313\r\n\
Range: npt=0.000-\r\n\r\n\
";

typedef enum
{
    OPTION_INDEX,
    DESCRIBE_INDEX,
    SETUP_INDEX,
    PLAY_INDEX,
    TEARDOWN_INDEX
}REQUEST_INDEX;

static UCHAR *rtsp_request_list_0[] = 
{
rtsp_option_request_0,
rtsp_describe_request_0,
rtsp_setup_request_0,
rtsp_play_request_0,
};

static UCHAR *rtsp_request_list_1[] = 
{
rtsp_option_request_1,
rtsp_describe_request_1,
rtsp_setup_request_1,
rtsp_play_request_1,
};

static UCHAR *rtsp_request_list_2[] = 
{
rtsp_option_request_2,
rtsp_describe_request_2,
rtsp_setup_request_2,
rtsp_play_request_2,
};

static UINT rtsp_request_size_0[] = 
{
sizeof(rtsp_option_request_0) - 1,
sizeof(rtsp_describe_request_0) - 1,
sizeof(rtsp_setup_request_0) - 1,
sizeof(rtsp_play_request_0) - 1,
};

static UINT rtsp_request_size_1[] = 
{
sizeof(rtsp_option_request_1) - 1,
sizeof(rtsp_describe_request_1) - 1,
sizeof(rtsp_setup_request_1) - 1,
sizeof(rtsp_play_request_1) - 1,
};

static UINT rtsp_request_size_2[] = 
{
sizeof(rtsp_option_request_2) - 1,
sizeof(rtsp_describe_request_2) - 1,
sizeof(rtsp_setup_request_2) - 1,
sizeof(rtsp_play_request_2) - 1,
};

static UINT rtsp_request_num = sizeof(rtsp_request_size_0) / sizeof(UINT);

static NX_RTSP_CLIENT *rtsp_client_ptr_0 = NX_NULL, *rtsp_client_ptr_1 = NX_NULL, *rtsp_client_ptr_2 = NX_NULL;

static UINT disconnect_count = 0;

static CHAR *sdp="v=0\r\ns=MPEG-1 or 2 Audio, streamed by the NetX RTSP Server\r\n\
m=video 0 RTP/AVP 96\r\n\
a=rtpmap:96 H264/90000\r\n\
a=fmtp:96 profile-level-id=42A01E; packetization-mode=1\r\n\
a=control:trackID=0\r\n\
";

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtsp_client_timeout_test_application_define(void *first_unused_memory)
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

    status  = nx_arp_enable(&client_ip_0, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    CHECK_STATUS(0, status);

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip_0);
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

    status  = nx_arp_enable(&client_ip_1, (void *) pointer, 1024);
    pointer =  pointer + 1024;
    CHECK_STATUS(0, status);

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip_1);
    CHECK_STATUS(0, status);

    /* Create the Test Client thread. */
    status = tx_thread_create(&client_thread_2, "Test Client 2", thread_client_2_entry, 0,
                              thread_2_stack, DEMO_STACK_SIZE, 
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    CHECK_STATUS(0, status);

    /* Create semaphores.  */
    tx_semaphore_create(&semaphore_server_start, "semaphore server start", 0);
    tx_semaphore_create(&semaphore_client_0_done, "semaphore client 0 done", 0);
    tx_semaphore_create(&semaphore_client_1_done, "semaphore client 1 done", 0);
    tx_semaphore_create(&semaphore_client_2_done, "semaphore client 2 done", 0);
    tx_semaphore_create(&semaphore_client_connected, "semaphore client connected", 0);
    tx_semaphore_create(&semaphore_client_disconnected, "semaphore client disconnected", 0);
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

    status = nx_tcp_socket_create(&client_ip_0, &rtsp_client_0, "Test Client Socket 0", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    CHECK_STATUS(0, status);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&rtsp_client_0, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Wait test server started.  */
    tx_semaphore_get(&semaphore_server_start, NX_WAIT_FOREVER);

    status = nxd_tcp_client_socket_connect(&rtsp_client_0, &server_ip_address, RTSP_SERVER_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    tx_semaphore_put(&semaphore_client_connected);

    for ( i = 0; i < rtsp_request_num; i++)
    {

        /* Send RTSP request data.  */
        status = nx_packet_allocate(&client_pool_0, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, rtsp_request_list_0[i], rtsp_request_size_0[i], &client_pool_0, NX_IP_PERIODIC_RATE);
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

            sprintf(temp_string, "Transport: RTP/AVP;unicast;source=1.2.3.4;client_port=%d-%d;server_port=%d-%d;ssrc=%d",
                    RTP_0_RTP_PORT, RTP_0_RTCP_PORT, RTP_SERVER_RTP_PORT, RTP_SERVER_RTCP_PORT, RTP_0_SSRC);

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
                    "RTP-Info: url=rtsp://1.2.3.4:554/stream0/trackID=0;seq=%d;rtptime=%d",
                    RTP_0_VIDEO_SEQ, RTP_TIMESTAMP_INIT_VALUE);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "RTP-Info");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, temp_string, strlen(temp_string));
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else
        {
            nx_packet_release(packet_ptr);
        }
    }

    tx_thread_sleep((NX_RTSP_SERVER_ACTIVITY_TIMEOUT + 5) * NX_IP_PERIODIC_RATE);

    /* Set the flag.  */
    tx_semaphore_put(&semaphore_client_0_done);
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
    server_ip_address.nxd_ip_address.v4 = TEST_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    status = nx_tcp_socket_create(&client_ip_1, &rtsp_client_1, "Test Client Socket 1", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    CHECK_STATUS(0, status);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&rtsp_client_1, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Wait test server started.  */
    tx_semaphore_get(&semaphore_server_start, NX_WAIT_FOREVER);

    status = nxd_tcp_client_socket_connect(&rtsp_client_1, &server_ip_address, RTSP_SERVER_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    tx_semaphore_put(&semaphore_client_connected);

    for ( i = 0; i < rtsp_request_num; i++)
    {

        /* Send RTSP request data.  */
        status = nx_packet_allocate(&client_pool_1, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, rtsp_request_list_1[i], rtsp_request_size_1[i], &client_pool_1, NX_IP_PERIODIC_RATE);
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

            sprintf(temp_string, "Transport: RTP/AVP;unicast;source=1.2.3.4;client_port=%d-%d;server_port=%d-%d;ssrc=%d",
                    RTP_1_RTP_PORT, RTP_1_RTCP_PORT, RTP_SERVER_RTP_PORT, RTP_SERVER_RTCP_PORT, RTP_1_SSRC);

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
                    "RTP-Info: url=rtsp://1.2.3.4:554/stream1/trackID=0;seq=%d;rtptime=%d",
                    RTP_1_VIDEO_SEQ, RTP_TIMESTAMP_INIT_VALUE);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "RTP-Info");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, temp_string, strlen(temp_string));
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else
        {
            nx_packet_release(packet_ptr);
        }
    }

    while (i < (NX_RTSP_SERVER_ACTIVITY_TIMEOUT + 5))
    {
        nx_rtsp_server_keepalive_update(rtsp_client_ptr_1);
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
        i++;
    }

    /* Set the flag.  */
    tx_semaphore_put(&semaphore_client_1_done);
}

void thread_client_2_entry(ULONG thread_input)
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

    status = nx_tcp_socket_create(&client_ip_0, &rtsp_client_2, "Test Client Socket 0", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);
    CHECK_STATUS(0, status);

    /* Bind and connect to server.  */
    status = nx_tcp_client_socket_bind(&rtsp_client_2, NX_ANY_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Wait until other clients are connected.  */
    tx_semaphore_get(&semaphore_client_connected, NX_WAIT_FOREVER);
    tx_semaphore_get(&semaphore_client_connected, NX_WAIT_FOREVER);

    status = nxd_tcp_client_socket_connect(&rtsp_client_2, &server_ip_address, RTSP_SERVER_PORT, 5 * NX_IP_PERIODIC_RATE);
    CHECK_STATUS(NX_NOT_CONNECTED, status);

    /* Wait until one client is disconnected.  */
    tx_semaphore_get(&semaphore_client_disconnected, NX_WAIT_FOREVER);

    status = nxd_tcp_client_socket_connect(&rtsp_client_2, &server_ip_address, RTSP_SERVER_PORT, 5 * NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    for ( i = 0; i < rtsp_request_num; i++)
    {

        /* Send RTSP request data.  */
        status = nx_packet_allocate(&client_pool_0, &packet_ptr, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_packet_data_append(packet_ptr, rtsp_request_list_2[i], rtsp_request_size_2[i], &client_pool_0, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_tcp_socket_send(&rtsp_client_2, packet_ptr, NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Receive the response from RTSP server.  */
        status = nx_tcp_socket_receive(&rtsp_client_2, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
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

            sprintf(temp_string, "Transport: RTP/AVP;unicast;source=1.2.3.4;client_port=%d-%d;server_port=%d-%d;ssrc=%d",
                    RTP_2_RTP_PORT, RTP_2_RTCP_PORT, RTP_SERVER_RTP_PORT, RTP_SERVER_RTCP_PORT, RTP_2_SSRC);

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
                    "RTP-Info: url=rtsp://1.2.3.4:554/stream2/trackID=0;seq=%d;rtptime=%d",
                    RTP_2_VIDEO_SEQ, RTP_TIMESTAMP_INIT_VALUE);

            buffer_ptr = strstr(packet_ptr -> nx_packet_prepend_ptr, "RTP-Info");
            if (buffer_ptr == NX_NULL)
            {
                error_counter++;
                CHECK_STATUS(0, error_counter);
            }

            status = memcmp(buffer_ptr, temp_string, strlen(temp_string));
            CHECK_STATUS(0, status);

            nx_packet_release(packet_ptr);
        }
        else
        {
            nx_packet_release(packet_ptr);
        }
    }

    /* Set the flag.  */
    tx_semaphore_put(&semaphore_client_2_done);
}


/* Define the helper Test server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT status;


    /* Print out test information banner.  */
    printf("NetX Test:   RTSP Client Timeout Test..................................");

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

    /* Set callback functions. */
    nx_rtsp_server_describe_callback_set(&rtsp_server, rtsp_describe_callback);
    nx_rtsp_server_setup_callback_set(&rtsp_server, rtsp_setup_callback);
    nx_rtsp_server_play_callback_set(&rtsp_server, rtsp_play_callback);
    nx_rtsp_server_teardown_callback_set(&rtsp_server, rtsp_teardown_callback);
    nx_rtsp_server_pause_callback_set(&rtsp_server, rtsp_pause_callback);
    nx_rtsp_server_set_parameter_callback_set(&rtsp_server, rtsp_set_parameter_callback);

    /* Start RTSP server. */
    nx_rtsp_server_start(&rtsp_server);

    tx_semaphore_put(&semaphore_server_start);
    tx_semaphore_put(&semaphore_server_start);

    tx_semaphore_get(&semaphore_client_0_done, NX_WAIT_FOREVER);
    tx_semaphore_get(&semaphore_client_1_done, NX_WAIT_FOREVER);
    tx_semaphore_get(&semaphore_client_2_done, NX_WAIT_FOREVER);

    if ((disconnect_count != 1) || rtsp_server.nx_rtsp_server_connected_client_count != 2)
    {
        error_counter++;
    }

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
UINT status = NX_SUCCESS;

    transport_ptr -> server_rtp_port = RTP_SERVER_RTP_PORT;
    transport_ptr -> server_rtcp_port = RTP_SERVER_RTCP_PORT;

    if (strstr(uri, "stream0"))
    {

        /* Obtain generated ssrc */
        transport_ptr -> rtp_ssrc = RTP_0_SSRC;

        /* Set static session ID for test.  */
        rtsp_client_ptr -> nx_rtsp_client_session_id = RTSP_SESSION_ID_0;

        /* Store the client pointer.  */
        rtsp_client_ptr_0 = rtsp_client_ptr;
    }
    else if (strstr(uri, "stream1"))
    {

        /* Obtain generated ssrc */
        transport_ptr -> rtp_ssrc = RTP_1_SSRC;

        /* Set static session ID for test.  */
        rtsp_client_ptr -> nx_rtsp_client_session_id = RTSP_SESSION_ID_1;

        /* Store the client pointer.  */
        rtsp_client_ptr_1 = rtsp_client_ptr;
    }
    else if (strstr(uri, "stream2"))
    {

        /* Obtain generated ssrc */
        transport_ptr -> rtp_ssrc = RTP_2_SSRC;

        /* Set static session ID for test.  */
        rtsp_client_ptr -> nx_rtsp_client_session_id = RTSP_SESSION_ID_2;

        /* Store the client pointer.  */
        rtsp_client_ptr_2 = rtsp_client_ptr;
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

    if (strstr(uri, "stream0"))
    {

        status = nx_rtsp_server_rtp_info_set(rtsp_client_ptr, "trackID=0", sizeof("trackID=0") - 1, RTP_0_VIDEO_SEQ, RTP_TIMESTAMP_INIT_VALUE);
        CHECK_STATUS(0, status);
    }
    else if (strstr(uri, "stream1"))
    {

        status = nx_rtsp_server_rtp_info_set(rtsp_client_ptr, "trackID=0", sizeof("trackID=0") - 1, RTP_1_VIDEO_SEQ, RTP_TIMESTAMP_INIT_VALUE);
        CHECK_STATUS(0, status);
    }
    else if (strstr(uri, "stream2"))
    {

        status = nx_rtsp_server_rtp_info_set(rtsp_client_ptr, "trackID=0", sizeof("trackID=0") - 1, RTP_2_VIDEO_SEQ, RTP_TIMESTAMP_INIT_VALUE);
        CHECK_STATUS(0, status);
    }
    else
    {
        status = NX_RTSP_SERVER_INVALID_REQUEST;
    }

    return(status);
}

static UINT rtsp_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length)
{
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
    if (rtsp_client_ptr != rtsp_client_ptr_0)
    {
        error_counter++;
    }
    disconnect_count++;
    tx_semaphore_put(&semaphore_client_disconnected);
    return(NX_SUCCESS);
}


#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtsp_client_timeout_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RTSP Client Timeout Test..................................N/A\n"); 

    test_control_return(3);  
}      
#endif

