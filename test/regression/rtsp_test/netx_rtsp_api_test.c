#include    "tx_api.h"
#include    "nx_api.h"
#include    "netxtestcontrol.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__)
#include    "nx_rtsp_server.h"

#define DEMO_STACK_SIZE     4096

#define TEST_RTSP_STACK_SIZE 2048
#define TEST_RTSP_SERVER_PORT 554
#define TEST_RTSP_SERVER_PRIORITY 3

/* Define the ThreadX object control blocks...  */

static TX_THREAD            test_thread;

/* Define the ThreadX object control blocks...  */

static NX_PACKET_POOL       pool_0;
static NX_IP                ip_0;

/* Define rtsp server control block.  */
static NX_RTSP_SERVER       rtsp_0;

static UCHAR rtsp_stack[TEST_RTSP_STACK_SIZE];

/* Define thread prototypes.  */

static void test_entry(ULONG thread_input);

static UINT describe_teardown_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length)
{
    return 0;
}

static UINT setup_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, NX_RTSP_TRANSPORT *transport_ptr)
{
    return 0;
}

static UINT play_pause_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *range_ptr, UINT range_length)
{
    return 0;
}

static UINT set_parameter_callback(NX_RTSP_CLIENT *rtsp_client_ptr, UCHAR *uri, UINT uri_length, UCHAR *parameter_ptr, ULONG parameter_length)
{
    return 0;
}

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtsp_api_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&test_thread, "Test thread", test_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();
}

void test_entry(ULONG thread_input)
{
UINT status;
UCHAR test_sdp[] = "test_sdp";
UCHAR test_track_id[] = "test_track_id";
NX_RTSP_CLIENT *client_ptr;
NX_RTSP_CLIENT_REQUEST test_request;
NX_PACKET test_packet;


    /* Print out test information banner.  */
    printf("NetX Test:   RTSP API Test.............................................");

    memset(&rtsp_0, 0, sizeof(NX_RTSP_SERVER));

    /* Test nx_rtsp_server_create.   */
    status = nx_rtsp_server_create(NX_NULL, "RTSP Server", sizeof("RTSP Server") - 1, &ip_0, &pool_0, rtsp_stack,
                                   TEST_RTSP_STACK_SIZE, TEST_RTSP_SERVER_PRIORITY, TEST_RTSP_SERVER_PORT, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_create(&rtsp_0, "RTSP Server", sizeof("RTSP Server") - 1, NX_NULL, &pool_0, rtsp_stack,
                                   TEST_RTSP_STACK_SIZE, TEST_RTSP_SERVER_PRIORITY, TEST_RTSP_SERVER_PORT, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_create(&rtsp_0, "RTSP Server", sizeof("RTSP Server") - 1, &ip_0, NX_NULL, rtsp_stack,
                                   TEST_RTSP_STACK_SIZE, TEST_RTSP_SERVER_PRIORITY, TEST_RTSP_SERVER_PORT, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_create(&rtsp_0, "RTSP Server", sizeof("RTSP Server") - 1, &ip_0, &pool_0, NX_NULL,
                                   TEST_RTSP_STACK_SIZE, TEST_RTSP_SERVER_PRIORITY, TEST_RTSP_SERVER_PORT, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;
    status = nx_rtsp_server_create(&rtsp_0, "RTSP Server", sizeof("RTSP Server") - 1, &ip_0, &pool_0, rtsp_stack,
                                   TEST_RTSP_STACK_SIZE, TEST_RTSP_SERVER_PRIORITY, TEST_RTSP_SERVER_PORT, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = 0;

    /* Test nx_rtsp_server_delete.  */
    status = nx_rtsp_server_delete(NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_delete(&rtsp_0);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test nx_rtsp_server_start.  */
    status = nx_rtsp_server_start(NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_start(&rtsp_0);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test nx_rtsp_server_stop.  */
    status = nx_rtsp_server_stop(NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_stop(&rtsp_0);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Initialize the client structure.  */
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;
    client_ptr = &(rtsp_0.nx_rtsp_server_client_list[0]);
    client_ptr -> nx_rtsp_client_server_ptr = &rtsp_0;
    client_ptr -> nx_rtsp_client_request_ptr = &test_request;
    client_ptr -> nx_rtsp_client_response_packet = &test_packet;

    /* Test nx_rtsp_server_sdp_set.  */
    test_request.nx_rtsp_client_request_method = NX_RTSP_METHOD_SETUP;
    status = nx_rtsp_server_sdp_set(NX_NULL, test_sdp, sizeof(test_sdp) - 1);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_sdp_set(client_ptr, NX_NULL, sizeof(test_sdp) - 1);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_sdp_set(client_ptr, test_sdp, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = NX_NULL;
    status = nx_rtsp_server_sdp_set(client_ptr, test_sdp, sizeof(test_sdp) - 1);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = &rtsp_0;
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_sdp_set(client_ptr, test_sdp, sizeof(test_sdp) - 1);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;
    client_ptr -> nx_rtsp_client_response_packet = NX_NULL;
    status = nx_rtsp_server_sdp_set(client_ptr, test_sdp, sizeof(test_sdp) - 1);
    CHECK_STATUS(NX_RTSP_SERVER_NO_PACKET, status);
    client_ptr -> nx_rtsp_client_response_packet = &test_packet;
    test_request.nx_rtsp_client_request_method = NX_RTSP_METHOD_PLAY;
    status = nx_rtsp_server_sdp_set(client_ptr, test_sdp, sizeof(test_sdp) - 1);
    CHECK_STATUS(NX_RTSP_SERVER_INVALID_REQUEST, status);

    /* Test nx_rtsp_server_rtp_info_set.  */
    status = nx_rtsp_server_rtp_info_set(NX_NULL, test_track_id, sizeof(test_track_id) - 1, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_rtp_info_set(client_ptr, NX_NULL, sizeof(test_track_id) - 1, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_rtp_info_set(client_ptr, test_track_id, 0, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = NX_NULL;
    status = nx_rtsp_server_rtp_info_set(client_ptr, test_track_id, sizeof(test_track_id) - 1, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = &rtsp_0;
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_rtp_info_set(client_ptr, test_track_id, sizeof(test_track_id) - 1, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;
    client_ptr -> nx_rtsp_client_response_packet = NX_NULL;
    status = nx_rtsp_server_rtp_info_set(client_ptr, test_track_id, sizeof(test_track_id) - 1, 0, 0);
    CHECK_STATUS(NX_RTSP_SERVER_NO_PACKET, status);
    client_ptr -> nx_rtsp_client_response_packet = &test_packet;
    test_request.nx_rtsp_client_request_method = NX_RTSP_METHOD_PAUSE;
    status = nx_rtsp_server_rtp_info_set(client_ptr, test_track_id, sizeof(test_track_id) - 1, 0, 0);
    CHECK_STATUS(NX_RTSP_SERVER_INVALID_REQUEST, status);

    /* Test nx_rtsp_server_range_npt_set.  */
    status = nx_rtsp_server_range_npt_set(NX_NULL, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = NX_NULL;
    status = nx_rtsp_server_range_npt_set(client_ptr, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = &rtsp_0;
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_range_npt_set(client_ptr, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;
    test_request.nx_rtsp_client_request_method = NX_RTSP_METHOD_DESCRIBE;
    status = nx_rtsp_server_range_npt_set(client_ptr, 0, 0);
    CHECK_STATUS(NX_RTSP_SERVER_INVALID_REQUEST, status);
    test_request.nx_rtsp_client_request_method = NX_RTSP_METHOD_PLAY;
    status = nx_rtsp_server_range_npt_set(client_ptr, 1, 0);
    CHECK_STATUS(NX_RTSP_SERVER_INVALID_PARAMETER, status);

    /* Test nx_rtsp_server_error_response_send.  */
    status = nx_rtsp_server_error_response_send(NX_NULL, 200);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = NX_NULL;
    status = nx_rtsp_server_error_response_send(client_ptr, 200);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = &rtsp_0;
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_error_response_send(client_ptr, 200);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;
    client_ptr -> nx_rtsp_client_response_packet = NX_NULL;
    status = nx_rtsp_server_error_response_send(client_ptr, 200);
    CHECK_STATUS(NX_RTSP_SERVER_NO_PACKET, status);
    client_ptr -> nx_rtsp_client_response_packet = &test_packet;
    status = nx_rtsp_server_error_response_send(client_ptr, 0);
    CHECK_STATUS(NX_RTSP_SERVER_INVALID_PARAMETER, status);

    /* Test nx_rtsp_server_keepalive_update.  */
    status = nx_rtsp_server_keepalive_update(NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = NX_NULL;
    status = nx_rtsp_server_keepalive_update(client_ptr);
    CHECK_STATUS(NX_PTR_ERROR, status);
    client_ptr -> nx_rtsp_client_server_ptr = &rtsp_0;
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_keepalive_update(client_ptr);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;

    /* Test nx_rtsp_server_describe_callback_set.  */
    status = nx_rtsp_server_describe_callback_set(NX_NULL, describe_teardown_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_describe_callback_set(&rtsp_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_describe_callback_set(&rtsp_0, describe_teardown_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;

    /* Test nx_rtsp_server_teardown_callback_set.  */
    status = nx_rtsp_server_teardown_callback_set(NX_NULL, describe_teardown_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_teardown_callback_set(&rtsp_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_teardown_callback_set(&rtsp_0, describe_teardown_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;

    /* Test nx_rtsp_server_setup_callback_set.  */
    status = nx_rtsp_server_setup_callback_set(NX_NULL, setup_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_setup_callback_set(&rtsp_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_setup_callback_set(&rtsp_0, setup_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;

    /* Test nx_rtsp_server_play_callback_set.  */
    status = nx_rtsp_server_play_callback_set(NX_NULL, play_pause_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_play_callback_set(&rtsp_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_play_callback_set(&rtsp_0, play_pause_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;

    /* Test nx_rtsp_server_pause_callback_set.  */
    status = nx_rtsp_server_pause_callback_set(NX_NULL, play_pause_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_pause_callback_set(&rtsp_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_pause_callback_set(&rtsp_0, play_pause_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;

    /* Test nx_rtsp_server_set_parameter_callback_set.  */
    status = nx_rtsp_server_set_parameter_callback_set(NX_NULL, set_parameter_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtsp_server_set_parameter_callback_set(&rtsp_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = 0;
    status = nx_rtsp_server_set_parameter_callback_set(&rtsp_0, set_parameter_callback);
    CHECK_STATUS(NX_PTR_ERROR, status);
    rtsp_0.nx_rtsp_server_id = NX_RTSP_SERVER_ID;

    /* Return the test result.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtsp_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RTSP API Test.............................................N/A\n");

    test_control_return(3);
}
#endif

