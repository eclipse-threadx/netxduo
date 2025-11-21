#include    "tx_api.h"
#include    "nx_api.h"
#include    "netxtestcontrol.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN)
#include    "nx_rtp_sender.h"

#define DEMO_STACK_SIZE     4096

/* Define the ThreadX object control blocks...  */

static TX_THREAD            test_thread;

/* Define the ThreadX object control blocks...  */

static NX_PACKET_POOL       pool_0;
static NX_IP                ip_0;

/* Define rtp sender control block.  */
static NX_RTP_SENDER        rtp_0;
static NX_RTP_SESSION       rtp_session_0;

/* Define thread prototypes.  */

static void test_entry(ULONG thread_input);


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtp_api_test_application_define(void *first_unused_memory)
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
UINT          status;
UINT          rtp_port;


    /* Print out test information banner.  */
    printf("NetX Test:   RTP API Test............................................");

    memset(&rtp_0, 0, sizeof(NX_RTP_SENDER));

    /* Test and check nx_rtp_sender_create */
    status = nx_rtp_sender_create(NX_NULL, NX_NULL, NX_NULL, NX_NULL, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_create(&rtp_0, NX_NULL, NX_NULL, NX_NULL, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_create(&rtp_0, &ip_0, NX_NULL, NX_NULL, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_create(&rtp_0, &ip_0, &pool_0, NX_NULL, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test and check nx_rtp_sender_delete */
    status = nx_rtp_sender_delete(NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test and check nx_rtp_sender_port_get */
    status = nx_rtp_sender_port_get(NX_NULL, NX_NULL, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_port_get(&rtp_0, NX_NULL, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_port_get(&rtp_0, &rtp_port, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test and check nx_rtp_sender_session_create */
    status = nx_rtp_sender_session_create(NX_NULL, NX_NULL, 0, 0, NX_NULL, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_session_create(&rtp_0, NX_NULL, 0, 0, NX_NULL, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_session_create(&rtp_0, &rtp_session_0, 0, 0, NX_NULL, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test and check nx_rtp_sender_session_packet_allocate */
    status = nx_rtp_sender_session_packet_allocate(NX_NULL, NX_NULL, NX_WAIT_FOREVER);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_session_packet_allocate(&rtp_session_0, NX_NULL, NX_WAIT_FOREVER);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test and check nx_rtp_sender_session_sequence_number_get */
    status = nx_rtp_sender_session_sequence_number_get(NX_NULL, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_session_sequence_number_get(&rtp_session_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test and check nx_rtp_sender_session_ssrc_get */
    status = nx_rtp_sender_session_ssrc_get(NX_NULL, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_session_ssrc_get(&rtp_session_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test and check nx_rtp_sender_session_packet_send */
    status = nx_rtp_sender_session_packet_send(NX_NULL, NX_NULL, NX_NULL, 0, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);
    status = nx_rtp_sender_session_packet_send(&rtp_session_0, NX_NULL, NX_NULL, 0, 0, 0);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Test and check RTCP API functions */
    status = nx_rtp_sender_rtcp_receiver_report_callback_set(NX_NULL, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);

    status = nx_rtp_sender_rtcp_receiver_report_callback_set(&rtp_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);

    status = nx_rtp_sender_rtcp_sdes_callback_set(NX_NULL, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);

    status = nx_rtp_sender_rtcp_sdes_callback_set(&rtp_0, NX_NULL);
    CHECK_STATUS(NX_PTR_ERROR, status);

    /* Return the test result.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtp_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RTP API Test............................................N/A\n");

    test_control_return(3);
}
#endif

