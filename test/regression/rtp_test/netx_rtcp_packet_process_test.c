#include "tx_api.h"
#include "nx_api.h"
#include "netxtestcontrol.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN)
#include    "nx_rtp_sender.h"

#define DEMO_STACK_SIZE            4096

#define NUM_PACKETS                24
#define PACKET_SIZE                1536
#define PACKET_POOL_SIZE           (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

#define RTP_SERVER_ADDRESS         IP_ADDRESS(1,2,3,4)
#define RTP_CLIENT_ADDRESS         IP_ADDRESS(1,2,3,5)
#define RTP_CLIENT_RTP_PORT        6002
#define RTP_CLIENT_RTCP_PORT       6003
#define RTP_PAYLOAD_TYPE_VIDEO     96
#define CNAME                      "AzureRTOS@microsoft.com"

/* Define the ThreadX object control blocks...  */

static TX_THREAD                   ntest_0;
static TX_THREAD                   ntest_1;

static NX_PACKET_POOL              pool_0;
static NX_IP                       ip_0;
static NX_IP                       ip_1;
static NX_UDP_SOCKET               rtp_client_socket;

/* Define rtp sender control block.  */
static NX_RTP_SENDER               rtp_0;
static NX_RTP_SESSION              rtp_session_0;

/* Define the counters used in the test application...  */
static TX_SEMAPHORE            semaphore_test_done;

/* Define RTCP packet for testing.
--receiver report--
   version: RFC 1899 Version (2)
   padding: False
   reception report count: 1
   packet type: receiver report (201)
   length: 7
   sender ssrc: 1052681868
   source 1:
       identifier: 11478
       fraction lost: 255
       cumulative number of packets lost: -1
       extended highest sequence number received: 94974
       interarrival jitter: 444
       last SR timestamp: 0
       delay since last SR timestamp: 0
--source description--
   version: RFC 1899 Version (2)
   padding: False
   source count: 1
   packet type: source description (202)
   length: 5
   chunk 1:
       indentifier: 1052681868
       sdes item：
            type: CNAME (1)
            length:13
            text: cn-test-cname
            type: END (0)
*/
static UCHAR test_rtcp_packet_data[]={
0x81, 0xc9, 0x00, 0x07, 0x3e, 0xbe, 0xa6, 0x8c, 0x00, 0x00, 0x2c, 0xd6, 0xff, 0xff, 0xff, 0xff,
0x00, 0x01, 0x72, 0xfe, 0x00, 0x00, 0x01, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x81, 0xca, 0x00, 0x05, 0x3e, 0xbe, 0xa6, 0x8c, 0x01, 0x0d, 0x63, 0x6e, 0x2d, 0x74, 0x65, 0x73,
0x74, 0x2d, 0x63, 0x6e, 0x61, 0x6d, 0x65, 0x00};

static UCHAR test_rtp_receiver_cname[] = "cn-test-cname";

/* Define thread prototypes.  */

static void ntest_0_entry(ULONG thread_input);
static void ntest_1_entry(ULONG thread_input);
static UINT test_rtcp_receiver_report_callback(NX_RTP_SESSION *session, NX_RTCP_RECEIVER_REPORT *report);
static UINT test_rtcp_sdes_callback(NX_RTCP_SDES_INFO *sdes_info);
extern void _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtcp_packet_process_test_application_define(void *first_unused_memory)
#endif
{

CHAR       *pointer;
UINT        status;

    /* Print out test information banner.  */
    printf("NetX Test:   RTCP Packet Pocess Test............................................");

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the client thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pointer, PACKET_POOL_SIZE);
    pointer = pointer + PACKET_POOL_SIZE;
    CHECK_STATUS(0, status);

    /* Create server IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", RTP_SERVER_ADDRESS, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;
    CHECK_STATUS(0, status);

    /* Create client IP instance.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", RTP_CLIENT_ADDRESS, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;
    CHECK_STATUS(0, status);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    CHECK_STATUS(0, status);

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    CHECK_STATUS(0, status);

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);
    CHECK_STATUS(0, status);
    status = nx_udp_enable(&ip_1);
    CHECK_STATUS(0, status);

    tx_semaphore_create(&semaphore_test_done, "semaphore test done", 0);
}

/* Define server threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
UINT        status;
NXD_ADDRESS client_ip_address;

    /* Create RTP sender.  */
    status = nx_rtp_sender_create(&rtp_0, &ip_0, &pool_0, CNAME, sizeof(CNAME) - 1);
    CHECK_STATUS(0, status);
    nx_rtp_sender_rtcp_receiver_report_callback_set(&rtp_0, test_rtcp_receiver_report_callback);
    nx_rtp_sender_rtcp_sdes_callback_set(&rtp_0, test_rtcp_sdes_callback);

    /* Setup rtp sender session.  */
    client_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    client_ip_address.nxd_ip_address.v4 = RTP_CLIENT_ADDRESS;
    status = nx_rtp_sender_session_create(&rtp_0, &rtp_session_0, RTP_PAYLOAD_TYPE_VIDEO,
                                          0, &client_ip_address,
                                          RTP_CLIENT_RTP_PORT, RTP_CLIENT_RTCP_PORT);

    /* Set session ssrc value the same as the source identifier in test_rtcp_packet_data packet.  */
    rtp_session_0.nx_rtp_session_ssrc = 11478;

    CHECK_STATUS(0, status);

    status = tx_semaphore_get(&semaphore_test_done, 5 * NX_IP_PERIODIC_RATE); 
    CHECK_STATUS(0, status);

    status = tx_semaphore_get(&semaphore_test_done, 5 * NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    status = tx_semaphore_get(&semaphore_test_done, 5 * NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Return the test result.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}

/* Define the client threads.  */
static void    ntest_1_entry(ULONG thread_input)
{
NX_PACKET *send_packet;
UINT       status;

    /* Create the rtp client socket.  */
    status = nx_udp_socket_create(&ip_1, &rtp_client_socket, "RTP Client Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    CHECK_STATUS(0, status);

    status =  nx_udp_socket_bind(&rtp_client_socket, RTP_CLIENT_RTCP_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    status = nx_packet_allocate(&pool_0, &send_packet, NX_UDP_PACKET, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    status = nx_packet_data_append(send_packet, test_rtcp_packet_data, sizeof(test_rtcp_packet_data), &pool_0,  NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    status = nx_udp_socket_send(&rtp_client_socket, send_packet, RTP_SERVER_ADDRESS, rtp_0.nx_rtp_sender_rtcp_port);
    CHECK_STATUS(0, status);

    /* Set rtcp receiver report callback to NULL. */
    status = nx_rtp_sender_rtcp_receiver_report_callback_set(&rtp_0, NX_NULL);
    CHECK_STATUS(0, status);

    /* Set rtcp sdes callback to NULL. */
    status = nx_rtp_sender_rtcp_sdes_callback_set(&rtp_0, NX_NULL);
    CHECK_STATUS(0, status);

    status = nx_packet_allocate(&pool_0, &send_packet, NX_UDP_PACKET, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    status = nx_packet_data_append(send_packet, test_rtcp_packet_data, sizeof(test_rtcp_packet_data), &pool_0,  NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    status = nx_udp_socket_send(&rtp_client_socket, send_packet, RTP_SERVER_ADDRESS, rtp_0.nx_rtp_sender_rtcp_port);
    CHECK_STATUS(0, status);

    tx_semaphore_put(&semaphore_test_done);
}

static UINT test_rtcp_receiver_report_callback(NX_RTP_SESSION *session, NX_RTCP_RECEIVER_REPORT *report)
{
    if((report->receiver_ssrc == 1052681868) &&
       (report->fraction_loss == 255) &&
       (report->packet_loss == -1) &&
       (report->extended_max = 94974) &&
       (report->jitter == 444) &&
       (report->last_sr == 0) &&
       (report->delay == 0))
    {
        tx_semaphore_put(&semaphore_test_done);
    }

    return(NX_SUCCESS);
}

static UINT test_rtcp_sdes_callback(NX_RTCP_SDES_INFO *sdes_info)
{
    if((sdes_info->ssrc == 1052681868) &&
       (strncmp(sdes_info->cname, test_rtp_receiver_cname, sizeof(test_rtp_receiver_cname) - 1) == 0) &&
       (sdes_info->cname_length == sizeof(test_rtp_receiver_cname) - 1))
    {
        tx_semaphore_put(&semaphore_test_done);
    }

    return NX_SUCCESS;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtcp_packet_process_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RTCP Packet Process Test............................................N/A\n"); 

    test_control_return(3);  
}      
#endif

