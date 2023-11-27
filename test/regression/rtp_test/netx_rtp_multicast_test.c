#include "tx_api.h"
#include "nx_api.h"
#include "netxtestcontrol.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN)
#include    "nx_rtp_sender.h"

#define DEMO_STACK_SIZE            4096

#define NUM_PACKETS                20
#define PACKET_SIZE                1536
#define PACKET_POOL_SIZE           (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

#define DEMO_MULTICAST_IP_ADDRESS  IP_ADDRESS(224, 1, 0, 55)

#define RTP_SERVER_ADDRESS         IP_ADDRESS(1, 2, 3, 4)
#define RTP_CLIENT_1_ADDRESS       IP_ADDRESS(1, 2, 3, 5)
#define RTP_CLIENT_2_ADDRESS       IP_ADDRESS(1, 2, 3, 6)
#define RTP_CLIENT_RTP_PORT        6002
#define RTP_CLIENT_RTCP_PORT       6003
#define RTP_PAYLOAD_TYPE           96
#define CNAME                      "AzureRTOS@microsoft.com"

/* Define test data. */
#define TEST_TIMESTAMP             1234
#define TEST_MSW                   123
#define TEST_LSW                   456

/* Define the number of tests to do */
#define TEST_CYCLES                5

static UCHAR test_rtp_packet_data[] = "test rtp packet data";

/* Define the ThreadX object control blocks...  */

static TX_THREAD                   ntest_0;
static TX_THREAD                   ntest_1;
static TX_THREAD                   ntest_2;

static NX_PACKET_POOL              pool_0;
static NX_IP                       ip_0;
static NX_IP                       ip_1;
static NX_IP                       ip_2;
static NX_UDP_SOCKET               rtp_client_1_socket;
static NX_UDP_SOCKET               rtp_client_2_socket;

static TX_SEMAPHORE                semaphore_test_1_done;
static TX_SEMAPHORE                semaphore_test_2_done;

/* Define rtp sender control block.  */
static NX_RTP_SENDER               rtp_0;
static NX_RTP_SESSION              rtp_session_0;
static UINT                        rtp_port;
static UINT                        rtcp_port;


/* Define thread prototypes.  */

static void ntest_0_entry(ULONG thread_input);
static void ntest_1_entry(ULONG thread_input);
static void ntest_2_entry(ULONG thread_input);
extern void _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtp_multicast_test_application_define(void *first_unused_memory)
#endif
{

CHAR       *pointer;
UINT        status;

    /* Print out test information banner.  */
    printf("NetX Test:   RTP Multicast Test............................................");

    /* Setup the working pointer.  */
    pointer = (CHAR *)first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the client thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the client thread.  */
    tx_thread_create(&ntest_2, "thread 2", ntest_2_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

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
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", RTP_CLIENT_1_ADDRESS, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;
    CHECK_STATUS(0, status);

    /* Create client IP instance.  */
    status = nx_ip_create(&ip_2, "NetX IP Instance 2", RTP_CLIENT_2_ADDRESS, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
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

    /* Enable ARP and supply ARP cache memory for IP Instance 2.  */
    status = nx_arp_enable(&ip_2, (void *) pointer, 1024);
    pointer = pointer + 1024;
    CHECK_STATUS(0, status);

    /* Enable UDP processing for all IP instances.  */
    status = nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);
    status += nx_udp_enable(&ip_2);
    CHECK_STATUS(0, status);

    /* Create semaphores for test done notification */
    tx_semaphore_create(&semaphore_test_1_done, "semaphore test 1", 0);
    tx_semaphore_create(&semaphore_test_2_done, "semaphore test 2", 0);
}

/* Define server threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
UINT        status;
NXD_ADDRESS client_ip_address;
NX_PACKET  *send_packet;
UINT        time_start;


    /* Enable IGMP & join in multicast group.  */
    status = nx_igmp_enable(&ip_0);
    status = nx_igmp_multicast_join(&ip_0, DEMO_MULTICAST_IP_ADDRESS);
    CHECK_STATUS(0, status);

    /* Create RTP sender.  */
    status = nx_rtp_sender_create(&rtp_0, &ip_0, &pool_0, CNAME, sizeof(CNAME) - 1);
    CHECK_STATUS(0, status);

    /* Get the udp port pair for rtp and rtcp */
    status = nx_rtp_sender_port_get(&rtp_0, &rtp_port, &rtcp_port);
    CHECK_STATUS(0, status);

    /* Setup rtp sender session.  */
    client_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    client_ip_address.nxd_ip_address.v4 = DEMO_MULTICAST_IP_ADDRESS;
    status = nx_rtp_sender_session_create(&rtp_0, &rtp_session_0, RTP_PAYLOAD_TYPE,
                                          0, &client_ip_address,
                                          RTP_CLIENT_RTP_PORT, RTP_CLIENT_RTCP_PORT);
    CHECK_STATUS(0, status);

    /* Wait for client threads ready. */
    tx_thread_sleep(20);

    /* Begin test cycles */
    for (UINT i = 0; i < TEST_CYCLES; i++)
    {

        /* Allocate a packet */
        status = nx_rtp_sender_session_packet_allocate(&rtp_session_0, &send_packet, 5 * NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        /* Copy payload data into the packet. */
        status = nx_packet_data_append(send_packet, (void*)test_rtp_packet_data, sizeof(test_rtp_packet_data), rtp_0.nx_rtp_sender_ip_ptr->nx_ip_default_packet_pool, 5 * NX_IP_PERIODIC_RATE);
        CHECK_STATUS(0, status);

        status = nx_rtp_sender_session_packet_send(&rtp_session_0, send_packet, TEST_TIMESTAMP, TEST_MSW, TEST_LSW, 1);
        CHECK_STATUS(0, status); 
    }

    /* Wait for the check in test thread 1 done. */
    status = tx_semaphore_get(&semaphore_test_1_done, 5 * NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Wait for the check in test thread 2 done. */
    status = tx_semaphore_get(&semaphore_test_2_done, 5 * NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Delete and release resources */
    status = nx_rtp_sender_session_delete(&rtp_session_0);
    CHECK_STATUS(0, status);

    status = nx_rtp_sender_delete(&rtp_0);
    CHECK_STATUS(0, status);

    /* Check if there is memory leak. */
    CHECK_STATUS(pool_0.nx_packet_pool_total, pool_0.nx_packet_pool_available);

    /* Return the test result.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}

/* Define the first client threads.  */
static void    ntest_1_entry(ULONG thread_input)
{
NX_PACKET *received_packet;
UINT       status;
UCHAR     *data;


    /* Enable IGMP & join in multicast group.  */
    status = nx_igmp_enable(&ip_1);
    status += nx_igmp_multicast_join(&ip_1, DEMO_MULTICAST_IP_ADDRESS);
    CHECK_STATUS(0, status);

    /* Create the rtp client socket.  */
    status = nx_udp_socket_create(&ip_1, &rtp_client_1_socket, "RTCP Client 1 Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    CHECK_STATUS(0, status);

    status =  nx_udp_socket_bind(&rtp_client_1_socket, RTP_CLIENT_RTP_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Begin test cycles */
    for (UINT i = 0; i < TEST_CYCLES; i++)
    {

        /* Receive rtp data packet. */
        status = nx_udp_socket_receive(&rtp_client_1_socket, &received_packet, 5 * TX_TIMER_TICKS_PER_SECOND);
        CHECK_STATUS(0, status);

        /* Validate RTP payload data */
        data = received_packet -> nx_packet_prepend_ptr;

        /* Check RTP version byte */
        CHECK_STATUS(0x80, *data);

        /* Move to check RTP data byte for payload type with marker */
        data++;
        CHECK_STATUS((0x80 | RTP_PAYLOAD_TYPE), *data);

        /* Move to check RTP data bytes for sequence number */
        data++;
        CHECK_STATUS((rtp_session_0.nx_rtp_session_sequence_number - 1), (data[0] << 8 | data[1]));

        /* Move to check RTP data bytes for time stamp */
        data += 2;
        CHECK_STATUS(rtp_session_0.nx_rtp_session_rtp_timestamp, (ULONG)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]));

        /* Move to check RTP data bytes for ssrc */
        data += 4;
        CHECK_STATUS(rtp_session_0.nx_rtp_session_ssrc, (ULONG)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]));

        /* Move to check RTP data bytes for data payload */
        data += 4;
        for (UINT i = 0; i < sizeof(test_rtp_packet_data); i++)
        {
            CHECK_STATUS(*(test_rtp_packet_data + i), data[i]);
        }

        /* Release the receive packet when the check finishes. */
        nx_packet_release(received_packet);
    }

    /* Set the flag to notify test thread 0 that the check finishes. */
    tx_semaphore_put(&semaphore_test_1_done);
}

/* Define the second client threads.  */
static void    ntest_2_entry(ULONG thread_input)
{
NX_PACKET *received_packet;
UINT       status;
UCHAR     *data;

    /* Enable IGMP & join in multicast group.  */
    status = nx_igmp_enable(&ip_2);
    status += nx_igmp_multicast_join(&ip_2, DEMO_MULTICAST_IP_ADDRESS);
    CHECK_STATUS(0, status);

    /* Create the rtp client socket.  */
    status = nx_udp_socket_create(&ip_2, &rtp_client_2_socket, "RTCP Client 2 Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    CHECK_STATUS(0, status);

    status =  nx_udp_socket_bind(&rtp_client_2_socket, RTP_CLIENT_RTP_PORT, NX_IP_PERIODIC_RATE);
    CHECK_STATUS(0, status);

    /* Begin test cycles */
    for (UINT i = 0; i < TEST_CYCLES; i++)
    {

        /* Receive rtp data packet. */
        status = nx_udp_socket_receive(&rtp_client_2_socket, &received_packet, 5 * TX_TIMER_TICKS_PER_SECOND);
        CHECK_STATUS(0, status);

        /* Validate RTP payload data */
        data = received_packet -> nx_packet_prepend_ptr;

        /* Check RTP version byte */
        CHECK_STATUS(0x80, *data);

        /* Move to check RTP data byte for payload type with marker */
        data++;
        CHECK_STATUS((0x80 | RTP_PAYLOAD_TYPE), *data);

        /* Move to check RTP data bytes for sequence number */
        data++;
        CHECK_STATUS((rtp_session_0.nx_rtp_session_sequence_number - 1), (data[0] << 8 | data[1]));

        /* Move to check RTP data bytes for time stamp */
        data += 2;
        CHECK_STATUS(rtp_session_0.nx_rtp_session_rtp_timestamp, (ULONG)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]));

        /* Move to check RTP data bytes for ssrc */
        data += 4;
        CHECK_STATUS(rtp_session_0.nx_rtp_session_ssrc, (ULONG)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]));

        /* Move to check RTP data bytes for data payload */
        data += 4;
        for (UINT i = 0; i < sizeof(test_rtp_packet_data); i++)
        {
            CHECK_STATUS(*(test_rtp_packet_data + i), data[i]);
        }

        /* Release the receive packet when the check finishes. */
        nx_packet_release(received_packet);
    }

    /* Set the flag to notify test thread 0 that the check finishes. */
    tx_semaphore_put(&semaphore_test_2_done);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtp_multicast_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RTP Multicast Test............................................N/A\n");

    test_control_return(3);
}
#endif

