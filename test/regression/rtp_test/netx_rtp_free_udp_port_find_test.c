#include "tx_api.h"
#include "nx_api.h"
#include "nx_udp.h"
#include "netxtestcontrol.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN)
#include    "nx_rtp_sender.h"

#define DEMO_STACK_SIZE            4096

#define NUM_PACKETS                10
#define PACKET_SIZE                1536
#define PACKET_POOL_SIZE           (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

#define RTP_SERVER_ADDRESS         IP_ADDRESS(1,2,3,4)
#define RTP_CLIENT_RTP_PORT        6002
#define RTP_CLIENT_RTCP_PORT       6003
#define RTP_PAYLOAD_TYPE           96
#define CNAME                      "AzureRTOS@microsoft.com"

/* Define the ThreadX object control blocks...  */

static TX_THREAD                   ntest_0;

static NX_PACKET_POOL              pool_0;
static NX_IP                       ip_0;

static NX_UDP_SOCKET               udp_socket_0;
static NX_UDP_SOCKET               udp_socket_1;

/* Define rtp sender control block.  */
static NX_RTP_SENDER               rtp_0;
static UINT                        rtp_port;
static UINT                        rtcp_port;

static NX_UDP_SOCKET               my_socket[NX_MAX_PORT + 1];


/* Define thread prototypes.  */

static void ntest_0_entry(ULONG thread_input);
extern void _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtp_free_udp_port_find_test_application_define(void *first_unused_memory)
#endif
{

CHAR       *pointer;
UINT        status;

    /* Print out test information banner.  */
    printf("NetX Test:   RTP Free UDP Port Find Test............................................");

    /* Setup the working pointer.  */
    pointer = (CHAR *)first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
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

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    CHECK_STATUS(0, status);

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);
    CHECK_STATUS(0, status);
}

/* Define server threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
UINT        status;
UINT        i;


    /* Create the test udp socket for use */
    status = nx_udp_socket_create(&ip_0, &udp_socket_0, "Test Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    status += nx_udp_socket_create(&ip_0, &udp_socket_1, "Test Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    CHECK_STATUS(0, status);

    /* Test 1: occupy the initial rtp port to test if rtp sender can find and bind following ports */
    status = nx_udp_socket_bind(&udp_socket_0, NX_RTP_SENDER_INITIAL_RTP_PORT, NX_NO_WAIT);
    status += nx_rtp_sender_create(&rtp_0, &ip_0, &pool_0, CNAME, sizeof(CNAME) - 1);
    status += nx_rtp_sender_port_get(&rtp_0, &rtp_port, &rtcp_port);
    CHECK_STATUS(0, status);
    CHECK_STATUS(NX_RTP_SENDER_INITIAL_RTP_PORT + 2, rtp_port);  /* rtp port shall be an even number */
    CHECK_STATUS(NX_RTP_SENDER_INITIAL_RTP_PORT + 3, rtcp_port); /* rtcp port shall be an odd number next to rtp port */
    nx_udp_socket_unbind(&udp_socket_0);
    status = nx_rtp_sender_delete(&rtp_0);
    CHECK_STATUS(0, status);

    /* Test 2: occupy the initial rtcp port to test if rtp sender can find and bind following ports */
    status = nx_udp_socket_bind(&udp_socket_0, (NX_RTP_SENDER_INITIAL_RTP_PORT + 1), NX_NO_WAIT);
    CHECK_STATUS(0, status);
    status = nx_rtp_sender_create(&rtp_0, &ip_0, &pool_0, CNAME, sizeof(CNAME) - 1);
    status += nx_rtp_sender_port_get(&rtp_0, &rtp_port, &rtcp_port);
    CHECK_STATUS(0, status);
    CHECK_STATUS(NX_RTP_SENDER_INITIAL_RTP_PORT + 2, rtp_port);  /* rtp port shall be an even number */
    CHECK_STATUS(NX_RTP_SENDER_INITIAL_RTP_PORT + 3, rtcp_port); /* rtcp port shall be an odd number next to rtp port */
    nx_udp_socket_unbind(&udp_socket_0);
    status = nx_rtp_sender_delete(&rtp_0);
    CHECK_STATUS(0, status);

    /* Test 3: occupy the initial rtp port and the next rtcp port to test if rtp sender can find and bind following ports */
    status = nx_udp_socket_bind(&udp_socket_0, (NX_RTP_SENDER_INITIAL_RTP_PORT), NX_NO_WAIT);
    status += nx_udp_socket_bind(&udp_socket_1, (NX_RTP_SENDER_INITIAL_RTP_PORT + 3), NX_NO_WAIT);
    CHECK_STATUS(0, status);
    status = nx_rtp_sender_create(&rtp_0, &ip_0, &pool_0, CNAME, sizeof(CNAME) - 1);
    status += nx_rtp_sender_port_get(&rtp_0, &rtp_port, &rtcp_port);
    CHECK_STATUS(0, status);
    CHECK_STATUS(NX_RTP_SENDER_INITIAL_RTP_PORT + 4, rtp_port);  /* rtp port shall be an even number */
    CHECK_STATUS(NX_RTP_SENDER_INITIAL_RTP_PORT + 5, rtcp_port); /* rtcp port shall be an odd number next to rtp port */
    nx_udp_socket_unbind(&udp_socket_0);
    nx_udp_socket_unbind(&udp_socket_1);
    status = nx_rtp_sender_delete(&rtp_0);
    CHECK_STATUS(0, status);

    /* Test 4: occupy all odd ports and see no free ports. */
    for (i = (NX_RTP_SENDER_INITIAL_RTP_PORT + 1); i <= NX_MAX_PORT; i += 2)
    {
        status = nx_udp_socket_create(&ip_0, &my_socket[i], "Socket Array", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_udp_socket_bind(&my_socket[i], i, NX_IP_PERIODIC_RATE);
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    status = nx_rtp_sender_create(&rtp_0, &ip_0, &pool_0, CNAME, sizeof(CNAME) - 1);
    CHECK_STATUS(NX_NO_FREE_PORTS, status);

    /* Test 5: occupy all odd ports as well as port 65532 & 65534, unbind port 65533 and see no free ports. */
    status = nx_udp_socket_create(&ip_0, &my_socket[65534], "Socket Array", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_bind(&my_socket[65534], 65534, NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_create(&ip_0, &my_socket[65532], "Socket Array", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_bind(&my_socket[65532], 65532, NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unbind port 65533. */
    status = nx_udp_socket_unbind(&my_socket[65533]);

    status = nx_rtp_sender_create(&rtp_0, &ip_0, &pool_0, CNAME, sizeof(CNAME) - 1);
    CHECK_STATUS(NX_NO_FREE_PORTS, status);

    /* Finally, delete the sockets and check if there is memory leak. */
    nx_udp_socket_delete(&udp_socket_0);
    nx_udp_socket_delete(&udp_socket_1);
    CHECK_STATUS(pool_0.nx_packet_pool_total, pool_0.nx_packet_pool_available);

    /* Return the test result.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rtp_free_udp_port_find_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RTP Free UDP Port Find Test............................................N/A\n");

    test_control_return(3);
}
#endif

