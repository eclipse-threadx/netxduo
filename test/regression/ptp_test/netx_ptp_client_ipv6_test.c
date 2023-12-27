/* PTP IPv6 test.  This test case validates PTP client synchronize over IPv6. 
   To run this test case, NetXDuo must be built with NX_ENABLE_IPV6_MULTICAST and FEATURE_NX_IPV6.
*/

#include   "netx_ptp_utility.h"

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_UDP_SOCKET           generic_socket;
static NX_UDP_SOCKET           event_socket;
static NX_PTP_CLIENT           ptp_client;

static NX_PTP_TIME             sync_ts = {0x0, 0x5F97CD71, 0x240d93b2};
static NX_PTP_TIME             follow_up_ts = {0x0, 0x5F97CD71, 0x240e29e0};
static NX_PTP_TIME             delay_response_ts = {0x0, 0x5F97CD71, 0x2494b730};
static NX_PTP_TIME             synced_time;
static NX_PTP_TIME             expected_time;
static USHORT                  synced_utc_offset;
static USHORT                  expected_utc_offset;
static UCHAR                   ptp_stack[2048];


#define NUM_PACKETS            24
#define PACKET_SIZE            1536
#define PACKET_POOL_SIZE       (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ptp_client_ipv6_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Print out test information banner.  */
    printf("NetX Test:   PTP IPv6 Test ............................................");

#if defined(NX_ENABLE_GPTP) || (NX_PTP_CLIENT_TRANSPORT_UDP==0)
    printf("N/A\n");
    test_control_return(3);
#else 
    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pointer, PACKET_POOL_SIZE);
    pointer = pointer + PACKET_POOL_SIZE;

    ASSERT_SUCCESS(status);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           pointer, 2048, 1);
    pointer = pointer + 2048;

    ASSERT_SUCCESS(status);

#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
    /* Enable IPv6 for both IP instances.  */
    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Check IPv6 enable status.  */
    ASSERT_SUCCESS(status);

    /* Enable ICMPv6 processing for both IP instances.  */
    status = nxd_icmp_enable(&ip_0);      
    status += nxd_icmp_enable(&ip_1);  

    /* Check ICMPv6 enable status.  */
    ASSERT_SUCCESS(status);

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check UDP enable status.  */
    ASSERT_SUCCESS(status);
#endif
#endif
}

#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)

/* PTP handler.  */
static UINT ptp_event_callback(NX_PTP_CLIENT *ptp_client_ptr, UINT event, VOID *event_data, VOID *callback_data)
{
NX_PTP_DATE_TIME date;
    
    NX_PARAMETER_NOT_USED(callback_data);

    switch (event)
    {
        case NX_PTP_CLIENT_EVENT_MASTER:
        {
            DBGPRINTF("new MASTER clock!\r\n");
            break;
        }

        case NX_PTP_CLIENT_EVENT_SYNC:
        {
            nx_ptp_client_sync_info_get((NX_PTP_CLIENT_SYNC *)event_data, NX_NULL, &synced_utc_offset);
            DBGPRINTF("SYNC event: utc offset=%d\r\n", synced_utc_offset);

            /* read the PTP clock */
            nx_ptp_client_time_get(ptp_client_ptr, &synced_time);

            /* convert PTP time to UTC date and time */
            nx_ptp_client_utility_convert_time_to_date(&synced_time, -synced_utc_offset, &date);

            /* display the current time */
            DBGPRINTF("ts: %d%d.%d\r\n", synced_time.second_high,
                                         synced_time.second_low,
                                         synced_time.nanosecond);
            DBGPRINTF("%2u/%02u/%u %02u:%02u:%02u.%09lu\r\n", date.day, date.month, date.year,
                                                              date.hour, date.minute, date.second,
                                                              date.nanosecond);

            break;
        }

        case NX_PTP_CLIENT_EVENT_TIMEOUT:
        {
            DBGPRINTF("Master clock TIMEOUT!\r\n");
            break;
        }
        default:
        {
            break;
        }
    }

    return(0);
}
#endif

/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
UINT status;
NX_PTP_TIME ts_diff = {1, 1, 1};

    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);
    ASSERT_SUCCESS(status);

    /* Sleep for DAD. */
    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);

    /* Reset synced time. */
    memset(&synced_time, 0, sizeof(synced_time));
    synced_utc_offset = 0xFFFF;

    /* Set expected value. */
    expected_utc_offset = 0x1234;
    expected_time.second_high = (delay_response_ts.second_high + follow_up_ts.second_high) / 2;
    expected_time.second_low = (delay_response_ts.second_low + follow_up_ts.second_low) / 2;
    expected_time.nanosecond = (delay_response_ts.nanosecond + follow_up_ts.nanosecond) / 2;
    
    /* Create the PTP client instance */
    status = nx_ptp_client_create(&ptp_client, &ip_0, 0, &pool_0,
                                  2, ptp_stack, sizeof(ptp_stack),
                                  nx_ptp_client_soft_clock_callback, NX_NULL);
    ASSERT_SUCCESS(status);

    /* start the PTP client */
    status = nx_ptp_client_start(&ptp_client, NX_NULL, 0, 0, 0, ptp_event_callback, NX_NULL);
    ASSERT_SUCCESS(status);

    /* Sleep 5 seconds for sync up. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Compare synced time. */
    ASSERT_TRUE(synced_utc_offset == expected_utc_offset);
    status = nx_ptp_client_utility_time_diff(&synced_time, &expected_time, &ts_diff);
    ASSERT_SUCCESS(status);
    ASSERT_TRUE(ts_diff.second_high == 0);
    ASSERT_TRUE(ts_diff.second_low == 0);
    ASSERT_TRUE(ts_diff.nanosecond / 1000000 <= 1000 / NX_PTP_CLIENT_TIMER_TICKS_PER_SECOND);
#endif

    printf("SUCCESS!\n");
    test_control_return(0);
}

/* This thread acts as PTP server, accepting the connection. */
static void    ntest_1_entry(ULONG thread_input)
{
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
DELAY_REQUEST_CONTEXT context;
UINT status;

    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_1, 0, NX_NULL, 10, NX_NULL);
    ASSERT_SUCCESS(status);

    /* Sleep for DAD. */
    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);

    create_socket(&ip_1, &generic_socket, PTP_GENERAL_UDP_PORT);
    create_socket(&ip_1, &event_socket, PTP_EVENT_UDP_PORT);

    /* Sleep 1 second to wait for PTP thread running. */
    tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);

    /* Set data through IPv6.  */
    set_ip_version(NX_IP_VERSION_V6);

    /* Send announce.  */
    send_announce(&generic_socket, &pool_0, expected_utc_offset);

    /* Send sync.  */
    send_sync(&event_socket, &pool_0, &sync_ts);

    /* Send follow up.  */
    send_follow_up(&generic_socket, &pool_0, &follow_up_ts);

    /* Wait for delay request.  */
    status = receive_delay_request(&event_socket, &context, NX_WAIT_FOREVER);
    ASSERT_SUCCESS(status);

    /* Send delay response.  */
    send_delay_response(&generic_socket, &pool_0, &context, &delay_response_ts);
#endif
}