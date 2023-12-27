/* PTP calibrate test.  This test case validates calibration of PTP client with different values. */

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
static UINT                    test_index;

TEST_TIMESTAMP test_timestamps[] =
{

    /* Basic */
    {
        {0x0, 0x0, 0x0},                /* Sync */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp */
        {0x0, 0x5F97CD71, 0x2494b730},  /* DelayResponse */
        {0x0, 0x0, 0x0},                /* FollowUp_received */
        {0x0, 0x0, 0x0},                /* DelayRequest */
    },

    /* offsetFromMaster is 0 */
    {
        {0x0, 0x0, 0x0},                /* Sync */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp */
        {0x0, 0x5F97CD71, 0x2494b730},  /* DelayResponse */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp_received */
        {0x0, 0x5F97CD71, 0x2494b730},  /* DelayRequest */
    },

    /* offsetFromMaster is positive and less than 1s */
    {
        {0x0, 0x0, 0x0},                /* Sync */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp */
        {0x0, 0x5F97CD71, 0x2494b730},  /* DelayResponse */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp_received */
        {0x0, 0x5F97CD71, 0x2494b710},  /* DelayRequest */
    },

    /* offsetFromMaster is positive and larger than 1s but need to increase second */
    {
        {0x0, 0x0, 0x0},                /* Sync */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp */
        {0x0, 0x5F97CD71, 0x2494b730},  /* DelayResponse */
        {0x0, 0x5F97CD6F, 0x35efcce0},  /* FollowUp_received */
        {0x0, 0x5F97CD6F, 0x36765a10},  /* DelayRequest */
    },

    /* offsetFromMaster is positive and less than 1s but the nanosecond will overflow */
    {
        {0x0, 0x0, 0x0},                /* Sync */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp */
        {0x0, 0x5F97CD71, 0x2494b730},  /* DelayResponse */
        {0x0, 0x5F97CD70, 0x35efcce0},  /* FollowUp_received */
        {0x0, 0x5F97CD70, 0x36765a10},  /* DelayRequest */
    },

    /* offsetFromMaster is negative and less than 1s */
    {
        {0x0, 0x0, 0x0},                /* Sync */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp */
        {0x0, 0x5F97CD71, 0x2494b730},  /* DelayResponse */
        {0x0, 0x5F97CD71, 0x240e29f0},  /* FollowUp_received */
        {0x0, 0x5F97CD71, 0x2494b740},  /* DelayRequest */
    },

    /* offsetFromMaster is negative and larger than 1s but need to decrease second */
    {
        {0x0, 0x0, 0x0},                /* Sync */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp */
        {0x0, 0x5F97CD71, 0x2494b730},  /* DelayResponse */
        {0x0, 0x5F97CD73, 0x3b4d1760},  /* FollowUp_received */
        {0x0, 0x5F97CD74, 0x00000040},  /* DelayRequest */
    },

    /* offsetFromMaster is negative and less than 1s but need to decrease second */
    {
        {0x0, 0x0, 0x0},                /* Sync */
        {0x0, 0x5F97CD71, 0x240e29e0},  /* FollowUp */
        {0x0, 0x5F97CD71, 0x2494b730},  /* DelayResponse */
        {0x0, 0x5F97CD71, 0x3b4d1760},  /* FollowUp_received */
        {0x0, 0x5F97CD72, 0x00000040},  /* DelayRequest */
    },
};


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
void netx_ptp_client_calibrate_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Print out test information banner.  */
    printf("NetX Test:   PTP Calibrate Test .......................................");

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

    if(status)
        ASSERT_SUCCESS(status);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _netx_ptp_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        ASSERT_SUCCESS(status);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if(status)
        ASSERT_SUCCESS(status);

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check UDP enable status.  */
    if(status)
        ASSERT_SUCCESS(status);
#endif
}


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

/* Hijack callback function to modify timestamp.  */
static UINT clock_callback(NX_PTP_CLIENT *client_ptr, UINT operation,
                           NX_PTP_TIME *time_ptr, NX_PACKET *packet_ptr,
                           VOID *callback_data)
{
    if (operation == NX_PTP_CLIENT_CLOCK_PACKET_TS_PREPARE)
    {

        /* Update DelayRequest timestamp. */
        clock_callback(client_ptr, NX_PTP_CLIENT_CLOCK_SET,
                       &test_timestamps[test_index].delay_request, NX_NULL, callback_data);
    }

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    return(_netx_ptp_clock_callback(client_ptr, operation, time_ptr, packet_ptr, callback_data));
#else
    return(nx_ptp_client_soft_clock_callback(client_ptr, operation, time_ptr, packet_ptr, callback_data));
#endif
}

/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
UINT status;
    
    /* Create the PTP client instance */
    status = nx_ptp_client_create(&ptp_client, &ip_0, 0, &pool_0,
                                  2, ptp_stack, sizeof(ptp_stack),
                                  clock_callback, NX_NULL);
    ASSERT_SUCCESS(status);

    for (test_index = 0; test_index < sizeof(test_timestamps) / sizeof(TEST_TIMESTAMP); test_index++)
    {

        /* Start the PTP client */
        status = nx_ptp_client_start(&ptp_client, NX_NULL, 0, 0, 0, ptp_event_callback, NX_NULL);
        ASSERT_SUCCESS(status);

        /* Reset synced time. */
        memset(&synced_time, 0, sizeof(synced_time));
        synced_utc_offset = 0xFFFF;

        /* Set expected value. */
        expected_utc_offset = 0x1234 + test_index;
        calibrate_timestamp(&test_timestamps[test_index], &expected_time);
        
        /* Wake up server thread.  */
        tx_thread_resume(&ntest_1);

        /* Sleep 5 seconds for sync up. */
        tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

        /* Compare synced time. */
        ASSERT_TRUE(synced_utc_offset == expected_utc_offset);
        ASSERT_SUCCESS(memcmp(&synced_time, &expected_time, sizeof(expected_time)));

        /* Stop the PTP client */
        status = nx_ptp_client_stop(&ptp_client);
        ASSERT_SUCCESS(status);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

/* This thread acts as PTP server, accepting the connection. */
static void    ntest_1_entry(ULONG thread_input)
{
DELAY_REQUEST_CONTEXT context;
UINT status;
UINT i;
UINT priority;

    create_socket(&ip_1, &generic_socket, PTP_GENERAL_UDP_PORT);
    create_socket(&ip_1, &event_socket, PTP_EVENT_UDP_PORT);

    for (i = 0; i < sizeof(test_timestamps) / sizeof(TEST_TIMESTAMP); i++)
    {

        /* Suspend current thread and wait for client thread. */
        tx_thread_suspend(tx_thread_identify());

        /* Sleep 1 second to wait for PTP thread running. */
        tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);

        /* Send announce.  */
        send_announce(&generic_socket, &pool_0, expected_utc_offset);

        /* Set the timestamp of FollowUp received.  */
        clock_callback(&ptp_client, NX_PTP_CLIENT_CLOCK_SET,
                       &test_timestamps[i].sync_received, NX_NULL, NX_NULL);

        /* Send sync.  */
        send_sync(&event_socket, &pool_0, &test_timestamps[i].sync);

        /* Send follow up.  */
        send_follow_up(&generic_socket, &pool_0, &test_timestamps[i].follow_up);

        /* Wait for delay request.  */
        status = receive_delay_request(&event_socket, &context, NX_WAIT_FOREVER);
        ASSERT_SUCCESS(status);

        /* Send delay response.  */
        send_delay_response(&generic_socket, &pool_0, &context, &test_timestamps[i].delay_response);
    }
}