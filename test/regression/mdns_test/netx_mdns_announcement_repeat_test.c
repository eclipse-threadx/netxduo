#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_system.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_SERVER && !defined NX_DISABLE_IPV4
#include   "nxd_mdns.h"
#define     DEMO_STACK_SIZE    2048
#define     BUFFER_SIZE        10240
#define     TOLERANCE          10
#define     LOCAL_FULL_SERVICE_COUNT    16
#define     PEER_FULL_SERVICE_COUNT     16
#define     PEER_PARTIAL_SERVICE_COUNT  32

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static UCHAR                   buffer[BUFFER_SIZE];
static ULONG                   current_buffer_size;

/* Define the timer parameters. */
static UINT                    t;
static UINT                    p;
static UINT                    k;
static UINT                    retrans_interval;
static UINT                    period_interval;
static UINT                    max_time;

/* Define the transmit count. */
static UINT                    retransmit_count;
static UINT                    cycle_count;

static UINT                    last_tick;
static UCHAR                   first_packet;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_announcement_repeat_test(void *first_unused_memory)
#endif
{
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;
    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, 
                          _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);

    /* Check UDP enable status.  */
    if(status)
        error_counter++;
    
    /* Create the test thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, NX_NULL,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE;
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;

    printf("NetX Test:   MDNS Announcement Repeat Test.............................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create mDNS. */
    current_buffer_size = (BUFFER_SIZE >> 1);
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);
    pointer = pointer + DEMO_STACK_SIZE;

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable mDNS.  */
    status = nx_mdns_enable(&mdns_0, 0);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Sleep 5 seconds for host name register. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);


    /* Test default timer parameters. */
    t = 100;
    p = 1;
    k = 1;
    retrans_interval = 0;
    period_interval = 0xFFFFFFFF;
    max_time = 3;
    retransmit_count = p;
    cycle_count = max_time;
    first_packet = NX_TRUE;
    nx_mdns_service_announcement_timing_set(&mdns_0, t, p, k, retrans_interval, period_interval, max_time);

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Add a service. */
    nx_mdns_service_add(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Sleep 5 seconds for service announcement. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Check whether all packets are transmitted. */
    if(retransmit_count || cycle_count)
        error_counter++;
    
    advanced_packet_process_callback = NX_NULL;
    nx_mdns_service_delete(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL);

    /* Sleep 1 seconds for goodbye. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);


    /* Change time parameter t from 100 to 200. */
    /* Test default timer parameters. */
    t = 200;
    p = 1;
    k = 1;
    retrans_interval = 0;
    period_interval = 0xFFFFFFFF;
    max_time = 3;
    retransmit_count = p;
    cycle_count = max_time;
    first_packet = NX_TRUE;
    nx_mdns_service_announcement_timing_set(&mdns_0, t, p, k, retrans_interval, period_interval, max_time);

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Add a service. */
    nx_mdns_service_add(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Sleep 10 seconds for service announcement. */
    tx_thread_sleep(10 * NX_IP_PERIODIC_RATE);

    /* Check whether all packets are transmitted. */
    if(retransmit_count || cycle_count)
        error_counter++;
    
    advanced_packet_process_callback = NX_NULL;
    nx_mdns_service_delete(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL);

    /* Sleep 1 seconds for goodbye. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);


    /* Change time parameter p from 1 to 2. */
    /* Test default timer parameters. */
    t = 100;
    p = 2;
    k = 1;
    retrans_interval = 0;
    period_interval = 0xFFFFFFFF;
    max_time = 3;
    retransmit_count = p;
    cycle_count = max_time;
    first_packet = NX_TRUE;
    nx_mdns_service_announcement_timing_set(&mdns_0, t, p, k, retrans_interval, period_interval, max_time);

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Add a service. */
    nx_mdns_service_add(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Sleep 5 seconds for service announcement. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Check whether all packets are transmitted. */
    if(retransmit_count || cycle_count)
        error_counter++;
    
    advanced_packet_process_callback = NX_NULL;
    nx_mdns_service_delete(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL);

    /* Sleep 1 seconds for goodbye. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);


    /* Change time parameter k from 1 to 2. */
    /* Test default timer parameters. */
    t = 100;
    p = 1;
    k = 2;
    retrans_interval = 0;
    period_interval = 0xFFFFFFFF;
    max_time = 3;
    retransmit_count = p;
    cycle_count = max_time;
    first_packet = NX_TRUE;
    nx_mdns_service_announcement_timing_set(&mdns_0, t, p, k, retrans_interval, period_interval, max_time);

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Add a service. */
    nx_mdns_service_add(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Sleep 10 seconds for service announcement. */
    tx_thread_sleep(10 * NX_IP_PERIODIC_RATE);

    /* Check whether all packets are transmitted. */
    if(retransmit_count || cycle_count)
        error_counter++;
    
    advanced_packet_process_callback = NX_NULL;
    nx_mdns_service_delete(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL);

    /* Sleep 1 seconds for goodbye. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);


    /* Change time parameter p from 1 to 2, retrans_interval from 0 to 100. */
    /* Test default timer parameters. */
    t = 100;
    p = 2;
    k = 1;
    retrans_interval = 100;
    period_interval = 0xFFFFFFFF;
    max_time = 3;
    retransmit_count = p;
    cycle_count = max_time;
    first_packet = NX_TRUE;
    nx_mdns_service_announcement_timing_set(&mdns_0, t, p, k, retrans_interval, period_interval, max_time);

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Add a service. */
    nx_mdns_service_add(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Sleep 10 seconds for service announcement. */
    tx_thread_sleep(10 * NX_IP_PERIODIC_RATE);

    /* Check whether all packets are transmitted. */
    if(retransmit_count || cycle_count)
        error_counter++;
    
    advanced_packet_process_callback = NX_NULL;
    nx_mdns_service_delete(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL);

    /* Sleep 1 seconds for goodbye. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);


    /* Change time parameter max time from 3 to 5. */
    /* Test default timer parameters. */
    t = 100;
    p = 1;
    k = 1;
    retrans_interval = 0;
    period_interval = 0xFFFFFFFF;
    max_time = 5;
    retransmit_count = p;
    cycle_count = max_time;
    first_packet = NX_TRUE;
    nx_mdns_service_announcement_timing_set(&mdns_0, t, p, k, retrans_interval, period_interval, max_time);

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Add a service. */
    nx_mdns_service_add(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Sleep 20 seconds for service announcement. */
    tx_thread_sleep(20 * NX_IP_PERIODIC_RATE);

    /* Check whether all packets are transmitted. */
    if(retransmit_count || cycle_count)
        error_counter++;
    
    advanced_packet_process_callback = NX_NULL;
    nx_mdns_service_delete(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL);

    /* Sleep 1 seconds for goodbye. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);


    /* Change time parameter period_interval from forever to 100, max_time from 3 to forever. */
    /* Test default timer parameters. */
    t = 100;
    p = 1;
    k = 1;
    retrans_interval = 0;
    period_interval = 100;
    max_time = 0xFF;
    retransmit_count = p;
    cycle_count = 300;
    first_packet = NX_TRUE;
    nx_mdns_service_announcement_timing_set(&mdns_0, t, p, k, retrans_interval, period_interval, max_time);

    /* Set callback function pointer. */
    advanced_packet_process_callback = my_packet_process;

    /* Add a service. */
    nx_mdns_service_add(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL, NX_NULL, 100, 0, 0, 80, NX_MDNS_RR_SET_UNIQUE, 0);

    /* Sleep 310 seconds for service announcement. */
    tx_thread_sleep(310 * NX_IP_PERIODIC_RATE);

    /* Check whether all packets are transmitted. */
    if(retransmit_count || cycle_count)
        error_counter++;
    
    advanced_packet_process_callback = NX_NULL;
    nx_mdns_service_delete(&mdns_0, "test", (CHAR *)"_ipp._tcp", NX_NULL);

    /* Sleep 1 seconds for goodbye. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);


    /* Determine if the test was successful.  */
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


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
UCHAR *pointer;
UINT   current_tick;
UINT   expected_tick_diff;
UINT   i;
UINT   base;

    /* Get protocol. */
    pointer = packet_ptr -> nx_packet_prepend_ptr + 9;

    /* Check UDP packets only. */
    if(*pointer != NX_PROTOCOL_UDP)
        return NX_TRUE;

    /* Get port. */
    pointer = packet_ptr -> nx_packet_prepend_ptr + 20;

    /* Check UDP port 5353 only. */
    if((((*pointer << 8) + *(pointer + 1)) != 5353) ||
       (((*(pointer + 2) << 8) + *(pointer + 3)) != 5353))
        return NX_TRUE;

    /* Get flag. */
    pointer = packet_ptr -> nx_packet_prepend_ptr + 30;

    /* Check whether this packet is the announcement. */
    if(((*pointer << 8) + *(pointer + 1)) == (NX_MDNS_RESPONSE_FLAG | NX_MDNS_AA_FLAG))
    {

        /* It is an announcement packet. */
        current_tick = tx_time_get();

        if(first_packet == NX_FALSE)
        {

            /* Check the timer interval. */
            if((p - retransmit_count > 0) && retransmit_count)
            {

                /* The packet is retransmitted in one cycle. */
                expected_tick_diff = retrans_interval;
            }
            else
            {

                /* The packet is retransmitted in a new cycle. */
                expected_tick_diff = t;
                base = 1 << k;
                for(i = (max_time - cycle_count); i > 1; i--)
                {
                    expected_tick_diff *= base;

                    /* Whether the max interval reaches. */
                    if(expected_tick_diff >= period_interval)
                    {
                        expected_tick_diff = period_interval;
                        break;
                    }
                }
            }

            /* Check time interval. */
            if(((int)((current_tick - last_tick) - expected_tick_diff) > TOLERANCE) || 
               ((int)(expected_tick_diff - (current_tick - last_tick)) > TOLERANCE))   
                error_counter++;
        }
        else
            first_packet = NX_FALSE;

        /* Store the current tick. */
        last_tick = current_tick;

        /* Update the count. */
        if(retransmit_count)
            retransmit_count--;
        if(retransmit_count == 0)
        {
            if(cycle_count)
                cycle_count--;
            if(cycle_count)
                retransmit_count = p;
        }
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_announcement_repeat_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Announcement Repeat Test.............................N/A\n");
    test_control_return(3);
}
#endif /* NX_MDNS_DISABLE_SERVER  */
