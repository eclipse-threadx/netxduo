#include    "nx_api.h"
#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_IPV4
#include    "netx_mdns_test.h"

#define     DEMO_STACK_SIZE             2048
#define     LOCAL_BUFFER_SIZE           5120
#define     PEER_BUFFER_SIZE            5120
#define     LOCAL_FULL_SERVICE_COUNT    16
#define     PEER_FULL_SERVICE_COUNT     16
#define     PEER_PARTIAL_SERVICE_COUNT  32


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static UCHAR                   local_buffer[LOCAL_BUFFER_SIZE];
static UCHAR                   peer_buffer[PEER_BUFFER_SIZE];
static ULONG                   current_buffer_size;
static UCHAR                   mdns_stack[DEMO_STACK_SIZE];


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */
static void         thread_0_entry(ULONG thread_input);
extern void         test_control_return(UINT status);
extern void         _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define the test threads.  */
extern MDNS_TEST_SEQ mdns_response_with_tc[];
extern MDNS_TEST_SEQ mdns_query_with_tc[];
extern MDNS_TEST_SEQ mdns_announcement_in_multiple_packets[];
extern MDNS_TEST_SEQ mdns_response_in_multiple_packets[];
extern MDNS_TEST_SEQ mdns_address_change[];
extern MDNS_TEST_SEQ mdns_case_insensitivity[];
extern MDNS_TEST_SEQ mdns_poof[];
extern MDNS_TEST_SEQ mdns_query_during_probing[];
extern MDNS_TEST_SEQ mdns_server_interface_reset[];
extern MDNS_TEST_SEQ mdns_server_send_goodbye[];
extern MDNS_TEST_SEQ mdns_dns_sd_query[];
extern MDNS_TEST_SEQ mdns_dns_sd_response[];
extern MDNS_TEST_SEQ mdns_server_announcement_with_txt[];
extern MDNS_TEST_SEQ mdns_probing_conflict[];
extern MDNS_TEST_SEQ mdns_response_no_delay[];
extern MDNS_TEST_SEQ mdns_response_interval[];
extern MDNS_TEST_SEQ mdns_response_aggregation[];
extern MDNS_TEST_SEQ mdns_known_answer_ignored[];
extern MDNS_TEST_SEQ mdns_known_answer_suppression_query[];
extern MDNS_TEST_SEQ mdns_known_answer_suppression_query_half_ttl[];
extern MDNS_TEST_SEQ mdns_known_answer_suppression_response[];
extern MDNS_TEST_SEQ mdns_known_answer_suppression_unique[];
extern MDNS_TEST_SEQ mdns_duplicate_question_suppression[];
extern MDNS_TEST_SEQ mdns_duplicate_answer_suppression[];
extern MDNS_TEST_SEQ mdns_one_shot_query[];
extern MDNS_TEST_SEQ mdns_continuous_query[];
extern MDNS_TEST_SEQ mdns_continuous_query_a[];
extern MDNS_TEST_SEQ mdns_continuous_query_unique_answer[];
extern MDNS_TEST_SEQ mdns_continuous_query_interval[];
extern MDNS_TEST_SEQ mdns_query_start_stop[];
extern MDNS_TEST_SEQ mdns_query_http_tcp[];
extern MDNS_TEST_SEQ mdns_query_pdl_datastream_tcp[];
extern MDNS_TEST_SEQ mdns_query_printer_tcp[];
extern MDNS_TEST_SEQ mdns_query_smb_tcp[];
extern MDNS_TEST_SEQ mdns_query_and_response_chaos[];
extern MDNS_TEST_SEQ mdns_multiple_questions_per_query[];
extern MDNS_TEST_SEQ mdns_basic_ipv6_query[];
extern MDNS_TEST_SEQ mdns_basic_ipv6_response[];
extern MDNS_TEST_SEQ mdns_basic_ipv6_announcement[];
extern MDNS_TEST_SEQ mdns_response_to_address_query[];
extern MDNS_TEST_SEQ mdns_client_passive[];
extern MDNS_TEST_SEQ mdns_client_passive_02[];
extern MDNS_TEST_SEQ mdns_query_rr_timeout[];

extern int mdns_response_with_tc_size;
extern int mdns_query_with_tc_size;
extern int mdns_announcement_in_multiple_packets_size;
extern int mdns_response_in_multiple_packets_size;
extern int mdns_address_change_size;
extern int mdns_case_insensitivity_size;
extern int mdns_poof_size;
extern int mdns_query_during_probing_size;
extern int mdns_server_interface_reset_size;
extern int mdns_server_send_goodbye_size;
extern int mdns_dns_sd_query_size;
extern int mdns_dns_sd_response_size;
extern int mdns_server_announcement_with_txt_size;
extern int mdns_probing_conflict_size;
extern int mdns_response_no_delay_size;
extern int mdns_response_interval_size;
extern int mdns_response_aggregation_size;
extern int mdns_known_answer_ignored_size;
extern int mdns_known_answer_suppression_query_size;
extern int mdns_known_answer_suppression_query_half_ttl_size;
extern int mdns_known_answer_suppression_response_size;
extern int mdns_known_answer_suppression_unique_size;
extern int mdns_duplicate_question_suppression_size;
extern int mdns_duplicate_answer_suppression_size;
extern int mdns_one_shot_query_size;
extern int mdns_continuous_query_size;
extern int mdns_continuous_query_a_size;
extern int mdns_continuous_query_unique_answer_size;
extern int mdns_continuous_query_interval_size;
extern int mdns_query_start_stop_size;
extern int mdns_query_http_tcp_size;
extern int mdns_query_pdl_datastream_tcp_size;
extern int mdns_query_printer_tcp_size;
extern int mdns_query_smb_tcp_size;
extern int mdns_query_and_response_chaos_size;
extern int mdns_multiple_questions_per_query_size;
extern int mdns_basic_ipv6_query_size;
extern int mdns_basic_ipv6_response_size;
extern int mdns_basic_ipv6_announcement_size;
extern int mdns_response_to_address_query_size;
extern int mdns_client_passive_size;
extern int mdns_client_passive_size_02;
extern int mdns_query_rr_timeout_size;

static MDNS_TEST_SUITE test_suite[] = 
{

#ifndef NX_MDNS_DISABLE_SERVER
    {&mdns_address_change[0], &mdns_address_change_size},
    {&mdns_case_insensitivity[0], &mdns_case_insensitivity_size},
    {&mdns_query_during_probing[0], &mdns_query_during_probing_size},
    {&mdns_server_interface_reset[0], &mdns_server_interface_reset_size},
    {&mdns_server_send_goodbye[0], &mdns_server_send_goodbye_size},
    {&mdns_dns_sd_response[0], &mdns_dns_sd_response_size},
    {&mdns_probing_conflict[0], &mdns_probing_conflict_size},
    {&mdns_server_announcement_with_txt[0], &mdns_server_announcement_with_txt_size},
    {&mdns_response_no_delay[0], &mdns_response_no_delay_size},
    {&mdns_response_interval[0], &mdns_response_interval_size},
    {&mdns_response_aggregation[0], &mdns_response_aggregation_size},
    {&mdns_response_with_tc[0], &mdns_response_with_tc_size},
    {&mdns_known_answer_suppression_response[0], &mdns_known_answer_suppression_response_size},
    {&mdns_known_answer_suppression_unique[0], &mdns_known_answer_suppression_unique_size},
    {&mdns_duplicate_answer_suppression[0], &mdns_duplicate_answer_suppression_size},
#if (NX_PHYSICAL_HEADER < 48) /* If the header is too large, the RRs in one packet will be different with the message captured.  */
    {&mdns_announcement_in_multiple_packets[0], &mdns_announcement_in_multiple_packets_size},
#endif
#ifdef NX_MDNS_ENABLE_IPV6
    {&mdns_response_in_multiple_packets[0], &mdns_response_in_multiple_packets_size},
    {&mdns_basic_ipv6_response[0], &mdns_basic_ipv6_response_size},
    {&mdns_basic_ipv6_announcement[0], &mdns_basic_ipv6_announcement_size},
    {&mdns_response_to_address_query[0], &mdns_response_to_address_query_size},
#endif /* NX_MDNS_ENABLE_IPV6  */
#endif /* NX_MDNS_DISABLE_SERVER  */

#ifndef NX_MDNS_DISABLE_CLIENT
    {&mdns_poof[0], &mdns_poof_size},
    {&mdns_dns_sd_query[0], &mdns_dns_sd_query_size},
    {&mdns_known_answer_ignored[0], &mdns_known_answer_ignored_size},
    {&mdns_known_answer_suppression_query[0], &mdns_known_answer_suppression_query_size},
    {&mdns_known_answer_suppression_query_half_ttl[0], &mdns_known_answer_suppression_query_half_ttl_size},
    {&mdns_duplicate_question_suppression[0], &mdns_duplicate_question_suppression_size},
    {&mdns_continuous_query[0], &mdns_continuous_query_size},
    {&mdns_continuous_query_unique_answer[0], &mdns_continuous_query_unique_answer_size},
    {&mdns_continuous_query_interval[0], &mdns_continuous_query_interval_size},
    {&mdns_query_start_stop[0], &mdns_query_start_stop_size},
    {&mdns_query_http_tcp[0], &mdns_query_http_tcp_size},
    {&mdns_query_pdl_datastream_tcp[0], &mdns_query_pdl_datastream_tcp_size},
    {&mdns_query_printer_tcp[0], &mdns_query_printer_tcp_size},
    {&mdns_query_smb_tcp[0], &mdns_query_smb_tcp_size},
    {&mdns_query_and_response_chaos[0], &mdns_query_and_response_chaos_size},
    {&mdns_query_with_tc[0], &mdns_query_with_tc_size},
    {&mdns_query_rr_timeout[0], &mdns_query_rr_timeout_size},
    {&mdns_multiple_questions_per_query[0], &mdns_multiple_questions_per_query_size},
    {&mdns_client_passive[0], &mdns_client_passive_size},
#ifdef NX_MDNS_ENABLE_IPV6
    {&mdns_basic_ipv6_query[0], &mdns_basic_ipv6_query_size},
#endif /* NX_MDNS_ENABLE_IPV6  */
#endif /* NX_MDNS_DISABLE_CLIENT  */
};


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_ram_test_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;
 
    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*32);
    pointer = pointer + 1536*32;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(10, 0, 0, 66), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ICMP for IP Instance 0.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check ARP enable status.  */
    if(status)
        error_counter++;

    /* Enable fragment processing for IP Instance 0.  */
    status = nx_ip_fragment_enable(&ip_0);

    /* Check fragment enable status.  */
    if(status)
        error_counter++;

    /* Enable UDP processing for IP Instance 0.  */
    status = nx_udp_enable(&ip_0);

    /* Check UDP enable status.  */
    if(status)
        error_counter++;

    /* Enable igmp processing for IP Instance 0.  */
    status = nx_igmp_enable(&ip_0);

    /* Check status. */
    if(status)
        error_counter++;
    
#if defined FEATURE_NX_IPV6 && defined NX_ENABLE_IPV6_MULTICAST
    /* Enable IPv6 processing for IP Instance 0.  */
    status = nxd_ipv6_enable(&ip_0);
#endif /* FEATURE_NX_IPV6 && NX_ENABLE_IPV6_MULTICAST */

    /* Check status. */
    if(status)
        error_counter++;
    
}

static void    thread_0_entry(ULONG thread_input)
{
int num_suite;
int i;

    num_suite = sizeof(test_suite) / sizeof(MDNS_TEST_SUITE);
    
    for(i = 0; i < num_suite; i++)
    {

        /* Create mDNS. */
        if(nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, mdns_stack, DEMO_STACK_SIZE, "ARMMDNSTest", 
                          local_buffer, LOCAL_BUFFER_SIZE, peer_buffer, PEER_BUFFER_SIZE, netx_mdns_probing_notify))
            error_counter++;

        /* Make sure the service probing and host probing in one packet for some test cases.  */
        mdns_0.nx_mdns_first_probing_delay = NX_MDNS_PROBING_TIMER_COUNT;

        /* Enable interface. */
        if(nx_mdns_enable(&mdns_0, 0))
            error_counter++;
        
        /* Run test case. */
        if(test_suite[i].test_case)
            netx_mdns_run_test_case(&ip_0, &mdns_0, test_suite[i].test_case, *(test_suite[i].test_case_size));

        /* Delete mDNS. */
        if(nx_mdns_delete(&mdns_0))
            error_counter++;
    }

    test_control_return(0xdeadbeef);
}
#endif /* __PRODUCT_NETXDUO__ && !NX_DISABLE_IPV4   */
