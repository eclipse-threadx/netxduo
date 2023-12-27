/**
 * @file sample.c
 * @brief This is a small demo of the high-performance NetX Duo TCP/IP stack.
 *        This program demonstrates link packet sending and receiving with a simulated Ethernet driver.
 *
 */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "netxtestcontrol.h"

extern void test_control_return(UINT);

#if defined(NX_ENABLE_VLAN)
#include    "nx_srp.h"
#include    "nx_link.h"

/* Define demo stack size.   */
#define                 PACKET_SIZE             1536
#define                 NX_PACKET_POOL_SIZE     ((PACKET_SIZE + sizeof(NX_PACKET)) * 30)
#define                 DEMO_STACK_SIZE         2048
#define                 HTTP_STACK_SIZE         2048
#define                 IPERF_STACK_SIZE        2048
#define                 VLAN_TAG                (100 | (3<<13))
#define                 SRP_THREAD_PRIORITY     4

/* Define the ThreadX and NetX object control blocks...  */
TX_THREAD               thread_0;
NX_PACKET_POOL          pool_0;
NX_IP                   ip_0;

UCHAR                   *pointer;
UCHAR                   *http_stack;
UCHAR                   *iperf_stack;
#ifdef FEATURE_NX_IPV6
NXD_ADDRESS             ipv6_address;
#endif
UCHAR                   pool_area[NX_PACKET_POOL_SIZE];

/* Define the counters used in the demo application...  */
ULONG                   error_counter;
NX_SRP                  nx_srp;
static ULONG            srp_stack[2048 *2 / sizeof(ULONG)];

/* Define thread prototypes.  */
VOID    thread_0_entry(ULONG thread_input);
extern  VOID nx_iperf_entry(NX_PACKET_POOL *pool_ptr, NX_IP *ip_ptr, UCHAR* http_stack, ULONG http_stack_size, UCHAR *iperf_stack, ULONG iperf_stack_size);
extern void    test_control_return(UINT status);

/***** Substitute your ethernet driver entry function here *********/
void _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define main entry point.  */
int main()
{

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
}

void increase_err_cnt()
{
    error_counter++;
}

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_mrp_state_machine_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;

    /* Setup the working pointer.  */
    pointer = (UCHAR *) first_unused_memory;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool",
                                   PACKET_SIZE, pool_area, NX_PACKET_POOL_SIZE);

    /* Check for packet pool create errors.  */
    if (status)
        increase_err_cnt();

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(192, 168, 0, 15), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, DEMO_STACK_SIZE, 1);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Check for IP create errors.  */
    if (status)
        increase_err_cnt();

    /* Attach second interface.  */
    status = nx_ip_interface_attach(&ip_0, "NetX IP Interface 0:2",
                                    IP_ADDRESS(192, 168, 100, 15), 0xFFFFFFFFUL, _nx_ram_network_driver);

    if (status)
    {
        increase_err_cnt();
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        increase_err_cnt();

    /* Enable ICMP */
    status = nx_icmp_enable(&ip_0);

    /* Check for ICMP enable errors.  */
    if(status)
        increase_err_cnt();

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);

    /* Check for UDP enable errors.  */
    if (status)
        increase_err_cnt();

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check for TCP enable errors.  */
    if (status)
        increase_err_cnt();

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

#ifdef FEATURE_NX_IPV6
    /* Set up the IPv6 address here. */
    ipv6_address.nxd_ip_address.v6[3] = 0x3;
    ipv6_address.nxd_ip_address.v6[2] = 0x0;
    ipv6_address.nxd_ip_address.v6[1] = 0x0;
    ipv6_address.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;

    /* Enable ICMPv6 services. */
    status = nxd_icmp_enable(&ip_0);
    if (status)
        increase_err_cnt();

    /* Enable IPv6 services. */
    status = nxd_ipv6_enable(&ip_0);
    if (status)
        increase_err_cnt();

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 10, NX_NULL);
    if (status)
        increase_err_cnt();
#endif
}

/* Define the test threads.  */
void    thread_0_entry(ULONG thread_input)
{
UINT status;
ULONG actual_status;
ULONG interface_index;
NX_INTERFACE *interface_ptr;
USHORT vlan_tag;
USHORT pcp;
UCHAR i;
UCHAR pcp_list[8];
UCHAR queue_id_list[8];
UCHAR hw_queue_number, hw_cbs_queue_number;
UINT port_rate;
NX_SRP* srp_ptr;
NX_MRP_ATTRIBUTE* attribute;

    NX_PARAMETER_NOT_USED(thread_input);

    /* Ensure the IP instance has been initialized.  */
    nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_WAIT_FOREVER);

    /* Set the HTTP stack and IPerf stack.  */
    http_stack = pointer;
    pointer += HTTP_STACK_SIZE;
    iperf_stack = pointer;
    pointer += IPERF_STACK_SIZE;

    /* Call entry function to start iperf test.  */
    nx_iperf_entry(&pool_0, &ip_0, http_stack, HTTP_STACK_SIZE, iperf_stack, IPERF_STACK_SIZE);

    interface_index = 0;
    interface_ptr = &(ip_0.nx_ip_interface[interface_index]);

    /* Create the SRP client instance */
    status = nx_srp_init(&nx_srp, &ip_0, 0, &pool_0, (UCHAR *)srp_stack, sizeof(srp_stack), SRP_THREAD_PRIORITY);
    /* Check for error.  */
    if(status)
        increase_err_cnt();

    /* Create an attribute */
    status = nx_mvrp_action_request(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), 100, NX_MVRP_ACTION_NEW);
    /* Check for error.  */
    if(status)
        increase_err_cnt();

    status = nx_mvrp_attribute_find(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), &attribute, 100);
    /* Check for error.  */
    if(status)
        increase_err_cnt();

    /* Case 1: Applicant state machine test */
    /* Begin! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    /* New! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_NEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();
    /* Join! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_JOIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    /* Lv! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    /* rNew! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RNEW);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    /* rJoinIn! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    /* rIn! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RIN);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AA) || (nx_srp.nx_mrp.oper_p2p_mac != NX_FALSE))
        increase_err_cnt();

    /* rJoinMt! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOINMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOINMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOINMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOINMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOINMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    /* rMt! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RMT);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    /* rLv! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    /* rLA! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    /* periodic! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_PERIODIC);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_PERIODIC);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AA))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_PERIODIC);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AP) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    /* tx! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AA) || (attribute ->applicant.action != NX_MRP_ACTION_SJ))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AN) || (attribute ->applicant.action != NX_MRP_ACTION_SN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    attribute ->registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA) || (attribute ->applicant.action != NX_MRP_ACTION_SN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    attribute ->registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AA) || (attribute ->applicant.action != NX_MRP_ACTION_SN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA) || (attribute ->applicant.action != NX_MRP_ACTION_SJ))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO) || (attribute ->applicant.action != NX_MRP_ACTION_SL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA) || (attribute ->applicant.action != NX_MRP_ACTION_SJ))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QP) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TX);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VO) || (attribute ->applicant.action != NX_MRP_ACTION_S))
        increase_err_cnt();

    /* txLA! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AA) || (attribute ->applicant.action != NX_MRP_ACTION_S))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_AN) || (attribute ->applicant.action != NX_MRP_ACTION_SN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA) || (attribute ->applicant.action != NX_MRP_ACTION_SN))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA) || (attribute ->applicant.action != NX_MRP_ACTION_SJ))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA) || (attribute ->applicant.action != NX_MRP_ACTION_SJ))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA) || (attribute ->applicant.action != NX_MRP_ACTION_SJ))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_QA) || (attribute ->applicant.action != NX_MRP_ACTION_SJ))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    /* txLAF! */
    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_VN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AN;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VN) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LA;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_AP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_QP;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_VP) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    attribute ->applicant.state = NX_MRP_APPLICANT_STATE_LO;
    status = nx_mrp_applicant_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLAF);
    if (status || (attribute ->applicant.state != NX_MRP_APPLICANT_STATE_LO) || (attribute ->applicant.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    /* Case 2: Registrar state machine test */
    /* Begin! */
    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_BEGIN);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    /* rNew! */
    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RNEW);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RNEW);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RNEW);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    /* rJoinin! */
    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOININ);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    /* rJoinMt! */
    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOINMT);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOINMT);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RJOINMT);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    /* rLv! */
    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_LV))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_LV))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLV);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    /* rLA! */
    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_LV))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_LV))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_RLA);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    /* txLA! */
    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_LV))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_LV))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_TXLA);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    /* Flush! */
    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_FLUSH);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_FLUSH);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_FLUSH);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    /* Leavetimer! */
    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LEAVETIMER);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_IN))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LEAVETIMER);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
    status = nx_mrp_registrar_event_process(&(nx_srp.nx_mrp), &(nx_srp.nx_mvrp.participant), attribute, NX_MRP_EVENT_LEAVETIMER);
    if (status || (attribute -> registrar.state != NX_MRP_REGISTRAR_STATE_MT))
        increase_err_cnt();

    /* Case 3: LA state machine test */
    /* Begin */
    nx_srp.nx_mvrp.participant.leaveall.state = NX_MRP_LA_STATE_ACTIVE;
    status = nx_mrp_leaveall_event_process(&(nx_srp.nx_mvrp.participant), NX_MRP_EVENT_BEGIN);
    if (status || (nx_srp.nx_mvrp.participant.leaveall.state != NX_MRP_LA_STATE_PASSIVE) || (nx_srp.nx_mvrp.participant.leaveall.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    nx_srp.nx_mvrp.participant.leaveall.state = NX_MRP_LA_STATE_PASSIVE;
    status = nx_mrp_leaveall_event_process(&(nx_srp.nx_mvrp.participant), NX_MRP_EVENT_BEGIN);
    if (status || (nx_srp.nx_mvrp.participant.leaveall.state != NX_MRP_LA_STATE_PASSIVE) || (nx_srp.nx_mvrp.participant.leaveall.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    /* tx! */
    nx_srp.nx_mvrp.participant.leaveall.state = NX_MRP_LA_STATE_ACTIVE;
    status = nx_mrp_leaveall_event_process(&(nx_srp.nx_mvrp.participant), NX_MRP_EVENT_TX);
    if (status || (nx_srp.nx_mvrp.participant.leaveall.state != NX_MRP_LA_STATE_PASSIVE) || (nx_srp.nx_mvrp.participant.leaveall.action != NX_MRP_ACTION_SLA))
        increase_err_cnt();

    nx_srp.nx_mvrp.participant.leaveall.state = NX_MRP_LA_STATE_PASSIVE;
    status = nx_mrp_leaveall_event_process(&(nx_srp.nx_mvrp.participant), NX_MRP_EVENT_TX);
    if (status || (nx_srp.nx_mvrp.participant.leaveall.state != NX_MRP_LA_STATE_PASSIVE) || (nx_srp.nx_mvrp.participant.leaveall.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    /* rLA! */
    nx_srp.nx_mvrp.participant.leaveall.state = NX_MRP_LA_STATE_ACTIVE;
    status = nx_mrp_leaveall_event_process(&(nx_srp.nx_mvrp.participant), NX_MRP_EVENT_RLA);
    if (status || (nx_srp.nx_mvrp.participant.leaveall.state != NX_MRP_LA_STATE_PASSIVE) || (nx_srp.nx_mvrp.participant.leaveall.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    nx_srp.nx_mvrp.participant.leaveall.state = NX_MRP_LA_STATE_PASSIVE;
    status = nx_mrp_leaveall_event_process(&(nx_srp.nx_mvrp.participant), NX_MRP_EVENT_RLA);
    if (status || (nx_srp.nx_mvrp.participant.leaveall.state != NX_MRP_LA_STATE_PASSIVE) || (nx_srp.nx_mvrp.participant.leaveall.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    /* rLA! */
    nx_srp.nx_mvrp.participant.leaveall.state = NX_MRP_LA_STATE_ACTIVE;
    status = nx_mrp_leaveall_event_process(&(nx_srp.nx_mvrp.participant), NX_MRP_EVENT_LEAVEALLTIMER);
    if (status || (nx_srp.nx_mvrp.participant.leaveall.state != NX_MRP_LA_STATE_ACTIVE) || (nx_srp.nx_mvrp.participant.leaveall.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    nx_srp.nx_mvrp.participant.leaveall.state = NX_MRP_LA_STATE_PASSIVE;
    status = nx_mrp_leaveall_event_process(&(nx_srp.nx_mvrp.participant), NX_MRP_EVENT_LEAVEALLTIMER);
    if (status || (nx_srp.nx_mvrp.participant.leaveall.state != NX_MRP_LA_STATE_ACTIVE) || (nx_srp.nx_mvrp.participant.leaveall.action != NX_MRP_ACTION_NULL))
        increase_err_cnt();

    /*Check the status. */
    if (error_counter == 0)
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
    else
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_mrp_state_machine_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   MRP State Machine Test.......................................N/A\n");
    test_control_return(3);
}

#endif
