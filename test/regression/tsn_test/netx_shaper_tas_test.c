/**
 * @file sample.c
 * @brief This is a small demo of the high-performance NetX Duo TCP/IP stack.
 *        This program demonstrates link packet sending and receiving with a simulated Ethernet driver.
 *
 */
#include   "tx_api.h"
#include   "nx_api.h"
#include    "netxtestcontrol.h"

extern void test_control_return(UINT);

#if defined(NX_ENABLE_VLAN)
#include   "nx_link.h"
#include   "nx_shaper.h"

/* Define demo stack size.   */
#define                 PACKET_SIZE             1536
#define                 NX_PACKET_POOL_SIZE     ((PACKET_SIZE + sizeof(NX_PACKET)) * 30)
#define                 DEMO_STACK_SIZE         2048
#define                 HTTP_STACK_SIZE         2048
#define                 IPERF_STACK_SIZE        2048
#define                 VLAN_TAG_1              (200 | (2<<13))
#define                 VLAN_TAG_2              (300 | (3<<13))
#define                 PORT_RATE               100
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
NX_SHAPER               shaper;
UINT                    interface_1_id;
UINT                    interface_2_id;

/* Define thread prototypes.  */
VOID    thread_0_entry(ULONG thread_input);
extern  VOID nx_iperf_entry(NX_PACKET_POOL *pool_ptr, NX_IP *ip_ptr, UCHAR* http_stack, ULONG http_stack_size, UCHAR *iperf_stack, ULONG iperf_stack_size);
extern void    test_control_return(UINT status);

extern UINT nx_tas_driver(NX_SHAPER_DRIVER_PARAMETER *params);
extern UINT nx_cbs_driver(NX_SHAPER_DRIVER_PARAMETER *params);
/***** Substitute your ethernet driver entry function here *********/
void _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_shaper_tas_test_application_define(void *first_unused_memory)
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
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(192, 168, 0, 15), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, DEMO_STACK_SIZE, 1);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Attach second interface.  */
    status = nx_ip_interface_attach(&ip_0, "NetX IP Interface 0:2",
                                    IP_ADDRESS(192, 168, 100, 15), 0xFFFFFFFFUL, _nx_ram_network_driver);

    if (status)
    {
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP */
    status = nx_icmp_enable(&ip_0);

    /* Check for ICMP enable errors.  */
    if(status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check for TCP enable errors.  */
    if (status)
        error_counter++;

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
        error_counter++;

    /* Enable IPv6 services. */
    status = nxd_ipv6_enable(&ip_0);
    if (status)
        error_counter++;

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 10, NX_NULL);
    if (status)
        error_counter++;
#endif

    status = nx_link_vlan_interface_create(&ip_0, "NetX IP Interface 0:2", IP_ADDRESS(192, 168, 200, 2), 0xFFFFFF00UL, VLAN_TAG_1, 0, &interface_1_id);
    if (status)
    {
        error_counter++;
    }

    status = nx_link_vlan_interface_create(&ip_0, "NetX IP Interface 0:3", IP_ADDRESS(192, 168, 300, 2), 0xFFFFFF00UL, VLAN_TAG_2, 0, &interface_2_id);
    if (status)
    {
        error_counter++;
    }
}

UINT demo_cbs_set(void* cbs_param, UCHAR shaper_type)
{
    return NX_SUCCESS;
}

UINT nx_tas_driver(struct NX_SHAPER_DRIVER_PARAMETER_STRUCT *parameter)
{
    return NX_SUCCESS;
}

UINT nx_fp_driver(struct NX_SHAPER_DRIVER_PARAMETER_STRUCT *parameter)
{
    return (NX_SUCCESS);
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

NX_SHAPER_CONTAINER shaper_container;
NX_SHAPER tas_shaper;
NX_SHAPER fp_shaper;
NX_SHAPER_TAS_CONFIG tas_config;
NX_SHAPER_FP_PARAMETER fp_param;
UCHAR shaper_capability;
UINT index;
NX_SHAPER_HW_QUEUE hw_queue[8];

    NX_PARAMETER_NOT_USED(thread_input);

    memset(&tas_config, 0, sizeof(tas_config));
    memset(&shaper_container , 0, sizeof(NX_SHAPER_CONTAINER));
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


/* Example start */
    /* case 1: Config TAS shaper: NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_WITH_CLOSE */
    status = nx_shaper_create(interface_ptr, &shaper_container, &tas_shaper, NX_SHAPER_TYPE_TAS, nx_tas_driver);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    status = nx_shaper_create(interface_ptr, &shaper_container, &fp_shaper, NX_SHAPER_TYPE_FP, nx_fp_driver);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    shaper_capability = NX_SHAPER_CAPABILITY_CBS_SUPPORTED | \
                        NX_SHAPER_CAPABILITY_TAS_SUPPORTED | \
                        NX_SHAPER_CAPABILITY_PREEMPTION_SUPPORTED;

    index = 0;
    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    status = nx_shaper_default_mapping_get(interface_ptr, pcp_list, queue_id_list, 8);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    status = nx_shaper_mapping_set(interface_ptr, pcp_list, queue_id_list, 8);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    memset(&fp_param, 0, sizeof(NX_SHAPER_FP_PARAMETER));
    fp_param.verification_enable = NX_TRUE;
    fp_param.express_guardband_enable = NX_TRUE;
    fp_param.express_queue_bitmap = (1 << 3) | (1 << 2);
    fp_param.ha = NX_SHAPER_FP_DEFAULT_HA;
    fp_param.ra = NX_SHAPER_FP_DEFAULT_RA;

    status = nx_shaper_fp_parameter_set(interface_ptr, &fp_param);
    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    tas_config.base_time = 0;
    tas_config.cycle_time = 1000;
    tas_config.auto_fill_status = NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_WITH_CLOSE;
    tas_config.traffic_count = 2;

    tas_config.traffic[0].pcp = 3;
    tas_config.traffic[0].time_offset = 0;
    tas_config.traffic[0].duration = 200;
    tas_config.traffic[0].traffic_control = NX_SHAPER_TRAFFIC_OPEN;

    tas_config.traffic[1].pcp = 2;
    tas_config.traffic[1].time_offset = 400;
    tas_config.traffic[1].duration = 100;
    tas_config.traffic[1].traffic_control = NX_SHAPER_TRAFFIC_OPEN;

    status = nx_shaper_tas_parameter_set(interface_ptr, &tas_config);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }
/* Example end */
    /* case 2: Config TAS shaper: NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_WITH_OPEN */
    tas_config.auto_fill_status = NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_WITH_OPEN;
    status = nx_shaper_tas_parameter_set(interface_ptr, &tas_config);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* case 3: Config TAS shaper: NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_DISABLED */
    tas_config.auto_fill_status = NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_DISABLED;
    status = nx_shaper_tas_parameter_set(interface_ptr, &tas_config);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

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
void netx_shaper_tas_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Shaper TAS Test.......................................N/A\n");
    test_control_return(3);
}

#endif