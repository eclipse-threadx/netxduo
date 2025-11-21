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
#define PORT_RATE 100
/* Define demo stack size.   */
#define                 PACKET_SIZE             1536
#define                 NX_PACKET_POOL_SIZE     ((PACKET_SIZE + sizeof(NX_PACKET)) * 30)
#define                 DEMO_STACK_SIZE         2048
#define                 HTTP_STACK_SIZE         2048
#define                 IPERF_STACK_SIZE        2048
#define                 VLAN_ID                 100

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

/* Define thread prototypes.  */
VOID    thread_0_entry(ULONG thread_input);
extern  VOID nx_iperf_entry(NX_PACKET_POOL *pool_ptr, NX_IP *ip_ptr, UCHAR* http_stack, ULONG http_stack_size, UCHAR *iperf_stack, ULONG iperf_stack_size);
extern void    test_control_return(UINT status);

/***** Substitute your ethernet driver entry function here *********/
void _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_shaper_cbs_test_application_define(void *first_unused_memory)
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

    status = nx_link_vlan_set(&ip_0, 1, VLAN_ID);
    if (status)
        error_counter++;

}

UINT demo_cbs_set(void* cbs_param, UCHAR shaper_type)
{
    return NX_SUCCESS;
}

UINT nx_cbs_driver(struct NX_SHAPER_DRIVER_PARAMETER_STRUCT *parameter)
{
    switch (parameter -> nx_shaper_driver_command)
    {
        case NX_SHAPER_COMMAND_INIT:
            break;

        case NX_SHAPER_COMMAND_CONFIG:
            break;

        case NX_SHAPER_COMMAND_PARAMETER_SET:
            break;

        default:
            break;
    }

    return (NX_SUCCESS);
}

/* Define the test threads.  */
void    thread_0_entry(ULONG thread_input)
{
UINT status;
ULONG actual_status;
ULONG interface_index;
NX_INTERFACE *interface_ptr;
NX_SHAPER_CBS_PARAMETER cbs_param;
USHORT pcp;
UCHAR i;
UCHAR pcp_list[8];
UCHAR queue_id_list[8];
UCHAR hw_queue_number, hw_cbs_queue_number;
UINT port_rate;

NX_SHAPER_CONTAINER shaper_container;
NX_SHAPER cbs_shaper;
NX_SHAPER_CBS_PARAMETER cbs_config;
UCHAR shaper_capability;
NX_SHAPER_HW_QUEUE hw_queue[8];
UINT index;

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

    memset(&shaper_container , 0, sizeof(NX_SHAPER_CONTAINER));
    /* Case 1: init shaper with 3 hw queue, 2 cbs hw queue */
    status = nx_shaper_create(interface_ptr, &shaper_container, &cbs_shaper, NX_SHAPER_TYPE_CBS, nx_cbs_driver);
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

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, 3, hw_queue);
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

    /* Case 2: init shaper with 4 hw queue, 2 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;
    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, 4, hw_queue);
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

    /* Case 3: init shaper with 5 hw queue, 2 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;
    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, 5, hw_queue);
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

    /* Case 4: init shaper with 6 hw queue, 2 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;
    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 5;
    hw_queue[index].priority = 6;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, 6, hw_queue);
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

    /* Case 5: init shaper with 7 hw queue, 2 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;
    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 5;
    hw_queue[index].priority = 6;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 6;
    hw_queue[index].priority = 7;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, 7, hw_queue);
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

    /* Case 6: init shaper with 8 hw queue, 2 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;
    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 5;
    hw_queue[index].priority = 6;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 6;
    hw_queue[index].priority = 7;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 7;
    hw_queue[index].priority = 8;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, 8, hw_queue);
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

    /* Case 7: init shaper with 2 hw queue, 1 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;

    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Case 8: init shaper with 3 hw queue, 1 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;

    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }


    /* Case 9: init shaper with 4 hw queue, 1 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;

    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Case 10: init shaper with 5 hw queue, 1 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;

    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Case 10.1: init shaper with 5 hw queue, 1 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;

    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_INVALID_PARAMETERS)
    {

        error_counter++;
        return;
    }

    /* Case 10.2: init shaper with 5 hw queue, 1 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;

    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;

    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Case 11: init shaper with 6 hw queue, 1 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;

    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 5;
    hw_queue[index].priority = 6;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;
    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Case 12: init shaper with 7 hw queue, 1 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;

    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 5;
    hw_queue[index].priority = 6;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 6;
    hw_queue[index].priority = 7;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;
    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Case 13 init shaper with 8 hw queue, 1 cbs hw queue */
    memset(interface_ptr -> shaper_container -> hw_queue, 0, sizeof(interface_ptr -> shaper_container -> hw_queue));
    index = 0;

    hw_queue[index].hw_queue_id = 0;
    hw_queue[index].priority = 1;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 1;
    hw_queue[index].priority = 2;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 2;
    hw_queue[index].priority = 3;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 3;
    hw_queue[index].priority = 4;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 4;
    hw_queue[index].priority = 5;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 5;
    hw_queue[index].priority = 6;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 6;
    hw_queue[index].priority = 7;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_NORMAL;

    hw_queue[index].hw_queue_id = 7;
    hw_queue[index].priority = 8;
    hw_queue[index++].type = NX_SHAPER_HW_QUEUE_CBS;
    status = nx_shaper_config(interface_ptr, PORT_RATE, shaper_capability, index, hw_queue);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Case 14: set default mapping */
    memset(pcp_list, 0, sizeof(pcp_list));
    memset(queue_id_list, 0, sizeof(queue_id_list));
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

    /* Case 15: get current mapping */
    memset(pcp_list, 0, sizeof(pcp_list));
    memset(queue_id_list, 0, sizeof(queue_id_list));
    status = nx_shaper_current_mapping_get(interface_ptr, pcp_list, queue_id_list, 8);
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Case 17: set the cbs parameters */
    status = nx_shaper_port_rate_get(interface_ptr, &port_rate);
    cbs_param.idle_slope = 30; // 30Mbps, 30 percent bandwidth reserve for cbs queue
    cbs_param.send_slope = 30 - port_rate;
    cbs_param.hi_credit = 463;
    cbs_param.low_credit = -1079;
    status = nx_shaper_cbs_parameter_set(interface_ptr, &cbs_param, NX_SHAPER_CLASS_B_PCP);
    /* Check status...  */
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
void netx_shaper_cbs_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Shaper CBS Test.......................................N/A\n");
    test_control_return(3);
}

#endif