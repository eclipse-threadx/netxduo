/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */ 
/** NetX Component                                                        */ 
/**                                                                       */
/**   RAM Network (RAM)                                                   */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

/* Include necessary system files. */

#include "nx_api.h"
#include "nx_ram_network_driver_test_1500.h"
#ifdef NX_ENABLE_INTERFACE_CAPABILITY
#define NX_DROP_ERROR_CHECKSUM
#include "nx_ip.h"
#include "nx_tcp.h"
#include "nx_udp.h"
#include "nx_icmp.h"
#include "nx_igmp.h"
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */


#ifdef NX_BSD_RAW_PPPOE_SUPPORT
#include "nxd_bsd.h"
#endif /* NX_BSD_RAW_PPPOE_SUPPORT */

#if defined(__PRODUCT_NETXDUO__) && defined(NX_ENABLE_VLAN)
#include "nx_link.h"
#endif

#ifdef NX_PCAP_ENABLE
#ifdef linux
#include "sys/time.h"
#else
#include "winsock.h"
#endif
FILE      *nx_network_driver_pcap_fp = NX_NULL;
#endif /* NX_PCAP_ENABLE  */

#ifdef NX_PPP_PPPOE_ENABLE
#include "nx_pppoe_client.h"
#include "nx_pppoe_server.h"

extern NX_PPPOE_CLIENT *_nx_pppoe_client_created_ptr;
extern NX_PPPOE_SERVER *_nx_pppoe_server_created_ptr;
#endif

ULONG      fragment_order_test =   0;
ULONG      packet_gather =   0;
ULONG      packet_drop   =   0;
NX_PACKET *packet_save[4] =  {0, 0, 0, 0};
NX_PACKET_POOL *driver_pool = NX_NULL;
CHAR       driver_data_buffer[3014];
ULONG      driver_data_length;

/* Define Ethernet address format.  This is prepended to the incoming IP
   and ARP/RARP messages.  The frame beginning is 14 bytes, but for speed 
   purposes, we are going to assume there are 16 bytes free in front of the
   prepend pointer and that the prepend pointer is 32-bit aligned.  

    Byte Offset     Size            Meaning

        0           6           Destination Ethernet Address
        6           6           Source Ethernet Address
        12          2           Ethernet Frame Type, where:
                                    
                                        0x0800 -> IP Datagram
                                        0x0806 -> ARP Request/Reply
                                        0x0835 -> RARP request reply

        42          18          Padding on ARP and RARP messages only.  */

#define NX_ETHERNET_IP                 0x0800
#define NX_ETHERNET_ARP                0x0806
#define NX_ETHERNET_RARP               0x8035
#define NX_ETHERNET_IPV6               0x86DD
#ifdef NX_PPP_PPPOE_ENABLE
#define NX_ETHERNET_PPPOE_DISCOVERY    0x8863
#define NX_ETHERNET_PPPOE_SESSION      0x8864
#endif
#define NX_ETHERNET_SIZE    14

#define NX_LINK_MTU      1514

/* For the simulated ethernet driver, physical addresses are allocated starting
   at the preset value and then incremented before the next allocation.  */

ULONG   simulated_address_msw =  0x0011;
ULONG   simulated_address_lsw =  0x22334456;

#define NX_MAX_RAM_INTERFACES 8 
#define NX_RAM_DRIVER_MAX_MCAST_ADDRESSES 8

typedef struct MAC_ADDRESS_STRUCT
{
    ULONG nx_mac_address_msw;
    ULONG nx_mac_address_lsw;

} MAC_ADDRESS;


/* Define an application-specific data structure that holds internal
   data (such as the state information) of a device driver.  

   The example below applies to the simulated RAM driver.  
   User shall replace its content with information related to 
   the actual driver being used. */
typedef struct _nx_ram_network_driver_instance_type
{
    UINT                nx_ram_network_driver_in_use;
    UINT                nx_ram_network_driver_id;
    NX_INTERFACE        *nx_ram_driver_interface_ptr;
    NX_IP               *nx_ram_driver_ip_ptr;
    MAC_ADDRESS         nx_ram_driver_mac_address;
    MAC_ADDRESS         nx_ram_driver_mcast_address[NX_RAM_DRIVER_MAX_MCAST_ADDRESSES];

} _nx_ram_network_driver_instance_type;

/* In this example, there are four instances of the simulated RAM driver.
   Therefore an array of four driver instances are created to keep track of 
   the interface information of each driver. */
static _nx_ram_network_driver_instance_type nx_ram_driver[NX_MAX_RAM_INTERFACES];


/* Define driver prototypes.  */

VOID _nx_ram_network_driver_internal(NX_IP_DRIVER *driver_req_ptr, UINT mtu_size);
VOID _nx_ram_network_driver_3000(NX_IP_DRIVER *driver_req_ptr)
{
    _nx_ram_network_driver_internal(driver_req_ptr, 3000);
}
VOID _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr)
{
    _nx_ram_network_driver_internal(driver_req_ptr, 1500);
}
VOID _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr)
{
    _nx_ram_network_driver_internal(driver_req_ptr, 1024);
}
VOID _nx_ram_network_driver_512(NX_IP_DRIVER *driver_req_ptr)
{
    _nx_ram_network_driver_internal(driver_req_ptr, 512);
}
VOID _nx_ram_network_driver_256(NX_IP_DRIVER *driver_req_ptr)
{
    _nx_ram_network_driver_internal(driver_req_ptr, 256);
}

UINT (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
UINT (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

VOID _nx_ram_network_driver_output(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT interface_instance_id);
VOID _nx_ram_network_driver_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT interface_instance_id);
VOID _nx_ram_network_driver_reset();

TX_TIMER        nx_driver_timers[NX_MAX_TIMER];
NX_IP_DRIVER    nx_driver_requests[NX_MAX_TIMER];
UCHAR           nx_driver_timer_used[NX_MAX_TIMER];


#ifndef NX_INTERFACE_CAPABILITY
#define NX_INTERFACE_CAPABILITY ( NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM | NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM | NX_INTERFACE_CAPABILITY_UDP_TX_CHECKSUM | NX_INTERFACE_CAPABILITY_ICMPV4_TX_CHECKSUM | NX_INTERFACE_CAPABILITY_ICMPV6_TX_CHECKSUM | NX_INTERFACE_CAPABILITY_IGMP_TX_CHECKSUM )    
#endif

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
UINT _nx_ram_network_driver_calculate_checksum(NX_INTERFACE *interface_ptr, NX_PACKET *packet_ptr, UCHAR is_check);
#endif

#ifdef NX_PCAP_ENABLE
UINT write_pcap_file(NX_PACKET *packet_ptr);
#endif /* NX_PCAP_ENABLE  */


/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_set_pool                     PORTABLE C      */ 
/*                                                           6.4.0        */ 
/*  AUTHOR                                                                */ 
/*                                                                        */ 
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */ 
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function sets the virtual network driver pool.                 */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    pool_ptr                              Pool used by driver           */
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    Application                                                         */
/*                                                                        */ 
/*  RELEASE HISTORY                                                       */ 
/*                                                                        */ 
/*    DATE              NAME                      DESCRIPTION             */ 
/*                                                                        */ 
/*  12-31-2023     Wenhui Xie               Initial Version 6.4.0         */
/*                                                                        */ 
/**************************************************************************/ 
UINT _nx_ram_network_driver_set_pool(NX_PACKET_POOL *pool_ptr)
{
    driver_pool = pool_ptr;
    return NX_SUCCESS;
}


/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_reset                        PORTABLE C      */ 
/*                                                           6.4.0        */ 
/*  AUTHOR                                                                */ 
/*                                                                        */ 
/*    Wenhui Xie, Microsoft Corporation                                   */ 
/*                                                                        */ 
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function resets the virtual network driver.                    */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    Application                                                         */
/*                                                                        */ 
/*  RELEASE HISTORY                                                       */ 
/*                                                                        */ 
/*    DATE              NAME                      DESCRIPTION             */ 
/*                                                                        */ 
/*  12-31-2023     Wenhui Xie               Initial Version 6.4.0         */
/*                                                                        */ 
/**************************************************************************/ 
void _nx_ram_network_driver_reset(void)
{
    simulated_address_msw = 0x0011;
    simulated_address_lsw = 0x22334456;

    fragment_order_test   = 0;
    packet_gather         = 0;
    packet_drop           = 0;
    packet_save[0]        = 0;
    packet_save[1]        = 0;
    packet_save[2]        = 0;
    packet_save[3]        = 0;

    memset(&nx_ram_driver[0], 0 ,sizeof(_nx_ram_network_driver_instance_type) * (NX_MAX_RAM_INTERFACES));
    memset(&nx_driver_timers[0], 0, sizeof(TX_TIMER) * (NX_MAX_TIMER));
    memset(&nx_driver_requests[0], 0, sizeof(NX_IP_DRIVER) * (NX_MAX_TIMER));
    memset(&nx_driver_timer_used[0], 0, sizeof(UCHAR) * (NX_MAX_TIMER));

    driver_pool = NX_NULL;
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_delay_entry                  PORTABLE C      */ 
/*                                                           6.4.0        */ 
/*  AUTHOR                                                                */ 
/*                                                                        */ 
/*    Wenhui Xie, Microsoft Corporation                                   */ 
/*                                                                        */ 
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function sends out delayed packet.                             */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    index                                 index of driver request       */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_output         Send physical packet out      */ 
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*                                                                        */ 
/*  RELEASE HISTORY                                                       */ 
/*                                                                        */ 
/*    DATE              NAME                      DESCRIPTION             */ 
/*                                                                        */ 
/*  12-31-2023     Wenhui Xie               Initial Version 6.4.0         */ 
/*                                                                        */ 
/**************************************************************************/ 
VOID _nx_ram_network_driver_delay_entry(ULONG timer_input)
{
TX_INTERRUPT_SAVE_AREA
UINT index;
UINT interface_instance_id;
NX_IP_DRIVER *driver_req;
    
    index                 = (timer_input & 0xFFFF0000) >> 16;
    interface_instance_id = timer_input & 0x0000FFFF;

    driver_req = &nx_driver_requests[index];

    /* Send out delayed packet. */
    _nx_ram_network_driver_output(driver_req -> nx_ip_driver_ptr, driver_req -> nx_ip_driver_packet, interface_instance_id);
    
    /* Deactivate timer.  */
    tx_timer_deactivate(&nx_driver_timers[index]);

    TX_DISABLE

    /* Clean the used flag. */
    nx_driver_timer_used[index] = NX_RAMDRIVER_TIMER_DIRTY;

    TX_RESTORE
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_timer_clean                  PORTABLE C      */ 
/*                                                           6.4.0        */ 
/*  AUTHOR                                                                */ 
/*                                                                        */ 
/*    Wenhui Xie, Microsoft Corporation                                   */ 
/*                                                                        */ 
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function cleans timers used by driver.                         */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*                                                                        */ 
/*  RELEASE HISTORY                                                       */ 
/*                                                                        */ 
/*    DATE              NAME                      DESCRIPTION             */ 
/*                                                                        */ 
/*  12-31-2023     Wenhui Xie               Initial Version 6.4.0         */ 
/*                                                                        */ 
/**************************************************************************/ 
VOID _nx_ram_network_driver_timer_clean(VOID)
{    
    UINT        timer_index;

    for(timer_index = 0; timer_index < NX_MAX_TIMER; timer_index++)
    {
        if(nx_driver_timer_used[timer_index] != NX_RAMDRIVER_TIMER_UNUSED)
        {
            tx_timer_deactivate(&nx_driver_timers[timer_index]);
            tx_timer_delete(&nx_driver_timers[timer_index]);
        }

        nx_driver_timer_used[timer_index] = NX_RAMDRIVER_TIMER_UNUSED;
    }
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_internal                     PORTABLE C      */ 
/*                                                           6.4.0        */ 
/*  AUTHOR                                                                */ 
/*                                                                        */ 
/*    Wenhui Xie, Microsoft Corporation                                   */ 
/*                                                                        */ 
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function acts as a virtual network for testing the NetX source */ 
/*    and driver concepts.                                                */ 
/*                                                                        */
/*    Note, This function has callback functions for test cases.          */
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    driver_req__ptr                            Pointer to NX_IP_DRIVER  */ 
/*    mtu_size                                   LINK MTU size            */
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX IP processing                                                  */ 
/*                                                                        */ 
/*  RELEASE HISTORY                                                       */ 
/*                                                                        */ 
/*    DATE              NAME                      DESCRIPTION             */ 
/*                                                                        */ 
/*  12-31-2023       Wenhui Xie             Initial Version 6.4.0         */
/*                                                                        */ 
/**************************************************************************/ 
VOID  _nx_ram_network_driver_internal(NX_IP_DRIVER *driver_req_ptr, UINT mtu_size)
{

TX_INTERRUPT_SAVE_AREA
NX_IP           *ip_ptr;
NX_PACKET       *packet_ptr;
#ifndef NX_ENABLE_VLAN
ULONG           *ethernet_frame_ptr;
#endif
NX_INTERFACE    *interface_ptr;
#ifdef __PRODUCT_NETXDUO__
UINT            interface_index;
#endif
UINT            i;
NX_PACKET       *dup_packet_ptr = NX_NULL;
UINT            timer_index;
UINT            op = 0, delay = 0;
UINT            status;
ULONG           timer_input;
NX_PACKET_POOL *pool_ptr;
UINT            old_threshold = 0;
USHORT          ether_type;

    /* Setup the IP pointer from the driver request. */
    ip_ptr =  driver_req_ptr -> nx_ip_driver_ptr;

    /* Set driver pool. */
    if (driver_pool)
        pool_ptr = driver_pool;
    else
        pool_ptr = ip_ptr -> nx_ip_default_packet_pool;

    /* Default to successful return.  */
    driver_req_ptr -> nx_ip_driver_status =  NX_SUCCESS;

#ifdef NX_ENABLE_VLAN
    /* Let link layer to preprocess the driver request and return actual interface.  */
    if (nx_link_driver_request_preprocess(driver_req_ptr, &interface_ptr) != NX_SUCCESS)
    {
        return;
    }
#else
    /* Setup interface pointer. */
    interface_ptr = driver_req_ptr -> nx_ip_driver_interface;
#endif

#ifdef __PRODUCT_NETXDUO__
    /* Obtain the index number of the network interface. */
    interface_index = interface_ptr -> nx_interface_index;
#endif

    /* Find out the driver interface if the driver command is not ATTACH. */
    if(driver_req_ptr -> nx_ip_driver_command != NX_LINK_INTERFACE_ATTACH)
    {
        for(i = 0; i < NX_MAX_RAM_INTERFACES;i++)
        {
            if(nx_ram_driver[i].nx_ram_network_driver_in_use == 0)
                continue;

            if(nx_ram_driver[i].nx_ram_driver_ip_ptr != ip_ptr)
                continue;

            if(nx_ram_driver[i].nx_ram_driver_interface_ptr != interface_ptr)
                continue;
            
            break;
        }

        if(i == NX_MAX_RAM_INTERFACES)
        {
            driver_req_ptr -> nx_ip_driver_status =  NX_INVALID_INTERFACE;
            return;
        }
    }

    /* Process according to the driver request type in the IP control block. */
    switch (driver_req_ptr -> nx_ip_driver_command)
    {

        case NX_LINK_INTERFACE_ATTACH:
        {

            /* Disable preemption.  */
            tx_thread_preemption_change(tx_thread_identify(), 0, &old_threshold);

            /* Find an available driver instance to attach the interface. */
            for(i = 0; i < NX_MAX_RAM_INTERFACES;i++)
            {
                if(nx_ram_driver[i].nx_ram_network_driver_in_use == 0)
                    break;
            }
            /* An available entry is found. */
            if(i < NX_MAX_RAM_INTERFACES)
            {
                /* Set the IN USE flag.*/
                nx_ram_driver[i].nx_ram_network_driver_in_use  = 1;

                nx_ram_driver[i].nx_ram_network_driver_id = i;

                /* Record the interface attached to the IP instance. */
                nx_ram_driver[i].nx_ram_driver_interface_ptr = interface_ptr;

                /* Record the IP instance. */
                nx_ram_driver[i].nx_ram_driver_ip_ptr = ip_ptr;

                nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_msw = simulated_address_msw;
                nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_lsw = simulated_address_lsw + i;
            }
            else
            {
                driver_req_ptr -> nx_ip_driver_status =  NX_INVALID_INTERFACE;
            }

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
            interface_ptr -> nx_interface_capability_flag = NX_INTERFACE_CAPABILITY;
#endif 

            /* Restore preemption.  */
            tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);

            break;
        }

#ifdef __PRODUCT_NETXDUO__
        case NX_LINK_UNINITIALIZE:
        case NX_LINK_INTERFACE_DETACH :
        {

            /* Zero out the driver instance. */
            memset(&(nx_ram_driver[i]), 0 , sizeof(_nx_ram_network_driver_instance_type));

            break;
        }
#endif
        case NX_LINK_INITIALIZE:
        {

            /* Device driver shall initialize the Ethernet Controller here. */

            packet_process_callback = NX_NULL;
            advanced_packet_process_callback = NX_NULL;

#ifdef __PRODUCT_NETXDUO__
            /* Once the Ethernet controller is initialized, the driver needs to 
               configure the NetX Interface Control block, as outlined below. */

            /* The nx_interface_ip_mtu_size should be the MTU for the IP payload.
               For regular Ethernet, the IP MTU is 1500. */
            nx_ip_interface_mtu_set(ip_ptr, interface_index, mtu_size);

            /* Set the physical address (MAC address) of this IP instance. */
            /* For this simulated RAM driver, the MAC address is constructed by 
               incrementing a base lsw value, to simulate multiple nodes hanging on the
               ethernet. */
            nx_ip_interface_physical_address_set(ip_ptr, interface_index, 
                                              nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_msw,
                                              nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_lsw, NX_FALSE);

            /* Indicate to the IP software that IP to physical mapping is required. */
            nx_ip_interface_address_mapping_configure(ip_ptr, interface_index, NX_TRUE);
#else

            interface_ptr -> nx_interface_ip_mtu_size = mtu_size;

            /* Set the physical address (MAC address) of this IP instance. */
            /* For this simulated RAM driver, the MAC address is constructed by 
               incrementing a base lsw value, to simulate multiple nodes hanging on the
               ethernet. */

            interface_ptr -> nx_interface_physical_address_msw = nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_msw;
            interface_ptr -> nx_interface_physical_address_lsw = nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_lsw;

            /* Indicate to the IP software that IP to physical mapping is required. */
            interface_ptr -> nx_interface_address_mapping_needed = NX_TRUE;
#endif 

            break;
        }

        case NX_LINK_ENABLE:
        {

            /* Process driver link enable.  An Ethernet driver shall enable the 
               transmit and reception logic.  Once the IP stack issues the 
               LINK_ENABLE command, the stack may start transmitting IP packets. */
               
            /* In the RAM driver, just set the enabled flag. */
            interface_ptr -> nx_interface_link_up =  NX_TRUE;

       break;
       }

        case NX_LINK_DISABLE:
        {

            /* Process driver link disable.  This command indicates the IP layer
               is not going to transmit any IP datagrams, nor does it expect any
               IP datagrams from the interface.  Therefore after processing this command,
               the device driver shall not send any incoming packets to the IP
               layer.  Optionally the device driver may turn off the interface. */

            /* In the RAM driver, just clear the enabled flag.  */
            interface_ptr -> nx_interface_link_up =  NX_FALSE;

            break;
        }

        case NX_LINK_PACKET_SEND:
        case NX_LINK_PACKET_BROADCAST:
        case NX_LINK_ARP_SEND:
        case NX_LINK_ARP_RESPONSE_SEND:
        case NX_LINK_RARP_SEND:
        {

            /* The IP stack sends down a data packet for transmission.
               The device driver needs to prepend a MAC header, and fill in the
               Ethernet frame type (assuming Ethernet protocol for network transmission)
               based on the type of packet being transmitted.

               The following sequence illustrates this process. */


            /* Place the ethernet frame at the front of the packet.  */
            packet_ptr =  driver_req_ptr -> nx_ip_driver_packet;

            if (interface_ptr -> nx_interface_link_up == NX_FALSE)
            {

                /* Link is down. Drop the packet. */
                nx_packet_transmit_release(packet_ptr);
                return;
            }

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
            if(((driver_req_ptr -> nx_ip_driver_command) == NX_LINK_PACKET_BROADCAST) ||
                ((driver_req_ptr -> nx_ip_driver_command) == NX_LINK_PACKET_SEND))
            _nx_ram_network_driver_calculate_checksum(nx_ram_driver[i].nx_ram_driver_interface_ptr, packet_ptr, NX_FALSE);
#endif 

            /* Advanced function entry for calling. */
            if(advanced_packet_process_callback != NX_NULL)
            {
                status = advanced_packet_process_callback(ip_ptr, packet_ptr, &op, &delay);

                if(!status)
                    return;

                /* Advanced process. */
                switch(op)
                {
                    case NX_RAMDRIVER_OP_DROP:
                    {

                        /* Drop the packet. */
                        nx_packet_transmit_release(packet_ptr);
                        return;
                    }break;

                    case NX_RAMDRIVER_OP_DELAY:
                    {
                        TX_DISABLE

                        /* Find an unused timer. */
                        for(timer_index = 0; timer_index < NX_MAX_TIMER; timer_index++)
                        {
                            if(nx_driver_timer_used[timer_index] != NX_RAMDRIVER_TIMER_USED)
                            {
                                if(nx_driver_timer_used[timer_index] == NX_RAMDRIVER_TIMER_DIRTY)
                                    tx_timer_delete(&nx_driver_timers[timer_index]);

                                nx_driver_timer_used[timer_index] = NX_RAMDRIVER_TIMER_USED;
                                break;
                            }
                        }
                        TX_RESTORE

                        if(timer_index < NX_MAX_TIMER)
                        {
                            memcpy(&nx_driver_requests[timer_index], driver_req_ptr, sizeof(NX_IP_DRIVER));

                            timer_input = (timer_index << 16) | i;

                            tx_timer_create(&nx_driver_timers[timer_index], "Driver timer",
                                            _nx_ram_network_driver_delay_entry, 
                                            (ULONG)timer_input,
                                            delay, delay, TX_NO_ACTIVATE);
                        }
                        else
                        {

                            /* No available timer, just send bypass. */
                            op = NX_RAMDRIVER_OP_BYPASS;
                        }
                    }break;

                    case NX_RAMDRIVER_OP_DUPLICATE:
                    {

                        /* Set the dup_packet_ptr. */
                        dup_packet_ptr = packet_ptr;
                    }break;

                    case NX_RAMDRIVER_OP_BYPASS:
                    default:
                    break;
                }
            }

             /*A function entry for calling*/
            if(packet_process_callback != NX_NULL)
            {

                status = packet_process_callback(ip_ptr, packet_ptr);
                if(!status)
                    return;
            }

            /* Get Ethernet type.  */
            if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_SEND)
            {
                ether_type = NX_ETHERNET_ARP;
            }
            else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_RESPONSE_SEND)
            {
                ether_type = NX_ETHERNET_ARP;
            }
            else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_RARP_SEND)
            {
                ether_type = NX_ETHERNET_RARP;
            }
#ifdef __PRODUCT_NETXDUO__
            else if (packet_ptr -> nx_packet_ip_version == 6)
            {
                ether_type = NX_ETHERNET_IPV6;
            }
#endif
            else
            {
                ether_type = NX_ETHERNET_IP;
            }

#ifdef NX_ENABLE_VLAN
            /* Add Ethernet header.  */
            if (nx_link_ethernet_header_add(ip_ptr,
                                            driver_req_ptr -> nx_ip_driver_interface -> nx_interface_index, packet_ptr,
                                            driver_req_ptr -> nx_ip_driver_physical_address_msw,
                                            driver_req_ptr -> nx_ip_driver_physical_address_lsw,
                                            (UINT)ether_type))
            {

                /* Release the packet.  */
                nx_packet_transmit_release(packet_ptr);
                break;
            }
#else
            /* Adjust the prepend pointer.  */
            packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - NX_ETHERNET_SIZE;

            /* Adjust the packet length.  */
            packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + NX_ETHERNET_SIZE;

            /* If the physical header won't fit, return an error.  */
            if (packet_ptr -> nx_packet_prepend_ptr < packet_ptr -> nx_packet_data_start)
            {                     

                /* Remove the Ethernet header.  */
                packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

                /* Adjust the packet length.  */
                packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

                /* Drop the packet. */
                nx_packet_transmit_release(packet_ptr);    

                return;
            }               

            /* Setup the ethernet frame pointer to build the ethernet frame.  Backup another 2
               bytes to get 32-bit word alignment.  */
            ethernet_frame_ptr =  (ULONG *) (packet_ptr -> nx_packet_prepend_ptr - 2);

            /* Build the ethernet frame.  */
            *ethernet_frame_ptr     =  driver_req_ptr -> nx_ip_driver_physical_address_msw;
            *(ethernet_frame_ptr+1) =  driver_req_ptr -> nx_ip_driver_physical_address_lsw;
            *(ethernet_frame_ptr+2) =  (interface_ptr -> nx_interface_physical_address_msw << 16) |
                                       (interface_ptr -> nx_interface_physical_address_lsw >> 16);
            *(ethernet_frame_ptr+3) =  (interface_ptr -> nx_interface_physical_address_lsw << 16);

            if(driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_SEND)
                *(ethernet_frame_ptr+3) |= NX_ETHERNET_ARP;
            else if(driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_RESPONSE_SEND)
                *(ethernet_frame_ptr+3) |= NX_ETHERNET_ARP;
            else if(driver_req_ptr -> nx_ip_driver_command == NX_LINK_RARP_SEND)
                *(ethernet_frame_ptr+3) |= NX_ETHERNET_RARP;                
#ifdef FEATURE_NX_IPV6
            else if(packet_ptr -> nx_packet_ip_version == 6)
                *(ethernet_frame_ptr+3) |= NX_ETHERNET_IPV6;
#endif
            else
                *(ethernet_frame_ptr+3) |= NX_ETHERNET_IP;


            /* Endian swapping if NX_LITTLE_ENDIAN is defined.  */
            NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));
            NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr+1));
            NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr+2));
            NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr+3));
#endif /* NX_ENABLE_VLAN */
                                
            /* At this point, the packet is a complete Ethernet frame, ready to be transmitted.
               The driver shall call the actual Ethernet transmit routine and put the packet
               on the wire.   

               In this example, the simulated RAM network transmit routine is called. */ 

            /* Check whether we need to duplicate the packet. */
            if(dup_packet_ptr != NX_NULL)
                nx_packet_copy(packet_ptr, &dup_packet_ptr, pool_ptr, NX_NO_WAIT); 
            if(op != NX_RAMDRIVER_OP_DELAY)
                _nx_ram_network_driver_output(ip_ptr, packet_ptr, i);
            else
                tx_timer_activate(&nx_driver_timers[timer_index]);

            /* Send the duplicate packet. */
            if(dup_packet_ptr != NX_NULL)
                _nx_ram_network_driver_output(ip_ptr, dup_packet_ptr, i);

            break;
        }
#ifdef NX_ENABLE_VLAN
    case NX_LINK_RAW_PACKET_SEND:
    {

        /* Send raw packet out directly.  */
        _nx_ram_network_driver_output(ip_ptr, driver_req_ptr -> nx_ip_driver_packet, i);
        break;
    }
#endif /* NX_ENABLE_VLAN */
        case NX_LINK_MULTICAST_JOIN:
        {
            UINT          mcast_index;

            /* The IP layer issues this command to join a multicast group.  Note that 
               multicast operation is required for IPv6.  
               
               On a typically Ethernet controller, the driver computes a hash value based
               on MAC address, and programs the hash table. 

               It is likely the driver also needs to maintain an internal MAC address table.
               Later if a multicast address is removed, the driver needs
               to reprogram the hash table based on the remaining multicast MAC addresses. */
            

            /* The following procedure only applies to our simulated RAM network driver, which manages
               multicast MAC addresses by a simple look up table. */
            for(mcast_index = 0; mcast_index < NX_RAM_DRIVER_MAX_MCAST_ADDRESSES; mcast_index++)
            {
                if(nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_msw == 0 &&
                   nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_lsw == 0 )
                {
                    nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_msw = driver_req_ptr -> nx_ip_driver_physical_address_msw;
                    nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_lsw = driver_req_ptr -> nx_ip_driver_physical_address_lsw;
                    break;
                }
            }
            if(mcast_index == NX_RAM_DRIVER_MAX_MCAST_ADDRESSES)
                driver_req_ptr -> nx_ip_driver_status =  NX_NO_MORE_ENTRIES;
            
            break;
        }

        case NX_LINK_MULTICAST_LEAVE:
        {

            UINT  mcast_index;

            /* The IP layer issues this command to remove a multicast MAC address from the
               receiving list.  A device driver shall properly remove the multicast address
               from the hash table, so the hardware does not receive such traffic.  Note that
               in order to reprogram the hash table, the device driver may have to keep track of
               current active multicast MAC addresses. */

            /* The following procedure only applies to our simulated RAM network driver, which manages
               multicast MAC addresses by a simple look up table. */
            for(mcast_index = 0; mcast_index < NX_RAM_DRIVER_MAX_MCAST_ADDRESSES; mcast_index++)
            {
                if(nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_msw == driver_req_ptr -> nx_ip_driver_physical_address_msw &&
                   nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_lsw == driver_req_ptr -> nx_ip_driver_physical_address_lsw)              
                {
                    nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_msw = 0;
                    nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_lsw = 0;
                    break;
                }
            }
            if(mcast_index == NX_RAM_DRIVER_MAX_MCAST_ADDRESSES)
                driver_req_ptr -> nx_ip_driver_status =  NX_ENTRY_NOT_FOUND;

            break;
        }

        case NX_LINK_GET_STATUS:
        {

            /* Return the link status in the supplied return pointer.  */
            *(driver_req_ptr -> nx_ip_driver_return_ptr) =  interface_ptr -> nx_interface_link_up;
            break;
        }

        case NX_LINK_DEFERRED_PROCESSING:
        {
        
            /* Driver defined deferred processing. This is typically used to defer interrupt 
               processing to the thread level.   

               A typical use case of this command is:
               On receiving an Ethernet frame, the RX ISR does not process the received frame,
               but instead records such an event in its internal data structure, and issues
               a notification to the IP stack (the driver sends the notification to the IP 
               helping thread by calling "_nx_ip_driver_deferred_processing()".  When the IP stack 
               gets a notification of a pending driver deferred process, it calls the 
               driver with the NX_LINK_DEFERRED_PROCESSING command.  The driver shall complete 
               the pending receive process. 
            */

            /* The simulated RAM driver doesn't require a deferred process so it breaks out of 
               the switch case. */

               
            break;
        }                   
                      
#ifdef __PRODUCT_NETXDUO__ 
        case NX_LINK_SET_PHYSICAL_ADDRESS:
        {

            /* Find an driver instance to attach the interface. */
            for(i = 0; i < NX_MAX_RAM_INTERFACES;i++)
            {
                if(nx_ram_driver[i].nx_ram_driver_interface_ptr == interface_ptr)
                    break;
            }
            
            /* An available entry is found. */
            if(i < NX_MAX_RAM_INTERFACES)
            {

                /* Set the physical address.  */
                nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_msw = driver_req_ptr -> nx_ip_driver_physical_address_msw;
                nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_lsw = driver_req_ptr -> nx_ip_driver_physical_address_lsw;
            }
            else
            {
                driver_req_ptr -> nx_ip_driver_status =  NX_INVALID_INTERFACE;
            }

            break;
        }
#endif

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
        case NX_INTERFACE_CAPABILITY_GET:   
        {
            interface_ptr -> nx_interface_capability_flag = NX_INTERFACE_CAPABILITY;
            break;
        }

        case NX_INTERFACE_CAPABILITY_SET:
        {
            break;
        }

#endif 
#ifdef NX_BSD_RAW_PPPOE_SUPPORT
            case NX_LINK_PACKET_PPPOE_SESS_SEND:
            case NX_LINK_PACKET_PPPOE_DISC_SEND:

                /* Place the ethernet frame at the front of the packet.  */
                packet_ptr =  driver_req_ptr -> nx_ip_driver_packet;

                _nx_ram_network_driver_output(ip_ptr, packet_ptr, i);
                break;

#endif /* NX_BSD_RAW_PPPOE_SUPPORT */
        default:
        {

            /* Invalid driver request.  */

            /* Return the unhandled command status.  */
            driver_req_ptr -> nx_ip_driver_status =  NX_UNHANDLED_COMMAND;
        }
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ram_network_driver                              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function acts as a virtual network for testing the NetX source */
/*    and driver concepts.                                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    driver_req__ptr                            Pointer to NX_IP_DRIVER  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX IP processing                                                  */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023       Wenhui Xie             Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
VOID  _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr)
{

NX_IP           *ip_ptr;
NX_PACKET       *packet_ptr;
#ifndef NX_ENABLE_VLAN
ULONG           *ethernet_frame_ptr;
#endif /* NX_ENABLE_VLAN */
NX_INTERFACE    *interface_ptr;
#ifdef __PRODUCT_NETXDUO__
UINT            interface_index;
#endif
UINT            i;
UINT            mtu_size = 128;
UINT            old_threshold = 0;
USHORT         ether_type;

    /* Setup the IP pointer from the driver request. */
    ip_ptr =  driver_req_ptr -> nx_ip_driver_ptr;

    /* Default to successful return.  */
    driver_req_ptr -> nx_ip_driver_status =  NX_SUCCESS;

#ifdef NX_ENABLE_VLAN
    /* Let link layer to preprocess the driver request and return actual interface.  */
    if (nx_link_driver_request_preprocess(driver_req_ptr, &interface_ptr) != NX_SUCCESS)
    {
        return;
    }
#else
    /* Setup interface pointer. */
    interface_ptr = driver_req_ptr -> nx_ip_driver_interface;
#endif

#ifdef __PRODUCT_NETXDUO__
    /* Obtain the index number of the network interface. */
    interface_index = interface_ptr -> nx_interface_index;
#endif

    /* Find out the driver interface if the driver command is not ATTACH. */
    if(driver_req_ptr -> nx_ip_driver_command != NX_LINK_INTERFACE_ATTACH)
    {
        for(i = 0; i < NX_MAX_RAM_INTERFACES;i++)
        {
            if(nx_ram_driver[i].nx_ram_network_driver_in_use == 0)
                continue;

            if(nx_ram_driver[i].nx_ram_driver_ip_ptr != ip_ptr)
                continue;

            if(nx_ram_driver[i].nx_ram_driver_interface_ptr != interface_ptr)
                continue;

            break;
        }

        if(i == NX_MAX_RAM_INTERFACES)
        {
            driver_req_ptr -> nx_ip_driver_status =  NX_INVALID_INTERFACE;
            return;
        }
    }

    /* Process according to the driver request type in the IP control block. */
    switch (driver_req_ptr -> nx_ip_driver_command)
    {
        case NX_LINK_INTERFACE_ATTACH:
        {

            /* Disable preemption.  */
            tx_thread_preemption_change(tx_thread_identify(), 0, &old_threshold);

            /* Find an available driver instance to attach the interface. */
            for(i = 0; i < NX_MAX_RAM_INTERFACES;i++)
            {
                if(nx_ram_driver[i].nx_ram_network_driver_in_use == 0)
                break;
            }
            /* An available entry is found. */
            if(i < NX_MAX_RAM_INTERFACES)
            {
                /* Set the IN USE flag.*/
                nx_ram_driver[i].nx_ram_network_driver_in_use  = 1;

                nx_ram_driver[i].nx_ram_network_driver_id = i;

                /* Record the interface attached to the IP instance. */
                nx_ram_driver[i].nx_ram_driver_interface_ptr = interface_ptr;

                /* Record the IP instance. */
                nx_ram_driver[i].nx_ram_driver_ip_ptr = ip_ptr;
                nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_msw = simulated_address_msw;
                nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_lsw = simulated_address_lsw + i;
            }
            else
            {
                driver_req_ptr -> nx_ip_driver_status =  NX_INVALID_INTERFACE;
            }

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
            interface_ptr -> nx_interface_capability_flag = NX_INTERFACE_CAPABILITY;
#endif

            /* Restore preemption.  */
            tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);

            break;
        }
#ifdef __PRODUCT_NETXDUO__
        case NX_LINK_INTERFACE_DETACH :
        {
            /* Zero out the driver instance. */
            memset(&(nx_ram_driver[i]), 0 , sizeof(_nx_ram_network_driver_instance_type));
            break;
        }
#endif
        case NX_LINK_INITIALIZE:
        {
            /* Device driver shall initialize the Ethernet Controller here. */

            packet_process_callback = NX_NULL;
            advanced_packet_process_callback = NX_NULL;

#ifdef __PRODUCT_NETXDUO__
            /* Once the Ethernet controller is initialized, the driver needs to
               configure the NetX Interface Control block, as outlined below. */

            /* The nx_interface_ip_mtu_size should be the MTU for the IP payload.
               For regular Ethernet, the IP MTU is 1500. */
            nx_ip_interface_mtu_set(ip_ptr, interface_index, mtu_size);

            /* Set the physical address (MAC address) of this IP instance. */
            /* For this simulated RAM driver, the MAC address is constructed by
               incrementing a base lsw value, to simulate multiple nodes hanging on the
               ethernet. */
            nx_ip_interface_physical_address_set(ip_ptr, interface_index,
                        nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_msw,
                        nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_lsw, NX_FALSE);

            /* Indicate to the IP software that IP to physical mapping is required. */
            nx_ip_interface_address_mapping_configure(ip_ptr, interface_index, NX_TRUE);
#else

            interface_ptr -> nx_interface_ip_mtu_size = mtu_size;

            /* Set the physical address (MAC address) of this IP instance. */
            /* For this simulated RAM driver, the MAC address is constructed by 
               incrementing a base lsw value, to simulate multiple nodes hanging on the
               ethernet. */

            interface_ptr -> nx_interface_physical_address_msw = nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_msw;
            interface_ptr -> nx_interface_physical_address_lsw = nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_lsw;

            /* Indicate to the IP software that IP to physical mapping is required. */
            interface_ptr -> nx_interface_address_mapping_needed = NX_TRUE;

#endif

            break;
        }

        case NX_LINK_ENABLE:
        {

            /* Process driver link enable.  An Ethernet driver shall enable the
               transmit and reception logic.  Once the IP stack issues the
               LINK_ENABLE command, the stack may start transmitting IP packets. */

            /* In the RAM driver, just set the enabled flag. */
            interface_ptr -> nx_interface_link_up =  NX_TRUE;

            break;
        }

        case NX_LINK_DISABLE:
        {

            /* Process driver link disable.  This command indicates the IP layer
               is not going to transmit any IP datagrams, nor does it expect any
               IP datagrams from the interface.  Therefore after processing this command,
               the device driver shall not send any incoming packets to the IP
               layer.  Optionally the device driver may turn off the interface. */

            /* In the RAM driver, just clear the enabled flag.  */
            interface_ptr -> nx_interface_link_up =  NX_FALSE;

            break;
        }

        case NX_LINK_PACKET_SEND:
        case NX_LINK_PACKET_BROADCAST:
        case NX_LINK_ARP_SEND:
        case NX_LINK_ARP_RESPONSE_SEND:
        case NX_LINK_RARP_SEND:
#ifdef NX_PPP_PPPOE_ENABLE
        case NX_LINK_PPPOE_DISCOVERY_SEND:
        case NX_LINK_PPPOE_SESSION_SEND:
#endif
        {
            /* Process driver send packet.  */

            /* Place the ethernet frame at the front of the packet.  */
            packet_ptr =  driver_req_ptr -> nx_ip_driver_packet;

            if (interface_ptr -> nx_interface_link_up == NX_FALSE)
            {

                /* Link is down. Drop the packet. */
                nx_packet_transmit_release(packet_ptr);
                return;
            }

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
            if(((driver_req_ptr -> nx_ip_driver_command) == NX_LINK_PACKET_BROADCAST) ||
                ((driver_req_ptr -> nx_ip_driver_command) == NX_LINK_PACKET_SEND))
            _nx_ram_network_driver_calculate_checksum(nx_ram_driver[i].nx_ram_driver_interface_ptr, packet_ptr, NX_FALSE);
#endif

            /* Get Ethernet type.  */
            if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_SEND)
            {
                ether_type = NX_ETHERNET_ARP;
            }
            else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_RESPONSE_SEND)
            {
                ether_type = NX_ETHERNET_ARP;
            }
            else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_RARP_SEND)
            {
                ether_type = NX_ETHERNET_RARP;
            }
#ifdef NX_PPP_PPPOE_ENABLE
            else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_PPPOE_DISCOVERY_SEND)
            {
                ether_type = NX_ETHERNET_PPPOE_DISCOVERY;
            }
            else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_PPPOE_SESSION_SEND)
            {
                ether_type = NX_ETHERNET_PPPOE_SESSION;
            }
#endif
#if defined(__PRODUCT_NETXDUO__)
            else if (packet_ptr -> nx_packet_ip_version == 6)
            {
                ether_type = NX_ETHERNET_IPV6;
            }
#endif
            else
            {
                ether_type = NX_ETHERNET_IP;
            }

#ifdef NX_ENABLE_VLAN
            /* Add Ethernet header.  */
            if (nx_link_ethernet_header_add(ip_ptr,
                                            driver_req_ptr -> nx_ip_driver_interface -> nx_interface_index, packet_ptr,
                                            driver_req_ptr -> nx_ip_driver_physical_address_msw,
                                            driver_req_ptr -> nx_ip_driver_physical_address_lsw,
                                            (UINT)ether_type))
            {

                /* Release the packet.  */
                nx_packet_transmit_release(packet_ptr);
                break;
            }
#else
            /* Adjust the prepend pointer.  */
            packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - NX_ETHERNET_SIZE;

            /* Adjust the packet length.  */
            packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + NX_ETHERNET_SIZE;

            /* If the physical header won't fit, return an error.  */
            if (packet_ptr -> nx_packet_prepend_ptr < packet_ptr -> nx_packet_data_start)
            {                     

                /* Remove the Ethernet header.  */
                packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

                /* Adjust the packet length.  */
                packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

                /* Drop the packet. */
                nx_packet_transmit_release(packet_ptr);

                return;
            }   

            /* Setup the ethernet frame pointer to build the ethernet frame.  Backup another 2
               bytes to get 32-bit word alignment.  */
            /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
            ethernet_frame_ptr =  (ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 2);

            /* Build the ethernet frame.  */
            *ethernet_frame_ptr     =  driver_req_ptr -> nx_ip_driver_physical_address_msw;
            *(ethernet_frame_ptr + 1) =  driver_req_ptr -> nx_ip_driver_physical_address_lsw;
            *(ethernet_frame_ptr + 2) =  (interface_ptr -> nx_interface_physical_address_msw << 16) |
            (interface_ptr -> nx_interface_physical_address_lsw >> 16);
            *(ethernet_frame_ptr + 3) =  (interface_ptr -> nx_interface_physical_address_lsw << 16) | ether_type;

            /* Endian swapping if NX_LITTLE_ENDIAN is defined.  */
            NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));
            NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr + 1));
            NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr + 2));
            NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr + 3));
#endif /* NX_ENABLE_VLAN */

            /* At this point, the packet is a complete Ethernet frame, ready to be transmitted.
               The driver shall call the actual Ethernet transmit routine and put the packet
               on the wire.
                 
               In this example, the simulated RAM network transmit routine is called. */

            _nx_ram_network_driver_output(ip_ptr, packet_ptr, i );

            break;
        }


#ifdef NX_ENABLE_VLAN
        case NX_LINK_RAW_PACKET_SEND:
        {

            /* Send raw packet out directly.  */
            _nx_ram_network_driver_output(ip_ptr, driver_req_ptr -> nx_ip_driver_packet, i);
            break;
        }
#endif /* NX_ENABLE_VLAN */

        case NX_LINK_MULTICAST_JOIN:
        {
            UINT          mcast_index;

            /* The IP layer issues this command to join a multicast group.  Note that
               multicast operation is required for IPv6.
                 
               On a typically Ethernet controller, the driver computes a hash value based
               on MAC address, and programs the hash table.
                 
               It is likely the driver also needs to maintain an internal MAC address table.
               Later if a multicast address is removed, the driver needs
               to reprogram the hash table based on the remaining multicast MAC addresses. */


            /* The following procedure only applies to our simulated RAM network driver, which manages
               multicast MAC addresses by a simple look up table. */
            for(mcast_index = 0; mcast_index < NX_RAM_DRIVER_MAX_MCAST_ADDRESSES; mcast_index++)
            {
                if(nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_msw == 0 &&
                   nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_lsw == 0 )
                {
                    nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_msw = driver_req_ptr -> nx_ip_driver_physical_address_msw;
                    nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_lsw = driver_req_ptr -> nx_ip_driver_physical_address_lsw;
                    break;
                }
            }
            if(mcast_index == NX_RAM_DRIVER_MAX_MCAST_ADDRESSES)
                driver_req_ptr -> nx_ip_driver_status =  NX_NO_MORE_ENTRIES;

            break;
        }

        case NX_LINK_MULTICAST_LEAVE:
        {

            UINT  mcast_index;

            /* The IP layer issues this command to remove a multicast MAC address from the
               receiving list.  A device driver shall properly remove the multicast address
               from the hash table, so the hardware does not receive such traffic.  Note that
               in order to reprogram the hash table, the device driver may have to keep track of
               current active multicast MAC addresses. */

            /* The following procedure only applies to our simulated RAM network driver, which manages
               multicast MAC addresses by a simple look up table. */
            for(mcast_index = 0; mcast_index < NX_RAM_DRIVER_MAX_MCAST_ADDRESSES; mcast_index++)
            {
                if(nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_msw == driver_req_ptr -> nx_ip_driver_physical_address_msw &&
                   nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_lsw == driver_req_ptr -> nx_ip_driver_physical_address_lsw)
                {
                    nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_msw = 0;
                    nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_lsw = 0;
                    break;
                }
            }
            if(mcast_index == NX_RAM_DRIVER_MAX_MCAST_ADDRESSES)
                driver_req_ptr -> nx_ip_driver_status =  NX_ENTRY_NOT_FOUND;

            break;
        }

        case NX_LINK_GET_STATUS:
        {

            /* Return the link status in the supplied return pointer.  */
            *(driver_req_ptr -> nx_ip_driver_return_ptr) =  ip_ptr-> nx_ip_interface[0].nx_interface_link_up;
            break;
        }

        case NX_LINK_DEFERRED_PROCESSING:
        {

            /* Driver defined deferred processing. This is typically used to defer interrupt
               processing to the thread level.
                 
               A typical use case of this command is:
               On receiving an Ethernet frame, the RX ISR does not process the received frame,
               but instead records such an event in its internal data structure, and issues
               a notification to the IP stack (the driver sends the notification to the IP
               helping thread by calling "_nx_ip_driver_deferred_processing()".  When the IP stack
               gets a notification of a pending driver deferred process, it calls the
               driver with the NX_LINK_DEFERRED_PROCESSING command.  The driver shall complete
               the pending receive process. */

            /* The simulated RAM driver doesn't require a deferred process so it breaks out of
               the switch case. */

            break;
        }
        
#ifdef __PRODUCT_NETXDUO__ 
        case NX_LINK_SET_PHYSICAL_ADDRESS:
        {

            /* Find an driver instance to attach the interface. */
            for(i = 0; i < NX_MAX_RAM_INTERFACES;i++)
            {
                if(nx_ram_driver[i].nx_ram_driver_interface_ptr == interface_ptr)
                    break;
            }
            
            /* An available entry is found. */
            if(i < NX_MAX_RAM_INTERFACES)
            {
                
                /* Set the physical address.  */
                nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_msw = driver_req_ptr -> nx_ip_driver_physical_address_msw;
                nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_lsw = driver_req_ptr -> nx_ip_driver_physical_address_lsw;
            }
            else
            {
                driver_req_ptr -> nx_ip_driver_status =  NX_INVALID_INTERFACE;
            }

            break;
        }
#endif

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
        case NX_INTERFACE_CAPABILITY_GET:
        {
            interface_ptr -> nx_interface_capability_flag = NX_INTERFACE_CAPABILITY;
            break;
        }

        case NX_INTERFACE_CAPABILITY_SET:
        {
            break;
        }

#endif
        default:
        {

            /* Invalid driver request.  */

            /* Return the unhandled command status.  */
            driver_req_ptr -> nx_ip_driver_status =  NX_UNHANDLED_COMMAND;
        }
    }
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_output                       PORTABLE C      */ 
/*                                                           6.4.0        */ 
/*  AUTHOR                                                                */ 
/*                                                                        */ 
/*    Wenhui Xie, Microsoft Corporation                                   */ 
/*                                                                        */ 
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function simply sends the packet to the IP instance on the     */ 
/*    created IP list that matches the physical destination specified in  */ 
/*    the Ethernet packet.  In a real hardware setting, this routine      */ 
/*    would simply put the packet out on the wire.                        */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    ip_ptr                                Pointer to IP protocol block  */ 
/*    packet_ptr                            Packet pointer                */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    nx_packet_copy                        Copy a packet                 */ 
/*    nx_packet_transmit_release            Release a packet              */ 
/*    _nx_ram_network_driver_receive        RAM driver receive processing */ 
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX IP processing                                                  */ 
/*                                                                        */ 
/*  RELEASE HISTORY                                                       */ 
/*                                                                        */ 
/*    DATE              NAME                      DESCRIPTION             */ 
/*                                                                        */ 
/*  12-31-2023       Wenhui Xie             Initial Version 6.4.0         */ 
/*                                                                        */ 
/**************************************************************************/ 
VOID  _nx_ram_network_driver_output(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT interface_instance_id)
{
NX_IP       *dest_ip;
NX_PACKET   *packet_copy;
ULONG       destination_address_msw;
ULONG       destination_address_lsw;
UINT        old_threshold = 0;
UINT        i;
UINT        mcast_index;
NX_PACKET_POOL *pool_ptr;

#ifdef NX_DEBUG_PACKET
UCHAR       *ptr;
UINT        j;

    ptr =  packet_ptr -> nx_packet_prepend_ptr;
    printf("Ethernet Packet: ");
    for (j = 0; j < 6; j++)
        printf("%02X", *ptr++);
    printf(" ");
    for (j = 0; j < 6; j++)
        printf("%02X", *ptr++);
    printf(" %02X", *ptr++);
    printf("%02X ", *ptr++);

    i = 0;
    for (j = 0; j < (packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE); j++)
    {
        printf("%02X", *ptr++);
        i++;
        if (i > 3)
        {
            i = 0;
            printf(" ");
        }
    }
    printf("\n");
#endif

    /* Pickup the destination IP address from the packet_ptr.  */
    destination_address_msw =  (ULONG) *(packet_ptr -> nx_packet_prepend_ptr);
    destination_address_msw =  (destination_address_msw << 8) | (ULONG) *(packet_ptr -> nx_packet_prepend_ptr+1);
    destination_address_lsw =  (ULONG) *(packet_ptr -> nx_packet_prepend_ptr+2);
    destination_address_lsw =  (destination_address_lsw << 8) | (ULONG) *(packet_ptr -> nx_packet_prepend_ptr+3);
    destination_address_lsw =  (destination_address_lsw << 8) | (ULONG) *(packet_ptr -> nx_packet_prepend_ptr+4);
    destination_address_lsw =  (destination_address_lsw << 8) | (ULONG) *(packet_ptr -> nx_packet_prepend_ptr+5);

    /* Disable preemption.  */
    tx_thread_preemption_change(tx_thread_identify(), 0, &old_threshold);

    /* Retrieve data from packet. */
    nx_packet_data_retrieve(packet_ptr, driver_data_buffer, &driver_data_length);

#ifdef NX_PCAP_ENABLE
    /* Write packet data into pcap file.  */
    write_pcap_file(packet_ptr);
#endif 

    /* Loop through all instances of created IPs to see who gets the packet.  */
    for(i = 0; i < NX_MAX_RAM_INTERFACES; i++)
    {

        /* Skip the interface from which the packet was sent. */
        if(i == interface_instance_id)
            continue;

        /* Skip the instance that has not been initialized. */
        if(nx_ram_driver[i].nx_ram_network_driver_in_use == 0)
            continue;

        dest_ip = nx_ram_driver[i].nx_ram_driver_ip_ptr;
        
        /* If the destination MAC address is broadcast or the destination matches the interface MAC,
           accept the packet. */
        if(((destination_address_msw == ((ULONG) 0x0000FFFF)) && (destination_address_lsw == ((ULONG) 0xFFFFFFFF))) || /* Broadcast match */
           ((destination_address_msw == nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_msw) &&
            (destination_address_lsw == nx_ram_driver[i].nx_ram_driver_mac_address.nx_mac_address_lsw)) ||
            (destination_address_msw == ((ULONG)0x00003333)) ||  /* Ethernet multicast address, RFC2464, Section7, Page 5 2.  */
            ((destination_address_msw == 0) && (destination_address_lsw == 0)))
        {

            /* Set the packet pool. */
            if (driver_pool)
                pool_ptr = driver_pool;
            else
                pool_ptr = dest_ip -> nx_ip_default_packet_pool;

            /* Allocate packet. */
            if (nx_packet_allocate(pool_ptr, &packet_copy, NX_RECEIVE_PACKET, NX_NO_WAIT))
            {

                /* Remove the Ethernet header.  */
                packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

                /* Adjust the packet length.  */
                packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

                /* Error, no point in continuing, just release the packet.  */
                nx_packet_transmit_release(packet_ptr);

                /* Restore preemption.  */
                tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
                return;
            }

            /* Skip two bytes. */
            packet_copy -> nx_packet_prepend_ptr += 2;
            packet_copy -> nx_packet_append_ptr += 2;

            /* Make a copy of packet for the forwarding.  */
            if (nx_packet_data_append(packet_copy, driver_data_buffer, driver_data_length, pool_ptr, NX_NO_WAIT))
            {
#ifdef NX_ENABLE_VLAN
                /* Error, no point in continuing, just release the packet.  */
                nx_link_packet_transmitted(nx_ram_driver[interface_instance_id].nx_ram_driver_ip_ptr,
                                           nx_ram_driver[interface_instance_id].nx_ram_driver_interface_ptr -> nx_interface_index,
                                           packet_ptr, NX_NULL);
#else
                /* Remove the Ethernet header.  */
                packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

                /* Adjust the packet length.  */
                packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

                /* Error, no point in continuing, just release the packet.  */
                nx_packet_transmit_release(packet_ptr);

                /* Release the packet. */
                nx_packet_release(packet_copy);

                /* Restore preemption.  */
                tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
#endif /* NX_ENABLE_VLAN */
                return;
            }        

#ifdef __PRODUCT_NETXDUO__
            /* Copy packet version. */
            packet_copy -> nx_packet_ip_version = packet_ptr -> nx_packet_ip_version;
#endif /* __PRODUCT_NETXDUO__ */

            _nx_ram_network_driver_receive(dest_ip, packet_copy, i);
        }            
        else 
        {
            for(mcast_index = 0; mcast_index < NX_RAM_DRIVER_MAX_MCAST_ADDRESSES; mcast_index++)
            {
                
                if(destination_address_msw == nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_msw &&
                   destination_address_lsw == nx_ram_driver[i].nx_ram_driver_mcast_address[mcast_index].nx_mac_address_lsw)
                {

                    /* Set the packet pool. */
                    if (driver_pool)
                        pool_ptr = driver_pool;
                    else
                        pool_ptr = dest_ip -> nx_ip_default_packet_pool;

                    /* Allocate packet. */
                    if (nx_packet_allocate(pool_ptr, &packet_copy, NX_RECEIVE_PACKET, NX_NO_WAIT))
                    {
                            
                        /* Remove the Ethernet header.  */
                        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;
                        
                        /* Adjust the packet length.  */
                        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;
                        
                        /* Error, no point in continuing, just release the packet.  */
                        nx_packet_transmit_release(packet_ptr);

                        /* Restore preemption.  */
                        tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
                        return;
                    }

                    /* Skip two bytes. */
                    packet_copy -> nx_packet_prepend_ptr += 2;
                    packet_copy -> nx_packet_append_ptr += 2;

                    /* Make a copy of packet for the forwarding.  */
                    if (nx_packet_data_append(packet_copy, driver_data_buffer, driver_data_length, pool_ptr, NX_NO_WAIT))
                    {
                            
                        /* Remove the Ethernet header.  */
                        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;
                        
                        /* Adjust the packet length.  */
                        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;
                        
                        /* Error, no point in continuing, just release the packet.  */
                        nx_packet_transmit_release(packet_ptr);

                        /* Restore preemption.  */
                        tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
                        return;
                    }        

                    _nx_ram_network_driver_receive(dest_ip, packet_copy, i);


                }
                
                
            }
        }
    }

#ifdef NX_ENABLE_VLAN
    /* Release the packet.  */
    nx_link_packet_transmitted(nx_ram_driver[interface_instance_id].nx_ram_driver_ip_ptr,
                                nx_ram_driver[interface_instance_id].nx_ram_driver_interface_ptr -> nx_interface_index,
                                packet_ptr, NX_NULL);
#else
    /* Remove the Ethernet header.  In real hardware environments, this is typically 
       done after a transmit complete interrupt.  */
    packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

    /* Adjust the packet length.  */
    packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

    /* Now that the Ethernet frame has been removed, release the packet.  */
    nx_packet_transmit_release(packet_ptr);
#endif
    /* Restore preemption.  */
    tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
}

/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_receive                      PORTABLE C      */ 
/*                                                           6.4.0        */ 
/*  AUTHOR                                                                */ 
/*                                                                        */ 
/*    Wenhui Xie, Microsoft Corporation                                   */ 
/*                                                                        */ 
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function processing incoming packets.  In the RAM network      */ 
/*    driver, the incoming packets are coming from the RAM driver output  */ 
/*    routine.  In real hardware settings, this routine would be called   */ 
/*    from the receive packet ISR.                                        */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    ip_ptr                                Pointer to IP protocol block  */ 
/*    packet_ptr                            Packet pointer                */ 
/*    interface_instance_id                 The interface ID the packet is*/
/*                                            destined for                */
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    None                                                                */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    _nx_ip_packet_receive                 IP receive packet processing  */ 
/*    _nx_ip_packet_deferred_receive        IP deferred receive packet    */ 
/*                                            processing                  */ 
/*    _nx_arp_packet_deferred_receive       ARP receive processing        */ 
/*    _nx_rarp_packet_deferred_receive      RARP receive processing       */ 
/*    nx_packet_release                     Packet release                */ 
/*                                                                        */ 
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    NetX IP processing                                                  */ 
/*                                                                        */ 
/*  RELEASE HISTORY                                                       */ 
/*                                                                        */ 
/*    DATE              NAME                      DESCRIPTION             */ 
/*                                                                        */ 
/*  12-31-2023     Wenhui Xie               Initial Version 6.4.0         */ 
/*                                                                        */ 
/**************************************************************************/ 
VOID _nx_ram_network_driver_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT interface_instance_id)
{
#ifdef NX_ENABLE_VLAN
    nx_link_ethernet_packet_received(ip_ptr,
                                     nx_ram_driver[interface_instance_id].nx_ram_driver_interface_ptr -> nx_interface_index,
                                     packet_ptr, NX_NULL);
#else
UINT    packet_type;

    /* Pickup the packet header to determine where the packet needs to be
       sent.  */
    packet_type =  (((UINT) (*(packet_ptr -> nx_packet_prepend_ptr+12))) << 8) | 
                    ((UINT) (*(packet_ptr -> nx_packet_prepend_ptr+13)));
    
    /* Setup interface pointer.  */
    packet_ptr -> nx_packet_ip_interface = nx_ram_driver[interface_instance_id].nx_ram_driver_interface_ptr;

    /* Route the incoming packet according to its ethernet type.  */
    /* The RAM driver accepts both IPv4 and IPv6 frames. */
    if ((packet_type == NX_ETHERNET_IP) || (packet_type == NX_ETHERNET_IPV6))
    {

        /* Note:  The length reported by some Ethernet hardware includes bytes after the packet
           as well as the Ethernet header.  In some cases, the actual packet length after the
           Ethernet header should be derived from the length in the IP header (lower 16 bits of
           the first 32-bit word).  */

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

                
#ifdef NX_ENABLE_INTERFACE_CAPABILITY
        if(_nx_ram_network_driver_calculate_checksum(packet_ptr -> nx_packet_ip_interface, packet_ptr, NX_TRUE))
        {
#ifdef NX_DROP_ERROR_CHECKSUM
            nx_packet_release(packet_ptr);
            return;
#endif /* NX_DROP_ERROR_CHECKSUM */
        }
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

        /* Route to the ip receive function.  */

#ifdef NX_DIRECT_ISR_CALL
        _nx_ip_packet_receive(ip_ptr, packet_ptr);
#else
        _nx_ip_packet_deferred_receive(ip_ptr, packet_ptr);
#endif
    }
#ifndef NX_DISABLE_IPV4
    else if (packet_type == NX_ETHERNET_ARP)
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

        /* Route to the ARP receive function.  */
        _nx_arp_packet_deferred_receive(ip_ptr, packet_ptr);

    }
    else if (packet_type == NX_ETHERNET_RARP)
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

        /* Route to the RARP receive function.  */
        _nx_rarp_packet_deferred_receive(ip_ptr, packet_ptr);
    }
#ifdef NX_PPP_PPPOE_ENABLE
    else if ((packet_type == NX_ETHERNET_PPPOE_DISCOVERY) || 
             (packet_type == NX_ETHERNET_PPPOE_SESSION))
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr = packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length = packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

        if (_nx_pppoe_client_created_ptr -> nx_pppoe_interface_ptr == nx_ram_driver[interface_instance_id].nx_ram_driver_interface_ptr)
        {
            /* Route to the PPPoE client receive function.  */
            _nx_pppoe_client_packet_deferred_receive(packet_ptr);
        }        
        else if (_nx_pppoe_server_created_ptr -> nx_pppoe_interface_ptr == nx_ram_driver[interface_instance_id].nx_ram_driver_interface_ptr)
        {
            /* Route to the PPPoE server receive function.  */
            _nx_pppoe_server_packet_deferred_receive(packet_ptr);
        }
    }
#endif
#endif

#ifdef NX_BSD_RAW_PPPOE_SUPPORT
    else if((packet_type == ETHERTYPE_PPPOE_DISC) || (packet_type == ETHERTYPE_PPPOE_SESS))
    {
        _nx_bsd_pppoe_packet_received(packet_ptr, packet_type, interface_instance_id);

    }
#endif /* NX_BSD_RAW_PPPOE_SUPPORT */

    else
    {
        /* Invalid ethernet header... release the packet.  */
        nx_packet_release(packet_ptr);
    }
#endif /* NX_ENABLE_VLAN */
}


#ifdef NX_ENABLE_INTERFACE_CAPABILITY
/**************************************************************************/ 
/*                                                                        */ 
/*  FUNCTION                                               RELEASE        */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_calculate_checksum           PORTABLE C      */ 
/*                                                           6.4.0        */ 
/*  AUTHOR                                                                */ 
/*                                                                        */ 
/*    Wenhui Xie, Microsoft Corporation                                   */ 
/*                                                                        */ 
/*  DESCRIPTION                                                           */ 
/*                                                                        */ 
/*    This function calculates or verifys checksum for headers.           */ 
/*                                                                        */ 
/*  INPUT                                                                 */ 
/*                                                                        */ 
/*    interface_ptr                         Pointer to interface          */ 
/*    packet_ptr                            Packet pointer                */ 
/*    is_check                              Check or verify               */ 
/*                                                                        */ 
/*  OUTPUT                                                                */ 
/*                                                                        */ 
/*    status                                Completion status             */
/*                                                                        */ 
/*  CALLS                                                                 */ 
/*                                                                        */ 
/*    _nx_ip_checksum_compute                                             */ 
/*                                                                        */
/*  CALLED BY                                                             */ 
/*                                                                        */ 
/*    _nx_ram_network_driver_internal                                     */ 
/*    _nx_ram_network_driver                                              */ 
/*                                                                        */ 
/*  RELEASE HISTORY                                                       */ 
/*                                                                        */ 
/*    DATE              NAME                      DESCRIPTION             */ 
/*                                                                        */ 
/*  12-31-2023     Wenhui Xie               Initial Version 6.4.0         */ 
/*                                                                        */ 
/**************************************************************************/ 
UINT  _nx_ram_network_driver_calculate_checksum(NX_INTERFACE *interface_ptr, NX_PACKET *packet_ptr, UCHAR is_check)
{
ULONG                   next_protocol = 0;
UCHAR                  *org_prepend_ptr;
USHORT                  checksum;
ULONG                   val;
UCHAR                   is_done = NX_FALSE;
UCHAR                   is_fragmented = NX_FALSE;
ULONG                   ip_src_addr[4];
ULONG                   ip_dst_addr[4];
ULONG                   data_length;
NX_TCP_HEADER          *tcp_header_ptr;
NX_UDP_HEADER          *udp_header_ptr;
#ifndef NX_DISABLE_IPV4
ULONG                   ip_header_length;
NX_IPV4_HEADER         *ip_header_ptr;
NX_ICMP_HEADER         *icmpv4_header_ptr;
NX_IGMP_HEADER         *igmp_header_ptr;
#endif /* NX_DISABLE_IPV4 */
#ifdef FEATURE_NX_IPV6
NX_ICMPV6_HEADER       *icmpv6_header_ptr;
NX_IPV6_HEADER         *ipv6_header_ptr;
#endif

    /* Get IP version. */
#ifndef NX_DISABLE_IPV4
    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
    {
        next_protocol = NX_PROTOCOL_IPV4;
    }
#endif /* NX_DISABLE_IPV4 */
#ifdef FEATURE_NX_IPV6
    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
    {
        next_protocol = NX_PROTOCOL_IPV6;
    }
#endif
    if (next_protocol == 0)
        return NX_INVALID_PACKET;

    /* Store original prepend_ptr. */
    org_prepend_ptr = packet_ptr -> nx_packet_prepend_ptr;

    /* Loop to process headers. */
    while(!is_done)
    {
        switch(next_protocol)
        {
#ifndef NX_DISABLE_IPV4
            case NX_PROTOCOL_IPV4:
            {

                /* It's assumed that the IP link driver has positioned the top pointer in the
                packet to the start of the IP address... so that's where we will start.  */
                ip_header_ptr = (NX_IPV4_HEADER *) packet_ptr -> nx_packet_prepend_ptr;

                /* Pick up the first word in the IP header. */
                val = ip_header_ptr -> nx_ip_header_word_0;

                /* Convert to host byte order. */
                NX_CHANGE_ULONG_ENDIAN(val);

                /* Obtain IP header length. */
                ip_header_length =  (val & NX_IP_LENGTH_MASK) >> 24;

                /* Check if IPv4 checksum is enabled. */
                if(((is_check) && (interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_IPV4_RX_CHECKSUM)) ||
                   ((!is_check) && (packet_ptr -> nx_packet_interface_capability_flag  & NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM)))
                {

                    /* Check fragmentation. */
                    if(is_fragmented)
                    {

                        /* Not support fragmentation. Restore origianl prepend_ptr. */
                        packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                        return NX_SUCCESS;
                    }
                
                    checksum = _nx_ip_checksum_compute(packet_ptr, NX_IP_VERSION_V4,
                                                       /* length is the size of IP header, including options */
                                                       ip_header_length << 2,
                                                       /* IPv4 header checksum doesn't care src/dest addresses */
                                                       NULL, NULL);

                    if(is_check)
                    {
                        checksum =  ~checksum & NX_LOWER_16_MASK;

                        /* Check the checksum. */
                        if (checksum)
                        {

                            /* Checksum error. Restore origianl prepend_ptr. */
                            packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                            return NX_INVALID_PACKET;
                        }
                    }
                    else
                    {
                        val = (ULONG)(~checksum);
                        val = val & NX_LOWER_16_MASK;

                        /* Convert to network byte order. */
                        NX_CHANGE_ULONG_ENDIAN(val);

                        /* Now store the checksum in the IP header.  */
                        ip_header_ptr -> nx_ip_header_word_2 =  ip_header_ptr -> nx_ip_header_word_2 | val;
                    }
                }

                /* Check if FRAGMENT flag is set. */
                val = ip_header_ptr -> nx_ip_header_word_1;
                NX_CHANGE_ULONG_ENDIAN(val);
                if(val & NX_IP_FRAGMENT_MASK)
                {

                    /* Fragmented packet not supported. Restore origianl prepend_ptr. */
                    is_fragmented = NX_TRUE;
                }

                /* Get src and dst addresses. */
                ip_src_addr[0] = ip_header_ptr -> nx_ip_header_source_ip;
                ip_dst_addr[0] = ip_header_ptr -> nx_ip_header_destination_ip;
                NX_CHANGE_ULONG_ENDIAN(ip_src_addr[0]);
                NX_CHANGE_ULONG_ENDIAN(ip_dst_addr[0]);

                /* Get next protocol. */
                next_protocol = (ip_header_ptr -> nx_ip_header_word_2 >> 8) & 0xFF;

                /* Remove IPv4 header. */
                packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + (ip_header_length << 2);
                data_length = packet_ptr -> nx_packet_length - (ip_header_length << 2);
                break;
            }
#endif /* NX_DISABLE_IPV4 */

            case NX_PROTOCOL_TCP:
            {
                
                /* Check if TCP checksum is enabled. */
                if(((is_check) && (interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_TCP_RX_CHECKSUM)) ||
                   ((!is_check) && (packet_ptr -> nx_packet_interface_capability_flag  & NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM)))
                {

                    /* Check fragmentation. */
                    if(is_fragmented)
                    {
                        /* When receiving a fragmented packet, do nothing, deliver it to NetX. */ 
                        packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                        return NX_SUCCESS;
                    }

                    /* Calculate the TCP checksum without protection.  */
                    checksum =  _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                                        data_length,
                                                        ip_src_addr, ip_dst_addr);

                    if(is_check)
                    {
                        checksum =  ~checksum & NX_LOWER_16_MASK;

                        /* Check the checksum. */
                        if (checksum)
                        {

                            /* Checksum error. Restore origianl prepend_ptr. */
                            packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                            return NX_INVALID_PACKET;
                        }
                    }
                    else
                    {                        

                        /* Pickup the pointer to the head of the TCP packet.  */
                        tcp_header_ptr =  (NX_TCP_HEADER *) packet_ptr -> nx_packet_prepend_ptr;

                        checksum = ~checksum & NX_LOWER_16_MASK;

                        /* Move the checksum into header.  */
                        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
                        tcp_header_ptr -> nx_tcp_header_word_4 |=  (checksum << NX_SHIFT_BY_16);
                        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
                    }
                }

                /* No necessary to process next protocol. */
                is_done = NX_TRUE;
                break;
            }

            case NX_PROTOCOL_UDP:
            {
                
                /* Check if UDP checksum is enabled. */
                if(((is_check) && (interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_UDP_RX_CHECKSUM)) ||
                   ((!is_check) && (packet_ptr -> nx_packet_interface_capability_flag  & NX_INTERFACE_CAPABILITY_UDP_TX_CHECKSUM)))
                {

                    /* Check fragmentation. */
                    if(is_fragmented)
                    {
                        /* When receiving a fragmented packet, do nothing, deliver it to NetX. */ 
                        packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                        return NX_SUCCESS;
                    }

                    /* Calculate the UDP checksum without protection.  */
                    checksum =  _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_UDP,
                                                        data_length,
                                                        ip_src_addr, ip_dst_addr);

                    if(is_check)
                    {

                        /* Pickup the pointer to the head of the UDP packet.  */
                        udp_header_ptr = (NX_UDP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);

                        /* Move the checksum into header.  */
                        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
                        if(((udp_header_ptr -> nx_udp_header_word_1 & NX_LOWER_16_MASK) == 0) &&
                           (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4))
                            checksum = 0;
                        else
                            checksum =  ~checksum & NX_LOWER_16_MASK;
                        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

                        /* Check the checksum. */
                        if (checksum)
                        {

                            /* Checksum error. Restore origianl prepend_ptr. */
                            packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                            return NX_INVALID_PACKET;
                        }
                    }
                    else
                    {                        

                        /* Pickup the pointer to the head of the UDP packet.  */
                        udp_header_ptr = (NX_UDP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);

                        /* Move the checksum into header.  */
                        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
                        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 | (~checksum & NX_LOWER_16_MASK);
                        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
                    }
                }

                /* No necessary to process next protocol. */
                is_done = NX_TRUE;
                break;
            }

#ifndef NX_DISABLE_IPV4
            case NX_PROTOCOL_ICMP:
            {
                
                /* Check if ICMPv4 checksum is enabled. */
                if(((is_check) && (interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_ICMPV4_RX_CHECKSUM)) ||
                   ((!is_check) && (packet_ptr -> nx_packet_interface_capability_flag  & NX_INTERFACE_CAPABILITY_ICMPV4_TX_CHECKSUM)))
                {

                    /* Check fragmentation. */
                    if(is_fragmented)
                    {

                        /* Not support fragmentation. Restore origianl prepend_ptr. */
                        packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                        return NX_SUCCESS;
                    }

                    /* Calculate the ICMPv4 checksum without protection.  */
                    checksum =  _nx_ip_checksum_compute(packet_ptr, NX_IP_ICMP,
                                                        data_length,
                                                        /* ICMPV4 header checksum doesn't care src/dest addresses */
                                                        NULL, NULL);

                    if(is_check)
                    {
                        checksum =  ~checksum & NX_LOWER_16_MASK;

                        /* Check the checksum. */
                        if (checksum)
                        {

                            /* Checksum error. Restore origianl prepend_ptr. */
                            packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                            return NX_INVALID_PACKET;
                        }
                    }
                    else
                    {                   

                        /* Pickup the pointer to the head of the ICMPv4 packet.  */
                        icmpv4_header_ptr =  (NX_ICMP_HEADER *) packet_ptr -> nx_packet_prepend_ptr;   
                        
                        /* Move the checksum into header.  */
                        NX_CHANGE_ULONG_ENDIAN(icmpv4_header_ptr -> nx_icmp_header_word_0);
                        icmpv4_header_ptr -> nx_icmp_header_word_0 =  icmpv4_header_ptr -> nx_icmp_header_word_0 | (~checksum & NX_LOWER_16_MASK);
                        NX_CHANGE_ULONG_ENDIAN(icmpv4_header_ptr -> nx_icmp_header_word_0);
                    }
                }

                /* No necessary to process next protocol. */
                is_done = NX_TRUE;
                break;
            }            
                        
            case NX_PROTOCOL_IGMP:
            {
                
                /* Check if IGMP checksum is enabled. */
                if(((is_check) && (interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_IGMP_RX_CHECKSUM)) ||
                   ((!is_check) && (packet_ptr -> nx_packet_interface_capability_flag  & NX_INTERFACE_CAPABILITY_IGMP_TX_CHECKSUM)))
                {

                    /* Check fragmentation. */
                    if(is_fragmented)
                    {

                        /* Not support fragmentation. Restore origianl prepend_ptr. */
                        packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                        return NX_SUCCESS;
                    }

                    /* Pickup the pointer to the head of the IGMP packet.  */
                    igmp_header_ptr =  (NX_IGMP_HEADER *) packet_ptr -> nx_packet_prepend_ptr;

                    /* Change the endian.  */
                    NX_CHANGE_ULONG_ENDIAN(igmp_header_ptr -> nx_igmp_header_word_0);
                    NX_CHANGE_ULONG_ENDIAN(igmp_header_ptr -> nx_igmp_header_word_1);

                    /* Calculate the checksum.  */
                    val =       igmp_header_ptr -> nx_igmp_header_word_0;
                    checksum =  (val >> NX_SHIFT_BY_16);
                    checksum += (val & NX_LOWER_16_MASK);
                    val =      igmp_header_ptr -> nx_igmp_header_word_1;
                    checksum += (val >> NX_SHIFT_BY_16);
                    checksum += (val & NX_LOWER_16_MASK);

                    /* Add in the carry bits into the checksum.  */
                    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

                    /* Do it again in case previous operation generates an overflow.  */
                    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

                    if(is_check)
                    {

                        /* Change the endian.  */
                        NX_CHANGE_ULONG_ENDIAN(igmp_header_ptr -> nx_igmp_header_word_0);
                        NX_CHANGE_ULONG_ENDIAN(igmp_header_ptr -> nx_igmp_header_word_1);

                        /* Check the checksum. */
                        if ((~checksum) & 0xFFFF)
                        {

                            /* Checksum error. Restore origianl prepend_ptr. */
                            packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                            return NX_INVALID_PACKET;
                        }
                    }
                    else
                    {

                        /* Place the checksum into the first header word.  */
                        igmp_header_ptr -> nx_igmp_header_word_0 =  igmp_header_ptr -> nx_igmp_header_word_0 | (~checksum & NX_LOWER_16_MASK);

                        /* Change the endian.  */
                        NX_CHANGE_ULONG_ENDIAN(igmp_header_ptr -> nx_igmp_header_word_0);
                        NX_CHANGE_ULONG_ENDIAN(igmp_header_ptr -> nx_igmp_header_word_1);
                    }

                    /* No necessary to process next protocol. */
                    is_done = NX_TRUE;
                    break;
                }

                /* No necessary to process next protocol. */
                is_done = NX_TRUE;
                break;
            }
#endif /* NX_DISABLE_IPV4 */   

#ifdef FEATURE_NX_IPV6 
            case NX_PROTOCOL_ICMPV6:
            {
                
                /* Check if ICMPv6 checksum is enabled. */
                if(((is_check) && (interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_ICMPV6_RX_CHECKSUM)) ||
                   ((!is_check) && (packet_ptr -> nx_packet_interface_capability_flag  & NX_INTERFACE_CAPABILITY_ICMPV6_TX_CHECKSUM)))
                {

                    /* Check fragmentation. */
                    if(is_fragmented)
                    {

                        /* Not support fragmentation. Restore origianl prepend_ptr. */
                        packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                        return NX_SUCCESS;
                    }

                    /* Calculate the ICMPv6 checksum without protection.  */
                    checksum =  _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_ICMPV6,
                                                        data_length,
                                                        ip_src_addr, ip_dst_addr);

                    if(is_check)
                    {
                        checksum =  ~checksum & NX_LOWER_16_MASK;

                        /* Check the checksum. */
                        if (checksum)
                        {

                            /* Checksum error. Restore origianl prepend_ptr. */
                            packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                            return NX_INVALID_PACKET;
                        }
                    }
                    else
                    {                        

                        /* Pickup the pointer to the head of the ICMPv6 packet.  */
                        icmpv6_header_ptr =  (NX_ICMPV6_HEADER *) packet_ptr -> nx_packet_prepend_ptr;   

                        checksum = ~checksum;
                        
                        /* Move the checksum into header.  */
                        NX_CHANGE_USHORT_ENDIAN(checksum);
                        icmpv6_header_ptr -> nx_icmpv6_header_checksum = checksum;
                    }
                }

                /* No necessary to process next protocol. */
                is_done = NX_TRUE;
                break;
            }

            case NX_PROTOCOL_IPV6:
            {
                
                /* Check fragmentation. */
                if(is_fragmented)
                {

                    /* Not support fragmentation. Restore origianl prepend_ptr. */
                    packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
                    return NX_SUCCESS;
                }
                
                /* Points to the base of IPv6 header. */
                ipv6_header_ptr = (NX_IPV6_HEADER*)packet_ptr -> nx_packet_prepend_ptr;
                
                /* Get src and dst addresses. */
                COPY_IPV6_ADDRESS(ipv6_header_ptr -> nx_ip_header_source_ip, ip_src_addr);
                COPY_IPV6_ADDRESS(ipv6_header_ptr -> nx_ip_header_destination_ip, ip_dst_addr);
                NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_src_addr);
                NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_dst_addr);

                /* Get next protocol. */
                next_protocol = (ipv6_header_ptr -> nx_ip_header_word_1 >> 16) & 0xFF;

                /* Remove IPv6 header. */
                packet_ptr -> nx_packet_prepend_ptr += sizeof(NX_IPV6_HEADER);
                data_length = packet_ptr -> nx_packet_length - sizeof(NX_IPV6_HEADER);
                break;
            }
            
            case NX_PROTOCOL_NEXT_HEADER_FRAGMENT:
                is_fragmented = NX_TRUE;
            case NX_PROTOCOL_NEXT_HEADER_HOP_BY_HOP:
            case NX_PROTOCOL_NEXT_HEADER_DESTINATION:
            case NX_PROTOCOL_NEXT_HEADER_ROUTING:
            {
                next_protocol = (ULONG)(*packet_ptr -> nx_packet_prepend_ptr);
                data_length -= (ULONG)(*(packet_ptr -> nx_packet_prepend_ptr + 1));
                packet_ptr -> nx_packet_prepend_ptr += (ULONG)(*(packet_ptr -> nx_packet_prepend_ptr + 1));
                break;
            }
#endif

            default:
                /* Unsupported protocol. */
                is_done = NX_TRUE;
                break;
        }
    }

    
    /* Restore origianl prepend_ptr. */
    packet_ptr -> nx_packet_prepend_ptr = org_prepend_ptr;
    return NX_SUCCESS;
}
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */


#ifdef NX_PCAP_ENABLE
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    get_time_of_day                                    PORTABLE C       */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets sec and usec from January 1, 1970                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    tv                                 Pointer to TIME_VAL structure    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    write_pcap_file                                                     */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023       Wenhui Xie             Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
VOID get_time_of_day(NX_TIME_VALUE *time_value) 
{
#ifdef linux

    /* Get the system time.  */
    gettimeofday(tv);
#else 
SYSTEMTIME  systemtime;
FILETIME    filetime;
ULONG64     time;

    /* Get the system time.  */
    GetSystemTime(&systemtime);

    /* Get the file time.  */
    SystemTimeToFileTime(&systemtime, &filetime);

    /* Set the time as ULONG64.  */
    time = ((ULONG64)filetime.dwLowDateTime);
    time += (((ULONG64)filetime.dwHighDateTime) << 32);

    /* Set the time as from January 1, 1970.  */
    time_value -> tv_sec = (LONG)((time - ((UINT64)116444736000000000ULL)) / 10000000L);
    time_value -> tv_usec = (LONG)(systemtime.wMilliseconds * 1000);
#endif
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    create_pcap_file                                     PORTABLE C     */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates libpcap file global header based on libpcap   */
/*    file format and writes it to the file.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    file_name                               String of file name         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_PCAP_FILE_OK                         Successful file open status */
/*    NX_PCAP_FILE_ERROR                      Failed file open status     */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023       Wenhui Xie               Initial Version 6.4.0       */
/*                                                                        */
/**************************************************************************/
UINT create_pcap_file(CHAR *file_name) 
{
NX_PCAP_FILE_HEADER     pcap_file_header;

    /* Set the pcap file header value.  */
    pcap_file_header.magic_number = 0xa1b2c3d4;
    pcap_file_header.version_major = 2;
    pcap_file_header.version_minor = 4;
    pcap_file_header.this_zone = -28800;
    pcap_file_header.sig_figs = 0;
    pcap_file_header.snapshot_length = 0x0000ffff;
    pcap_file_header.link_type = 1;

    /* Open the pcap file.  */
    nx_network_driver_pcap_fp = fopen(file_name, "wb+");

    /* Check if open the pcap file.  */
    if (nx_network_driver_pcap_fp == NX_NULL)
        return (NX_PCAP_FILE_ERROR);

    /* Write the pcap file header.  */
    fwrite(&pcap_file_header, sizeof(pcap_file_header), 1, nx_network_driver_pcap_fp);

    /* Return.  */
    return (NX_PCAP_FILE_OK);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    write_pcap_file                                     PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates libpcap file packet header based on libpcap   */
/*    file format, receives packet data, and writes them to the file.     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer to the source packet  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_PCAP_FILE_OK                         Successful file open status */
/*    NX_PCAP_FILE_ERROR                      Failed file open status     */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ram_network_driver_output                                       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023       Wenhui Xie            Initial Version 6.4.0          */
/*                                                                        */
/**************************************************************************/
UINT write_pcap_file(NX_PACKET *packet_ptr)
{
NX_PCAP_PACKET_HEADER   pcap_packet_header;
NX_TIME_VALUE           time_value;
CHAR                    data_buffer[3014];
ULONG                   data_length;

    /* Get the system time.  */
    get_time_of_day(&time_value);

    /* Retrieve data from packet. */
    nx_packet_data_retrieve(packet_ptr, data_buffer, &data_length);

    /* Set the time.  */
    pcap_packet_header.time_stamp_second = time_value.tv_sec;
    pcap_packet_header.time_stamp_microseconds = time_value.tv_usec;
    pcap_packet_header.capture_length = data_length;
    pcap_packet_header.actual_length = data_length;

    /* Check if open the pcap file.  */
    if (nx_network_driver_pcap_fp == NX_NULL)
        return (NX_PCAP_FILE_ERROR);

    /* Write the pcap packet header.  */
    fwrite(&pcap_packet_header, sizeof(pcap_packet_header), 1, nx_network_driver_pcap_fp);

    /* Write the packet data.  */
    fwrite(data_buffer, data_length, 1, nx_network_driver_pcap_fp);

    /* Flush the file data.  */
    fflush(nx_network_driver_pcap_fp);

    /* Return.  */
    return (NX_PCAP_FILE_OK);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    close_pcap_file                                     PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wenhui Xie, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function closes the libpcap file opened                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*     None                                                               */
/*                                                                        */
/*  OUTPUT                                                                */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023       Wenhui Xie            Initial Version 6.4.0          */
/*                                                                        */
/**************************************************************************/
VOID close_pcap_file()
{

    /* Check if the pcap file pointer.  */
    if (nx_network_driver_pcap_fp != NX_NULL)
    {

        /* Close the file.  */
        fclose(nx_network_driver_pcap_fp);

        /* Set the pcap file pointer to NX_NULL.  */
        nx_network_driver_pcap_fp = NX_NULL;
    }
}
#endif /* NX_PCAP_ENABLE  */

#ifdef NX_BSD_RAW_SUPPORT
/* Stub function used by BSD raw socket. */
UINT _nx_driver_hardware_packet_send(NX_PACKET *packet_ptr)
{

    if (!(packet_ptr -> nx_packet_ip_interface -> nx_interface_valid))
        return(NX_PTR_ERROR);
    return(NX_SUCCESS);
}

/* Callback function pointer when packet is received. */
VOID (*_nx_driver_hardware_packet_received_callback)(NX_PACKET *packet_ptr, UCHAR *consumed);
#endif /* NX_BSD_RAW_SUPPORT */
