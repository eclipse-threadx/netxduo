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

#ifdef WIN32
#define     HAVE_REMOTE
#define     WPCAP
#endif

#include    "pcap.h"
#include    "nx_api.h"
#include    "tx_thread.h"
#ifndef WIN32
#include    "pthread.h"
#endif
#ifdef      NX_ENABLE_PPPOE
#include    "nx_pppoe_server.h"
#endif

#ifdef WIN32
#pragma   comment(lib, "wpcap.lib")
#pragma   comment(lib, "Packet.lib")
#pragma   comment(lib, "ws2_32.lib")
#endif

/* Define zero-terminated string containing the source name to open. */
/* In windows, the SOURCE NAME looks like this "rpcap://\\Device\\NPF_{4C8Bxxxx-xxxx-xxxx-xxxx-xxxxxxxx8356}" */
/* In Linux, the SOURCE NAME looks like this "eth0" */
#ifndef NX_PCAP_SOURCE_NAME
#define NX_PCAP_SOURCE_NAME     "rpcap://\\Device\\NPF_{4C8Bxxxx-xxxx-xxxx-xxxx-xxxxxxxx8356}"

#endif /* NX_LIBPCAP_SOURCE_NAME */

/* Define the Link MTU. Note this is not the same as the IP MTU.  The Link MTU
   includes the addition of the Physical Network header (usually Ethernet). This
   should be larger than the IP instance MTU by the size of the physical header. */
#define NX_LINK_MTU         1514
#define NX_MAX_PACKET_SIZE  1536

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

#define NX_ETHERNET_IP              0x0800
#define NX_ETHERNET_ARP             0x0806
#define NX_ETHERNET_RARP            0x8035
#define NX_ETHERNET_IPV6            0x86DD
#define NX_ETHERNET_PPPOE_DISCOVERY 0x8863
#define NX_ETHERNET_PPPOE_SESSION   0x8864
#define NX_ETHERNET_SIZE            14

/* For the pcap ethernet driver, physical addresses are allocated starting
   at the preset value and then incremented before the next allocation.  */

ULONG   nx_pcap_address_msw =  0x0011;
ULONG   nx_pcap_address_lsw =  0x22334457;

static const CHAR  *nx_pcap_source_name = NX_PCAP_SOURCE_NAME;

#ifdef WIN32
/* Define the Windows thread to call pcap_loop. */
static HANDLE       nx_pcap_receive_thread;
#else
/* Define the Linux thread to call pcap_loop. */
static pthread_t    nx_pcap_receive_thread;
#endif
static NX_IP        *nx_pcap_default_ip;
static pcap_t       *nx_pcap_fp;

/* Define the buffer to store data that will be sent by pcap. */
static UCHAR        nx_pcap_send_buff[NX_MAX_PACKET_SIZE];


/* Define driver prototypes.  */

UINT         _nx_pcap_initialize(NX_IP *ip_ptr);
UINT         _nx_pcap_send_packet(NX_PACKET * packet_ptr);
#ifdef WIN32
DWORD WINAPI _nx_pcap_receive_thread_entry(LPVOID  thread_input);
#else
void         *_nx_pcap_receive_thread_entry(void *arg);
#endif
VOID         _nx_lpcap_packet_receive_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
VOID         _nx_pcap_network_driver_output(NX_PACKET *packet_ptr);
VOID         _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);
VOID         nx_pcap_cleanup();

/* Define interface capability.  */

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
#define NX_INTERFACE_CAPABILITY ( NX_INTERFACE_CAPABILITY_IPV4_RX_CHECKSUM | \
                                  NX_INTERFACE_CAPABILITY_TCP_RX_CHECKSUM | \
                                  NX_INTERFACE_CAPABILITY_UDP_RX_CHECKSUM | \
                                  NX_INTERFACE_CAPABILITY_ICMPV4_RX_CHECKSUM | \
                                  NX_INTERFACE_CAPABILITY_ICMPV6_RX_CHECKSUM  )    
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

VOID nx_pcap_set_source_name(const CHAR *source_name)
{
    nx_pcap_source_name = source_name;
}

UINT _nx_pcap_send_packet(NX_PACKET * packet_ptr)
{
ULONG   size = 0;

    /* Make sure the data length is less than MTU. */
    if(packet_ptr -> nx_packet_length > NX_MAX_PACKET_SIZE)
        return NX_NOT_SUCCESSFUL;

    if(nx_packet_data_retrieve(packet_ptr, nx_pcap_send_buff, &size))
        return NX_NOT_SUCCESSFUL;

    if(pcap_sendpacket(nx_pcap_fp, nx_pcap_send_buff, size) != 0)
        return NX_NOT_SUCCESSFUL;

    return NX_SUCCESS;
}


void nx_pcap_cleanup()
{
    pcap_close(nx_pcap_fp);
}


VOID _nx_pcap_packet_receive_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

NX_PACKET   *packet_ptr;
UINT        status;
UINT        packet_type;

#ifndef NX_ENABLE_PCAP_LOCAL_RECEIVE
    /* Check whether the packet is generated by local. */
    if((*(pkt_data + 6)  == ((nx_pcap_address_msw >> 8) & 0xFF)) &&
       (*(pkt_data + 7)  == (nx_pcap_address_msw & 0xFF)) &&
       (*(pkt_data + 8)  == ((nx_pcap_address_lsw >> 24) & 0xFF)) &&
       (*(pkt_data + 9)  == ((nx_pcap_address_lsw >> 16) & 0xFF)) &&
       (*(pkt_data + 10) == ((nx_pcap_address_lsw >> 8) & 0xFF)) &&
       (*(pkt_data + 11) == (nx_pcap_address_lsw & 0xFF)))
    {
        return;
    }
#endif /* NX_PCAP_LOCAL_RECEIVE */

    _tx_thread_context_save();

    status = nx_packet_allocate(nx_pcap_default_ip -> nx_ip_default_packet_pool, &packet_ptr, NX_RECEIVE_PACKET, NX_NO_WAIT);

    if(status)
    {
        _tx_thread_context_restore();
        return;
    }

    /* Make sure IP header is 4-byte aligned. */
    packet_ptr -> nx_packet_prepend_ptr += 2;
    packet_ptr -> nx_packet_append_ptr += 2;

    status = nx_packet_data_append(packet_ptr, (VOID*)pkt_data, header -> len,
                                   nx_pcap_default_ip -> nx_ip_default_packet_pool, NX_NO_WAIT);

    if(status)
    {
        nx_packet_release(packet_ptr);
        _tx_thread_context_restore();
        return;
    }

    /* Pickup the packet header to determine where the packet needs to be sent.  */
    packet_type =  (((UINT) (*(packet_ptr -> nx_packet_prepend_ptr+12))) << 8) | 
                     ((UINT) (*(packet_ptr -> nx_packet_prepend_ptr+13)));

    /* Route the incoming packet according to its ethernet type.  */
    if((packet_type == NX_ETHERNET_IP) || (packet_type == NX_ETHERNET_IPV6))
    {

        /* Note:  The length reported by some Ethernet hardware includes bytes after the packet
           as well as the Ethernet header.  In some cases, the actual packet length after the
           Ethernet header should be derived from the length in the IP header (lower 16 bits of
           the first 32-bit word).  */

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;


        _nx_ip_packet_deferred_receive(nx_pcap_default_ip, packet_ptr);
    }
    else if(packet_type == NX_ETHERNET_ARP)
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

        _nx_arp_packet_deferred_receive(nx_pcap_default_ip, packet_ptr);

    }
    else if(packet_type == NX_ETHERNET_RARP)
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

        _nx_rarp_packet_deferred_receive(nx_pcap_default_ip, packet_ptr);
    }
#ifdef NX_ENABLE_PPPOE
    else if ((packet_type == NX_ETHERNET_PPPOE_DISCOVERY) ||
             (packet_type == NX_ETHERNET_PPPOE_SESSION))
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

        /* Route to the PPPoE receive function.  */
        _nx_pppoe_packet_deferred_receive(packet_ptr);
    }
#endif
    else
    {

        /* Invalid ethernet header... release the packet.  */
        nx_packet_release(packet_ptr);
    }
    _tx_thread_context_restore();
}

#ifdef WIN32
DWORD WINAPI _nx_pcap_receive_thread_entry(LPVOID  thread_input)
{
    /* Loop to capture packets. */
    pcap_loop(nx_pcap_fp, 0, _nx_pcap_packet_receive_handler, NULL);
    return 0;
}
#else
void *_nx_pcap_receive_thread_entry(void *arg)
{

    /* Loop to capture packets. */
    pcap_loop(nx_pcap_fp, 0, _nx_pcap_packet_receive_handler, NULL);
    return((void *)0);
}
#endif

UINT _nx_pcap_initialize(NX_IP *ip_ptr_in)
{
CHAR    errbuf[PCAP_ERRBUF_SIZE] = { 0 };

#ifndef WIN32
struct sched_param sp;
    
    /* Define the thread's priority. */
#ifdef TX_LINUX_PRIORITY_ISR
    sp.sched_priority = TX_LINUX_PRIORITY_ISR;
#else
    sp.sched_priority = 2;
#endif
#endif
    
    /* Return if source has been opened. */
    if(nx_pcap_fp)
        return 1;

#ifdef WIN32
    if((nx_pcap_fp = pcap_open(nx_pcap_source_name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, errbuf)) == NULL)
    {
        return NX_NOT_CREATED;
    }
#else
    if((nx_pcap_fp = pcap_create(nx_pcap_source_name, NULL)) == NULL)
    {
        return NX_NOT_CREATED;
    }
    
    if (pcap_set_immediate_mode(nx_pcap_fp, 1) < 0)
    {
        nx_pcap_cleanup();
        return NX_NOT_CREATED;
    }

    if (pcap_set_promisc(nx_pcap_fp, 1) < 0)
    {
        nx_pcap_cleanup();
        return NX_NOT_CREATED;
    }

    if (pcap_set_snaplen(nx_pcap_fp, 65536) < 0)
    {
        nx_pcap_cleanup();
        return NX_NOT_CREATED;
    }

    if (pcap_activate(nx_pcap_fp) < 0)
    {
        nx_pcap_cleanup();
        return NX_NOT_CREATED;
    }
#endif

    nx_pcap_default_ip = ip_ptr_in;

#ifdef WIN32
    nx_pcap_receive_thread = CreateThread(NULL, 0, _nx_pcap_receive_thread_entry, (LPVOID)NULL, CREATE_SUSPENDED, NULL);
    SetThreadPriority(nx_pcap_receive_thread, THREAD_PRIORITY_BELOW_NORMAL);
    ResumeThread(nx_pcap_receive_thread);
#else

    /* Create a Linux thread to loop for capturing packets */
    pthread_create(&nx_pcap_receive_thread, NULL, _nx_pcap_receive_thread_entry, NULL);

    /* Set the thread's policy and priority */
    pthread_setschedparam(nx_pcap_receive_thread, SCHED_FIFO, &sp);
#endif

    return NX_SUCCESS;
}


VOID  _nx_pcap_network_driver_output(NX_PACKET *packet_ptr)
{
UINT        old_threshold = 0;

    /* Disable preemption.  */ 
    tx_thread_preemption_change(tx_thread_identify(), 0, &old_threshold);

    _nx_pcap_send_packet(packet_ptr);

    /* Remove the Ethernet header.  In real hardware environments, this is typically 
       done after a transmit complete interrupt.  */
    packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

    /* Adjust the packet length.  */
    packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

    /* Now that the Ethernet frame has been removed, release the packet.  */
    nx_packet_transmit_release(packet_ptr);

    /* Restore preemption.  */
    tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
}


VOID  _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr)
{
NX_IP           *ip_ptr;
NX_PACKET       *packet_ptr;
ULONG           *ethernet_frame_ptr;
NX_INTERFACE    *interface_ptr;     
#ifdef __PRODUCT_NETXDUO__    
UINT            interface_index;
#endif  

    /* Setup the IP pointer from the driver request.  */
    ip_ptr =  driver_req_ptr -> nx_ip_driver_ptr;

    /* Default to successful return.  */
    driver_req_ptr -> nx_ip_driver_status =  NX_SUCCESS;

    /* Setup interface pointer.  */
    interface_ptr = driver_req_ptr -> nx_ip_driver_interface;
    
#ifdef __PRODUCT_NETXDUO__
    /* Obtain the index number of the network interface. */
    interface_index = interface_ptr -> nx_interface_index;
#endif  

    /* Process according to the driver request type in the IP control 
       block.  */
    switch (driver_req_ptr -> nx_ip_driver_command)
    {

        case NX_LINK_INTERFACE_ATTACH:
            {
                interface_ptr = (NX_INTERFACE*)(driver_req_ptr -> nx_ip_driver_interface);
                break;
            }

        case NX_LINK_INITIALIZE:
            {

                /* Device driver shall initialize the Ethernet Controller here. */

                /* Once the Ethernet controller is initialized, the driver needs to 
                   configure the NetX Interface Control block, as outlined below. */
                   
#ifdef __PRODUCT_NETXDUO__
                /* The nx_interface_ip_mtu_size should be the MTU for the IP payload.
                   For regular Ethernet, the IP MTU is 1500. */
                nx_ip_interface_mtu_set(ip_ptr, interface_index, (NX_LINK_MTU - NX_ETHERNET_SIZE));

                /* Set the physical address (MAC address) of this IP instance.  */
                /* For this pcap driver, the MAC address is constructed by 
                   incrementing a base lsw value, to simulate multiple nodes hanging on the
                   ethernet.  */
                nx_ip_interface_physical_address_set(ip_ptr, interface_index, 
                        nx_pcap_address_msw,
                        nx_pcap_address_lsw, 
                        NX_FALSE);

                /* Indicate to the IP software that IP to physical mapping is required.  */
                nx_ip_interface_address_mapping_configure(ip_ptr, interface_index, NX_TRUE);
#else 
                interface_ptr -> nx_interface_ip_mtu_size =  NX_LINK_MTU;
                interface_ptr -> nx_interface_physical_address_msw =  nx_pcap_address_msw;
                interface_ptr -> nx_interface_physical_address_lsw =  nx_pcap_address_lsw;
                interface_ptr -> nx_interface_address_mapping_needed =  NX_TRUE;
#endif
       

                _nx_pcap_initialize(ip_ptr); 

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
                nx_ip_interface_capability_set(ip_ptr, interface_index, NX_INTERFACE_CAPABILITY);
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */
                break;
            }

        case NX_LINK_ENABLE:
            {

                /* Process driver link enable.  An Ethernet driver shall enable the 
                   transmit and reception logic.  Once the IP stack issues the 
                   LINK_ENABLE command, the stack may start transmitting IP packets. */


                /* In the driver, just set the enabled flag.  */
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

                /* In the pcap driver, just clear the enabled flag.  */
                interface_ptr -> nx_interface_link_up =  NX_FALSE;

                break;
            }

        case NX_LINK_PACKET_SEND:
        case NX_LINK_PACKET_BROADCAST:
        case NX_LINK_ARP_SEND:
        case NX_LINK_ARP_RESPONSE_SEND:
        case NX_LINK_RARP_SEND:
#ifdef NX_ENABLE_PPPOE
        case NX_LINK_PPPOE_DISCOVERY_SEND:
        case NX_LINK_PPPOE_SESSION_SEND:
#endif
            {

                /* 
                   The IP stack sends down a data packet for transmission. 
                   The device driver needs to prepend a MAC header, and fill in the 
                   Ethernet frame type (assuming Ethernet protocol for network transmission)
                   based on the type of packet being transmitted.

                   The following sequence illustrates this process. 
                   */

                /* Place the ethernet frame at the front of the packet.  */
                packet_ptr =  driver_req_ptr -> nx_ip_driver_packet;

                /* Adjust the prepend pointer.  */
                packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - NX_ETHERNET_SIZE;

                /* Adjust the packet length.  */
                packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + NX_ETHERNET_SIZE;

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
#ifdef NX_ENABLE_PPPOE
                else if(driver_req_ptr -> nx_ip_driver_command == NX_LINK_PPPOE_DISCOVERY_SEND)
                {
                    *(ethernet_frame_ptr + 3) |= NX_ETHERNET_PPPOE_DISCOVERY;        
                }
                else if(driver_req_ptr -> nx_ip_driver_command == NX_LINK_PPPOE_SESSION_SEND)
                {
                    *(ethernet_frame_ptr + 3) |= NX_ETHERNET_PPPOE_SESSION;        
                }
#endif
#ifdef __PRODUCT_NETXDUO__
                else if(packet_ptr -> nx_packet_ip_version == 4)
                    *(ethernet_frame_ptr+3) |= NX_ETHERNET_IP;
                else
                    *(ethernet_frame_ptr+3) |= NX_ETHERNET_IPV6;
#else
                else
                    *(ethernet_frame_ptr+3) |= NX_ETHERNET_IP;
#endif
                    


                /* Endian swapping if NX_LITTLE_ENDIAN is defined.  */
                NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));
                NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr+1));
                NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr+2));
                NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr+3));

                /* At this point, the packet is a complete Ethernet frame, ready to be transmitted.
                   The driver shall call the actual Ethernet transmit routine and put the packet
                   on the wire.   

                   In this example, the pcap network transmit routine is called. */ 
                _nx_pcap_network_driver_output(packet_ptr);
                break;
            }

        case NX_LINK_MULTICAST_JOIN:
            {

                /* The IP layer issues this command to join a multicast group.  Note that 
                   multicast operation is required for IPv6.  

                   On a typically Ethernet controller, the driver computes a hash value based
                   on MAC address, and programs the hash table. 

                   It is likely the driver also needs to maintain an internal MAC address table.
                   Later if a multicast address is removed, the driver needs
                   to reprogram the hash table based on the remaining multicast MAC addresses. */

                break;
            }

        case NX_LINK_MULTICAST_LEAVE:
            {

                /* The IP layer issues this command to remove a multicast MAC address from the
                   receiving list.  A device driver shall properly remove the multicast address
                   from the hash table, so the hardware does not receive such traffic.  Note that
                   in order to reprogram the hash table, the device driver may have to keep track of
                   current active multicast MAC addresses. */

                /* The following procedure only applies to our pcap network driver, which manages
                   multicast MAC addresses by a simple look up table. */

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
                   the pending receive process. 
                   */

                /* The pcap driver doesn't require a deferred process so it breaks out of 
                   the switch case. */


                break;
            }

        default:
            {

                /* Invalid driver request.  */
                /* Return the unhandled command status.  */
                driver_req_ptr -> nx_ip_driver_status =  NX_UNHANDLED_COMMAND;
            }

    }
}

