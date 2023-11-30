#include "tx_api.h"
#include "nx_api.h"
                      
extern void test_control_return(UINT status);
#ifdef FEATURE_NX_IPV6
#include "nx_udp.h"
#include "nx_ip.h"
#include "nx_ipv6.h"
#include "nxd_dhcpv6_client.h"   

#define DEMO_STACK_SIZE         2048
#define DHCPV6_IANA_ID          0xc0dedbad

static TX_THREAD                dhcpv6_client_thread;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static NX_DHCPV6                dhcp_client;

static CHAR                     *pointer;
static ULONG                    error_counter;

static UCHAR                    solicit = NX_FALSE;
static UCHAR                    request = NX_FALSE;
static ULONG                    server_identifier;
static ULONG                    server_identifier_length;
static ULONG                    server_duid_type;
static ULONG                    server_hardware_type;
static ULONG                    server_msw;
static ULONG                    server_lsw;

/* Define thread prototypes.  */

static void dhcpv6_client_thread_entry(ULONG thread_input);
extern void _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);       
static UINT my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern UINT _nx_dhcpv6_utility_get_block_option_length(UCHAR *buffer_ptr, ULONG *option, ULONG *length);

/* Frame (118 bytes) Solicit  */
static unsigned char pkt1[118] = {
0x33, 0x33, 0x00, 0x01, 0x00, 0x02, 0x00, 0x80, /* 33...... */
0xa3, 0xc7, 0x1c, 0xf6, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x40, 0x11, 0x40, 0xfe, 0x80, /* ...@.@.. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x80, /* ........ */
0xa3, 0xff, 0xfe, 0xc7, 0x1c, 0xf6, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x02, 0x22, /* ......." */
0x02, 0x23, 0x00, 0x40, 0xc2, 0x19, 0x01, 0xdc, /* .#.@.... */
0x5d, 0x45, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, /* ]E...... */
0x00, 0x01, 0x5a, 0xcd, 0x54, 0xc7, 0x00, 0x80, /* ..Z.T... */
0xa3, 0xc7, 0x1c, 0xf6, 0x00, 0x03, 0x00, 0x0c, /* ........ */
0xc0, 0xde, 0xdb, 0xad, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, /* ........ */
0x0c, 0x1c, 0x00, 0x06, 0x00, 0x08, 0x00, 0x17, /* ........ */
0x00, 0x1f, 0x00, 0x29, 0x00, 0x18              /* ...).. */
};

/* Frame (178 bytes) Advertise  */
static unsigned char pkt2[178] = {
0x00, 0x80, 0xa3, 0xc7, 0x1c, 0xf6, 0xec, 0x08, /* ........ */
0x6b, 0x93, 0x70, 0xde, 0x86, 0xdd, 0x60, 0x00, /* k.p...`. */
0x00, 0x00, 0x00, 0x7c, 0x11, 0x40, 0xfe, 0x80, /* ...|.@.. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xee, 0x08, /* ........ */
0x6b, 0xff, 0xfe, 0x93, 0x70, 0xde, 0xfe, 0x80, /* k...p... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x80, /* ........ */
0xa3, 0xff, 0xfe, 0xc7, 0x1c, 0xf6, 0xd3, 0x98, /* ........ */
0x02, 0x22, 0x00, 0x7c, 0xd9, 0x80, 0x02, 0xdc, /* .".|.... */
0x5d, 0x45, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, /* ]E...... */
0x00, 0x01, 0x5a, 0xcd, 0x54, 0xc7, 0x00, 0x80, /* ..Z.T... */
0xa3, 0xc7, 0x1c, 0xf6, 0x00, 0x02, 0x00, 0x0a, /* ........ */
0x00, 0x03, 0x00, 0x01, 0xec, 0x08, 0x6b, 0x93, /* ......k. */
0x70, 0xde, 0x00, 0x03, 0x00, 0x28, 0xc0, 0xde, /* p....(.. */
0xdb, 0xad, 0x00, 0x00, 0xa8, 0xc0, 0x00, 0x01, /* ........ */
0x0e, 0x00, 0x00, 0x05, 0x00, 0x18, 0x12, 0x34, /* .......4 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, /* ........ */
0x51, 0x80, 0x00, 0x01, 0x51, 0x80, 0x00, 0x17, /* Q...Q... */
0x00, 0x20, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, /* . .4.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, /* ...4.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x02                                      /* .. */
};


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_client_process_server_duid_test_application_define(void * first_unused_memory)
#endif
{
UINT            status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;
    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    if(status)
        error_counter++;

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);
    if(status)
        error_counter++;

    status = nx_udp_enable(&ip_0);
    if(status)
        error_counter++;
                 
    /* Create the main thread.  */
    tx_thread_create(&dhcpv6_client_thread, "dhcpv6 client thread", dhcpv6_client_thread_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;       
}

void dhcpv6_client_thread_entry(ULONG thread_input)
{
UINT        status;
                      
                             
    /* Print out test information banner.  */
    printf("NetX Test:   DHCPv6 Client Process Server Duid Test....................");
                                                                              
    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Set the new physical address.  */
    status = nx_ip_interface_physical_address_set(&ip_0, 0, 0x00000080, 0xa3c71cf6, NX_TRUE);  

    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }    
          
    /* Set the linklocal address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);

    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait to finish the DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Create a DHCPv6 Client. */
    status = nx_dhcpv6_client_create(&dhcp_client, &ip_0, "DHCPv6 Client", &pool_0, pointer, 2048, NX_NULL, NX_NULL);
    pointer += 2048;
                           
    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Create a Link Layer Plus Time DUID for the DHCPv6 Client. Set time ID field 
       to NULL; the DHCPv6 Client API will supply one. */
    status = nx_dhcpv6_create_client_duid(&dhcp_client, NX_DHCPV6_DUID_TYPE_LINK_TIME, NX_DHCPV6_HW_TYPE_IEEE_802, 0x5acd54c7);   
           
    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Create the DHCPv6 client's Identity Association (IA-NA) now. */
    status = nx_dhcpv6_create_client_iana(&dhcp_client, DHCPV6_IANA_ID, 0xFFFFFFFF,  0xFFFFFFFF); 

    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }       
              
    /* Set the DNS Server option.  */
    status = nx_dhcpv6_request_option_DNS_server(&dhcp_client, NX_TRUE); 
             
    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set the SNTP Server option.  */
    status = nx_dhcpv6_request_option_time_server(&dhcp_client, NX_TRUE); 
             
    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the Time Zone option.  */
    status = nx_dhcpv6_request_option_timezone(&dhcp_client, NX_TRUE); 
             
    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set the Domain Search List option.  */
    status = nx_dhcpv6_request_option_domain_name(&dhcp_client, NX_TRUE); 
             
    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the call back function.  */
    packet_process_callback = my_packet_process;

    /* Start the NetX DHCPv6 Client.  */
    status =  nx_dhcpv6_start(&dhcp_client);

    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Request the IPv6 address.  */
    status = nx_dhcpv6_request_solicit(&dhcp_client);

    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for Advertise.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Check the error counter.  */
    if ((error_counter) || (solicit != NX_TRUE) || (request != NX_TRUE))
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
static UINT my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

ULONG       received_message_type;
NX_PACKET   *response_packet;
UINT        status;
NX_IPV6_HEADER  *ip_header;

    /* Update the prepend to point DHCPv6 message, IPv6 header, UDP header.  */
    packet_ptr -> nx_packet_prepend_ptr += (40 + 8);

    /* Extract the message type which should be the first byte.  */
    _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr, 1, &received_message_type);

    /* Check for an illegal message type. */
    if ((received_message_type == NX_DHCPV6_MESSAGE_TYPE_SOLICIT) && (solicit == NX_FALSE))
    {

        solicit = NX_TRUE;

        /* Send DHCPv6 Server Advertise response.  */

        /* Allocate a response packet.  */
        status =  nx_packet_allocate(&pool_0, &response_packet, NX_RECEIVE_PACKET, TX_WAIT_FOREVER);
    
        /* Check status.  */
        if (status)
        {
            error_counter++;

            /* Relase the packet.  */
            nx_packet_release(packet_ptr);
            return(NX_FALSE);
        }

        response_packet -> nx_packet_prepend_ptr += 2;
        response_packet -> nx_packet_append_ptr += 2;

        /* Write the DHCPv6 Server response messages into the packet payload!  */
        status = nx_packet_data_append(response_packet, pkt2, sizeof(pkt2), &pool_0, NX_NO_WAIT);

        /* Check status.  */
        if (status)
        {
            error_counter++;
            nx_packet_release(packet_ptr);
            nx_packet_release(response_packet);
            return(NX_FALSE);
        }

        /* Set the packet version.  */
        response_packet -> nx_packet_ip_version = NX_IP_VERSION_V6;

        /* Set the IP header pointer.  */
        response_packet -> nx_packet_ip_header = response_packet -> nx_packet_prepend_ptr + 14;        
        ip_header = (NX_IPV6_HEADER *)(response_packet -> nx_packet_ip_header);
        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_source_ip);
        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_destination_ip);

        /* Update the data pointer UDP + DHCPv6 message.  */
        response_packet -> nx_packet_prepend_ptr += 54;
        response_packet -> nx_packet_length -= 54;

        /* Set the packet interface.  */
        response_packet -> nx_packet_address.nx_packet_ipv6_address_ptr = &ip_0.nx_ipv6_address[0];

        dhcp_client.nx_dhcpv6_message_hdr.nx_message_xid = 0xdc5d45;

        /* Receive the DHCPv6 Server response.  */
        _nx_udp_packet_receive(ip_ptr, response_packet);

    }
    else if((received_message_type == NX_DHCPV6_MESSAGE_TYPE_REQUEST) && (request == NX_FALSE))
    {

        /* Skip the DHCPv6 header. Type and Transaction ID.  */
        packet_ptr -> nx_packet_prepend_ptr += 4;

        /* Skip the Client Identifier.  */
        packet_ptr -> nx_packet_prepend_ptr += 18;

        /* Skip the Elapsed time.  */
        packet_ptr -> nx_packet_prepend_ptr += 6;

        /* Extract the server identifier.  */
        _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr, 2, &server_identifier);
        _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 2, 2, &server_identifier_length);
        _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 4, 2, &server_duid_type);
        _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 6, 2, &server_hardware_type);
        _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 8, 2, &server_msw);
        _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 10, 4, &server_lsw);

        /* Check the server identifier.  */
        if ((server_identifier == 2) && (server_identifier_length == 10) &&
            (server_duid_type == 3) && (server_hardware_type == 1) &&
            (server_msw == 0x0000ec08) && (server_lsw == 0x6b9370de))
            request = NX_TRUE;
    }

    /* Relase the packet.  */
    nx_packet_release(packet_ptr);

    return(NX_FALSE);   
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcpv6_client_process_server_duid_test_application_define(void * first_unused_memory)
#endif
{
    printf("NetX Test:   DHCPv6 Client Process Server Duid Test....................N/A\n");
    test_control_return(3);
}
#endif
