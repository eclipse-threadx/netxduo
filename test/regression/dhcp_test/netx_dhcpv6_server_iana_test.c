/* Verify DHCPv6 Server can correctly process IANA option in DHCPv6 Solicit message.  */

/*  Procedure
    1.Memset the packet pool.
    2.Create DHCPv6 Server.
    3.Inject DHCPv6 Solicit message.
    4.Check if receive DHCPv6 Advertise message from DHCPv6 Server.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6
#include   "nxd_dhcpv6_server.h"


#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               server_thread;
static NX_PACKET_POOL          server_pool;
static NX_IP                   server_ip;
static NX_DHCPV6_SERVER        dhcp_server;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static UCHAR                   advertise_message_count = 0;
static CHAR                    *pointer;  

/* Define thread prototypes.  */

static void    server_thread_entry(ULONG thread_input);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);  
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
                                 
/* Define some DHCPv6 parameters.  */

#define DHCPV6_IANA_ID                  0xC0DEDBAD 
#define DHCPV6_T1                       NX_DHCPV6_INFINITE_LEASE 
#define DHCPV6_T2                       NX_DHCPV6_INFINITE_LEASE 
#define NX_DHCPV6_REFERRED_LIFETIME     NX_DHCPV6_INFINITE_LEASE
#define NX_DHCPV6_VALID_LIFETIME        NX_DHCPV6_INFINITE_LEASE
                                                               
static NXD_ADDRESS             server_address; 
static NXD_ADDRESS             dns_ipv6_address;
static NXD_ADDRESS             start_ipv6_address;
static NXD_ADDRESS             end_ipv6_address;             
static ULONG                   client_address[4];
static CHAR                    mac[6];


/* Frame (342 bytes)  DHCPv6 Solicit, IANA is filled in the last option.  */
static const unsigned char pkt1[118] = {
0x33, 0x33, 0x00, 0x01, 0x00, 0x02, 0x08, 0x00, /* 33...... */
0x27, 0xdf, 0x0b, 0xb2, 0x86, 0xdd, 0x60, 0x0c, /* '.....`. */
0x28, 0xf6, 0x00, 0x40, 0x11, 0x01, 0xfe, 0x80, /* (..@.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, /* ........ */
0x27, 0xff, 0xfe, 0xdf, 0x0b, 0xb2, 0xff, 0x02, /* '....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x02, 0x22, /* ......." */
0x02, 0x23, 0x00, 0x40, 0xb2, 0x37, 0x01, 0xdd, /* .#.@.7.. */
0xf3, 0x3a, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, /* .:...... */
0x00, 0x01, 0x20, 0xec, 0x65, 0xde, 0x08, 0x00, /* .. .e... */
0x27, 0xdf, 0x0b, 0xb2, 0x00, 0x06, 0x00, 0x08, /* '....... */
0x00, 0x17, 0x00, 0x18, 0x00, 0x27, 0x00, 0x1f, /* .....'.. */
0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, /* ........ */
0x00, 0x0c, 0x27, 0xdf, 0x0b, 0xb2, 0x00, 0x00, /* ..'..... */
0x0e, 0x10, 0x00, 0x00, 0x15, 0x18              /* ...... */
};


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcpv6_server_iana_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&server_thread, "thread server", server_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();
    
    /* Clear the memory value.  */
    memset(pointer, 0, NX_PACKET_POOL_SIZE);

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;
    
    /* Create an IP instance for the DHCP Server.  */
    status = nx_ip_create(&server_ip, "DHCP Server", IP_ADDRESS(10, 0, 0, 1), 0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1024, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable the IPv6 services. */
    status = nxd_ipv6_enable(&server_ip);
    
    /* Check for IPv6 enable errors.  */
    if (status)
    {
        error_counter++;
    }

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&server_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nxd_icmp_enable(&server_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    return;
}

/* Define the test threads.  */

void    server_thread_entry(ULONG thread_input)
{

UINT        status;
ULONG       duid_time;
UINT        addresses_added;
NX_PACKET   *my_packet;

    printf("NetX Test:   NetX DHCPv6 Server IANA Test..............................");

    /* Set the IPv6 address of DHCPv6 Server.  */
    server_address.nxd_ip_version = NX_IP_VERSION_V6 ;
    server_address.nxd_ip_address.v6[0] = 0x20010db8;
    server_address.nxd_ip_address.v6[1] = 0xf101;
    server_address.nxd_ip_address.v6[2] = 0x00000000;
    server_address.nxd_ip_address.v6[3] = 0x00000101;    

    /* Set the link local and global addresses. */
    status = nxd_ipv6_address_set(&server_ip, 0, NX_NULL, 10, NULL);
    status += nxd_ipv6_address_set(&server_ip, 0, &server_address, 64, NULL);

    /* Check for errors. */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the ND Cache for DHCPv6 Client.  */
    client_address[0] = 0xfe800000;
    client_address[1] = 0x00000000;
    client_address[2] = 0x0a0027ff;
    client_address[3] = 0xfedf0bb2;
    mac[0] = 0x08;                    
    mac[1] = 0x00;
    mac[2] = 0x27;
    mac[3] = 0xdf;
    mac[4] = 0x0b;
    mac[5] = 0xb2;
    status = nxd_nd_cache_entry_set(&server_ip, client_address, 0, mac);

    /* Check for errors. */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Validate the link local and global addresses. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Create the DHCPv6 Server. */
    status =  nx_dhcpv6_server_create(&dhcp_server, &server_ip, "DHCPv6 Server", &server_pool, pointer, 2048, NX_NULL, NX_NULL);
    pointer += 2048;

    /* Check for errors.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set up the DNS IPv6 server address. */
    dns_ipv6_address.nxd_ip_version = NX_IP_VERSION_V6 ;
    dns_ipv6_address.nxd_ip_address.v6[0] = 0x20010db8;
    dns_ipv6_address.nxd_ip_address.v6[1] = 0x0000f101;
    dns_ipv6_address.nxd_ip_address.v6[2] = 0x00000000;
    dns_ipv6_address.nxd_ip_address.v6[3] = 0x00000107;

    status = nx_dhcpv6_create_dns_address(&dhcp_server, &dns_ipv6_address);

    /* Check for errors. */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

     /* Note: For DUID types that do not require time, the 'duid_time' input can be left at zero. 
        The DUID_TYPE and HW_TYPE are configurable options that are user defined in nx_dhcpv6_server.h.  */

    /* Set the DUID time as the start of the millenium. */
    duid_time = SECONDS_SINCE_JAN_1_2000_MOD_32;
    status = nx_dhcpv6_set_server_duid(&dhcp_server,
                                    NX_DHCPV6_SERVER_DUID_TYPE, NX_DHCPV6_SERVER_HW_TYPE,
                                    dhcp_server.nx_dhcpv6_ip_ptr -> nx_ip_arp_physical_address_msw,
                                    dhcp_server.nx_dhcpv6_ip_ptr -> nx_ip_arp_physical_address_lsw,
                                    duid_time);

    /* Check for errors. */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the IPv6 start address.  */
    start_ipv6_address.nxd_ip_version = NX_IP_VERSION_V6 ;
    start_ipv6_address.nxd_ip_address.v6[0] = 0x20010db8;
    start_ipv6_address.nxd_ip_address.v6[1] = 0x00000f101;
    start_ipv6_address.nxd_ip_address.v6[2] = 0x0;
    start_ipv6_address.nxd_ip_address.v6[3] = 0x00000110;    

    /* Set the IPv6 end address.  */
    end_ipv6_address.nxd_ip_version = NX_IP_VERSION_V6 ;
    end_ipv6_address.nxd_ip_address.v6[0] = 0x20010db8;
    end_ipv6_address.nxd_ip_address.v6[1] = 0x0000f101;
    end_ipv6_address.nxd_ip_address.v6[2] = 0x00000000;
    end_ipv6_address.nxd_ip_address.v6[3] = 0x00000120;  

    /* Set the IPv6 address range.  */
    status = nx_dhcpv6_create_ip_address_range(&dhcp_server, &start_ipv6_address, &end_ipv6_address, &addresses_added);

    /* Check for errors. */
    if ((status) || (addresses_added != 16))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Start the NetX DHCPv6 server!  */
    status =  nx_dhcpv6_server_start(&dhcp_server);

    /* Check for errors. */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the DHCP DISCOVER packet.  */  
    status = nx_packet_allocate(&server_pool, &my_packet, NX_UDP_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Set the callback function to process the Message packet from DHCPv6 Server.  */
    advanced_packet_process_callback = my_packet_process;    

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    my_packet -> nx_packet_length = sizeof(pkt1) - 14;
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + sizeof(pkt1) - 14;

    /* Directly receive the DHCP DISCOVER packet.  */
    _nx_ip_packet_deferred_receive(&server_ip, my_packet);

    /* Check if receive the advertise message.  */
    if (advertise_message_count != 1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Output successfully.  */
    printf("SUCCESS!\n");
    test_control_return(0);

    return;
}


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UCHAR       message_type;


    /* Check the IP.  */
    if (ip_ptr == &server_ip)
    {

        /* Get the message type.  */
        message_type = *(packet_ptr -> nx_packet_prepend_ptr + 40 + 8);

        /* Check if it is Advertise message from DHCPv6 Server.  */
        if (message_type == NX_DHCPV6_MESSAGE_TYPE_ADVERTISE)
        {

            /* Yes, receive the advertise message.  */
            advertise_message_count ++;
        }
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcpv6_server_iana_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NetX DHCPv6 Server IANA Test..............................N/A\n"); 

    test_control_return(3);  
}      
#endif