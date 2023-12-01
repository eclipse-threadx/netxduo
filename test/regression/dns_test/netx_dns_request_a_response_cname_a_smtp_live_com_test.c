/* This NetX test concentrates on the basic DNS operation. Request: smtp.live.com  A, Response: CNAME + A*/

/*
Frame 4: 294 bytes on wire (2352 bits), 294 bytes captured (2352 bits) on interface 0
Ethernet II, Src: IntelCor_0e:3d:f4 (00:1b:21:0e:3d:f4), Dst: Lantroni_98:00:26 (00:80:a3:98:00:26)
Internet Protocol Version 4, Src: 172.19.1.1, Dst: 172.19.100.172
User Datagram Protocol, Src Port: 53 (53), Dst Port: 30005 (30005)
Domain Name System (response)
    [Request In: 3]
    [Time: 0.000331000 seconds]
    Transaction ID: 0x486a
    Flags: 0x8180 Standard query response, No error
    Questions: 1
    Answer RRs: 2
    Authority RRs: 4
    Additional RRs: 4
    Queries
        smtp.live.com: type A, class IN
    Answers
        smtp.live.com: type CNAME, class IN, cname smtp.glbdns2.microsoft.com
            Name: smtp.live.com
            Type: CNAME (Canonical NAME for an alias) (5)
            Class: IN (0x0001)
            Time to live: 3000
            Data length: 25
            CNAME: smtp.glbdns2.microsoft.com
        smtp.glbdns2.microsoft.com: type A, class IN, addr 65.55.163.152
            Name: smtp.glbdns2.microsoft.com
            Type: A (Host Address) (1)
            Class: IN (0x0001)
            Time to live: 16
            Data length: 4
            Address: 65.55.163.152
    Authoritative nameservers
        microsoft.com: type NS, class IN, ns ns3.msft.net
        microsoft.com: type NS, class IN, ns ns4.msft.net
        microsoft.com: type NS, class IN, ns ns1.msft.net
        microsoft.com: type NS, class IN, ns ns2.msft.net
    Additional records
        ns2.msft.net: type A, class IN, addr 208.84.2.53
        ns2.msft.net: type AAAA, class IN, addr 2620:0:32::53
        ns4.msft.net: type A, class IN, addr 208.76.45.53
        ns4.msft.net: type AAAA, class IN, addr 2620:0:37::53

*/

/* Frame (294 bytes) */
char response_cname_a[294] = {
0x00, 0x80, 0xa3, 0x98, 0x00, 0x26, 0x00, 0x1b, /* .....&.. */
0x21, 0x0e, 0x3d, 0xf4, 0x08, 0x00, 0x45, 0x00, /* !.=...E. */
0x01, 0x18, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, /* ....@.@. */
0x7c, 0x01, 0xac, 0x13, 0x01, 0x01, 0xac, 0x13, /* |....... */
0x64, 0xac, 0x00, 0x35, 0x75, 0x35, 0x01, 0x04, /* d..5u5.. */
0xdc, 0xb6, 0x48, 0x6a, 0x81, 0x80, 0x00, 0x01, /* ..Hj.... */
0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x04, 0x73, /* .......s */
0x6d, 0x74, 0x70, 0x04, 0x6c, 0x69, 0x76, 0x65, /* mtp.live */
0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, /* .com.... */
0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, /* ........ */
0x00, 0x0b, 0xb8, 0x00, 0x19, 0x04, 0x73, 0x6d, /* ......sm */
0x74, 0x70, 0x07, 0x67, 0x6c, 0x62, 0x64, 0x6e, /* tp.glbdn */
0x73, 0x32, 0x09, 0x6d, 0x69, 0x63, 0x72, 0x6f, /* s2.micro */
0x73, 0x6f, 0x66, 0x74, 0xc0, 0x16, 0xc0, 0x2b, /* soft...+ */
0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, /* ........ */
0x00, 0x04, 0x41, 0x37, 0xa3, 0x98, 0xc0, 0x38, /* ..A7...8 */
0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x28, 0x8b, /* ......(. */
0x00, 0x0e, 0x03, 0x6e, 0x73, 0x33, 0x04, 0x6d, /* ...ns3.m */
0x73, 0x66, 0x74, 0x03, 0x6e, 0x65, 0x74, 0x00, /* sft.net. */
0xc0, 0x38, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, /* .8...... */
0x28, 0x8b, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, /* (....ns4 */
0xc0, 0x64, 0xc0, 0x38, 0x00, 0x02, 0x00, 0x01, /* .d.8.... */
0x00, 0x00, 0x28, 0x8b, 0x00, 0x06, 0x03, 0x6e, /* ..(....n */
0x73, 0x31, 0xc0, 0x64, 0xc0, 0x38, 0x00, 0x02, /* s1.d.8.. */
0x00, 0x01, 0x00, 0x00, 0x28, 0x8b, 0x00, 0x06, /* ....(... */
0x03, 0x6e, 0x73, 0x32, 0xc0, 0x64, 0xc0, 0x9e, /* .ns2.d.. */
0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x63, 0x63, /* ......cc */
0x00, 0x04, 0xd0, 0x54, 0x02, 0x35, 0xc0, 0x9e, /* ...T.5.. */
0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x63, 0x63, /* ......cc */
0x00, 0x10, 0x26, 0x20, 0x00, 0x00, 0x00, 0x32, /* ..& ...2 */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x53, 0xc0, 0x7a, 0x00, 0x01, 0x00, 0x01, /* .S.z.... */
0x00, 0x00, 0x1d, 0x92, 0x00, 0x04, 0xd0, 0x4c, /* .......L */
0x2d, 0x35, 0xc0, 0x7a, 0x00, 0x1c, 0x00, 0x01, /* -5.z.... */
0x00, 0x00, 0x1d, 0x92, 0x00, 0x10, 0x26, 0x20, /* ......&  */
0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, /* ...7.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x53              /* .....S */
};

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_udp.h"
#include   "nxd_dns.h"
#include   "nx_ram_network_driver_test_1500.h"
                                
extern void    test_control_return(UINT status);
#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   client_ip;
static NX_IP                   server_ip;


static NX_UDP_SOCKET           server_socket;

static NX_DNS                  client_dns;

#define DNS_SERVER_ADDRESS     IP_ADDRESS(172,19,1,1)  

#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL   
NX_PACKET_POOL                 client_pool;
#endif

/* Define the counters used in the demo application...  */

static UINT                    status;
static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);

#define        DNS_START_OFFSET (14 + 20 + 8)

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_request_a_response_cname_a_smtp_live_com_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    
    /* Create the DNS main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* .  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1500, pointer, 8192);
    pointer = pointer + 8192;
        
#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL   

    /* Create the packet pool for the DNS Client to send packets. 

        If the DNS Client is configured for letting the host application create 
        the DNS packet pool, (see NX_DNS_CLIENT_USER_CREATE_PACKET_POOL option), see
       nx_dns_create() for guidelines on packet payload size and pool size. 
       packet traffic for NetX Duo processes. 
    */
    status =  nx_packet_pool_create(&client_pool, "DNS Client Packet Pool", NX_DNS_PACKET_PAYLOAD, pointer, NX_DNS_PACKET_POOL_SIZE);

    pointer = pointer + NX_DNS_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        return;
#endif

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip, "NetX IP Instance 0", IP_ADDRESS(172, 19, 100, 172), 0xFFFF0000UL, &pool_0, _nx_ram_network_driver_512,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&server_ip, "NetX IP Instance 1", IP_ADDRESS(172, 19, 1, 1), 0xFFFF0000UL, &pool_0, _nx_ram_network_driver_512,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&client_ip);
    status += nx_udp_enable(&server_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

NXD_ADDRESS ip_address;

    /* Test the A type with the new API,(google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS Request A Response CNAME+A smtp.live.com Test.........");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a DNS instance for the Client.  Note this function will create
       the DNS Client packet pool for creating DNS message packets intended
       for querying its DNS server. */
    status =  nx_dns_create(&client_dns, &client_ip, (UCHAR *)"DNS Client");

    /* Check status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
        
    /* Is the DNS client configured for the host application to create the pecket pool? */
#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL   

    /* Yes, use the packet pool created above which has appropriate payload size
       for DNS messages. */
     status = nx_dns_packet_pool_set(&client_dns, &client_pool);

     /* Check for set DNS packet pool error.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#endif /* NX_DNS_CLIENT_USER_CREATE_PACKET_POOL */    

    /* Add an IPv4 server address to the Client list. */
    status = nx_dns_server_add(&client_dns, DNS_SERVER_ADDRESS);

    /* Check status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Secd dns query, and record the single host ip address. */
    status = nxd_dns_host_by_name_get(&client_dns, (UCHAR *)"smtp.live.com", &ip_address, 4 * NX_IP_PERIODIC_RATE, NX_IP_VERSION_V4);
    
    /* Check status and compare the host ip address.  */
    if (status || (ip_address.nxd_ip_address.v4 != IP_ADDRESS(65, 55, 163, 152)))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

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


static void    thread_1_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        port;
USHORT      nx_dns_transmit_id;
UCHAR       *data_ptr;
NX_PACKET   *response_packet;

    /* Create a UDP socket act as the DNS server.  */
    status = nx_udp_socket_create(&server_ip, &server_socket, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&server_socket, 53, TX_WAIT_FOREVER);

    /* Act as the DNS server to receive the DNS query and send the DNS response.  */

        /* Receive a UDP packet.  */
    status = nx_udp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    /* Get the DNS client UDP port.  */
    status = nx_udp_packet_info_extract(my_packet, NX_NULL, NX_NULL, &port, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    /* Get the DNS transmit ID.  */
    data_ptr = my_packet -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
    nx_dns_transmit_id = *data_ptr++;
    nx_dns_transmit_id = (USHORT)((nx_dns_transmit_id << 8) | *data_ptr);

    /* Release the packet.  */
    nx_packet_release(my_packet);

    /* Send the DNS response packet.  */
    
    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&pool_0, &response_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    /* Write the DNS response messages into the packet payload!  */
    memcpy(response_packet -> nx_packet_prepend_ptr, response_cname_a + DNS_START_OFFSET, sizeof(response_cname_a) - DNS_START_OFFSET);

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length =  sizeof(response_cname_a) - DNS_START_OFFSET;
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

    /* Update the DNS transmit ID.  */
    data_ptr = response_packet -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
    *data_ptr++ = (UCHAR)(nx_dns_transmit_id >> 8);
    *data_ptr = (UCHAR)nx_dns_transmit_id;

    /* Send the UDP packet with the correct port.  */
    status =  nx_udp_socket_send(&server_socket, response_packet, IP_ADDRESS(172, 19, 100, 172), port);

    /* Check the status.  */
    if (status)
    {
        error_counter++; 
        nx_packet_release(response_packet);
        return;
    }

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&server_socket);

    /* Check status.  */
    if (status)
    {        
        error_counter++;   
        return;
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&server_socket);

    /* Check status.  */
    if (status)
    {        
        error_counter++;
        return;
    }
    
    /* Let the DNS threads execute.    */
    tx_thread_relinquish();
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_request_a_response_cname_a_smtp_live_com_test_application_define(void *first_unused_memory)
#endif

{

    /* Print out test information banner.  */
    printf("NetX Test:   DNS Request A Response CNAME+A smtp.live.com Test.........N/A\n");
    test_control_return(3);

}
#endif
