/* This NetX test concentrates on the basic DNS operation. Fake response test.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_udp.h"
#include   "nxd_dns.h"
#include   "nx_ram_network_driver_test_1500.h"
                                
extern void    test_control_return(UINT status);
#ifndef NX_DISABLE_IPV4

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   client_ip;
static NX_IP                   server_ip;

static NX_UDP_SOCKET           server_socket;
static NX_DNS                  client_dns;


#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL   
NX_PACKET_POOL                 client_pool;
#endif

/* Define the counters used in the demo application...  */

static UINT                    status;
static ULONG                   error_counter;
static UINT                    dns_query_port_1 = 0;
static UINT                    dns_query_port_2 = 0;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);

#define        DNS_START_OFFSET (14 + 20 + 8)

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_fake_response_test_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&client_ip, "NetX IP Instance 0", IP_ADDRESS(192, 168, 100, 98), 0xFFFF0000UL, &pool_0, _nx_ram_network_driver_512,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&server_ip, "NetX IP Instance 1", IP_ADDRESS(192, 168, 100, 2), 0xFFFF0000UL, &pool_0, _nx_ram_network_driver_512,
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

UCHAR       record_buffer[64];
UINT        record_count;
ULONG       *ipv4_address_ptr;

    /* Print out some test information banners.  */
    printf("NetX Test:   DNS Fake Response Test....................................");

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
    status = nx_dns_server_add(&client_dns, IP_ADDRESS(192, 168, 100, 2));

    /* Check status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send query.  */
    status = nx_dns_ipv4_address_by_name_get(&client_dns, (UCHAR *)"google.com", &record_buffer[0], 64, &record_count, NX_IP_PERIODIC_RATE);
    ipv4_address_ptr = (ULONG *)record_buffer;

    /* Check status.  */
    if ((status) ||
        (*ipv4_address_ptr != IP_ADDRESS(74,125,224,194)))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Send query again.  */
    status = nx_dns_ipv4_address_by_name_get(&client_dns, (UCHAR *)"google.com", &record_buffer[0], 64, &record_count, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

extern char response_a_google_com_pkt[];
extern int response_a_google_com_pkt_size;
extern char response_a_berkley_edu_pkt[];
extern int response_a_berkley_edu_pkt_size;

static void    thread_1_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        port;
USHORT      nx_dns_transmit_id;
UCHAR       *data_ptr;
NX_PACKET   *response_packet;
UCHAR       *response_data;
UINT        response_data_size;

    /* Create a UDP socket act as the DNS server.  */
    status = nx_udp_socket_create(&server_ip, &server_socket, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&server_socket, 53, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    for (UINT i = 0; i < 2; i++)
    {

        /* Receive a UDP packet.  */
        status = nx_udp_socket_receive(&server_socket, &my_packet, NX_IP_PERIODIC_RATE);

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

        if (i == 0)
        {
            dns_query_port_1 = port;
        }
        else
        {
            dns_query_port_2 = port;
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

        if (i == 0)
        {
            response_data = response_a_google_com_pkt;
            response_data_size = response_a_google_com_pkt_size;
        }
        else
        {
            response_data = response_a_berkley_edu_pkt;
            response_data_size = response_a_berkley_edu_pkt_size;
        }

        /* Write the DNS response messages into the packet payload!  */
        memcpy(response_packet -> nx_packet_prepend_ptr, response_data + DNS_START_OFFSET, response_data_size - DNS_START_OFFSET);

        /* Adjust the write pointer.  */
        response_packet -> nx_packet_length =  response_data_size - DNS_START_OFFSET;
        response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

        /* Update the DNS transmit ID.  */
        data_ptr = response_packet -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
        *data_ptr++ = (UCHAR)(nx_dns_transmit_id >> 8);
        *data_ptr = (UCHAR)nx_dns_transmit_id;

        /* Send the UDP packet with the correct port.  */
        status =  nx_udp_socket_send(&server_socket, response_packet, IP_ADDRESS(192, 168, 100, 98), port);

        /* Check the status.  */
        if (status)
        {
            error_counter++; 
            nx_packet_release(response_packet);
            return;
        }
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
void    netx_dns_fake_response_test_application_define(void *first_unused_memory)
#endif

{

    /* Print out test information banner.  */
    printf("NetX Test:   DNS Fake Response Test....................................N/A\n");
    test_control_return(3);

}
#endif
