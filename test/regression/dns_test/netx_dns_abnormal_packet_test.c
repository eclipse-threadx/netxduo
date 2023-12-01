/* This NetX test reading overflow when processing abnormal packet.  */

/* Invalid name string */
static unsigned char invalid_response_0[] = {
0x1C, 0x1A, 0xDF, 0xB0, 0x2F, 0x0A, 0x74, 0xB6, 
0xB6, 0x40, 0x93, 0x2D, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x69, 0x72, 0x5D, 0x00, 0x00, 0x40, 0x11, 
0x80, 0xA6, 0xC0, 0xA8, 0x01, 0xFE, 0xC0, 0xA8, 
0x04, 0x32, 0x00, 0x35, 0xC8, 0xE1, 0x00, 0x55, 
0x4C, 0x59, 0x88, 0xCC, 0x81, 0x80, 0x00, 0x01, 
0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x63, 
0x6C, 0x69, 0x65, 0x6E, 0x74, 0x73, 0x34, 0x06, 
0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 
0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 
0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 
0xC3, 0x00, 0x0C, 0x37, 0x63, 0x6C, 0x69, 0x65, 
0x6E, 0x74, 0x73, 0x01, 0x6C, 0xC0, 0x15, 0xC0, 
0x31, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 
0x2C, 0x00, 0x04, 0xAC, 0xD9, 0x03, 0xCE
};

/* Invalid name string */
static unsigned char invalid_response_1[] = {
0x1C, 0x1A, 0xDF, 0xB0, 0x2F, 0x0A, 0x74, 0xB6, 
0xB6, 0x40, 0x93, 0x2D, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x69, 0x72, 0x5D, 0x00, 0x00, 0x40, 0x11, 
0x80, 0xA6, 0xC0, 0xA8, 0x01, 0xFE, 0xC0, 0xA8, 
0x04, 0x32, 0x00, 0x35, 0xC8, 0xE1, 0x00, 0x55, 
0x4C, 0x59, 0x88, 0xCC, 0x81, 0x80, 0x00, 0x01, 
0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x63, 
0x6C, 0x69, 0x65, 0x6E, 0x74, 0x73, 0x34, 0x06, 
0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 
0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 
0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 
0xC3, 0x00, 0x0C, 0x37, 0x63, 0x6C, 0x69, 0x65, 
0x6E, 0x74, 0x73, 0x01, 0x6C, 0xC0, 0x15, 0xC0, 
0x4C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 
0x2C, 0x00, 0x04, 0xAC, 0xD9, 0x03, 0xC0
};

/* Invalid name string */
static unsigned char invalid_response_2[] = {
0x1C, 0x1A, 0xDF, 0xB0, 0x2F, 0x0A, 0x74, 0xB6, 
0xB6, 0x40, 0x93, 0x2D, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x69, 0x72, 0x5D, 0x00, 0x00, 0x40, 0x11, 
0x80, 0xA6, 0xC0, 0xA8, 0x01, 0xFE, 0xC0, 0xA8, 
0x04, 0x32, 0x00, 0x35, 0xC8, 0xE1, 0x00, 0x55, 
0x4C, 0x59, 0x88, 0xCC, 0x81, 0x80, 0x00, 0x01, 
0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x63, 
0x6C, 0x69, 0x65, 0x6E, 0x74, 0x73, 0x34, 0x06, 
0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 
0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 
0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 
0xC3, 0x00, 0x0C, 0x37, 0x63, 0x6C, 0x69, 0x65, 
0x6E, 0x74, 0x73, 0x01, 0x6C, 0xC0, 0x15, 0xC0, 
0x4B, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 
0x2C, 0x00, 0x04, 0xAC, 0xD9, 0x01, 0x01
};

/* Invalid IP address */
static unsigned char invalid_response_3[] =
{
0x1C, 0x1A, 0xDF, 0xB0, 0x2F, 0x0A, 0x74, 0xB6, 
0xB6, 0x40, 0x93, 0x2D, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x69, 0x72, 0x5D, 0x00, 0x00, 0x40, 0x11, 
0x80, 0xA6, 0xC0, 0xA8, 0x01, 0xFE, 0xC0, 0xA8, 
0x04, 0x32, 0x00, 0x35, 0xC8, 0xE1, 0x00, 0x55, 
0x4C, 0x59, 0x88, 0xCC, 0x81, 0x80, 0x00, 0x01, 
0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x63, 
0x6C, 0x69, 0x65, 0x6E, 0x74, 0x73, 0x34, 0x06, 
0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 
0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 
0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 
0xC3, 0x00, 0x0C, 0x07, 0x63, 0x6C, 0x69, 0x65, 
0x6E, 0x74, 0x73, 0x01, 0x6C, 0xC0, 0x15, 0xC0, 
0x31, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 
0x2C, 0x00, 0x04, 0xAC, 0xD9, 0x03
};

/* Valid response */
static unsigned char valid_response[] =
{
0x1C, 0x1A, 0xDF, 0xB0, 0x2F, 0x0A, 0x74, 0xB6, 
0xB6, 0x40, 0x93, 0x2D, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x69, 0x72, 0x5D, 0x00, 0x00, 0x40, 0x11, 
0x80, 0xA6, 0xC0, 0xA8, 0x01, 0xFE, 0xC0, 0xA8, 
0x04, 0x32, 0x00, 0x35, 0xC8, 0xE1, 0x00, 0x55, 
0x4C, 0x59, 0x88, 0xCC, 0x81, 0x80, 0x00, 0x01, 
0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x63, 
0x6C, 0x69, 0x65, 0x6E, 0x74, 0x73, 0x34, 0x06, 
0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 
0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 
0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 
0xC3, 0x00, 0x0C, 0x07, 0x63, 0x6C, 0x69, 0x65, 
0x6E, 0x74, 0x73, 0x01, 0x6C, 0xC0, 0x15, 0xC0, 
0x31, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 
0x2C, 0x00, 0x04, 0xAC, 0xD9, 0x03, 0xCE
};

static unsigned char invalid_response_txt[] = 
{
0x18, 0x03, 0x73, 0x33, 0xc1, 0xbd, 0xc8, 0x3a, 
0x35, 0x60, 0x4b, 0x46, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x96, 0xc1, 0xa0, 0x00, 0x00, 0x40, 0x11,  
0x36, 0xfc, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 
0x00, 0x69, 0x00, 0x35, 0xc1, 0x8b, 0x00, 0x82, 
0xec, 0x71, 0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 
0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 
0x6d, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 
0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 
0x00, 0x52, 0x52, 0x76, 0x3d, 0x73, 0x70, 0x66, 
0x31, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 
0x65, 0x3a, 0x5f, 0x6e, 0x65, 0x74, 0x62, 0x6c, 
0x6f, 0x63, 0x6b, 0x73, 0x2e, 0x67, 0x6f, 0x6f, 
0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 
0x69, 0x70, 0x34, 0x3a, 0x32, 0x31, 0x36, 0x2e, 
0x37, 0x33, 0x2e, 0x39, 0x33, 0x2e, 0x37, 0x30, 
0x2f, 0x33, 0x31, 0x20, 0x69, 0x70, 0x34, 0x3a, 
0x32, 0x31, 0x36, 0x2e, 0x37, 0x33, 0x2e, 0x39, 
0x33, 0x2e, 0x37, 0x32, 0x2f, 0x33, 0x31, 0x20, 
0x7e, 0x61, 0x6c, 0x6c
};


#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_udp.h"
#include   "nxd_dns.h"
#include   "nx_ram_network_driver_test_1500.h"
                                
extern void    test_control_return(UINT status);
#if !defined(NX_DISABLE_IPV4)

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

static UCHAR                   pool_buffer[8192] = {0};
static UCHAR                   record_buffer[500];

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
void    netx_dns_abnormal_packet_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1500, pool_buffer, 8192);

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
ULONG       host_ip_address;
UINT        i;
UINT        test_num;

    /* Print out some test information banners.  */
    printf("NetX Test:   DNS Abnormal Packet Test..................................");

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

    client_dns.nx_dns_retries = 1;

#ifdef NX_DNS_CACHE_ENABLE
    test_num = 4;
#else
    test_num = 1;
#endif

    for (i = 0; i < test_num; i++)
    {
        status = nx_dns_host_by_name_get(&client_dns, (UCHAR *)"berkeley.edu", &host_ip_address, NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if(status == NX_SUCCESS)
        {
            error_counter++;
        }
    }

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
    status = nx_dns_host_text_get(&client_dns, (UCHAR *)"google.com", &record_buffer[0], sizeof(record_buffer), NX_IP_PERIODIC_RATE); 

    /* Check status.  */
    if(status == NX_SUCCESS)
    {
        error_counter++;
    }
#endif

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
UCHAR       *invalid_responses[] = 
{
#ifdef NX_DNS_CACHE_ENABLE
    invalid_response_0,
    invalid_response_1,
    invalid_response_2,
#endif
    invalid_response_3,
#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
    invalid_response_txt,
#endif
};
UINT       invalid_responses_len[] = 
{
#ifdef NX_DNS_CACHE_ENABLE
    sizeof(invalid_response_0),
    sizeof(invalid_response_1),
    sizeof(invalid_response_2),
#endif
    sizeof(invalid_response_3),
#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
    sizeof(invalid_response_txt),
#endif
};
UCHAR       *response_ptr;
UINT        response_len;
UINT        i;
UINT        test_num = sizeof(invalid_responses_len) / sizeof(UINT);

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

    for (i = 0; i < test_num; i ++)
    {

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
        if (i == 1)
        {
            client_dns.nx_dns_transmit_id = 0xc00c;
            nx_dns_transmit_id = client_dns.nx_dns_transmit_id;
        }
        else
        {
            data_ptr = my_packet -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
            nx_dns_transmit_id = *data_ptr++;
            nx_dns_transmit_id = (USHORT)((nx_dns_transmit_id << 8) | *data_ptr);
        }


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

        response_ptr = invalid_responses[i];
        response_len = invalid_responses_len[i];

        /* Write the DNS response messages into the packet payload!  */
        memcpy(response_packet -> nx_packet_prepend_ptr, response_ptr + DNS_START_OFFSET, response_len - DNS_START_OFFSET);

        /* Adjust the write pointer.  */
        response_packet -> nx_packet_length =  response_len - DNS_START_OFFSET;
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
void    netx_dns_abnormal_packet_test_application_define(void *first_unused_memory)
#endif

{

    /* Print out test information banner.  */
    printf("NetX Test:   DNS Abnormal Packet Test..................................N/A\n");
    test_control_return(3);

}
#endif
