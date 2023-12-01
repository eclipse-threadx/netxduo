/* This NetX test concentrates on the basic DNS operation. Unencode invalid string.  */

/* Frame (125 bytes) */
static unsigned char invalid_ptr_response_0[125] = {
0xf4, 0x8e, 0x38, 0xa3, 0xab, 0xf6, 0x8c, 0xec, /* ..8..... */
0x4b, 0x68, 0xd1, 0xfe, 0x08, 0x00, 0x45, 0x00, /* Kh....E. */
0x00, 0x6f, 0x1a, 0x9a, 0x40, 0x00, 0x40, 0x11, /* .o..@.@. */
0xd6, 0x2e, 0xc0, 0xa8, 0x64, 0x02, 0xc0, 0xa8, /* ....d... */
0x64, 0x62, 0x00, 0x35, 0xef, 0x67, 0x00, 0x5b, /* db.5.g.[ */
0x7e, 0xb5, 0x00, 0x02, 0x81, 0x80, 0x00, 0x01, /* ~....... */
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31, /* .......1 */
0x34, 0x03, 0x32, 0x30, 0x33, 0x02, 0x35, 0x38, /* 4.203.58 */
0x03, 0x32, 0x31, 0x36, 0x07, 0x69, 0x6e, 0x2d, /* .216.in- */
0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, /* addr.arp */
0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x02, 0x31, /* a......1 */
0x34, 0x03, 0x32, 0x30, 0x33, 0x02, 0x35, 0x38, /* 4.203.58 */
0x03, 0x32, 0x31, 0x36, 0x07, 0x69, 0x6e, 0x2d, /* .216.in- */
0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, /* addr.arp */
0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, /* a....... */
0x95, 0x04, 0x00, 0x01, 0x00                    /* ..... */
};

/* Frame-2 (128 bytes) */
static unsigned char invalid_ptr_response_1[128] = {
0xf4, 0x8e, 0x38, 0xa3, 0xab, 0xf6, 0x8c, 0xec, /* ..8..... */
0x4b, 0x68, 0xd1, 0xfe, 0x08, 0x00, 0x45, 0x00, /* Kh....E. */
0x00, 0x6f, 0x1a, 0x9a, 0x40, 0x00, 0x40, 0x11, /* .o..@.@. */
0xd6, 0x2e, 0xc0, 0xa8, 0x64, 0x02, 0xc0, 0xa8, /* ....d... */
0x64, 0x62, 0x00, 0x35, 0xef, 0x67, 0x00, 0x5b, /* db.5.g.[ */
0x7e, 0xb5, 0x00, 0x02, 0x81, 0x80, 0x00, 0x01, /* ~....... */
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31, /* .......1 */
0x34, 0x03, 0x32, 0x30, 0x33, 0x02, 0x35, 0x38, /* 4.203.58 */
0x03, 0x32, 0x31, 0x36, 0x07, 0x69, 0x6e, 0x2d, /* .216.in- */
0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, /* addr.arp */
0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x02, 0x31, /* a......1 */
0x34, 0x03, 0x32, 0x30, 0x33, 0x02, 0x35, 0x38, /* 4.203.58 */
0x03, 0x32, 0x31, 0x36, 0x07, 0x69, 0x6e, 0x2d, /* .216.in- */
0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, /* addr.arp */
0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, /* a....... */
0x95, 0x04, 0x00, 0x01, 0xc0, 0x54, 0xc0, 0x52                    /* ..... */
};

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

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);

#define        DNS_START_OFFSET (14 + 20 + 8)

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_invalid_name_unencode_test_application_define(void *first_unused_memory)
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

UCHAR       host_name[300];
UINT        i; 

    /* Print out some test information banners.  */
    printf("NetX Test:   DNS Invalid Name Unencode Test............................");

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

    host_name[0] = '.';
    host_name[1] = '.';
    host_name[2] = '.';
    host_name[3] = '.';

    for (i = 0; i < 2; i++) {
        /* Send DNS PTR query, response invalid name. */
        status = nx_dns_host_by_address_get(&client_dns, IP_ADDRESS(216, 58, 203, 14), &host_name[4], 256, NX_IP_PERIODIC_RATE);

        /* Sleep 1s to check if crash.  */
        tx_thread_sleep(NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if(status == NX_SUCCESS)
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
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}


static void    thread_1_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        port;
USHORT      nx_dns_transmit_id;
UCHAR       *data_ptr;
NX_PACKET   *response_packet[2];
UINT        i;
UCHAR       *invalid_ptr_response;
UINT        response_len;

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
    for (i = 0; i < 2; i++)
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
        data_ptr = my_packet -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
        nx_dns_transmit_id = *data_ptr++;
        nx_dns_transmit_id = (USHORT)((nx_dns_transmit_id << 8) | *data_ptr);

        /* Release the packet.  */
        nx_packet_release(my_packet);

        /* Send the DNS response packet.  */
        /* Allocate a response packet.  */
        status =  nx_packet_allocate(&pool_0, &response_packet[i], NX_UDP_PACKET, TX_WAIT_FOREVER);
     
        /* Check status.  */
        if (status)
        {
            error_counter++;
            return;
        }

        if (i == 0)
        {
            invalid_ptr_response = invalid_ptr_response_0;
            response_len = 125;
        } else {
            invalid_ptr_response = invalid_ptr_response_1;
            response_len = 128;
        }
        /* Write the DNS response messages into the packet payload!  */
        memcpy(response_packet[i] -> nx_packet_prepend_ptr, invalid_ptr_response + DNS_START_OFFSET, response_len - DNS_START_OFFSET);

        /* Adjust the write pointer.  */
        response_packet[i] -> nx_packet_length =  response_len - DNS_START_OFFSET;
        response_packet[i] -> nx_packet_append_ptr =  response_packet[i] -> nx_packet_prepend_ptr + response_packet[i] -> nx_packet_length;

        /* Update the DNS transmit ID.  */
        data_ptr = response_packet[i] -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
        *data_ptr++ = (UCHAR)(nx_dns_transmit_id >> 8);
        *data_ptr = (UCHAR)nx_dns_transmit_id;

        /* Send the UDP packet with the correct port.  */
        status =  nx_udp_socket_send(&server_socket, response_packet[i], IP_ADDRESS(192, 168, 100, 98), port);

        /* Check the status.  */
        if (status)
        {
            error_counter++; 
            nx_packet_release(response_packet[i]);
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
void    netx_dns_invalid_name_unencode_test_application_define(void *first_unused_memory)
#endif

{

    /* Print out test information banner.  */
    printf("NetX Test:   DNS Invalid Name Unencode Test............................N/A\n");
    test_control_return(3);

}
#endif
