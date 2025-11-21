/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_udp.h"
#include   "nxd_dns.h"

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

#define DNS_SERVER_ADDRESS     IP_ADDRESS(10,0,0,1)

#ifdef __PRODUCT_NETXDUO__
static NXD_ADDRESS address_ipv4_0;
static NXD_ADDRESS address_ipv4_1;
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS address_ipv6_0;
static NXD_ADDRESS address_ipv6_1;
#endif
#endif

#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL   
NX_PACKET_POOL                 client_pool;
#endif

/* Define the counters used in the demo application...  */

static UINT                    status;
static ULONG                   error_counter;
static ULONG                   notify_calls =  0;

static UCHAR                   record_buffer[500];
static UINT                    record_count;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    receive_packet_function(NX_UDP_SOCKET *socket_ptr);

/* DNS Tests.  */
static void    dns_test_initialize();
static void    dns_a_type_test();

#ifdef __PRODUCT_NETXDUO__
static void    dns_aaaa_type_test();
#endif /* __PRODUCT_NETXDUO__ */

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
static void    dns_a_cname_type_test();
static void    dns_mx_type_test();
static void    dns_mx_a_type_test();
static void    dns_cname_type_test();
static void    dns_ns_a_type_test();
static void    dns_srv_type_test();
static void    dns_txt_type_test();
static void    dns_soa_type_test();
#endif   

/* DNS retransmit test.  */
static void    dns_retransmit_test();

/* Send DNS response.  */
static UINT    nx_dns_response_packet_send(NX_UDP_SOCKET *server_socket, UINT port, USHORT nx_dns_transmit_id, UINT packet_number);

extern char response_a_google_com_pkt[246];
extern int response_a_google_com_pkt_size;

extern char response_a_berkley_edu_pkt[88];
extern int response_a_berkley_edu_pkt_size;

extern char response_aaaa_berkley_edu_pkt[100];
extern int response_aaaa_berkley_edu_pkt_size;

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES

extern char response_a_cname_www_npr_org_pkt[119];
extern int response_a_cname_www_npr_org_pkt_size;

extern char response_mx_google_com_pkt[178];
extern int response_mx_google_com_pkt_size;

extern char response_mx_a_google_com_pkt[258];
extern int response_mx_a_google_com_pkt_size;

extern char response_mx_a_berkley_edu_pkt[107];
extern int response_mx_a_berkley_edu_pkt_size;

extern char response_cname_www_baidu_com_pkt[100];
extern int response_cname_www_baidu_com_pkt_size;

extern char response_ns_a_ti_com_pkt[349];
extern int response_ns_a_ti_com_pkt_size;

extern char response_srv_google_com_pkt[373];
extern int response_srv_google_com_pkt_size;

extern char response_txt_google_com_pkt[373];
extern int response_txt_google_com_pkt_size;

extern char response_soa_google_com_pkt[120];
extern int response_soa_google_com_pkt_size;

#endif

typedef struct DNS_TEST_STRUCT
{
    char          *dns_test_pkt_data;
    int           dns_test_pkt_size;
} DNS_TEST;

#define test_count    19
static DNS_TEST       dns_test[test_count];

extern ULONG test_control_successful_tests;
extern ULONG test_control_failed_tests;

#define        DNS_START_OFFSET (14 + 20 + 8)

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_function_test_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&client_ip, "NetX IP Instance 0", IP_ADDRESS(10, 0, 0, 10), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&server_ip, "NetX IP Instance 1", IP_ADDRESS(10, 0, 0, 1), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
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
            
    /* Create a DNS instance for the Client.  Note this function will create
       the DNS Client packet pool for creating DNS message packets intended
       for querying its DNS server. */
    status =  nx_dns_create(&client_dns, &client_ip, (UCHAR *)"DNS Client");
        
    /* Is the DNS client configured for the host application to create the pecket pool? */
#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL   

    /* Yes, use the packet pool created above which has appropriate payload size
       for DNS messages. */
     status = nx_dns_packet_pool_set(&client_dns, &client_pool);

     /* Check for set DNS packet pool error.  */
    if (status)
    {
        error_counter++;
    }

#endif /* NX_DNS_CLIENT_USER_CREATE_PACKET_POOL */    

    /* Add a then remove ipv4 DNS servers, check for max entries as well */
    for (int i = 0; i < (NX_DNS_MAX_SERVERS); i++)
    {
        status = nx_dns_server_add(&client_dns, IP_ADDRESS(10,1,1,i));    
        if (status)
        {
            error_counter++;
        }
    }

    status = nx_dns_server_add(&client_dns, IP_ADDRESS(10,1,1,NX_DNS_MAX_SERVERS));
    if (status != NX_NO_MORE_ENTRIES)
    {
        error_counter++;
    }

    /* check size when we are at max entries.  */
    UINT size = 0;
    status = nx_dns_get_serverlist_size(&client_dns, &size);
    if (status != NX_SUCCESS || size != 5)
    {
        error_counter++;
    }

    for (int i = 0; i < (NX_DNS_MAX_SERVERS); i++)
    {
        status = nx_dns_server_remove(&client_dns, IP_ADDRESS(10,1,1,i));    
        if (status)
        {
            error_counter++;
        }
    }

#ifdef __PRODUCT_NETXDUO__
    /* Add one IPv4 server address.  */
    address_ipv4_0.nxd_ip_address.v4 = IP_ADDRESS(1,1,1,1);
    address_ipv4_0.nxd_ip_version = NX_IP_VERSION_V4;
    status = nxd_dns_server_add(&client_dns,&address_ipv4_0);
    if (status)
    {
        error_counter++;
    }

    /* Add an other IPv4 server address to the Client list. */
    address_ipv4_1.nxd_ip_address.v4 = IP_ADDRESS(10,1,1,1);
    address_ipv4_1.nxd_ip_version = NX_IP_VERSION_V4;
    status = nxd_dns_server_add(&client_dns, &address_ipv4_1);    
    if (status)
    {
        error_counter++;
    }

#ifdef FEATURE_NX_IPV6
    /* Add one IPv6 server address.  */
    address_ipv6_0.nxd_ip_address.v6[0] = 13;
    address_ipv6_0.nxd_ip_address.v6[1] = 13;
    address_ipv6_0.nxd_ip_address.v6[2] = 13;
    address_ipv6_0.nxd_ip_address.v6[3] = 13;
    address_ipv6_0.nxd_ip_version = NX_IP_VERSION_V6;
    status = nxd_dns_server_add(&client_dns, &address_ipv6_0);
    if (status)
    {
        error_counter++;
    }

    /* Add an other IPv6 server address to the Client list. */
    address_ipv6_1.nxd_ip_address.v6[0] = 14;
    address_ipv6_1.nxd_ip_address.v6[1] = 14;
    address_ipv6_1.nxd_ip_address.v6[2] = 14;
    address_ipv6_1.nxd_ip_address.v6[3] = 14;
    address_ipv6_1.nxd_ip_version = NX_IP_VERSION_V6;
    status = nxd_dns_server_add(&client_dns, &address_ipv6_1);    
    if (status)
    {
        error_counter++;
    }
#endif

    /* Check duplicate server logic */
    status = nxd_dns_server_add(&client_dns, &address_ipv4_1);
    if (status != NX_DNS_DUPLICATE_ENTRY) 
    {
        error_counter++;
    }

#ifdef FEATURE_NX_IPV6
    status = nxd_dns_server_add(&client_dns, &address_ipv6_1);
    if (status != NX_DNS_DUPLICATE_ENTRY) 
    {
        error_counter++;
    }
#endif

    /* check for size less than max entries.  */
    status = nx_dns_get_serverlist_size(&client_dns, &size);
#ifdef FEATURE_NX_IPV6
    if (status != NX_SUCCESS || size != 4)
#else
    if (status != NX_SUCCESS || size != 2) 
#endif
    {
        error_counter++;
    }

    ULONG get_ipv4_address;
#ifdef FEATURE_NX_IPV6
    /* use nx api for IPv6 address.  */
    status = nx_dns_server_get(&client_dns, 2, &get_ipv4_address);
    if (status != NX_DNS_INVALID_ADDRESS_TYPE) 
    {
        error_counter++;
    }
#endif

    /* try getting address outside of bounds.  */
    status = nx_dns_server_get(&client_dns, NX_DNS_MAX_SERVERS, &get_ipv4_address);
    if (status != NX_DNS_PARAM_ERROR) {
        error_counter++;
    }

    /* try getting from index that is not set.  */
    status = nx_dns_server_get(&client_dns, 4, &get_ipv4_address);
    if (status != NX_DNS_SERVER_NOT_FOUND)
    {
        error_counter++;
    }

    /* these should work.  */
    status = nx_dns_server_get(&client_dns, 0, &get_ipv4_address);
    if (status != NX_SUCCESS || get_ipv4_address != IP_ADDRESS(1,1,1,1))
    {
        error_counter++;
    }

    status = nx_dns_server_get(&client_dns, 1, &get_ipv4_address);
    if (status != NX_SUCCESS || get_ipv4_address != IP_ADDRESS(10,1,1,1))
    {
        error_counter++;
    }

#ifdef FEATURE_NX_IPV6
    NXD_ADDRESS get_ipv6_address;
    status = nxd_dns_server_get(&client_dns, 2, &get_ipv6_address);
    if (status != NX_SUCCESS || !CHECK_IPV6_ADDRESSES_SAME(&get_ipv6_address.nxd_ip_address.v6[0], &address_ipv6_0.nxd_ip_address.v6[0]))
    {
        error_counter++;
    }

    /* Check for an address that does not exist.  */
    address_ipv6_0.nxd_ip_address.v6[0] = 1;
    address_ipv6_0.nxd_ip_address.v6[1] = 2;
    address_ipv6_0.nxd_ip_address.v6[2] = 3;
    address_ipv6_0.nxd_ip_address.v6[3] = 4;
    status = nxd_dns_server_remove(&client_dns, &address_ipv6_0);
    if (status != NX_DNS_SERVER_NOT_FOUND)
    {
        error_counter++;
    }

    /* Remove an ipv6 that does exist.  */
    status = nxd_dns_server_remove(&client_dns, &address_ipv6_1);
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
#endif
    status = nx_dns_server_remove_all(&client_dns);
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
#endif

    /* Add an IPv4 server address to the Client list. */
    status = nx_dns_server_add(&client_dns, DNS_SERVER_ADDRESS);    
    if (status)
    {
        error_counter++;
    }

    status = nx_dns_get_serverlist_size(&client_dns, &size);
    if (status != NX_SUCCESS || size != 1)
    {
        error_counter++;
    }

    /* The DNS test initialize.  */
    dns_test_initialize();

    /* Test the DNS A type function.  */
    dns_a_type_test();
    
    /* DNS retransmit test.  */
    dns_retransmit_test();
                                
#ifdef __PRODUCT_NETXDUO__
    /* Test the DNS AAAA type function.  */
    dns_aaaa_type_test();
#endif
        
#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
    
    /* Test the DNS A + CNAME type function.  */
    dns_a_cname_type_test();
            
    /* Test the DNS MX type function.  */
    dns_mx_type_test();
            
    /* Test the DNS MX type with addtional A type  function.  */
    dns_mx_a_type_test();
    
    /* Test the DNS CNAME type function.  */
    dns_cname_type_test();
    
    /* Test the DNS NS type with addtional A type function.  */
    dns_ns_a_type_test();
    
    /* Test the DNS SRV type.  */
    dns_srv_type_test();
    
    /* Test the DNS SRV type.  */
    dns_txt_type_test();
    
    /* Test the DNS SOA type.  */
    dns_soa_type_test();

#endif

    status = nx_dns_delete(&client_dns);

    if (status)
    {
        error_counter++;
    }

    test_control_return(0xdeadbeef);
}
    

static void    thread_1_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        port;
UINT        i;
USHORT      nx_dns_transmit_id;
UCHAR       *data_ptr;

    /* Create a UDP socket act as the DNS server.  */
    status = nx_udp_socket_create(&server_ip, &server_socket, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Register the receive notify function.  */
    status =  nx_udp_socket_receive_notify(&server_socket, receive_packet_function);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&server_socket, 53, TX_WAIT_FOREVER);

    /* Act as the DNS server to receive the DNS query and send the DNS response.  */
    for (i = 0; i < test_count; i++ )
    {

        /* Receive a UDP packet.  */
        status =  nx_udp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status)
        {
            error_counter++;
            return;
        }       

        /* If the Test the DNS client retransmission.*/
        if((i == 4) || (i == 5))
        {          
            nx_packet_release(my_packet);
            continue;
        }

        /* Get the DNS client UDP port.  */
        status = nx_udp_packet_info_extract(my_packet, NX_NULL ,NX_NULL, &port, NX_NULL);

        /* Check status.  */
        if (status)
        {
            error_counter++; 
            return;
        }

        /* Get the DNS transmit ID.  */
        data_ptr = my_packet -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
        nx_dns_transmit_id = *data_ptr++;
        nx_dns_transmit_id =  (USHORT)((nx_dns_transmit_id << 8) | *data_ptr);

        /* Release the packet.  */
        nx_packet_release(my_packet);

        /* Send the DNS response packet.  */
        status = nx_dns_response_packet_send(&server_socket, port, nx_dns_transmit_id, i);

        /* Check status.  */
        if (status)
        {        
            error_counter++; 
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

static void    receive_packet_function(NX_UDP_SOCKET *socket_ptr)
{

    if (socket_ptr == &server_socket)
        notify_calls++;
}

static UINT   nx_dns_response_packet_send(NX_UDP_SOCKET *server_socket, UINT port, USHORT nx_dns_transmit_id, UINT packet_number)
{
UINT        status;
NX_PACKET   *response_packet;
UCHAR        *data_ptr;

    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&pool_0, &response_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Write the DNS response messages into the packet payload!  */
    dns_test[packet_number].dns_test_pkt_data += DNS_START_OFFSET;
    memcpy(response_packet -> nx_packet_prepend_ptr, dns_test[packet_number].dns_test_pkt_data, dns_test[packet_number].dns_test_pkt_size - DNS_START_OFFSET);

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length =  dns_test[packet_number].dns_test_pkt_size - DNS_START_OFFSET;
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

    /* Update the DNS transmit ID.  */
    data_ptr = response_packet -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
    *data_ptr++ = (UCHAR)(nx_dns_transmit_id >> 8);
    *data_ptr = (UCHAR)nx_dns_transmit_id;

    /* Send the UDP packet with the correct port.  */
    status =  nx_udp_socket_send(server_socket, response_packet, IP_ADDRESS(10, 0, 0, 10), port);

    /* Check the status.  */
    if (status)      
        nx_packet_release(response_packet);         

    return status;
}

static void     dns_test_initialize()
{

    /* DNS A type test.  */
    dns_test[0].dns_test_pkt_data = &response_a_google_com_pkt[0];
    dns_test[0].dns_test_pkt_size = response_a_google_com_pkt_size;  
    dns_test[1].dns_test_pkt_data = &response_a_google_com_pkt[0];
    dns_test[1].dns_test_pkt_size = response_a_google_com_pkt_size;  
    dns_test[2].dns_test_pkt_data = &response_a_berkley_edu_pkt[0];
    dns_test[2].dns_test_pkt_size = response_a_berkley_edu_pkt_size;   
    dns_test[3].dns_test_pkt_data = &response_a_berkley_edu_pkt[0];
    dns_test[3].dns_test_pkt_size = response_a_berkley_edu_pkt_size; 

    /* DNS retransmit test.  */
    dns_test[4].dns_test_pkt_data = &response_a_berkley_edu_pkt[0];
    dns_test[4].dns_test_pkt_size = response_a_berkley_edu_pkt_size; 
    dns_test[5].dns_test_pkt_data = &response_a_berkley_edu_pkt[0];
    dns_test[5].dns_test_pkt_size = response_a_berkley_edu_pkt_size; 
    dns_test[6].dns_test_pkt_data = &response_a_berkley_edu_pkt[0];
    dns_test[6].dns_test_pkt_size = response_a_berkley_edu_pkt_size;

#ifdef __PRODUCT_NETXDUO__
    
#ifdef FEATURE_NX_IPV6           
    /* DNS A type test.  */
    dns_test[7].dns_test_pkt_data = &response_aaaa_berkley_edu_pkt[0];
    dns_test[7].dns_test_pkt_size = response_aaaa_berkley_edu_pkt_size;  
    dns_test[8].dns_test_pkt_data = &response_aaaa_berkley_edu_pkt[0];
    dns_test[8].dns_test_pkt_size = response_aaaa_berkley_edu_pkt_size;   

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
    
    /* DNS extended type test.  */
    dns_test[9].dns_test_pkt_data = &response_a_cname_www_npr_org_pkt[0];
    dns_test[9].dns_test_pkt_size = response_a_cname_www_npr_org_pkt_size; 
    dns_test[10].dns_test_pkt_data = &response_a_cname_www_npr_org_pkt[0];
    dns_test[10].dns_test_pkt_size = response_a_cname_www_npr_org_pkt_size; 
    dns_test[11].dns_test_pkt_data = &response_mx_google_com_pkt[0];
    dns_test[11].dns_test_pkt_size = response_mx_google_com_pkt_size;     
    dns_test[12].dns_test_pkt_data = &response_mx_a_google_com_pkt[0];
    dns_test[12].dns_test_pkt_size = response_mx_a_google_com_pkt_size;    
    dns_test[13].dns_test_pkt_data = &response_mx_a_berkley_edu_pkt[0];
    dns_test[13].dns_test_pkt_size = response_mx_a_berkley_edu_pkt_size;
    dns_test[14].dns_test_pkt_data = &response_cname_www_baidu_com_pkt[0];
    dns_test[14].dns_test_pkt_size = response_cname_www_baidu_com_pkt_size;      
    dns_test[15].dns_test_pkt_data = &response_ns_a_ti_com_pkt[0];
    dns_test[15].dns_test_pkt_size = response_ns_a_ti_com_pkt_size; 
    dns_test[16].dns_test_pkt_data = &response_srv_google_com_pkt[0];
    dns_test[16].dns_test_pkt_size = response_srv_google_com_pkt_size; 
    dns_test[17].dns_test_pkt_data = &response_txt_google_com_pkt[0];
    dns_test[17].dns_test_pkt_size = response_txt_google_com_pkt_size; 
    dns_test[18].dns_test_pkt_data = &response_soa_google_com_pkt[0];
    dns_test[18].dns_test_pkt_size = response_soa_google_com_pkt_size;
#endif /* NX_DNS_ENABLE_EXTENDED_RR_TYPES */

#else /* FEATURE_NX_IPV6 */
        
    /* DNS A type test.  */
    dns_test[7].dns_test_pkt_data = &response_aaaa_berkley_edu_pkt[0];
    dns_test[7].dns_test_pkt_size = response_aaaa_berkley_edu_pkt_size;   

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
    
    /* DNS extended type test.  */
    dns_test[8].dns_test_pkt_data = &response_a_cname_www_npr_org_pkt[0];
    dns_test[8].dns_test_pkt_size = response_a_cname_www_npr_org_pkt_size; 
    dns_test[9].dns_test_pkt_data = &response_a_cname_www_npr_org_pkt[0];
    dns_test[9].dns_test_pkt_size = response_a_cname_www_npr_org_pkt_size; 
    dns_test[10].dns_test_pkt_data = &response_mx_google_com_pkt[0];
    dns_test[10].dns_test_pkt_size = response_mx_google_com_pkt_size;     
    dns_test[11].dns_test_pkt_data = &response_mx_a_google_com_pkt[0];
    dns_test[11].dns_test_pkt_size = response_mx_a_google_com_pkt_size;    
    dns_test[12].dns_test_pkt_data = &response_mx_a_berkley_edu_pkt[0];
    dns_test[12].dns_test_pkt_size = response_mx_a_berkley_edu_pkt_size; 
    dns_test[13].dns_test_pkt_data = &response_cname_www_baidu_com_pkt[0];
    dns_test[13].dns_test_pkt_size = response_cname_www_baidu_com_pkt_size;      
    dns_test[14].dns_test_pkt_data = &response_ns_a_ti_com_pkt[0];
    dns_test[14].dns_test_pkt_size = response_ns_a_ti_com_pkt_size; 
    dns_test[15].dns_test_pkt_data = &response_srv_google_com_pkt[0];
    dns_test[15].dns_test_pkt_size = response_srv_google_com_pkt_size; 
    dns_test[16].dns_test_pkt_data = &response_txt_google_com_pkt[0];
    dns_test[16].dns_test_pkt_size = response_txt_google_com_pkt_size; 
    dns_test[17].dns_test_pkt_data = &response_soa_google_com_pkt[0];
    dns_test[17].dns_test_pkt_size = response_soa_google_com_pkt_size; 
#endif /* NX_DNS_ENABLE_EXTENDED_RR_TYPES */
#endif /* FEATURE_NX_IPV6 */

#else /* __PRODUCT_NETXDUO__ */

#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
    
    /* DNS extended type test.  */    
    dns_test[7].dns_test_pkt_data = &response_a_cname_www_npr_org_pkt[0];
    dns_test[7].dns_test_pkt_size = response_a_cname_www_npr_org_pkt_size; 
    dns_test[8].dns_test_pkt_data = &response_a_cname_www_npr_org_pkt[0];
    dns_test[8].dns_test_pkt_size = response_a_cname_www_npr_org_pkt_size; 
    dns_test[9].dns_test_pkt_data = &response_mx_google_com_pkt[0];
    dns_test[9].dns_test_pkt_size = response_mx_google_com_pkt_size;     
    dns_test[10].dns_test_pkt_data = &response_mx_a_google_com_pkt[0];
    dns_test[10].dns_test_pkt_size = response_mx_a_google_com_pkt_size;    
    dns_test[11].dns_test_pkt_data = &response_mx_a_berkley_edu_pkt[0];
    dns_test[11].dns_test_pkt_size = response_mx_a_berkley_edu_pkt_size; 
    dns_test[12].dns_test_pkt_data = &response_cname_www_baidu_com_pkt[0];
    dns_test[12].dns_test_pkt_size = response_cname_www_baidu_com_pkt_size;      
    dns_test[13].dns_test_pkt_data = &response_ns_a_ti_com_pkt[0];
    dns_test[13].dns_test_pkt_size = response_ns_a_ti_com_pkt_size; 
    dns_test[14].dns_test_pkt_data = &response_srv_google_com_pkt[0];
    dns_test[14].dns_test_pkt_size = response_srv_google_com_pkt_size; 
    dns_test[15].dns_test_pkt_data = &response_txt_google_com_pkt[0];
    dns_test[15].dns_test_pkt_size = response_txt_google_com_pkt_size; 
    dns_test[16].dns_test_pkt_data = &response_soa_google_com_pkt[0];
    dns_test[16].dns_test_pkt_size = response_soa_google_com_pkt_size; 
#endif /* NX_DNS_ENABLE_EXTENDED_RR_TYPES */

#endif /* __PRODUCT_NETXDUO__ */
}

static void    dns_a_type_test()
{    
ULONG               host_ip_address;
ULONG               *ipv4_address_ptr1;
ULONG               *ipv4_address_ptr2;
ULONG               *ipv4_address_ptr3;
ULONG               *ipv4_address_ptr4;
ULONG               *ipv4_address_ptr5;
ULONG               *ipv4_address_ptr6;
ULONG               *ipv4_address_ptr7;
ULONG               *ipv4_address_ptr8;
ULONG               *ipv4_address_ptr9;
ULONG               *ipv4_address_ptr10;
ULONG               *ipv4_address_ptr11;

    /* Test the A type with the old API,(google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS A Type Google Com Old API Record Singer Addr Test.....");

    /* Secd dns query, and record the single host ip address. */
    status = nx_dns_host_by_name_get(&client_dns, (UCHAR *)"google.com", &host_ip_address, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check status and compare the host ip address.  */
    if (status || host_ip_address != IP_ADDRESS(74,125,224,194))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }

    
    /* Test the A type with the new API,(google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS A Type Google Com New API Record Multi Addr Test......");

    /* Test the A type NetX(new API) to process the multiple address. */
    status = nx_dns_ipv4_address_by_name_get(&client_dns, (UCHAR *)"google.com", &record_buffer[0], 500, &record_count, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check the record buffer.  */             
    ipv4_address_ptr1 = (ULONG *)record_buffer;  
    ipv4_address_ptr2 = (ULONG *)(record_buffer + 4);
    ipv4_address_ptr3 = (ULONG *)(record_buffer + 8);
    ipv4_address_ptr4 = (ULONG *)(record_buffer + 12);
    ipv4_address_ptr5 = (ULONG *)(record_buffer + 16);
    ipv4_address_ptr6 = (ULONG *)(record_buffer + 20); 
    ipv4_address_ptr7 = (ULONG *)(record_buffer + 24);
    ipv4_address_ptr8 = (ULONG *)(record_buffer + 28);
    ipv4_address_ptr9 = (ULONG *)(record_buffer + 32);
    ipv4_address_ptr10 = (ULONG *)(record_buffer + 36);
    ipv4_address_ptr11 = (ULONG *)(record_buffer + 40); 
    
    /* Check status and compare the host ip address.  */
    if (status || (record_count != 11) ||
        (*ipv4_address_ptr1 != IP_ADDRESS(74,125,224,194)) ||
        (*ipv4_address_ptr2 != IP_ADDRESS(74,125,224,195)) ||
        (*ipv4_address_ptr3 != IP_ADDRESS(74,125,224,196)) ||
        (*ipv4_address_ptr4 != IP_ADDRESS(74,125,224,197)) ||
        (*ipv4_address_ptr5 != IP_ADDRESS(74,125,224,198)) ||
        (*ipv4_address_ptr6 != IP_ADDRESS(74,125,224,199)) ||
        (*ipv4_address_ptr7 != IP_ADDRESS(74,125,224,200)) ||
        (*ipv4_address_ptr8 != IP_ADDRESS(74,125,224,201)) ||
        (*ipv4_address_ptr9 != IP_ADDRESS(74,125,224,206)) ||
        (*ipv4_address_ptr10 != IP_ADDRESS(74,125,224,192))||
        (*ipv4_address_ptr11 != IP_ADDRESS(74,125,224,193)))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }

    
    /* Test the A type with the old API,(berkeley.edu.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS A Type Berkley Edu Old API Record Singer Addr Test....");

    /* Secd dns query, and record the single host ip address. */
    status = nx_dns_host_by_name_get(&client_dns, (UCHAR *)"berkeley.edu", &host_ip_address, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check status and compare the host ip address.  */
    if (status || host_ip_address != IP_ADDRESS(169,229,216,200))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }

    
    /* Test the A type with the new API,(berkeley.edu.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS A Type Berkley Edu New API Record Multi Addr Test.....");

    /* Test the A type NetX(new API) to process the multiple address. */
    status = nx_dns_ipv4_address_by_name_get(&client_dns, (UCHAR *)"berkeley.edu", &record_buffer[0], 500, &record_count, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check the record buffer.  */             
    ipv4_address_ptr1 = (ULONG *)record_buffer;  
    
    /* Check status and compare the host ip address.  */
    if (status || (record_count != 1) ||
        (*ipv4_address_ptr1 != IP_ADDRESS(169,229,216,200)))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }

}

static void    dns_retransmit_test()
{    
ULONG               *ipv4_address_ptr1;
            
    /* Test DNS Query retransmission the A type with the new API,(berkeley.edu.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS A Type Berkley Edu New API Retransmission Test........");

    /* Test the A type NetX(new API) to process the multiple address. */
    status = nx_dns_ipv4_address_by_name_get(&client_dns, (UCHAR *)"berkeley.edu", &record_buffer[0], 500, &record_count, 2 * NX_IP_PERIODIC_RATE);
    
    /* Check the record buffer.  */             
    ipv4_address_ptr1 = (ULONG *)record_buffer;  
    
    /* Check status and compare the host ip address.  */
    if (status || (record_count != 1) ||
        (*ipv4_address_ptr1 != IP_ADDRESS(169,229,216,200)))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }

}

#ifdef __PRODUCT_NETXDUO__
static void    dns_aaaa_type_test()
{
     
NX_DNS_IPV6_ADDRESS     *ipv6_address_ptr;  

#ifdef FEATURE_NX_IPV6 
NXD_ADDRESS             host_ipduo_address;
#endif

#ifdef FEATURE_NX_IPV6
    /* Test the AAAA type with the old API,(berkeley.edu.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS AAAA Type Berkley Edu Old API Record Singer Addr Test.");

    /* Secd DNS AAAA query, and record the single host ip address. */
    status = nxd_dns_host_by_name_get(&client_dns, (UCHAR *)"berkeley.edu", &host_ipduo_address, 4 * NX_IP_PERIODIC_RATE, NX_IP_VERSION_V6);
    
    /* Check status and compare the host ip address.  */
    if (status || 
        host_ipduo_address.nxd_ip_address.v6[0] != 0x2607f140 ||
        host_ipduo_address.nxd_ip_address.v6[1] != 0x00000081 ||
        host_ipduo_address.nxd_ip_address.v6[2] != 0x00000000 ||
        host_ipduo_address.nxd_ip_address.v6[3] != 0x0000000f)
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }
#endif

    /* Test the A type with the new API,(berkeley.edu.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS AAAA Type Berkley Edu New API Record Multi Addr Test..");

    /* Test the AAAA type NetX Duo(new API) to process the multiple address. */
    status =  nxd_dns_ipv6_address_by_name_get(&client_dns, (UCHAR *)"berkeley.edu", &record_buffer[0], 200, &record_count, 4 * NX_IP_PERIODIC_RATE);
         
    ipv6_address_ptr = (NX_DNS_IPV6_ADDRESS *)record_buffer;   
    
    /* Check the record buffer.  */    
    /* Check status and compare the host ip address.  */
    if (status || record_count != 1 || 
        (*ipv6_address_ptr).ipv6_address[0] != 0x2607f140 ||
        (*ipv6_address_ptr).ipv6_address[1] != 0x00000081 ||
        (*ipv6_address_ptr).ipv6_address[2] != 0x00000000 ||
        (*ipv6_address_ptr).ipv6_address[3] != 0x0000000f)
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }
}
#endif /* __PRODUCT_NETXDUO__ */


#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES

static void    dns_a_cname_type_test()
{    
ULONG               host_ip_address;
ULONG               *ipv4_address_ptr1;

    /* Test the A type with the old API,(google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS A CNAME Type Www Npr Org Old API Test.................");

    /* Secd dns query, and record the single host ip address. */
    status = nx_dns_host_by_name_get(&client_dns, (UCHAR *)"www.npr.org", &host_ip_address, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check status and compare the host ip address.  */
    if (status || host_ip_address != IP_ADDRESS(216,35,221,76))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }

    
    /* Test the A type with the new API,(google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS A CNAME Type Www Npr Org New API Test.................");

    /* Test the A type NetX(new API) to process the multiple address. */
    status = nx_dns_ipv4_address_by_name_get(&client_dns, (UCHAR *)"www.npr.org", &record_buffer[0], 500, &record_count, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check the record buffer.  */             
    ipv4_address_ptr1 = (ULONG *)record_buffer;  
    
    /* Check status and compare the host ip address.  */
    if (status || (record_count != 1) ||
        (*ipv4_address_ptr1 != IP_ADDRESS(216,35,221,76)))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }

}

static void    dns_mx_type_test()
{
        
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr1;
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr2;
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr3;
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr4;
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr5;

    /* Test the MX type (google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS MX Type Google Com New API Record Multi MX Test.......");

    /* Secd DNS MX query, and record the multiple mail exchange info. */
    status = nx_dns_domain_mail_exchange_get(&client_dns, (UCHAR *)"google.com", &record_buffer[0], 500, &record_count, 4 * NX_IP_PERIODIC_RATE);


    /* Check the record buffer.  */
    nx_dns_mx_entry_ptr1 = (NX_DNS_MX_ENTRY *)record_buffer;  
    nx_dns_mx_entry_ptr2 = (NX_DNS_MX_ENTRY *)(record_buffer + sizeof(NX_DNS_MX_ENTRY));             
    nx_dns_mx_entry_ptr3 = (NX_DNS_MX_ENTRY *)(record_buffer + (2 * sizeof(NX_DNS_MX_ENTRY)));  
    nx_dns_mx_entry_ptr4 = (NX_DNS_MX_ENTRY *)(record_buffer + (3 * sizeof(NX_DNS_MX_ENTRY)));
    nx_dns_mx_entry_ptr5 = (NX_DNS_MX_ENTRY *)(record_buffer + (4 * sizeof(NX_DNS_MX_ENTRY)));

    /* Check status and compare the host ip address.  */
    if (status || record_count != 5)
    {
        error_counter++;
    }

    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr1 -> nx_dns_mx_preference != 50 ||
       memcmp(nx_dns_mx_entry_ptr1 -> nx_dns_mx_hostname_ptr, "alt4.aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr1 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }

    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr2 -> nx_dns_mx_preference != 30 ||
       memcmp(nx_dns_mx_entry_ptr2 -> nx_dns_mx_hostname_ptr, "alt2.aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr2 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }
    
    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr3 -> nx_dns_mx_preference != 10 ||
       memcmp(nx_dns_mx_entry_ptr3 -> nx_dns_mx_hostname_ptr, "aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr3 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }
    
    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr4 -> nx_dns_mx_preference != 20 ||
       memcmp(nx_dns_mx_entry_ptr4 -> nx_dns_mx_hostname_ptr, "alt1.aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr4 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }
    
    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr5 -> nx_dns_mx_preference != 40 ||
       memcmp(nx_dns_mx_entry_ptr5 -> nx_dns_mx_hostname_ptr, "alt3.aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr5 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }
  
}



static void    dns_mx_a_type_test()
{
        
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr1;
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr2;
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr3;
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr4;
NX_DNS_MX_ENTRY *nx_dns_mx_entry_ptr5;

    /* Test the MX&A type (google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS MX&A Type Google Com New API Record Multi MX Test.....");

    /* Secd DNS MX query, and record the multiple mail exchange info. */
    status = nx_dns_domain_mail_exchange_get(&client_dns, (UCHAR *)"google.com", &record_buffer[0], 500, &record_count, 4 * NX_IP_PERIODIC_RATE);


    /* Check the record buffer.  */
    nx_dns_mx_entry_ptr1 = (NX_DNS_MX_ENTRY *)record_buffer;  
    nx_dns_mx_entry_ptr2 = (NX_DNS_MX_ENTRY *)(record_buffer + sizeof(NX_DNS_MX_ENTRY));             
    nx_dns_mx_entry_ptr3 = (NX_DNS_MX_ENTRY *)(record_buffer + (2 * sizeof(NX_DNS_MX_ENTRY)));  
    nx_dns_mx_entry_ptr4 = (NX_DNS_MX_ENTRY *)(record_buffer + (3 * sizeof(NX_DNS_MX_ENTRY)));
    nx_dns_mx_entry_ptr5 = (NX_DNS_MX_ENTRY *)(record_buffer + (4 * sizeof(NX_DNS_MX_ENTRY)));

    /* Check status and compare the host ip address.  */
    if (status || record_count != 5)
    {
        error_counter++;
    }
        
    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr1 -> nx_dns_mx_preference != 20 ||
       nx_dns_mx_entry_ptr1 -> nx_dns_mx_ipv4_address != IP_ADDRESS(209,85,225,26) ||
       memcmp(nx_dns_mx_entry_ptr1 -> nx_dns_mx_hostname_ptr, "alt1.aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr1 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }
    
    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr2 -> nx_dns_mx_preference != 30 ||
       nx_dns_mx_entry_ptr2 -> nx_dns_mx_ipv4_address != IP_ADDRESS(74,125,130,26) ||
       memcmp(nx_dns_mx_entry_ptr2 -> nx_dns_mx_hostname_ptr, "alt2.aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr2 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }
        
    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr3 -> nx_dns_mx_preference != 40 ||
       nx_dns_mx_entry_ptr3 -> nx_dns_mx_ipv4_address != IP_ADDRESS(173,194,76,26) ||
       memcmp(nx_dns_mx_entry_ptr3 -> nx_dns_mx_hostname_ptr, "alt3.aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr3 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }

    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr4 -> nx_dns_mx_preference != 50 ||
       nx_dns_mx_entry_ptr4 -> nx_dns_mx_ipv4_address != IP_ADDRESS(173,194,73,26) ||
       memcmp(nx_dns_mx_entry_ptr4 -> nx_dns_mx_hostname_ptr, "alt4.aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr4 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }
        
    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr5 -> nx_dns_mx_preference != 10 ||
       nx_dns_mx_entry_ptr5 -> nx_dns_mx_ipv4_address != IP_ADDRESS(173,194,79,26) ||
       memcmp(nx_dns_mx_entry_ptr5 -> nx_dns_mx_hostname_ptr, "aspmx.l.google.com", strlen((const char*)(nx_dns_mx_entry_ptr5 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }
  
    
    /* Test the MX&A type (berkeley.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS MX&A Type Berkley Com New API Record Multi MX Test....");

    /* Secd DNS MX query, and record the multiple mail exchange info. */
    status = nx_dns_domain_mail_exchange_get(&client_dns, (UCHAR *)"berkeley.edu", &record_buffer[0], 500, &record_count, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check the record buffer.  */
    nx_dns_mx_entry_ptr1 = (NX_DNS_MX_ENTRY *)record_buffer;  

    /* Check status and compare the host ip address.  */
    if (status || record_count != 1)
    {
        error_counter++;
    }
        
    /* Check the all mail exchange info.  */
    if(nx_dns_mx_entry_ptr1 -> nx_dns_mx_preference != 10 ||
       nx_dns_mx_entry_ptr1 -> nx_dns_mx_ipv4_address != IP_ADDRESS(169,229,218,141) ||
       memcmp(nx_dns_mx_entry_ptr1 -> nx_dns_mx_hostname_ptr, "mx.berkeley.edu", strlen((const char*)(nx_dns_mx_entry_ptr1 -> nx_dns_mx_hostname_ptr))))
    {
        error_counter++;
    } 

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }  

}


static void    dns_cname_type_test()
{
        
    /* Test the CNAME type (mail.baidu.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS CNAME Type Www Baidu Com New API Record Cname Test....");

    /* Secd DNS CNAME query, and record the cname info. */
    status = nx_dns_cname_get(&client_dns, (UCHAR *)"www.baidu.com", &record_buffer[0], 500, 4 * NX_IP_PERIODIC_RATE);  

    /* Check status and compare the host ip address.  */
    if (status || 
        memcmp(record_buffer, "www.a.shifen.com", strlen((const char*)(&record_buffer[0]))))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }
  
}

static void    dns_ns_a_type_test()
{
        
NX_DNS_NS_ENTRY *nx_dns_ns_entry_ptr1;
NX_DNS_NS_ENTRY *nx_dns_ns_entry_ptr2;
NX_DNS_NS_ENTRY *nx_dns_ns_entry_ptr3;
NX_DNS_NS_ENTRY *nx_dns_ns_entry_ptr4;
NX_DNS_NS_ENTRY *nx_dns_ns_entry_ptr5;
NX_DNS_NS_ENTRY *nx_dns_ns_entry_ptr6;
NX_DNS_NS_ENTRY *nx_dns_ns_entry_ptr7;
NX_DNS_NS_ENTRY *nx_dns_ns_entry_ptr8;

    /* Test the NS&A type (ti.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS NS&A Type Ti Com New API Record Multi NS Test.........");

    /* Secd DNS NS query, and record the multiple name server info. */
    status = nx_dns_domain_name_server_get(&client_dns, (UCHAR *)"ti.com", &record_buffer[0], 200, &record_count, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check the record buffer.  */
    nx_dns_ns_entry_ptr1 = (NX_DNS_NS_ENTRY *)record_buffer;  
    nx_dns_ns_entry_ptr2 = (NX_DNS_NS_ENTRY *)(record_buffer + sizeof(NX_DNS_NS_ENTRY));
    nx_dns_ns_entry_ptr3 = (NX_DNS_NS_ENTRY *)(record_buffer + (2 * sizeof(NX_DNS_NS_ENTRY)));
    nx_dns_ns_entry_ptr4 = (NX_DNS_NS_ENTRY *)(record_buffer + (3 * sizeof(NX_DNS_NS_ENTRY)));
    nx_dns_ns_entry_ptr5 = (NX_DNS_NS_ENTRY *)(record_buffer + (4 * sizeof(NX_DNS_NS_ENTRY)));
    nx_dns_ns_entry_ptr6 = (NX_DNS_NS_ENTRY *)(record_buffer + (5 * sizeof(NX_DNS_NS_ENTRY)));
    nx_dns_ns_entry_ptr7 = (NX_DNS_NS_ENTRY *)(record_buffer + (6 * sizeof(NX_DNS_NS_ENTRY)));
    nx_dns_ns_entry_ptr8 = (NX_DNS_NS_ENTRY *)(record_buffer + (7 * sizeof(NX_DNS_NS_ENTRY)));

    /* Check status and compare the host ip address.  */
    if (status || record_count != 8)
    {
        error_counter++;
    }
                       
    /* Check the all mail exchange info.  */
    if(nx_dns_ns_entry_ptr8 -> nx_dns_ns_ipv4_address!= IP_ADDRESS(64,95,61,4) ||
       memcmp(nx_dns_ns_entry_ptr8 -> nx_dns_ns_hostname_ptr, "ns-c.pnap.net", strlen((const char*)(nx_dns_ns_entry_ptr8 -> nx_dns_ns_hostname_ptr))))
    {
        error_counter++;
    }

    /* Check the all mail exchange info.  */
    if(nx_dns_ns_entry_ptr7 -> nx_dns_ns_ipv4_address!= IP_ADDRESS(64,94,123,4) ||
       memcmp(nx_dns_ns_entry_ptr7 -> nx_dns_ns_hostname_ptr, "ns-a.pnap.net", strlen((const char*)(nx_dns_ns_entry_ptr7 -> nx_dns_ns_hostname_ptr))))
    {
        error_counter++;
    }

    /* Check the all mail exchange info.  */
    if(nx_dns_ns_entry_ptr6 -> nx_dns_ns_ipv4_address!= IP_ADDRESS(192,94,94,43) ||
       memcmp(nx_dns_ns_entry_ptr6 -> nx_dns_ns_hostname_ptr, "ns2.ti.com", strlen((const char*)(nx_dns_ns_entry_ptr6 -> nx_dns_ns_hostname_ptr))))
    {
        error_counter++;
    }
    
            
    /* Check the all mail exchange info.  */
    if(nx_dns_ns_entry_ptr5 -> nx_dns_ns_ipv4_address!= IP_ADDRESS(192,94,94,42) ||
       memcmp(nx_dns_ns_entry_ptr5 -> nx_dns_ns_hostname_ptr, "ns.ti.com", strlen((const char*)(nx_dns_ns_entry_ptr5 -> nx_dns_ns_hostname_ptr))))
    {
        error_counter++;
    }
                        
    /* Check the all mail exchange info.  */
    if(nx_dns_ns_entry_ptr4 -> nx_dns_ns_ipv4_address!= IP_ADDRESS(198,47,26,151) ||
       memcmp(nx_dns_ns_entry_ptr4 -> nx_dns_ns_hostname_ptr, "ns4.ti.com", strlen((const char*)(nx_dns_ns_entry_ptr4 -> nx_dns_ns_hostname_ptr))))
    {
        error_counter++;
    }

    /* Check the all mail exchange info.  */
    if(nx_dns_ns_entry_ptr3 -> nx_dns_ns_ipv4_address!= IP_ADDRESS(198,47,26,150) ||
       memcmp(nx_dns_ns_entry_ptr3 -> nx_dns_ns_hostname_ptr, "ns3.ti.com", strlen((const char*)(nx_dns_ns_entry_ptr3 -> nx_dns_ns_hostname_ptr))))
    {
        error_counter++;
    }
            
    /* Check the all mail exchange info.  */
    if(nx_dns_ns_entry_ptr2 -> nx_dns_ns_ipv4_address!= IP_ADDRESS(64,94,123,36) ||
       memcmp(nx_dns_ns_entry_ptr2 -> nx_dns_ns_hostname_ptr, "ns-b.pnap.net", strlen((const char*)(nx_dns_ns_entry_ptr2 -> nx_dns_ns_hostname_ptr))))
    {
        error_counter++;
    }
            
    /* Check the all mail exchange info.  */
    if(nx_dns_ns_entry_ptr1 -> nx_dns_ns_ipv4_address!= IP_ADDRESS(64,95,61,36) ||
       memcmp(nx_dns_ns_entry_ptr1 -> nx_dns_ns_hostname_ptr, "ns-d.pnap.net", strlen((const char*)(nx_dns_ns_entry_ptr1 -> nx_dns_ns_hostname_ptr))))
    {
        error_counter++;
    }
            
    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }    
}


static void    dns_srv_type_test()
{
        
NX_DNS_SRV_ENTRY *nx_dns_srv_entry_ptr1;
NX_DNS_SRV_ENTRY *nx_dns_srv_entry_ptr2;
NX_DNS_SRV_ENTRY *nx_dns_srv_entry_ptr3;
NX_DNS_SRV_ENTRY *nx_dns_srv_entry_ptr4;
NX_DNS_SRV_ENTRY *nx_dns_srv_entry_ptr5;

    /* Test the SRV type (google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS SRV Type Google Com New API Record Multi service Test.");

    /* Secd DNS SRV query, and record the multiple service info. */
    status = nx_dns_domain_service_get(&client_dns, (UCHAR *)"_xmpp-client._tcp.google.com", &record_buffer[0], 500, &record_count, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check the record buffer.  */
    nx_dns_srv_entry_ptr1 = (NX_DNS_SRV_ENTRY *)record_buffer;  
    nx_dns_srv_entry_ptr2 = (NX_DNS_SRV_ENTRY *)(record_buffer + sizeof(NX_DNS_SRV_ENTRY));             
    nx_dns_srv_entry_ptr3 = (NX_DNS_SRV_ENTRY *)(record_buffer + (2 * sizeof(NX_DNS_SRV_ENTRY)));  
    nx_dns_srv_entry_ptr4 = (NX_DNS_SRV_ENTRY *)(record_buffer + (3 * sizeof(NX_DNS_SRV_ENTRY)));
    nx_dns_srv_entry_ptr5 = (NX_DNS_SRV_ENTRY *)(record_buffer + (4 * sizeof(NX_DNS_SRV_ENTRY)));

    /* Check status and compare the host ip address.  */
    if (status || record_count != 5)
    {
        error_counter++;
    }

    /* Check the all mail exchange info.  */
    if(nx_dns_srv_entry_ptr1 -> nx_dns_srv_port_number != 5222 ||
       nx_dns_srv_entry_ptr1 -> nx_dns_srv_priority != 20 ||
       nx_dns_srv_entry_ptr1 -> nx_dns_srv_weight != 0 ||
       memcmp(nx_dns_srv_entry_ptr1 -> nx_dns_srv_hostname_ptr, "alt3.xmpp.l.google.com", strlen((const char*)(nx_dns_srv_entry_ptr1 -> nx_dns_srv_hostname_ptr))))
    {
        error_counter++;
    }
    
    /* Check the all mail exchange info.  */
    if(nx_dns_srv_entry_ptr2 -> nx_dns_srv_port_number != 5222 ||
       nx_dns_srv_entry_ptr2 -> nx_dns_srv_priority != 20 ||
       nx_dns_srv_entry_ptr2 -> nx_dns_srv_weight != 0 ||
       memcmp(nx_dns_srv_entry_ptr2 -> nx_dns_srv_hostname_ptr, "alt1.xmpp.l.google.com", strlen((const char*)(nx_dns_srv_entry_ptr2 -> nx_dns_srv_hostname_ptr))))
    {
        error_counter++;
    }

    /* Check the all mail exchange info.  */
    if(nx_dns_srv_entry_ptr3 -> nx_dns_srv_port_number != 5222 ||
       nx_dns_srv_entry_ptr3 -> nx_dns_srv_priority != 20 ||
       nx_dns_srv_entry_ptr3 -> nx_dns_srv_weight != 0 ||
       memcmp(nx_dns_srv_entry_ptr3 -> nx_dns_srv_hostname_ptr, "alt4.xmpp.l.google.com", strlen((const char*)(nx_dns_srv_entry_ptr3 -> nx_dns_srv_hostname_ptr))))
    {
        error_counter++;
    }
    
    /* Check the all mail exchange info.  */
    if(nx_dns_srv_entry_ptr4 -> nx_dns_srv_port_number != 5222 ||
       nx_dns_srv_entry_ptr4 -> nx_dns_srv_priority != 5 ||
       nx_dns_srv_entry_ptr4 -> nx_dns_srv_weight != 0 ||
       memcmp(nx_dns_srv_entry_ptr4 -> nx_dns_srv_hostname_ptr, "xmpp.l.google.com", strlen((const char*)(nx_dns_srv_entry_ptr4 -> nx_dns_srv_hostname_ptr))))
    {
        error_counter++;
    }
    
    /* Check the all mail exchange info.  */
    if(nx_dns_srv_entry_ptr5 -> nx_dns_srv_port_number != 5222 ||
       nx_dns_srv_entry_ptr5 -> nx_dns_srv_priority != 20 ||
       nx_dns_srv_entry_ptr5 -> nx_dns_srv_weight != 0 ||
       memcmp(nx_dns_srv_entry_ptr5 -> nx_dns_srv_hostname_ptr, "alt2.xmpp.l.google.com", strlen((const char*)(nx_dns_srv_entry_ptr5 -> nx_dns_srv_hostname_ptr))))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }
  
}


static void    dns_txt_type_test()
{
        
    /* Test the TXT type (google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS TXT Type Google Com New API Record Txt Test...........");

    /* Secd DNS CNAME query, and record the cname info. */
    status = nx_dns_host_text_get(&client_dns, (UCHAR *)"google.com", &record_buffer[0], 500, 4 * NX_IP_PERIODIC_RATE); 

    /* Check status and compare the host ip address.  */
    if (status || 
        memcmp(record_buffer, "v=spf1 include:_netblocks.google.com ip4:216.73.93.70/31 ip4:216.73.93.72/31 ~all", strlen((const char*)(&record_buffer[0]))))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }
  
}


static void    dns_soa_type_test()
{
        
NX_DNS_SOA_ENTRY  *nx_dns_soa_entry_ptr;

    /* Test the SOA type (google.com.)  */
    /* Print out some test information banners.  */
    printf("NetX Test:   DNS SOA Type Google Com New API Record start of zone Test.");

    /* Secd DNS SRV query, and record the multiple service info. */
    status = nx_dns_authority_zone_start_get(&client_dns, (UCHAR *)"google.com", &record_buffer[0], 100, 4 * NX_IP_PERIODIC_RATE);
    
    /* Check the record buffer.  */
    nx_dns_soa_entry_ptr = (NX_DNS_SOA_ENTRY *)record_buffer;  

    /* Check status and compare the host ip address.  */
    if (status)
    {
        error_counter++;
    }

    /* Check the all mail exchange info.  */
    if(nx_dns_soa_entry_ptr -> nx_dns_soa_serial != 2012090400 ||
       nx_dns_soa_entry_ptr -> nx_dns_soa_refresh != 2 * 60 * 60 ||
       nx_dns_soa_entry_ptr -> nx_dns_soa_retry != 30 * 60 ||
       nx_dns_soa_entry_ptr -> nx_dns_soa_expire != 14 * 24 * 60 * 60 ||
       nx_dns_soa_entry_ptr -> nx_dns_soa_minmum != 5 * 60 ||
       memcmp( nx_dns_soa_entry_ptr -> nx_dns_soa_host_mname_ptr, "ns1.google.com", strlen((const char*)(nx_dns_soa_entry_ptr -> nx_dns_soa_host_mname_ptr))) ||
       memcmp( nx_dns_soa_entry_ptr -> nx_dns_soa_host_rname_ptr, "dns-admin.google.com", strlen((const char*)(nx_dns_soa_entry_ptr -> nx_dns_soa_host_rname_ptr))))
    {
        error_counter++;
    }

    /* Printf the test result.  */
    if (error_counter)
    {        
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }
  
}

#endif
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_function_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   DNS Function Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif