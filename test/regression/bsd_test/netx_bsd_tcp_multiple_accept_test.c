/* This NetX test concentrates on the basic BSD TCP blocking operation.  */
/* The BSD APIs involved in this test are:  socket(), connect(), send(), soc_close() */

#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nx_icmpv6.h"
#include   "nxd_bsd.h"
#define     DEMO_STACK_SIZE         4096

#define notify(v) 

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            1
/* Define the counters used in the test application...  */
static void                   *server1_stack_area;
static void                   *server2_stack_area;
static ULONG                   error_counter;
static ULONG                   packet_pool_area[(256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 8 / 4];
static TX_SEMAPHORE            session_start[4], session_end[4];

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS ipv6_address_ip0;
static NXD_ADDRESS ipv6_address_ip1;
#endif
static char *requests[4] = {"Request1", "Request2", "Request3", "Request4"};
static char *response[4] = {"Response1", "Response2", "Response3", "Response4"};
static void validate_bsd_structure(void);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_multiple_accept_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, packet_pool_area, sizeof(packet_pool_area));


    if (status)
    {
        notify(status);
        error_counter++;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
    {
        notify(status);
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
    {
        notify(status);
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
    {
        notify(status);
        error_counter++;
    }

    server1_stack_area = pointer;
    server2_stack_area = pointer + DEMO_STACK_SIZE;
    pointer = (void*)((ULONG)server2_stack_area + DEMO_STACK_SIZE);

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    status = tx_semaphore_create(&session_start[0], "0", 0);
    status += tx_semaphore_create(&session_start[1], "1", 0);
    status += tx_semaphore_create(&session_start[2], "2", 0);
    status += tx_semaphore_create(&session_start[3], "3", 0);
    status = tx_semaphore_create(&session_end[0], "4", 0);
    status += tx_semaphore_create(&session_end[1], "5", 0);
    status += tx_semaphore_create(&session_end[2], "6", 0);
    status += tx_semaphore_create(&session_end[3], "7", 0);
    if(status != TX_SUCCESS)
        error_counter++;

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check TCP enable status.  */
    if (status)
    {
        notify(status);
        error_counter++;
    }
}
typedef struct client_info_struct
{
    int sockfd;
    int message_id;
    int port_number;
} client_info;

static client_info client_data[4] = {
    {0, 0, 12345},
    {0, 0, 12345},
    {0, 0, 12346},
    {0, 0, 12346},
};
static ULONG stack_space[4][DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_THREAD helper_thread[4];

static TX_THREAD tcp_server1, tcp_server2;
static VOID bsd_server_helper_thread_entry(ULONG thread_input)
{
int         ret;
int         sockfd, message_id;
char        buf[30];

    sockfd = client_data[thread_input].sockfd;
    message_id = client_data[thread_input].message_id;
    /* Receive data from the client. */
    ret = recv(sockfd, buf, sizeof(buf), 0);
    if (ret <= 0)
    {
        error_counter++;
    }

    buf[ret] = 0;
   
    /* Validate the data. */
    if((ret != (int)strlen(requests[message_id & 3])) || (strncmp(buf, requests[message_id & 3], ret)))
    {
        error_counter++;
    }
    
    /* Send a response back. */
    ret = send(sockfd, response[message_id & 3], strlen(response[message_id & 3]), 0);
    if(ret != (int)strlen(response[message_id & 3]))
    {
        error_counter++;
    }
    
    tx_semaphore_get(&session_end[thread_input], NX_WAIT_FOREVER);
    ret = soc_close(sockfd);
    if(ret < 0)
    {
        error_counter++;
    }

    return;
}
    
static NX_TCP_SOCKET client_socket;

static void start_tcp_client4(int index)
{
UINT status;
NX_PACKET *packet_ptr;

    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", NX_IP_NORMAL,
                                  NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100, NX_NULL, NX_NULL);
    status += nx_tcp_client_socket_bind(&client_socket, NX_ANY_PORT, 0);
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1,2,3,4), client_data[index].port_number, NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
    {
        notify(status);
        error_counter++;
    }

    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
    if(status)
    {
        notify(status);
        error_counter++;
    }

    if(client_data[index].port_number == 12345)
        status = nx_packet_data_append(packet_ptr, requests[0], strlen(requests[0]), &pool_0, NX_NO_WAIT);
    else
        status = nx_packet_data_append(packet_ptr, requests[1], strlen(requests[1]), &pool_0, NX_NO_WAIT);    

    if(status)
    {
        notify(status);
        error_counter++;
    }

    status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);

    if(status)
    {
        notify(status);
        error_counter++;
    }

    status = nx_tcp_socket_receive(&client_socket, &packet_ptr, NX_WAIT_FOREVER);
    if(status)
    {
        notify(status);
        error_counter++;
    }
    else if(client_data[index].port_number == 12345)
    {
        if((packet_ptr -> nx_packet_length != strlen(response[0])) ||
           (strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, response[0], packet_ptr -> nx_packet_length)))
            error_counter++;
        nx_packet_release(packet_ptr);
    }
    else
    {
        if((packet_ptr -> nx_packet_length != strlen(response[1])) ||
           (strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, response[1], packet_ptr -> nx_packet_length)))
        {
            notify(status);
            error_counter++;
        }

        nx_packet_release(packet_ptr);
    }

    status = nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);
    if(status == NX_NOT_CONNECTED || status == NX_DISCONNECT_FAILED)
        status = 0;
    if(client_socket.nx_tcp_socket_bound_next)
        status += nx_tcp_client_socket_unbind(&client_socket);
    
    tx_semaphore_put(&session_end[index]);

    status += nx_tcp_socket_delete(&client_socket);
    if(status)
    {
        notify(status);
        error_counter++;
    }
}

static void tcp_server_entry(ULONG);
static void start_tcp_server4(void)
{
UINT status;
    status = tx_thread_create(&tcp_server1, "tcp server1", tcp_server_entry, 12345,
                              server1_stack_area, DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE,
                              TX_AUTO_START);
#if 1
    status += tx_thread_create(&tcp_server2, "tcp server2", tcp_server_entry, 12346,
                              server2_stack_area, DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE,
                              TX_AUTO_START);
#endif
    if(status)
    {
        notify(status);
        error_counter++;
    }

}

static void tcp_server_entry(ULONG param)
{
int                sockfd; 
struct sockaddr_in remote_addr, local_addr;
int                address_length;
int                ret;
int                newsock;
int                i, j, index;
UINT               status;
int                port = (int)param;


    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        notify(status);
        error_counter++;
    }
    
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
    {
        notify(status);
        error_counter++;
    }
    
    ret = listen(sockfd, 5);
    if(ret < 0)
    {
        notify(status);
        error_counter++;
    }

    for(j = 0; j < 2; j++)
    {
        address_length = sizeof(remote_addr);

        if(port == 12345)
            i = 0;
        else
            i = 1;

        index = 2 * i + j;
        tx_semaphore_put(&session_start[index]);
        newsock = accept(sockfd, (struct sockaddr*)&remote_addr, &address_length);
        
        if(newsock <= 0)
        {
            notify(status);
            error_counter++;
        }
        
        if(address_length != sizeof(remote_addr))
        {
            notify(status);
            error_counter++;
        }
        
        if((remote_addr.sin_family != AF_INET) || (remote_addr.sin_addr.s_addr != htonl(0x01020305)))
        {
            notify(status);
            error_counter++;
        }
        
        /* Set the client data */
        client_data[index].sockfd = newsock;
        client_data[index].message_id = i;
        
        /* Create a helper thread to handle the new socket. */
        status = tx_thread_create(&helper_thread[index], "helper thread", bsd_server_helper_thread_entry, 
                              index, stack_space[index], DEMO_STACK_SIZE, 2, 2, TX_NO_TIME_SLICE, TX_AUTO_START);

        if(status != TX_SUCCESS)
        {
            notify(status);
            error_counter++;
        }
    }

    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
    {
        notify(status);
        error_counter++;
    }

}


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
#ifdef FEATURE_NX_IPV6    
char mac_ip0[6];
char mac_ip1[6];
UINT status;
#endif



    printf("NetX Test:   Basic BSD TCP Multiple Accept Test............");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#ifdef FEATURE_NX_IPV6    
    /* First set up IPv6 addresses. */
    ipv6_address_ip0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_ip0.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address_ip0.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_ip0.nxd_ip_address.v6[2] = 0x021122ff;
    ipv6_address_ip0.nxd_ip_address.v6[3] = 0xfe334456;

    ipv6_address_ip1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_ip1.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address_ip1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_ip1.nxd_ip_address.v6[2] = 0x021122ff;
    ipv6_address_ip1.nxd_ip_address.v6[3] = 0xfe334457;
    
    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_ip0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_ip1, 64, NX_NULL);

    status += nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    
    mac_ip0[0] = ip_0.nx_ip_interface[0].nx_interface_physical_address_msw >> 8;
    mac_ip0[1] = ip_0.nx_ip_interface[0].nx_interface_physical_address_msw & 0xFF;
    mac_ip0[2] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 24) & 0xff;
    mac_ip0[3] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 16) & 0xff;
    mac_ip0[4] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 8) & 0xff;
    mac_ip0[5] = ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw  & 0xff;

    mac_ip1[0] = ip_1.nx_ip_interface[0].nx_interface_physical_address_msw >> 8;
    mac_ip1[1] = ip_1.nx_ip_interface[0].nx_interface_physical_address_msw & 0xFF;
    mac_ip1[2] = (ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw >> 24) & 0xff;
    mac_ip1[3] = (ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw >> 16) & 0xff;
    mac_ip1[4] = (ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw >> 8) & 0xff;
    mac_ip1[5] = ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw  & 0xff;
    
    status += nxd_nd_cache_entry_set(&ip_0, ipv6_address_ip1.nxd_ip_address.v6, 0,  mac_ip1);
    status += nxd_nd_cache_entry_set(&ip_1, ipv6_address_ip0.nxd_ip_address.v6, 0,  mac_ip0);

    if(status)
    {
        notify(status);
        error_counter++;
    }
#endif    

    start_tcp_server4();

    tx_semaphore_get(&session_start[0], NX_WAIT_FOREVER);
    start_tcp_client4(0);

    tx_semaphore_get(&session_start[1], NX_WAIT_FOREVER);
    start_tcp_client4(1);

    tx_semaphore_get(&session_start[2], NX_WAIT_FOREVER);
    start_tcp_client4(2);

    tx_semaphore_get(&session_start[3], NX_WAIT_FOREVER);
    start_tcp_client4(3);

    validate_bsd_structure();
    if(error_counter)
        printf("ERROR!\n");
    else
        printf("SUCCESS!\n");

    if(error_counter)
        test_control_return(1);    

    test_control_return(0);    
}
    


extern TX_BLOCK_POOL nx_bsd_socket_block_pool;
static void validate_bsd_structure(void)
{
int i;
    /* Make sure every BSD socket should be free by now. */
    
    for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
    {
        if(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE)
        {
            error_counter++;
        }

        if(nx_bsd_socket_array[i].nx_bsd_socket_tcp_socket ||
           nx_bsd_socket_array[i].nx_bsd_socket_udp_socket)
        {
            error_counter++;
        }
    }
    
    /* Make sure all the NX SOCKET control blocks are released. */
    if(nx_bsd_socket_block_pool.tx_block_pool_available != 
       nx_bsd_socket_block_pool.tx_block_pool_total)
    {
        error_counter++;
    }

    /* Make sure all the sockets are released */
    if(ip_0.nx_ip_tcp_created_sockets_ptr ||
       ip_0.nx_ip_udp_created_sockets_ptr)
    {
        error_counter++;
        return;
    }
}

#else
extern void       test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_multiple_accept_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP Multiple Accept Test............N/A\n"); 

    test_control_return(3);  
}      
#endif
