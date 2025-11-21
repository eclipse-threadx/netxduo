/* This NetX test concentrates on the basic BSD UDP non-blocking operation.  */


#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nx_icmpv6.h"
#include   "nxd_bsd.h"

#define     DEMO_STACK_SIZE         4096


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_UDP_SOCKET           server_socket;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            20
/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];
extern TX_BLOCK_POOL nx_bsd_socket_block_pool;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS ipv6_address_ip0[3][3];
static NXD_ADDRESS ipv6_address_ip1[3][3];
#endif /* FEATURE_NX_IPV6 */
static char *requests_ipv4[3] = {"Request1_ipv4", "Request22_ipv4", "Request333_ipv4"};
static char *response_ipv4[3] = {"Response1_ipv4", "Response22_ipv4", "Response333_ipv4"};
#ifdef FEATURE_NX_IPV6
static char *requests_ipv6[6] = {"Request1_ipv6", "Request22_ipv6", "Request333_ipv6", "Request4444_ipv6", "Request55555_ipv6", "Request666666_ipv6"};
static char *response_ipv6[6] = {"Response1_ipv6", "Response22_ipv6", "Response333_ipv4", "Request4444_ipv6", "Request55555_ipv6", "Request666666_ipv6"};
#endif
static void validate_bsd_structure(void);

#define IP0_IF0_V4_ADDR   IP_ADDRESS(1,2,3,4)  
#define IP0_IF1_V4_ADDR   IP_ADDRESS(2,2,3,4)  
#define IP0_IF2_V4_ADDR   IP_ADDRESS(3,2,3,4)  

#define IP1_IF0_V4_ADDR   IP_ADDRESS(1,2,3,5)  
#define IP1_IF1_V4_ADDR   IP_ADDRESS(2,2,3,5)  
#define IP1_IF2_V4_ADDR   IP_ADDRESS(3,2,3,5)  

#define ITERATIONS  100
static ULONG ip0_address[3] = {IP0_IF0_V4_ADDR, IP0_IF1_V4_ADDR, IP0_IF2_V4_ADDR};
static ULONG ip1_address[3] = {IP1_IF0_V4_ADDR, IP1_IF1_V4_ADDR, IP1_IF2_V4_ADDR};
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_udp_connect_test_application_define(void *first_unused_memory)
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
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, (256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 2);
    pointer = pointer + (256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 2;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP0_IF0_V4_ADDR, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Attach a 2nd interface */
    status += nx_ip_interface_attach(&ip_0, "ip_0_second", IP0_IF1_V4_ADDR, 0xFFFFFF00UL,  _nx_ram_network_driver_256);
    status += nx_ip_interface_attach(&ip_0, "ip_0_third", IP0_IF2_V4_ADDR, 0xFFFFFF00UL,  _nx_ram_network_driver_256);

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP1_IF0_V4_ADDR, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;

    status += nx_ip_interface_attach(&ip_1, "ip_1_second", IP1_IF1_V4_ADDR, 0xFFFFFF00UL,  _nx_ram_network_driver_256);
    status += nx_ip_interface_attach(&ip_1, "ip_1_third", IP1_IF2_V4_ADDR, 0xFFFFFF00UL,  _nx_ram_network_driver_256);
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable UDP processing for both IP instances.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check UDP enable and BSD init status.  */
    if (status)
        error_counter++;
}

static void test_udp4_connect(void)
{
int sockfd;
struct sockaddr_in  remote_addr, local_addr;
int                 ret;
char                buf[30];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);


    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;
    
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(54321);
    remote_addr.sin_addr.s_addr = htonl(ip1_address[1]);

    ret = connect(sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
    if(ret < 0)
       error_counter++;
    
    ret = recv(sockfd, buf, sizeof(buf), 0);

    if((ret != (int)strlen(requests_ipv4[1])) || (strncmp(buf, requests_ipv4[1], strlen(requests_ipv4[1]))))
        error_counter++;
    tx_thread_sleep(1);
    ret = send(sockfd, response_ipv4[1], strlen(response_ipv4[1]), 0);
    if(ret != (int)strlen(response_ipv4[1]))
        error_counter++;



    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;
}

#ifdef FEATURE_NX_IPV6
static void test_udp6_connect(void)
{
int sockfd;
struct sockaddr_in6  remote_addr, local_addr;
int                  ret;
char                 buf[30];

    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons(12345);



    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;
    
    remote_addr.sin6_family = AF_INET6;
    remote_addr.sin6_port = htons(54321);
    remote_addr.sin6_addr._S6_un._S6_u32[0] = htonl(ipv6_address_ip1[1][1].nxd_ip_address.v6[0]);
    remote_addr.sin6_addr._S6_un._S6_u32[1] = htonl(ipv6_address_ip1[1][1].nxd_ip_address.v6[1]);
    remote_addr.sin6_addr._S6_un._S6_u32[2] = htonl(ipv6_address_ip1[1][1].nxd_ip_address.v6[2]);
    remote_addr.sin6_addr._S6_un._S6_u32[3] = htonl(ipv6_address_ip1[1][1].nxd_ip_address.v6[3]);

    ret = connect(sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
    if(ret < 0)
       error_counter++;
    
    ret = recv(sockfd, buf, sizeof(buf), 0);

    if((ret != (INT)strlen(requests_ipv6[3])) || (strncmp(buf, requests_ipv6[3], strlen(requests_ipv6[3]))))
        error_counter++;

    ret = send(sockfd, response_ipv6[3], strlen(response_ipv6[3]), 0);
    if(ret != (INT)strlen(response_ipv6[3]))
        error_counter++;

    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;
}
#endif
/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
#ifdef FEATURE_NX_IPV6    
static char mac_ip0[6];
static char mac_ip1[6];
UINT status;
int i,j;
#endif


    printf("NetX Test:   Basic BSD UDP Connect Test....................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6    

    for(i = 0; i < 3; i++)
    {
        mac_ip0[0] = (char)(ip_0.nx_ip_interface[i].nx_interface_physical_address_msw >> 8);
        mac_ip0[1] = ip_0.nx_ip_interface[i].nx_interface_physical_address_msw & 0xFF;
        mac_ip0[2] = (ip_0.nx_ip_interface[i].nx_interface_physical_address_lsw >> 24) & 0xff;
        mac_ip0[3] = (ip_0.nx_ip_interface[i].nx_interface_physical_address_lsw >> 16) & 0xff;
        mac_ip0[4] = (ip_0.nx_ip_interface[i].nx_interface_physical_address_lsw >> 8) & 0xff;
        mac_ip0[5] = ip_0.nx_ip_interface[i].nx_interface_physical_address_lsw  & 0xff;
        
        mac_ip1[0] = (char)(ip_1.nx_ip_interface[i].nx_interface_physical_address_msw >> 8);
        mac_ip1[1] = ip_1.nx_ip_interface[i].nx_interface_physical_address_msw & 0xFF;
        mac_ip1[2] = (ip_1.nx_ip_interface[i].nx_interface_physical_address_lsw >> 24) & 0xff;
        mac_ip1[3] = (ip_1.nx_ip_interface[i].nx_interface_physical_address_lsw >> 16) & 0xff;
        mac_ip1[4] = (ip_1.nx_ip_interface[i].nx_interface_physical_address_lsw >> 8) & 0xff;
        mac_ip1[5] = ip_1.nx_ip_interface[i].nx_interface_physical_address_lsw  & 0xff;

        for(j = 0; j < 3; j ++)
        {
            if(j == 0)
            {
                /* First set up IPv6 linklocal addresses. */
                ipv6_address_ip0[i][j].nxd_ip_version = NX_IP_VERSION_V6;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[0] = 0xfe800000;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[1] = 0x00000000;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[2] = ((mac_ip0[0] | 0x2) << 24) | (mac_ip0[1] << 16) | (mac_ip0[2] << 8) | 0xFF;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[3] = (0xFE << 24) | ((mac_ip0[3] | 0x2) << 16) | (mac_ip0[4] << 8) | mac_ip0[5];
        
                ipv6_address_ip1[i][j].nxd_ip_version = NX_IP_VERSION_V6;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[0] = 0xfe800000;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[1] = 0x00000000;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[2] = 
                    ((mac_ip1[0] | 0x2) << 24) | (mac_ip1[1] << 16) | (mac_ip1[2] << 8) | 0xFF;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[3] = 
                    (0xFE << 24) | ((mac_ip1[3] | 0x2) << 16) | (mac_ip1[4] << 8) | mac_ip1[5];
        
                status = nxd_ipv6_address_set(&ip_0, i, &ipv6_address_ip0[i][j], 10, NX_NULL);
                status += nxd_ipv6_address_set(&ip_1, i, &ipv6_address_ip1[i][j], 10, NX_NULL);
            }
            else
            {
                /* Global Adddress */
                ipv6_address_ip0[i][j].nxd_ip_version = NX_IP_VERSION_V6;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[0] = 0x20000000 + i;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[1] = j;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[2] = ipv6_address_ip0[i][0].nxd_ip_address.v6[2];
                ipv6_address_ip0[i][j].nxd_ip_address.v6[3] = ipv6_address_ip0[i][0].nxd_ip_address.v6[3];
        
                ipv6_address_ip1[i][j].nxd_ip_version = NX_IP_VERSION_V6;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[0] = 0x20000000 + i;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[1] = j;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[2] = ipv6_address_ip1[i][0].nxd_ip_address.v6[2];
                ipv6_address_ip1[i][j].nxd_ip_address.v6[3] = ipv6_address_ip1[i][0].nxd_ip_address.v6[3];

        
                status = nxd_ipv6_address_set(&ip_0, i, &ipv6_address_ip0[i][j], 64, NX_NULL);
                status += nxd_ipv6_address_set(&ip_1, i, &ipv6_address_ip1[i][j], 64, NX_NULL);
            }
            status += nxd_nd_cache_entry_set(&ip_0, ipv6_address_ip1[i][j].nxd_ip_address.v6, 0,  mac_ip1);
            status += nxd_nd_cache_entry_set(&ip_1, ipv6_address_ip0[i][j].nxd_ip_address.v6, 0,  mac_ip0);        
        }

    }



    status += nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    


    if(status)
        error_counter++;
#endif
    
    test_udp4_connect();
    tx_thread_sleep(3);

#ifdef FEATURE_NX_IPV6    
    
    test_udp6_connect(); 

    tx_thread_sleep(1);
#endif
    

    validate_bsd_structure();

    if(error_counter)
        printf("ERROR!\n");
    else
        printf("SUCCESS!\n");

    if(error_counter)
        test_control_return(1);    

    test_control_return(0);    
}

static void    udp_client_to_AF_INET_AF_INET6(int if_index, int addr_index, int test_case)
{

UINT            status;
NX_PACKET       *packet_ptr;
int             i;
#ifdef FEATURE_NX_IPV6
int j;
#endif

    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 10);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind to a UDP port. */
    status = nx_udp_socket_bind(&server_socket, 54321, NX_WAIT_FOREVER);
    if(status)
        error_counter++;

    for(i = 2; i >= 0; i--)
    {
    
        /* Allocate a packet. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;
    
        /* Fill in the packet with data */
        memcpy(packet_ptr -> nx_packet_prepend_ptr, requests_ipv4[i], strlen(requests_ipv4[i]));
    
        packet_ptr -> nx_packet_length = strlen(requests_ipv4[i]);
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;


        /* Send a UDP packet */
        status =  nx_udp_socket_send(&server_socket, packet_ptr, ip0_address[i], 12345);
        if(status)
            error_counter++;

        status = nx_udp_socket_receive(&server_socket, &packet_ptr, 3);
        if((test_case == 0) && (if_index == i))
        {
            if(status != NX_SUCCESS)
            {
                error_counter++;
            }
            else
            {
                if((packet_ptr -> nx_packet_length != strlen(response_ipv4[1])) || 
                   (strncmp(response_ipv4[1], (char*)packet_ptr -> nx_packet_prepend_ptr, packet_ptr -> nx_packet_length)))
                    error_counter++;
            }
        }
        else if(status == NX_SUCCESS)
            error_counter++;
        
#ifdef FEATURE_NX_IPV6    
        for(j = 0; j < 2; j++)
        {
            /* Allocate a packet. */
            status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
            if (status)
                error_counter++;

            /* Fill in the packet with data */
            memcpy(packet_ptr -> nx_packet_prepend_ptr, requests_ipv6[i * 3 + j], strlen(requests_ipv6[i * 3 + j]));
            
            packet_ptr -> nx_packet_length = strlen(requests_ipv6[i * 3 + j]);
            packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;
            
            
            /* Send a UDP packet */
            status =  nxd_udp_socket_send(&server_socket, packet_ptr, &ipv6_address_ip0[i][j + 1], 12345);
            if(status)
                error_counter++;

            status = nx_udp_socket_receive(&server_socket, &packet_ptr, 1);
            if((if_index == i) && (j == addr_index))
            {
                if(status != NX_SUCCESS)
                {
                    error_counter++;
                }
                else
                {
                    if((packet_ptr -> nx_packet_length != strlen(response_ipv6[3])) || 
                       (strncmp(response_ipv6[3], (char*)packet_ptr -> nx_packet_prepend_ptr, packet_ptr -> nx_packet_length)))
                        error_counter++;
                }
            }
        
            else if(status == NX_SUCCESS)
                error_counter++;
            

        }
#endif

    }

    status = nx_udp_socket_unbind(&server_socket);
    if(status)
        error_counter++;

    status = nx_udp_socket_delete(&server_socket);
    if(status)
        error_counter++;



}


static void    ntest_1_entry(ULONG thread_input)
{
ULONG           actual_status;
UINT            status;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(3);
    }

    tx_thread_sleep(1);

    udp_client_to_AF_INET_AF_INET6(1, 30, 0);

    tx_thread_sleep(2);

#ifdef FEATURE_NX_IPV6
    udp_client_to_AF_INET_AF_INET6(1, 0, 1);
#endif


}

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
void    netx_bsd_udp_connect_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD UDP Connect Test....................N/A\n"); 

    test_control_return(3);  
}      
#endif
