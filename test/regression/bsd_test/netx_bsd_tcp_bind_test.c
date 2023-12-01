/* This NetX test concentrates on the basic BSD TCP blocking operation.  */
/* The BSD APIs involved in this test are:  socket(), connect(), send(), soc_close() */

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
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            140
/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   packet_pool_area[(256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 8 / 4];
static ULONG stack_space[NUM_CLIENTS][DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_THREAD helper_thread[NUM_CLIENTS];
static TX_SEMAPHORE server_done_sema, test_done_sema, sema_0;
static int test_case = 0;
/* Define thread prototypes.  */
static TX_MUTEX                protection;
static int                     count;
static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS ipv6_address_ip0[3][3];
static NXD_ADDRESS ipv6_address_ip1[3][3];
#endif
static char *requests = "Request1";
static void validate_bsd_structure(void);
static VOID bsd_server_helper_thread_entry(ULONG thread_input);

#define IP0_IF0_V4_ADDR   IP_ADDRESS(1,2,3,4)  
#define IP0_IF1_V4_ADDR   IP_ADDRESS(2,2,3,4)  
#define IP0_IF2_V4_ADDR   IP_ADDRESS(3,2,3,4)  

#define IP1_IF0_V4_ADDR   IP_ADDRESS(1,2,3,5)  
#define IP1_IF1_V4_ADDR   IP_ADDRESS(2,2,3,5)  
#define IP1_IF2_V4_ADDR   IP_ADDRESS(3,2,3,5)  

static ULONG ip0_address[3] = {IP0_IF0_V4_ADDR, IP0_IF1_V4_ADDR, IP0_IF2_V4_ADDR};
static ULONG ip1_address[3] = {IP1_IF0_V4_ADDR, IP1_IF1_V4_ADDR, IP1_IF2_V4_ADDR};


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_bind_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    memset(helper_thread, 0, sizeof(TX_THREAD) * NUM_CLIENTS);
    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, packet_pool_area, sizeof(packet_pool_area));


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

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
    
    status = tx_semaphore_create(&server_done_sema, "server done", 0);
    status += tx_semaphore_create(&test_done_sema, "test done", 0);
    status += tx_semaphore_create(&sema_0, "SEMA 0", 0);

    if (status)
        error_counter++;
}
typedef struct client_info_struct
{
    int sockfd;
    int message_id;
} client_info;

static client_info client_data[NUM_CLIENTS];

#if 0
static void test_tcp_server4_6_bind_synch(void)
{
int thread_count, test_case_count, i;
UINT status = 0;

    switch(test_case)
    {
    case 0: thread_count = 5; test_case_count = 9; break;
    case 1: thread_count = 5; test_case_count = 9; break;
    case 2: thread_count = 4; test_case_count = 7; break;
    case 3: thread_count = 4; test_case_count = 4; break;
    case 4: thread_count = 3; break;
    }
    
    /* Let all the server threads run. */
    for(i = 0; i < thread_count; i++)
        tx_semaphore_put(&server_wait_sema);

    /* Let the client run. */
    tx_semaphore_put(&client_wait_sema);

    /* Wait for all tests to finish. */
    if(test_case != 4)
    {
        for(i = 0; i < test_case_count; i++)
        {
            status = tx_semaphore_get(&server_done_sema, 5 * NX_IP_PERIODIC_RATE);
            if(status != TX_SUCCESS)
                error_counter++;
        
        }
    }
}
#endif
static VOID bsd_server4_helper_thread_test_2(ULONG param)
{
int                sockfd;
struct sockaddr_in remote_addr,local_addr;
int                address_length;
int                ret;
int                newsock;
int                index;
UINT               status;
INT                reuseaddr = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;

    /* Test bind to port 0. */
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = 0;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    address_length = sizeof(local_addr);
    ret = getsockname(sockfd, (struct sockaddr*)&local_addr, &address_length);
    if(ret < 0)
        error_counter++;

    /* Check whether port is zero. */
    if (local_addr.sin_port == 0)
        error_counter++;
    soc_close(sockfd);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(INT));

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    if(param < 3)
        local_addr.sin_addr.s_addr = htonl(ip0_address[param]);
    else
        local_addr.sin_addr.s_addr = INADDR_ANY;
    
    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;
    
    ret = listen(sockfd, 5);
    if(ret < 0)
        error_counter++;    



    while(1)
    {
        if((test_case == 1) && (param == 1))
            break;
        if((test_case == 2) && (param == 3))
            break;

        if(test_case == 4)
            break;

        address_length = sizeof(remote_addr);
        newsock = accept(sockfd, (struct sockaddr*)&remote_addr, &address_length);
        if(newsock < 0)
            error_counter++;
        if(address_length != sizeof(remote_addr))
            error_counter++;
        
        if(param < 3)
            if((remote_addr.sin_family != AF_INET) || (remote_addr.sin_addr.s_addr != htonl(ip1_address[param])))
                error_counter++;

        if(newsock > 0)
        {
            tx_mutex_get(&protection, 5 * NX_IP_PERIODIC_RATE);
            index = count;
            count++;
            tx_mutex_put(&protection);
            client_data[index].sockfd = newsock;
            client_data[index].message_id = 0xFFFF;
            
            status = tx_thread_create(&helper_thread[index], "helper thread", bsd_server_helper_thread_entry,
                                      index, stack_space[index], DEMO_STACK_SIZE, 2, 2, TX_NO_TIME_SLICE,
                                      TX_AUTO_START);
            if(status)
                error_counter++;
        }
    }
    if(soc_close(sockfd) < 0)
        error_counter++;
    
    tx_semaphore_put(&server_done_sema);
}

#ifdef FEATURE_NX_IPV6
static VOID bsd_server6_helper_thread_test_2(ULONG param)
{
int                 sockfd;
struct sockaddr_in6 remote_addr,local_addr;
int                 address_length;
int                 ret;
int                 newsock;
int                 if_index, addr_index, index;
INT                 reuseaddr = 1;
   
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(INT));

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons(12345);
    if(param != 0xFF00)
    {
        if_index = param >> 8;
        addr_index = param & 0xFF;
        local_addr.sin6_addr._S6_un._S6_u32[0] = htonl(ipv6_address_ip0[if_index][addr_index].nxd_ip_address.v6[0]);
        local_addr.sin6_addr._S6_un._S6_u32[1] = htonl(ipv6_address_ip0[if_index][addr_index].nxd_ip_address.v6[1]);
        local_addr.sin6_addr._S6_un._S6_u32[2] = htonl(ipv6_address_ip0[if_index][addr_index].nxd_ip_address.v6[2]);
        local_addr.sin6_addr._S6_un._S6_u32[3] = htonl(ipv6_address_ip0[if_index][addr_index].nxd_ip_address.v6[3]);
    }

    
    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;
    
    ret = listen(sockfd, 5);
    if(ret < 0)
        error_counter++;    




    while(1)
    {
        if((test_case == 3) && (param == 0xFF00))
            break;

        if(test_case == 4)
            break;

        address_length = sizeof(remote_addr);
        newsock = accept(sockfd, (struct sockaddr*)&remote_addr, &address_length);
        if(newsock < 0)
            error_counter++;
        if(address_length != sizeof(remote_addr))
            error_counter++;
        
        if(param != 0xFF00)
        {
            if((remote_addr.sin6_family != AF_INET6) || 
               (remote_addr.sin6_addr._S6_un._S6_u32[0] != htonl(ipv6_address_ip1[if_index][addr_index].nxd_ip_address.v6[0])) ||
               (remote_addr.sin6_addr._S6_un._S6_u32[1] != htonl(ipv6_address_ip1[if_index][addr_index].nxd_ip_address.v6[1])) ||
               (remote_addr.sin6_addr._S6_un._S6_u32[2] != htonl(ipv6_address_ip1[if_index][addr_index].nxd_ip_address.v6[2])) ||
               (remote_addr.sin6_addr._S6_un._S6_u32[3] != htonl(ipv6_address_ip1[if_index][addr_index].nxd_ip_address.v6[3])))
                error_counter++;
        }

        if(newsock > 0)
        {

            tx_mutex_get(&protection, 5 * NX_IP_PERIODIC_RATE);
            index = count;
            count++;
            tx_mutex_put(&protection);
            client_data[index].sockfd = newsock;
            client_data[index].message_id = 0xFFFF;
            
            tx_thread_create(&helper_thread[index], "helper thread", bsd_server_helper_thread_entry,
                             index, stack_space[index], DEMO_STACK_SIZE, 2, 2, TX_NO_TIME_SLICE,
                             TX_AUTO_START);
        }

    }
    if(soc_close(sockfd) < 0)
        error_counter++;

    tx_semaphore_put(&server_done_sema);
}
#endif

static VOID test_tcp_server4_6_bind(void)
{
#ifdef FEATURE_NX_IPV6
UINT status;
int  index;

    tx_mutex_get(&protection, 5 * NX_IP_PERIODIC_RATE);
    index = count;
    count = count + 5;
    tx_mutex_put(&protection);
    
    /* Create a thread that binds to the first IPv4 interface. */
    status = tx_thread_create(&helper_thread[index], (CHAR*)"IPv4 if0", bsd_server4_helper_thread_test_2,
                              0, stack_space[index], DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
                              
    /* Create a thread that binds to the 2nd IPv4 interface. */    
    status += tx_thread_create(&helper_thread[index + 1], "IPv4 if1", bsd_server4_helper_thread_test_2,
                               1, stack_space[index + 1], DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Create a thread that binds to the IPv4 INADDR_ANY */
    status += tx_thread_create(&helper_thread[index + 2], "IPv4 if_any", bsd_server4_helper_thread_test_2,
                               3, stack_space[index + 2], DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Create a thread that binds to the 1st IPv6 address of the 2nd interface IPv6 address. */
    status += tx_thread_create(&helper_thread[index + 3], "IPv6 if0", bsd_server6_helper_thread_test_2,
                               0x0101, stack_space[index + 3], DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    /* Create a thread that binds to INADDR6_ANY */
    status += tx_thread_create(&helper_thread[index + 4], "IPv6 if_any", bsd_server6_helper_thread_test_2,
                               0xFF00, stack_space[index + 4], DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    /* The first test is to make sure they can all make connections with only the ones they are assigned to. */
    if(status)
        error_counter++;

#if 0
    test_tcp_server4_6_bind_synch();

    test_case = 1; /* Kill socket binds to the 2nd IPv4 interface. */

    test_tcp_server4_6_bind_synch();

    test_case = 2;/* Kill socket binds to IPv4 INADDR_ANY. */

    test_tcp_server4_6_bind_synch();

    test_case = 3; /* Kill socket binds to IPv6 INADDR_ANY */

    /* Create a thread that binds to the IPv4 INADDR_ANY */
    status = tx_thread_create(&helper_thread[index + 2], "IPv4 if_any", bsd_server4_helper_thread_test_2,
                              3, stack_space[index + 2], DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);



    test_tcp_server4_6_bind_synch();

    
    test_case = 4; /* Done. */
    test_tcp_server4_6_bind_synch();

#endif
    tx_semaphore_get(&test_done_sema, 5 * NX_IP_PERIODIC_RATE);

#endif
    
}

static VOID bsd_server_helper_thread_entry(ULONG thread_input)
{
int         ret;
int         sockfd, message_id;
char        buf[30];

    sockfd = client_data[thread_input].sockfd;
    message_id = client_data[thread_input].message_id;
    /* Receive data from the client. */

    ret = recv(sockfd, buf, sizeof(buf), 0);
    if(ret <= 0)
        error_counter++;

    /* Validate the data. */
    if((ret != (int)strlen(requests)) || strncmp(buf, requests, ret))
        error_counter++;
    
    /* Send a response back. */
    ret = send(sockfd, buf, ret, 0);
    if(ret <= 0)
        error_counter++;

    tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    if(message_id == 0xFFFF)
        tx_semaphore_put(&server_done_sema);
    return;
}


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
#ifdef FEATURE_NX_IPV6    
char mac_ip0[6];
char mac_ip1[6];
UINT status;
int i,j;
#endif


    tx_mutex_create(&protection, "test protection", TX_NO_INHERIT);
    count = 0;


    printf("NetX Test:   Basic BSD TCP Bind Test.......................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#ifdef FEATURE_NX_IPV6    
    /* First set up IPv6 addresses. */

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

    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif    

    tx_semaphore_put(&server_done_sema);

    test_tcp_server4_6_bind();

    /* Done. */
    tx_semaphore_delete(&server_done_sema);
    tx_semaphore_delete(&test_done_sema);
    tx_semaphore_delete(&sema_0);

    validate_bsd_structure();

    if(error_counter)
        printf("ERROR!\n");
    else
        printf("SUCCESS!\n");

    if(error_counter)
        test_control_return(1);    

    test_control_return(0);    
}
    
static NX_TCP_SOCKET tcp_sockets;
static void    test_client_bind(void)
{

int           i, j;
UINT          status = NX_SUCCESS;
NX_PACKET     *packet_ptr;


    for(i = 0; i < 3; i++)
    {
        for(j = 0; j < 3; j++)
        {
            status =  nx_tcp_socket_create(&ip_1, &tcp_sockets, "Server Socket", 
                                           NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                           NX_NULL, NX_NULL);
            status +=  nx_tcp_client_socket_bind(&tcp_sockets, NX_ANY_PORT, 0);
            
            if(status != NX_SUCCESS)
                error_counter++;
            
#ifdef FEATURE_NX_IPV6
            if(j == 0)
                status = nx_tcp_client_socket_connect(&tcp_sockets, ip0_address[i], 12345, NX_IP_PERIODIC_RATE / 5);
            else
                status = nxd_tcp_client_socket_connect(&tcp_sockets, &ipv6_address_ip0[i][j], 12345, NX_IP_PERIODIC_RATE / 5);
#else
            status = nx_tcp_client_socket_connect(&tcp_sockets, ip0_address[i], 12345, NX_IP_PERIODIC_RATE / 5);
#endif
            
            if(status != NX_SUCCESS)
            {
                status = nx_tcp_client_socket_unbind(&tcp_sockets);
                status += nx_tcp_socket_delete(&tcp_sockets);
                
                if(status)
                    error_counter++;
                continue;
            }
            
            status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
            status += nx_packet_data_append(packet_ptr, requests, strlen(requests),
                                            &pool_0, NX_NO_WAIT);
            status += nx_tcp_socket_send(&tcp_sockets, packet_ptr, 2);
            if(status != NX_SUCCESS)
                error_counter++;
#if 0
            tx_thread_sleep(1);
#endif
            status = nx_tcp_socket_receive(&tcp_sockets, &packet_ptr, 2 * NX_IP_PERIODIC_RATE);
            if(status != NX_SUCCESS)
                error_counter++;
            /* Validate the received data. */
            else if(packet_ptr -> nx_packet_length != strlen(requests))
                error_counter++;
            else if(strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, requests, packet_ptr -> nx_packet_length))
                error_counter++;
            if(status == NX_SUCCESS)
                nx_packet_release(packet_ptr);
            
            tx_semaphore_put(&sema_0);
            status = nx_tcp_socket_disconnect(&tcp_sockets, 1 * NX_IP_PERIODIC_RATE);
            if(status == NX_NOT_CONNECTED || status == NX_DISCONNECT_FAILED)
                status = 0;
            if(tcp_sockets.nx_tcp_socket_bound_next)
                status += nx_tcp_client_socket_unbind(&tcp_sockets);
            

            status += nx_tcp_socket_delete(&tcp_sockets);
                
            if(status != NX_SUCCESS)
                error_counter++;
        }
    }
}

static void    ntest_1_entry(ULONG thread_input)
{

UINT            status;
ULONG           actual_status;
int             i;
int             index;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(3);
    }
    tx_semaphore_get(&server_done_sema, TX_WAIT_FOREVER);

    /* Simulate a multiple client conneting to the same server. */
    test_client_bind();

    for(i = 0; i < 9; i++)
        tx_semaphore_get(&server_done_sema, 5 * NX_IP_PERIODIC_RATE);

    test_case = 1; /* Kill socket binds to the 2nd IPv4 interface. */
    test_client_bind();    
    for(i = 0; i < 10; i++)
        tx_semaphore_get(&server_done_sema, 5 * NX_IP_PERIODIC_RATE);
    test_client_bind();
    for(i = 0; i < 9; i++)
        tx_semaphore_get(&server_done_sema, 5 * NX_IP_PERIODIC_RATE);

    test_case = 2; /* Kill socket binds to IPv4 INADDR_ANY */
    test_client_bind();
    for(i = 0; i < 9; i++)
        tx_semaphore_get(&server_done_sema, 5 * NX_IP_PERIODIC_RATE);
    test_client_bind();
    for(i = 0; i < 7; i++)
        tx_semaphore_get(&server_done_sema, 5 * NX_IP_PERIODIC_RATE);

    test_case = 3; /* Kill socket binds to IPv6 INADDR_ANY */
#if 1
    tx_mutex_get(&protection, 5 * NX_IP_PERIODIC_RATE);
    index = count;
    count++;
    tx_mutex_put(&protection);
#endif
    status = tx_thread_create(&helper_thread[index], "IPv4 if_any", bsd_server4_helper_thread_test_2,
                              3, stack_space[index], DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    test_client_bind();
    for(i = 0; i < 6; i++)
        tx_semaphore_get(&server_done_sema, 5 * NX_IP_PERIODIC_RATE);    
    test_client_bind();
    for(i = 0; i < 4; i++)
        tx_semaphore_get(&server_done_sema, 5 * NX_IP_PERIODIC_RATE);    
    test_case = 4;
    test_client_bind();
    for(i = 0; i < 6; i++)
        tx_semaphore_get(&server_done_sema, 5 * NX_IP_PERIODIC_RATE);    

    tx_semaphore_put(&test_done_sema);

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
void    netx_bsd_tcp_bind_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP Bind Test.......................N/A\n"); 

    test_control_return(3);  
}      
#endif
