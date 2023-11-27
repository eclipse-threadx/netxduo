/* This NetX test concentrates on the packet debug information.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_packet.h"
#include   "nx_ram_network_driver_test_1500.h"
extern VOID    test_control_return(UINT status);

#if defined(NX_ENABLE_PACKET_DEBUG_INFO) && defined(__PRODUCT_NETXDUO__) && (__NETXDUO_MINOR_VERSION__ > 8) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048

#define     TEST_SIZE               1536
#define     PACKET_NUM              16

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NX_TCP_SOCKET           temp_socket;
static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
#endif /* FEATURE_NX_IPV6 */

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
#ifndef NX_DISABLE_FRAGMENTATION
static UCHAR                   buffer[2048];
#endif /* NX_DISABLE_FRAGMENTATION */
static CHAR                   *verify_file;
static NX_PACKET_POOL         *verify_pool;
static UINT                    count; 
static UINT                    operation; 
static UINT                    delay;

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
static VOID    verify_packet(NX_PACKET_POOL *pool_ptr, CHAR *in_files);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
VOID    netx_packet_debug_info_test_application_define(VOID *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    error_counter =  0;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Initialize the NetX system.  */
    nx_system_initialize();


    /* Create first packet pool.  */
    pointer = (CHAR *)(((ALIGN_TYPE)pointer + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1));
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pointer, ((TEST_SIZE + sizeof(NX_PACKET) + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1)) * PACKET_NUM);

    pointer = pointer + (TEST_SIZE + NX_PACKET_ALIGNMENT + sizeof(NX_PACKET)) * PACKET_NUM;
    if (status)
        error_counter++;

    /* Create second packet pool.  */
    pointer = (CHAR *)(((ALIGN_TYPE)pointer + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1));
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", TEST_SIZE, pointer, ((TEST_SIZE + sizeof(NX_PACKET) + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1)) * PACKET_NUM);

    pointer = pointer + (TEST_SIZE + NX_PACKET_ALIGNMENT + sizeof(NX_PACKET)) * PACKET_NUM;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_1500,
        pointer, 2048, 2);
    pointer = pointer + 2048;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (VOID *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (VOID *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check UDP enable status.  */
    if (status)
        error_counter++;

#ifndef NX_DISABLE_FRAGMENTATION
    /* Enable IP fragmentation logic on both IP instances.  */
    status =  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check for IP fragment enable errors.  */
    if (status)
        error_counter++;
#endif /* NX_DISABLE_FRAGMENTATION */


#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 traffic.  */
    status += nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Check IPv6 enable status.  */
    if (status)
        error_counter++;

    /* Set source and destination address with global address. */    
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010DB8;
    address_0.nxd_ip_address.v6[1] = 0x00010001;
    address_0.nxd_ip_address.v6[2] = 0x021122FF;
    address_0.nxd_ip_address.v6[3] = 0xFE334456;

    address_1.nxd_ip_version = NX_IP_VERSION_V6;
    address_1.nxd_ip_address.v6[0] = 0x20010DB8;
    address_1.nxd_ip_address.v6[1] = 0x00010001;
    address_1.nxd_ip_address.v6[2] = 0x021122FF;
    address_1.nxd_ip_address.v6[3] = 0xFE334499;

    status = nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &address_1, 64, NX_NULL);

    /* Check for IPv6 enable errors.  */
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
}


static VOID    verify_packet(NX_PACKET_POOL *pool_ptr, CHAR *in_files)
{
UINT  i;
CHAR *file_info, *p;
ULONG packet_status;
UINT  packet_found = NX_FALSE;
NX_PACKET *packet_ptr;
CHAR *thread_info;
ULONG line_info;

    for (i = 0; i < pool_ptr -> nx_packet_pool_total; i++)
    {
        /* Get debug information. */
        _nx_packet_debug_info_get(pool_ptr, i, &packet_ptr, &packet_status, &thread_info, &file_info, &line_info);

        /* Check if no packets are expected to be allocated. */
        if (in_files == NX_NULL) 
        {
            if (packet_status == NX_PACKET_ALLOCATED)
            {
                error_counter++;
                break;
            }
        }
        else
        {

            /* Check if is the packet looking for? */
            /* Trim path. */
            for(p = file_info + strlen(file_info); p != file_info && *p != '\\' && *p != '/'; p--);

            if(*p == '\\' || *p == '/')
                p++;

            /* Is expected packet found? */
            if(strcmp(in_files, p) == 0)
                packet_found = NX_TRUE;
        }
    }

    /* Check whether packet is found in specified file. */
    if((in_files != NX_NULL) && (packet_found == NX_FALSE))
        error_counter++;
}


/* Define the test threads.  */
static VOID    ntest_0_entry(ULONG thread_input)
{
UINT            status;
NX_PACKET      *packet_ptr;

    printf("NetX Test:   Packet Debug Info Test....................................");

    /* Verify no packet used. */
    verify_packet(&pool_0, NX_NULL);
    verify_packet(&pool_1, NX_NULL);

#ifdef FEATURE_NX_IPV6
    /* Sleep 3 seconds to finish DAD.  */
    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */


    /* Verify ARP/ND and ICMP packet debug information. */
    /* Ping between two IPs. */
    verify_pool = &pool_0;
    verify_file = NX_PACKET_ARP_WAITING_QUEUE;
    advanced_packet_process_callback = my_packet_process;
    operation = NX_RAMDRIVER_OP_BYPASS;
    delay = 0;
    count = 0;
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1,2,3,5), "", 0, &packet_ptr, NX_IP_PERIODIC_RATE);
    if(status == NX_SUCCESS)
    {

        /* Verify packet is processed by nx_icmp_interface_ping.c before passing to application. */
        verify_packet(&pool_0, "nx_icmp_interface_ping.c");
        verify_packet(&pool_1, NX_NULL);
        nx_packet_release(packet_ptr);

        /* Verify no packet used. */
        verify_packet(&pool_0, NX_NULL);
    }

#ifdef FEATURE_NX_IPV6
    verify_pool = &pool_0;
    verify_file = NX_PACKET_ND_WAITING_QUEUE;
    status = nxd_icmp_ping(&ip_0, &address_1, "zzzNzFzHbJKLMNOPQRSTUVWXYZ", 28, &packet_ptr, NX_IP_PERIODIC_RATE);
    if(status == NX_SUCCESS)
    {

        /* Verify packet is processed by nx_icmp_interface_ping6.c before passing to application. */
        verify_packet(&pool_0, "nx_icmp_interface_ping6.c");
        verify_packet(&pool_1, NX_NULL);
        nx_packet_release(packet_ptr);

        /* Verify no packet used. */
        verify_packet(&pool_0, NX_NULL);
    }
#endif /* FEATURE_NX_IPV6 */


    /* Verify TCP packet debug information. */
    /* Create two TCP socket socket.  */
    nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                         NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                         NX_NULL, NX_NULL);

    nx_tcp_socket_create(&ip_0, &temp_socket, "Client Socket", 
                         NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                         NX_NULL, NX_NULL);

    /* Bind the socket.  */
    nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);
    nx_tcp_client_socket_bind(&temp_socket, 13, NX_WAIT_FOREVER);

    /* Attempt to connect server at the same time.  */
    nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_NO_WAIT);
    nx_tcp_client_socket_connect(&temp_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_NO_WAIT);

    /* Verify a SYN packet is in peer's listen queue. */
    verify_packet(&pool_0, NX_NULL);
    verify_packet(&pool_1, NX_PACKET_TCP_LISTEN_QUEUE);

    /* Let remote accpet the connection. */
    tx_thread_resume(&ntest_1);

    /* Disconnect the connection and let the SYN packet be processed. */
    nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);
    nx_tcp_socket_disconnect(&temp_socket, NX_IP_PERIODIC_RATE);
    nx_tcp_client_socket_unbind(&temp_socket);

    /* Verify no packet used. */
    verify_packet(&pool_0, NX_NULL);
    verify_packet(&pool_1, NX_NULL);

    /* Connect server.  */
    nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_WAIT_FOREVER);

    /* Allocate a packet and send to peer. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    verify_packet(&pool_0, "nx_packet_allocate.c");
    nx_packet_data_append(packet_ptr, "ABCD", 4, &pool_0, NX_WAIT_FOREVER);
    verify_packet(&pool_0, "nx_packet_data_append.c");

    /* The packet is in send queue before ACKed. */
    nx_tcp_socket_send(&client_socket, packet_ptr, NX_WAIT_FOREVER);

    /* Verify a packet is in TCP send/receive queue. */
    verify_packet(&pool_0, "nx_tcp_socket_send_internal.c");
    verify_packet(&pool_1, NX_PACKET_TCP_RECEIVE_QUEUE);

    /* Let remote receive the pakcet. */
    tx_thread_resume(&ntest_1);

    nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);


    /* Verify UDP packet debug information. */
    nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Bind the UDP socket to the IP port.  */
    nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);
    nx_udp_socket_bind(&socket_1, 0x88, TX_WAIT_FOREVER);

    /* Allocate a packet.  */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_WAIT_FOREVER);
    nx_packet_data_append(packet_ptr, "ABCD", 4, &pool_0, NX_WAIT_FOREVER);

    /* Send the UDP packet.  */
    if(nx_udp_socket_send(&socket_0, packet_ptr, IP_ADDRESS(1, 2, 3, 5), 0x88))
    {
        error_counter++;
        nx_packet_release(packet_ptr);
    }
    else
    {

        /* Verify a packet is in UDP receive queue. */
        verify_packet(&pool_1, NX_PACKET_UDP_RECEIVE_QUEUE);

        /* Receive a UDP packet.  */
        nx_udp_socket_receive(&socket_1, &packet_ptr, NX_WAIT_FOREVER);
        nx_packet_release(packet_ptr);

        /* Verify no packet used. */
        verify_packet(&pool_0, NX_NULL);
        verify_packet(&pool_1, NX_NULL);
    }


#ifndef NX_DISABLE_FRAGMENTATION
    /* Verify fragmentation packet debug information. */
    /* Allocate a packet.  */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, TX_WAIT_FOREVER);
    nx_packet_data_append(packet_ptr, buffer, sizeof(buffer), &pool_0, NX_WAIT_FOREVER);

    /* Let driver delay the second fragmentation for one second. */
    operation = NX_RAMDRIVER_OP_DELAY;
    delay = 100;
    count = 1;

    /* Send the UDP packet.  */
    if(nx_udp_socket_send(&socket_0, packet_ptr, IP_ADDRESS(1, 2, 3, 5), 0x88))
    {
        error_counter++;
        nx_packet_release(packet_ptr);
    }
    else
    {

        /* Verify a packet is in UDP receive queue. */
        verify_packet(&pool_1, NX_PACKET_IP_FRAGMENT_QUEUE);

        /* Receive a UDP packet.  */
        nx_udp_socket_receive(&socket_1, &packet_ptr, NX_WAIT_FOREVER);
        nx_packet_release(packet_ptr);

        /* Verify no packet used. */
        verify_packet(&pool_0, NX_NULL);
        verify_packet(&pool_1, NX_NULL);
    }
#endif /* NX_DISABLE_FRAGMENTATION */


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


static void    ntest_1_entry(ULONG thread_input)
{

UINT            status;
ULONG           actual_status;
NX_PACKET      *packet_ptr;


    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        error_counter++;
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                NX_NULL, NX_NULL);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    tx_thread_suspend(&ntest_1);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_WAIT_FOREVER);

    /* Disconnect the connection and let the SYN packet be processed. */
    nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);
    nx_tcp_server_socket_unaccept(&server_socket);

    /* Verify the SYN packet is still in listen queue. */
    verify_packet(&pool_1, NX_PACKET_TCP_LISTEN_QUEUE);
    nx_tcp_server_socket_relisten(&ip_1, 12, &server_socket);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_WAIT_FOREVER);

    /* Disconnect the connection and let the SYN packet be processed. */
    nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_relisten(&ip_1, 12, &server_socket);

    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, NX_WAIT_FOREVER);

    tx_thread_suspend(&ntest_1);

    if(nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER))
    {
        error_counter++;
    }
    else
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
        nx_packet_release(packet_ptr);

        /* Verify no packet used. */
        verify_packet(&pool_0, NX_NULL);
        verify_packet(&pool_1, NX_NULL);
    }

    nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);
}


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    if(verify_pool)
    {

        /* Verify packet used. */
        verify_packet(verify_pool, verify_file);
        verify_pool = NX_NULL;
    }

    /* Is there an operation needed? */
    if(operation != NX_RAMDRIVER_OP_BYPASS)
    {
        count--;
        if(count == 0)
        {
            *operation_ptr = operation;
            *delay_ptr = delay;
            operation = NX_RAMDRIVER_OP_BYPASS;
        }
    }

    return NX_TRUE;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
VOID    netx_packet_debug_info_test_application_define(VOID *first_unused_memory)
#endif
{

    printf("NetX Test:   Packet Debug Info Test....................................N/A\n");

    test_control_return(3);
}
#endif /* NX_ENABLE_PACKET_DEBUG_INFO */
