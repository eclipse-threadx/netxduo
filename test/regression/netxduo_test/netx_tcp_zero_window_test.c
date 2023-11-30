/* This case tests zero window probe is implemented.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048
#define     WINDOW_SIZE             128


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static UCHAR                   send_buff[WINDOW_SIZE];
static UCHAR                   recv_buff[WINDOW_SIZE];
static UCHAR                   zero_window_probe;
static UCHAR                   zero_window_probe_ack;
#ifdef NX_ENABLE_DUAL_PACKET_POOL
static NX_PACKET_POOL          my_auxiliary_pool;
#endif /* NX_ENABLE_DUAL_PACKET_POOL */
static NX_PACKET_POOL          no_packet_pool;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
#endif /* FEATURE_NX_IPV6 */

/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    advanced_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_zero_window_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;
NX_PACKET *pkt_ptr;
UINT    header_size = sizeof(NX_PACKET);

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

#ifdef NX_PACKET_ALIGNMENT
    pointer = (CHAR *)(((ALIGN_TYPE)pointer + NX_PACKET_ALIGNMENT - 1) / NX_PACKET_ALIGNMENT * NX_PACKET_ALIGNMENT);
    header_size = (header_size + NX_PACKET_ALIGNMENT - 1) / NX_PACKET_ALIGNMENT * NX_PACKET_ALIGNMENT;
#endif /* NX_PACKET_ALIGNMENT */

#ifdef NX_ENABLE_DUAL_PACKET_POOL
    /* Create an auxiliary packet pool. */
    status =  nx_packet_pool_create(&my_auxiliary_pool, "NetX Auxiliary Packet Pool", 256, pointer, (256 + header_size));
    pointer = pointer + 256 + header_size;

    if (status)
        error_counter++;
#endif /* NX_ENABLE_DUAL_PACKET_POOL */

    /* Create a packet pool with no packet. */
    status =  nx_packet_pool_create(&no_packet_pool, "NetX No Packet Pool", 256, pointer, (256 + header_size));
    pointer = pointer + 256 + header_size;

    if (status)
        error_counter++;

    /* Allocate the only one packet from pool. */
    nx_packet_allocate(&no_packet_pool, &pkt_ptr, NX_TCP_PACKET, NX_NO_WAIT);

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create a packet pool with payload not four bytes aligned.  */
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;
                                     
    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_2.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_2.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_2.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[3] = 0x10000002;   

    /* Set interfaces' address */
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);

    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status = nxd_ipv6_enable(&ip_1);

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    if(status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
                                     
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;
UINT        i;
ULONG       tcp_transmit_window;
#ifdef NX_ENABLE_DUAL_PACKET_POOL
NX_PACKET  *waste_packet;
#endif /* NX_ENABLE_DUAL_PACKET_POOL */

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Zero Window Test......................................");

#ifdef FEATURE_NX_IPV6
    /* Sleep 5 seconds for DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    for (i = 0; i < sizeof(send_buff); i++)
    {
        send_buff[i] = 0x01;
        recv_buff[i] = 0x00;
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                            NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, WINDOW_SIZE,
                            NX_NULL, NX_NULL);
                            
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    for (i = 0; i < 4; i++)
#else
    for (i = 0; i < 2; i++)
#endif /* FEATURE_NX_IPV6 */
    {

        zero_window_probe = 0;
        zero_window_probe_ack = 0;

        /* Attempt to connect the socket.  */
#ifdef FEATURE_NX_IPV6
        if (i > 1)
        {
            status = nxd_tcp_client_socket_connect(&client_socket, &ipv6_address_2, 12, 5 * NX_IP_PERIODIC_RATE);
        }
        else
#endif /* FEATURE_NX_IPV6 */
        {

            status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);
        }

        /* Check for error.  */
        if (status)
            error_counter++;

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            error_counter++;

        /* Write send_buff into the packet payload!  */
        status = nx_packet_data_append(my_packet, send_buff, WINDOW_SIZE, &pool_0, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            error_counter++;

        /* Send the packet out!  */
        status =  nx_tcp_socket_send(&client_socket, my_packet, 5 * NX_IP_PERIODIC_RATE);

        /* Determine if the status is valid.  */
        if (status)
        {
            error_counter++;
            nx_packet_release(my_packet);
        }

        /* Get TCP transmit window size. */
        status = nx_tcp_socket_info_get(&client_socket, NX_NULL, NX_NULL,
                                        NX_NULL, NX_NULL,
                                        NX_NULL, NX_NULL,
                                        NX_NULL, NX_NULL,
                                        NX_NULL, &tcp_transmit_window,
                                        NX_NULL);
        
        /* Check for error */
        if (status)
        {
            error_counter++;
        }

        /* Check transmit window. */
        if (tcp_transmit_window != 0)
        {
            error_counter++;
        }

        /* Sleep one second to make sure ACK is received. */
        tx_thread_sleep(NX_IP_PERIODIC_RATE);

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            error_counter++;

        /* Write send_buff into the packet payload!  */
        status = nx_packet_data_append(my_packet, "ABC", 3, &pool_0, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            error_counter++;

        if (i & 1)
        {

            /* Set both pools with no packets. */
            ip_0.nx_ip_default_packet_pool = &no_packet_pool;
#ifdef NX_ENABLE_DUAL_PACKET_POOL
            ip_0.nx_ip_auxiliary_packet_pool = &my_auxiliary_pool;
#endif /* NX_ENABLE_DUAL_PACKET_POOL */

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
            /* Disable all interface capability. */
            nx_ip_interface_capability_set(&ip_0, 0, 0);
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */
        }
#ifdef NX_ENABLE_DUAL_PACKET_POOL
        else
        {

            /* Set the same pool with no packets. */
            ip_0.nx_ip_default_packet_pool = &my_auxiliary_pool;
            ip_0.nx_ip_auxiliary_packet_pool = &my_auxiliary_pool;

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
            /* Enable all TX checksum capability. */
            nx_ip_interface_capability_set(&ip_0, 0, NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM | 
                                                     NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_UDP_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV4_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_ICMPV6_TX_CHECKSUM |
                                                     NX_INTERFACE_CAPABILITY_IGMP_TX_CHECKSUM);
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */
        }

        /* Allocate all packets from auxiliary pool. */
        status = nx_packet_allocate(&my_auxiliary_pool, &waste_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            error_counter++;
#endif /* NX_ENABLE_DUAL_PACKET_POOL */

        /* Send the packet out!  */
        /* Window is full, so it can't be sent. */
        status =  nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);

        /* Determine if the status is valid.  */
        if (status == NX_SUCCESS)
        {

            /* Packet should not be sent. */
            error_counter++;
        }

#ifdef NX_ENABLE_DUAL_PACKET_POOL
        /* Release wasted packet. */
        nx_packet_release(waste_packet);
#endif /* NX_ENABLE_DUAL_PACKET_POOL */

        /* Use auxiliary packet pool and default pool together.  */
        ip_0.nx_ip_default_packet_pool = &pool_0;
#ifdef NX_ENABLE_DUAL_PACKET_POOL
        ip_0.nx_ip_auxiliary_packet_pool = &my_auxiliary_pool;
#endif /* NX_ENABLE_DUAL_PACKET_POOL */

        /* Window is full, so it can't be sent until timeout. */
        status =  nx_tcp_socket_send(&client_socket, my_packet, 
                                     (client_socket.nx_tcp_socket_timeout_max_retries + 2) * NX_IP_PERIODIC_RATE);

        /* Determine if the status is valid.  */
        if (status)
        {
            nx_packet_release(my_packet);
        }
        else
        {

            /* Packet should not be sent. */
            error_counter++;
        }

        /* Whether socket is still established. */
        if (client_socket.nx_tcp_socket_state == NX_TCP_CLOSED)
        {

            /* Connection is closed. */
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Set callback function to drop all zero window probe ACK. */
        advanced_packet_process_callback = advanced_packet_process;
        tx_thread_sleep((client_socket.nx_tcp_socket_timeout_max_retries + 2) * NX_IP_PERIODIC_RATE);

        /* Whether socket is still established. */
        if (client_socket.nx_tcp_socket_state != NX_TCP_CLOSED)
        {
            error_counter++;
        }

        /* Check zero window probe received. */
        if ((zero_window_probe != client_socket.nx_tcp_socket_timeout_max_retries) || 
            (zero_window_probe_ack != client_socket.nx_tcp_socket_timeout_max_retries)) 
        {
            error_counter++;
        }

        /* Clear callback function. */
        advanced_packet_process_callback = NX_NULL;

        /* Wakeup server thread. */
        tx_thread_resume(&thread_1);
    }

    /* Check status.  */
    if (error_counter)
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

UINT    status;
UINT    i;

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, WINDOW_SIZE,
                                NX_NULL, NX_NULL);
    
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    for (i = 0; i < 4; i++)
#else
    for (i = 0; i < 2; i++)
#endif /* FEATURE_NX_IPV6 */
    {

        /* Accept a client socket connection.  */
        status =  nx_tcp_server_socket_accept(&server_socket, NX_WAIT_FOREVER);

        /* Check for error.  */
        if (status)
            error_counter++;

        /* Suspend server thread. */
        tx_thread_suspend(&thread_1);

        /* Reset connection. */
        nx_tcp_socket_disconnect(&server_socket, NX_NO_WAIT);
        nx_tcp_server_socket_unaccept(&server_socket);
        nx_tcp_server_socket_relisten(&ip_1, 12, &server_socket);
    }
}

static UINT    advanced_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    /* Drop zero window probe from ip_0. */
    if (ip_ptr == &ip_0)
    {

        /* Is the length match TCP zero window probe packet? */
        if ((packet_ptr -> nx_packet_length == 41) ||
            (packet_ptr -> nx_packet_length == 61))
        {

            /* Yes it is. */
            /* Check one byte data. */
            if (*(packet_ptr -> nx_packet_append_ptr - 1) == 'A')
            {

                /* It's zero window probe packet. */
                zero_window_probe++;
            }
        }
        return NX_TRUE;
    }

    /* Is the length match TCP ACK packet? */
    if ((packet_ptr -> nx_packet_length == 40) || (packet_ptr -> nx_packet_length == 60))
    {

        /* Yes it is. Drop it. */
        zero_window_probe_ack++;
        *operation_ptr = NX_RAMDRIVER_OP_DROP;
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_zero_window_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Zero Window Test......................................N/A\n");

    test_control_return(3);  
}      
#endif
