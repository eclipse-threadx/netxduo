/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_FRAGMENTATION) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
#endif /* FEATURE_NX_IPV6 */

static UCHAR                   send_buff[300];
static UCHAR                   recv_buff[300];


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_fragment_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* .  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create two packet pools.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 5120);
    pointer = pointer + 5120;
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 256, pointer, 5120);
    pointer = pointer + 5120;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 traffic.  */
    status += nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Enable ICMP processing for both IP instances.  */
    status +=  nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
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
    status = nxd_ipv6_address_set(&ip_1, 0, &address_1, 64, NX_NULL);

#endif /* FEATURE_NX_IPV6 */

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
    
    /* Enable IP fragmentation logic on both IP instances.  */
    status =  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check for IP fragment enable errors.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        i;
UINT        status;
NX_PACKET   *my_packet;
ULONG       data_len;
#if !defined(NX_DISABLE_IP_INFO) && !defined(NX_DISABLE_PACKET_CHAIN)
ULONG       fragment_failures = 0;
NX_PACKET  *test_packet;
NX_PACKET  *last_packet_1 = NX_NULL;
NX_PACKET  *last_packet_2 = NX_NULL;
#endif 


    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Fragment Test.........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Sleep 5 seconds to finish DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Let thread 1 start to send. */
    tx_thread_resume(&thread_1);

#ifdef NX_FRAGMENT_IMMEDIATE_ASSEMBLY
    /* Receive a packet. */
    status = nx_udp_socket_receive(&socket_0, &my_packet, 3 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
    {

        /* Check whether packet is in sequence. */
        nx_packet_data_retrieve(my_packet, recv_buff, &data_len);
        if(data_len != sizeof(send_buff))
            error_counter++;
        else if(memcmp(send_buff, recv_buff, data_len))
            error_counter++;
        nx_packet_release(my_packet);
    }

    /* Receive a packet. */
    status = nx_udp_socket_receive(&socket_0, &my_packet, 3 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
    {

        /* Check whether packet is in sequence. */
        nx_packet_data_retrieve(my_packet, recv_buff, &data_len);
        if(data_len != 3)
            error_counter++;
        else if(memcmp("ABC", recv_buff, data_len))
            error_counter++;
        nx_packet_release(my_packet);
    }

#ifdef FEATURE_NX_IPV6
    /* Receive a packet. */
    status = nx_udp_socket_receive(&socket_0, &my_packet, 3 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
    {

        /* Check whether packet is in sequence. */
        nx_packet_data_retrieve(my_packet, recv_buff, &data_len);
        if(data_len != sizeof(send_buff))
            error_counter++;
        else if(memcmp(send_buff, recv_buff, data_len))
            error_counter++;
        nx_packet_release(my_packet);
    }

    /* Receive a packet. */
    status = nx_udp_socket_receive(&socket_0, &my_packet, 3 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
    {

        /* Check whether packet is in sequence. */
        nx_packet_data_retrieve(my_packet, recv_buff, &data_len);
        if(data_len != 3)
            error_counter++;
        else if(memcmp("ABC", recv_buff, data_len))
            error_counter++;
        nx_packet_release(my_packet);
    }
#endif /* FEATURE_NX_IPV6 */
#endif /* NX_FRAGMENT_IMMEDIATE_ASSEMBLY */

    /* Receive packets. */
#ifdef FEATURE_NX_IPV6
    for(i = 0; i < 2000; i++)
#else
    for(i = 0; i < 1000; i++)
#endif /* FEATURE_NX_IPV6 */
    {
        status = nx_udp_socket_receive(&socket_0, &my_packet, 3 * NX_IP_PERIODIC_RATE);
        if (status)
        {
            error_counter++;
            break;
        }
        else
        {

            /* Check whether packet is in sequence. */
            nx_packet_data_retrieve(my_packet, recv_buff, &data_len);
            if(data_len != sizeof(send_buff))
                error_counter++;
            else if(memcmp(send_buff, recv_buff, data_len))
                error_counter++;
            nx_packet_release(my_packet);
        }
    }

#if !defined(NX_DISABLE_IP_INFO) && !defined(NX_DISABLE_PACKET_CHAIN)

    /* Get the original failures. */
    fragment_failures = ip_0.nx_ip_fragment_failures;

    /* Create a packet larger than MTU.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_0, NX_WAIT_FOREVER);

    /* Allocate packet until no packet is available. */
    while (nx_packet_allocate(&pool_0, &test_packet, NX_UDP_PACKET, NX_NO_WAIT) == NX_SUCCESS)
    {
        last_packet_2 = last_packet_1; 
        last_packet_1 = test_packet; 
    }

    /* Make sure no ARP request is needed. */
    nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 
                             ip_1.nx_ip_interface[0].nx_interface_physical_address_msw,
                             ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw);

    /* Send the UDP packet.  */
    status += nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }

    /* Check whether */
    if (ip_0.nx_ip_fragment_failures != fragment_failures + 1)
    {
        error_counter++;
    }

    /* Release one packet. It should not be able to send since packet is not enough. */
    nx_packet_release(last_packet_1);

    /* Create a packet larger than MTU.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_0, NX_WAIT_FOREVER);

    /* Make sure no ARP request is needed. */
    nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 
                             ip_1.nx_ip_interface[0].nx_interface_physical_address_msw,
                             ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw);

    /* Send the UDP packet.  */
    status += nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }

    /* Check whether */
    if (ip_0.nx_ip_fragment_failures != fragment_failures + 2)
    {
        error_counter++;
    }

    /* Release the second packet. It should be able to send packet. */
    nx_packet_release(last_packet_2);

    /* Create a packet larger than MTU.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_0, NX_WAIT_FOREVER);

    /* Modify the length of packet and keep append_ptr. The fragment process should discard this packet. */
    my_packet -> nx_packet_length += 256;


    /* Send the UDP packet.  */
    status += nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }

    /* Check whether */
    if (ip_0.nx_ip_fragment_failures != fragment_failures + 3)
    {
        error_counter++;
    }

#endif /* !NX_DISABLE_IP_INFO && !NX_DISABLE_PACKET_CHAIN */

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_0);

    /* Delete the UDP socket.  */
    status +=  nx_udp_socket_delete(&socket_0);

    /* Check status.  */
    if (status)
        error_counter++;

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

UINT        i;
UINT        status;
NX_PACKET   *my_packet;


    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x89, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Initialize send buffer. */
    for(i = 0; i < sizeof(send_buff); i++)
        send_buff[i] = (UCHAR)(i & 0xFF);

#ifdef NX_FRAGMENT_IMMEDIATE_ASSEMBLY
    /* Create a packet larger than MTU.  */
    status =  nx_packet_allocate(&pool_1, &my_packet, NX_UDP_PACKET, NX_NO_WAIT);
    status += nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_1, NX_NO_WAIT);

    /* Send the UDP packet.  */
    status +=  nx_udp_socket_send(&socket_1, my_packet, IP_ADDRESS(1, 2, 3, 4), 0x88);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Create a small packet.  */
    status =  nx_packet_allocate(&pool_1, &my_packet, NX_UDP_PACKET, NX_NO_WAIT);
    status += nx_packet_data_append(my_packet, "ABC", 3, &pool_1, NX_NO_WAIT);

    /* Send the UDP packet.  */
    status +=  nx_udp_socket_send(&socket_1, my_packet, IP_ADDRESS(1, 2, 3, 4), 0x88);

    /* Check status.  */
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Create a packet larger than MTU.  */
    status =  nx_packet_allocate(&pool_1, &my_packet, NX_UDP_PACKET, NX_NO_WAIT);
    status += nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_1, NX_NO_WAIT);

    /* Send the UDP packet.  */
    status +=  nxd_udp_socket_send(&socket_1, my_packet, &address_0, 0x88);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Create a small packet.  */
    status =  nx_packet_allocate(&pool_1, &my_packet, NX_UDP_PACKET, NX_NO_WAIT);
    status += nx_packet_data_append(my_packet, "ABC", 3, &pool_1, NX_NO_WAIT);

    /* Send the UDP packet.  */
    status +=  nxd_udp_socket_send(&socket_1, my_packet, &address_0, 0x88);

    /* Check status.  */
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
#endif /* NX_FRAGMENT_IMMEDIATE_ASSEMBLY */
    /* Send 1000 packets from user specified packet pool. */
    for(i = 0; i < 1000; i++)
    {

        /* Create a packet larger than MTU.  */
        status =  nx_packet_allocate(&pool_1, &my_packet, NX_UDP_PACKET, NX_WAIT_FOREVER);
        status += nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_1, NX_WAIT_FOREVER);

        /* Send the UDP packet.  */
        status +=  nx_udp_socket_send(&socket_1, my_packet, IP_ADDRESS(1, 2, 3, 4), 0x88);

        /* Check status.  */
        if (status)
        {
            error_counter++;
            nx_packet_release(my_packet);
            break;
        }
        tx_thread_relinquish();
    }

#ifdef FEATURE_NX_IPV6
    /* Send 1000 packets from user specified packet pool. */
    for(i = 0; i < 1000; i++)
    {

        /* Create a packet larger than MTU.  */
        status =  nx_packet_allocate(&pool_1, &my_packet, NX_UDP_PACKET, NX_WAIT_FOREVER);
        status += nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_1, NX_WAIT_FOREVER);

        /* Send the UDP packet.  */
        status +=  nxd_udp_socket_send(&socket_1, my_packet, &address_0, 0x88);

        /* Check status.  */
        if (status)
        {
            error_counter++;
            nx_packet_release(my_packet);
            break;
        }
        tx_thread_relinquish();
    }
#endif /* FEATURE_NX_IPV6 */

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_1);

    /* Delete the UDP socket.  */
    status +=  nx_udp_socket_delete(&socket_1);

    /* Check status.  */
    if (status)
        error_counter++;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_fragment_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   UDP Fragment Test.........................................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_FRAGMENTATION */
