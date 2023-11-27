/* This NetX test concentrates on the raw nxe API.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_tcp.h"
#include   "nx_udp.h"
#include   "nx_packet.h"

extern void    test_control_return(UINT status);
#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   invalid_ip;
#ifdef __PRODUCT_NETXDUO__
NXD_ADDRESS                    des_address;
#endif
static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_raw_nxe_api_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
NX_PACKET   *invalid_packet;
NX_PACKET   *invalid_packet2;
UCHAR       *temp_ptr;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Raw Nxe API Test.......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(my_packet, "ABCD", 4, &pool_0, NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable raw with null pointer, should return error. */ 
    status = nx_ip_raw_packet_enable(NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable raw with invalid IP ID, should return error. */ 
    invalid_ip.nx_ip_id = 0;
    status = nx_ip_raw_packet_enable(&invalid_ip);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable raw with null pointer, should return error. */ 
    status = nx_ip_raw_packet_disable(NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable raw with invalid IP. */ 
    status = nx_ip_raw_packet_disable(&invalid_ip);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive raw packet before enable, error should be returned. */
    status = nx_ip_raw_packet_receive(&ip_0, &my_packet, NX_IP_PERIODIC_RATE);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive raw packet without null packet pointer. */
    status = nx_ip_raw_packet_receive(&ip_0, NX_NULL, NX_IP_PERIODIC_RATE);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive raw packet with invalid IP instance. */
    ip_0.nx_ip_id = 0;
    status = nx_ip_raw_packet_receive(&ip_0, &my_packet, NX_IP_PERIODIC_RATE);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    ip_0.nx_ip_id = NX_IP_ID;

    /* Send the raw IP packet before enable.  */
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);
    if (status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef __PRODUCT_NETXDUO__
#ifdef FEATURE_NX_IPV6
    des_address.nxd_ip_version = NX_IP_VERSION_V6;
    des_address.nxd_ip_address.v6[0] = 0x20010DB8;
    des_address.nxd_ip_address.v6[1] = 0x00010001;
    des_address.nxd_ip_address.v6[2] = 0x021122FF;
    des_address.nxd_ip_address.v6[3] = 0xFE334456;       

    /* Send raw packet with null IP instance. */
    status = nxd_ip_raw_packet_send(&ip_0, my_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
#endif


    /* Enable RAW. */
    status = nx_ip_raw_packet_enable(&ip_0);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set raw filter with null IP instance, should return error. */
    status = nx_ip_raw_packet_filter_set(NX_NULL, NX_NULL);
#ifdef NX_ENABLE_IP_RAW_PACKET_FILTER
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#else
    if(status != NX_NOT_SUPPORTED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Receive raw packet with null IP instance, should return error. */
    status = nx_ip_raw_packet_receive(NX_NULL, NX_NULL, NX_IP_PERIODIC_RATE);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Send the raw IP packet with null IP instance.  */
    status =  nx_ip_raw_packet_send(NX_NULL, my_packet, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the raw IP packet with invalid IP instance.  */
    status =  nx_ip_raw_packet_send(&invalid_ip, my_packet, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the raw IP packet with NULL packet.  */
    invalid_packet2 = NX_NULL;
    status =  nx_ip_raw_packet_send(&ip_0, invalid_packet2, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the raw IP packet with invalid packet state.  */
#ifdef __PRODUCT_NETXDUO__
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
#else
    my_packet -> nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
#endif
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#ifdef __PRODUCT_NETXDUO__
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#else
    my_packet -> nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#endif

    /* Send the raw IP packet with invalid IP address.  */
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, 0, NX_IP_NORMAL);
    if (status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the raw IP packet with invalid type of service.  */
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0xffffffff);
    if (status != NX_OPTION_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &invalid_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    temp_ptr = invalid_packet -> nx_packet_prepend_ptr;
    invalid_packet -> nx_packet_prepend_ptr = invalid_packet -> nx_packet_data_start;
    /* Send the invalid raw IP packet. */
    status =  nx_ip_raw_packet_send(&ip_0, invalid_packet, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);
    if (status != NX_UNDERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_prepend_ptr = temp_ptr;

    temp_ptr = invalid_packet -> nx_packet_append_ptr;
    invalid_packet -> nx_packet_append_ptr = invalid_packet -> nx_packet_data_end + 1;
    /* Send the invalid raw IP packet. */
    status =  nx_ip_raw_packet_send(&ip_0, invalid_packet, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);
    if (status != NX_OVERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_append_ptr = temp_ptr;


    /* Send raw packet with null IP instance. */
    status = nx_ip_raw_packet_source_send(NX_NULL, my_packet, IP_ADDRESS(1, 2, 3, 5), 0, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send raw packet with null packet. */
    invalid_packet2 = NX_NULL;
    status = nx_ip_raw_packet_source_send(&ip_0, invalid_packet2, IP_ADDRESS(1, 2, 3, 5), 0, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send raw packet with invalid IP instance. */
    ip_0.nx_ip_id = 0;
    status = nx_ip_raw_packet_source_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    ip_0.nx_ip_id = NX_IP_ID;

    /* Send raw packet with invalid IP address. */
    status = nx_ip_raw_packet_source_send(&ip_0, my_packet, 0, 0, NX_IP_NORMAL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send raw packet with invalid packet state. */
#ifdef __PRODUCT_NETXDUO__
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
#else
    my_packet -> nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
#endif
    status = nx_ip_raw_packet_source_send(&ip_0, my_packet, 0, 0, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#ifdef __PRODUCT_NETXDUO__
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#else
    my_packet -> nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#endif
    
    /* Send raw packet with invalid type of service. */
    status = nx_ip_raw_packet_source_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0, 0xffffffff);
    if(status != NX_OPTION_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    temp_ptr = invalid_packet -> nx_packet_prepend_ptr;
    invalid_packet -> nx_packet_prepend_ptr = invalid_packet -> nx_packet_data_start;
    /* Send the invalid raw IP packet. */
    status = nx_ip_raw_packet_source_send(&ip_0, invalid_packet, IP_ADDRESS(1, 2, 3, 5), 0, NX_IP_NORMAL);
    if (status != NX_UNDERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_prepend_ptr = temp_ptr;

    temp_ptr = invalid_packet -> nx_packet_append_ptr;
    invalid_packet -> nx_packet_append_ptr = invalid_packet -> nx_packet_data_end + 1;
    /* Send the invalid raw IP packet. */
    status = nx_ip_raw_packet_source_send(&ip_0, invalid_packet, IP_ADDRESS(1, 2, 3, 5), 0, NX_IP_NORMAL);
    if (status != NX_OVERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_append_ptr = temp_ptr;

    /* Send raw packet with invalid interface index. */
    status = nx_ip_raw_packet_source_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0xffff, NX_IP_NORMAL);
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    ip_0.nx_ip_interface[0].nx_interface_valid = NX_FALSE;
    /* Send raw packet with invalid interface. */
    status = nx_ip_raw_packet_source_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0, NX_IP_NORMAL);
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_TRUE;

    /* Set raw packet receive queue size with null ip instance. */
    status = nx_ip_raw_receive_queue_max_set(NX_NULL, 5);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set raw packet receive queue size with invalid IP instance. */
    ip_0.nx_ip_id = 0;
    status = nx_ip_raw_receive_queue_max_set(&ip_0, 5);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    ip_0.nx_ip_id = NX_IP_ID;

#ifdef __PRODUCT_NETXDUO__
    
#ifdef FEATURE_NX_IPV6
    /* Send raw packet with null IP instance. */
    status = nxd_ip_raw_packet_send(NX_NULL, my_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send raw packet with invalid IP instance. */
    invalid_ip.nx_ip_id = 0;
    status = nxd_ip_raw_packet_send(&invalid_ip, my_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send raw packet with NULL packet. */
    invalid_ip.nx_ip_id = 0;
    invalid_packet2 = NX_NULL;
    status = nxd_ip_raw_packet_send(&ip_0, invalid_packet2, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send raw packet with invalid packet state. */
#ifdef __PRODUCT_NETXDUO__
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
#else
    my_packet -> nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
#endif
    status = nxd_ip_raw_packet_send(&ip_0, my_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#ifdef __PRODUCT_NETXDUO__
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#else
    my_packet -> nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#endif

    /* Send raw packet to NULL IP address. */
    status = nxd_ip_raw_packet_send(&ip_0, my_packet, NX_NULL, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send raw packet to an invalid IP address. */
    des_address.nxd_ip_version = 8;        
    status = nxd_ip_raw_packet_send(&ip_0, my_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    des_address.nxd_ip_version = NX_IP_VERSION_V6;

    /* Send raw packet with invalid protocol. */
    status = nxd_ip_raw_packet_send(&ip_0, my_packet, &des_address, 0xffff, 0x80, NX_IP_NORMAL);
    if(status != NX_INVALID_PARAMETERS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    des_address.nxd_ip_version = NX_IP_VERSION_V4;

    temp_ptr = invalid_packet -> nx_packet_prepend_ptr;
    invalid_packet -> nx_packet_prepend_ptr = invalid_packet -> nx_packet_data_start;
    /* Send the invalid raw IP packet. */
    status = nxd_ip_raw_packet_send(&ip_0, invalid_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if (status != NX_UNDERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_prepend_ptr = temp_ptr;

    temp_ptr = invalid_packet -> nx_packet_append_ptr;
    invalid_packet -> nx_packet_append_ptr = invalid_packet -> nx_packet_data_end + 1;
    /* Send the invalid raw IP packet. */
    status = nxd_ip_raw_packet_send(&ip_0, invalid_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if (status != NX_OVERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_append_ptr = temp_ptr;

    des_address.nxd_ip_version = NX_IP_VERSION_V6;

    temp_ptr = invalid_packet -> nx_packet_prepend_ptr;
    invalid_packet -> nx_packet_prepend_ptr = invalid_packet -> nx_packet_data_start;
    /* Send the invalid raw IP packet. */
    status = nxd_ip_raw_packet_send(&ip_0, invalid_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if (status != NX_UNDERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_prepend_ptr = temp_ptr;

    /* Send to unspecified IP address. */
    memset(des_address.nxd_ip_address.v6, 0, sizeof(des_address.nxd_ip_address.v6));
    status = nxd_ip_raw_packet_send(&ip_0, my_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if (status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    des_address.nxd_ip_address.v6[0] = 1;

    temp_ptr = invalid_packet -> nx_packet_prepend_ptr;
    invalid_packet -> nx_packet_prepend_ptr = invalid_packet -> nx_packet_data_start;
    /* Send the invalid raw IP packet. */
    status = nxd_ip_raw_packet_source_send(&ip_0, invalid_packet, &des_address, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if (status != NX_UNDERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_prepend_ptr = temp_ptr;

    temp_ptr = invalid_packet -> nx_packet_append_ptr;
    invalid_packet -> nx_packet_append_ptr = invalid_packet -> nx_packet_data_end + 1;
    /* Send the invalid raw IP packet. */
    status = nxd_ip_raw_packet_source_send(&ip_0, invalid_packet, &des_address, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if (status != NX_OVERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_append_ptr = temp_ptr;

    /* Send to an  invalid IPv6 addres. */
    des_address.nxd_ip_address.v6[0] = 0;
    des_address.nxd_ip_address.v6[1] = 0;
    des_address.nxd_ip_address.v6[2] = 0;
    des_address.nxd_ip_address.v6[3] = 0;
    status = nxd_ip_raw_packet_send(&ip_0, my_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Send to an invalid IPv4 address. */
    des_address.nxd_ip_version = NX_IP_VERSION_V4;
    des_address.nxd_ip_address.v4 = 0;
    status = nxd_ip_raw_packet_send(&ip_0, my_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send to an valid IPv4 address with an invalid packet. */
    des_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    invalid_packet -> nx_packet_prepend_ptr = invalid_packet -> nx_packet_data_start;
    /* Send the invalid raw IP packet. */
    status = nxd_ip_raw_packet_send(&ip_0, invalid_packet, &des_address, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if (status != NX_UNDERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_prepend_ptr = temp_ptr;

    /* Send to an valid IPv4 address with an invalid packet. */
    des_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    invalid_packet -> nx_packet_prepend_ptr = invalid_packet -> nx_packet_data_start;
    /* Send the invalid raw IP packet. */
    status = nxd_ip_raw_packet_source_send(&ip_0, invalid_packet, &des_address, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if (status != NX_UNDERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_prepend_ptr = temp_ptr;

#ifdef FEATURE_NX_IPV6
    /* Send to an valid IPv6 address with an invalid packet. */
    des_address.nxd_ip_version = NX_IP_VERSION_V6;
    invalid_packet -> nx_packet_prepend_ptr = invalid_packet -> nx_packet_data_start;
    /* Send the invalid raw IP packet. */
    status = nxd_ip_raw_packet_source_send(&ip_0, invalid_packet, &des_address, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if (status != NX_UNDERFLOW)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    invalid_packet -> nx_packet_prepend_ptr = temp_ptr;
#endif /* FEATURE_NX_IPV6 */


    /* Send raw packet with null IP instance. */
    status = nxd_ip_raw_packet_source_send(NX_NULL, my_packet, &des_address, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send raw packet with null packet. */
    status = nxd_ip_raw_packet_source_send(&ip_0, NX_NULL, &des_address, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send raw packet with null destination. */
    status = nxd_ip_raw_packet_source_send(&ip_0, my_packet, NX_NULL, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send to an invalid IP address. */    
    des_address.nxd_ip_version = 8;
    status = nxd_ip_raw_packet_source_send(&ip_0, my_packet, &des_address, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send to an invalid IPv4 address. */
    des_address.nxd_ip_version = NX_IP_VERSION_V4;
    des_address.nxd_ip_address.v4 = 0;
    status = nxd_ip_raw_packet_source_send(&ip_0, my_packet, &des_address, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send with an invalid interface. */
    des_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    status = nxd_ip_raw_packet_source_send(&ip_0, my_packet, &des_address, 0xffff, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Send to an invalid IPv6 address. */
    des_address.nxd_ip_version = NX_IP_VERSION_V6;
    des_address.nxd_ip_address.v6[0] = 0;
    des_address.nxd_ip_address.v6[1] = 0;
    des_address.nxd_ip_address.v6[2] = 0;
    des_address.nxd_ip_address.v6[3] = 0;
    status = nxd_ip_raw_packet_source_send(&ip_0, my_packet, &des_address, 0, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send with invalid IPv6 address index. */
    des_address.nxd_ip_address.v6[0] = 0x20010DB8;
    des_address.nxd_ip_address.v6[1] = 0x00010001;
    des_address.nxd_ip_address.v6[2] = 0x021122FF;
    des_address.nxd_ip_address.v6[3] = 0xFE334456;       
    status = nxd_ip_raw_packet_source_send(&ip_0, my_packet, &des_address, 0xffff, NX_IP_RAW >> 16, 0x80, NX_IP_NORMAL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

#endif



    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_raw_nxe_api_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Raw Nxe API Test.......................................N/A\n");
    test_control_return(3);  
}
#endif
