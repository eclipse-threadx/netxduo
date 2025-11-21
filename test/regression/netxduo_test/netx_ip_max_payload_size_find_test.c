/* This NetX test concentrates on the ip max payload size find operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void  test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) 
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;
#endif

/* Define the counters used in the test application...  */

static ULONG                   error_counter;



/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);
void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_max_payload_size_find_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

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

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1024,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

#ifndef NX_DISABLE_IPV4
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

    /* Enable ICMP processing for both IP instances.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
#endif


#ifdef FEATURE_NX_IPV6

    status = nxd_ipv6_enable(&ip_0);
    status = nxd_ipv6_enable(&ip_1);
    if(status)
        error_counter++;

    status = nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);
    if(status)
        error_counter++;

    ipv6_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_0.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_0.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000002;   

    /* Set interfaces' address */
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_1, 64, NX_NULL);

    if(status)
        error_counter++;
#endif
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NXD_ADDRESS dest_address;
ULONG start_offset, payload_length;
    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Max Payload Size Find Test.............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver_512);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Attach the 2nd interface to IP instance1 */
    status = nx_ip_interface_attach(&ip_1, "2nd interface", IP_ADDRESS(4, 3, 2, 11), 0xFF000000, _nx_ram_network_driver_256);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_IPV4
    dest_address.nxd_ip_version = NX_IP_VERSION_V4;
    dest_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    status = nx_ip_max_payload_size_find(&ip_0, &dest_address, 0, 80, 80, NX_PROTOCOL_TCP,
                                         &start_offset, &payload_length);

    if((status != NX_SUCCESS) || (start_offset != (40 + NX_PHYSICAL_HEADER)) || (payload_length != 1460))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
        
    dest_address.nxd_ip_version = NX_IP_VERSION_V4;
    dest_address.nxd_ip_address.v4 = IP_ADDRESS(4, 3, 2, 11);

    status = nx_ip_max_payload_size_find(&ip_0, &dest_address, 1, 80, 80, NX_PROTOCOL_TCP,
                                         &start_offset, &payload_length);
       
    if((status != NX_SUCCESS) ||(start_offset != (40 + NX_PHYSICAL_HEADER)) || (payload_length != 472))  
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test an invalid address. */        
    dest_address.nxd_ip_version = NX_IP_VERSION_V4;
    dest_address.nxd_ip_address.v4 = IP_ADDRESS(4, 3, 2, 11);

    status = nx_ip_max_payload_size_find(&ip_0, &dest_address, 3, 80, 80, NX_PROTOCOL_TCP,
                                         &start_offset, &payload_length);

    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
        
    dest_address.nxd_ip_version = NX_IP_VERSION_V4;
    dest_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);

    status = nx_ip_max_payload_size_find(&ip_1, &dest_address, 0, 80, 80, NX_PROTOCOL_TCP,
                                         &start_offset, &payload_length);

    if((status != NX_SUCCESS) || (start_offset != (40 + NX_PHYSICAL_HEADER)) || (payload_length != 984))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

        
    dest_address.nxd_ip_version = NX_IP_VERSION_V4;
    dest_address.nxd_ip_address.v4 = IP_ADDRESS(4, 3, 2, 10);

    status = nx_ip_max_payload_size_find(&ip_1, &dest_address, 1, 80, 80, NX_PROTOCOL_TCP,
                                         &start_offset, &payload_length);

    /* 56 = 16 + 20 + 20.  216 = 256 + 16 - 56 */
    if((status != NX_SUCCESS) ||(start_offset != (40 + NX_PHYSICAL_HEADER)) || (payload_length != 216))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

#ifdef FEATURE_NX_IPV6       
    /* Find the max payload with invalid address index.  */
    status = nx_ip_max_payload_size_find(&ip_0, &ipv6_address_1, (NX_MAX_IPV6_ADDRESSES + NX_LOOPBACK_IPV6_ENABLED), 80, 80, NX_PROTOCOL_UDP, &start_offset, &payload_length);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                              
    /* Find the max payload with valid address index.  */
    status = nx_ip_max_payload_size_find(&ip_0, &ipv6_address_1, 0, 80, 80, NX_PROTOCOL_UDP, &start_offset, &payload_length);
    /* 64 = 16 + 40 + 8    208 = 1500 + 16 - 64 */
    if((status != NX_SUCCESS) || (start_offset != (48 + NX_PHYSICAL_HEADER)) || (payload_length != 1452))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

#ifndef NX_DISABLE_IPV4
    /* Test an invalid address. */
    dest_address.nxd_ip_version = NX_IP_VERSION_V4;
    dest_address.nxd_ip_address.v4 = IP_ADDRESS(4, 3, 2, 11);

    status = nx_ip_max_payload_size_find(&ip_1, &dest_address, 3, 80, 80, NX_PROTOCOL_TCP,
                                         &start_offset, &payload_length);

    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    

    printf("SUCCESS!\n");
    test_control_return(0);

}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_max_payload_size_find_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Max Payload Size Find Test.............................N/A\n");
    test_control_return(3);

}
#endif
    
