/* This NetX test concentrates on the ICMP ping through all loopback addresses with multiple addresses.  */

#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void  test_control_return(UINT status);
#if !defined(NX_DISABLE_LOOPBACK_INTERFACE) && defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;
#endif /* FEATURE_NX_IPV6 */


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_loopback_multihome_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 4096);
    pointer = pointer + 4096;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

#ifndef NX_DISABLE_IPV4
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
#endif

    /* Enable ICMP processing for IP_0.  */
    status =  nxd_icmp_enable(&ip_0);

    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);

    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */

    /* Set the second interface.  */
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, _nx_ram_network_driver_256);

    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Set ipv6 version and address.  */
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
    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);

    if(status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;  

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Loopback Multihome Test................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Wait for DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */
                  
    /* Detect packet in driver callback function.  */
    advanced_packet_process_callback = packet_process;

#ifndef NX_DISABLE_IPV4
    /* Now ping the first IPv4 interface address.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 4), "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        error_counter++;
    }
    else
    {

        /* Release the packet. */
        nx_packet_release(my_packet);
    }


    /* Now ping the second IPv4 interface address.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        error_counter++;
    }
    else
    {

        /* Release the packet. */
        nx_packet_release(my_packet);
    }
#endif


#ifdef FEATURE_NX_IPV6
    /* Now ping the first IPv6 interface address.  */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        error_counter++;
    }
    else
    {

        /* Release the packet. */
        nx_packet_release(my_packet);
    }


    /* Now ping the second IPv6 interface address.  */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        error_counter++;
    }
    else
    {

        /* Release the packet. */
        nx_packet_release(my_packet);
    }
#endif /* FEATURE_NX_IPV6 */
         
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

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    /* No packet is expected to be sent out by driver. */
    error_counter++;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_loopback_multihome_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   IP Loopback Multihome Test................................N/A\n");
    test_control_return(3);
}
#endif 
