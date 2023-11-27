/* This NetX test concentrates on failure situation of IPv6 send.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6
#include   "nx_nd_cache.h"
#include   "nx_icmpv6.h"

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

#ifndef NX_DISABLE_LOOPBACK_INTERFACE
static NXD_ADDRESS             lo_address;    
static NX_PACKET              *consume_packet[20];
static ULONG                   consumed;
#endif /* NX_DISABLE_LOOPBACK_INTERFACE */

#ifdef NX_DISABLE_FRAGMENTATION
static CHAR                    send_buffer[256];
#endif /* NX_DISABLE_FRAGMENTATION */


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_send_fail_test_application_define(void *first_unused_memory)
#endif
{
    
CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "Pool 0", 512, pointer, 4096);
    pointer = pointer + 4096;

    /* Create a packet pool.  */
    status +=  nx_packet_pool_create(&pool_1, "Pool 1", 512, pointer, 4096);
    pointer = pointer + 4096;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create an IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Enable ICMP for IP Instance 0 and 1.  */
    status += nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    if(status)
        error_counter++;

#ifndef NX_DISABLE_LOOPBACK_INTERFACE 
    /* Set IPv6 loopback address.  */
    lo_address.nxd_ip_version = NX_IP_VERSION_V6;
    lo_address.nxd_ip_address.v6[0] = 0x00000000;
    lo_address.nxd_ip_address.v6[1] = 0x00000000;
    lo_address.nxd_ip_address.v6[2] = 0x00000000;
    lo_address.nxd_ip_address.v6[3] = 0x00000001;
#endif /* FEATURE_NX_IPV6 */
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *pkt_ptr;
NXD_ADDRESS address_1;
NXD_ADDRESS address_unknown;
ULONG       prefix_length;
UINT        interface_index;
UINT        i;

    /* Print out some test information banners.  */
    printf("NetX Test:   IPv6 send fail Test.......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set interfaces' address */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, NX_NULL, 10, NX_NULL);

    /* Check status. */
    if (status)
    {
        error_counter++;
    }

    /* Sleep 5 seconds for DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

#ifndef NX_DISABLE_LOOPBACK_INTERFACE
    /* Now ping loopback address.  */
    status = nxd_icmp_ping(&ip_0, &lo_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &pkt_ptr, NX_IP_PERIODIC_RATE);

    /* Check status. */
    if (status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(pkt_ptr);
    }

    /* Now consume packets from pool_0. */
    consumed = 0;
    while (pool_0.nx_packet_pool_available > 1)
    {
        nx_packet_allocate(&pool_0, &consume_packet[consumed++], 0, NX_NO_WAIT);
    }

    /* Now ping loopback address. Only one packet is left so it is not possible to receive the packet.  */
    status = nxd_icmp_ping(&ip_0, &lo_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &pkt_ptr, NX_IP_PERIODIC_RATE);

    /* Check status. */
    if (status == NX_SUCCESS)
    {
        error_counter++;
        nx_packet_release(pkt_ptr);
    }

    /* Release consumed packets. */
    while (consumed)
    {
        consumed--;
        nx_packet_release(consume_packet[consumed]);
    }
#endif /* NX_DISABLE_LOOPBACK_INTERFACE */

    /* Get the link local address of ip_1. */
    status = nxd_ipv6_address_get(&ip_1, 0, &address_1, &prefix_length, &interface_index);

    /* Check status. */
    if (status)
    {
        error_counter++;
    }

    /* Set function pointer of ICMPv6 to NULL. */
    ip_0.nx_ip_icmpv6_packet_process = NX_NULL;

    /* Now ping ip_1's address. ICMPv6 process function pointer is set to NULL.  */
    status = nxd_icmp_ping(&ip_0, &address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &pkt_ptr, NX_IP_PERIODIC_RATE);

    /* Check status. */
    if (status == NX_SUCCESS)
    {
        error_counter++;
        nx_packet_release(pkt_ptr);
    }

    /* Recover function pointer of ICMPv6. */
    ip_0.nx_ip_icmpv6_packet_process = _nx_icmpv6_packet_process;

    /* Now ping ip_1's address.  */
    status = nxd_icmp_ping(&ip_0, &address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &pkt_ptr, NX_IP_PERIODIC_RATE);

    /* Check status. */
    if (status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(pkt_ptr);
    }

#ifdef NX_DISABLE_FRAGMENTATION
    /* Now ping ip_1's address. Fragment is disabled but sizeof data is larger than MTU.  */
    status = nxd_icmp_ping(&ip_0, &address_1, send_buffer, sizeof(send_buffer), &pkt_ptr, NX_IP_PERIODIC_RATE);

    /* Check status. */
    if (status == NX_SUCCESS)
    {
        error_counter++;
        nx_packet_release(pkt_ptr);
    }
#endif /* NX_DISABLE_FRAGMENTATION */

    /* Set an unknown destination. */
    address_unknown.nxd_ip_version = NX_IP_VERSION_V6;
    address_unknown.nxd_ip_address.v6[0] = 0xFE800000;
    address_unknown.nxd_ip_address.v6[1] = 0x00000000;
    address_unknown.nxd_ip_address.v6[2] = 0x00000000;
    address_unknown.nxd_ip_address.v6[3] = 0x00000001;

    /* Ping unknow address until ND queue depth. */
    for (i = 0; i <= NX_ND_MAX_QUEUE_DEPTH; i++)
    {
        status = nxd_icmp_ping(&ip_0, &address_unknown, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &pkt_ptr, NX_NO_WAIT);

        /* Check status. */
        if (status == NX_SUCCESS)
        {
            error_counter++;
            nx_packet_release(pkt_ptr);
        }
    }

    /* Determine how to report error.  */
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
    
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_send_fail_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 send fail Test.......................................N/A\n");

    test_control_return(3);

}
#endif
