/* This NetX test concentrates on the basic TCP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(NX_ENABLE_LOW_WATERMARK)
#include "nx_ipv6.h"

#define     DEMO_STACK_SIZE         2048
#define     PACKET_SIZE             1536
#define     POOL_0_COUNT            20
#define     POOL_1_COUNT            10
#define     TEST_LOOP               100


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;
static ULONG                   fragments_count;
static ULONG                   drop_count;


/* Define pool area. */
static UCHAR                   pool_area_0[POOL_0_COUNT * (sizeof(NX_PACKET) + PACKET_SIZE)];
static UCHAR                   pool_area_1[POOL_1_COUNT * (sizeof(NX_PACKET) + PACKET_SIZE)];

static UCHAR                   ping_buffer[2048];

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_low_watermark_fragment_test_application_define(void *first_unused_memory)
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

    /* Create two packet pools.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pool_area_0, sizeof(pool_area_0));
    status +=  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", PACKET_SIZE, pool_area_1, sizeof(pool_area_1));

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

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */

    /* Enable ICMP processing for both IP instances.  */
    status =  nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;

    status = nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        i;
NX_PACKET  *packet_ptr;
UINT        status;

    /* Print out some test information banners.  */
    printf("NetX Test:   Low Watermark Fragment Test...............................");

    /* Setup driver callback to drop last fragment of each ICMP packet. */
    advanced_packet_process_callback = packet_process;

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

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */

    /* Set low_watermark. */
    nx_packet_pool_low_watermark_set(&pool_1, 2);
    fragments_count = 0;
    drop_count = 0;
    for (i = 0; (i < TEST_LOOP) && (error_counter == 0); i++)
    {

#ifndef NX_DISABLE_IPV4
        /* Ping IP1 address with fragments. The first fragment will be dropped by driver.  */
        nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), ping_buffer, sizeof(ping_buffer),
                     &packet_ptr, NX_NO_WAIT);
        fragments_count++;

        /* Ping IP1 address without fragments.  */
        status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "", 0, &packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
            error_counter++;
        else
            nx_packet_release(packet_ptr);
#endif /* NX_DISABLE_IPV4 */

#ifdef FEATURE_NX_IPV6
        /* Ping IP1 address with fragments. The first fragment will be dropped by driver.  */
        nxd_icmp_ping(&ip_0, &ipv6_address_2, ping_buffer, sizeof(ping_buffer),
                      &packet_ptr, NX_NO_WAIT);
        fragments_count++;

        /* Ping IP1 address without fragments.  */
        status = nxd_icmp_ping(&ip_0, &ipv6_address_2, "", 0, &packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
            error_counter++;
        else
            nx_packet_release(packet_ptr);
#endif /* FEATURE_NX_IPV6 */
    }

    /* Check status.  */
    if (error_counter || (drop_count != fragments_count))
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
ULONG ip_version;
#ifndef NX_DISABLE_IPV4
NX_IPV4_HEADER *ip_header_ptr;
#endif /* NX_DISABLE_IPV4 */
#ifdef FEATURE_NX_IPV6
NX_IPV6_HEADER *ipv6_header_ptr;
NX_IPV6_HEADER_FRAGMENT_OPTION *ipv6_fragment_option;
#endif /* FEATURE_NX_IPV6 */

    if (ip_ptr == &ip_1)
        return NX_TRUE;

    ip_version = packet_ptr -> nx_packet_ip_version;

    if (ip_version == NX_IP_VERSION_V6)
    {
#ifdef FEATURE_NX_IPV6
        if (packet_ptr -> nx_packet_length < 40)
        {
            return NX_TRUE;
        }
        ipv6_header_ptr = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
        NX_CHANGE_ULONG_ENDIAN(ipv6_header_ptr -> nx_ip_header_word_1);
        if (((ipv6_header_ptr -> nx_ip_header_word_1 >> 8) & 0xFF) == NX_PROTOCOL_NEXT_HEADER_FRAGMENT)
        {
            ipv6_fragment_option = (NX_IPV6_HEADER_FRAGMENT_OPTION *)(packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_IPV6_HEADER));
            NX_CHANGE_USHORT_ENDIAN(ipv6_fragment_option -> nx_ipv6_header_fragment_option_offset_flag);
            if (ipv6_fragment_option -> nx_ipv6_header_fragment_option_offset_flag & 1)
            {
                *operation_ptr = NX_RAMDRIVER_OP_DROP;
                drop_count++;
            }
            NX_CHANGE_USHORT_ENDIAN(ipv6_fragment_option -> nx_ipv6_header_fragment_option_offset_flag);
        }
        NX_CHANGE_ULONG_ENDIAN(ipv6_header_ptr -> nx_ip_header_word_1);
#endif /* FEATURE_NX_IPV6 */
    }
#ifndef NX_DISABLE_IPV4
    else
    {
        if ((packet_ptr -> nx_packet_length < 20) || (packet_ptr -> nx_packet_length == 28))
        {
            return NX_TRUE;
        }
        ip_header_ptr = (NX_IPV4_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
        if (ip_header_ptr -> nx_ip_header_word_1 & (NX_IP_FRAGMENT_MASK | NX_IP_MORE_FRAGMENT) ==
                (NX_IP_FRAGMENT_MASK | NX_IP_MORE_FRAGMENT))
        {
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
            drop_count++;
        }
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
    }
#endif /* NX_DISABLE_IPV4 */

    return NX_TRUE;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_low_watermark_fragment_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Low Watermark Fragment Test...............................N/A\n");

    test_control_return(3);

}
#endif /* NX_ENABLE_LOW_WATERMARK */
