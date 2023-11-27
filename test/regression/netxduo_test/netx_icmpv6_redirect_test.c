/* This NetX test to test the ICMPv6 Echo request process.  */

#include    "tx_api.h"
#include    "nx_api.h"
extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_ICMPV6_REDIRECT_PROCESS)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"    
#include    "nx_icmpv6.h"
#include    "nx_ram_network_driver_test_1500.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;           
static ULONG                   echo_request_sent;


/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* ICMPv6 redirect to 3ffe:501:ffff::200:ff:fe00:100. */
static const unsigned char pkt1[] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, 
0x00, 0x00, 0xa0, 0xa0, 0x86, 0xdd, 0x60, 0x00, 
0x00, 0x00, 0x00, 0x30, 0x3a, 0xff, 0xfe, 0x80, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0x3f, 0xfe, 
0x05, 0x01, 0xff, 0xff, 0x01, 0x00, 0x02, 0x11, 
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x89, 0x00, 
0x97, 0xda, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xfe, 
0x05, 0x01, 0xff, 0xff, 0x00, 0x00, 0x02, 0x00, 
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0x3f, 0xfe, 
0x05, 0x01, 0xff, 0xff, 0x00, 0x00, 0x02, 0x00, 
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0x02, 0x01, 
0x00, 0x00, 0x00, 0x00, 0x01, 0x00 };


/* ICMPv6 redirect to 3ffe:501:ffff::300:ff:fe00:100. */
static const unsigned char pkt2[102] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0xa0, 0xa0, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x30, 0x3a, 0xff, 0xfe, 0x80, /* ...0:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0x3f, 0xfe, /* ......?. */
0x05, 0x01, 0xff, 0xff, 0x01, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x89, 0x00, /* "..3DV.. */
0x95, 0xda, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xfe, /* ......?. */
0x05, 0x01, 0xff, 0xff, 0x00, 0x00, 0x03, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0x3f, 0xfe, /* ......?. */
0x05, 0x01, 0xff, 0xff, 0x00, 0x00, 0x03, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0x02, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x01, 0x00              /* ...... */
};


/* ICMPv6 redirect to 3ffe:501:ffff::200:ff:fe00:100. 
 * MTU in MTU option is 1484 */
static const unsigned char pkt3[110] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0xa0, 0xa0, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x38, 0x3a, 0xff, 0xfe, 0x80, /* ...8:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0x3f, 0xfe, /* ......?. */
0x05, 0x01, 0xff, 0xff, 0x01, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x89, 0x00, /* "..3DV.. */
0x92, 0x40, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, /* .0...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa1, 0xa1, 0x3f, 0xfe, /* ......?. */
0x05, 0x01, 0xff, 0xff, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0x05, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x05, 0xcc, 0x02, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0xa1, 0xa1              /* ...... */
};


/* ICMPv6 redirect to 3ffe:501:ffff::200:ff:fe00:100. 
 * MTU in MTU option is 1244 */
static const unsigned char pkt4[110] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0xa0, 0xa0, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x38, 0x3a, 0xff, 0xfe, 0x80, /* ...8:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0x3f, 0xfe, /* ......?. */
0x05, 0x01, 0xff, 0xff, 0x01, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x89, 0x00, /* "..3DV.. */
0x92, 0x32, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, /* .0...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa1, 0xa1, 0x3f, 0xfe, /* ......?. */
0x05, 0x01, 0xff, 0xff, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0x05, 0xff, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x04, 0xdc, 0x02, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0xa1, 0xa1              /* ...... */
};

/* ICMPv6 redirect to 3ffe:501:ffff::200:ff:fe00:100. 
 * MTU in MTU option is 1200, less than NX_MINIMUM_IPV6_PATH_MTU */
static const unsigned char pkt5[110] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0xa0, 0xa0, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x38, 0x3a, 0xff, 0xfe, 0x80, /* ...8:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0x3f, 0xfe, /* ......?. */
0x05, 0x01, 0xff, 0xff, 0x01, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x89, 0x00, /* "..3DV.. */
0x93, 0x5c, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, /* .0...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa1, 0xa1, 0x3f, 0xfe, /* ......?. */
0x05, 0x01, 0xff, 0xff, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0x05, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x04, 0xb0, 0x02, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0xa1, 0xa1              /* ...... */
};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmpv6_redirect_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    echo_request_sent = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*4);
    pointer = pointer + 1536*4;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = _nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;
                
    /* Check IP create status.  */
    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
                 
    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check ICMP enable status.  */
    if(status)
        error_counter++;

}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT             status;
NX_PACKET       *packet_ptr;   
NXD_ADDRESS      src, dst, dst_2, router;
UINT             i;
    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 Redirect Test......................................");

    /* Setup address. */
    src.nxd_ip_version = NX_IP_VERSION_V6;
    src.nxd_ip_address.v6[0] = 0x3ffe0501;
    src.nxd_ip_address.v6[1] = 0xffff0100;
    src.nxd_ip_address.v6[2] = 0x021122ff;
    src.nxd_ip_address.v6[3] = 0xfe334456;

    dst.nxd_ip_version = NX_IP_VERSION_V6;
    dst.nxd_ip_address.v6[0] = 0x3ffe0501;
    dst.nxd_ip_address.v6[1] = 0xffff0000;
    dst.nxd_ip_address.v6[2] = 0x020000ff;
    dst.nxd_ip_address.v6[3] = 0xfe000100;

    dst_2.nxd_ip_version = NX_IP_VERSION_V6;
    dst_2.nxd_ip_address.v6[0] = 0x3ffe0501;
    dst_2.nxd_ip_address.v6[1] = 0xffff0000;
    dst_2.nxd_ip_address.v6[2] = 0x030000ff;
    dst_2.nxd_ip_address.v6[3] = 0xfe000100;

    router.nxd_ip_version = NX_IP_VERSION_V6;
    router.nxd_ip_address.v6[0] = 0xfe800000;
    router.nxd_ip_address.v6[1] = 0x00000000;
    router.nxd_ip_address.v6[2] = 0x020000ff;
    router.nxd_ip_address.v6[3] = 0xfe00a0a0;

    /* Set the linklocal address*/
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);
    status += nxd_ipv6_address_set(&ip_0, 0, &src, 64, NX_NULL);
       
    /* Check the status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                        
    
    /* Waiting for DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Send ICMP redirect packet to ip_0. */
    /* The redirect destination is 0x3ffe:501:ffff:0:200:ff:fe00:100. */
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_RECEIVE_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt1) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ICMP redirect packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Since this message is not sent from router(no router yet). It should not be added into destination table. */
    if (ip_0.nx_ipv6_destination_table_size != 0)
    {
        error_counter++;
    }

    /* Set router. */
    nxd_ipv6_default_router_add(&ip_0, &router, 60, 0);

    /* Send ICMP redirect packet to ip_0. */
    /* The redirect destination is 0x3ffe:501:ffff:0:200:ff:fe00:100. */
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_RECEIVE_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt1) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ICMP redirect packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Check the destination table. */
    if ((ip_0.nx_ipv6_destination_table_size != 1) || (ip_0.nx_ipv6_destination_table[0].nx_ipv6_destination_entry_valid != NX_TRUE))
    {
        error_counter++;
    }


    /* Now move this desitnation table entry from the first one to the second one. */
    memcpy(&ip_0.nx_ipv6_destination_table[1], &ip_0.nx_ipv6_destination_table[0], sizeof(ip_0.nx_ipv6_destination_table[0]));
    ip_0.nx_ipv6_destination_table[0].nx_ipv6_destination_entry_valid = NX_FALSE; 
    

    /* Send ICMP redirect packet to ip_0. */
    /* The redirect destination is 0x3ffe:501:ffff:0:200:ff:fe00:100. */
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_RECEIVE_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt1) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ICMP redirect packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Check the destination table. */
    if ((ip_0.nx_ipv6_destination_table_size != 1) || (ip_0.nx_ipv6_destination_table[1].nx_ipv6_destination_entry_valid != NX_TRUE))
    {
        error_counter++;
    }

    /* Setup filter function to check whether echo request is sent. */
    advanced_packet_process_callback = my_packet_process;    
    status = nxd_icmp_ping(&ip_0, &dst, "", 0, &packet_ptr, NX_NO_WAIT);

    if ((status == NX_SUCCESS) || (echo_request_sent != 1))
    {
        error_counter++;
    }


    /* Occupy all destination tables. */
    for (i = 0; i < NX_IPV6_DESTINATION_TABLE_SIZE; i++)
    {
        if (i != 1)
        {
            memcpy(&ip_0.nx_ipv6_destination_table[i], &ip_0.nx_ipv6_destination_table[1], sizeof(ip_0.nx_ipv6_destination_table[i]));
            ip_0.nx_ipv6_destination_table_size++;
        }
    }

    /* The redirect destination is 0x3ffe:501:ffff:0:300:ff:fe00:100. */
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_RECEIVE_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt2) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ICMP redirect packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Release destination tables occpied before. */
    for (i = 0; i < NX_IPV6_DESTINATION_TABLE_SIZE; i++)
    {
        if (i != 1)
        {
            ip_0.nx_ipv6_destination_table[i].nx_ipv6_destination_entry_valid = NX_FALSE; 
            ip_0.nx_ipv6_destination_table_size--;
        }
    }


    /* Send ICMP redirect packet to ip_0. */
    /* The redirect destination is 0x3ffe:501:ffff:0:300:ff:fe00:100. */
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_RECEIVE_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt2) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ICMP redirect packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Check the destination table. */
    if (ip_0.nx_ipv6_destination_table_size != 2)
    {
        error_counter++;
    }

    /* Setup filter function to check whether echo request is sent. */
    advanced_packet_process_callback = my_packet_process;    
    status = nxd_icmp_ping(&ip_0, &dst_2, "", 0, &packet_ptr, NX_NO_WAIT);

    if ((status == NX_SUCCESS) || (echo_request_sent != 2))
    {
        error_counter++;
    }


    /* Remove destination entry for 0x3ffe:501:ffff:0:200:ff:fe00:100*/
    ip_0.nx_ipv6_destination_table[1].nx_ipv6_destination_entry_valid = NX_FALSE; 
    ip_0.nx_ipv6_destination_table_size--;

    /* The redirect destination is 0x3ffe:501:ffff:0:200:ff:fe00:100. */
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_RECEIVE_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt3[14], sizeof(pkt3) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt3) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ICMP redirect packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Check the destination table. */
    if (ip_0.nx_ipv6_destination_table_size != 2) 
    {
        error_counter++;
    }

#ifdef NX_ENABLE_IPV6_PATH_MTU_DISCOVERY
    if (ip_0.nx_ipv6_destination_table[1].nx_ipv6_destination_entry_path_mtu != 1484)
    {
        error_counter++;
    }
#endif /* NX_ENABLE_IPV6_PATH_MTU_DISCOVERY */


    /* Remove destination entry for 0x3ffe:501:ffff:0:200:ff:fe00:100*/
    ip_0.nx_ipv6_destination_table[1].nx_ipv6_destination_entry_valid = NX_FALSE; 
    ip_0.nx_ipv6_destination_table_size--;

    /* The redirect destination is 0x3ffe:501:ffff:0:200:ff:fe00:100. */
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_RECEIVE_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt4[14], sizeof(pkt4) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt4) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ICMP redirect packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Check the destination table. The option length is invalid, so the destination table is not updated. */
    if (ip_0.nx_ipv6_destination_table_size != 1)
    {
        error_counter++;
    }

    /* The redirect destination is 0x3ffe:501:ffff:0:200:ff:fe00:100. */
    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_RECEIVE_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt5[14], sizeof(pkt5) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt5) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the ICMP redirect packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);

    /* Check the destination table. */
    if (ip_0.nx_ipv6_destination_table_size != 2) 
    {
        error_counter++;
    }

#ifdef NX_ENABLE_IPV6_PATH_MTU_DISCOVERY
    if (ip_0.nx_ipv6_destination_table[1].nx_ipv6_destination_entry_path_mtu != 1200)
    {
        error_counter++;
    }
#endif /* NX_ENABLE_IPV6_PATH_MTU_DISCOVERY */

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                        

    /* Out successful.  */
    printf("SUCCESS!\n");    
    test_control_return(0);
}                  


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
UCHAR *data = packet_ptr -> nx_packet_prepend_ptr;

    /* Check whether it is an echo request packet. */
    if (packet_ptr -> nx_packet_length == 48)
    {

        /* Is it ICMPv6 packet? */
        if (data[6] == 0x3A)
        {
            /* Is the ICMPv6 type echo request? */
            if (data[40] == 0x80)
            {

                /* It is echo request packet. */
                echo_request_sent++;
                advanced_packet_process_callback = NX_NULL;
            }
        }
    }

    return NX_TRUE;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmpv6_redirect_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 Redirect Test......................................N/A\n");

    test_control_return(3);         
}
#endif
