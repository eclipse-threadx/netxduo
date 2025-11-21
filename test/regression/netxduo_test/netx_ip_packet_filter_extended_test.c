/* This NetX test concentrates on the ICMP ping operation.  */

#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if defined(NX_ENABLE_IP_PACKET_FILTER) && !defined(NX_DISABLE_ICMP_INFO) && defined(__PRODUCT_NETXDUO__)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             global_address_0; 
static NXD_ADDRESS             global_address_1;  
#endif /* FEATURE_NX_IPV6 */


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static UINT    drop_incoming_packet_extended(struct NX_IP_STRUCT *ip_ptr, NX_PACKET *packet_ptr, UINT direction);
static UINT    drop_outgoing_packet_extended(struct NX_IP_STRUCT *ip_ptr, NX_PACKET *packet_ptr, UINT direction);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_packet_filter_extended_test_application_define(void *first_unused_memory)
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

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
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
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 
    status += nxd_ipv6_enable(&ip_1);

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;
                          
    /* Enable ICMPv6 processing.  */
    status = nxd_icmp_enable(&ip_0);      
    status += nxd_icmp_enable(&ip_1);   

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;
    
    /* Set ipv6 global address for IP instance 0.  */
    global_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_0.nxd_ip_address.v6[0] = 0x20010000;
    global_address_0.nxd_ip_address.v6[1] = 0x00000000;
    global_address_0.nxd_ip_address.v6[2] = 0x00000000;
    global_address_0.nxd_ip_address.v6[3] = 0x10000001;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &global_address_0, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;       

    /* Set ipv6 global address for IP instance 1.  */
    global_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_1.nxd_ip_address.v6[0] = 0x20010000;
    global_address_1.nxd_ip_address.v6[1] = 0x00000000;
    global_address_1.nxd_ip_address.v6[2] = 0x00000000;
    global_address_1.nxd_ip_address.v6[3] = 0x10000002;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_1, 0, &global_address_1, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;   
#endif /* FEATURE_NX_IPV6 */
}                 


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
UINT        test_sent = 0;
UINT        test_responses_received = 0;
UINT        test_received = 0;
UINT        test_responded_to = 0;
    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Packet Filter Extended Test............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);     

#ifndef NX_DISABLE_IPV4
    /* Do not set packet filter. */
    ip_0.nx_ip_packet_filter_extended = NX_NULL;

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
    nx_packet_release(my_packet);

    test_sent++; test_responses_received++;
    test_received++; test_responded_to++;

    /* Check ping sent and ping received. */
    if ((ip_0.nx_ip_pings_sent != test_sent) ||
        (ip_0.nx_ip_ping_responses_received != test_responses_received) ||
        (ip_1.nx_ip_pings_received != test_received) ||
        (ip_1.nx_ip_pings_responded_to != test_responded_to))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Set packet filter to drop outgoing packet. */
    ip_0.nx_ip_packet_filter_extended = drop_outgoing_packet_extended;

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    test_sent++; 

    /* Check ping sent and ping received. */
    if ((ip_0.nx_ip_pings_sent != test_sent) ||
        (ip_0.nx_ip_ping_responses_received != test_responses_received) ||
        (ip_1.nx_ip_pings_received != test_received) ||
        (ip_1.nx_ip_pings_responded_to != test_responded_to))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Set packet filter to drop incoming packet. */
    ip_0.nx_ip_packet_filter_extended = drop_incoming_packet_extended;

    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    test_sent++; 
    test_received++; test_responded_to++;

    /* Check ping sent and ping received. */
    if ((ip_0.nx_ip_pings_sent != test_sent) ||
        (ip_0.nx_ip_ping_responses_received != test_responses_received) ||
        (ip_1.nx_ip_pings_received != test_received) ||
        (ip_1.nx_ip_pings_responded_to != test_responded_to))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

#ifdef FEATURE_NX_IPV6
    /* Do not set packet filter. */
    ip_0.nx_ip_packet_filter_extended = NX_NULL;

    status =  nxd_icmp_ping(&ip_0, &global_address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    nx_packet_release(my_packet);

    test_sent++; test_responses_received++;
    test_received++; test_responded_to++;

    /* Check ping sent and ping received. */
    if ((ip_0.nx_ip_pings_sent != test_sent) ||
        (ip_0.nx_ip_ping_responses_received != test_responses_received) ||
        (ip_1.nx_ip_pings_received != test_received) ||
        (ip_1.nx_ip_pings_responded_to != test_responded_to))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Set packet filter to drop outgoing packet. */
    ip_0.nx_ip_packet_filter_extended = drop_outgoing_packet_extended;

    status =  nxd_icmp_ping(&ip_0, &global_address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    test_sent++;

    /* Check ping sent and ping received. */
    if ((ip_0.nx_ip_pings_sent != test_sent) ||
        (ip_0.nx_ip_ping_responses_received != test_responses_received) ||
        (ip_1.nx_ip_pings_received != test_received) ||
        (ip_1.nx_ip_pings_responded_to != test_responded_to))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Set packet filter to drop incoming packet. */
    ip_0.nx_ip_packet_filter_extended = drop_incoming_packet_extended;

    status =  nxd_icmp_ping(&ip_0, &global_address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
    
    test_sent++;
    test_received++; test_responded_to++;

    /* Check ping sent and ping received. */
    if ((ip_0.nx_ip_pings_sent != test_sent) ||
        (ip_0.nx_ip_ping_responses_received != test_responses_received) ||
        (ip_1.nx_ip_pings_received != test_received) ||
        (ip_1.nx_ip_pings_responded_to != test_responded_to))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* FEATURE_NX_IPV6 */

    printf("SUCCESS!\n");
    test_control_return(0);
}         

static UINT    drop_incoming_packet_extended(struct NX_IP_STRUCT *ip_ptr, NX_PACKET *packet_ptr, UINT direction)
{
    if (direction == NX_IP_PACKET_IN)
    {
        return(NX_INVALID_PACKET);
    }
    return(NX_SUCCESS);
}

static UINT    drop_outgoing_packet_extended(struct NX_IP_STRUCT *ip_ptr, NX_PACKET *packet_ptr, UINT direction)
{
    if (direction == NX_IP_PACKET_OUT)
    {
        return(NX_INVALID_PACKET);
    }
    return(NX_SUCCESS);
}

#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_packet_filter_extended_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   IP Packet Filter Extended Test............................N/A\n");
    
    test_control_return(3);
}
#endif
