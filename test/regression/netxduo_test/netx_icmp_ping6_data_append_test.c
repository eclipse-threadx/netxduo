/* This NetX test concentrates on the ICMP Interface Ping6 data append operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"        

extern void    test_control_return(UINT status);
#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_FRAGMENTATION)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static NXD_ADDRESS             global_address_0;
static NXD_ADDRESS             global_address_1;
static CHAR                    data[4096];


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping6_data_append_test_application_define(void *first_unused_memory)
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

    /* Create a packet pool, packet payload size is 256, packet counts is 10.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, ((sizeof(NX_PACKET) + 256) * 10));
    pointer = pointer + 4096;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 
    status += nxd_ipv6_enable(&ip_1);

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMPv6 processing for IP instances0 .  */
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
}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
UINT        i;

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Ping6 Data Append Test...............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Initialize the data.  */
    for (i = 0; i < 4096; i ++)
        data[i] = 'A';

    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);     

    /* Ping an IP address that does exist. One packet size is 256, use 2 packets.  */
    status = nxd_icmp_ping(&ip_0, &global_address_1, data, 400, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an IP address that does exist. One packet size is 256, use 20 packets, data append failure.  */
    status = nxd_icmp_ping(&ip_0, &global_address_1, data, 4096, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status != NX_OVERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}         
#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_ping6_data_append_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Ping6 Data Append Test...............................N/A\n");
    
    test_control_return(3);
}
#endif
