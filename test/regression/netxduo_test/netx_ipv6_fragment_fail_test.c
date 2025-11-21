/* This NetX test concentrates on fragment IPv6 packet fail due to empty packet pool.  */

#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void  test_control_return(UINT status);
#if !defined(NX_DISABLE_FRAGMENTATION) && defined(FEATURE_NX_IPV6)  
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NXD_ADDRESS             addr_0, addr_1;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                    send_buff[2000];


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_fragment_fail_test_application_define(void *first_unused_memory)
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

    /* Create a packet pool with two packets available.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 4000);
    pointer = pointer + 4000;

    if (status)
        error_counter++;

    /* Create another packet pool.  */
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 1536, pointer, 15360);
    pointer = pointer + 15360;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create an IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ICMP processing.  */
    status +=  nxd_icmp_enable(&ip_0);
    status +=  nxd_icmp_enable(&ip_1);
  
    /* Enable IPv6 */
    status += nxd_ipv6_enable(&ip_0); 
    status += nxd_ipv6_enable(&ip_1); 
  
    /* Enable fragmentation */
    status += nx_ip_fragment_enable(&ip_0); 
    status += nx_ip_fragment_enable(&ip_1); 

    /* Check status.  */
    if(status)
        error_counter++;        
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Fragment Fail Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set IPv6 address. */
    addr_0.nxd_ip_version = NX_IP_VERSION_V6;
    addr_0.nxd_ip_address.v6[0] = 0xFE800000;
    addr_0.nxd_ip_address.v6[1] = 0x00000000;
    addr_0.nxd_ip_address.v6[2] = 0x00000000;
    addr_0.nxd_ip_address.v6[3] = 0x00000001;
    addr_1.nxd_ip_version = NX_IP_VERSION_V6;
    addr_1.nxd_ip_address.v6[0] = 0xFE800000;
    addr_1.nxd_ip_address.v6[1] = 0x00000000;
    addr_1.nxd_ip_address.v6[2] = 0x00000000;
    addr_1.nxd_ip_address.v6[3] = 0x00000002;
    
    status = nxd_ipv6_address_set(&ip_0, 0, &addr_0, 10, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &addr_1, 10, NX_NULL);

    /* Check status */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Ping IP_1 to make sure ND cache is filled. */
    status = nxd_icmp_ping(&ip_0, &addr_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &packet_ptr, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    nx_packet_release(packet_ptr);

    /* Now send a ping that takes two packets. */
    status = nxd_icmp_ping(&ip_0, &addr_1, send_buff, sizeof(send_buff), &packet_ptr, NX_IP_PERIODIC_RATE);

    /* Check status */
    if(status == NX_SUCCESS)
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
void    netx_ipv6_fragment_fail_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   IPv6 Fragment Fail Test...................................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_ICMP_INFO */
