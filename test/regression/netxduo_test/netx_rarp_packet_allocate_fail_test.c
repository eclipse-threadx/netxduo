/* This NetX test concentrates on the auxiliary packet usage of RARP module.  */

#include   "tx_api.h"
#include   "nx_api.h"   
#include   "nx_rarp.h"        
#include   "nx_ram_network_driver_test_1500.h"

extern VOID    test_control_return(UINT status);

#if !defined(NX_DISABLE_RARP_INFO) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          no_packet_pool_0;
static NX_PACKET_POOL          no_packet_pool_1;
static NX_IP                   ip_0;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
extern VOID    test_control_return(UINT status);       
extern VOID    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);      
                                                                         
#define NX_ETHERNET_RARP    0x8035
#define NX_ETHERNET_SIZE    14

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
VOID    netx_rarp_packet_allocate_fail_test_application_define(VOID *first_unused_memory)
#endif
{

CHAR       *pointer;
UINT        status;
NX_PACKET  *pkt_ptr;
UINT        header_size = sizeof(NX_PACKET);

    
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

    /* Create an auxiliary packet pool. */
#if defined(__PRODUCT_NETXDUO__) && defined(NX_PACKET_ALIGNMENT)
    header_size = (sizeof(NX_PACKET) + NX_PACKET_ALIGNMENT - 1) / NX_PACKET_ALIGNMENT * NX_PACKET_ALIGNMENT;
    pointer = (CHAR *)(((ALIGN_TYPE)pointer + NX_PACKET_ALIGNMENT - 1) / NX_PACKET_ALIGNMENT * NX_PACKET_ALIGNMENT);
#endif 
    status =  nx_packet_pool_create(&no_packet_pool_0, "NetX Auxiliary Packet Pool", 256, pointer, (256 + header_size));
    pointer = pointer + 256 + header_size;

    if (status)
        error_counter++;

    /* Create a packet pool with no packet. */
    status =  nx_packet_pool_create(&no_packet_pool_1, "NetX No Packet Pool", 256, pointer, (256 + header_size));
    pointer = pointer + 256 + header_size;

    if (status)
        error_counter++;

    /* Allocate the only one packet from pool. */
    nx_packet_allocate(&no_packet_pool_0, &pkt_ptr, NX_TCP_PACKET, NX_NO_WAIT);
    nx_packet_allocate(&no_packet_pool_1, &pkt_ptr, NX_TCP_PACKET, NX_NO_WAIT);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", 0, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (VOID *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
}
                          

/* Define the test threads.  */

static VOID    ntest_0_entry(ULONG thread_input)
{

UINT        status;

    /* Print out some test information banners.  */
    printf("NetX Test:   RARP Packet Allocate Fail Test............................");
            
    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Set packet pool to empty one. */
    ip_0.nx_ip_default_packet_pool = &no_packet_pool_0;
#ifdef NX_ENABLE_DUAL_PACKET_POOL
    ip_0.nx_ip_auxiliary_packet_pool = &no_packet_pool_0;
#endif /* NX_ENABLE_DUAL_PACKET_POOL */

   /* Enable RARP for IP Instance 0.  */
    status  =  nx_rarp_enable(&ip_0);
    if (status)           
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                              

    /* Waiting NetX sending the RARP request to get the address.  */
    tx_thread_sleep(1.5 * NX_IP_PERIODIC_RATE);     

    /* No RARP request should be sent due to no packet. */
    if ((ip_0.nx_ip_rarp_requests_sent) || (no_packet_pool_0.nx_packet_pool_empty_requests == 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef NX_ENABLE_DUAL_PACKET_POOL
    /* Set auxiliry packet pool to empty one. */
    ip_0.nx_ip_auxiliary_packet_pool = &no_packet_pool_1;

    /* Waiting NetX sending the RARP request to get the address.  */
    tx_thread_sleep(1.5 * NX_IP_PERIODIC_RATE);     

    /* No RARP request should be sent due to no packet. */
    if ((ip_0.nx_ip_rarp_requests_sent) || (no_packet_pool_1.nx_packet_pool_empty_requests == 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_ENABLE_DUAL_PACKET_POOL */

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
VOID    netx_rarp_packet_allocate_fail_test_application_define(VOID *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   RARP Packet Allocate Fail Test............................N/A\n");

    test_control_return(3);

}
#endif /* NX_ENABLE_DUAL_PACKET_POOL */
