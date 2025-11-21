/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"      
#include   "nx_ip.h"
                                       
extern void  test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

static NX_UDP_SOCKET           socket_0; 

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
static NXD_ADDRESS             address_3;
/* Used to construct a packet whose checksum is 0. */
static UCHAR                   data[4096 * 32 + 2];
#endif
static NXD_ADDRESS             address_2;

static UCHAR                   pool_area[1536*120];


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);  

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nxd_udp_socket_send_special_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
                                              
    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pool_area, sizeof(pool_area));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;             
    
    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);  

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable IPv6 traffic.  */
#ifdef FEATURE_NX_IPV6
    status = nxd_ipv6_enable(&ip_0);

    /* Enable ICMP processing for both IP instances.  */
    status +=  nxd_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    /* Set source and destination address with global address. */    
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010DB8;
    address_0.nxd_ip_address.v6[1] = 0x00010001;
    address_0.nxd_ip_address.v6[2] = 0x021122FF;
    address_0.nxd_ip_address.v6[3] = 0xFE334456;       

    /* Set the destination address.  */
    address_1.nxd_ip_version = NX_IP_VERSION_V6;
    address_1.nxd_ip_address.v6[0] = 0x20010DB8;
    address_1.nxd_ip_address.v6[1] = 0x00010001;
    address_1.nxd_ip_address.v6[2] = 0x021122FF;
    address_1.nxd_ip_address.v6[3] = 0xFE334499;

    /* Set the IPv6 address.  */
    status += nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL); 

    /* Check for status.  */
    if (status)
        error_counter++;

    address_3.nxd_ip_version = NX_IP_VERSION_V6;
    address_3.nxd_ip_address.v6[0] = 0x30010DB8;
    address_3.nxd_ip_address.v6[1] = 0x00010001;
    address_3.nxd_ip_address.v6[2] = 0x021122FF;
    address_3.nxd_ip_address.v6[3] = 0xFE334499;
#endif /* FEATURE_NX_IPV6 */  

    address_2.nxd_ip_version = NX_IP_VERSION_V4;
    address_2.nxd_ip_address.v4 = IP_ADDRESS(111, 222, 222, 222);
}                     

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;  

    /* Print out some test information banners.  */
    printf("NetX Test:   NXD UDP Socket Send Special Test..........................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Sleep 5 seconds to finish DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */   

    /* Create udp socket without ip instance. */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if(status)
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

    /* Append the packet.  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Socket is not bound, should return error. */
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_2, 0x89);  
    if(status != NX_NOT_BOUND)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, 2 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the the packet with an address that will cause route fail.  */
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_2, 0x89);  
    if (status != NX_IP_ADDRESS_ERROR)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }           

#ifdef FEATURE_NX_IPV6  
    /* Send the the packet with an address that will cause route fail. */
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_3, 0x89);  
    if (status != NX_NO_INTERFACE_ADDRESS)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }  
#endif


    nx_packet_release(my_packet);

#ifdef FEATURE_NX_IPV6
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set data to let checksum be 0. */
    memset(data, 0xff, 4096 * 32 + 2);
    data[4096*32 - 1] = 0x9f;
    data[4096*32] = 0xd5;
    data[4096*32 + 1] = 0x39;

    status = nx_packet_data_append(my_packet, data, sizeof(data), &pool_0, NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the UDP packet.  */
    status =  nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);
    if(status != NX_SUCCESS)
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
void    netx_nxd_udp_socket_send_special_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NXD UDP Socket Send Special Test..........................N/A\n");

    test_control_return(3);  
}      
#endif
