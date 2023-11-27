/* This NetX test concentrates on the basic multicast IGMP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status); 
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6) && (NX_MAX_PHYSICAL_INTERFACES > 1)
#define     DEMO_STACK_SIZE     2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input); 
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_multicast_interface_detach_test_application_define(void *first_unused_memory)
#endif
{

    CHAR    *pointer;
    UINT    status;


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
              
    /* Check the status.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer =  pointer + 2048;            

    /* Check the status.  */
    if(status)
        error_counter++;

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_512);

    /* Check the status.  */
    if(status)
        error_counter++;
}
                     

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NXD_ADDRESS group_address[8];           

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Multicast Interface Detach Test......................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                  
    /* Set the group address .  */ 
    group_address[0].nxd_ip_version = NX_IP_VERSION_V6;
    group_address[0].nxd_ip_address.v6[0] = 0xff020000;
    group_address[0].nxd_ip_address.v6[1] = 0x00000000;
    group_address[0].nxd_ip_address.v6[2] = 0x00000000;
    group_address[0].nxd_ip_address.v6[3] = 0x01020301;    

    /* Set the group address .  */ 
    group_address[1].nxd_ip_version = NX_IP_VERSION_V6;
    group_address[1].nxd_ip_address.v6[0] = 0xff020000;
    group_address[1].nxd_ip_address.v6[1] = 0x00000000;
    group_address[1].nxd_ip_address.v6[2] = 0x00000000;
    group_address[1].nxd_ip_address.v6[3] = 0x01020302;  

    /* Set the group address .  */ 
    group_address[2].nxd_ip_version = NX_IP_VERSION_V6;
    group_address[2].nxd_ip_address.v6[0] = 0xff020000;
    group_address[2].nxd_ip_address.v6[1] = 0x00000000;
    group_address[2].nxd_ip_address.v6[2] = 0x00000000;
    group_address[2].nxd_ip_address.v6[3] = 0x01020303;

    /* Set the group address .  */ 
    group_address[3].nxd_ip_version = NX_IP_VERSION_V6;
    group_address[3].nxd_ip_address.v6[0] = 0xff020000;
    group_address[3].nxd_ip_address.v6[1] = 0x00000000;
    group_address[3].nxd_ip_address.v6[2] = 0x00000000;
    group_address[3].nxd_ip_address.v6[3] = 0x01020304;

    /* Set the group address .  */ 
    group_address[4].nxd_ip_version = NX_IP_VERSION_V6;
    group_address[4].nxd_ip_address.v6[0] = 0xff020000;
    group_address[4].nxd_ip_address.v6[1] = 0x00000000;
    group_address[4].nxd_ip_address.v6[2] = 0x00000000;
    group_address[4].nxd_ip_address.v6[3] = 0x01020305;

    /* Set the group address .  */ 
    group_address[5].nxd_ip_version = NX_IP_VERSION_V6;
    group_address[5].nxd_ip_address.v6[0] = 0xff020000;
    group_address[5].nxd_ip_address.v6[1] = 0x00000000;
    group_address[5].nxd_ip_address.v6[2] = 0x00000000;
    group_address[5].nxd_ip_address.v6[3] = 0x01020306;

    /* Set the group address .  */ 
    group_address[6].nxd_ip_version = NX_IP_VERSION_V6;
    group_address[6].nxd_ip_address.v6[0] = 0xff020000;
    group_address[6].nxd_ip_address.v6[1] = 0x00000000;
    group_address[6].nxd_ip_address.v6[2] = 0x00000000;
    group_address[6].nxd_ip_address.v6[3] = 0x01020307;

    /* Set the group address .  */ 
    group_address[7].nxd_ip_version = NX_IP_VERSION_V6;
    group_address[7].nxd_ip_address.v6[0] = 0xff020000;
    group_address[7].nxd_ip_address.v6[1] = 0x00000000;
    group_address[7].nxd_ip_address.v6[2] = 0x00000000;
    group_address[7].nxd_ip_address.v6[3] = 0x01020308;

    /* Perform IGMP join operations.  */
    status = nxd_ipv6_multicast_interface_join(&ip_0, &group_address[0],  1); 
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[1], 1);   
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[1], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[2], 1); 
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[2], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[2], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[3], 1); 
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[3], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[3], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[3], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[4], 1);  
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[4], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[4], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[4], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[4], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[5], 1); 
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[5], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[5], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[5], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[5], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[5], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[6], 1);
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[6], 1);   
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[6], 1);  
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[6], 1);  
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[6], 1);  
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[6], 1);  
    status += nxd_ipv6_multicast_interface_join(&ip_0, &group_address[6], 1);  
                   
    /* Check status.  */
    if(status)
        error_counter ++;

    /* Detach the seconde interface.  */
    status = nx_ip_interface_detach(&ip_0, 1);      
                   
    /* Check status.  */
    if(status)
        error_counter ++;

    /* Check the groups info.  */
    if((ip_0.nx_ipv6_multicast_groups_joined != 0) ||
       (ip_0.nx_ipv6_multicast_entry[0].nx_ip_mld_join_count != 0) ||
       (ip_0.nx_ipv6_multicast_entry[1].nx_ip_mld_join_count != 0) ||
       (ip_0.nx_ipv6_multicast_entry[2].nx_ip_mld_join_count != 0) ||
       (ip_0.nx_ipv6_multicast_entry[3].nx_ip_mld_join_count != 0) ||
       (ip_0.nx_ipv6_multicast_entry[4].nx_ip_mld_join_count != 0) ||
       (ip_0.nx_ipv6_multicast_entry[5].nx_ip_mld_join_count != 0) ||
       (ip_0.nx_ipv6_multicast_entry[6].nx_ip_mld_join_count != 0))
        error_counter ++;

    /* Check for status.  */
    if(error_counter)
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
void    netx_ipv6_multicast_interface_detach_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   IPv6 Multicast Interface Detach Test......................N/A\n");
    test_control_return(3);   
}
#endif /* NX_ENABLE_IPV6_MULTICAST */
