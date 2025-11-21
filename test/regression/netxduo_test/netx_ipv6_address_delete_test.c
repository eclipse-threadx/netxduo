/* This test case validates nxd_ipv6_address_delete. */

#include    "tx_api.h"
#include    "nx_api.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6) && (NX_MAX_PHYSICAL_INTERFACES > 1)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"


#define     DEMO_STACK_SIZE         2048
#define     TEST_INTERFACE          0

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

static NXD_ADDRESS             if0_lla;
static NXD_ADDRESS             if1_lla;
static NXD_ADDRESS             if0_ga0;
static NXD_ADDRESS             if0_ga1;
static NXD_ADDRESS             if0_ga2;
static NXD_ADDRESS             if1_ga0;
static NXD_ADDRESS             if1_ga1;
static NXD_ADDRESS             if1_ga2;
static NXD_ADDRESS             if1_ga3;
static NXD_ADDRESS             if2_ga0;
static UINT                    if0_lla_index;
static UINT                    if0_ga0_index;
static UINT                    if0_ga1_index;
static UINT                    if0_ga2_index;
static UINT                    if1_ga0_index;
static UINT                    if1_ga1_index;
 #ifndef NX_DISABLE_ERROR_CHECKING
static UINT                    if1_ga3_index;
static UINT                    if2_ga0_index;
#endif /* NX_DISABLE_ERROR_CHECKING */


#define PRIMARY_INTERFACE 0
#define SECONDARY_INTERFACE 1

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);

extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_address_delete_application_define(void *first_unused_memory)
#endif
{
    CHAR       *pointer;
    UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Set up IF0 LLA. */
    if0_lla.nxd_ip_version = NX_IP_VERSION_V6;
    if0_lla.nxd_ip_address.v6[0] = 0xFE800000;
    if0_lla.nxd_ip_address.v6[1] = 0x00000000;
    if0_lla.nxd_ip_address.v6[2] = 0x00000000;
    if0_lla.nxd_ip_address.v6[3] = 0x00000001;

    /* Set up IF1 LLA. */
    if1_lla.nxd_ip_version = NX_IP_VERSION_V6;
    if1_lla.nxd_ip_address.v6[0] = 0xFE800000;
    if1_lla.nxd_ip_address.v6[1] = 0x00000000;
    if1_lla.nxd_ip_address.v6[2] = 0x00000000;
    if1_lla.nxd_ip_address.v6[3] = 0x00000002;

    /* Set up IF0 GA0 */
    if0_ga0.nxd_ip_version = NX_IP_VERSION_V6;
    if0_ga0.nxd_ip_address.v6[0] = 0x20010000;
    if0_ga0.nxd_ip_address.v6[1] = 0x00000000;
    if0_ga0.nxd_ip_address.v6[2] = 0x00000000;
    if0_ga0.nxd_ip_address.v6[3] = 0x00010001;

    /* Set up IF0 GA1 */
    if0_ga1.nxd_ip_version = NX_IP_VERSION_V6;
    if0_ga1.nxd_ip_address.v6[0] = 0x20010000;
    if0_ga1.nxd_ip_address.v6[1] = 0x00000000;
    if0_ga1.nxd_ip_address.v6[2] = 0x00000000;
    if0_ga1.nxd_ip_address.v6[3] = 0x00010002;

    /* Set up IF0 GA2 */
    if0_ga2.nxd_ip_version = NX_IP_VERSION_V6;
    if0_ga2.nxd_ip_address.v6[0] = 0x20010000;
    if0_ga2.nxd_ip_address.v6[1] = 0x00000000;
    if0_ga2.nxd_ip_address.v6[2] = 0x00000000;
    if0_ga2.nxd_ip_address.v6[3] = 0x00010003;

    /* Set up IF1 GA0 */
    if1_ga0.nxd_ip_version = NX_IP_VERSION_V6;
    if1_ga0.nxd_ip_address.v6[0] = 0x20010000;
    if1_ga0.nxd_ip_address.v6[1] = 0x00000000;
    if1_ga0.nxd_ip_address.v6[2] = 0x00000000;
    if1_ga0.nxd_ip_address.v6[3] = 0x00020001;

    /* Set up IF1 GA1 */
    if1_ga1.nxd_ip_version = NX_IP_VERSION_V6;
    if1_ga1.nxd_ip_address.v6[0] = 0x20010000;
    if1_ga1.nxd_ip_address.v6[1] = 0x00000000;
    if1_ga1.nxd_ip_address.v6[2] = 0x00000000;
    if1_ga1.nxd_ip_address.v6[3] = 0x00020002;

    /* Set up IF1 GA2 */
    if1_ga2.nxd_ip_version = NX_IP_VERSION_V6;
    if1_ga2.nxd_ip_address.v6[0] = 0x20010000;
    if1_ga2.nxd_ip_address.v6[1] = 0x00000000;
    if1_ga2.nxd_ip_address.v6[2] = 0x00000000;
    if1_ga2.nxd_ip_address.v6[3] = 0x00020003;

    /* Set up IF1 GA3 */
    if1_ga3.nxd_ip_version = NX_IP_VERSION_V6;
    if1_ga3.nxd_ip_address.v6[0] = 0x20010000;
    if1_ga3.nxd_ip_address.v6[1] = 0x00000000;
    if1_ga3.nxd_ip_address.v6[2] = 0x00000000;
    if1_ga3.nxd_ip_address.v6[3] = 0x00020004;

    /* Set up IF2 GA0 */
    if2_ga0.nxd_ip_version = NX_IP_VERSION_V6;
    if2_ga0.nxd_ip_address.v6[0] = 0x20010000;
    if2_ga0.nxd_ip_address.v6[1] = 0x00000000;
    if2_ga0.nxd_ip_address.v6[2] = 0x00000000;
    if2_ga0.nxd_ip_address.v6[3] = 0x00030001;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);

}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
    UINT       status;
    UINT       i;

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Address Delete Test .................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Attach two more interface. */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", 0x02010101, 0xFFFFFF00, _nx_ram_network_driver_1500);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address0 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_lla, 64, &if0_lla_index);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address0 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga0, 64, &if0_ga0_index);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address1 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga1, 64, &if0_ga1_index);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address2 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga2, 64, &if0_ga2_index); 
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address0 on the 2nd interface. */
    status = nxd_ipv6_address_set(&ip_0, SECONDARY_INTERFACE, &if1_ga0, 64, &if1_ga0_index);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address1 on the 2nd interface. */
    status = nxd_ipv6_address_set(&ip_0, SECONDARY_INTERFACE, &if1_ga1, 64, &if1_ga1_index);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

 #ifndef NX_DISABLE_ERROR_CHECKING
    /* This assumes the max entry of IPv6 address is 6. */
    if(NX_MAX_IPV6_ADDRESSES == 6)
    {

        /* Set Global address3 on the 2nd interface.  This one should fail.*/
        status = nxd_ipv6_address_set(&ip_0, SECONDARY_INTERFACE, &if1_ga3, 64, &if1_ga3_index);
        if(status != NX_NO_MORE_ENTRIES)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* This assumes the max physical interface is 2. */
    if(NX_MAX_PHYSICAL_INTERFACES == 2)
    {

        /* Set global address0 on the 3rd interface. This one should fail. */
        status = nxd_ipv6_address_set(&ip_0, 2, &if2_ga0, 64, &if2_ga0_index);
        if(status != NX_INVALID_INTERFACE)
        {
            test_control_return(1);
        }
    }
#endif /* NX_DISABLE_ERROR_CHECKING */


    /* Verify the IP addresses just set. */
    if((!CHECK_IPV6_ADDRESSES_SAME(ip_0.nx_ipv6_address[if0_lla_index].nxd_ipv6_address, if0_lla.nxd_ip_address.v6)) ||
       (!CHECK_IPV6_ADDRESSES_SAME(ip_0.nx_ipv6_address[if0_ga0_index].nxd_ipv6_address, if0_ga0.nxd_ip_address.v6)) ||
       (!CHECK_IPV6_ADDRESSES_SAME(ip_0.nx_ipv6_address[if0_ga1_index].nxd_ipv6_address, if0_ga1.nxd_ip_address.v6)) ||
       (!CHECK_IPV6_ADDRESSES_SAME(ip_0.nx_ipv6_address[if0_ga2_index].nxd_ipv6_address, if0_ga2.nxd_ip_address.v6)) ||
       (!CHECK_IPV6_ADDRESSES_SAME(ip_0.nx_ipv6_address[if1_ga0_index].nxd_ipv6_address, if1_ga0.nxd_ip_address.v6)) ||       
       (!CHECK_IPV6_ADDRESSES_SAME(ip_0.nx_ipv6_address[if1_ga1_index].nxd_ipv6_address, if1_ga1.nxd_ip_address.v6)))  

    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete all IPv6 addresses on IF0 */
    status = nxd_ipv6_address_delete(&ip_0, if0_lla_index);
    status += nxd_ipv6_address_delete(&ip_0, if0_ga0_index);
    status += nxd_ipv6_address_delete(&ip_0, if0_ga1_index);
    status += nxd_ipv6_address_delete(&ip_0, if0_ga2_index);
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Make sure there are no IPv6 addresses on IF0 */
    if(ip_0.nx_ip_interface[PRIMARY_INTERFACE].nxd_interface_ipv6_address_list_head)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete all IPv6 address on IF1 */
    status = nxd_ipv6_address_delete(&ip_0, if1_ga0_index);
    status += nxd_ipv6_address_delete(&ip_0, if1_ga1_index);
    
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Make sure there are no IPv6 addresses on IF0 */
    if(ip_0.nx_ip_interface[SECONDARY_INTERFACE].nxd_interface_ipv6_address_list_head)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    if(ip_0.nx_ipv6_address[0].nxd_ipv6_address_valid || ip_0.nx_ipv6_address[1].nxd_ipv6_address_valid || ip_0.nx_ipv6_address[2].nxd_ipv6_address_valid ||
       ip_0.nx_ipv6_address[3].nxd_ipv6_address_valid || ip_0.nx_ipv6_address[4].nxd_ipv6_address_valid || ip_0.nx_ipv6_address[5].nxd_ipv6_address_valid ||
       (ip_0.nx_ip_interface[PRIMARY_INTERFACE].nxd_interface_ipv6_address_list_head != NX_NULL))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the 1nd address on the 2nd interface  */
    for(i = 0; i < NX_MAX_IPV6_ADDRESSES; i++)
    {
        status = nxd_ipv6_address_delete(&ip_0, i);
        
        if(status != NX_NO_INTERFACE_ADDRESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nxd_ipv6_address_delete(&ip_0, NX_MAX_IPV6_ADDRESSES);
    if(status != NX_NO_INTERFACE_ADDRESS)
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
void           netx_ipv6_address_delete_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Address Delete Test .................................N/A\n");

    test_control_return(3);

}
#endif
