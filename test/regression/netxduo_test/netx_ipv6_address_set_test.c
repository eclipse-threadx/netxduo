/* This test case validates nxd_ipv6_address_set. */

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

#ifndef NX_DISABLE_ERROR_CHECKING
static NXD_ADDRESS             multicast_addr;
#endif /* NX_DISABLE_ERROR_CHECKING */
static NXD_ADDRESS             if0_lla;
static NXD_ADDRESS             if1_lla;
static NXD_ADDRESS             if0_ga0;
static NXD_ADDRESS             if0_ga1;
static NXD_ADDRESS             if0_ga2;
static NXD_ADDRESS             if0_gax;
static NXD_ADDRESS             if1_ga0;
static NXD_ADDRESS             if1_ga1;
static NXD_ADDRESS             if1_ga2;
static NXD_ADDRESS             if1_ga3;
static NXD_ADDRESS             if2_ga0;

static int if0_lla_check;
static int if0_ga1_check;
static int if0_ga2_check;
static int if1_ga0_check;
static int if1_ga1_check;
static int if1_ga2_check;

static NXD_ADDRESS             if_addr;

#define PRIMARY_INTERFACE 0
#define SECONDARY_INTERFACE 1

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);

extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ipv6_address_set_test_application_define(void *first_unused_memory)
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

#ifndef NX_DISABLE_ERROR_CHECKING
    /* Set up multicast address. */
    multicast_addr.nxd_ip_version = NX_IP_VERSION_V6;
    multicast_addr.nxd_ip_address.v6[0] = 0xFF050000;
    multicast_addr.nxd_ip_address.v6[1] = 0x00000000;
    multicast_addr.nxd_ip_address.v6[2] = 0x00000000;
    multicast_addr.nxd_ip_address.v6[3] = 0x00010003;
#endif /* NX_DISABLE_ERROR_CHECKING */

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);

}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      prefix_length;
UINT       interface_index;
NXD_IPV6_ADDRESS *ipv6_addr_ptr;
UINT       address_count;
UINT       i;
UINT       link_local_address_index;

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Address Set Test.....................................");

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

#ifndef NX_DISABLE_ERROR_CHECKING
    /* Set multicast address on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &multicast_addr, 64, NX_NULL);
    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING */

    /* Set Global address0 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_lla, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address1 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga1, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address2 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga2, 64, NX_NULL); 
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Set link local address on the 1st interface.  */ 
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, NX_NULL, 10, &link_local_address_index);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set link local address on the 1st interface again.  */ 
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, NX_NULL, 10, NX_NULL);
    if(status != NX_DUPLICATED_ENTRY)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the link local address. */
    status = nxd_ipv6_address_delete(&ip_0, link_local_address_index);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address0 on the 2nd interface. */
    status = nxd_ipv6_address_set(&ip_0, SECONDARY_INTERFACE, &if1_ga0, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address1 on the 2nd interface. */
    status = nxd_ipv6_address_set(&ip_0, SECONDARY_INTERFACE, &if1_ga1, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address2 on the 2nd interface. */
    status = nxd_ipv6_address_set(&ip_0, SECONDARY_INTERFACE, &if1_ga2, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    /* Set global address0 on the 3rd interface. This one should fail. */
    status = nxd_ipv6_address_set(&ip_0, 2, &if2_ga0, 64, NX_NULL);
    if(status != NX_INVALID_INTERFACE)
    {
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING */

    /* Now go through all the IPv6 addresses and make sure the values are programmed correctly. */
    if((ip_0.nx_ipv6_address[0].nxd_ipv6_address_valid != 1) ||
       (ip_0.nx_ipv6_address[0].nxd_ipv6_address_type != NX_IP_VERSION_V6) ||
       (memcmp(ip_0.nx_ipv6_address[0].nxd_ipv6_address, &if0_lla.nxd_ip_address.v6[0], 16)) ||
       (ip_0.nx_ipv6_address[0].nxd_ipv6_address_prefix_length != 64) ||
       (ip_0.nx_ipv6_address[0].nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_VALID) ||
       (ip_0.nx_ipv6_address[0].nxd_ipv6_address_attached != &ip_0.nx_ip_interface[0]))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    if((ip_0.nx_ipv6_address[1].nxd_ipv6_address_valid != 1) ||
       (ip_0.nx_ipv6_address[1].nxd_ipv6_address_type != NX_IP_VERSION_V6) ||
       (memcmp(ip_0.nx_ipv6_address[1].nxd_ipv6_address, &if0_ga1.nxd_ip_address.v6[0], 16)) ||
       (ip_0.nx_ipv6_address[1].nxd_ipv6_address_prefix_length != 64) ||
       (ip_0.nx_ipv6_address[1].nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_VALID) ||
       (ip_0.nx_ipv6_address[1].nxd_ipv6_address_attached != &ip_0.nx_ip_interface[0]))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    if((ip_0.nx_ipv6_address[2].nxd_ipv6_address_valid != 1) ||
       (ip_0.nx_ipv6_address[2].nxd_ipv6_address_type != NX_IP_VERSION_V6) ||
       (memcmp(ip_0.nx_ipv6_address[2].nxd_ipv6_address, &if0_ga2.nxd_ip_address.v6[0], 16)) ||
       (ip_0.nx_ipv6_address[2].nxd_ipv6_address_prefix_length != 64) ||
       (ip_0.nx_ipv6_address[2].nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_VALID) ||
       (ip_0.nx_ipv6_address[2].nxd_ipv6_address_attached != &ip_0.nx_ip_interface[0]))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    if((ip_0.nx_ipv6_address[3].nxd_ipv6_address_valid != 1) ||
       (ip_0.nx_ipv6_address[3].nxd_ipv6_address_type != NX_IP_VERSION_V6) ||
       (memcmp(ip_0.nx_ipv6_address[3].nxd_ipv6_address, &if1_ga0.nxd_ip_address.v6[0], 16)) ||
       (ip_0.nx_ipv6_address[3].nxd_ipv6_address_prefix_length != 64) ||
       (ip_0.nx_ipv6_address[3].nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_VALID) ||
       (ip_0.nx_ipv6_address[3].nxd_ipv6_address_attached != &ip_0.nx_ip_interface[1]))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }    
    
    /* Check each interface, making sure they have the proper IPv6 addresses configured. */
    if0_lla_check = if0_ga1_check = if0_ga2_check = if1_ga0_check = 0;
    ipv6_addr_ptr = ip_0.nx_ip_interface[0].nxd_interface_ipv6_address_list_head;
    address_count = 0;
    while(ipv6_addr_ptr)
    {
        if(memcmp(ipv6_addr_ptr -> nxd_ipv6_address, &if0_lla.nxd_ip_address.v6[0], 16) == 0)
            if0_lla_check++;
        if(memcmp(ipv6_addr_ptr -> nxd_ipv6_address, &if0_ga1.nxd_ip_address.v6[0], 16) == 0)
            if0_ga1_check++;
        if(memcmp(ipv6_addr_ptr -> nxd_ipv6_address, &if0_ga2.nxd_ip_address.v6[0], 16) == 0)
            if0_ga2_check++;

        address_count++;
        ipv6_addr_ptr = ipv6_addr_ptr -> nxd_ipv6_address_next;
    }
    if((address_count != 3) || (if0_lla_check != 1) || (if0_ga1_check != 1) || (if0_ga2_check != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }    


    ipv6_addr_ptr = ip_0.nx_ip_interface[1].nxd_interface_ipv6_address_list_head;
    address_count = 0;
    while(ipv6_addr_ptr)
    {
        if(memcmp(ipv6_addr_ptr -> nxd_ipv6_address, &if1_ga0.nxd_ip_address.v6[0], 16) == 0)
            if1_ga0_check++;
        if(memcmp(ipv6_addr_ptr -> nxd_ipv6_address, &if1_ga1.nxd_ip_address.v6[0], 16) == 0)
            if1_ga1_check++;
        if(memcmp(ipv6_addr_ptr -> nxd_ipv6_address, &if1_ga2.nxd_ip_address.v6[0], 16) == 0)
            if1_ga2_check++;

        address_count++;
        ipv6_addr_ptr = ipv6_addr_ptr -> nxd_ipv6_address_next;
    }
    
    if((address_count != 3) || (if1_ga0_check != 1) || (if1_ga1_check != 1) || (if1_ga2_check != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Reprogram all the interface IPv6 addresses. */

    /* Now delete all the IPv6 addresses. */
    for(i = 0; i < 6; i++)
    {
        status = nxd_ipv6_address_delete(&ip_0, i);

        if(status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

    }

    status = nxd_ipv6_address_delete(&ip_0, 6);
    if(status != NX_NO_INTERFACE_ADDRESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Set up IF0 LLA. */
    if0_lla.nxd_ip_version = NX_IP_VERSION_V6;
    if0_lla.nxd_ip_address.v6[0] = 0xFE800000;
    if0_lla.nxd_ip_address.v6[1] = 0x00000000;
    if0_lla.nxd_ip_address.v6[2] = 0x00010000;
    if0_lla.nxd_ip_address.v6[3] = 0x00000001;

    /* Set up IF1 LLA. */
    if1_lla.nxd_ip_version = NX_IP_VERSION_V6;
    if1_lla.nxd_ip_address.v6[0] = 0xFE800000;
    if1_lla.nxd_ip_address.v6[1] = 0x00000000;
    if1_lla.nxd_ip_address.v6[2] = 0x00010000;
    if1_lla.nxd_ip_address.v6[3] = 0x00000002;

    /* Set up IF0 GA0 */
    if0_ga0.nxd_ip_version = NX_IP_VERSION_V6;
    if0_ga0.nxd_ip_address.v6[0] = 0x20010000;
    if0_ga0.nxd_ip_address.v6[1] = 0x00000000;
    if0_ga0.nxd_ip_address.v6[2] = 0x00010000;
    if0_ga0.nxd_ip_address.v6[3] = 0x00010001;

    /* Set up IF0 GA1 */
    if0_ga1.nxd_ip_version = NX_IP_VERSION_V6;
    if0_ga1.nxd_ip_address.v6[0] = 0x20010000;
    if0_ga1.nxd_ip_address.v6[1] = 0x00000000;
    if0_ga1.nxd_ip_address.v6[2] = 0x00010000;
    if0_ga1.nxd_ip_address.v6[3] = 0x00010002;

    /* Set up IF0 GA2 */
    if0_ga2.nxd_ip_version = NX_IP_VERSION_V6;
    if0_ga2.nxd_ip_address.v6[0] = 0x20010000;
    if0_ga2.nxd_ip_address.v6[1] = 0x00000000;
    if0_ga2.nxd_ip_address.v6[2] = 0x00010000;
    if0_ga2.nxd_ip_address.v6[3] = 0x00010003;

    /* Set up IF1 GA0 */
    if1_ga0.nxd_ip_version = NX_IP_VERSION_V6;
    if1_ga0.nxd_ip_address.v6[0] = 0x20010000;
    if1_ga0.nxd_ip_address.v6[1] = 0x00000000;
    if1_ga0.nxd_ip_address.v6[2] = 0x00010000;
    if1_ga0.nxd_ip_address.v6[3] = 0x00020001;

    /* Set up IF1 GA1 */
    if1_ga1.nxd_ip_version = NX_IP_VERSION_V6;
    if1_ga1.nxd_ip_address.v6[0] = 0x20010000;
    if1_ga1.nxd_ip_address.v6[1] = 0x00000000;
    if1_ga1.nxd_ip_address.v6[2] = 0x00010000;
    if1_ga1.nxd_ip_address.v6[3] = 0x00020002;

    /* Set up IF1 GA2 */
    if1_ga2.nxd_ip_version = NX_IP_VERSION_V6;
    if1_ga2.nxd_ip_address.v6[0] = 0x20010000;
    if1_ga2.nxd_ip_address.v6[1] = 0x00000000;
    if1_ga2.nxd_ip_address.v6[2] = 0x00010000;
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
    if2_ga0.nxd_ip_address.v6[2] = 0x00010000;
    if2_ga0.nxd_ip_address.v6[3] = 0x00030001;

    /* Set Global address0 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga0, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address1 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga1, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address2 on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga2, 64, NX_NULL); 
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }        
         
    /* Set duplicated Global address2 on the 1st interface again. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_ga2, 64, NX_NULL);
    if(status != NX_DUPLICATED_ENTRY)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
         
    /* Set invalid addrss on the 1st interface. */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, NX_NULL, 64, NX_NULL);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address0 on the 2nd interface. */
    status = nxd_ipv6_address_set(&ip_0, SECONDARY_INTERFACE, &if1_ga0, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address1 on the 2nd interface. */
    status = nxd_ipv6_address_set(&ip_0, SECONDARY_INTERFACE, &if1_ga1, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Global address2 on the 2nd interface. */
    status = nxd_ipv6_address_set(&ip_0, SECONDARY_INTERFACE, &if1_ga2, 64, NX_NULL);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING

    /* Set global address0 on the 3rd interface. This one should fail. */
    status = nxd_ipv6_address_set(&ip_0, 2, &if2_ga0, 64, NX_NULL);
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING */

    /* Now read back the IP addresses and make sure they match. */
    status = nxd_ipv6_address_get(&ip_0, 0, &if_addr, &prefix_length, &interface_index);
    if(status != NX_SUCCESS || (memcmp(&if_addr,  &if0_ga0, sizeof(NXD_ADDRESS))) || (prefix_length != 64) || (interface_index != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_ipv6_address_get(&ip_0, 1, &if_addr, &prefix_length, &interface_index);
    if((status != NX_SUCCESS || (memcmp(&if_addr,  &if0_ga1, sizeof(NXD_ADDRESS)))) || (prefix_length != 64) || (interface_index != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_ipv6_address_get(&ip_0, 2, &if_addr, &prefix_length, &interface_index);
    if((status != NX_SUCCESS || (memcmp(&if_addr,  &if0_ga2, sizeof(NXD_ADDRESS))) || (prefix_length != 64)) || (interface_index != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_ipv6_address_get(&ip_0, 3, &if_addr, &prefix_length, &interface_index);
    if((status != NX_SUCCESS) || (memcmp(&if_addr,  &if1_ga0, sizeof(NXD_ADDRESS))) || (prefix_length != 64) || (interface_index != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }  

    status = nxd_ipv6_address_get(&ip_0, 4, &if_addr, &prefix_length, &interface_index);
    if((status != NX_SUCCESS) || (memcmp(&if_addr,  &if1_ga1, sizeof(NXD_ADDRESS))) || (prefix_length != 64) || (interface_index != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_ipv6_address_get(&ip_0, 5, &if_addr, &prefix_length, &interface_index);
    if((status != NX_SUCCESS) || (memcmp(&if_addr,  &if1_ga2, sizeof(NXD_ADDRESS))) || (prefix_length != 64) || (interface_index != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
               
    /* Set up IF0 GAX */
    if0_gax.nxd_ip_version = NX_IP_VERSION_V6;
    if0_gax.nxd_ip_address.v6[0] = 0x20010000;
    if0_gax.nxd_ip_address.v6[1] = 0x00000009;
    if0_gax.nxd_ip_address.v6[2] = 0x00000000;
    if0_gax.nxd_ip_address.v6[3] = 0x00010003;

    /* Loop to add the IPv6 addresses. */
    for(i = 6; i < NX_MAX_IPV6_ADDRESSES; i++)
    {

        status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_gax, 64, NX_NULL);
        if(status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Update the IP address IF0 GAX */
        if0_gax.nxd_ip_version = NX_IP_VERSION_V6;
        if0_gax.nxd_ip_address.v6[1] += 1;
    } 
     
    /* Add the IPv6 address that exceed the max IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_gax, 64, NX_NULL);
    if(status != NX_NO_MORE_ENTRIES)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the address on the 1 interface  */
    for(i = 0; i < NX_MAX_IPV6_ADDRESSES; i++)
    {
        status = nxd_ipv6_address_delete(&ip_0, i);

        if(status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Set up IF0 GAX */
    if0_gax.nxd_ip_version = NX_IP_VERSION_V6;
    if0_gax.nxd_ip_address.v6[0] = 0x20010000;
    if0_gax.nxd_ip_address.v6[1] = 0x00000009;
    if0_gax.nxd_ip_address.v6[2] = 0x00000000;
    if0_gax.nxd_ip_address.v6[3] = 0x00010003;

    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_gax, 64, NX_NULL);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set up the address only v6[2] different with the address above.  */
    if0_gax.nxd_ip_version = NX_IP_VERSION_V6;
    if0_gax.nxd_ip_address.v6[0] = 0x20010000;
    if0_gax.nxd_ip_address.v6[1] = 0x00000009;
    if0_gax.nxd_ip_address.v6[2] = 0x00000002;
    if0_gax.nxd_ip_address.v6[3] = 0x00010003;

    status = nxd_ipv6_address_set(&ip_0, PRIMARY_INTERFACE, &if0_gax, 64, NX_NULL);
    if (status != NX_SUCCESS)
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
void netx_ipv6_address_set_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Address Set Test.....................................N/A\n");
    test_control_return(3);

}

#endif
