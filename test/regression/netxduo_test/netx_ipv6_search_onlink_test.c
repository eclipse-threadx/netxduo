/* This NetX test to test the IPv6 onlink search.  */

#include    "tx_api.h"
#include    "nx_api.h"
extern void    test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
static NXD_ADDRESS             test_address;
static NXD_ADDRESS             prefix_0;  /* 1111:0001:1000:0003::/64  */
static NXD_ADDRESS             prefix_1;  /* 2222:1111:1001:1002::/63  */
static NXD_ADDRESS             prefix_2;  /* 3333:0001:1234:1002:1234::/72 */


/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_search_onlink_test_application_define(void *first_unused_memory)
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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*4);
    pointer = pointer + 1536*4;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = _nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Enable IPv6 */
    status += nxd_ipv6_enable(&ip_0);


    /* Enable ICMP for IP Instance 0.  */
    status += nxd_icmp_enable(&ip_0);

    /* Check status.  */
    if(status)
        error_counter++;

}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT        i;
UINT        status;
UINT        address1_index, address2_index; 
UINT        prefix_length;
NXD_ADDRESS temp_prefix;
    
    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Search Onlink Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* prefix_0:  1111:0001:1000:0003::/64  */
    prefix_0.nxd_ip_address.v6[0] = 0x11110001;
    prefix_0.nxd_ip_address.v6[1] = 0x10000003;
    prefix_0.nxd_ip_address.v6[2] = 0;
    prefix_0.nxd_ip_address.v6[3] = 0;

    /* prefix_1: 2222:1111:1001:1002::/63 */
    prefix_1.nxd_ip_address.v6[0] = 0x22221111;
    prefix_1.nxd_ip_address.v6[1] = 0x10011002;
    prefix_1.nxd_ip_address.v6[2] = 0;
    prefix_1.nxd_ip_address.v6[3] = 0;

    /* prefix_2: 3333:0001:1234:1002:1234::/72 */
    prefix_2.nxd_ip_address.v6[0] = 0x33330001;
    prefix_2.nxd_ip_address.v6[1] = 0x12341002;
    prefix_2.nxd_ip_address.v6[2] = 0x12000000;
    prefix_2.nxd_ip_address.v6[3] = 0;

    status = _nx_ipv6_prefix_list_add_entry(&ip_0, &prefix_0.nxd_ip_address.v6[0], 64, 1800);
    status += _nx_ipv6_prefix_list_add_entry(&ip_0, &prefix_1.nxd_ip_address.v6[0], 63, 1800);
    status += _nx_ipv6_prefix_list_add_entry(&ip_0, &prefix_2.nxd_ip_address.v6[0], 72, 1800);

    if(status)
        error_counter++;        

    /* Manually configure an IPv6 address that is on the prefix list */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x33330001;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x12341002;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x12340000;
    ipv6_address_1.nxd_ip_address.v6[3] = 1;

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 72, &address1_index);

    /* Manually configure an IPv6 address that is NOT on the prefix list */
    ipv6_address_2.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_2.nxd_ip_address.v6[0] = 0x44440000;
    ipv6_address_2.nxd_ip_address.v6[1] = 0x12341002;
    ipv6_address_2.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[3] = 1;

    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_2, 71, &address2_index);
    if(status)
        error_counter++;

    /* Test an onlink entry. */
    test_address.nxd_ip_address.v6[0] = 0x11110001;
    test_address.nxd_ip_address.v6[1] = 0x10000003;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;

    /* Modify the previous test to make it offlink. */
    test_address.nxd_ip_address.v6[0] = 0x11110001;
    test_address.nxd_ip_address.v6[1] = 0x10000002;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;    

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status == 1)
        error_counter++;
    
    /* Test the 2nd onlink entry */
    test_address.nxd_ip_address.v6[0] = 0x22221111;
    test_address.nxd_ip_address.v6[1] = 0x10011002;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;

    /* This one should also be onlink */
    test_address.nxd_ip_address.v6[0] = 0x22221111;
    test_address.nxd_ip_address.v6[1] = 0x10011003;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;


    /* This one should be offlink */
    test_address.nxd_ip_address.v6[0] = 0x22221111;
    test_address.nxd_ip_address.v6[1] = 0x10011006;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 0)
        error_counter++;

    /* Test the 3rd onlink entry */
    test_address.nxd_ip_address.v6[0] = 0x33330001;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x12000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;


    /* This one should also be onlink. */
    test_address.nxd_ip_address.v6[0] = 0x33330001;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x12800000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;

    /* This one should also be offlink. */
    test_address.nxd_ip_address.v6[0] = 0x33330001;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x13000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 0)
        error_counter++;


    /* Test the manually configured one. */
    test_address.nxd_ip_address.v6[0] = 0x44440000;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x01000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;

    /* Test the manually configured one. */
    test_address.nxd_ip_address.v6[0] = 0x44440000;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x00800000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;

    /* Test the manually configured one.  This one should be offlink. */
    test_address.nxd_ip_address.v6[0] = 0x44440000;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x02000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 0)
        error_counter++;

    /* Test the manually configured one.  This one should be onlink. */
    test_address.nxd_ip_address.v6[0] = 0x44440000;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x01000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;


    /* Delete the 3rd onlink entry. */
    _nx_ipv6_prefix_list_delete(&ip_0, &prefix_2.nxd_ip_address.v6[0], 72);

    /* Test the 3rd onlink entry */
    test_address.nxd_ip_address.v6[0] = 0x33330001;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x12000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;    

    /* Make sure the 1st and the 2nd prefix entry is still there. */
    test_address.nxd_ip_address.v6[0] = 0x11110001;
    test_address.nxd_ip_address.v6[1] = 0x10000003;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;

    /* Test the 2nd onlink entry */
    test_address.nxd_ip_address.v6[0] = 0x22221111;
    test_address.nxd_ip_address.v6[1] = 0x10011002;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;    
    
    /* Now delete 1st and 2nd, and then make sure they are indeed removed. */    
    _nx_ipv6_prefix_list_delete(&ip_0, &prefix_1.nxd_ip_address.v6[0], 63);
    _nx_ipv6_prefix_list_delete(&ip_0, &prefix_0.nxd_ip_address.v6[0], 64);

    /* The first prefix should still be there because it is also set manually. */
    test_address.nxd_ip_address.v6[0] = 0x33330001;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x12000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;

    /* Test the 2nd onlink entry */
    test_address.nxd_ip_address.v6[0] = 0x22221111;
    test_address.nxd_ip_address.v6[1] = 0x10011002;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 0)
        error_counter++;    


    /* Make sure the manually configured entry is still there. */
    test_address.nxd_ip_address.v6[0] = 0x44440000;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x01000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;

    /* Now delete the 1st manually configured IPv6 address, verify that the 1st prefix is
       no longer onlink but the 2nd manually configure IPv6 address is onlink. */
    nxd_ipv6_address_delete(&ip_0, address1_index);
    test_address.nxd_ip_address.v6[0] = 0x33330001;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x12000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 0)
        error_counter++;
    
    test_address.nxd_ip_address.v6[0] = 0x44440000;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x01000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 1)
        error_counter++;

    /* delete the 2nd manually configured address, and verify that all the entries are gone. */
    nxd_ipv6_address_delete(&ip_0, address2_index);    
    test_address.nxd_ip_address.v6[0] = 0x11110001;
    test_address.nxd_ip_address.v6[1] = 0x10000003;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 0)
        error_counter++;    

    test_address.nxd_ip_address.v6[0] = 0x22221111;
    test_address.nxd_ip_address.v6[1] = 0x10011003;
    test_address.nxd_ip_address.v6[2] = 0;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 0)
        error_counter++;


    test_address.nxd_ip_address.v6[0] = 0x33330001;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x12000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 0)
        error_counter++;

    test_address.nxd_ip_address.v6[0] = 0x44440000;
    test_address.nxd_ip_address.v6[1] = 0x12341002;
    test_address.nxd_ip_address.v6[2] = 0x01000000;
    test_address.nxd_ip_address.v6[3] = 1;

    status = _nxd_ipv6_search_onlink(&ip_0, &test_address.nxd_ip_address.v6[0]);
    if(status != 0)
        error_counter++;

    /* temp_prefix: 4444:0001:1234:1002:1200::1/64 */
    temp_prefix.nxd_ip_address.v6[0] = 0x44440001;
    temp_prefix.nxd_ip_address.v6[1] = 0x12341002;
    temp_prefix.nxd_ip_address.v6[2] = 0x12000000;
    temp_prefix.nxd_ip_address.v6[3] = 0x00000001;

    prefix_length = 64;  
                       
    /* Loop to add entry with prefix.  */
    for (i = 0; i < NX_IPV6_PREFIX_LIST_TABLE_SIZE; i++)
    {

        /* Added the entry.  */
        status = _nx_ipv6_prefix_list_add_entry(&ip_0, &temp_prefix.nxd_ip_address.v6[0], prefix_length, 1800);

        /* Check the status.  */
        if (status)
        {       
            printf("ERROR!\n");
            test_control_return(1);
        }
        else
        {

            /* Update the address.  */
            temp_prefix.nxd_ip_address.v6[0]++;

            if (i % 2)
                prefix_length = 64 + i;
            else
                prefix_length = 64 - i;
        }
    }

    /* Added the entry.  */
    status = _nx_ipv6_prefix_list_add_entry(&ip_0, &temp_prefix.nxd_ip_address.v6[0], prefix_length, 1800);

    /* Check the status.  */
    if (status != NX_OVERFLOW)
    {       
        printf("ERROR!\n");
        test_control_return(1);
    }   

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
void           netx_ipv6_search_onlink_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Search Onlink Test...................................N/A\n");

    test_control_return(3);

}
#endif
