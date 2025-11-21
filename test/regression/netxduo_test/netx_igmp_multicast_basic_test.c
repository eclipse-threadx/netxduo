/* This NetX test concentrates on the basic multicast IGMP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IGMP_INFO) && !defined(NX_DISABLE_IPV4)

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
void    netx_igmp_multicast_basic_test_application_define(void *first_unused_memory)
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

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Set the second interface.  */
    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_512);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable IGMP processing for both this IP instance.  */
    status =  nx_igmp_enable(&ip_0);

    /* Check enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

    UINT        status;
    ULONG       igmp_reports_sent;
    ULONG       igmp_queries_received;
    ULONG       igmp_checksum_errors;
    ULONG       current_groups_joined;


    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Multicast Basic Operation Test.......................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test the first interface.  */
    /* Perform 7 IGMP join operations.  */
    status =   nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,1), 0);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,2), 0);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,3), 0);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 0);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,5), 0);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,7), 0);

#ifdef __PRODUCT_NETXDUO__
    /* Test the  nxe_igmp_multicast_interface_join_internal.c */
    status +=  nx_ipv4_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,6), 0);
#else
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,6), 0);
#endif /* __PRODUCT_NETXDUO__ */

    /* Join one group another 4 times to test the counting operation.  */
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 0);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 0);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 0);
    status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 0);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Call the IGMP information get routine to see if all the groups are there.  */
    status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);

    /* Check for status.  */
    if ((status) || (igmp_reports_sent) || (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 7))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Attempt to join a new group. This should result in an error.  */
    status =  nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224,0,0,8));

    /* Determine if an error has occurred.  */
    if (status != NX_NO_MORE_ENTRIES)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status =   nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,1));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,2));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,3));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,5));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,7));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
#ifdef __PRODUCT_NETXDUO__
    status +=  nx_ipv4_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,6), 0);
#else
    status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,6));
#endif /* __PRODUCT_NETXDUO__ */

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    if(NX_MAX_PHYSICAL_INTERFACES > 1)
    {

        /* Test the second interface.  */
        /* Perform 7 IGMP join operations.  */
        status =   nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,1), 1);
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,2), 1);
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,3), 1);
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,5), 1);
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,6), 1);
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,7), 1);

        /* Join one group another 4 times to test the counting operation.  */
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);
        status +=  nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,4), 1);

        /* Determine if there is an error.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Call the IGMP information get routine to see if all the groups are there.  */
        status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);

        /* Check for status.  */
        if ((status) || (igmp_reports_sent) || (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 7))
        {

            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Attempt to join a new group. This should result in an error.  */
        status =  nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224,0,0,8));

        /* Determine if an error has occurred.  */
        if (status != NX_NO_MORE_ENTRIES)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Now leave all the groups to make sure that processing works properly.  */
#ifdef __PRODUCT_NETXDUO__
        status =  nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,1), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,2), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,3), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,5), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,6), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,7), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), 1);
        status += nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,4), 1);
#else
        status =   nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,1));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,2));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,3));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,5));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,6));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,7));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
        status +=  nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,4));
#endif
        /* Determine if there is an error.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Call the IGMP information get routine to see if all the groups are there.  */
    status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);

    /* Check for status.  */
    if ((status) || (igmp_reports_sent) || (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined))
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
void    netx_igmp_multicast_basic_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   IGMP Multicast Basic Operation Test.......................N/A\n");
    test_control_return(3);

}
#endif /* NX_DISABLE_IGMP_INFO */
