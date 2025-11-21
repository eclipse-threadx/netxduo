/* This NetX test tests the IGMP report send IGMP operation.  The application
   registers (joins) a group address with the IP instance long enough to send
   out an initial report.  Then the application wishes to resend the same IGMP
   report (because it detects a new router.  The timeout in the multicast entry for that
   group address is reset to one so that an IGMP report is sent out on the next
   periodic.  For 5.9, this service is an internal function and only supports
   sending join IGMP reports.  
*/

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_igmp.h"

extern void    test_control_return(UINT status);

#if  !defined(NX_DISABLE_IGMP_INFO) && (NX_MAX_PHYSICAL_INTERFACES > 1)
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
void    netx_igmp_interface_indirect_report_send_test_application_define(void *first_unused_memory)
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
    
    status = nx_ip_interface_attach(&ip_0, "Secondary IP", IP_ADDRESS(1,2,4,4), 0xFFFFFF00UL, _nx_ram_network_driver_512);
    if (status)
        error_counter++;
    
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

    
    /* Let the IP task initialize the driver. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 5);

    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Multicast Indirect Report Send Test..................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Perform an IGMP join operation on the primary interface.  */
    status =   nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,7), 0);

    /* Determine if there is an error.  */
    if (status)
    {
        error_counter++ ;   
    }

    /* Perform another IGMP join operation on the primary interface.  */
    status =   nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,1), 0);

    /* Determine if there is an error.  */
    if (status)
    {
        error_counter++ ;   
    }

    /* Perform an IGMP join operation on the secondary interface.  */
    status =   nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,3), 1);

    /* Determine if there is an error.  */
    if (status)
    {
        error_counter++ ;   
    }     
    
    /* Should be long enough for three IP periodic cycles to send a report. */
    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);

    /* Call the IGMP information get routine to see if all the groups are there.  */
    status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);

    /* Check for status and if NetX sent off any IGMP reports.  */
    if ((status) || (igmp_reports_sent != 3) ||  (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 3))
    {
        error_counter++;
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
       
#ifdef __PRODUCT_NETXDUO__
    /* Perform IGMP leave operation and test if we need to send a leave report. */
    status =   nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,3), 1);
#else
    status =   nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,3));
#endif

    /* Determine if there is an error.  */
    if (status)
    {
        error_counter++ ;   
    }

    /* Call the IGMP information get routine to see if all the groups are there.  */
    status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);
    
#ifndef NX_DISABLE_IGMPV2
    /* Check for status and if NetX sent off any IGMP reports.  */
    if ((igmp_reports_sent != 3) ||  (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 2))
#else
      /* IGMPv1 protocol does not call for sending leave reports. */
    if ((igmp_reports_sent != 3) ||  (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 2))
#endif      
    {
        error_counter++;
    }

    /* Attempt to rejoin the group after we cleared the multicast entry for it.   */
    status =  _nx_igmp_interface_report_send(&ip_0, IP_ADDRESS(224,0,0,1), 0, NX_TRUE);
    
    /* Determine if there is an error.   */
    if (status != NX_SUCCESS)
    {
        error_counter++ ;   
    }
    
    /* Wait a second, only one IGMP report goes out per IP thread task periodic. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Call the IGMP information get routine to see if NetX sent out another report message.  */
    status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);

    if (status)
    {
        error_counter++;
    }    
    
    /* Check IGMP statistics.  */
    
#ifndef NX_DISABLE_IGMPV2
    if ((status) || (igmp_reports_sent != 4) || (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 2))
#else
      /* IGMPv1 protocol does not call for sending leave reports. */
    if ((status) || (igmp_reports_sent != 4) ||  (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 2))
#endif      
    {
        error_counter++;
    }

    /* Send a join report for a group that we left the membership of.   */
    status =  _nx_igmp_interface_report_send(&ip_0, IP_ADDRESS(224,0,0,7), 0, NX_TRUE);
    
    /* Determine if there is an error.  This call should succeed because nx_igmp_interface_report_send does not check
       the membership of the group address.  It is assumed the caller does.  */
    if (status != NX_SUCCESS)
    {
        error_counter++ ;   
    }
    
    status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);

    if (status)
    {
        error_counter++;
    }    
    
#ifndef NX_DISABLE_IGMPV2
    if ((status) || (igmp_reports_sent != 5) || (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 2))
#else
      /* IGMPv1 protocol does not call for sending leave reports. */
    if ((status) || (igmp_reports_sent != 5) ||  (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 2))
#endif      
    {
        error_counter++;
    }
   
    /* Perform an IGMP leave operation on the primary interface.  */
#ifdef __PRODUCT_NETXDUO__
    status =   nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,5), 0);
#else
    status =   nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,5));
#endif

    /* We never joined this group so this call should return an error. */
    if (status == NX_SUCCESS)
    {
        error_counter++;   
    }
    
    /* Call the IGMP information get routine to see if NetX sent out another report message.  */
    status =  nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined);

    if (status)
    {
        error_counter++;
    }    
    
    /* Check for status.  There should be no change here. */
#ifndef NX_DISABLE_IGMPV2
    if ((status) || (igmp_reports_sent != 5) || (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 2))
#else
      /* IGMPv1 protocol does not call for sending leave reports. */
    if ((status) || (igmp_reports_sent != 5) ||  (igmp_queries_received) || (igmp_checksum_errors) || (current_groups_joined != 2))
#endif 
    {
        error_counter++;
    }

    if (error_counter)
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
void    netx_igmp_interface_indirect_report_send_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   IGMP Multicast Indirect Report Send Test...................N/A\n");
    test_control_return(3);

}
#endif /* NX_DISABLE_IGMP_INFO */
