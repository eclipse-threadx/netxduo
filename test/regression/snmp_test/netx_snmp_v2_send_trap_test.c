/* This SNMP Agent test sends a V2 trap with a non null trap list. A successful result is the correction
   number of messages/packets sent and no internal errors.  */

 
#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_snmp.h"
#include   "nx_udp.h"
#include   "small_mib_helper.h"

extern void    test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         4096


extern MIB_ENTRY   mib2_mib[];

static UINT    v2query_response_complete = NX_FALSE; 

static UINT    v2_mib2_getnext_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    v2_mib2_set_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    v2_mib2_get_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    v2_mib2_username_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *username);
static VOID    v2_mib2_variable_update(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr);

#define     QUERY_COUNT        1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_agent;
static TX_THREAD               thread_manager;
static NX_SNMP_AGENT           v2_my_agent;
static NX_PACKET_POOL          v2_pool_0;
static NX_IP                   agent_ip;
static NX_IP                   manager_ip;

static NX_UDP_SOCKET           snmp_manager_socket;

#define SNMP_MANAGER_ADDRESS   IP_ADDRESS(10,0,0,1)  
#define SNMP_AGENT_ADDRESS     IP_ADDRESS(10,0,0,10)  


/* Define the counters used in the demo application...  */

static UINT                    status;
static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    snmp_test_initialize();


/* Send SNMP manager query.  */
static UINT    nx_snmp_query_packet_send(NX_UDP_SOCKET *snmp_manager_socket, UINT request_id, UINT packet_number);

extern char simple_get_query_pkt[82];
extern int  simple_get_query_size;

typedef struct SNMP_QUERY_STRUCT
{
    char          *snmp_query_pkt_data;
    int           snmp_query_pkt_size;
} SNMP_QUERY;


static SNMP_QUERY       snmp_query[QUERY_COUNT];


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_snmp_v2_send_trap_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    
    /* Create the SNMP agent thread.  */
    tx_thread_create(&thread_agent, "Agent thread", thread_0_entry, 0,  
                      pointer, DEMO_STACK_SIZE, 4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the SNMP Manager thread.  */
    tx_thread_create(&thread_manager, "Manager thread", thread_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&v2_pool_0, "NetX Main Packet Pool", 1000, pointer, 4096);
    pointer = pointer + 4096;

    /* Create an IP instance.  */
    status += nx_ip_create(&agent_ip, "Agent IP", SNMP_AGENT_ADDRESS, 0xFFFFFF00UL, &v2_pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&manager_ip, "Manager IP", SNMP_MANAGER_ADDRESS, 0xFFFFFF00UL, &v2_pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
    {

        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&agent_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&manager_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
    {
        error_counter++;
    }

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&agent_ip);
    status += nx_udp_enable(&manager_ip);

    /* Check for UDP enable errors.  */
    if (status)
    {
        error_counter++;
    }

        /* Create an SNMP agent instance.  */
    status = nx_snmp_agent_create(&v2_my_agent, "SNMP Agent", &agent_ip, pointer, 4096, &v2_pool_0, 
                         v2_mib2_username_processing, v2_mib2_get_processing, 
                         v2_mib2_getnext_processing, v2_mib2_set_processing);

    if (status)
    {
        error_counter++;
    }

    return;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT status;
NX_SNMP_TRAP_OBJECT trap_list[7];
NX_SNMP_OBJECT_DATA trap_data0;
NX_SNMP_OBJECT_DATA trap_data1;
NX_SNMP_OBJECT_DATA trap_data2;
NX_SNMP_OBJECT_DATA trap_data3;
NX_SNMP_OBJECT_DATA trap_data4;
NX_SNMP_OBJECT_DATA trap_data5;
UINT                counter = 133;


    printf("NetX Test:   SNMP V2 Send Trap Test....................................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Start the SNMP instance.  */
    status = nx_snmp_agent_start(&v2_my_agent);
    
    /* Return the test result.  */
    if (status)
    {
       error_counter++;
    }

    /* Wait for the 'manager' to finish querying the Agent. */
    while (v2query_response_complete == NX_FALSE)
    {
        tx_thread_sleep(100);
    }


    /* Now send the traps. */
    /* Send trap to indicate the link is up.  */
    trap_list[0].nx_snmp_object_string_ptr =  (UCHAR *) "1.3.6.1.2.1.2.2.1.1.0";
    trap_list[0].nx_snmp_object_data = &trap_data0;
    trap_data0.nx_snmp_object_data_type =  NX_SNMP_INTEGER;
    trap_data0.nx_snmp_object_data_msw =   counter++;

    trap_list[1].nx_snmp_object_string_ptr =  (UCHAR *) "1.3.6.1.2.1.2.2.1.7.0";
    trap_list[1].nx_snmp_object_data = &trap_data1;
    trap_data1.nx_snmp_object_data_type =  NX_SNMP_INTEGER;
    trap_data1.nx_snmp_object_data_msw =   counter++;

    /* Null terminate the list. */
    trap_list[2].nx_snmp_object_string_ptr =  NX_NULL;
    trap_list[2].nx_snmp_object_data = NX_NULL;
#if 1
    trap_list[2].nx_snmp_object_string_ptr =  (UCHAR *) "1.3.6.1.2.1.2.2.1.8.0";
    trap_list[2].nx_snmp_object_data = &trap_data2;
    trap_data2.nx_snmp_object_data_type =  NX_SNMP_INTEGER;
    trap_data2.nx_snmp_object_data_msw =   tx_time_get();

    trap_list[3].nx_snmp_object_string_ptr =  (UCHAR *) "1.3.6.1.2.1.2.2.1.9.0";
    trap_list[3].nx_snmp_object_data = &trap_data3;
    trap_data3.nx_snmp_object_data_type =  NX_SNMP_INTEGER;
    trap_data3.nx_snmp_object_data_msw =   counter++;

    trap_list[4].nx_snmp_object_string_ptr =  (UCHAR *) "1.3.6.1.2.1.2.2.1.10.0.1";
    trap_list[4].nx_snmp_object_data = &trap_data4;
    trap_data4.nx_snmp_object_data_type =  NX_SNMP_INTEGER;
    trap_data4.nx_snmp_object_data_msw =   tx_time_get();


    trap_list[5].nx_snmp_object_string_ptr =  (UCHAR *) "1.3.6.1.2.1.2.2.1.10.0.2";
    trap_list[5].nx_snmp_object_data = &trap_data5;
    trap_data5.nx_snmp_object_data_type =  NX_SNMP_INTEGER;
    trap_data5.nx_snmp_object_data_msw =   counter++;

    /* Null terminate the list. */
    trap_list[6].nx_snmp_object_string_ptr =  NX_NULL;
    trap_list[6].nx_snmp_object_data = NX_NULL;
#endif

    status = nx_snmp_agent_trapv2_send(&v2_my_agent, SNMP_MANAGER_ADDRESS, (UCHAR *)"trap", NX_SNMP_TRAP_COLDSTART, tx_time_get(), &trap_list[0]); 

    if (status)
    {
        error_counter++;
    }


    /* Check for correct internal counters of SNMP processing. */
    if ((v2_my_agent.nx_snmp_agent_get_requests != 1) ||
        (v2_my_agent.nx_snmp_agent_total_get_variables != 1) ||
        (v2_my_agent.nx_snmp_agent_packets_received != 1) ||
        (v2_my_agent.nx_snmp_agent_packets_sent != 2) ||
        (v2_my_agent.nx_snmp_agent_getresponse_sent != 1) ||
        (v2_my_agent.nx_snmp_agent_traps_sent != 1))
    {
        error_counter++;
    }

   
    /* Check for errors processing the request and sending the trap. */
    if (v2_my_agent.nx_snmp_agent_invalid_packets ||
        v2_my_agent.nx_snmp_agent_internal_errors ||
        v2_my_agent.nx_snmp_agent_allocation_errors  ||
        v2_my_agent.nx_snmp_agent_request_errors  ||
        v2_my_agent.nx_snmp_agent_too_big_errors  ||
        v2_my_agent.nx_snmp_agent_username_errors ||
        v2_my_agent.nx_snmp_agent_unknown_requests)
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

    return;

}
    
/* SNMP Manager thread */
static void    thread_1_entry(ULONG thread_input)
{

NX_PACKET   *agent_packet;
UINT        port;
UINT        i;
USHORT      request_id = 1;

    /* Let the agent get set up first! */
    tx_thread_sleep(50);

    /* Create a UDP socket act as the DNS server.  */
    status = nx_udp_socket_create(&manager_ip, &snmp_manager_socket, "Manager Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        v2query_response_complete = NX_TRUE;
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&snmp_manager_socket, 161, 200);


    /* Check status.  */
    if (status)
    {
        error_counter++;
        v2query_response_complete = NX_TRUE;
    }

    /* Load the test data up. */
    snmp_test_initialize();

    /* Send SNMP queries to the agent.  */
    for (i = 0; i < QUERY_COUNT; i++ )
    {

        /* Send the SNMP manager query packet.  */
        status = nx_snmp_query_packet_send(&snmp_manager_socket, request_id,  i);

        /* Check status.  */
        if (status)
        {
            
            error_counter++;
            v2query_response_complete = NX_TRUE;
            break;
        }

        /* Receive the SNMP agent response.  */
        status =  nx_udp_socket_receive(&snmp_manager_socket, &agent_packet, 200);

        /* Check status.  */
        if (status)
        {
            
            error_counter++;
            v2query_response_complete = NX_TRUE;
            break;
        }

        /* Get the SNMP agent UDP port.  */
        status = nx_udp_packet_info_extract(agent_packet, NX_NULL ,NX_NULL, &port, NX_NULL);

        /* Check status.  */

        if (status)
        {
            
            error_counter++;
            v2query_response_complete = NX_TRUE;
            break;
        }

        /* Release the packet.  */
        nx_packet_release(agent_packet);

        request_id++;
    }

    /* Indicate the test is complete. */
    v2query_response_complete = NX_TRUE;

    /* Unbind the UDP socket.  */
     nx_udp_socket_unbind(&snmp_manager_socket);

    /* Delete the UDP socket.  */
    nx_udp_socket_delete(&snmp_manager_socket);

    return;
}


static UINT   nx_snmp_query_packet_send(NX_UDP_SOCKET *snmp_manager_socket, UINT snmp_request_id, UINT packet_number)
{
UINT        status;
NX_PACKET   *response_packet;


    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&v2_pool_0, &response_packet, NX_UDP_PACKET, 200);
    
    /* Check status.  */
    if (status)
    {

        error_counter++;
        return(1);
    }

    memset(response_packet -> nx_packet_prepend_ptr, 0, (response_packet -> nx_packet_data_end - response_packet -> nx_packet_prepend_ptr));

    /* Write the SMTP response messages into the packet payload!  */
    memcpy(response_packet -> nx_packet_prepend_ptr, 
           snmp_query[packet_number].snmp_query_pkt_data, 
           snmp_query[packet_number].snmp_query_pkt_size); 

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length =  snmp_query[packet_number].snmp_query_pkt_size; 
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

    /* Send the UDP packet with the correct port.  */
    status =  nx_udp_socket_send(snmp_manager_socket, response_packet, IP_ADDRESS(10, 0, 0, 10), 161);

    /* Check the status.  */
    if (status)      
    {

        error_counter++;
        nx_packet_release(response_packet);         
    }

    return status;
}


static void  snmp_test_initialize()
{

    snmp_query[0].snmp_query_pkt_data = &simple_get_query_pkt[0];
    snmp_query[0].snmp_query_pkt_size = simple_get_query_size;  

}


/* Define the application's GET processing routine.  */

UINT    v2_mib2_get_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
{

UINT    i;
UINT    status;



    /* Loop through the sample MIB to see if we have information for the supplied variable.  */
    i =  0;
    status =  NX_SNMP_ERROR;
    while (mib2_mib[i].object_name)
    {

        /* See if we have found the matching entry.  */
        status =  nx_snmp_object_compare(object_requested, mib2_mib[i].object_name);

        /* Was it found?  */
        if (status == NX_SUCCESS)
        {

            /* Yes it was found.  */
            break;
        }

        /* Move to the next index.  */
        i++;
    }

    /* Determine if a not found condition is present.  */
    if (status != NX_SUCCESS)
    {

        /* The object was not found - return an error.  */
        return(NX_SNMP_ERROR_NOSUCHNAME);
    }

    /* Determine if the entry has a get function.  */
    if (mib2_mib[i].object_get_callback)
    {

        /* Yes, call the get function.  */
        status =  (mib2_mib[i].object_get_callback)(mib2_mib[i].object_value_ptr, object_data);
    }
    else
    {

        /* No get function, return no access.  */
        status =  NX_SNMP_ERROR_NOACCESS;
    }

    /* Return the status.  */
    return(status);
}


/* Define the application's GETNEXT processing routine.  */

UINT    v2_mib2_getnext_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
{

UINT    i;
UINT    status;


    /* Loop through the sample MIB to see if we have information for the supplied variable.  */
    i =  0;
    status =  NX_SNMP_ERROR;
    while (mib2_mib[i].object_name)
    {

        /* See if we have found the next entry.  */
        status =  nx_snmp_object_compare(object_requested, mib2_mib[i].object_name);

        /* Is the next entry the mib greater?  */
        if (status == NX_SNMP_NEXT_ENTRY)
        {

            /* Yes it was found.  */
            break;
        }

        /* Move to the next index.  */
        i++;
    }

    /* Determine if a not found condition is present.  */
    if (status != NX_SNMP_NEXT_ENTRY)
    {

        /* The object was not found - return an error.  */
        return(NX_SNMP_ERROR_NOSUCHNAME);
    }


    /* Copy the new name into the object.  */
    nx_snmp_object_copy(mib2_mib[i].object_name, object_requested);

    /* Determine if the entry has a get function.  */
    if (mib2_mib[i].object_get_callback)
    {

        /* Yes, call the get function.  */
        status =  (mib2_mib[i].object_get_callback)(mib2_mib[i].object_value_ptr, object_data);

        /* Determine if the object data indicates an end-of-mib condition.  */
        if (object_data -> nx_snmp_object_data_type == NX_SNMP_END_OF_MIB_VIEW)
        {

            /* Copy the name supplied in the mib table.  */
            nx_snmp_object_copy(mib2_mib[i].object_value_ptr, object_requested);
        }
    }
    else
    {

        /* No get function, return no access.  */
        status =  NX_SNMP_ERROR_NOACCESS;
    }

    /* Return the status.  */
    return(status);
}


/* Define the application's SET processing routine.  */

UINT    v2_mib2_set_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
{

UINT    i;
UINT    status;


    /* Loop through the sample MIB to see if we have information for the supplied variable.  */
    i =  0;
    status =  NX_SNMP_ERROR;
    while (mib2_mib[i].object_name)
    {

        /* See if we have found the matching entry.  */
        status =  nx_snmp_object_compare(object_requested, mib2_mib[i].object_name);

        /* Was it found?  */
        if (status == NX_SUCCESS)
        {

            /* Yes it was found.  */
            break;
        }

        /* Move to the next index.  */
        i++;
    }

    /* Determine if a not found condition is present.  */
    if (status != NX_SUCCESS)
    {

        /* The object was not found - return an error.  */
        return(NX_SNMP_ERROR_NOSUCHNAME);
    }


    /* Determine if the entry has a set function.  */
    if (mib2_mib[i].object_set_callback)
    {

        /* Yes, call the set function.  */
        status =  (mib2_mib[i].object_set_callback)(mib2_mib[i].object_value_ptr, object_data);
    }
    else
    {

        /* No get function, return no access.  */
        status =  NX_SNMP_ERROR_NOACCESS;
    }

    
    /* Return the status.  */
    return(status);
}

/* Create an error code if matching user not found. */
#define USER_NOT_FOUND 1

/* Define the username callback routine routine. Usernames should be 
   associated with permissions (public or private string) and what version
   of SNMP the user is configured for. The username callback should verify
   the incoming username MIB access permissions.  */
UINT  v2_mib2_username_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *username)
{

    v2_mib2_variable_update(&agent_ip, &v2_my_agent);

    return NX_SUCCESS;

}

extern ULONG    sysUpTime;
/* Define the application's update routine.  */ 

VOID  v2_mib2_variable_update(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr)
{

    /* Update the snmp parameters.  */
    sysUpTime =                 tx_time_get();
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_snmp_v2_send_trap_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   SNMP V2 Send Trap Test....................................N/A\n"); 

    test_control_return(3);  
}      
#endif
