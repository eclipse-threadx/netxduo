/* This tests processing abornal packet.
   */

#include   "tx_api.h"
#include   "nx_api.h" 
#include   "nxd_snmp.h"
#include   "nx_udp.h"
#include   "small_mib_helper.h"

extern void    test_control_return(UINT);

#define     DEMO_STACK_SIZE         4096

#if !defined(NX_DISABLE_IPV4)

static NX_SNMP_SECURITY_KEY    my_privacy_key;
static NX_SNMP_SECURITY_KEY    my_authentication_key;

static UINT    v3_mib2_getnext_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    v3_mib2_set_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    v3_mib2_get_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    v3_mib2_username_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *username);
static VOID    v3_mib2_variable_update(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr);


static UINT    query_response_complete = NX_FALSE; /* to synchronize when the agent sends the SNMP trap */
#define        QUERY_COUNT             4

/* To show byte by byte comparison of pre-recorded response with SNMP agent, define this option.  
#define VERBOSE
*/


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_agent;
static TX_THREAD               thread_manager;
static NX_SNMP_AGENT           my_agent;
static NX_PACKET_POOL          pool_0;
static NX_IP                   agent_ip;
static NX_IP                   manager_ip;
static NX_UDP_SOCKET           snmp_manager_socket;

#define SNMP_MANAGER_ADDRESS   IP_ADDRESS(10,0,0,1)  
#define SNMP_AGENT_ADDRESS     IP_ADDRESS(10,0,0,10)  


/* Define the counters used in the demo application...  */

static UINT                    status;
static ULONG                   error_counter = 0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    snmp_test_initialize();

/* Send SNMP manager query.  */
static UINT    nx_snmp_query_packet_send(NX_UDP_SOCKET *snmp_manager_socket, UINT request_id, UINT packet_number);

static unsigned char test_get_request_pkt_v1[] = {
0x30, 0x28, 0x02, 0x01, 0x00, 0x04,             /* ..0(.... */
0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, /* .public. */
0x1b, 0x02, 0x01, 0x29, 0x02, 0x01, 0x00, 0x02, /* ...).... */
0x01, 0x00, 0x30, 0x10, 0x30, 0x1e, 0x06, 0x0a, /* ..0.0... */
0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, /* +....... */ 
0x02, 0x00, 0x05, 0x00                          /* .... */
};

static unsigned char test_get_request_pkt_v3[] = {
0x30, 0x73, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x14, 0xa2, 0xd6, 0x5e, 0x02, 0x03, 0x00,
0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x26, 0x30, 0x24, 0x04, 0x11, 0x80, 0x00,
0x1f, 0x88, 0x80, 0xb1, 0x98, 0x19, 0x38, 0x12, 0x6f, 0x40, 0x60, 0x00, 0x00, 0x00, 0x00, 0x02,
0x01, 0x06, 0x02, 0x01, 0x00, 0x04, 0x05, 0x75, 0x73, 0x65, 0x72, 0x31, 0x04, 0x00, 0x04, 0x00,
0x30, 0x33, 0x04, 0x11, 0x80, 0x00, 0x1f, 0x88, 0x80, 0xb1, 0x98, 0x19, 0x38, 0x12, 0x6f, 0x40,
0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xa0, 0x1c, 0x02, 0x04, 0x4c, 0x1f, 0xe2, 0x4d, 0x02,
0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x1e, 0x06, 0x0a, 
0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 
0x02, 0x00, 0x05, 0x00
};

static unsigned char test_get_request_pkt_v3_1[] = {
0x30, 0x73, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x14, 0xa2, 0xd6, 0x5e, 0x02, 0x03, 0x00,
0xff, 0xe3, 0x04, 0x01, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x30, 0x24, 0x04, 0x11, 0x80, 0x00,
0x1f, 0x88, 0x80, 0xb1, 0x98, 0x19, 0x38, 0x12, 0x6f, 0x40, 0x60, 0x00, 0x00, 0x00, 0x00, 0x02,
0x01, 0x06, 0x02, 0x01, 0x00, 0x04, 0x05, 0x75, 0x73, 0x65, 0x72, 0x31, 0x04, 0x00, 0x04, 0x00,
0x30, 0x33, 0x04, 0x11, 0x80, 0x00, 0x1f, 0x88, 0x80, 0xb1, 0x98, 0x19, 0x38, 0x12, 0x6f, 0x40,
0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xa0, 0x1c, 0x02, 0x04, 0x4c, 0x1f, 0xe2, 0x4d, 0x02,
0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x1e, 0x06, 0x0a, 
0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 
0x02, 0x00, 0x05, 0x00
};

typedef struct SNMP_QUERY_STRUCT
{
    char          *snmp_query_pkt_data;
    int            snmp_query_pkt_size;
} SNMP_QUERY;

static SNMP_QUERY       snmp_query[QUERY_COUNT];

static UCHAR context_engine[] = {0x80, 0x00, 0x1f, 0x88, 0x80, 0xb1, 0x98, 0x19, 0x38, 0x12, 0x6f, 0x40, 0x60, 0x00, 0x00, 0x00, 0x00};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_snmp_abnormal_packet_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    
    /* Create the SNMP agent thread.  */
    status = tx_thread_create(&thread_agent, "Agent thread", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 

                              4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the SNMP Manager thread.  */
    status += tx_thread_create(&thread_manager, "Manager thread", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

        /* Check for IP create errors.  */
    /* Check for IP create errors.  */
    if (status)
    {
        error_counter++;
        test_control_return(1);
    }        

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1500, pointer, 15000);
    pointer = pointer + 10000;

        /* Check for IP create errors.  */
    if (status)
    {
        error_counter++;
    }        

    /* Create an IP instance.  */
    status = nx_ip_create(&agent_ip, "Agent IP", SNMP_AGENT_ADDRESS, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer , 2048, 1);

    pointer += 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&manager_ip, "Manager IP", SNMP_MANAGER_ADDRESS, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 1);

    pointer += 2048;

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
    status = nx_snmp_agent_create(&my_agent, "public", &agent_ip, pointer, 4096, &pool_0, 
                                  v3_mib2_username_processing, v3_mib2_get_processing, 
                                  v3_mib2_getnext_processing, v3_mib2_set_processing);
    pointer =  pointer + 4096;

    if (status)
    {
        error_counter++;
    }

    status = nx_snmp_agent_context_engine_set(&my_agent, context_engine, sizeof(context_engine));

    status += nx_snmp_agent_v3_context_boots_set(&my_agent, 6);

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
UINT                counter = 133;


    printf("NetX Test:   SNMP Abnormal Packet Test.................................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Start the SNMP instance.  */
    status = nx_snmp_agent_start(&my_agent);
    
    /* Return the test result.  */
    if (status)
    {
       error_counter++;
    }

    while (!query_response_complete)
    {
        tx_thread_sleep(20);
    }

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

    my_agent.nx_snmp_agent_interface_index = 500;
    status = nx_snmp_agent_trap_send(&my_agent, SNMP_MANAGER_ADDRESS, (UCHAR *)"trap", (UCHAR *) "1.3.6.1.2.1.1.3.0", NX_SNMP_TRAP_COLDSTART, 0, tx_time_get(), &trap_list[0]);

    if (status == NX_SUCCESS)
    {
        error_counter++;
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    status = nx_snmp_agent_set_interface(&my_agent, 200);
    if (status == NX_SUCCESS)
    {
        error_counter++;
    }
#endif

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
  

static void    thread_1_entry(ULONG thread_input)
{

UINT        i;
USHORT      request_id = 1;


    /* Let the agent get set up first! */
    tx_thread_sleep(30);


    status = nx_udp_socket_create(&manager_ip, &snmp_manager_socket, "Manager Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Bind the UDP socket to an IP port.  */
    status |=  nx_udp_socket_bind(&snmp_manager_socket, 0, 100);

    /* Check status.  */
    if (status)
    {

        error_counter++;

        /* Indicate the query response is complete. */
        query_response_complete = NX_TRUE;

        return;
    }

    /* Load the test data. */
    snmp_test_initialize();

    /* Send SNMP queries to the agent..  */
    for (i = 0; i < QUERY_COUNT; i++ )
    {

        if (i == 1)
        {
            my_agent.nx_snmp_agent_v3_message_security_options = 0x02;
            nx_snmp_agent_md5_key_create(&my_agent, (UCHAR *)("privpassword"), &my_privacy_key);
            nx_snmp_agent_privacy_key_use(&my_agent, &my_privacy_key);
        }

        if (i == 2)
        {
            my_agent.nx_snmp_agent_v3_message_security_options = 0x01;
            nx_snmp_agent_md5_key_create(&my_agent, (UCHAR *)("authpassword"), &my_authentication_key);
            nx_snmp_agent_authenticate_key_use(&my_agent, &my_authentication_key);
        }

        if (i == 3)
        {
            my_agent.nx_snmp_agent_v3_security_authentication_size = 0x0C;
        }

        /* Send the SNMP manager query packet.  */
        status = nx_snmp_query_packet_send(&snmp_manager_socket, request_id, i);

        /* Check status.  */
        if (status)
        {        
            error_counter++; 
            break;
        }
        
        tx_thread_sleep(NX_IP_PERIODIC_RATE);

        request_id++;
    }

    /* Indicate the query response is complete. */
    query_response_complete = NX_TRUE;

}


static UINT   nx_snmp_query_packet_send(NX_UDP_SOCKET *snmp_manager_socket, UINT snmp_request_id, UINT packet_number)
{
UINT        status;
NX_PACKET   *query_packet;

    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&pool_0, &query_packet, NX_UDP_PACKET, 100);
    
    /* Check status.  */
    if (status)
    {
        return status;
    }


    memset(query_packet -> nx_packet_prepend_ptr, 0, (query_packet -> nx_packet_data_end - query_packet -> nx_packet_prepend_ptr));

    /* Write the SMTP response messages into the packet payload!  */
    memcpy(query_packet -> nx_packet_prepend_ptr, 
           snmp_query[packet_number].snmp_query_pkt_data, 
           snmp_query[packet_number].snmp_query_pkt_size); 

    /* Adjust the write pointer.  */
    query_packet -> nx_packet_length =  snmp_query[packet_number].snmp_query_pkt_size; 
    query_packet -> nx_packet_append_ptr =  query_packet -> nx_packet_prepend_ptr + query_packet -> nx_packet_length;

    /* Send the UDP packet with the correct port.  */
    status =  nx_udp_socket_send(snmp_manager_socket, query_packet, SNMP_AGENT_ADDRESS, 161);

    /* Check the status.  */
    if (status)      
        nx_packet_release(query_packet);

    return status;
}


static void  snmp_test_initialize()
{

     /* Contact - no security*/
     snmp_query[0].snmp_query_pkt_data = test_get_request_pkt_v3;
     snmp_query[0].snmp_query_pkt_size = sizeof(test_get_request_pkt_v3);
     snmp_query[1].snmp_query_pkt_data = test_get_request_pkt_v1;  
     snmp_query[1].snmp_query_pkt_size = sizeof(test_get_request_pkt_v1);
     snmp_query[2].snmp_query_pkt_data = test_get_request_pkt_v1;  
     snmp_query[2].snmp_query_pkt_size = sizeof(test_get_request_pkt_v1);
     snmp_query[3].snmp_query_pkt_data = test_get_request_pkt_v3_1;
     snmp_query[3].snmp_query_pkt_size = sizeof(test_get_request_pkt_v3_1);
}


/* Define the application's GET processing routine.  */

UINT    v3_mib2_get_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
{
    error_counter++;

    /* Return the status.  */
    return(NX_SUCCESS);
}


/* Define the application's GETNEXT processing routine.  */

UINT    v3_mib2_getnext_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
{

    /* Return the status.  */
    return(NX_SUCCESS);
}


/* Define the application's SET processing routine.  */

UINT    v3_mib2_set_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
{

    /* Return the status.  */
    return(NX_SUCCESS);
}

/* Define the username callback routine routine. Usernames should be 
   associated with permissions (public or private string) and what version
   of SNMP the user is configured for. The username callback should verify
   the incoming username MIB access permissions.  */
UINT  v3_mib2_username_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *username)
{

    return(NX_SUCCESS);

}

/* Define the application's update routine.  */ 

VOID  v3_mib2_variable_update(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr)
{

}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_snmp_abnormal_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   SNMP Abnormal Packet Test.................................N/A\n"); 

    test_control_return(3);  
}      
#endif
