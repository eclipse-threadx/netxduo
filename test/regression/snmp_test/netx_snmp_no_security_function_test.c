/* This NetX test is a simple contact between agent and browser with no security.  Note that 
   NX_SNMP_FUNCTION_TESTING must be defined in nxd_snmp.c or else timer tick data (boot time, SysTimerTick, will not match the 
   'pre-recorded' data that the NetX SNMP Agent responses re compared with, and the test will fail. 
   */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_snmp.h"
#include   "nx_udp.h"


extern void    test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define VERBOSE
#define     DEMO_STACK_SIZE         2048

UCHAR      *current_object_requested;
UINT        aquery_response_complete = NX_FALSE; /* to synchronize when the agent sends the SNMP trap */

#define     NX_SNMP_ID_OFFSET       17   /* Size of top snmp header, version, public string */ 
                                         /* data header, and request id block; assumes public string is 'public' */
#define     QUERY_COUNT             2
#define     RESPONSE_COUNT          2


UCHAR   asysDescr[] =                "NetX SNMP Agent";              /* sysDescr:OctetString                 RO */
UCHAR   asysObjectID[] =             "1.3.6.1.2.1.1";                /* sysObjectID:ObjectID                 RO */
LONG    asysUpTime =                  0;                             /* sysUpTime:TimeTicks                  RO */
UCHAR   asysContact[128] =           "NetX sysContact Name";         /* sysContact:OctetString               RW */
UCHAR   asysName[128] =              "NetX sysName";                 /* sysName:OctetString                  RW */

/* This is for SNMPv3 discovery/synchronization. */
ULONG   ausmStatsUnknownEngineIDs =        0;                       /* usmStatsUnknownEngineIDs:Counter      RO */ 
ULONG   ausmStatsNotInTimeWindows =        0;                       /* usmStatsNotInTimeWindows:Counter      RO */ 
ULONG   ausmStatsUnsupportedSec   =        01;
ULONG   ausmStatsUnknownUsername   =       0;

/* Define application MIB data structure. Actual application structures would certainly vary.  */

typedef struct NOSEC_MIB_ENTRY_STRUCT
{

    UCHAR       *object_name;
    void        *object_value_ptr;
    UINT        (*object_get_callback)(VOID *source_ptr, NX_SNMP_OBJECT_DATA *object_data);
    UINT        (*object_set_callback)(VOID *destination_ptr, NX_SNMP_OBJECT_DATA *object_data);
} NOSEC_MIB_ENTRY;

/* Define the actual MIB-2.  */

static NOSEC_MIB_ENTRY   mib2_mib[] = {

    /*    OBJECT ID                OBJECT VARIABLE                  GET ROUTINE                 SET ROUTINE   */

    {(UCHAR *) "1.3.6.1.2.1.1.1.0",      asysDescr,                   nx_snmp_object_string_get,      NX_NULL},                       
    {(UCHAR *) "1.3.6.1.2.1.1.2.0",      asysObjectID,                nx_snmp_object_id_get,          NX_NULL},
    {(UCHAR *) "1.3.6.1.2.1.1.3.0",       &asysUpTime,                 nx_snmp_object_timetics_get,    NX_NULL},   
    {(UCHAR *) "1.3.6.1.2.1.1.4.0",       asysContact,                 nx_snmp_object_string_get,      nx_snmp_object_string_set},
    {(UCHAR *) "1.3.6.1.2.1.1.5.0",       asysName,                    nx_snmp_object_string_get,      nx_snmp_object_string_set},

    /*  Subset of usm variable bindings for SNMPv3 discovery messages and synchronization: */
    {(UCHAR *) "1.3.6.1.6.3.15.1.1.1.0",     &ausmStatsUnsupportedSec,          nx_snmp_object_counter_get,     nx_snmp_object_counter_set},
    {(UCHAR *) "1.3.6.1.6.3.15.1.1.2.0",     &ausmStatsNotInTimeWindows,        nx_snmp_object_counter_get,     nx_snmp_object_counter_set},
    {(UCHAR *) "1.3.6.1.6.3.15.1.1.3.0",     &ausmStatsUnknownUsername,         nx_snmp_object_counter_get,     nx_snmp_object_counter_set},
    {(UCHAR *) "1.3.6.1.6.3.15.1.1.4.0",     &ausmStatsUnknownEngineIDs,        nx_snmp_object_counter_get,     nx_snmp_object_counter_set},
    {(UCHAR *) "1.3.6.1.7",               (UCHAR *) "1.3.6.1.7",               nx_snmp_object_end_of_mib,      NX_NULL},
    {NX_NULL, NX_NULL, NX_NULL, NX_NULL}
};

/* To show byte by byte comparison of pre-recorded response with SNMP agent, define this option.  
#define VERBOSE
*/


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_agent;
static TX_THREAD               thread_manager;
static NX_SNMP_AGENT           my_nosec_agent;
static NX_PACKET_POOL          nosec_pool;
static NX_IP                   agent_ip;
static NX_IP                   manager_ip;
static NX_UDP_SOCKET           snmp_manager_socket;

#define SNMP_MANAGER_ADDRESS   IP_ADDRESS(10,0,0,1)  
#define SNMP_AGENT_ADDRESS     IP_ADDRESS(10,0,0,10)  



UCHAR acontext_engine_id[] = {0x80, 0x00, 0x0d, 0xfe, 0x03, 0x00, 0x77, 0x23, 0x23, 0x46, 0x69};
UINT  acontext_engine_size = 11;

/* Define the counters used in the demo application...  */

static UINT                    status;
static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    snmp_test_initialize();
static UINT    check_valid_response(NX_PACKET *agent_packet, UINT packet_number, UINT *valid);


static UINT    nosec_mib2_getnext_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    nosec_mib2_set_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    nosec_mib2_get_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT  nosec_mib2_username_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *username);
static VOID  nosec_mib2_variable_update(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr);

/* Send SNMP manager query.  */
static UINT    nx_snmp_query_packet_send(NX_UDP_SOCKET *snmp_manager_socket, UINT request_id, UINT packet_number);

extern char get_v3_request_packet[101];
extern int  v3_request_size;
extern char get_v3_next_request_packet[141];
extern int  v3_next_request_size;
extern char v3_report_packet[147];
extern int  v3_report_size;
extern char v3_response_packet[154];
extern int  v3_response_size;


typedef struct SNMP_QUERY_STRUCT
{
    char          *snmp_query_pkt_data;
    int            snmp_query_pkt_size;
} SNMP_QUERY;

typedef struct SNMP_RESPONSE_STRUCT
{
    char          *snmp_response_pkt_data;
    int            snmp_response_pkt_size;
} SNMP_RESPONSE;


static SNMP_QUERY       snmp_query[QUERY_COUNT];
static SNMP_RESPONSE    snmp_response[RESPONSE_COUNT];

#define        SNMP_START_OFFSET (14 + 20 + 8) // ethernet, ip and udp headers


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_snmp_security_no_security_application_define(void *first_unused_memory)
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

    printf("NetX Test:   SNMP No Security Function Test............................");

        /* Check for IP create errors.  */
    /* Check for IP create errors.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&nosec_pool, "NetX Main Packet Pool", 1000, pointer, 4096);
    pointer = pointer + 4096;

        /* Check for IP create errors.  */
    if (status)
    {

#ifdef VERBOSE
        printf("\npacket create error 0x%x \n",  status);
#endif
        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Create an IP instance.  */
    status = nx_ip_create(&agent_ip, "Agent IP", SNMP_AGENT_ADDRESS, 0xFFFFFF00UL, &nosec_pool, _nx_ram_network_driver_1500, pointer , 2048, 1);

    pointer += 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&manager_ip, "Manager IP", SNMP_MANAGER_ADDRESS, 0xFFFFFF00UL, &nosec_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);

    pointer += 2048;

    /* Check for IP create errors.  */
    if (status)
    {

#ifdef VERBOSE
        printf("\nIP create error 0x%x \n",  status);
#endif
        printf("ERROR!\n");
        test_control_return(1);
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
        printf("ERROR!\n");
        test_control_return(1);
    }          

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&agent_ip);
    status += nx_udp_enable(&manager_ip);

    /* Check for UDP enable errors.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }          


        /* Create an SNMP agent instance.  */
    status = nx_snmp_agent_create(&my_nosec_agent, "public", &agent_ip, pointer, 4096, &nosec_pool, 
                         nosec_mib2_username_processing, nosec_mib2_get_processing, 
                         nosec_mib2_getnext_processing, nosec_mib2_set_processing);
    pointer =  pointer + 4096;

    if (status)
    {

#ifdef VERBOSE
        printf("\nagent create error 0x%x \n", status);
#endif
        printf("ERROR!\n");
        test_control_return(1);
    }          

    if (my_nosec_agent.nx_snmp_agent_v3_enabled == NX_TRUE)
    {
        ULONG boot_count;

        /* Make sure boot time and engine boot ID match the pre-recorded data. */
        boot_count = 0x1; 
        status = nx_snmp_agent_context_engine_set(&my_nosec_agent, acontext_engine_id, acontext_engine_size);
        status |= nx_snmp_agent_v3_context_boots_set(&my_nosec_agent, boot_count);

        if (status)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }          
    }
    else
    {

#ifdef VERBOSE
        printf("\n agent not enabled for V3 \n");
#endif
        printf("ERROR!\n");
        test_control_return(1);
    }          

}

/* Define the SNMP Agent thread.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT status;


    tx_thread_sleep(20);

    /* Start the SNMP instance.  */
    status = nx_snmp_agent_start(&my_nosec_agent);
    
    /* Return the test result.  */
    if (status)
    {
       error_counter++;
    }

    while (!aquery_response_complete)
    {
        tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);
    }

   // tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);

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
    
/* SNMP Manager thread */
static void    thread_1_entry(ULONG thread_input)
{

NX_PACKET   *agent_packet;
UINT        port;
UINT        i;
USHORT      request_id = 1;
UINT        valid = NX_TRUE;

    /* Let the agent get set up first! */
    tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);

    status = nx_udp_socket_create(&manager_ip, &snmp_manager_socket, "Manager Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Bind the UDP socket to the IP port.  */
    status |=  nx_udp_socket_bind(&snmp_manager_socket, 0, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

#ifdef VERBOSE
        printf("\n UDP socket create error 0x%x \n", status);
#endif
        error_counter++;

        /* Indicate the query response is complete. */
        aquery_response_complete = NX_TRUE;

        return;
    }

    /* Load the test data. */
    snmp_test_initialize();

    /* Send SNMP queries to the agent..  */
    for (i = 0; i < QUERY_COUNT; i++ )
    {

        /* Send the SNMP manager query packet.  */
        status = nx_snmp_query_packet_send(&snmp_manager_socket, request_id,  i);

#ifdef VERBOSE
        printf("\n%d query packet send error 0x%x \n",i, status);
#endif
        /* Check status.  */
        if (status)
        {        
            error_counter++; 
            break;
        }    

        /* Receive the SNMP agent response.  */
        status =  nx_udp_socket_receive(&snmp_manager_socket, &agent_packet, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status)
        {

#ifdef VERBOSE
        printf("\n%d socket receive error 0x%x \n",i, status);
#endif
            error_counter++;
            break;
        }       

        /* Get the SNMP agent UDP port.  */
        status = nx_udp_packet_info_extract(agent_packet, NX_NULL ,NX_NULL, &port, NX_NULL);

        /* Check status.  */
        if (status)
        {

#ifdef VERBOSE
        printf("\n%d packet extract error 0x%x \n",i, status);
#endif
            error_counter++; 
            break;
        }

        /* Release the packet.  */
        nx_packet_release(agent_packet);

        request_id++;
    }

    /* Indicate the query response is complete. */
    aquery_response_complete = NX_TRUE;

}


/* Determines if we got a valid response using known SNMP query and response data.  */
UINT check_valid_response(NX_PACKET *agent_packet, UINT packet_number, UINT *valid)
{

UINT  data_size;
UCHAR *work_ptr;
UINT   j;


    work_ptr = (UCHAR *)(&snmp_response[packet_number].snmp_response_pkt_data[0] + SNMP_START_OFFSET);

    data_size = snmp_response[packet_number].snmp_response_pkt_size  - SNMP_START_OFFSET;

    if (data_size == 0)
    {
        return 1; /* Invalid data */
    }

    for (j = 0; j < data_size; j++)
    {

        /* For each test , initialize outcome as successful test. */
        *valid = NX_TRUE;

#ifdef VERBOSE
        printf("%d. 0%x  0%x ", j, *(agent_packet -> nx_packet_prepend_ptr + j), work_ptr[j]);
#endif

        /* It is unlikely this logic is needed as long as NX_SNMP_FUNCTION_TESTING is defined, 
           and the sysUpTime is always updated to 1. */

        if (*(agent_packet -> nx_packet_prepend_ptr + j) != work_ptr[j])
        {

            /* There is no way to match certain variables such as 'engine boot time' with system time of the pre-recorded
               data.  Ignore this data */

            if (packet_number == 1)   
            {

                /* Case 1: the 'work' packet timer tick data is two bytes  */
                if (j == 109)
                {
                
                    /* Determine if the time value is 1 byte or 2 bytes. */
                    if ((work_ptr[j] == 2) && (*(agent_packet -> nx_packet_prepend_ptr+j) == 1))
                    {
                        /* 2 bytes. Skip an extra byte. We do this by bumping the work pointer by one. */
                        work_ptr = (UCHAR *)(&snmp_response[packet_number].snmp_response_pkt_data[0] + SNMP_START_OFFSET + 1);
                    }               
    
                    /* For either cast, skip the time value. */
                    j++;
#ifdef VERBOSE    
                    printf("Packet %d skipping %d'th element for comparison\n", packet_number, j);
#endif

                    continue;
                }
                /* Case 2:  both have same length of timer tick data, but different value. */
                else if (j == 110)
                {

                    /* Just skip over the current index. */
#ifdef VERBOSE
                    printf("Packet %d skipping timer tick data at %d'th index for comparison\n", packet_number, j);
#endif

                    /* Are they both two bytes long? */
                    if (work_ptr[j-1] == 2)
                    {

                        /* Yes. Skip an extra index in addition
                           to the current one. */
#ifdef VERBOSE
                        printf("Packet %d two byte timer tick: skip one more index to %d'th index\n", packet_number, j);
#endif

                        j++;
                    }

                    continue;
                }
                else
                {

                    /* Else invalid or unexpected data. */
                    return(1);
                }
            }
            else
            {
            
                /* Else invalid or unexpected data. */
                return(1);
            }
        }
#ifdef VERBOSE
        printf("\n");
#endif

    }

    return NX_SUCCESS;

}

static UINT   nx_snmp_query_packet_send(NX_UDP_SOCKET *snmp_manager_socket, UINT snmp_request_id, UINT packet_number)
{
UINT        status;
NX_PACKET   *query_packet;

    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&nosec_pool, &query_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {

#ifdef VERBOSE
        printf("\n packet allocate error 0x%x \n", status);
#endif
        return status;
    }

    /* Write the SNMP query messages into the packet payload!  */
    snmp_query[packet_number].snmp_query_pkt_data += SNMP_START_OFFSET;
    memcpy(query_packet -> nx_packet_prepend_ptr, snmp_query[packet_number].snmp_query_pkt_data, snmp_query[packet_number].snmp_query_pkt_size - SNMP_START_OFFSET);

    /* Adjust the write pointer.  */
    query_packet -> nx_packet_length =  snmp_query[packet_number].snmp_query_pkt_size - SNMP_START_OFFSET;
    query_packet -> nx_packet_append_ptr =  query_packet -> nx_packet_prepend_ptr + query_packet -> nx_packet_length;


    /* Send the UDP packet with the correct port.  */
    status =  nx_udp_socket_send(snmp_manager_socket, query_packet, IP_ADDRESS(10, 0, 0, 10), 161);

    /* Check the status.  */
    if (status)      
    {

#ifdef VERBOSE
        printf("\n socket send error 0x%x \n", status);
#endif
        nx_packet_release(query_packet);         
    }
    return status;
}


static void  snmp_test_initialize()
{

     /* Contact - no security*/
     snmp_query[0].snmp_query_pkt_data = &get_v3_request_packet[0];
     snmp_query[0].snmp_query_pkt_size = v3_request_size;
     snmp_query[1].snmp_query_pkt_data = &get_v3_next_request_packet[0];  
     snmp_query[1].snmp_query_pkt_size = v3_next_request_size;

     snmp_response[0].snmp_response_pkt_data = &v3_report_packet[0];
     snmp_response[0].snmp_response_pkt_size = v3_report_size;
     snmp_response[1].snmp_response_pkt_data = &v3_response_packet[0];
     snmp_response[1].snmp_response_pkt_size = v3_response_size;

}


/* Define the application's GET processing routine.  */
UINT    nosec_mib2_get_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
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

UINT    nosec_mib2_getnext_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
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

UINT    nosec_mib2_set_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
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
UINT  nosec_mib2_username_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *username)
{

    nosec_mib2_variable_update(&agent_ip, &my_nosec_agent);

    return NX_SUCCESS;

}


/* Define the application's update routine.  */ 

VOID  nosec_mib2_variable_update(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr)
{


    /* Update the snmp parameters.  */
    asysUpTime =                 1; /* This is necessary to compare pre-recorded data with SNMP agent response! */
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_snmp_security_no_security_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   SNMP No Security Function Test............................N/A\n"); 

    test_control_return(3);  
}      
#endif

