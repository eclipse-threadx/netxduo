/* This NetX test concentrates on the basic SNMPv2 operation.  The 'manager' sends
   a request for an unknown item ("oid"). The SNMP agent should not responds, but
   set an internal error and be able to respond to the next request. 

   The MIB database is defined in demo_snmp_helper.h */
 

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_snmp.h"
#include   "nx_udp.h"
#include   "small_mib_helper.h"

extern void    test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_FRAGMENTATION) 

#define     DEMO_STACK_SIZE         4096

extern MIB_ENTRY   mib2_mib[];

//NX_SNMP_SECURITY_KEY my_authentication_key;

NX_SNMP_SECURITY_KEY my_privacy_key;

static UINT    mib2_getnext_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    mib2_set_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    mib2_get_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
static UINT    mib2_username_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *username);
static VOID    mib2_variable_update(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr);

static UCHAR context_engine_id[] = {0x80, 0x00, 0x0d, 0xfe, 0x03, 0x00, 0x11, 0x23, 0x23, 0x44, 0x55};
static UINT context_engine_size = 11;
static UCHAR context_name[] = {0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c};
static UINT context_name_size = 7;


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_agent;
static NX_SNMP_AGENT           my_agent;
static NX_PACKET_POOL          pool_0;
static NX_IP                   agent_ip;

#define SNMP_AGENT_ADDRESS     IP_ADDRESS(10, 128, 16, 17)


/* Define the counters used in the demo application...  */

static UINT                    status;
static ULONG                   error_counter;
static ULONG                   snmp_stack[DEMO_STACK_SIZE / sizeof(ULONG)];


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    snmp_test_initialize();

/* Inject SNMP manager query.  */
static VOID packet_inject(UCHAR *data_ptr, UINT data_size);


extern unsigned char v3_buffer_overwrite_packet1[1514];
extern int           v3_buffer_overwrite_packet1_size;
extern unsigned char v3_buffer_overwrite_packet2[54];
extern int           v3_buffer_overwrite_packet2_size;

#define QUERY_COUNT  2

typedef struct SNMP_QUERY_STRUCT
{
    char          *snmp_query_pkt_data;
    int           snmp_query_pkt_size;
} SNMP_QUERY;


static SNMP_QUERY   snmp_query[QUERY_COUNT];


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_snmp_v3_buffer_overwrite_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    
    /* Create the SNMP agent thread.  */
    tx_thread_create(&thread_agent, "Agent thread", thread_0_entry, 0,  
                      pointer, DEMO_STACK_SIZE, 4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, (sizeof(NX_PACKET) + 1536) * 10);
    pointer = pointer + (sizeof(NX_PACKET) + 1536) * 10;

    /* Create an IP instance.  */
    status += nx_ip_create(&agent_ip, "Agent IP", SNMP_AGENT_ADDRESS, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
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

    /* Check for ARP enable errors.  */
    if (status)
    {
        error_counter++;
    }

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&agent_ip);

    /* Check for UDP enable errors.  */
    if (status)
    {
        error_counter++;
    }

    status =  nx_ip_fragment_enable(&agent_ip);
    if (status)
    {
        error_counter++;
    }
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT status;
UINT        i;
NX_PACKET  *packet_ptr;

    printf("NetX Test:   SNMP V3 Buffer Overwrite Test.............................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Create an SNMP agent instance.  */
    status = nx_snmp_agent_create(&my_agent, "SNMP Agent", &agent_ip, snmp_stack, sizeof(snmp_stack), &pool_0, 
                         mib2_username_processing, mib2_get_processing, 
                         mib2_getnext_processing, mib2_set_processing);

    if (status)
    {
        error_counter++;
    }
    
#ifdef AUTHENTICATION_REQUIRED
    /* Create an authentication key. */
    status = nx_snmp_agent_md5_key_create(&my_agent, (UCHAR *)"authpassword", &my_authentication_key);
    if (status)
    {
        error_counter++;
    }

    /* Use the authentication key. */
    status = nx_snmp_agent_authenticate_key_use(&my_agent, &my_authentication_key);
    if (status)
    {
        error_counter++;
    }
#endif

    /* Create a privacy key. */
    status = nx_snmp_agent_md5_key_create(&my_agent, (UCHAR *)"privpassword", &my_privacy_key);
    if (status)
    {
        error_counter++;
    }

#if 0
    /* Use the privacy key. */
    status = nx_snmp_agent_privacy_key_use(&my_agent, &my_privacy_key);
    if (status)
    {
        error_counter++;
    }
#endif

    /* Start the SNMP instance.  */
    status = nx_snmp_agent_start(&my_agent);
    
    /* Return the test result.  */
    if (status)
    {
       error_counter++;
    }

    /* Load the test data up. */
    snmp_test_initialize();

    /* Send SNMP queries to the agent.  */
    for (i = 0; i < QUERY_COUNT; i++ )
    {

        /* Inject the SNMP manager query packet.  */
        packet_inject(snmp_query[i].snmp_query_pkt_data, snmp_query[i].snmp_query_pkt_size);
    }

    /* Wait for processing snmp packet.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Make sure the packet pool is not corrupted.  */
    while (pool_0.nx_packet_pool_available)
    {
        if (nx_packet_allocate(&pool_0, &packet_ptr, 0, NX_NO_WAIT) ||
            (packet_ptr -> nx_packet_pool_owner != &pool_0))
        {
            error_counter++;
            break;
        }
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

static VOID packet_inject(UCHAR *data_ptr, UINT data_size)
{
UINT        status;
NX_PACKET  *my_packet;

    status = nx_packet_allocate(&pool_0, &my_packet, NX_RECEIVE_PACKET, NX_NO_WAIT);

    /* Check status */
    if(status)
        error_counter ++;

    /* Make sure IP header is 4-byte aligned. */
    my_packet -> nx_packet_prepend_ptr += 2;
    my_packet -> nx_packet_append_ptr += 2;

    /* Fill in the packet with data. Skip the MAC header.  */
    status = nx_packet_data_append(my_packet, data_ptr, data_size, &pool_0, NX_NO_WAIT);

    /* Check status */
    if(status)
        error_counter ++;

    /* Skip the MAC header.  */
    my_packet -> nx_packet_length -= 14;
    my_packet -> nx_packet_prepend_ptr += 14;

    /* Directly receive the TCP packet.  */
    _nx_ip_packet_deferred_receive(&agent_ip, my_packet);
}

static void  snmp_test_initialize()
{
    snmp_query[0].snmp_query_pkt_data = &v3_buffer_overwrite_packet1[0];
    snmp_query[0].snmp_query_pkt_size = v3_buffer_overwrite_packet1_size;

    snmp_query[1].snmp_query_pkt_data = &v3_buffer_overwrite_packet2[0];
    snmp_query[1].snmp_query_pkt_size = v3_buffer_overwrite_packet2_size;
}


/* Define the application's GET processing routine.  */

UINT    mib2_get_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
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

UINT    mib2_getnext_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
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

UINT    mib2_set_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data)
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
UINT  mib2_username_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *username)
{

    mib2_variable_update(&agent_ip, &my_agent);

    return NX_SUCCESS;

}

/* Define the application's update routine.  */ 

VOID  mib2_variable_update(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr)
{

    /* Update the snmp parameters.  */
    return;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_snmp_v3_buffer_overwrite_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   SNMP V3 Buffer Overwrite Test.............................N/A\n"); 

    test_control_return(3);  
}      
#endif

