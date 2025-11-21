/* This NetX test concentrates on the basic IP operation.  */

#include   "nxd_mqtt_client.h"
#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *ip_0_memory_ptr;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern ULONG   simulated_address_msw;
extern ULONG   simulated_address_lsw;
extern void SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_mqtt_api_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

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
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create IP instances.  */
    ip_0_memory_ptr =  pointer;
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);                                    
}



/* Define the test threads.  */
#define MQTT_CLIENT_THREAD_PRIORITY  2
static NXD_MQTT_CLIENT my_client;
static ULONG mqtt_stack_space[DEMO_STACK_SIZE / sizeof(ULONG)];
static ULONG client_memory;
static void    ntest_0_entry(ULONG thread_input)
{
NXD_ADDRESS server_ip;

UINT        status;
UCHAR       message[4];    

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT API Test ............................................");


    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test MQTT_CLIENT control block being NULL */
    status = nxd_mqtt_client_create(NX_NULL, NX_NULL, NX_NULL, 0, &ip_0, &pool_0, mqtt_stack_space, sizeof(mqtt_stack_space), MQTT_CLIENT_THREAD_PRIORITY, NX_NULL, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Test IP control block being NULL */
    status = nxd_mqtt_client_create(&my_client, NX_NULL, NX_NULL, 0, /* &ip_0*/NX_NULL, &pool_0, mqtt_stack_space, sizeof(mqtt_stack_space), MQTT_CLIENT_THREAD_PRIORITY, NX_NULL, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Test packet_pool control block being NULL */
    status = nxd_mqtt_client_create(&my_client, NX_NULL, NX_NULL, 0, &ip_0, NX_NULL/*&pool_0*/, mqtt_stack_space, sizeof(mqtt_stack_space), MQTT_CLIENT_THREAD_PRIORITY, NX_NULL, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Test stack space being NULL */
    status = nxd_mqtt_client_create(&my_client, NX_NULL, NX_NULL, 0, &ip_0, &pool_0, NX_NULL/*mqtt_stack_space*/, sizeof(mqtt_stack_space), MQTT_CLIENT_THREAD_PRIORITY, NX_NULL, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    
    /* Test stack size being 0 */
    status = nxd_mqtt_client_create(&my_client, NX_NULL, NX_NULL, 0, &ip_0, &pool_0, mqtt_stack_space, 0, MQTT_CLIENT_THREAD_PRIORITY, NX_NULL, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    
    /* Test ip_id != NX_IP_ID */
    ip_0.nx_ip_id = 0;
    status = nxd_mqtt_client_create(&my_client, NX_NULL, NX_NULL, 0, &ip_0, &pool_0, mqtt_stack_space, sizeof(mqtt_stack_space), MQTT_CLIENT_THREAD_PRIORITY, NX_NULL, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    ip_0.nx_ip_id = NX_IP_ID;

    /* Test client connect API. */
    server_ip.nxd_ip_version = 4;
    /* Test MQTT_CLIENT control block being NULL */
    status = nxd_mqtt_client_connect(NX_NULL, &server_ip, NXD_MQTT_PORT,  0, 0, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Test server_ip being NULL */
    status = nxd_mqtt_client_connect(&my_client, NX_NULL, NXD_MQTT_PORT, 0, 0, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Test invalid port number */
    status = nxd_mqtt_client_connect(&my_client, &server_ip,  0, 0, 0, 0);
    if(status != NX_INVALID_PORT)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    
    /* Test invalid IP version number */
    server_ip.nxd_ip_version = 3;
    status = nxd_mqtt_client_connect(&my_client, &server_ip,  NXD_MQTT_PORT, 0, 0, 0);    
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Restore the IP version number */
    server_ip.nxd_ip_version = 6;
    
    /* Test invalid username/password combination. */
    status = nxd_mqtt_client_login_set(&my_client, NX_NULL, 8, NX_NULL, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    
    /* Test invalid username/password combination. */
    status = nxd_mqtt_client_login_set(&my_client, NX_NULL, 0, NX_NULL, 8);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Test invalid client_ptr. */
    status = nxd_mqtt_client_login_set(NX_NULL, NX_NULL, 0, NX_NULL, 8);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* MQTT 5.10sp4:  The following test was removed because MQTT shall 
       allow user name being set and password not being set. */
#if 0
    status = nxd_mqtt_client_login_set(&my_client, "username", 8, NX_NULL, 0);
    if (status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
#endif

    /* Validate nxd_mqtt_client_publish  */
    status = nxd_mqtt_client_publish(NX_NULL, "topic", 5, "message", 7, 0, 0, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Validate topic name */
    status = nxd_mqtt_client_publish(&my_client, NX_NULL, 5, "message", 7, 0, 0, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    status = nxd_mqtt_client_publish(&my_client, "topic", 0, "message", 7, 0, 0, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Validate message length. */
    status = nxd_mqtt_client_publish(&my_client, "topic", 5, "message", 0, 0, 0, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Validate message empty and non-zero length. */
    status = nxd_mqtt_client_publish(&my_client, "topic", 5, NX_NULL, 2, 0, 0, 0);
    if(status != NXD_MQTT_NOT_CONNECTED)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Validate message empty and zero length. */
    status = nxd_mqtt_client_publish(&my_client, "topic", 5, NX_NULL, 0, 0, 0, 0);
    if(status != NXD_MQTT_NOT_CONNECTED)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Validate QoS value. */
    status = nxd_mqtt_client_publish(&my_client, "topic", 5, "message", 7, 0, 4, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    

    /* Validate nxd_mqtt_client_subscribe. */
    status = nxd_mqtt_client_subscribe(NX_NULL, "topic", 5, 0);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);


    status = nxd_mqtt_client_subscribe(&my_client, NX_NULL, 5, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    status = nxd_mqtt_client_subscribe(&my_client, "topic", 0, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    status = nxd_mqtt_client_subscribe(&my_client, "topic", 5, 3);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);


    /* validate nxd_mqtt_client_unsubscribe. */
    status = nxd_mqtt_client_unsubscribe(NX_NULL, "topic", 5);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);


    status = nxd_mqtt_client_unsubscribe(&my_client, NX_NULL, 5);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    status = nxd_mqtt_client_unsubscribe(&my_client, "topic", 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);



    /* Validate nxd_mqtt_client_receive_notify_set. */
    status = nxd_mqtt_client_receive_notify_set(NX_NULL, NX_NULL);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Validate nxd_mqtt_client_receive_notify_set. */
    status = nxd_mqtt_client_receive_notify_set(&my_client, NX_NULL);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Validate nxd_mqtt_client_disconnect_notify_set NULL client_ptr behavior. */
    status = nxd_mqtt_client_disconnect_notify_set(NX_NULL, NX_NULL);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Validate nxd_mqtt_client_disconnect */
    status = nxd_mqtt_client_disconnect(NX_NULL);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    

    /* Validate nxd_mqtt_client_delete */
    status = nxd_mqtt_client_delete(NX_NULL);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    

    /* Validate nxd_mqtt_client_message_get. */
    status = nxd_mqtt_client_message_get(NX_NULL, NX_NULL, 0, NX_NULL, message, sizeof(message), NX_NULL);
    if(status != NX_PTR_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);        

    status = nxd_mqtt_client_message_get(&my_client, NX_NULL, 0, NX_NULL, NX_NULL, 0, NX_NULL);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);        
    status = nxd_mqtt_client_message_get(&my_client, NX_NULL, 0, NX_NULL, message, sizeof(message), NX_NULL);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);        

    status = nxd_mqtt_client_will_message_set(NX_NULL, NX_NULL, 0, NX_NULL, 0, 0, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    status = nxd_mqtt_client_will_message_set(&my_client, NX_NULL, 2, NX_NULL, 0, 0, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    
    status = nxd_mqtt_client_will_message_set(&my_client, "ab", 0, NX_NULL, 0, 0, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    
    status = nxd_mqtt_client_will_message_set(&my_client, "Ab", 2, NX_NULL, 0, 0, 4);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    

    status = nxd_mqtt_client_will_message_set(&my_client, "Ab", 2, NX_NULL, 0, 2, 0);
    if(status != NXD_MQTT_INVALID_PARAMETER)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    

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
