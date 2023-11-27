/* MQTT connect test.  This test case validates MQTT client connect without username/password. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_mqtt_client.h"
extern void    test_control_return(UINT status);
#define     DEMO_STACK_SIZE    2048

#define CLIENT_ID "1234"

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

extern void SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number);

/* Define what the initial system looks like.  */
static NXD_MQTT_CLIENT *client_ptr;
static UCHAR *stack_ptr;
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void       netx_mqtt_not_connected_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    stack_ptr = pointer;
    pointer += DEMO_STACK_SIZE;
    client_ptr = (NXD_MQTT_CLIENT*)pointer;

}

#define MQTT_CLIENT_THREAD_PRIORITY  2
#define TOPIC "topic"
#define MESSAGE "message"
static UINT keepalive_value;
static UINT cleansession_value;
#ifdef CTEST
static
#else /* CTEST */
extern
#endif /* CTEST */
UCHAR mqtt_memory[8192];
/* Define the test threads.  */
/* This thread sets up MQTT client and makes a connect request without username/password. */
static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NXD_ADDRESS server_address;

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT Not Connect Test ....................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_mqtt_client_create(client_ptr, "my client", CLIENT_ID, strlen(CLIENT_ID), &ip_0, &pool_0,
                                    stack_ptr, DEMO_STACK_SIZE, MQTT_CLIENT_THREAD_PRIORITY, 
                                    mqtt_memory, sizeof(mqtt_memory));
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    tx_thread_sleep(1);

    status = nxd_mqtt_client_publish(client_ptr, TOPIC, strlen(TOPIC), MESSAGE, strlen(MESSAGE), 0, 0, 1);
    if(status != NXD_MQTT_NOT_CONNECTED)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    status = nxd_mqtt_client_subscribe(client_ptr, TOPIC, strlen(TOPIC), 0);
    if(status != NXD_MQTT_NOT_CONNECTED)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);


    status = nxd_mqtt_client_unsubscribe(client_ptr, TOPIC, strlen(TOPIC));
    if(status != NXD_MQTT_NOT_CONNECTED)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    nxd_mqtt_client_delete(client_ptr);

    /* Determine if the test was successful.  */
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



