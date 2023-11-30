/* MQTT connect test.  This test case validates MQTT client connect without username/password. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_mqtt_client.h"
extern void    test_control_return(UINT status);
#define     DEMO_STACK_SIZE    2048

#define CLIENT_ID "1234"
#define TOPIC "topic"
#define MESSAGE_QOS0 "MESSAGE_QOS0"
#define MESSAGE_QOS1 "MESSAGE_QOS11"
#define MESSAGE_QOS2 "MESSAGE_QOS222"

static UINT packet_identifier = 0xbeef;


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           server_socket;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
#ifdef CTEST
static
#else /* CTEST */
extern
#endif /* CTEST */
UCHAR mqtt_memory[8192];
extern void SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number);

/* Define what the initial system looks like.  */
static NXD_MQTT_CLIENT *client_ptr;
//NXD_MQTT_CLIENT my_client;
static UCHAR *stack_ptr;
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void       netx_mqtt_client_receive_QoS2_application_define(void *first_unused_memory)
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
                     4, 4, TX_NO_TIME_SLICE, TX_DONT_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                           pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    stack_ptr = pointer;
    pointer += DEMO_STACK_SIZE;
    client_ptr = (NXD_MQTT_CLIENT*)pointer;
    //client_ptr = &my_client;

}



static UINT keepalive_value;
static UINT cleansession_value;
#define DEMO_TIMER_EVENT     1
#define DEMO_MESSAGE_EVENT   2
#define DEMO_ALL_EVENTS 3

TX_EVENT_FLAGS_GROUP mqtt_app_flag;

static VOID my_notify_func(NXD_MQTT_CLIENT* client_ptr, UINT number_of_messages)
{
  
    tx_event_flags_set(&mqtt_app_flag, DEMO_MESSAGE_EVENT, TX_OR);
    return;
  
}

static UCHAR topic[100], message[100];

#define MQTT_CLIENT_THREAD_PRIORITY  2
/* Define the test threads.  */
/* This thread sets up MQTT client and makes a connect request without username/password. */
static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NXD_ADDRESS server_address;
ULONG events;
UINT topic_length, message_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT Receive QoS 2 Test ..................................");

    status = tx_event_flags_create(&mqtt_app_flag, "my app event");
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_mqtt_client_create(client_ptr, "my client", CLIENT_ID, strlen(CLIENT_ID), &ip_0, &pool_0,
                                    stack_ptr, DEMO_STACK_SIZE, MQTT_CLIENT_THREAD_PRIORITY, mqtt_memory, sizeof(mqtt_memory));
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    tx_thread_sleep(1);
    status = nxd_mqtt_client_receive_notify_set(client_ptr, my_notify_func);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    server_address.nxd_ip_version = 4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    keepalive_value = 0;
    cleansession_value = 0;
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT,
                                     keepalive_value, cleansession_value, 5);
#ifndef NXD_MQTT_REQUIRE_TLS
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Wait for incoming message. */
    tx_event_flags_get(&mqtt_app_flag, DEMO_ALL_EVENTS, TX_OR_CLEAR, &events, TX_WAIT_FOREVER);
    
    status = nxd_mqtt_client_message_get(client_ptr, topic, sizeof(topic), &topic_length, message, sizeof(message), &message_length);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);


    if ((topic_length != strlen(TOPIC)) || strncmp(TOPIC, topic, topic_length) || (message_length != strlen(MESSAGE_QOS2)) ||
        strncmp(message, MESSAGE_QOS2, message_length))
    {
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }
    nx_packet_release(packet_ptr);

    tx_thread_sleep(3);
#else
    if(status != NXD_MQTT_CONNECT_FAILURE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
#endif

    nxd_mqtt_client_disconnect(client_ptr);
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

    /* Check for error.  */

static UCHAR content[100];

static UCHAR fixed_header[] = {0x10, 0x00, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x4, 0x0, 0x0, 0x0};

/* This thread acts as MQTT server, accepting the connection. */
static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
NX_PACKET  *packet_ptr;
UCHAR      *byte;
UINT        index = 0;
    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, NXD_MQTT_PORT, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    tx_thread_resume(&ntest_0);

    /* Accept a connection from client socket.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    tx_thread_sleep(1);
    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* construct the connect message. */
    memcpy(content, fixed_header, sizeof(fixed_header));
    /* Append client ID */
    content[sizeof(fixed_header)] = (strlen(CLIENT_ID) >> 8) & 0xf;
    content[sizeof(fixed_header) + 1] = (strlen(CLIENT_ID) & 0xf);
    memcpy(content +  sizeof(fixed_header) + 2, CLIENT_ID, strlen(CLIENT_ID));

    content[1] = (UCHAR)(sizeof(fixed_header) + strlen(CLIENT_ID));

    /* Fill in the connection_flag, keepalive, and cleansession flags. */
    content[10] = keepalive_value >> 8;
    content[11] = keepalive_value & 0xFF;
    if(cleansession_value)
        content[9] = content[9] | 2;

    /* Validate the MQTT connect request. */
    if(memcmp(packet_ptr -> nx_packet_prepend_ptr, content, sizeof(fixed_header) + strlen(CLIENT_ID)))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Response with SUCCESS */
    byte = packet_ptr -> nx_packet_prepend_ptr ;
    byte[0] = 0x20;
    byte[1] = 0x02;
    byte[2] = 0;
    byte[3] = 0;

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + 4;
    packet_ptr -> nx_packet_length = 4;
    
    status = nx_tcp_socket_send(&server_socket, packet_ptr, 1);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    tx_thread_sleep(50);

    /* Send a publish message with QoS 2 */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 0);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    byte = packet_ptr -> nx_packet_prepend_ptr;
    byte[0] = 0x34;

    index = 2;
    byte[index++] = (strlen(TOPIC) >> 8)&0xFF;
    byte[index++] = strlen(TOPIC) & 0xFF;
    memcpy(byte + index, TOPIC, strlen(TOPIC));

    index += strlen(TOPIC);
    byte[index++] = packet_identifier >> 8;
    byte[index++] = packet_identifier & 0xFF;

    byte[index++] = ((strlen(MESSAGE_QOS2)) >> 8) & 0xFF;
    byte[index++] = (strlen(MESSAGE_QOS2)) & 0xFF;

    memcpy(byte + index, MESSAGE_QOS2, strlen(MESSAGE_QOS2));
    index += strlen(MESSAGE_QOS2);

    byte[1] = index - 2;
    packet_ptr -> nx_packet_length = index;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + index;

    status = nx_tcp_socket_send(&server_socket, packet_ptr, 1);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Expect PUBBACK */
    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    byte = packet_ptr -> nx_packet_prepend_ptr;
    if(packet_ptr -> nx_packet_length != 4)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    if((byte[0] != 0x50) || (byte[1] != 2) || (byte[2] != (packet_identifier >> 8)) || (byte[3] != (packet_identifier & 0xFF)))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);


    /* Respond with PUBREL */
    byte[0] = 0x60;
    status = nx_tcp_socket_send(&server_socket, packet_ptr, 1);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Expect PUBCOMP */
    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    byte = packet_ptr -> nx_packet_prepend_ptr;
    if(packet_ptr -> nx_packet_length != 4)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    if((byte[0] != 0x70) || (byte[1] != 2) || (byte[2] != (packet_identifier >> 8)) || (byte[3] != (packet_identifier & 0xFF)))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* All deon, release the packet. */
    status = nx_packet_release(packet_ptr);



    /* Disconnect.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, NXD_MQTT_PORT);

    /* Check for error.  */
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
}

