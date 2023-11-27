/* MQTT connect test.  This test case validates MQTT client connect without username/password. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_mqtt_client.h"
extern void    test_control_return(UINT status);

#if !defined(NXD_MQTT_REQUIRE_TLS)

#define     DEMO_STACK_SIZE    2048

#define CLIENT_ID "1234"
#define TOPIC_LEN 256
#define MESSAGE_LEN 256
#define CLIENT_MEMORY_SIZE 1024
#define PACKET_BUFFER_SIZE 1024

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           server_socket;


#define NUM_PACKETS                 32
#define PACKET_SIZE                 128
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

static TX_SEMAPHORE semaphore_server_received;
static TX_SEMAPHORE semaphore_client_sent;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */
static NXD_MQTT_CLIENT *client_ptr;
static UCHAR *client_memory;
static CHAR *stack_ptr;
static UCHAR *packet_buffer;
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void       netx_mqtt_client_publish_packet_chain_application_define(void *first_unused_memory)
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
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    tx_semaphore_create(&semaphore_server_received, "semaphore server received", 0);
    tx_semaphore_create(&semaphore_client_sent, "semaphore client sent", 0);

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pointer, PACKET_POOL_SIZE);
    pointer = pointer + PACKET_POOL_SIZE;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;
    stack_ptr = pointer;
    pointer += DEMO_STACK_SIZE;

    packet_buffer = pointer;
    pointer += PACKET_BUFFER_SIZE;

    client_memory = pointer;
    pointer += CLIENT_MEMORY_SIZE;

    client_ptr = (NXD_MQTT_CLIENT*)pointer;
}

#define MQTT_CLIENT_THREAD_PRIORITY  2
static UINT keepalive_value;
static UINT cleansession_value;
static UINT QoS;
static UINT retain;
static UCHAR *topic;
static UCHAR *message;

/* Define the test threads.  */
/* This thread sets up MQTT client and makes a connect request without username/password. */
static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NXD_ADDRESS server_address;
UINT        i;
NX_PACKET  *temp_packets[NUM_PACKETS];

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT Publish Packet Chain Test............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_mqtt_client_create(client_ptr, "my client", CLIENT_ID, strlen(CLIENT_ID), &ip_0, &pool_0,
                                    stack_ptr, DEMO_STACK_SIZE, MQTT_CLIENT_THREAD_PRIORITY, client_memory, CLIENT_MEMORY_SIZE);
    if(status)
        error_counter++;

    server_address.nxd_ip_version = 4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    keepalive_value = 0;
    cleansession_value = 0;

    topic = packet_buffer;
    message =  packet_buffer + TOPIC_LEN;

    for (i = 0; i < TOPIC_LEN; i++)
    {
        topic[i] = i & 0xff;
        message[i] = 0xff - (i & 0xff);
    }

    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT,
                                     keepalive_value, cleansession_value, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    QoS = 1;
    retain = 0;

    for (i = 0 ; i < NUM_PACKETS - 2; i++)
    {
        status = nx_packet_allocate(&pool_0, &(temp_packets[i]), NX_TCP_PACKET, NX_WAIT_FOREVER);
        if (status)
        {
            error_counter++;
            break;
        }
    }

    /* Fail to append topic. */
    status = nxd_mqtt_client_publish(client_ptr, topic, TOPIC_LEN, message, MESSAGE_LEN, retain, QoS, NX_IP_PERIODIC_RATE);
    if (status != NXD_MQTT_INTERNAL_ERROR)
        error_counter++;

    /* Fail to append QOS. */
    status = nxd_mqtt_client_publish(client_ptr, topic, 195, message, MESSAGE_LEN, retain, QoS, NX_IP_PERIODIC_RATE);
    if (status != NXD_MQTT_INTERNAL_ERROR)
        error_counter++;

    /* Fail to append message. */
    status = nxd_mqtt_client_publish(client_ptr, topic, 66, message, MESSAGE_LEN, retain, QoS, NX_IP_PERIODIC_RATE);
    if (status != NXD_MQTT_INTERNAL_ERROR)
        error_counter++;

    for (i = 0 ; i < NUM_PACKETS - 2; i++)
    {
        nx_packet_release(temp_packets[i]);
    }

    /* Issue a subscribe command. */
    status = nxd_mqtt_client_publish(client_ptr, topic, TOPIC_LEN, message, MESSAGE_LEN, retain, QoS, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    tx_semaphore_put(&semaphore_client_sent);

    tx_semaphore_get(&semaphore_server_received, NX_WAIT_FOREVER);

    nxd_mqtt_client_disconnect(client_ptr);

    nxd_mqtt_client_delete(client_ptr);

    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total)
        error_counter++;

    /* Determine if the test was successful.  */
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

/* This thread acts as MQTT server, accepting the connection. */
static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
NX_PACKET  *packet_ptr;
UCHAR      *byte;
USHORT      packet_id;
UINT        len, packet_len;
UCHAR       control_header;
UINT        i;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, NXD_MQTT_PORT, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    tx_thread_resume(&ntest_0);

    /* Accept a connection from client socket.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    tx_thread_sleep(1);

    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);

    if (status)
    {
        error_counter++;
    }
    else
    {

        /* Response with Connect SUCCESS */
        byte = packet_ptr->nx_packet_prepend_ptr;
        byte[0] = 0x20;
        byte[1] = 0x02;
        byte[2] = 0;
        byte[3] = 0;

        packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr + 4;
        packet_ptr->nx_packet_length = 4;

        status = nx_tcp_socket_send(&server_socket, packet_ptr, 1 * NX_IP_PERIODIC_RATE);
        if (status)
            error_counter++;

        packet_ptr = NX_NULL;
        packet_len = 0;

        tx_semaphore_get(&semaphore_client_sent, NX_WAIT_FOREVER);

        while (1)
        {
            status = nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_IP_PERIODIC_RATE);

            if (status)
                break;

            nx_packet_data_retrieve(packet_ptr, packet_buffer + packet_len, (ULONG *)&len);
            packet_len += len;

            nx_packet_release(packet_ptr);
        }

        tx_semaphore_put(&semaphore_server_received);

        /* Check the publish message. */

        control_header = 0x30 | (packet_buffer[0] & 0x0F); /* Publish */
        len = 1 + 2 + 2 + TOPIC_LEN; /* Control header 1 + remaining length 2 + topic length 2 + topic */

        for (i = 0 ; i < TOPIC_LEN; i++)
        {
            if (packet_buffer[5 + i] != (i & 0xff))
            {
                error_counter++;
                break;
            }
        }

        if (((control_header & 6) >> 1) != 0)
        {
            packet_id = packet_buffer[len];/* Fill in packet ID MSB. */
            packet_id = (packet_id << 8) | packet_buffer[len + 1];/* Fill in packet ID MSB. */
            len += 2;
        }

        /* Check the message being pulished. */
        for (i = 0 ; i < MESSAGE_LEN; i++)
        {
            if (packet_buffer[len + i] != (0xff - (i & 0xff)))
            {
                error_counter++;
                break;
            }
        }

        len += MESSAGE_LEN;

        /* Fill in the QoS and Retain information. */
        control_header = control_header & 0xF8;
        control_header = control_header | (QoS << 1);
        if (retain)
            control_header = control_header | 1;

        /* Now validate message length */
        if (packet_len != len)
            error_counter++;

        /* Validate the MQTT publish request. */
        if (packet_buffer[0] != control_header)
            error_counter++;

        /* Disconnect.  */
        status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
            error_counter++;
    }

    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, NXD_MQTT_PORT);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_mqtt_client_publish_packet_chain_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT Publish Packet Chain Test............................N/A\n");

    test_control_return(3);  
}
#endif
