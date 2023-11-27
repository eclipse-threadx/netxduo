/* MQTT connect test.  This test case validates MQTT client connect without username/password. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_mqtt_client.h"
extern void    test_control_return(UINT status);
#define     DEMO_STACK_SIZE    2048

#define CLIENT_ID "1234"
#define TOPIC1    "topic1"
#define MESSAGE1  "message1"

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
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);



/* Define what the initial system looks like.  */
static NXD_MQTT_CLIENT *client_ptr;
static UCHAR *client_memory;
static CHAR *stack_ptr;
#define CLIENT_MEMORY_SIZE 1024
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void       netx_mqtt_client_publish_QoS2_application_define(void *first_unused_memory)
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

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

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

    client_memory = pointer;
    pointer += CLIENT_MEMORY_SIZE;

    client_ptr = (NXD_MQTT_CLIENT*)pointer;
}


#define MQTT_CLIENT_THREAD_PRIORITY  2
static UINT keepalive_value;
static UINT cleansession_value;
static UINT QoS;
static UINT retain;
/* Define the test threads.  */
/* This thread sets up MQTT client and makes a connect request without username/password. */
static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NXD_ADDRESS server_address;

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT Publish QoS 2 Test ..................................");

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
    tx_thread_sleep(1);

    server_address.nxd_ip_version = 4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    keepalive_value = 0;
    cleansession_value = 0;
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT, 
                                     keepalive_value, cleansession_value, 5);
#ifndef NXD_MQTT_REQUIRE_TLS
    if(status)
        error_counter++;

    QoS = 2;
    retain = 0;
    /* Issue a subscribe command. */
    status = nxd_mqtt_client_publish(client_ptr, TOPIC1, strlen(TOPIC1), MESSAGE1, strlen(MESSAGE1), retain, QoS, 2);
    if(status)
        error_counter++;

    tx_thread_sleep(10);
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


static UCHAR content[100];

/* This thread acts as MQTT server, accepting the connection. */
static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
NX_PACKET  *packet_ptr;
UCHAR      *byte;
USHORT      packet_id;
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
    if(status)
        error_counter++;

    tx_thread_sleep(1);
    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Response with Connect SUCCESS */
    byte = packet_ptr -> nx_packet_prepend_ptr ;
    byte[0] = 0x20;
    byte[1] = 0x02;
    byte[2] = 0;
    byte[3] = 0;

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + 4;
    packet_ptr -> nx_packet_length = 4;
    
    status = nx_tcp_socket_send(&server_socket, packet_ptr, 1);
    if(status)
        error_counter++;

    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5);
    if(status)
        error_counter++;

    /* construct the publish message. */
    byte = content;
    *byte++ = 0x30 | ((*(packet_ptr -> nx_packet_prepend_ptr) & 0x0F)); /* Publish */
    byte++; /* Skip the length field. */
    *byte++ = (strlen(TOPIC1) >> 8) & 0xFF;
    *byte++ = strlen(TOPIC1) & 0xFF;
    /* Fill in the topic string. */
    memcpy(byte, TOPIC1, strlen(TOPIC1));
    byte += strlen(TOPIC1);
    if(((content[0] & 6) >> 1) != 0)
    {
        packet_id = packet_ptr -> nx_packet_prepend_ptr[byte - content];/* Fill in packet ID MSB. */
        packet_id = (packet_id << 8) | packet_ptr -> nx_packet_prepend_ptr[byte - content + 1];/* Fill in packet ID MSB. */
       *byte++ += ((packet_id >> 8) & 0xFF );
       *byte++ += (packet_id & 0xFF);
    }
    /* Fill in the message being pulished. */
    memcpy(byte, MESSAGE1, strlen(MESSAGE1));
    byte += strlen(MESSAGE1);

    /* Fill in the QoS and Retain information. */
    content[0] = content[0] & 0xF8;
    content[0] = content[0] | (QoS << 1);
    if(retain)
        content[0] = content[0] | 1;
    

    /* Now validate message length */
    if(packet_ptr -> nx_packet_length != (byte - content))
        error_counter++;

    /* Fill in the remaining length field. */
    content[1] = (packet_ptr -> nx_packet_length - 2) & 0xFF;

    /* Validate the MQTT pubish request. */
    if(memcmp(packet_ptr -> nx_packet_prepend_ptr, content, packet_ptr -> nx_packet_length))
        error_counter++;
    
    if(((content[0] & 0x6) >> 1) == 1)
    {
        /* QoS 1: Respond with PUBACK */
        byte = packet_ptr -> nx_packet_prepend_ptr ;
        byte[0] = 0x40;
        byte[1] = 0x02;
        byte[2] = (packet_id >> 8) & 0xFF;
        byte[3] = packet_id  & 0xFF;
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + 4;
        packet_ptr -> nx_packet_length = 4;
    }
    if(((content[0] & 0x6) >> 1) == 2)
    {
        byte = packet_ptr -> nx_packet_prepend_ptr ;
        byte[0] = 0x50;
        byte[1] = 0x02;
        byte[2] = (packet_id >> 8) & 0xFF;
        byte[3] = packet_id  & 0xFF;
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + 4;
        packet_ptr -> nx_packet_length = 4;
    }
    if(((content[0] & 0x6) >> 1) != 0)
    {
        status = nx_tcp_socket_send(&server_socket, packet_ptr, 1);
        if(status)
            error_counter++;
    }

    /* Now expect PUBREL */
    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 10);
    if(status)
        error_counter++;

    byte = packet_ptr -> nx_packet_prepend_ptr;
    if((byte[0] != 0x60) || (byte[1] != 2) || (byte[2] != ((packet_id >> 8) & 0xFF)) || (byte[3] != (packet_id & 0xFF)))
        error_counter++;

    /* Response with PUBCOMP*/
    byte[0] = 0x70;

   
    status = nx_tcp_socket_send(&server_socket, packet_ptr, 1);
    if (status)
        error_counter++;
    /* Disconnect.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

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

