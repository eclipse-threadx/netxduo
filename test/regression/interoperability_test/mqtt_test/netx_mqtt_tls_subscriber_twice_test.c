#include "mqtt_interoperability_test.h"
#include "ca.c"

#ifndef NX_SECURE_ENABLE
INT mqtt_subscriber_entry(TLS_TEST_INSTANCE* instance_ptr)
{
    print_error_message( "NX_SEUCRE_ENABLE is not defined.\n");
    return 0;
}
#else /* ifdef NX_SECURE_ENABLE */

#include "nxd_mqtt_client.h"

/* Define the ThreadX and NetX object control blocks...  */

NX_PACKET_POOL    pool_0;
NX_IP             ip_0;  

NX_TCP_SOCKET tcp_socket;

#define REMOTE_SERVER_PORT          4433
#define LOCAL_CLIENT_PORT           30024

/* Define the IP thread's stack area.  */
ULONG             ip_thread_stack[3 * 1024 / sizeof(ULONG)];

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 64)
ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

/* Define the ARP cache area.  */
ULONG             arp_space_area[512 / sizeof(ULONG)];

/* Define the demo thread.  */
ULONG             demo_thread_stack[6 * 1024 / sizeof(ULONG)];
TX_THREAD         demo_thread;

/* Define the pcap driver function. */
VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* Define a global variable for the pointer of current test instance. */
TLS_TEST_INSTANCE* client_instance_ptr;
void client_thread_entry(ULONG thread_input);

#ifdef DEBUG_NX_SECURE
INT main()
{
    tx_kernel_enter();
}
#else
/* Declare semaphores. */
extern TLS_TEST_SEMAPHORE* semaphore_mqtt_server_prepared;
extern TLS_TEST_SEMAPHORE* semaphore_mqtt_topic_subscribed;
extern TLS_TEST_SEMAPHORE* semaphore_mqtt_message_published;
extern TLS_TEST_SEMAPHORE* semaphore_mqtt_test_finished;

INT mqtt_subscriber_entry(TLS_TEST_INSTANCE* instance_ptr)
{
    client_instance_ptr = instance_ptr;
    tx_kernel_enter();
}
#endif

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    tx_application_define(void *first_unused_memory)
#endif
{
UINT  status;

    /* Initialize the NetX system.  */
    nx_system_initialize();
    
    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, 
                          "NetX IP Instance 0", 
                          TLS_TEST_IP_ADDRESS_NUMBER,                           
                          0xFFFFFF00UL, 
                          &pool_0,
                          _nx_pcap_network_driver,
                          (UCHAR*)ip_thread_stack,
                          sizeof(ip_thread_stack),
                          1);
    show_error_message_if_fail(NX_SUCCESS == status);
    
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *)arp_space_area, sizeof(arp_space_area));
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    status =  nx_ip_fragment_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);
    tx_thread_create(&demo_thread, "demo thread", client_thread_entry, 0,
            demo_thread_stack, sizeof(demo_thread_stack),
            16, 16, 4, TX_AUTO_START);
}

/* Declare the MQTT client control block. */
static NXD_MQTT_CLIENT              mqtt_client;
#define  CLIENT_ID_STRING           "mytestclient"
#define  MQTT_CLIENT_STACK_SIZE     4096

/* Define the priority of the MQTT internal thread. */
#define MQTT_THREAD_PRIORTY         2

/* Declare a 2000-byte memory space the application supplies to the MQTT client instance. */
static ULONG                        client_memory[2000 / sizeof(ULONG)];

/* Declare the MQTT thread stack space. */
static ULONG                        mqtt_client_stack[MQTT_CLIENT_STACK_SIZE / sizeof(ULONG)];

/* Define the MQTT keep alive timer for 5 minutes */
#define MQTT_KEEP_ALIVE_TIMER       300

/* Define the subscribed topic. */
#define TOPIC_NAME                  "test"

#define QOS0                        0
#define QOS1                        1

/* Declare external cryptosuites. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

/* Define crypto metadata buffer. */
static UCHAR metadata_buffer[5*4096];

/* Declare buffers to hold message and topic. */
static UCHAR message_buffer[NXD_MQTT_MAX_MESSAGE_LENGTH];
static UCHAR topic_buffer[NXD_MQTT_MAX_TOPIC_NAME_LENGTH];

/* For remote certificate. */
NX_SECURE_X509_CERT remote_certificate, remote_issuer, ca_certificate;
UCHAR remote_cert_buffer[2000];
UCHAR remote_issuer_buffer[2000];
static UCHAR tls_packet_buffer[4096];
static UINT error_counter;

/* Define the callback function for tls connection. */
UINT tls_setup_method(NXD_MQTT_CLIENT* client_ptr, NX_SECURE_TLS_SESSION* tls_session,
        NX_SECURE_X509_CERT* certificate, NX_SECURE_X509_CERT* trusted_certificate)
{
    
    /* Create a tls session. */
    if (nx_secure_tls_session_create(tls_session,
                                     &nx_crypto_tls_ciphers,
                                     metadata_buffer,
                                     sizeof(metadata_buffer)))
    {
        error_counter++;
        return 1;
    }
    
    nx_secure_tls_session_packet_buffer_set(tls_session, tls_packet_buffer, sizeof(tls_packet_buffer));
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));

    nx_secure_x509_certificate_initialize(&ca_certificate, ca_der, ca_der_len,
                                          NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(tls_session, &ca_certificate);

    return(NX_SUCCESS);
}

void client_thread_entry(ULONG thread_input)
{
UINT        status, topic_length, message_length;
NXD_ADDRESS server_ip;
INT         test_result = 0;
UINT        i;
    
    /* Address of remote server. */
    print_error_message( "remote ip address number %lu, remote ip address string %s.\n", REMOTE_IP_ADDRESS_NUMBER, REMOTE_IP_ADDRESS_STRING);
    
    /* Create MQTT client instance. */
    status = nxd_mqtt_client_create(&mqtt_client, "my_client", CLIENT_ID_STRING, strlen(CLIENT_ID_STRING),
                                    &ip_0, &pool_0, (VOID*)mqtt_client_stack, sizeof(mqtt_client_stack), 
                                    MQTT_THREAD_PRIORTY,
                                    (UCHAR*)client_memory, sizeof(client_memory));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

#ifndef DEBUG_NX_SECURE
    /* Wait for the mqtt server. */
    tls_test_semaphore_wait(semaphore_mqtt_server_prepared);
    print_error_message( "subscriber get semaphore_server_prepared.\n");
#endif

    error_counter = 0;
    for (i = 0; i < 4; i++)
    {

        if (i == 0)
        {

            /* Start the connection to the server. */
            server_ip.nxd_ip_version = 4;
            server_ip.nxd_ip_address.v4 = 0x7F000001;

            /* Connect mqtt server with tls to port not bound. */
            status = nxd_mqtt_client_secure_connect(&mqtt_client, &server_ip, 443, 
                                                    tls_setup_method,
                                                    MQTT_KEEP_ALIVE_TIMER, 1, NX_WAIT_FOREVER);
            exit_if_fail(NX_SUCCESS != status, TLS_TEST_UNKNOWN_TYPE_ERROR);
            continue;
        }
        else
        {

            /* Start the connection to the server. */
            server_ip.nxd_ip_version = 4;
            server_ip.nxd_ip_address.v4 = REMOTE_IP_ADDRESS_NUMBER;

            /* Connect mqtt server with tls. */
            status = nxd_mqtt_client_secure_connect(&mqtt_client, &server_ip, MQTT_PORT, 
                                                    tls_setup_method,
                                                    MQTT_KEEP_ALIVE_TIMER, 1, NX_WAIT_FOREVER);
            exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
        }
        
        /* Subscribe to the topic with QoS level 0. */
        status = nxd_mqtt_client_subscribe(&mqtt_client, TOPIC_NAME, strlen(TOPIC_NAME), QOS0);
        add_error_counter_if_fail(NX_SUCCESS == status, test_result);

#ifndef DEBUG_NX_SECURE
        /* Post the semaphore to indicate that the given topic is subscribed. */
        tls_test_semaphore_post(semaphore_mqtt_topic_subscribed);
        
        /* Wait for the publisher. */
        tls_test_semaphore_wait(semaphore_mqtt_message_published);
#endif
        status = nxd_mqtt_client_message_get(&mqtt_client, topic_buffer, sizeof(topic_buffer), &topic_length, 
                                             message_buffer, sizeof(message_buffer), &message_length);
        add_error_counter_if_fail(NX_SUCCESS == status, test_result);

        /* Verify test result. */
        if(status == NXD_MQTT_SUCCESS)
        {
            add_error_counter_if_fail( 5 == message_length, test_result);
            add_error_counter_if_fail( 'h' == message_buffer[0], test_result);
            add_error_counter_if_fail( 'e' == message_buffer[1], test_result);
            add_error_counter_if_fail( 'l' == message_buffer[2], test_result);
            add_error_counter_if_fail( 'l' == message_buffer[3], test_result);
            add_error_counter_if_fail( 'o' == message_buffer[4], test_result);
        }
        
        /* Now unsubscribe the topic. */
        status = nxd_mqtt_client_unsubscribe(&mqtt_client, TOPIC_NAME, strlen(TOPIC_NAME));
        add_error_counter_if_fail(NX_SUCCESS == status, test_result);

        /* Disconnect from the broker. */
        status = nxd_mqtt_client_disconnect(&mqtt_client);
        add_error_counter_if_fail(NX_SUCCESS == status, test_result);

        add_error_counter_if_fail(error_counter == 0, test_result);
    }

    /* Delete the client instance, release all the resources. */
    status = nxd_mqtt_client_delete(&mqtt_client);
    add_error_counter_if_fail(NX_SUCCESS == status, test_result);
    
#ifndef DEBUG_NX_SECURE
    /* Post the semaphore to indicate that the test is finished. */
    status = tls_test_semaphore_post(semaphore_mqtt_test_finished);
    add_error_counter_if_fail(NX_SUCCESS == status, test_result);
#endif

    exit(test_result);
}
#endif /* ifndef NX_SECURE_ENABLE */
