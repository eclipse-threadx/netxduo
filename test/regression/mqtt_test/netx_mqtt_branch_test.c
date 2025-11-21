/* MQTT connect test.  This test case validates MQTT client connect without username/password. */

#include   "tx_api.h"
#include   "tx_mutex.h"
#include   "tx_thread.h"
#include   "tx_timer.h"
#include   "tx_event_flags.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nxd_mqtt_client.h"
extern void    test_control_return(UINT status);
#define     DEMO_STACK_SIZE    2048

#define CLIENT_ID "1234"
#define TOPIC1    "topic1"
#define MESSAGE1  "message1"

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_2;


#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

#ifdef NX_SECURE_ENABLE

#include "../web_test/test_device_cert.c"
#include "../web_test/test_ca_cert.c"

/* Declare external cryptosuites. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

static NX_SECURE_TLS_SESSION tls_server_session;
static NX_SECURE_X509_CERT server_local_certificate;

/* Define crypto metadata buffer. */
static UCHAR client_metadata[5*4096];
static UCHAR server_metadata[5*4096];

/* For remote certificate. */
static NX_SECURE_X509_CERT remote_certificate, remote_issuer, ca_certificate;
static UCHAR remote_cert_buffer[2000];
static UCHAR remote_issuer_buffer[2000];
static UCHAR tls_packet_buffer[2][4096];

#define TEST_LOOP 2
#else
#define TEST_LOOP 1
#endif


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

extern void SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number);

/* Define what the initial system looks like.  */
static NXD_MQTT_CLIENT *client_ptr;
static NXD_MQTT_CLIENT *client_ptr_test;
static UCHAR *client_memory;
static UCHAR *client_memory_test;
static CHAR *stack_ptr;
static CHAR *stack_ptr_test;
static UCHAR filler_data[PACKET_SIZE] = { 0 };
#define CLIENT_MEMORY_SIZE 1024
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void       netx_mqtt_client_branch_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    status = tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);            

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pointer, PACKET_POOL_SIZE);
    pointer = pointer + PACKET_POOL_SIZE;

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create a packet pool for test create.  */
    status = nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", PACKET_SIZE, pointer, PACKET_POOL_SIZE);
    pointer = pointer + PACKET_POOL_SIZE;

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        /* Create an IP instance for test create.  */
    status = nx_ip_create(&ip_2, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 3), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Check ARP enable status.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    // status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    stack_ptr = pointer;
    pointer += DEMO_STACK_SIZE;

    client_memory = pointer;
    pointer += CLIENT_MEMORY_SIZE;

    client_ptr = (NXD_MQTT_CLIENT*)pointer;

    /* Make room for create test client memory and control block. */
    pointer += sizeof(NXD_MQTT_CLIENT);

    stack_ptr_test = pointer;
    pointer += DEMO_STACK_SIZE;

    client_memory_test = pointer;
    pointer += CLIENT_MEMORY_SIZE;

    client_ptr_test = (NXD_MQTT_CLIENT*)pointer;
}

#ifdef NX_SECURE_ENABLE

/* Define the callback function for tls connection. */
static UINT client_tls_setup(NXD_MQTT_CLIENT* client_ptr, NX_SECURE_TLS_SESSION* tls_session,
                             NX_SECURE_X509_CERT* certificate, NX_SECURE_X509_CERT* trusted_certificate)
{
UINT status;

    /* Create a tls session. */
    status = nx_secure_tls_session_create(tls_session,
                                          &nx_crypto_tls_ciphers,
                                          client_metadata,
                                          sizeof(client_metadata));

    if (status)
    {
        return status;
    }
    
    nx_secure_tls_session_packet_buffer_set(tls_session, tls_packet_buffer[0], sizeof(tls_packet_buffer[0]));
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));

    nx_secure_x509_certificate_initialize(&ca_certificate, test_ca_cert_der, test_ca_cert_der_len,
                                          NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(tls_session, &ca_certificate);

    return(NX_SUCCESS);
}

static UINT server_tls_setup(NX_SECURE_TLS_SESSION *tls_session)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session,
                                          &nx_crypto_tls_ciphers,
                                          server_metadata,
                                          sizeof(server_metadata));
    if (status)
    {
        return status;
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    nx_secure_x509_certificate_initialize(&server_local_certificate,
                                          test_device_cert_der, test_device_cert_der_len,
                                          NX_NULL, 0, test_device_cert_key_der,
                                          test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);

    nx_secure_tls_local_certificate_add(tls_session, &server_local_certificate);

    nx_secure_tls_session_packet_buffer_set(tls_session, tls_packet_buffer[1], sizeof(tls_packet_buffer[1]));

    return(NX_SUCCESS);
}
#endif

#define MQTT_CLIENT_THREAD_PRIORITY  2
static UINT keepalive_value;
static UINT cleansession_value;
static UINT QoS;
/* Define the test threads.  */
/* This thread sets up MQTT client and performs multiple branch tests on different APIs. */
static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NXD_ADDRESS server_address;
UINT        i;

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT Branch Test ......................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NXD_MQTT_CLOUD_ENABLE    
    /* Test create internal mutex already created. */
    TX_MUTEX* old_mutex_create_ptr = _tx_mutex_created_ptr;
    _tx_mutex_created_ptr = &(client_ptr_test -> nxd_mqtt_protection);
    status = nxd_mqtt_client_create(client_ptr_test, "my client", CLIENT_ID, strlen(CLIENT_ID), &ip_2, &pool_1,
                                    stack_ptr_test, DEMO_STACK_SIZE, MQTT_CLIENT_THREAD_PRIORITY, client_memory_test, CLIENT_MEMORY_SIZE);
    if(status != NXD_MQTT_INTERNAL_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    _tx_mutex_created_ptr = old_mutex_create_ptr;    
    
    /* Test create internal thread already created. */
    TX_THREAD* old_thread_create_ptr = _tx_thread_created_ptr;
    _tx_thread_created_ptr = &(client_ptr_test -> nxd_mqtt_thread);
    status = nxd_mqtt_client_create(client_ptr_test, "my client", CLIENT_ID, strlen(CLIENT_ID), &ip_2, &pool_1,
                                    stack_ptr_test, DEMO_STACK_SIZE, MQTT_CLIENT_THREAD_PRIORITY, client_memory_test, CLIENT_MEMORY_SIZE);
    if(status != NXD_MQTT_INTERNAL_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    _tx_thread_created_ptr = old_thread_create_ptr;    
    

    /* Test create internal event flags already created. */
    TX_EVENT_FLAGS_GROUP* old_event_flags_create_ptr = _tx_event_flags_created_ptr;
    _tx_event_flags_created_ptr = &(client_ptr_test -> nxd_mqtt_events);
    status = nxd_mqtt_client_create(client_ptr_test, "my client", CLIENT_ID, strlen(CLIENT_ID), &ip_2, &pool_1,
                                    stack_ptr_test, DEMO_STACK_SIZE, MQTT_CLIENT_THREAD_PRIORITY, client_memory_test, CLIENT_MEMORY_SIZE);
    if(status != NXD_MQTT_INTERNAL_ERROR)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    _tx_event_flags_created_ptr = old_event_flags_create_ptr;    
#endif

    /* Create client for following tests. */
    status = nxd_mqtt_client_create(client_ptr, "my client", CLIENT_ID, strlen(CLIENT_ID), &ip_0, &pool_0,
                                    stack_ptr, DEMO_STACK_SIZE, MQTT_CLIENT_THREAD_PRIORITY, client_memory, CLIENT_MEMORY_SIZE);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Set client state to connected. */
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_CONNECTED;

    tx_thread_sleep(1);

    server_address.nxd_ip_version = 4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    keepalive_value = 0;
    cleansession_value = 0;

    QoS = 1;
    
    /* Test invalid mutex ptr on login_set. */
    client_ptr -> nxd_mqtt_client_mutex_ptr -> tx_mutex_id = 0;
    status = nxd_mqtt_client_login_set(client_ptr, "test_user", 10, "test_pass", 10);
    if(status != NXD_MQTT_MUTEX_FAILURE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    client_ptr -> nxd_mqtt_client_mutex_ptr->tx_mutex_id = TX_MUTEX_ID;

    /* Test invalid mutex ptr on sub_unsub. */
    client_ptr -> nxd_mqtt_client_mutex_ptr -> tx_mutex_id = 0;
    status = nxd_mqtt_client_subscribe(client_ptr, "topic", 6, 0);
    if(status != NXD_MQTT_MUTEX_FAILURE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    client_ptr -> nxd_mqtt_client_mutex_ptr->tx_mutex_id = TX_MUTEX_ID;

    /* Validate sub_unsub packet_allocate behavior. */
    ULONG temp_payload_size = client_ptr -> nxd_mqtt_client_packet_pool_ptr -> nx_packet_pool_payload_size;
    client_ptr -> nxd_mqtt_client_packet_pool_ptr -> nx_packet_pool_payload_size = 0;
    status = nxd_mqtt_client_subscribe(client_ptr, "topic", 6, 0);
    if(status != NXD_MQTT_PACKET_POOL_FAILURE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    client_ptr -> nxd_mqtt_client_packet_pool_ptr -> nx_packet_pool_payload_size = temp_payload_size;

    /* Validate client_connect tx_mutex_get behavior. */
    client_ptr -> nxd_mqtt_client_mutex_ptr -> tx_mutex_id = 0;
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT, keepalive_value, 
                                     cleansession_value, NX_IP_PERIODIC_RATE);
    if(status != NXD_MQTT_MUTEX_FAILURE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    client_ptr -> nxd_mqtt_client_mutex_ptr->tx_mutex_id = TX_MUTEX_ID;

    /* Validate client_connect client already connected behavior. */
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT, keepalive_value, 
                                     cleansession_value, NX_IP_PERIODIC_RATE);
    if(status != NXD_MQTT_ALREADY_CONNECTED)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    // /* Validate client_connect client connecting behavior. */
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_CONNECTING;
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT, keepalive_value, 
                                     cleansession_value, NX_IP_PERIODIC_RATE);
    if(status != NXD_MQTT_CONNECTING)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    // /* Validate client_connect client not idle behavior. */
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_INITIALIZE;
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT, keepalive_value, 
                                     cleansession_value, NX_IP_PERIODIC_RATE);
    if(status != NXD_MQTT_INVALID_STATE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    // /* Set client state to idle for remaining connect tests. */
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_IDLE;

    /* Validate socket_connect NX_IN_PROGRESS */
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT, keepalive_value, 
                                     cleansession_value, NX_IP_PERIODIC_RATE);
    if(status != NXD_MQTT_CONNECT_FAILURE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    // /* Validate socket_connect NOT NX_SUCCESS */
    UINT old_tcp_socket_state = client_ptr -> nxd_mqtt_client_socket . nx_tcp_socket_state;
    client_ptr -> nxd_mqtt_client_socket . nx_tcp_socket_state = NX_TCP_SYN_SENT;
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT, keepalive_value, 
                                     cleansession_value, NX_IP_PERIODIC_RATE);
    if(status != NXD_MQTT_CONNECT_FAILURE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    // /* Validate wait option == 0 behavior and tcp_client_socket_connect not NX_SUCCUSS && not NX_IN_PROGRESS. */
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT, keepalive_value, 
                                     cleansession_value, 0);
    if(status != NXD_MQTT_CONNECT_FAILURE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Reset tcp socket state for remaining tests. */
    client_ptr -> nxd_mqtt_client_socket . nx_tcp_socket_state = old_tcp_socket_state;

    /* Validate wait option == 0 NX_IN_PROGRESS behavior. */
#ifdef NX_SECURE_ENABLE
    client_ptr -> nxd_mqtt_client_use_tls = 1;
#endif
    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT, keepalive_value, 
                                     cleansession_value, 0);
    if(status != NX_IN_PROGRESS)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

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

 