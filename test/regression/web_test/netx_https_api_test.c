#include <stdio.h>
#include "tx_api.h"
#include "nx_api.h"
#include "fx_api.h"
#include "nx_ip.h"

#ifdef NX_WEB_HTTPS_ENABLE
#include "nx_secure_tls.h"
#endif

#include "nx_web_http_client.h"
#include "nx_web_http_server.h"

#define TEST(prefix, name)  void prefix ## _ ##name()
#define EXPECT_EQ(expected, actual) \
    if(expected != actual)          \
    {                               \
        printf("\nERROR! File: %s Line: %d\n", __FILE__, __LINE__); \
        printf("Expected: 0x%x, (%d) Got: 0x%x (%d)\n", (int)expected, (int)expected, (int)actual, (int)actual); \
        error_counter++; \
    }

#define EXPECT_TRUE(statement) \
    if(!statement)          \
    {                               \
        printf("\nERROR! File: %s Line: %d\n", __FILE__, __LINE__); \
        printf("Expected statement to be true!\n"); \
        error_counter++; \
    }


//typedef void VOID;

extern void    test_control_return(UINT status);

UINT nx_web_http_client_create_test(void);
UINT nx_web_http_client_delete_test(void);
UINT nx_web_http_client_get_start_test(void);
UINT nx_web_http_client_put_start_test(void);
UINT nx_web_http_client_post_start_test(void);
UINT nx_web_http_client_head_start_test(void);
UINT nx_web_http_client_delete_start_test(void);
#ifdef NX_WEB_HTTPS_ENABLE
UINT nx_web_http_client_get_secure_start_test(void);
UINT nx_web_http_client_put_secure_start_test(void);
UINT nx_web_http_client_post_secure_start_test(void);
UINT nx_web_http_client_head_secure_start_test(void);
UINT nx_web_http_client_delete_secure_start_test(void);
#endif
UINT nx_web_http_client_response_body_get_test(void);
UINT nx_web_http_client_put_packet_test(void);
UINT nx_web_http_client_response_header_callback_set_test(void);
UINT nx_web_http_client_request_initialize_test(void);
UINT nx_web_http_client_request_send_test(void);
UINT nx_web_http_client_request_header_add_test(void);
UINT nx_web_http_client_connect_test(void);
#ifdef NX_WEB_HTTPS_ENABLE
UINT nx_web_http_client_secure_connect_test(void);
#endif
UINT nx_web_http_server_callback_data_send_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_callback_response_send_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_content_get_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_create_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_delete_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_param_get_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_query_get_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_start_test(VOID *stack_memory, UINT stack_size);
#ifdef NX_WEB_HTTPS_ENABLE
UINT nx_web_http_server_secure_configure_test(VOID *stack_memory, UINT stack_size);
#endif
UINT nx_web_http_server_stop_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_content_get_extended_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_content_length_get_test(VOID *stack_memory, UINT stack_size);
#ifdef  NX_WEB_HTTP_MULTIPART_ENABLE
UINT nx_web_http_server_get_entity_header_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_get_entity_content_test(VOID *stack_memory, UINT stack_size);
#endif
UINT nx_web_http_server_callback_generate_response_header_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_callback_packet_send_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_gmt_callback_set_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_cache_info_callback_set_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_mime_maps_additional_set_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_type_get_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_packet_content_find_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_packet_get_test(VOID *stack_memory, UINT stack_size);
UINT nx_web_http_server_invalid_userpassword_notify_set_test(VOID *stack_memory, UINT stack_size);

#define DEMO_STACK_SIZE         4096
#define TEST_WINDOW_SIZE 2000
static UCHAR stack_memory[4096];

static UCHAR ip_data[4096];
static UCHAR pool_data[4096];

#define         SERVER_PACKET_SIZE  (NX_WEB_HTTP_SERVER_MIN_PACKET_SIZE * 2)

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)

static TX_THREAD        test_thread;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

void test_thread_entry(ULONG thread_input);

/* Define device drivers.  */
extern void _fx_ram_driver(FX_MEDIA *media_ptr);
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);



#ifdef CTEST
void    test_application_define(void* first_unused_memory)
#else /* CTEST */
void    netx_https_api_test(void* first_unused_memory)
#endif /* CTEST */
{
UINT status;
UINT error_counter = 0;
CHAR *pointer;

    printf("NetX Test:   HTTPS API Test............................................");

    /* Initialize the NetX system.  */
    nx_system_initialize();


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the test thread. */
    status = tx_thread_create(&test_thread, "HTTPS API Test Thread", test_thread_entry, 0,
                              pointer, DEMO_STACK_SIZE,
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "HTTP Server Packet Pool", SERVER_PACKET_SIZE,
                                    pointer, SERVER_PACKET_SIZE*8);
    pointer = pointer + SERVER_PACKET_SIZE * 8;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "HTTP Client IP", HTTP_SERVER_ADDRESS,
                          0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1024,
                          pointer, 4096, 1);
    pointer =  pointer + 4096;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&ip_0);
    if (status)
        error_counter++;


}

void test_thread_entry(ULONG thread_input)
{
UINT status;
UINT error_counter = 0;

    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);


    status = nx_web_http_client_create_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_delete_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_get_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_put_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_post_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_head_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_delete_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

#ifdef NX_WEB_HTTPS_ENABLE
    status = nx_web_http_client_get_secure_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_put_secure_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_post_secure_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_head_secure_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_delete_secure_start_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }
#endif

    status = nx_web_http_client_response_body_get_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_put_packet_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_response_header_callback_set_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_request_initialize_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_request_send_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_request_header_add_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_client_connect_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }
#ifdef NX_WEB_HTTPS_ENABLE
    status = nx_web_http_client_secure_connect_test();
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }
#endif


    status = nx_web_http_server_callback_data_send_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_callback_response_send_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_content_get_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_create_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_delete_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_param_get_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_query_get_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_start_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

#ifdef NX_WEB_HTTPS_ENABLE
    status = nx_web_http_server_secure_configure_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }
#endif

    status = nx_web_http_server_stop_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_content_get_extended_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_content_length_get_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

#ifdef  NX_WEB_HTTP_MULTIPART_ENABLE
    status = nx_web_http_server_get_entity_header_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_get_entity_content_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }
#endif

    status = nx_web_http_server_callback_generate_response_header_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_callback_packet_send_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_gmt_callback_set_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_cache_info_callback_set_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_mime_maps_additional_set_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_type_get_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_packet_content_find_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_packet_get_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_web_http_server_invalid_userpassword_notify_set_test(stack_memory, sizeof(stack_memory));
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    nx_ip_delete(&ip_0);
    nx_packet_pool_delete(&pool_0);
    tx_thread_delete(&test_thread);

    if(error_counter > 0)
    {
        printf("FAILURE!!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}

/************************ Utility functions. **************************/
#ifdef NX_WEB_HTTPS_ENABLE
/* Define the TLS setup callback function.  */
static UINT tls_callback(NX_WEB_HTTP_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls_session)
{

    return(NX_SUCCESS);
}
#endif /* NX_WEB_HTTPS_ENABLE  */


UINT server_auth_check(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, CHAR *resource, CHAR **name, CHAR **password, CHAR **realm)
{
    return(NX_SUCCESS);
}

UINT server_req_notify(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, CHAR *resource, NX_PACKET *packet_ptr)
{
    return(NX_SUCCESS);
}


/************************ Begin test cases. **************************/

UINT nx_web_http_client_create_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
UINT status;
UINT error_counter = 0;

    /* Setup the IP instance so tests will pass. */
    ip_0.nx_ip_id = NX_IP_ID;

    memset(&http_client, 0, sizeof(NX_WEB_HTTP_CLIENT));
    status = nx_web_http_client_create(NX_NULL, "Name", &ip_0, &pool_0, TEST_WINDOW_SIZE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    memset(&http_client, 0, sizeof(NX_WEB_HTTP_CLIENT));
    status = nx_web_http_client_create(&http_client, "Name", NX_NULL, &pool_0, TEST_WINDOW_SIZE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    memset(&http_client, 0, sizeof(NX_WEB_HTTP_CLIENT));
    status = nx_web_http_client_create(&http_client, "Name", &ip_0, NX_NULL, TEST_WINDOW_SIZE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Name can be NULL. */
    memset(&http_client, 0, sizeof(NX_WEB_HTTP_CLIENT));
    status = nx_web_http_client_create(&http_client, NX_NULL, &ip_0, &pool_0, TEST_WINDOW_SIZE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Proper usage test for cases below. */
    status = nx_web_http_client_delete(&http_client);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_web_http_client_create(&http_client, "Name", &ip_0, &pool_0, TEST_WINDOW_SIZE);
    EXPECT_EQ(NX_SUCCESS, status);

    EXPECT_EQ(http_client.nx_web_http_client_ip_ptr,  &ip_0);

    EXPECT_EQ(http_client.nx_web_http_client_packet_pool_ptr, &pool_0);

    EXPECT_EQ(http_client.nx_web_http_client_state,   NX_WEB_HTTP_CLIENT_STATE_READY);

    EXPECT_EQ(http_client.nx_web_http_client_method, NX_WEB_HTTP_METHOD_NONE);

    EXPECT_EQ(http_client.nx_web_http_client_id, NX_WEB_HTTP_CLIENT_ID);
    status = nx_web_http_client_delete(&http_client);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_delete_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
UINT status;
UINT error_counter = 0;

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_delete",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_delete(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_delete(&http_client);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}


UINT nx_web_http_client_get_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    /*NX_WEB_HTTP_CLIENT *client_ptr, NXD_ADDRESS *ip_address, UINT server_port,
                                     CHAR *resource, CHAR *username, CHAR *password,
                                     ULONG wait_option)*/
    http_client.nx_web_http_client_id = NX_WEB_HTTP_CLIENT_ID;

    status = nx_web_http_client_get_start(NX_NULL, &ip_addr, 0, resource, "www.abc.com", NX_NULL, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_get_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_get_start(&http_client, NX_NULL, 0, resource, "www.abc.com", NX_NULL, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_get_start(&http_client, &ip_addr, 0, NX_NULL, "www.abc.com", NX_NULL, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    http_client.nx_web_http_client_id = 0;
    status = nx_web_http_client_get_start(&http_client, &ip_addr, 0, resource, "www.abc.com", NX_NULL, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}


UINT nx_web_http_client_put_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    /* Control block not initialized. */
    status = nx_web_http_client_put_start(&http_client, &ip_addr, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_put_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_put_start(NX_NULL, &ip_addr, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_put_start(&http_client, NX_NULL, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_put_start(&http_client, &ip_addr, NX_WEB_HTTP_SERVER_PORT, NX_NULL, "www.abc.com", "name", "password", 100, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_post_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_post_start(&http_client, &ip_addr, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_post_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_post_start(NX_NULL, &ip_addr, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_post_start(&http_client, NX_NULL, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_post_start(&http_client, &ip_addr, NX_WEB_HTTP_SERVER_PORT, NX_NULL, "www.abc.com", "name", "password", 100, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_head_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_head_start(&http_client, &ip_addr, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_head_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_head_start(NX_NULL, &ip_addr, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_head_start(&http_client, NX_NULL, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_head_start(&http_client, &ip_addr, NX_WEB_HTTP_SERVER_PORT, NX_NULL, "www.abc.com", "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_delete_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_delete_start(&http_client, &ip_addr, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_delete_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_delete_start(NX_NULL, &ip_addr, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_delete_start(&http_client, NX_NULL, NX_WEB_HTTP_SERVER_PORT, resource, "www.abc.com", "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_delete_start(&http_client, &ip_addr, NX_WEB_HTTP_SERVER_PORT, NX_NULL, "www.abc.com", "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);
    
    status = nx_web_http_client_delete(&http_client);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

#ifdef NX_WEB_HTTPS_ENABLE
UINT nx_web_http_client_get_secure_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_get_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_get_secure_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_get_secure_start(NX_NULL, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_get_secure_start(&http_client, NX_NULL, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_get_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, NX_NULL, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_get_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);
    
    status = nx_web_http_client_delete(&http_client);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_put_secure_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_put_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_put_secure_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_put_secure_start(NX_NULL, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_put_secure_start(&http_client, NX_NULL, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_put_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, NX_NULL, "www.abc.com", "name", "password", 100, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_put_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_post_secure_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_post_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_post_secure_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_post_secure_start(NX_NULL, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_post_secure_start(&http_client, NX_NULL, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_post_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, NX_NULL, "www.abc.com", "name", "password", 100, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_post_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", 100, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_head_secure_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_head_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_head_secure_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_head_secure_start(NX_NULL, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_head_secure_start(&http_client, NX_NULL, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_head_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, NX_NULL, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_head_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_delete_secure_start_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NXD_ADDRESS ip_addr;
CHAR *resource = "test";
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_delete_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_delete_secure_start",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_delete_secure_start(NX_NULL, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_delete_secure_start(&http_client, NX_NULL, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_delete_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, NX_NULL, "www.abc.com", "name", "password", tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_delete_secure_start(&http_client, &ip_addr, NX_WEB_HTTPS_SERVER_PORT, resource, "www.abc.com", "name", "password", NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}
#endif /* NX_WEB_HTTPS_ENABLE  */

UINT nx_web_http_client_response_body_get_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NX_PACKET *packet_ptr;
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_response_body_get(&http_client, &packet_ptr, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_response_body_get",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_response_body_get(NX_NULL, &packet_ptr, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_response_body_get(&http_client, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_put_packet_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
NX_PACKET packet;
UINT status;
UINT error_counter = 0;

    nx_web_http_client_delete(&http_client);

    /* Control block not initialized. */
    status = nx_web_http_client_put_packet(&http_client, &packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_put_packet",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_put_packet(NX_NULL, &packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_put_packet(&http_client, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}


static VOID response_header_callback(NX_WEB_HTTP_CLIENT *client_ptr, CHAR *field_name, UINT field_name_length,
             CHAR *field_value, UINT field_value_length)
{

}

UINT nx_web_http_client_response_header_callback_set_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
UINT status;
UINT error_counter = 0;

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_response_header_callback_set",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_response_header_callback_set(NX_NULL, response_header_callback);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_response_header_callback_set(&http_client, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_request_initialize_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
CHAR *resource = "resource";
UINT status;
UINT error_counter = 0;

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_request_initialize",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_request_initialize(NX_NULL, NX_WEB_HTTP_METHOD_GET, resource, "www.abc.com", 0, NX_FALSE,
                "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_request_initialize(&http_client, NX_WEB_HTTP_METHOD_GET, NX_NULL, "www.abc.com", 0, NX_FALSE,
                "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_request_initialize(&http_client, NX_WEB_HTTP_METHOD_NONE, resource, "www.abc.com", 0, NX_FALSE,
                "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_WEB_HTTP_METHOD_ERROR, status);

    /* Test method parameters. */
    status = nx_web_http_client_request_initialize(&http_client, NX_WEB_HTTP_METHOD_PUT, resource, "www.abc.com", 0, NX_FALSE,
                "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_WEB_HTTP_METHOD_ERROR, status);

    status = nx_web_http_client_request_initialize(&http_client, NX_WEB_HTTP_METHOD_POST, resource, "www.abc.com", 0, NX_FALSE,
                "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_WEB_HTTP_METHOD_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_request_send_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
UINT status;
UINT error_counter = 0;

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_request_send",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_request_send(NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_request_header_add_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
UINT status;
UINT error_counter = 0;

    /* Create web server instance for test. */
    status = nx_web_http_client_create(&http_client, "nx_web_http_client_request_header_add",
                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);

    status = nx_web_http_client_request_header_add(NX_NULL, "field_name", sizeof("field_name"),
                              "field_value", sizeof("field_value"), NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_request_header_add(&http_client, NX_NULL, sizeof("field_name"),
                              "field_value", sizeof("field_value"), NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_request_header_add(&http_client, "field_name", sizeof("field_name"),
                              NX_NULL, sizeof("field_value"), NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_client_delete(&http_client);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_client_connect_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
UINT status;
NXD_ADDRESS ip_addr;
UINT error_counter = 0;

    status = nx_web_http_client_connect(NX_NULL, &ip_addr, NX_WEB_HTTP_SERVER_PORT, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_connect(&http_client, NX_NULL, NX_WEB_HTTP_SERVER_PORT, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

#ifdef NX_WEB_HTTPS_ENABLE
UINT nx_web_http_client_secure_connect_test(void)
{
NX_WEB_HTTP_CLIENT http_client;
UINT status;
NXD_ADDRESS ip_addr;
UINT error_counter = 0;

    status = nx_web_http_client_secure_connect(NX_NULL, &ip_addr, NX_WEB_HTTP_SERVER_PORT, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_secure_connect(&http_client, NX_NULL, NX_WEB_HTTP_SERVER_PORT, tls_callback, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_client_secure_connect(&http_client, &ip_addr, NX_WEB_HTTP_SERVER_PORT, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}
#endif

UINT nx_web_http_server_callback_data_send_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
UCHAR *data_ptr = "data to send";
UINT data_length = sizeof("data to send");
UINT status;
UINT error_counter = 0;

    /* Control block not initialized. */
    status = nx_web_http_server_callback_data_send(&http_server, data_ptr, data_length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */

    status = nx_web_http_server_create(&http_server, "nx_web_http_server_callback_data_send",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_callback_data_send(NX_NULL, data_ptr, data_length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_callback_data_send(&http_server, NX_NULL, data_length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_server_delete(&http_server);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_callback_response_send_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
CHAR *header = "header";
CHAR *information = "info";
CHAR *additional_info = "additional info";
UINT status;
UINT error_counter = 0;


    status = nx_web_http_server_callback_response_send(NX_NULL, header, information, additional_info);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_callback_response_send(&http_server, NX_NULL, information, additional_info);
    EXPECT_EQ(NX_PTR_ERROR, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_content_get_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
UINT status;
NX_PACKET packet;
CHAR dest_buffer[100];
CHAR dest_size = sizeof(dest_buffer);
UINT actual_size;
UINT error_counter = 0;

    /* Control block not initialized. */
    status = nx_web_http_server_content_get(&http_server, &packet, 0, dest_buffer, dest_size, &actual_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_server_delete(&http_server);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_content_get",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_content_get(NX_NULL, &packet, 0, dest_buffer, dest_size, &actual_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_content_get(&http_server, NX_NULL, 0, dest_buffer, dest_size, &actual_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_content_get(&http_server, &packet, 0, NX_NULL, dest_size, &actual_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_content_get(&http_server, &packet, 0, dest_buffer, dest_size, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_server_delete(&http_server);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_create_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
UINT status;
UINT error_counter = 0;


    status = nx_web_http_server_create(NX_NULL, "nx_web_http_server_create",
                                       NX_NULL, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_server_delete(&http_server);

    status = nx_web_http_server_create(&http_server, "nx_web_http_server_create",
                                       NX_NULL, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_server_delete(&http_server);

    status = nx_web_http_server_create(&http_server, "nx_web_http_server_create",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       NX_NULL, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_server_delete(&http_server);

    status = nx_web_http_server_create(&http_server, "nx_web_http_server_create",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, NX_NULL,
                                       server_auth_check, server_req_notify);
    EXPECT_EQ(NX_PTR_ERROR, status);

    nx_web_http_server_delete(&http_server);

    /* Create server - expect successful return for following checks. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_create",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);
    EXPECT_EQ(NX_SUCCESS, status);

    EXPECT_EQ((ULONG)(&http_server), http_server.nx_web_http_server_tcpserver.nx_tcpserver_reserved);
    EXPECT_EQ(&ip_0, http_server.nx_web_http_server_ip_ptr);
    EXPECT_EQ(&pool_0, http_server.nx_web_http_server_packet_pool_ptr);
    EXPECT_EQ(server_auth_check, http_server.nx_web_http_server_authentication_check);
    EXPECT_EQ(server_req_notify, http_server.nx_web_http_server_request_notify);
    EXPECT_EQ(NX_WEB_HTTP_SERVER_ID, http_server.nx_web_http_server_id);
    EXPECT_EQ(NX_WEB_HTTP_SERVER_PORT, http_server.nx_web_http_server_listen_port);

    nx_web_http_server_delete(&http_server);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_delete_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
UINT status;
UINT error_counter = 0;

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_delete",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_delete(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);

    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}


UINT nx_web_http_server_param_get_test(VOID *stack_memory, UINT stack_size)
{
NX_PACKET packet;
CHAR param_buf[100];
UINT param_size;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_param_get(NX_NULL, 1, param_buf, &param_size, sizeof(param_buf));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_param_get(&packet, 1, NX_NULL, &param_size, sizeof(param_buf));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_param_get(&packet, 1, param_buf, NX_NULL, sizeof(param_buf));
    EXPECT_EQ(NX_PTR_ERROR, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_query_get_test(VOID *stack_memory, UINT stack_size)
{
NX_PACKET packet;
CHAR param_buf[100];
UINT param_size;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_query_get(NX_NULL, 1, param_buf, &param_size, sizeof(param_buf));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_query_get(&packet, 1, NX_NULL, &param_size, sizeof(param_buf));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_query_get(&packet, 1, param_buf, NX_NULL, sizeof(param_buf));
    EXPECT_EQ(NX_PTR_ERROR, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_start_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_start(&http_server);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_start(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

#ifdef NX_WEB_HTTPS_ENABLE
UINT nx_web_http_server_secure_configure_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;

const NX_SECURE_TLS_CRYPTO crypto_table;
UCHAR metadata_buffer[100];
UCHAR packet_buffer[100];
NX_SECURE_X509_CERT identity_certificate;
NX_SECURE_X509_CERT *trusted_certificates[1];
NX_SECURE_X509_CERT *remote_certificates[1];
UCHAR remote_certificate_buffer[100];
UINT status;
UINT error_counter = 0;

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_secure_configure",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_secure_configure(NX_NULL, &crypto_table, metadata_buffer, sizeof(metadata_buffer),
                                                 packet_buffer, sizeof(packet_buffer), &identity_certificate,
                                                 trusted_certificates, 1, remote_certificates, 1,
                                                 remote_certificate_buffer, sizeof(remote_certificate_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_secure_configure(&http_server, NX_NULL, metadata_buffer, sizeof(metadata_buffer),
                                                 packet_buffer, sizeof(packet_buffer), &identity_certificate,
                                                 trusted_certificates, 1, remote_certificates, 1,
                                                 remote_certificate_buffer, sizeof(remote_certificate_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_secure_configure(&http_server, &crypto_table, NX_NULL, sizeof(metadata_buffer),
                                                 packet_buffer, sizeof(packet_buffer), &identity_certificate,
                                                 trusted_certificates, 1, remote_certificates, 1,
                                                 remote_certificate_buffer, sizeof(remote_certificate_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_secure_configure(&http_server, &crypto_table, metadata_buffer, sizeof(metadata_buffer),
                                                 NX_NULL, sizeof(packet_buffer), &identity_certificate,
                                                 trusted_certificates, 1, remote_certificates, 1,
                                                 remote_certificate_buffer, sizeof(remote_certificate_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_secure_configure(&http_server, &crypto_table, metadata_buffer, sizeof(metadata_buffer),
                                                 packet_buffer, sizeof(packet_buffer), NX_NULL,
                                                 trusted_certificates, 1, remote_certificates, 1,
                                                 remote_certificate_buffer, sizeof(remote_certificate_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}
#endif

UINT nx_web_http_server_stop_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_stop(&http_server);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_stop(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_content_get_extended_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
NX_PACKET packet;
CHAR buffer[100];
UINT content_size;
UINT status;
UINT error_counter = 0;

    /* Control block not initialized. */
    status = nx_web_http_server_content_get_extended(&http_server, &packet, 0, buffer, sizeof(buffer), &content_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_content_get_extended",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_content_get_extended(NX_NULL, &packet, 0, buffer, sizeof(buffer), &content_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_content_get_extended(&http_server, NX_NULL, 0, buffer, sizeof(buffer), &content_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_content_get_extended(&http_server, &packet, 0, NX_NULL, sizeof(buffer), &content_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_content_get_extended(&http_server, &packet, 0, buffer, sizeof(buffer), NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_content_length_get_test(VOID *stack_memory, UINT stack_size)
{
NX_PACKET packet;
ULONG length;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_content_length_get(NX_NULL, &length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_content_length_get(&packet, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

#ifdef  NX_WEB_HTTP_MULTIPART_ENABLE
UINT nx_web_http_server_get_entity_header_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
NX_PACKET *packet_ptr;
UCHAR buffer[100];
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_get_entity_header(&http_server, &packet_ptr, buffer, sizeof(buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_get_entity_header",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_get_entity_header(NX_NULL, &packet_ptr, buffer, sizeof(buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_get_entity_header(&http_server, NX_NULL, buffer, sizeof(buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_get_entity_header(&http_server, &packet_ptr, NX_NULL, sizeof(buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_get_entity_content_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
NX_PACKET *packet_ptr;
ULONG offset;
ULONG length;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_get_entity_content(&http_server, &packet_ptr, &offset, &length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_get_entity_content",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_get_entity_content(NX_NULL, &packet_ptr, &offset, &length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_get_entity_content(&http_server, NX_NULL, &offset, &length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_get_entity_content(&http_server, &packet_ptr, NX_NULL, &length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_get_entity_content(&http_server, &packet_ptr, &offset, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}
#endif

UINT nx_web_http_server_callback_generate_response_header_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
NX_PACKET *packet_ptr;
CHAR *status_code = "404";
CHAR *content_type = "text";
CHAR *header = "header";
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_callback_generate_response_header(&http_server, &packet_ptr, status_code, 100, content_type, header);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_callback_generate_response_header",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_callback_generate_response_header(NX_NULL, &packet_ptr, status_code, 100, content_type, header);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_callback_generate_response_header(&http_server, NX_NULL, status_code, 100, content_type, header);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_callback_generate_response_header(&http_server, &packet_ptr, NX_NULL, 100, content_type, header);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_callback_packet_send_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
NX_PACKET packet;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_callback_packet_send(&http_server, &packet);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_callback_packet_send",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_callback_packet_send(NX_NULL, &packet);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_callback_packet_send(&http_server, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

static VOID gmt_callback(NX_WEB_HTTP_SERVER_DATE *date)
{

}

UINT nx_web_http_server_gmt_callback_set_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_gmt_callback_set(&http_server, gmt_callback);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_gmt_callback_set",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_gmt_callback_set(NX_NULL, gmt_callback);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_gmt_callback_set(&http_server, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}



UINT cache_info_callback(CHAR *resource, UINT *age, NX_WEB_HTTP_SERVER_DATE *date)
{
    return(NX_SUCCESS);
}


UINT nx_web_http_server_cache_info_callback_set_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_cache_info_callback_set (&http_server, cache_info_callback);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_cache_info_callback_set ",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_cache_info_callback_set (NX_NULL, cache_info_callback);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_cache_info_callback_set (&http_server, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_mime_maps_additional_set_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
NX_WEB_HTTP_SERVER_MIME_MAP mime_map;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_mime_maps_additional_set(&http_server, &mime_map, 1);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_mime_maps_additional_set",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_mime_maps_additional_set(NX_NULL, &mime_map, 1);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_mime_maps_additional_set(&http_server, NX_NULL, 1);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_type_get_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
CHAR name[100];
CHAR type_string[100];
UINT string_size;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_type_get(&http_server, name, type_string, &string_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_type_get",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_type_get(NX_NULL, name, type_string, &string_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_type_get(&http_server, NX_NULL, type_string, &string_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_type_get(&http_server, name, NX_NULL, &string_size);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_type_get(&http_server, name, type_string, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_packet_content_find_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
NX_PACKET *packet_ptr;
ULONG length;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_packet_content_find(&http_server, &packet_ptr, &length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_packet_content_find",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_packet_content_find(NX_NULL, &packet_ptr, &length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_packet_content_find(&http_server, NX_NULL, &length);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_packet_content_find(&http_server, &packet_ptr, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

UINT nx_web_http_server_packet_get_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
NX_PACKET *packet_ptr;
UINT status;
UINT error_counter = 0;

    status = nx_web_http_server_packet_get(&http_server, &packet_ptr);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_packet_get",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_packet_get(NX_NULL, &packet_ptr);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_packet_get(&http_server, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

static UINT invalid_username_password_callback(CHAR *resource, NXD_ADDRESS *client_nxd_address, UINT request_type)
{
    return(NX_SUCCESS);
}

UINT nx_web_http_server_invalid_userpassword_notify_set_test(VOID *stack_memory, UINT stack_size)
{
NX_WEB_HTTP_SERVER http_server;
UINT status;
UINT error_counter = 0;

    /* Create web server instance for test. */
    status = nx_web_http_server_create(&http_server, "nx_web_http_server_invalid_userpassword_notify_set",
                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,
                                       stack_memory, stack_size, &pool_0,
                                       server_auth_check, server_req_notify);

    status = nx_web_http_server_invalid_userpassword_notify_set(NX_NULL, invalid_username_password_callback);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_invalid_userpassword_notify_set(&http_server, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_web_http_server_delete(&http_server);
    EXPECT_EQ(NX_SUCCESS, status);

    if(error_counter > 0)
    {
        return(1);
    }

    return(NX_SUCCESS);
}

/********************************************************************************
 * Python used to generate skeleton test cases:
#!/bin/python

def gen_client_tests(input_list):
    ret_str = ""
    for name in input_list:
        ret_str += "\nUINT " + name + "(void)\n{"
        ret_str += "\nNX_WEB_HTTP_CLIENT http_client;"
        ret_str += "\nUINT status;"
        ret_str += "\n "
        ret_str += "\n    / * Create web server instance for test. * /"
        ret_str += "\n    status = nx_web_http_client_create(&http_client, \"" + name + "\","
        ret_str += "\n                                       &ip_0, &pool_0, TEST_WINDOW_SIZE);"
        ret_str += "\n "
        ret_str += "\n    status = " + name + "(&http_client, );"
        ret_str += "\n    EXPECT_EQ(NX_PTR_ERROR, status);"
        ret_str += "\n "
        ret_str += "\n    return(NX_SUCCESS);\n}\n"
    return ret_str

def gen_server_tests(input_list):
    ret_str = ""
    for name in input_list:
        ret_str += "\nUINT " + name + "_test(VOID *stack_memory, UINT stack_size)\n{"
        ret_str += "\nNX_WEB_HTTP_SERVER http_server;"
        ret_str += "\nUINT status;"
        ret_str += "\n    / * Create web server instance for test. * /"
        ret_str += "\n    status = nx_web_http_server_create(&http_server, \"" + name + "\","
        ret_str += "\n                                       &ip_0, NX_WEB_HTTP_SERVER_PORT, NX_NULL,"
        ret_str += "\n                                       stack_memory, stack_size, &pool_0,"
        ret_str += "\n                                       server_auth_check, server_req_notify);"
        ret_str += "\n "
        ret_str += "\n    status = " + name + "(&http_server, );"
        ret_str += "\n    EXPECT_EQ(NX_PTR_ERROR, status);"
        ret_str += "\n "
        ret_str += "\n    return(NX_SUCCESS);\n}\n"
    return ret_str

def gen_server_prototypes(input_list):
    ret_str = ""
    for name in input_list:
        ret_str += "\nUINT " + name + "_test(VOID *stack_memory, UINT stack_size);"
    return ret_str


def gen_client_prototypes(input_list):
    ret_str = ""
    for name in input_list:
        ret_str += "\nUINT " + name + "_test(void);"
    return ret_str

def gen_server_calls(input_list):
    ret_str = ""
    for name in input_list:
        ret_str += "\n    status = " + name + "_test(stack_memory, sizeof(stack_memory));"
        ret_str += "\n    if(status != NX_SUCCESS)"
        ret_str += "\n    {"
        ret_str += "\n        test_control_return(1);"
        ret_str += "\n    }"
        ret_str += "\n "
    return ret_str

def gen_client_calls(input_list):
    ret_str = ""
    for name in input_list:
        ret_str += "\n    status = " + name + "_test();"
        ret_str += "\n    if(status != NX_SUCCESS)"
        ret_str += "\n    {"
        ret_str += "\n        test_control_return(1);"
        ret_str += "\n    }"
        ret_str += "\n"
    return ret_str

def gen_all_tests():
    ret_str = ""
    ret_str += gen_client_prototypes(client_api_list)
    ret_str += gen_server_prototypes(server_api_list)
    ret_str += gen_client_calls(client_api_list)
    ret_str += gen_server_calls(server_api_list)
    ret_str += gen_client_tests(client_api_list)
    ret_str += gen_server_tests(server_api_list)
    return ret_str

def write_tests():
    f = open("./test.c", "w")
    tests = gen_all_tests()
    f.write(tests)
    f.close()

client_api_list = [ "nx_web_http_client_create",
"nx_web_http_client_delete",
"nx_web_http_client_get_start",
"nx_web_http_client_put_start",
"nx_web_http_client_post_start",
"nx_web_http_client_head_start",
"nx_web_http_client_delete_start",
"nx_web_http_client_get_secure_start",
"nx_web_http_client_put_secure_start",
"nx_web_http_client_post_secure_start",
"nx_web_http_client_head_secure_start",
"nx_web_http_client_delete_secure_start",
"nx_web_http_client_response_body_get",
"nx_web_http_client_put_packet",
"nx_web_http_client_response_header_callback_set",
"nx_web_http_client_request_initialize",
"nx_web_http_client_request_send",
"nx_web_http_client_request_header_add",
"nx_web_http_client_connect",
"nx_web_http_client_secure_connect" ]

server_api_list = [ "nx_web_http_server_callback_data_send",
"nx_web_http_server_callback_response_send",
"nx_web_http_server_content_get",
"nx_web_http_server_create",
"nx_web_http_server_delete",
"nx_web_http_server_param_get",
"nx_web_http_server_query_get",
"nx_web_http_server_start",
"nx_web_http_server_secure_configure",
"nx_web_http_server_stop",
"nx_web_http_server_content_get_extended",
"nx_web_http_server_content_length_get",
"nx_web_http_server_get_entity_header",
"nx_web_http_server_get_entity_content",
"nx_web_http_server_callback_generate_response_header",
"nx_web_http_server_callback_packet_send",
"nx_web_http_server_gmt_callback_set",
"nx_web_http_server_cache_info_callback_set ",
"nx_web_http_server_mime_maps_additional_set",
"nx_web_http_server_type_get",
"nx_web_http_server_packet_content_find",
"nx_web_http_server_packet_get",
"nx_web_http_server_invalid_userpassword_notify_set" ]

*/


