/* This case tests basic GET method. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nx_web_http_client.h"
#include    "nx_web_http_server.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         4096

/* Define device drivers.  */
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

/* Set up the HTTP client global variables. */

#define         CLIENT_PACKET_SIZE  (NX_WEB_HTTP_CLIENT_MIN_PACKET_SIZE * 2)

static TX_THREAD           client_thread;
static NX_PACKET_POOL      client_pool;
static NX_WEB_HTTP_CLIENT  my_client;
static NX_IP               client_ip;
static UINT                error_counter;

/* Set up the HTTP server global variables */

#define         SERVER_PACKET_SIZE  (NX_WEB_HTTP_SERVER_MIN_PACKET_SIZE * 2)

static NX_TCP_SOCKET       server_socket;
static NX_PACKET_POOL      server_pool;
static TX_THREAD           server_thread;
static NX_IP               server_ip;
static NXD_ADDRESS         server_ip_address;

static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define HTTP_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)

/* Define status maps. */
static NX_WEB_HTTP_CLIENT_STATUS_MAP test_status_maps[] =
{
    {"100",    NX_WEB_HTTP_STATUS_CODE_CONTINUE},
    {"101",    NX_WEB_HTTP_STATUS_CODE_SWITCHING_PROTOCOLS},
    {"201",    NX_WEB_HTTP_STATUS_CODE_CREATED},
    {"202",    NX_WEB_HTTP_STATUS_CODE_ACCEPTED},
    {"203",    NX_WEB_HTTP_STATUS_CODE_NON_AUTH_INFO},
    {"204",    NX_WEB_HTTP_STATUS_CODE_NO_CONTENT},
    {"205",    NX_WEB_HTTP_STATUS_CODE_RESET_CONTENT},
    {"206",    NX_WEB_HTTP_STATUS_CODE_PARTIAL_CONTENT},
    {"300",    NX_WEB_HTTP_STATUS_CODE_MULTIPLE_CHOICES},
    {"301",    NX_WEB_HTTP_STATUS_CODE_MOVED_PERMANETLY},
    {"302",    NX_WEB_HTTP_STATUS_CODE_FOUND},
    {"303",    NX_WEB_HTTP_STATUS_CODE_SEE_OTHER},
    {"304",    NX_WEB_HTTP_STATUS_CODE_NOT_MODIFIED},
    {"305",    NX_WEB_HTTP_STATUS_CODE_USE_PROXY},
    {"307",    NX_WEB_HTTP_STATUS_CODE_TEMPORARY_REDIRECT},
    {"400",    NX_WEB_HTTP_STATUS_CODE_BAD_REQUEST},
    {"401",    NX_WEB_HTTP_STATUS_CODE_UNAUTHORIZED},
    {"402",    NX_WEB_HTTP_STATUS_CODE_PAYMENT_REQUIRED},
    {"403",    NX_WEB_HTTP_STATUS_CODE_FORBIDDEN},
    {"404",    NX_WEB_HTTP_STATUS_CODE_NOT_FOUND},
    {"405",    NX_WEB_HTTP_STATUS_CODE_METHOD_NOT_ALLOWED},
    {"406",    NX_WEB_HTTP_STATUS_CODE_NOT_ACCEPTABLE},
    {"407",    NX_WEB_HTTP_STATUS_CODE_PROXY_AUTH_REQUIRED},
    {"408",    NX_WEB_HTTP_STATUS_CODE_REQUEST_TIMEOUT},
    {"409",    NX_WEB_HTTP_STATUS_CODE_CONFLICT},
    {"410",    NX_WEB_HTTP_STATUS_CODE_GONE},
    {"411",    NX_WEB_HTTP_STATUS_CODE_LENGTH_REQUIRED},
    {"412",    NX_WEB_HTTP_STATUS_CODE_PRECONDITION_FAILED},
    {"413",    NX_WEB_HTTP_STATUS_CODE_ENTITY_TOO_LARGE},
    {"414",    NX_WEB_HTTP_STATUS_CODE_URL_TOO_LARGE},
    {"415",    NX_WEB_HTTP_STATUS_CODE_UNSUPPORTED_MEDIA},
    {"416",    NX_WEB_HTTP_STATUS_CODE_RANGE_NOT_SATISFY},
    {"417",    NX_WEB_HTTP_STATUS_CODE_EXPECTATION_FAILED},
    {"500",    NX_WEB_HTTP_STATUS_CODE_INTERNAL_ERROR},
    {"501",    NX_WEB_HTTP_STATUS_CODE_NOT_IMPLEMENTED},
    {"502",    NX_WEB_HTTP_STATUS_CODE_BAD_GATEWAY},
    {"503",    NX_WEB_HTTP_STATUS_CODE_SERVICE_UNAVAILABLE},
    {"504",    NX_WEB_HTTP_STATUS_CODE_GATEWAY_TIMEOUT},
    {"505",    NX_WEB_HTTP_STATUS_CODE_VERSION_ERROR},
};

static UINT test_count = sizeof(test_status_maps)/sizeof(NX_WEB_HTTP_CLIENT_STATUS_MAP);

static char pkt[] = {
0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, /* HTTP/1.1 */
0x20, 0x32, 0x30, 0x30, 0x20, 0x0d, 0x0a, 0x0d, /*  200 ... */
0x0a,                                           /* .        */
};

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_status_code_test_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;


    error_counter = 0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&server_thread, "HTTP Server thread", thread_server_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     NX_WEB_HTTP_SERVER_PRIORITY, NX_WEB_HTTP_SERVER_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "HTTP Server Packet Pool", SERVER_PACKET_SIZE, 
                                    pointer, SERVER_PACKET_SIZE*8);
    pointer = pointer + SERVER_PACKET_SIZE * 8;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, "HTTP Server IP", HTTP_SERVER_ADDRESS, 
                          0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1024,
                          pointer, 4096, 1);
    pointer =  pointer + 4096;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status = nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;


     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&server_ip);
    if (status)
        error_counter++;

    /* Create the HTTP Client thread. */
    status = tx_thread_create(&client_thread, "HTTP Client", thread_client_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              NX_WEB_HTTP_SERVER_PRIORITY + 2, NX_WEB_HTTP_SERVER_PRIORITY + 2, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "HTTP Client Packet Pool", CLIENT_PACKET_SIZE, 
                                    pointer, CLIENT_PACKET_SIZE*8);
    pointer = pointer + CLIENT_PACKET_SIZE * 8;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip, "HTTP Client IP", HTTP_CLIENT_ADDRESS, 
                          0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status  = nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip);
    if (status)
        error_counter++;
}

void thread_client_entry(ULONG thread_input)
{
UINT            i;
UINT            status;
NX_PACKET       *recv_packet;


    /* Wait server to set up.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = HTTP_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    /* First loop test HTTP, second loop test HTTPS.  */
    for (i = 0; i < test_count ; i++)
    {

        /* Create an HTTP client instance.  */
        status = nx_web_http_client_create(&my_client, "HTTP Client", &client_ip, &client_pool, 1536);

        /* Check status.  */
        if (status)
            error_counter++;

        /* Send a GET request.  */
        status = nx_web_http_client_get_start(&my_client, &server_ip_address,
                                              NX_WEB_HTTP_SERVER_PORT, "http://1.2.3.4/test.txt",
                                              "1.2.3.4", "name", "password", NX_WAIT_FOREVER);

        /* Check status.  */
        if (status)
            error_counter++;

        /* Get response from server.  */
        status = nx_web_http_client_response_body_get(&my_client, &recv_packet, 1 * NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (test_status_maps[i].nx_web_http_client_status_string[0] == '2')
        {
            if (status != NX_SUCCESS && status != NX_WEB_HTTP_GET_DONE)
                error_counter++;
        }
        else if (status != test_status_maps[i].nx_web_http_client_status_code)
        {
            error_counter++;
        }

        if (recv_packet)
        {
            nx_packet_release(recv_packet);
        }

        status = nx_web_http_client_delete(&my_client);
        if (status)
            error_counter++;

        tx_thread_resume(&server_thread);
    }
}

/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT         status;
NX_PACKET   *recv_packet;
NX_PACKET   *send_packet;
UINT         i;

    /* Print out test information banner.  */
    printf("NetX Test:   Web Status Code Test......................................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a TCP socket act as the HTTP server.  */
    status = nx_tcp_socket_create(&server_ip, &server_socket, "Socket Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 
                                  NX_IP_TIME_TO_LIVE, 2048, NX_NULL, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Bind the TCP socket to the IP port.  */
    status =  nx_tcp_server_socket_listen(&server_ip, 80, &server_socket, 5, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Act as the HTTP server to receive the Client query and send the HTTP server response.  */
    for (i = 0; i < test_count; i++ )
    {

        /* Wait for a connection request.  */
        status =  nx_tcp_server_socket_accept(&server_socket, 500);
    
        /* Check status.  */
        if (status)
        {
            error_counter++;
        }
    
        /* Receive a TCP packet.  */
        status =  nx_tcp_socket_receive(&server_socket, &recv_packet, 10 * NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status)
        {
            error_counter++;
        }

        /* Release the packet.  */
        nx_packet_release(recv_packet);

        nx_packet_allocate(&server_pool, &send_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

        /* Set the test status code.  */
        pkt[9] = test_status_maps[i].nx_web_http_client_status_string[0];
        pkt[10] = test_status_maps[i].nx_web_http_client_status_string[1];
        pkt[11] = test_status_maps[i].nx_web_http_client_status_string[2];

        nx_packet_data_append(send_packet, pkt, sizeof(pkt), &server_pool, NX_WAIT_FOREVER);

        /* Send the TCP response packet.  */
        status = nx_tcp_socket_send(&server_socket, send_packet, 200);

        /* Check status.  */
        if (status)
        {
            error_counter++; 
        }

        /* Disconnect the server socket.  */
        status =  nx_tcp_socket_disconnect(&server_socket, 200);

        /* Unaccept the server socket.  */
        status =  nx_tcp_server_socket_unaccept(&server_socket);

        /* Unbind the UDP socket.  */
        status =  nx_tcp_server_socket_relisten(&server_ip, 80, &server_socket);

        /* Check status.  */
        if (status)
        {
            error_counter++;
        }

        tx_thread_suspend(&server_thread);
    }

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&server_socket);

    /* Unbind the UDP socket.  */
    status =  nx_tcp_server_socket_unlisten(&server_ip, 80);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }
    /* Delete the TCP socket.  */
    status =  nx_tcp_socket_delete(&server_socket);

    /* Check status.  */
    if (status)
    {        
        error_counter++;
    }

    /* Check packet pool.  */
    if (server_pool.nx_packet_pool_available != server_pool.nx_packet_pool_total)
    {
        error_counter++;
    }

    if (client_pool.nx_packet_pool_available != client_pool.nx_packet_pool_total)
    {
        error_counter++;
    }

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
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_status_code_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Web Status Code Test......................................N/A\n"); 

    test_control_return(3);  
}      
#endif

