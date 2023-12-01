/* This case tests digest authentication. 
 HA1 = MD5("name:NetX Duo HTTP demo:password")
     = 01bb2595c9221423951ee86f3573b465
 HA2 = MD5("GET:/index.htm")
     = d4b1da8c7955d2e98bc56ffc93003b44
 Response = MD5("01bb2595c9221423951ee86f3573b465:
                 nonce:
                 00000001:0a4f113b:auth:
                 d4b1da8c7955d2e98bc56ffc93003b44")
 */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nxd_http_client.h"
#include    "nxd_http_server.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(NX_HTTP_DIGEST_ENABLE)

#include "../web_test/http_digest_authentication.c"


#define     DEMO_STACK_SIZE         4096

/* Set up FileX and file memory resources. */
static CHAR             ram_disk_memory[4096];
static FX_MEDIA         ram_disk;
static UCHAR            media_memory[4096];

static UCHAR            server_stack[16000];

/* Define device drivers.  */
extern void _fx_ram_driver(FX_MEDIA *media_ptr);
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

/* Set up the HTTP client global variables. */

#define         CLIENT_PACKET_SIZE  (NX_HTTP_CLIENT_MIN_PACKET_SIZE * 2)

static TX_THREAD           client_thread;
static NX_PACKET_POOL      client_pool;
static NX_HTTP_CLIENT      my_client;
static NX_IP               client_ip;
static UINT                error_counter;

/* Set up the HTTP server global variables */

#define         SERVER_PACKET_SIZE  (NX_HTTP_SERVER_MIN_PACKET_SIZE * 2)

static NX_HTTP_SERVER      my_server;
static NX_PACKET_POOL      server_pool;
static TX_THREAD           server_thread;
static NX_IP               server_ip;
#ifdef __PRODUCT_NETXDUO__
static NXD_ADDRESS     server_ip_address;
#else
static ULONG           server_ip_address;
#endif

static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define HTTP_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)


static TX_SEMAPHORE server_start;
static TX_SEMAPHORE client_stop;


static UINT  authentication_check(NX_HTTP_SERVER *server_ptr, UINT request_type, 
                                  CHAR *resource, CHAR **name, CHAR **password, CHAR **realm);
static UINT  authentication_check_extended(NX_HTTP_SERVER *server_ptr, UINT request_type, CHAR *resource, CHAR **name, UINT *name_length, 
                                           CHAR **password, UINT *password_length, CHAR **realm, UINT *realm_length);

static CHAR nonce_buffer[NX_HTTP_SERVER_NONCE_SIZE + 1];
static CHAR temp_nonce_buffer[NX_HTTP_SERVER_NONCE_SIZE + 1];
static CHAR response_buffer[32 + 1];
static NX_MD5 client_md5data;

static char pkt[] = {
0x47, 0x45, 0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x20, /* GET /index.htm  */
0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, /* HTTP/1.1.. */
};

static UINT test_count;

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_digest_authenticate_test_application_define(void *first_unused_memory)
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
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

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
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
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

    tx_semaphore_create(&server_start, "server start", 0);
    tx_semaphore_create(&client_stop, "client stop", 0);
}

void thread_client_entry(ULONG thread_input)
{
UINT            status;
NX_PACKET       *send_packet;
NX_PACKET       *recv_packet;
CHAR            *buffer_ptr;


    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Set server IP address.  */
#ifdef __PRODUCT_NETXDUO__ 
    server_ip_address.nxd_ip_address.v4 = HTTP_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
#else
    server_ip_address = HTTP_SERVER_ADDRESS;
#endif

    /* Create an HTTP client instance.  */
    status = nx_http_client_create(&my_client, "HTTP Client", &client_ip, &client_pool, 1536);

    /* Check status.  */
    if (status)
        error_counter++;

    for (test_count = 0; test_count < 2; test_count++)
    {
        tx_semaphore_get(&server_start, NX_WAIT_FOREVER);

        /* Bind the client socket.  */
        status = nx_tcp_client_socket_bind(&(my_client.nx_http_client_socket), NX_ANY_PORT, NX_WAIT_FOREVER);

        /* Check status of the bind.  */
        if (status)
            error_counter++;

        /* Connect to the HTTP server.  */
#ifdef __PRODUCT_NETXDUO__

    /* Invoke the 'Duo' (supports IPv6/IPv4) connection call. */
        status = nxd_tcp_client_socket_connect(&(my_client.nx_http_client_socket), &server_ip_address,
            my_client.nx_http_client_connect_port, NX_WAIT_FOREVER);
#else
    /* Invoke the NetX (IPv4 only) connection call. */
        status = nx_tcp_client_socket_connect(&(my_client.nx_http_client_socket), server_ip_address,
            my_client.nx_http_client_connect_port, NX_WAIT_FOREVER);
#endif

        /* Allocate a packet.  */
        status = nx_packet_allocate(&client_pool, &send_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;

        nx_packet_data_append(send_packet, pkt, sizeof(pkt), &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, "\r\n", 2, &client_pool, NX_WAIT_FOREVER);

        /* Send the request.  */
        status = nx_tcp_socket_send(&(my_client.nx_http_client_socket), send_packet, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status)
            error_counter++;

        /* Initialize the buffer.  */
        memset(nonce_buffer, 0, sizeof(nonce_buffer));
        memset(response_buffer, 0, sizeof(response_buffer));

        /* Pickup the response from the Server.  */
        status = nx_tcp_socket_receive(&(my_client.nx_http_client_socket), &recv_packet, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status)
            error_counter++;
        else
        {
            status = http_nonce_retrieve(recv_packet, nonce_buffer);
            if (status)
                error_counter++;
            nx_packet_release(recv_packet);

            /* Check if the nonce is regenerated.  */
            if (test_count == 0)
            {
                memcpy(temp_nonce_buffer, nonce_buffer, sizeof(nonce_buffer));
            }
            else
            {
                if (memcmp(temp_nonce_buffer, nonce_buffer, sizeof(nonce_buffer)) == 0)
                {
                    error_counter++;
                }
            }
        }

        http_digest_response_calculate(&client_md5data, "name", "NetX Duo HTTP demo", "password", nonce_buffer, "GET",
                                       "/index.htm", "00000001", "0a4f113b", response_buffer);

        /* Disconnect and unbind the socket.  */
        nx_tcp_socket_disconnect(&(my_client.nx_http_client_socket), NX_HTTP_CLIENT_TIMEOUT);
        nx_tcp_client_socket_unbind(&(my_client.nx_http_client_socket));

        /* Bind the client socket.  */
        status = nx_tcp_client_socket_bind(&(my_client.nx_http_client_socket), NX_ANY_PORT, NX_WAIT_FOREVER);

        /* Check status of the bind.  */
        if (status)
            error_counter++;

        /* Connect to the HTTP server.  */
#ifdef __PRODUCT_NETXDUO__

    /* Invoke the 'Duo' (supports IPv6/IPv4) connection call. */
        status = nxd_tcp_client_socket_connect(&(my_client.nx_http_client_socket), &server_ip_address,
            my_client.nx_http_client_connect_port, NX_WAIT_FOREVER);
#else
    /* Invoke the NetX (IPv4 only) connection call. */
        status = nx_tcp_client_socket_connect(&(my_client.nx_http_client_socket), server_ip_address,
            my_client.nx_http_client_connect_port, NX_WAIT_FOREVER);
#endif

        /* Allocate a packet.  */
        status = nx_packet_allocate(&client_pool, &send_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;

        nx_packet_data_append(send_packet, pkt, sizeof(pkt), &client_pool, NX_WAIT_FOREVER);

        /* Build the Authorization header.  */
        nx_packet_data_append(send_packet, "Authorization: Digest", 21, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, " username=\"name\",", 17, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, " realm=\"NetX Duo HTTP demo\",", 28, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, " nonce=\"", 8, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, nonce_buffer, NX_HTTP_SERVER_NONCE_SIZE, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, "\",", 2, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, " uri=\"/index.htm\",", 17, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, " qop=auth,", 10, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, " nc=00000001,", 13, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, " cnonce=\"0a4f113b\",", 19, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, " response=\"", 11, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, response_buffer, 32, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, "\",", 2, &client_pool, NX_WAIT_FOREVER);
        nx_packet_data_append(send_packet, " opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n", 44, &client_pool, NX_WAIT_FOREVER);

        nx_packet_data_append(send_packet, "\r\n", 2, &client_pool, NX_WAIT_FOREVER);

        /* Now send the packet to the HTTP server.  */
        status = nx_tcp_socket_send(&(my_client.nx_http_client_socket), send_packet, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status)
            error_counter++;

        /* Pickup the response from the Server.  */
        status = nx_tcp_socket_receive(&(my_client.nx_http_client_socket), &recv_packet, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status)
        {
            error_counter++;
        }
        else
        {
            buffer_ptr = (CHAR *)recv_packet->nx_packet_prepend_ptr;

            if (test_count == 0)
            {
                /* Check the status, If authentication success , it should be 200. */
                if ((buffer_ptr[9] != '2') || (buffer_ptr[10] != '0') || (buffer_ptr[11] != '0'))
                    error_counter++;
            }
            else
            {
                /* Check the status, If authentication fail , it should be 401. */
                if ((buffer_ptr[9] != '4') || (buffer_ptr[10] != '0') || (buffer_ptr[11] != '1'))
                    error_counter++;
            }

            nx_packet_release(recv_packet);
        }

        /* Disconnect and unbind the socket.  */
        nx_tcp_socket_disconnect(&(my_client.nx_http_client_socket), NX_HTTP_CLIENT_TIMEOUT);
        nx_tcp_client_socket_unbind(&(my_client.nx_http_client_socket));

        tx_semaphore_put(&client_stop);
    }

    status = nx_http_client_delete(&my_client);
    if (status)
        error_counter++;

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

static UINT digest_authenticate_callback(NX_HTTP_SERVER *server_ptr, CHAR *name_ptr,
                                    CHAR *realm_ptr, CHAR *password_ptr, CHAR *method,
                                    CHAR *authorization_uri, CHAR *authorization_nc,
                                    CHAR *authorization_cnonce)
{

    if (memcmp(authorization_nc, "00000001", 8) != 0)
    {
        return 1;
    }

    if (test_count == 0)
    {
        /* Test authentication success.  */
        return 0;
    }
    else
    {
        /* Test authentication fail.  */
        return 1;
    }
}

/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT            status;
FX_FILE         my_file;


    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Digest Authenticate Test.............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    fx_media_format(&ram_disk,
                    _fx_ram_driver,               // Driver entry
                    ram_disk_memory,              // RAM disk memory pointer
                    media_memory,                 // Media buffer pointer
                    sizeof(media_memory),         // Media buffer size
                    "MY_RAM_DISK",                // Volume Name
                    1,                            // Number of FATs
                    32,                           // Directory Entries
                    0,                            // Hidden sectors
                    256,                          // Total sectors
                    512,                          // Sector size
                    8,                            // Sectors per cluster
                    1,                            // Heads
                    1);                           // Sectors per track
    
    /* Open the RAM disk.  */
    status = fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, media_memory, sizeof(media_memory)) ;
    if(status)
        error_counter++;

    /* Give NetX a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    status = fx_file_create(&ram_disk, "index.htm");
    status += fx_file_open(&ram_disk, &my_file, "index.htm", FX_OPEN_FOR_WRITE);
    status += fx_file_write(&my_file, "https server", 12);
    status += fx_file_close(&my_file);
    if (status)
        error_counter++;

    /* Create the HTTP Server.  */
    status = nx_http_server_create(&my_server, "My HTTP Server", &server_ip, &ram_disk, 
                                   server_stack, sizeof(server_stack), &server_pool, authentication_check, NX_NULL);
    if (status)
        error_counter++;

    nx_http_server_digest_authenticate_notify_set(&my_server, digest_authenticate_callback);

    /* OK to start the HTTP Server.   */
    status = nx_http_server_start(&my_server);
    if (status)
        error_counter++;

    tx_semaphore_put(&server_start);
    tx_semaphore_get(&client_stop, NX_WAIT_FOREVER);

    status = nx_http_server_authentication_check_set(&my_server, authentication_check_extended);
    if (status)
        error_counter++;

    tx_semaphore_put(&server_start);
}

/* Define the application's authentication check.  This is called by
   the HTTP server whenever a new request is received.  */
static UINT  authentication_check(NX_HTTP_SERVER *server_ptr, UINT request_type, 
                                  CHAR *resource, CHAR **name, CHAR **password, CHAR **realm)
{

    /* Just use a simple name, password, and realm for all 
       requests and resources.  */
    *name =     "name";
    *password = "password";
    *realm =    "NetX Duo HTTP demo";

    /* Request digest authentication.  */
    return(NX_HTTP_DIGEST_AUTHENTICATE);
}

static UINT  authentication_check_extended(NX_HTTP_SERVER *server_ptr, UINT request_type, CHAR *resource, CHAR **name, UINT *name_length,
                                           CHAR **password, UINT *password_length, CHAR **realm, UINT *realm_length)
{

    /* Just use a simple name, password, and realm for all 
       requests and resources.  */
    *name =     "name";
    *password = "password";
    *realm =    "NetX Duo HTTP demo";
    *name_length = 4;
    *password_length = 8;
    *realm_length = 18;

    /* Request digest authentication.  */
    return(NX_HTTP_DIGEST_AUTHENTICATE);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_digest_authenticate_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Digest Authenticate Test.............................N/A\n"); 

    test_control_return(3);  
}      
#endif

