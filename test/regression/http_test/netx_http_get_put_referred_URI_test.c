/* This case tests the ability of the HTTP Client to accept a URI resource string that does not
   designate a root directory based file location.  If the string begins with an HTTP: or HTTPS: (not .
   case sensitive) the HTTP Client will send the string as is. (Note this does not guarantee the HTTP server                                                                                                  .
   will forward to the referred location.) Otherwise the URI is processed as if it is root directory based,                                                                                                                                                                                                       .
   and a leading forward slash '/' is appended if one is missing.                                                                                                                                                                                                                                                                                                               .
 */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nxd_http_client.h"

extern void  test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048
#define     SERVER_PORT             80

/* Set up FileX and file memory resources. */
static CHAR             *ram_disk_memory;
static FX_MEDIA         ram_disk;
static unsigned char    media_memory[512];

/* Define device drivers.  */
extern void _fx_ram_driver(FX_MEDIA *media_ptr);
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);
static void  http_test_initialize();
static UINT  nx_http_response_packet_send(NX_TCP_SOCKET *server_socket, UINT port, INT packet_number);


static char PUT_firstreply[202] = {
0x48, 0x54,                                     /* HT */
0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, /* TP/1.1 2 */
0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x44, /* 00 OK..D */
0x61, 0x74, 0x65, 0x3a, 0x20, 0x54, 0x75, 0x65, /* ate: Tue */
0x2c, 0x20, 0x32, 0x34, 0x20, 0x4d, 0x61, 0x79, /* , 24 May */
0x20, 0x32, 0x30, 0x31, 0x36, 0x20, 0x32, 0x33, /*  2016 23 */
0x3a, 0x32, 0x36, 0x3a, 0x35, 0x34, 0x20, 0x47, /* :26:54 G */
0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65, 0x72, 0x76, /* MT..Serv */
0x65, 0x72, 0x3a, 0x20, 0x4d, 0x61, 0x6b, 0x6f, /* er: Mako */
0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x6e, /* Server.n */
0x65, 0x74, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, /* et..Cont */
0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, /* ent-Type */
0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, /* : text/h */
0x74, 0x6d, 0x6c, 0x3b, 0x20, 0x63, 0x68, 0x61, /* tml; cha */
0x72, 0x73, 0x65, 0x74, 0x3d, 0x75, 0x74, 0x66, /* rset=utf */
0x2d, 0x38, 0x0d, 0x0a, 0x43, 0x61, 0x63, 0x68, /* -8..Cach */
0x65, 0x2d, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, /* e-Contro */
0x6c, 0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x73, 0x74, /* l: no-st */
0x6f, 0x72, 0x65, 0x2c, 0x20, 0x6e, 0x6f, 0x2d, /* ore, no- */
0x63, 0x61, 0x63, 0x68, 0x65, 0x2c, 0x20, 0x6d, /* cache, m */
0x75, 0x73, 0x74, 0x2d, 0x72, 0x65, 0x76, 0x61, /* ust-reva */
0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2c, 0x20, /* lidate,  */
0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, 0x3d, /* max-age= */
0x30, 0x0d, 0x0a, 0x4b, 0x65, 0x65, 0x70, 0x2d, /* 0..Keep- */
0x41, 0x6c, 0x69, 0x76, 0x65, 0x3a, 0x20, 0x43, /* Alive: C */
0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x0d, 0x0a  /* lose.... */
};

static int PUT_firstreply_size = 202;


static char GET_firstreply[638] = {
0x48, 0x54, /* HT */
0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, /* TP/1.1 2 */
0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x43, /* 00 OK..C */
0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, /* ontent-T */
0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, /* ype: tex */
0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3b, 0x20, /* t/html;  */
0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, /* charset= */
0x75, 0x74, 0x66, 0x2d, 0x38, 0x0d, 0x0a, 0x43, /* utf-8..C */
0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, /* ontent-L */
0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34, /* ength: 4 */
0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, /* ..Connec */
0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63, 0x6c, /* tion: cl */
0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x53, 0x74, 0x61, /* ose..Sta */
0x74, 0x75, 0x73, 0x3a, 0x20, 0x32, 0x30, 0x30, /* tus: 200 */
0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x58, 0x2d, 0x46, /*  OK..X-F */
0x72, 0x61, 0x6d, 0x65, 0x2d, 0x4f, 0x70, 0x74, /* rame-Opt */
0x69, 0x6f, 0x6e, 0x73, 0x3a, 0x20, 0x41, 0x4c, /* ions: AL */
0x4c, 0x4f, 0x57, 0x41, 0x4c, 0x4c, 0x0d, 0x0a, /* LOWALL.. */
0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x2d, 0x43, /* Access-C */
0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x41, /* ontrol-A */
0x6c, 0x6c, 0x6f, 0x77, 0x2d, 0x4f, 0x72, 0x69, /* llow-Ori */
0x67, 0x69, 0x6e, 0x3a, 0x20, 0x2a, 0x0d, 0x0a, /* gin: *.. */
0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x2d, 0x43, /* Access-C */
0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x41, /* ontrol-A */
0x6c, 0x6c, 0x6f, 0x77, 0x2d, 0x4d, 0x65, 0x74, /* llow-Met */
0x68, 0x6f, 0x64, 0x73, 0x3a, 0x20, 0x47, 0x45, /* hods: GE */
0x54, 0x2c, 0x20, 0x50, 0x4f, 0x53, 0x54, 0x2c, /* T, POST, */
0x20, 0x50, 0x55, 0x54, 0x2c, 0x20, 0x4f, 0x50, /*  PUT, OP */
0x54, 0x49, 0x4f, 0x4e, 0x53, 0x2c, 0x20, 0x44, /* TIONS, D */
0x45, 0x4c, 0x45, 0x54, 0x45, 0x2c, 0x20, 0x50, /* ELETE, P */
0x41, 0x54, 0x43, 0x48, 0x0d, 0x0a, 0x41, 0x63, /* ATCH..Ac */
0x63, 0x65, 0x73, 0x73, 0x2d, 0x43, 0x6f, 0x6e, /* cess-Con */
0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x41, 0x6c, 0x6c, /* trol-All */
0x6f, 0x77, 0x2d, 0x48, 0x65, 0x61, 0x64, 0x65, /* ow-Heade */
0x72, 0x73, 0x3a, 0x20, 0x6f, 0x72, 0x69, 0x67, /* rs: orig */
0x69, 0x6e, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x74, /* in, cont */
0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, /* ent-type */
0x2c, 0x20, 0x58, 0x2d, 0x52, 0x65, 0x71, 0x75, /* , X-Requ */
0x65, 0x73, 0x74, 0x65, 0x64, 0x2d, 0x57, 0x69, /* ested-Wi */
0x74, 0x68, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, /* th..Acce */
0x73, 0x73, 0x2d, 0x43, 0x6f, 0x6e, 0x74, 0x72, /* ss-Contr */
0x6f, 0x6c, 0x2d, 0x4d, 0x61, 0x78, 0x2d, 0x41, /* ol-Max-A */
0x67, 0x65, 0x3a, 0x20, 0x31, 0x38, 0x30, 0x30, /* ge: 1800 */
0x0d, 0x0a, 0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, /* ..ETag:  */
0x22, 0x36, 0x30, 0x35, 0x39, 0x38, 0x32, 0x38, /* "6059828 */
0x32, 0x63, 0x65, 0x36, 0x38, 0x32, 0x38, 0x66, /* 2ce6828f */
0x36, 0x38, 0x35, 0x34, 0x35, 0x34, 0x64, 0x66, /* 685454df */
0x66, 0x39, 0x62, 0x35, 0x65, 0x66, 0x34, 0x66, /* f9b5ef4f */
0x64, 0x22, 0x0d, 0x0a, 0x43, 0x61, 0x63, 0x68, /* d"..Cach */
0x65, 0x2d, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, /* e-Contro */
0x6c, 0x3a, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61, /* l: max-a */
0x67, 0x65, 0x3d, 0x30, 0x2c, 0x20, 0x70, 0x72, /* ge=0, pr */
0x69, 0x76, 0x61, 0x74, 0x65, 0x2c, 0x20, 0x6d, /* ivate, m */
0x75, 0x73, 0x74, 0x2d, 0x72, 0x65, 0x76, 0x61, /* ust-reva */
0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x0d, 0x0a, /* lidate.. */
0x58, 0x2d, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, /* X-Reques */
0x74, 0x2d, 0x49, 0x64, 0x3a, 0x20, 0x30, 0x30, /* t-Id: 00 */
0x63, 0x61, 0x64, 0x31, 0x30, 0x36, 0x2d, 0x61, /* cad106-a */
0x32, 0x34, 0x35, 0x2d, 0x34, 0x61, 0x39, 0x34, /* 245-4a94 */
0x2d, 0x39, 0x61, 0x39, 0x36, 0x2d, 0x35, 0x31, /* -9a96-51 */
0x37, 0x37, 0x66, 0x62, 0x61, 0x64, 0x34, 0x62, /* 77fbad4b */
0x35, 0x64, 0x0d, 0x0a, 0x58, 0x2d, 0x52, 0x75, /* 5d..X-Ru */
0x6e, 0x74, 0x69, 0x6d, 0x65, 0x3a, 0x20, 0x30, /* ntime: 0 */
0x2e, 0x36, 0x34, 0x33, 0x37, 0x35, 0x30, 0x0d, /* .643750. */
0x0a, 0x58, 0x2d, 0x50, 0x6f, 0x77, 0x65, 0x72, /* .X-Power */
0x65, 0x64, 0x2d, 0x42, 0x79, 0x3a, 0x20, 0x50, /* ed-By: P */
0x68, 0x75, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x50, /* husion P */
0x61, 0x73, 0x73, 0x65, 0x6e, 0x67, 0x65, 0x72, /* assenger */
0x20, 0x34, 0x2e, 0x30, 0x2e, 0x35, 0x37, 0x0d, /*  4.0.57. */
0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x54, /* .Date: T */
0x75, 0x65, 0x2c, 0x20, 0x32, 0x34, 0x20, 0x4d, /* ue, 24 M */
0x61, 0x79, 0x20, 0x32, 0x30, 0x31, 0x36, 0x20, /* ay 2016  */
0x32, 0x33, 0x3a, 0x32, 0x36, 0x3a, 0x33, 0x31, /* 23:26:31 */
0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65, /*  GMT..Se */
0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x6e, 0x67, /* rver: ng */
0x69, 0x6e, 0x78, 0x2f, 0x31, 0x2e, 0x39, 0x2e, /* inx/1.9. */
0x33, 0x20, 0x2b, 0x20, 0x50, 0x68, 0x75, 0x73, /* 3 + Phus */
0x69, 0x6f, 0x6e, 0x20, 0x50, 0x61, 0x73, 0x73, /* ion Pass */
0x65, 0x6e, 0x67, 0x65, 0x72, 0x20, 0x34, 0x2e, /* enger 4. */
0x30, 0x2e, 0x35, 0x37, 0x0d, 0x0a, 0x0d, 0x0a, /* 0.57.... */
0x36, 0x38, 0x2e, 0x32                          /* 68.2 */
};

static int GET_firstreply_size = 638;


typedef struct HTTP_RESPONSE_STRUCT
{
    char          *http_response_pkt_data;
    int           http_response_pkt_size;
} HTTP_RESPONSE;


static HTTP_RESPONSE       http_response[2];

/* Set up the HTTP client global variables. */

#define         CLIENT_PACKET_SIZE  (800)
#define         CLIENT_PACKET_POOL_SIZE ((CLIENT_PACKET_SIZE + sizeof(NX_PACKET)) * 4)
ULONG           client_packet_pool_area[CLIENT_PACKET_POOL_SIZE/4 + 4];

static TX_THREAD       client_thread;
static NX_HTTP_CLIENT  my_client;
static NX_PACKET_POOL  client_pool;
static NX_IP           client_ip;
static UINT            error_counter = 0;

/* Set up the HTTP server global variables */

#define         SERVER_PACKET_SIZE  (800)
#define         SERVER_PACKET_POOL_SIZE ((SERVER_PACKET_SIZE + sizeof(NX_PACKET)) * 4)
ULONG           server_packet_pool_area[SERVER_PACKET_POOL_SIZE/4 + 4];

/* Define the IP thread stack areas.  */

ULONG           server_ip_thread_stack[2 * 1024 / sizeof(ULONG)];
ULONG           client_ip_thread_stack[2 * 1024 / sizeof(ULONG)];

/* Define the ARP cache areas.  */

ULONG             server_arp_space_area[512 / sizeof(ULONG)];
ULONG             client_arp_space_area[512 / sizeof(ULONG)];



static NX_TCP_SOCKET   server_socket;
static NX_PACKET_POOL  server_pool;
static TX_THREAD       server_thread;
static NX_IP           server_ip;
#ifdef __PRODUCT_NETXDUO__
static NXD_ADDRESS     server_ip_address;
#else
static ULONG           server_ip_address;
#endif

 
static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define HTTP_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)


static CHAR    *pointer;

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_get_put_referred_URI_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;

    error_counter = 0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    status = tx_thread_create(&server_thread, "HTTP Server thread", thread_server_entry, 5,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;
    
    /* Create the HTTP Client thread. */
    status = tx_thread_create(&client_thread, "HTTP Client", thread_client_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    /* Initialize the NetX system.  */
    nx_system_initialize();
    

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "HTTP Server Packet Pool", SERVER_PACKET_SIZE, 
                                    pointer , SERVER_PACKET_POOL_SIZE);

    pointer = pointer + SERVER_PACKET_POOL_SIZE;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, 
                          "HTTP Server IP", 
                          HTTP_SERVER_ADDRESS, 
                          0xFFFFFF00UL, 
                          &server_pool, _nx_ram_network_driver_1024,
                          pointer, DEMO_STACK_SIZE, 1);

    pointer = pointer + DEMO_STACK_SIZE;
    
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status =  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&server_ip);
    if (status)
        error_counter++;

    /* Set up the server's IPv4 address here. */
#ifdef __PRODUCT_NETXDUO__ 
    server_ip_address.nxd_ip_address.v4 = HTTP_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
#else
    server_ip_address = HTTP_SERVER_ADDRESS;
#endif

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "HTTP Client Packet Pool", CLIENT_PACKET_SIZE,
                                    pointer, CLIENT_PACKET_POOL_SIZE);

    pointer = pointer + CLIENT_PACKET_POOL_SIZE;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip, "HTTP Client IP", HTTP_CLIENT_ADDRESS, 
                          0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024,
                          pointer, DEMO_STACK_SIZE, 1);

    pointer = pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    status =  nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip);
    if (status)
        error_counter++;

        /* Save the memory pointer for the RAM disk.  */
    ram_disk_memory =  pointer;
}


void thread_client_entry(ULONG thread_input)
{

UINT            status;
NX_PACKET       *send_packet;

    /* wait for the server to set up */
    tx_thread_sleep(20);

    /* Format the RAM disk - the memory for the RAM disk was setup in 
      tx_application_define above.  This must be set up before the client(s) start
      sending requests. */
    status = fx_media_format(&ram_disk, 
                            _fx_ram_driver,         /* Driver entry               */
                            ram_disk_memory,        /* RAM disk memory pointer    */
                            media_memory,           /* Media buffer pointer       */
                            sizeof(media_memory),   /* Media buffer size          */
                            "MY_RAM_DISK",          /* Volume Name                */
                            1,                      /* Number of FATs             */
                            32,                     /* Directory Entries          */
                            0,                      /* Hidden sectors             */
                            256,                    /* Total sectors              */
                            128,                    /* Sector size                */
                            1,                      /* Sectors per cluster        */
                            1,                      /* Heads                      */
                            1);                     /* Sectors per track          */

    /* Check the media format status.  */
    if (status != FX_SUCCESS)
        error_counter++;

    /* Open the RAM disk.  */
    status =  fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, media_memory, sizeof(media_memory));

    if (status != FX_SUCCESS)
        error_counter++;

    /* Create an HTTP client instance.  */
    status = nx_http_client_create(&my_client, "HTTP Client", &client_ip, &client_pool, 1460);
    if (status)
        error_counter++;

    /* Upload the 1st file to the server domain. */
#ifdef __PRODUCT_NETXDUO__

    status =  nxd_http_client_put_start(&my_client, &server_ip_address, "http://www.abc.com/client_test.htm", 
                                            "name", "password", 103, 3 * NX_IP_PERIODIC_RATE);
#else

    status =  nx_http_client_put_start(&my_client, server_ip_address, "http://www.abc.com/client_test.htm", 
                                       "name", "password", 103, 3 * NX_IP_PERIODIC_RATE);
#endif

    if (status)
        error_counter++;
    
     /* Allocate a packet.  */
    status =  nx_packet_allocate(&client_pool, &send_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if(status)
    {
        error_counter++;
    }

    /* Build a simple 103-byte HTML page.  */
    nx_packet_data_append(send_packet, "<HTML>\r\n", 8, 
                        &client_pool, NX_WAIT_FOREVER);
    nx_packet_data_append(send_packet, 
                 "<HEAD><TITLE>NetX HTTP Test</TITLE></HEAD>\r\n", 44,
                        &client_pool, NX_WAIT_FOREVER);
    nx_packet_data_append(send_packet, "<BODY>\r\n", 8, 
                        &client_pool, NX_WAIT_FOREVER);
    nx_packet_data_append(send_packet, "<H1>Another NetX Test Page!</H1>\r\n", 25, 
                        &client_pool, NX_WAIT_FOREVER);
    nx_packet_data_append(send_packet, "</BODY>\r\n", 9,
                        &client_pool, NX_WAIT_FOREVER);
    nx_packet_data_append(send_packet, "</HTML>\r\n", 9,
                        &client_pool, NX_WAIT_FOREVER);

    /* Complete the PUT by writing the total length.  */
    status =  nx_http_client_put_packet(&my_client, send_packet, 1 * NX_IP_PERIODIC_RATE);
    if(status)
    {
        error_counter++;
    }
    
    tx_thread_sleep(10);
    
    /* Send the 1st GET request to the server. */  
#ifdef __PRODUCT_NETXDUO__ 

    status =  nxd_http_client_get_start(&my_client, &server_ip_address, "http://www.abc.com/client_test.htm", 
                                        NX_NULL, 0, "name", "password", 100);
#else

    status =  nx_http_client_get_start(&my_client, server_ip_address, "http://www.abc.com/client_test.htm", 
                                       NX_NULL, 0, "name", "password", 100);
#endif  /* USE_DUO */

    if(status)
    {
        error_counter++;
    }
    
    nx_http_client_delete(&my_client);

}


/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{

UINT         status;
NX_PACKET   *my_packet;

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP GET PUT Referred URI Test............................");

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
    status =  nx_tcp_server_socket_listen(&server_ip, SERVER_PORT, &server_socket, 5, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Load up the server 'responses'. */
    http_test_initialize();
        
    /* Wait for a connection request.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Receive a TCP packet.  */
    status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }       
    else
    {
        /* Release the packet.  */
        nx_packet_release(my_packet);
    }
                   
    /* Receive another TCP packet.  */
    status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {

        error_counter++;
    } 
    else
    {
        /* Release the packet.  */
        nx_packet_release(my_packet);
    }   
     
    tx_thread_sleep(20);
        
    /* Send the TCP response packet.  */
    nx_http_response_packet_send(&server_socket, 80, 0);
              
    nx_tcp_socket_disconnect(&server_socket, 500);
      
    /* Unaccept the server socket.  */               
    nx_tcp_server_socket_unaccept(&server_socket);

    nx_tcp_server_socket_relisten(&server_ip, SERVER_PORT, &server_socket);

    /* Wait for a 2nd connection request.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Receive a TCP packet.  */
    status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }       
    else
    {
        /* Release the packet.  */
        nx_packet_release(my_packet);
    }

    tx_thread_sleep(10);

    /* Send the TCP response packet.  */
    nx_http_response_packet_send(&server_socket, 80, 1);

    /* Wait for the client to terminate the connection. */
    tx_thread_sleep(20);
     
    /* Delete the TCP socket.  */
    nx_tcp_socket_delete(&server_socket);

    if(error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {

        printf("SUCCESS!\n");
        test_control_return(0);
    };
}


static void  http_test_initialize()
{

    http_response[0].http_response_pkt_data = &PUT_firstreply[0];
    http_response[0].http_response_pkt_size = PUT_firstreply_size;  
    
    http_response[1].http_response_pkt_data = &GET_firstreply[0];
    http_response[1].http_response_pkt_size = GET_firstreply_size;  

}


static UINT   nx_http_response_packet_send(NX_TCP_SOCKET *server_socket, UINT port, INT packet_number)
{
UINT        status;
NX_PACKET   *response_packet;


    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&server_pool, &response_packet, NX_TCP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Write the HTTP response messages into the packet payload!  */
    memcpy(response_packet -> nx_packet_prepend_ptr, http_response[packet_number].http_response_pkt_data, 
           http_response[packet_number].http_response_pkt_size);

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length =  http_response[packet_number].http_response_pkt_size;
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

    /* Send the TCP packet with the correct port.  */
    status =  nx_tcp_socket_send(server_socket, response_packet, 100);

    /* Check the status.  */
    if (status)      
        nx_packet_release(response_packet);         

    return status;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_get_put_referred_URI_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP GET PUT Referred URI Test............................N/A\n"); 

    test_control_return(3);  
}      
#endif
