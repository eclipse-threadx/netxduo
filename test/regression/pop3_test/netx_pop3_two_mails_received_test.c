/* 
   This is a small demo of POP3 Client on the high-performance NetX TCP/IP stack.  
   This demo relies on Thread, NetX and POP3 Client API to conduct 
   a POP3 mail session. 

   The POP3 'server' is a TCP socket that sends responses and downloads 2 mail items
   of three packets each.  
 */

#include  "tx_api.h"
#include  "nx_api.h"
#include    "nx_ram_network_driver_test_1500.h"
#include  "nxd_pop3_client.h"
extern   void  test_control_return(UINT);
#if !defined(NX_DISABLE_IPV4)

#define DEMO_STACK_SIZE             2048
#define SERVER_PORT                 110

static   UINT  error_counter = 0;
static   UINT  client_running = NX_TRUE;

extern   void  _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);
static   UINT  nx_pop3_response_packet_send(NX_TCP_SOCKET *server_socket_ptr, INT packet_number);
static   UINT  pop3_initialize_responses();

/* Set up Client thread entry point. */
static void    client_thread_entry(ULONG info);
/* Set up Server thread entry point. */
static void    server_thread_entry(ULONG info);


/* Set up the POP3 Client and POP3 server socket.  */

static TX_THREAD           client_thread;
static NX_POP3_CLIENT      pop3_client;
static NX_PACKET_POOL      client_packet_pool;
static NX_IP               client_ip;
static TX_THREAD           server_thread;
static NX_TCP_SOCKET       server_socket;
static NX_PACKET_POOL      server_packet_pool;
static NX_IP               server_ip;

/* Use the maximum size payload to insure no packets are dropped. */
#define PAYLOAD_SIZE 1514

/* Shared secret is the same as password. */

#define LOCALHOST                               "recipient@domain.com" 
#define LOCALHOST_PASSWORD                      "testpwd" 

typedef struct POP3_RESPONSE_STRUCT
{
    char          *pop3_response_pkt_data;
    int            pop3_response_pkt_size;
} POP3_RESPONSE;

#define NUM_RESPONSES      15
static  POP3_RESPONSE      pop3_response[NUM_RESPONSES];


static char greeting[115] = {
0x2b, 0x4f, /* ..\...+O */
0x4b, 0x20, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x65, /* K mail.e */
0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x6c, 0x6f, /* xpresslo */
0x67, 0x69, 0x63, 0x2e, 0x63, 0x6f, 0x6d, 0x20, /* gic.com  */
0x50, 0x4f, 0x50, 0x33, 0x20, 0x4d, 0x44, 0x61, /* POP3 MDa */
0x65, 0x6d, 0x6f, 0x6e, 0x20, 0x31, 0x35, 0x2e, /* emon 15. */
0x35, 0x2e, 0x33, 0x20, 0x72, 0x65, 0x61, 0x64, /* 5.3 read */
0x79, 0x20, 0x3c, 0x4d, 0x44, 0x41, 0x45, 0x4d, /* y <MDAEM */
0x4f, 0x4e, 0x2d, 0x46, 0x32, 0x30, 0x31, 0x36, /* ON-F2016 */
0x31, 0x30, 0x30, 0x34, 0x31, 0x31, 0x35, 0x32, /* 10041152 */
0x2e, 0x41, 0x41, 0x35, 0x32, 0x35, 0x36, 0x38, /* .AA52568 */
0x39, 0x30, 0x4d, 0x44, 0x31, 0x32, 0x30, 0x33, /* 90MD1203 */
0x40, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x65, 0x78, /* @mail.ex */
0x70, 0x72, 0x65, 0x73, 0x73, 0x6c, 0x6f, 0x67, /* presslog */
0x69, 0x63, 0x2e, 0x63, 0x6f, 0x6d, 0x3e, 0x0d, /* ic.com>. */
0x0a                                            /* . */
};

static int greeting_size = 115;

static char user_ok[47] = {
0x2b, 0x4f,                                     /* ...c..+O */
0x4b, 0x20, 0x74, 0x65, 0x73, 0x74, 0x72, 0x65, /* K testre */
0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x40, /* cipient@ */
0x65, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x6c, /* expressl */
0x6f, 0x67, 0x69, 0x63, 0x2e, 0x63, 0x6f, 0x6d, /* ogic.com */
0x2e, 0x2e, 0x2e, 0x20, 0x55, 0x73, 0x65, 0x72, /* ... User */
0x20, 0x6f, 0x6b, 0x0d, 0x0a                    /*  ok.. */
};

static int user_ok_size = 47;

static char password_ok[83] = {
0x2b, 0x4f, /* ...p..+O */
0x4b, 0x20, 0x74, 0x65, 0x73, 0x74, 0x72, 0x65, /* K testre */
0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x40, /* cipient@ */
0x65, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x6c, /* expressl */
0x6f, 0x67, 0x69, 0x63, 0x2e, 0x63, 0x6f, 0x6d, /* ogic.com */
0x27, 0x73, 0x20, 0x6d, 0x61, 0x69, 0x6c, 0x62, /* 's mailb */
0x6f, 0x78, 0x20, 0x68, 0x61, 0x73, 0x20, 0x31, /* ox has 1 */
0x20, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x20, 0x6d, /*  total m */
0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x20, /* essages  */
0x28, 0x31, 0x38, 0x37, 0x34, 0x30, 0x32, 0x20, /* (187402  */
0x6f, 0x63, 0x74, 0x65, 0x74, 0x73, 0x29, 0x0d, /* octets). */
0x0a                                            /* . */
};

static int password_ok_size = 83;

static char stat_ok[14] = {
0x2b, 0x4f, /* ..}...+O */
0x4b, 0x20, 0x32, 0x20, 0x31, 0x38, 0x37, 0x34, /* K 2 1874 */
0x30, 0x32, 0x0d, 0x0a                          /* 02.. */
};

static int stat_ok_size = 14;

static char retr_ok[19] = {
0x2b, 0x4f, /* ..Tv..+O */
0x4b, 0x20, 0x31, 0x38, 0x37, 0x34, 0x30, 0x32, /* K 187402 */
0x20, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x73, 0x0d, /*  octets. */
0x0a                                            /* . */
};

static int retr_ok_size = 19;


static char first_data_packet[82] = {
0x52, 0x65, /* ..G...Re */
0x74, 0x75, 0x72, 0x6e, 0x2d, 0x70, 0x61, 0x74, /* turn-pat */
0x68, 0x3a, 0x20, 0x3c, 0x74, 0x65, 0x73, 0x74, /* h: <test */
0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, /* recipien */
0x74, 0x74, 0x65, 0x73, 0x74, 0x32, 0x40, 0x67, /* ttest2@g */
0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, /* mail.com */
0x3e, 0x0d, 0x0a, 0x41, 0x75, 0x74, 0x68, 0x65, /* >..Authe */
0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, /* nticatio */
0x6e, 0x2d, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, /* n-Result */
0x73, 0x3a, 0x20, 0x65, 0x78, 0x70, 0x72, 0x65, /* s: expre */
0x73, 0x73, 0x6c, 0x6f, 0x67, 0x69, 0x63, 0x2e
};

static int first_data_packet_size = 82;

static char second_data_packet[82] = {
0x65, 0x64, /* ......ed */
0x3b, 0x0d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, /* ;..      */
0x20, 0x20, 0x20, 0x64, 0x3d, 0x67, 0x6d, 0x61, /*    d=gma */
0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x3b, 0x20, /* il.com;  */
0x73, 0x3d, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, /* s=201201 */
0x31, 0x33, 0x3b, 0x0d, 0x0a, 0x20, 0x20, 0x20, /* 13;..    */
0x20, 0x20, 0x20, 0x20, 0x20, 0x68, 0x3d, 0x63, /*      h=c */
0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, /* ontent-t */
0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, /* ransfer- */
0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, /* encoding */
0x3a, 0x66, 0x72, 0x6f, 0x6d, 0x3a, 0x6d, 0x69
};

static int second_data_packet_size = 82;

static char last_data_packet[82] = {
0x65, 0x64, /* ......ed */
0x3b, 0x0d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, /* ;..      */
0x20, 0x20, 0x20, 0x64, 0x3d, 0x67, 0x6d, 0x61, /*    d=gma */
0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x3b, 0x20, /* il.com;  */
0x73, 0x3d, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, /* s=201201 */
0x31, 0x33, 0x3b, 0x0d, 0x0a, 0x20, 0x20, 0x20, /* 13;..    */
0x20, 0x20, 0x20, 0x20, 0x20, 0x68, 0x3d, 0x63, /*      h=c */
0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, /* ontent-t */
0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, /* ransfer- */
0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, /* encoding */
0x3a, 0x66, 0x72, 0x0d, 0x0a, 0x2e, 0x0d, 0x0a
};

static int last_data_packet_size = 82;

static char dele_ok[23] = {
0x2b, 0x4f, /* ......+O */
0x4b, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, /* K messag */
0x65, 0x20, 0x31, 0x20, 0x64, 0x65, 0x6c, 0x65, /* e 1 dele */
0x74, 0x65, 0x64, 0x0d, 0x0a                    /* ted.. */
};


static int dele_ok_size = 23;


static char retr_ok2[19] = {
0x2b, 0x4f, /* ..Tv..+O */
0x4b, 0x20, 0x31, 0x38, 0x37, 0x34, 0x30, 0x32, /* K 187402 */
0x20, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x73, 0x0d, /*  octets. */
0x0a                                            /* . */
};

static int retr_ok2_size = 19;


static char first_data_packet2[82] = {
0x52, 0x65, /* ..G...Re */
0x74, 0x75, 0x72, 0x6e, 0x2d, 0x70, 0x61, 0x74, /* turn-pat */
0x68, 0x3a, 0x20, 0x3c, 0x74, 0x65, 0x73, 0x74, /* h: <test */
0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, /* recipien */
0x74, 0x74, 0x65, 0x73, 0x74, 0x32, 0x40, 0x67, /* ttest2@g */
0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, /* mail.com */
0x3e, 0x0d, 0x0a, 0x41, 0x75, 0x74, 0x68, 0x65, /* >..Authe */
0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, /* nticatio */
0x6e, 0x2d, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, /* n-Result */
0x73, 0x3a, 0x20, 0x65, 0x78, 0x70, 0x72, 0x65, /* s: expre */
0x73, 0x73, 0x6c, 0x6f, 0x67, 0x69, 0x63, 0x2e
};

static int first_data_packet2_size = 82;

static char second_data_packet2[82] = {
0x65, 0x64, /* ......ed */
0x3b, 0x0d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, /* ;..      */
0x20, 0x20, 0x20, 0x64, 0x3d, 0x67, 0x6d, 0x61, /*    d=gma */
0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x3b, 0x20, /* il.com;  */
0x73, 0x3d, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, /* s=201201 */
0x31, 0x33, 0x3b, 0x0d, 0x0a, 0x20, 0x20, 0x20, /* 13;..    */
0x20, 0x20, 0x20, 0x20, 0x20, 0x68, 0x3d, 0x63, /*      h=c */
0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, /* ontent-t */
0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, /* ransfer- */
0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, /* encoding */
0x3a, 0x66, 0x72, 0x6f, 0x6d, 0x3a, 0x6d, 0x69
};

static int second_data_packet2_size = 82;

static char last_data_packet2[82] = {
0x65, 0x64, /* ......ed */
0x3b, 0x0d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, /* ;..      */
0x20, 0x20, 0x20, 0x64, 0x3d, 0x67, 0x6d, 0x61, /*    d=gma */
0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x3b, 0x20, /* il.com;  */
0x73, 0x3d, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, /* s=201201 */
0x31, 0x33, 0x3b, 0x0d, 0x0a, 0x20, 0x20, 0x20, /* 13;..    */
0x20, 0x20, 0x20, 0x20, 0x20, 0x68, 0x3d, 0x63, /*      h=c */
0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, /* ontent-t */
0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, /* ransfer- */
0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, /* encoding */
0x3a, 0x66, 0x72, 0x0d, 0x0a, 0x2e, 0x0d, 0x0a
};

static int last_data_packet2_size = 82;

static char dele_ok2[23] = {
0x2b, 0x4f, /* ......+O */
0x4b, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, /* K messag */
0x65, 0x20, 0x31, 0x20, 0x64, 0x65, 0x6c, 0x65, /* e 1 dele */
0x74, 0x65, 0x64, 0x0d, 0x0a                    /* ted.. */
};


static int dele_ok2_size = 23;



static char quit_ok[93] = {
0x2b, 0x4f, /* ......+O */
0x4b, 0x20, 0x74, 0x65, 0x73, 0x74, 0x72, 0x65, /* K testre */
0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x40, /* cipient@ */
0x65, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x6c, /* expressl */
0x6f, 0x67, 0x69, 0x63, 0x2e, 0x63, 0x6f, 0x6d, /* ogic.com */
0x20, 0x65, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, /*  express */
0x6c, 0x6f, 0x67, 0x69, 0x63, 0x2e, 0x63, 0x6f, /* logic.co */
0x6d, 0x20, 0x50, 0x4f, 0x50, 0x33, 0x20, 0x53, /* m POP3 S */
0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, /* erver si */
0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x6f, 0x66, /* gning of */
0x66, 0x20, 0x28, 0x6d, 0x61, 0x69, 0x6c, 0x62, /* f (mailb */
0x6f, 0x78, 0x20, 0x65, 0x6d, 0x70, 0x74, 0x79, /* ox empty */
0x29, 0x0d, 0x0a                                /* ).. */
};

static int quit_ok_size = 93;


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_pop3_two_mails_received_test_application_define(void *first_unused_memory)
#endif
{

UINT     status;
UCHAR   *free_memory_pointer;

    
    /* Setup the working pointer.  */
    free_memory_pointer =  (UCHAR *) first_unused_memory;

    /* Initialize NetX.  */
    nx_system_initialize();
    
    /* Create the Server thread.  */
    status = tx_thread_create(&server_thread, "Server thread ", server_thread_entry, 0,  
                              free_memory_pointer, DEMO_STACK_SIZE, 
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    free_memory_pointer = free_memory_pointer + DEMO_STACK_SIZE ;

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_packet_pool, "Server Packet Pool", PAYLOAD_SIZE, free_memory_pointer , PAYLOAD_SIZE*10);

    free_memory_pointer = free_memory_pointer + PAYLOAD_SIZE*10;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, 
                          "Server IP", 
                          IP_ADDRESS(1,2,3,4), 
                          0xFFFFFF00UL, 
                          &server_packet_pool, _nx_ram_network_driver_1024,
                          free_memory_pointer, DEMO_STACK_SIZE, 1);

    free_memory_pointer = free_memory_pointer + DEMO_STACK_SIZE;
    
    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
    
    /* Enable ARP and supply ARP cache memory. */
    nx_arp_enable(&server_ip, (void *) free_memory_pointer, 1024);

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer = free_memory_pointer + 1024;
    
    /* Enable TCP and ICMP for Server IP. */
    nx_tcp_enable(&server_ip);
    nx_icmp_enable(&server_ip);

    /* Create a client thread.  */
    tx_thread_create(&client_thread, "Client", client_thread_entry, 0,  
                     free_memory_pointer, DEMO_STACK_SIZE, 1, 1, 
                     TX_NO_TIME_SLICE, TX_AUTO_START);

    free_memory_pointer =  free_memory_pointer + DEMO_STACK_SIZE;

    /* The demo client username and password is the authentication 
       data used when the server attempts to authentication the client. */

    /* Create Client packet pool. */
    status =  nx_packet_pool_create(&client_packet_pool, "POP3 Client Packet Pool", 
                                    PAYLOAD_SIZE, free_memory_pointer, (PAYLOAD_SIZE * 10));
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer = free_memory_pointer + (PAYLOAD_SIZE * 10);    

    /* Create IP instance for demo Client */
    status = nx_ip_create(&client_ip, "POP3 Client IP Instance", IP_ADDRESS(1,2,3,5), 0xFFFFFF00UL, 
                          &client_packet_pool, _nx_ram_network_driver_1024, free_memory_pointer, 
                          2048, 1);

    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer =  free_memory_pointer + 2048;

    /* Enable ARP and supply ARP cache memory. */
    nx_arp_enable(&client_ip, (void *) free_memory_pointer, 1024);

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer = free_memory_pointer + 1024;
    
    /* Enable TCP and ICMP for Client IP. */
    nx_tcp_enable(&client_ip);
    nx_icmp_enable(&client_ip);

    return;
}

/* Define the server thread.  */
void    server_thread_entry(ULONG thread_input)
{

UINT         status;
NX_PACKET   *my_packet;
UINT         receive_packet;
UINT         i =0;

    /* Print out test information banner.  */
    printf("NetX Test:   POP3 Two Mail Items Received Test........................."); 

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        error_counter++;
    }

    /* Create a socket as the  server.  */
    status = nx_tcp_socket_create(&server_ip, &server_socket, "Socket Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,  NX_IP_TIME_TO_LIVE, 2048, NX_NULL, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Load up the server 'responses'. */
    pop3_initialize_responses();
    
    /* Bind the TCP socket to the POP3 port.  */
    status =  nx_tcp_server_socket_listen(&server_ip, 110, &server_socket, 5, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }
    
    /* Wait for a connection request.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Wait for Client requests */
    while ( i < NUM_RESPONSES )
    {
           
         /* Default TCP server not to send a packet. */
        receive_packet = NX_TRUE;
        
        status = nx_pop3_response_packet_send(&server_socket, i);

        /* Check status.  */
        if (status)
        {
            error_counter++;
        }
        
        /* If this is the QUIT response, we're done */
        if (i == 14)
        {
            break;
        }
        

        /* In these iterations, the server sends a packet without expecting a
           response.  */
        if (
            (i == 4) ||
            (i == 5) ||
            (i == 6) ||
            (i == 9) ||
            (i == 10) ||
            (i == 11) 
            )
        {

            /* Set the flag not to receive a packet. */
            receive_packet = NX_FALSE;
        }
        
        /* TCP server expects to receive a packet. */
        if (receive_packet)
        {   
            
            status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

            /* Check status.  */
            if (status)
            {
                error_counter++;
            }
            else
            {
                nx_packet_release(my_packet);
            }
        }  
        
        /* Advance the index for the next response. */
        i++;
    } 

    /* Wait for the client to terminate the connection. */
    while(client_running == NX_TRUE)
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


/* Define the application thread entry function. */

void    client_thread_entry(ULONG info)
{

UINT        status;
UINT        mail_item, number_mail_items; 
UINT        bytes_downloaded = 0;
UINT        final_packet = NX_FALSE;
ULONG       total_size, mail_item_size, bytes_retrieved;
NX_PACKET   *packet_ptr;

    NX_PARAMETER_NOT_USED(info);

    /* Let the IP instance get initialized with driver parameters. */
    tx_thread_sleep(10);

    /* Create a NetX POP3 Client instance with no byte or block memory pools. 
       Note that it uses its password for its APOP shared secret. */
    status =  nx_pop3_client_create(&pop3_client,
                                    NX_FALSE /* if true, enables Client to send APOP command to authenticate */,
                                    &client_ip, &client_packet_pool, IP_ADDRESS(1,2,3,4), 110,
                                    LOCALHOST, LOCALHOST_PASSWORD);

    /* Check for error. */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Find out how many items are in our mailbox.  */
    status = nx_pop3_client_mail_items_get(&pop3_client, &number_mail_items, &total_size);

    /* If nothing in the mailbox, disconnect. */
    if (number_mail_items == 0)
    {
        error_counter++;
    }
   
    /* Download all mail items.  */
    mail_item = 1; 

    while (mail_item <= number_mail_items)
    {

        /* This submits a RETR request and gets the mail message size. */
        status = nx_pop3_client_mail_item_get(&pop3_client, mail_item, &mail_item_size);

        /* Loop to get the next mail message packet until the last mail item 
           packet is downloaded. */
        do
        {

            status = nx_pop3_client_mail_item_message_get(&pop3_client, &packet_ptr, 
                                                        &bytes_retrieved, 
                                                        &final_packet); 

            if (status != NX_SUCCESS)
            {
                break;
            }

            nx_packet_release(packet_ptr);

            /* Determine if this is the last data packet. */
            if (final_packet)
            {
                /* It is. Let the server know it can delete this mail item. */
                status = nx_pop3_client_mail_item_delete(&pop3_client, mail_item);

                if (status != NX_SUCCESS)
                {
                    break;
                }
            }

            /* Keep track of how much mail message data is left. */
            bytes_downloaded += bytes_retrieved;

        } while (final_packet == NX_FALSE);

        /* Get the next mail item. */
        mail_item++;

        /* Clear the download size before downloading the next mail item. */
        bytes_downloaded = 0;

        tx_thread_sleep(10);
    }

    /* Tell the POP3 server we're leaving the session. This sends the QUIT command. */
    status = nx_pop3_client_quit(&pop3_client);

    if (status) 
    {
        error_counter++;
    }
    
    client_running = NX_FALSE;
    
    /* Disconnect and delete the POP3 Client.  */
    nx_pop3_client_delete(&pop3_client);
    
}

static UINT   nx_pop3_response_packet_send(NX_TCP_SOCKET *server_socket_ptr, INT packet_number)
{

UINT        status;
NX_PACKET   *response_packet;

    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&server_packet_pool, &response_packet, NX_TCP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Write the  response messages into the packet payload!  */
      memcpy(response_packet -> nx_packet_prepend_ptr, pop3_response[packet_number].pop3_response_pkt_data, 
             pop3_response[packet_number].pop3_response_pkt_size);

     response_packet -> nx_packet_length =  pop3_response[packet_number].pop3_response_pkt_size;

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;
       
    /* Send the  packet with the correct port.  */
    status = nx_tcp_socket_send(server_socket_ptr, response_packet, 100);

    /* Check the status.  */
    if (status)      
    {
    
        error_counter++;
    }

    return status;
}

static UINT pop3_initialize_responses()
{

    pop3_response[0].pop3_response_pkt_data = &greeting[0];
    pop3_response[0].pop3_response_pkt_size = greeting_size ;  

    pop3_response[1].pop3_response_pkt_data = &user_ok[0];
    pop3_response[1].pop3_response_pkt_size = user_ok_size ;  

    pop3_response[2].pop3_response_pkt_data = &password_ok[0];
    pop3_response[2].pop3_response_pkt_size = password_ok_size ;  

    pop3_response[3].pop3_response_pkt_data = &stat_ok[0];
    pop3_response[3].pop3_response_pkt_size = stat_ok_size ;  

    pop3_response[4].pop3_response_pkt_data = &retr_ok[0];
    pop3_response[4].pop3_response_pkt_size = retr_ok_size ;  

    pop3_response[5].pop3_response_pkt_data = &first_data_packet[0];
    pop3_response[5].pop3_response_pkt_size = first_data_packet_size ;  

    pop3_response[6].pop3_response_pkt_data = &second_data_packet[0];
    pop3_response[6].pop3_response_pkt_size = second_data_packet_size ;  

    pop3_response[7].pop3_response_pkt_data = &last_data_packet[0];
    pop3_response[7].pop3_response_pkt_size = last_data_packet_size ;  

    pop3_response[8].pop3_response_pkt_data = &dele_ok[0];
    pop3_response[8].pop3_response_pkt_size = dele_ok_size ;  

   
    pop3_response[9].pop3_response_pkt_data = &retr_ok2[0];
    pop3_response[9].pop3_response_pkt_size = retr_ok2_size ;  

    pop3_response[10].pop3_response_pkt_data = &first_data_packet2[0];
    pop3_response[10].pop3_response_pkt_size = first_data_packet2_size ;  

    pop3_response[11].pop3_response_pkt_data = &second_data_packet2[0];
    pop3_response[11].pop3_response_pkt_size = second_data_packet2_size ;  

    pop3_response[12].pop3_response_pkt_data = &last_data_packet2[0];
    pop3_response[12].pop3_response_pkt_size = last_data_packet2_size ;  

    pop3_response[13].pop3_response_pkt_data = &dele_ok2[0];
    pop3_response[13].pop3_response_pkt_size = dele_ok2_size ; 
    

    pop3_response[14].pop3_response_pkt_data = &quit_ok[0];
    pop3_response[14].pop3_response_pkt_size = quit_ok_size ; 
    
    return NX_SUCCESS;
}


#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_pop3_two_mails_received_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   POP3 Two Mail Items Received Test.........................N/A\n"); 

    test_control_return(3);  
}      
#endif
