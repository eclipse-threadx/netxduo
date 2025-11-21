/* This demonstrates sharing a port between an IPv4 and IPv6 TCP client socket to send 
   and receive packets (e.g emulates a socket that can send/receive iPv4 and Ipv6 packets)
   using a simulated Ethernet driver.  */

#include   "tx_api.h"
#include   "nx_api.h"


extern  void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6) && defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_client;
static TX_THREAD               thread_server;
static NX_PACKET_POOL          bsd_pool;
static NX_IP                   bsd_server_ip;
static NX_IP                   bsd_client_ip;
static NX_TCP_SOCKET           server_socket1;
static NX_TCP_SOCKET           server_socket2;

static UINT                    error_counter = 0;

#define CLIENT_ADDRESS      IP_ADDRESS(1,2,3,5)
#define SERVER_ADDRESS      IP_ADDRESS(1,2,3,4)
#define CLIENT_PORT         87


static char *requests[2] = {"Request1", "Request2"};
static char *responses[2] = {"Response1", "Response2"};
static UINT spin = NX_TRUE;

/* Define thread prototypes.  */

static  VOID    thread_client_entry(ULONG thread_input);
static  VOID    thread_server_entry(ULONG thread_input);
void            _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);



/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_clients_shared_port_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a BSD packet pool.  */
    status =  nx_packet_pool_create(&bsd_pool, "NetX BSD Packet Pool", 256, pointer, 16384);
    
    pointer = pointer + 16384;   
    if (status!= NX_SUCCESS)
    {
        error_counter++; 
    }

    /********************** Set up the Server IP instance **************************/

    /* Create a thread for server.  */
    status= tx_thread_create(&thread_server, "BSD App Server", thread_server_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status!= NX_SUCCESS)
    {
        error_counter++; 
    }
      
    /* Create an IP instance for the BSD Server.  */
    status = nx_ip_create(&bsd_server_ip, "NetX BSD Server", SERVER_ADDRESS, 0xFFFFFF00UL,  
                          &bsd_pool, _nx_ram_network_driver, pointer, DEMO_STACK_SIZE, 1);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status != NX_SUCCESS)
    {
        error_counter++; 
    }

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&bsd_server_ip);

    /* Enable ARP and supply ARP cache memory for BSD Server Instance */
    status +=  nx_arp_enable(&bsd_server_ip, (void *) pointer, 1024);
    
    pointer = pointer + 1024; 

    /* Check ARP enable status.  */     
    if (status)
    {
        error_counter++; 
    }

    pointer = pointer + 2048; 

    /********************** Set up the Client IP instance **************************/

    /* Create a thread for client.  */
    status= tx_thread_create(&thread_client, "BSD App Client", thread_client_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status!= NX_SUCCESS)
    {
        error_counter++; 
    }
      
    /* Create an IP instance for the BSD Client.  */
    status = nx_ip_create(&bsd_client_ip, "NetX BSD Client", CLIENT_ADDRESS, 0xFFFFFF00UL,  
                          &bsd_pool, _nx_ram_network_driver, pointer, DEMO_STACK_SIZE, 1);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status != NX_SUCCESS)
    {
        error_counter++; 
    }

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&bsd_client_ip);

    /* Enable ARP and supply ARP cache memory for BSD Client Instance */
    status +=  nx_arp_enable(&bsd_client_ip, (void *) pointer, 1024);
    
    pointer = pointer + 1024; 

    /* Check ARP enable status.  */     
    if (status)
    {
        error_counter++; 
    }

    /* Now initialize BSD Client IP.  */
    status = bsd_initialize (&bsd_client_ip, &bsd_pool, pointer, 2048, 4);

    /* Check for BSD errors.  */
    if (status)
    {
        error_counter++; 
    }

    return;
}



void    thread_client_entry(ULONG thread_input)
{

INT          status, sock_tcp_client, sock_tcp_client6;
struct       sockaddr_in echoClientAddr;  
struct       sockaddr_in echoServAddr;  
struct       sockaddr_in localAddr;   
struct       sockaddr_in6 echoServAddr6;               
struct       sockaddr_in6 echoClientAddr6;               
struct       sockaddr_in6 localAddr6;               
NXD_ADDRESS  ip_address;
UINT         address_index;
UINT         loopcount = 0;
CHAR         rcvBuffer[32];
INT          length;


    printf("NetX Test:   Basic BSD TCP Client Socket Shared Port Test............");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    memset(&echoClientAddr, 0, sizeof(echoClientAddr));

    memset(&echoClientAddr6, 0, sizeof(echoClientAddr6));

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&bsd_client_ip);
    if(status)
    {
        printf("ERROR!\n");
        error_counter++; 
    }

    /* Enable ICMPv6 */
    status = nxd_icmp_enable(&bsd_client_ip);
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set ip_0 interface address. */
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    ip_address.nxd_ip_address.v6[1] = 0xf101;
    ip_address.nxd_ip_address.v6[2] = 0;
    ip_address.nxd_ip_address.v6[3] = 0x1235;

    status = nxd_ipv6_address_set(&bsd_client_ip, 0, NX_NULL, 10, &address_index);

    status |= nxd_ipv6_address_set(&bsd_client_ip, 0, &ip_address, 64, &address_index);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for IPv6 stack to finish DAD process. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    echoClientAddr6.sin6_addr._S6_un._S6_u32[0] = htonl(0x20010db8);
    echoClientAddr6.sin6_addr._S6_un._S6_u32[1] = htonl(0xf101);
    echoClientAddr6.sin6_addr._S6_un._S6_u32[2] = 0x0;
    echoClientAddr6.sin6_addr._S6_un._S6_u32[3] = htonl(0x1235);
    echoClientAddr6.sin6_port = htons(CLIENT_PORT);
    echoClientAddr6.sin6_family = AF_INET6;


    echoServAddr6.sin6_addr._S6_un._S6_u32[0] = htonl(0x20010db8);
    echoServAddr6.sin6_addr._S6_un._S6_u32[1] = htonl(0xf101);
    echoServAddr6.sin6_addr._S6_un._S6_u32[2] = 0x0;
    echoServAddr6.sin6_addr._S6_un._S6_u32[3] = htonl(0x1234);
    echoServAddr6.sin6_port = htons(77);
    echoServAddr6.sin6_family = AF_INET6;

    /* Create BSD TCP IPv6 Client Socket */ 
    sock_tcp_client6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    if (sock_tcp_client6 == -1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Create BSD TCP IPv4 Client Socket */ 
    sock_tcp_client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock_tcp_client == -1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   

    echoClientAddr.sin_family = AF_INET;
    echoClientAddr.sin_port = htons(CLIENT_PORT);
    echoClientAddr.sin_addr.s_addr = htonl(CLIENT_ADDRESS);


    echoServAddr.sin_family = AF_INET;
    echoServAddr.sin_port = htons(76);
    echoServAddr.sin_addr.s_addr = htonl(SERVER_ADDRESS);

    /* Bind the IPv4 and IPv6 Client sockets. */
    status = bind (sock_tcp_client, (struct sockaddr *) &echoClientAddr, sizeof(echoClientAddr));
    status |= bind (sock_tcp_client6, (struct sockaddr *) &echoClientAddr6, sizeof(echoClientAddr6));
    if (status < 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Now connect to TCP server socket.  */
    status = connect(sock_tcp_client, (struct sockaddr *)&echoServAddr, sizeof(echoServAddr));
    if (status < 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    length = sizeof(localAddr);
    status = getsockname(sock_tcp_client, (struct sockaddr *)&localAddr, &length);
    if (localAddr.sin_port != htons(CLIENT_PORT))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status = connect(sock_tcp_client6, (struct sockaddr *)&echoServAddr6, sizeof(echoServAddr6));
    if (status < 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    length = sizeof(localAddr6);
    status = getsockname(sock_tcp_client6, (struct sockaddr *)&localAddr6, &length);
    if (localAddr6.sin6_port != htons(CLIENT_PORT))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* All set to accept client connections */

    /* Loop to handle IPv4 and IPv6 clients*/
    while(loopcount < 5)
    {

        /* Send data to server connected to specified client.  This demo assumes the
           server will receive and send in order of server #1 and server #2. This is
           ok since we only need to establish that BSD can emulate a socket that sends
           and receives IPv4 packets. */
        status = send(sock_tcp_client, requests[0], strlen(requests[0]), 0);

        if (status == ERROR)
        {
            error_counter++; 
        }


        /* Send data to server connected to specified client.  */
        status = send(sock_tcp_client6, requests[1], strlen(requests[1]), 0);

        if (status == ERROR )
        {
            error_counter++; 
        }
        status = recv(sock_tcp_client, (VOID *)rcvBuffer, 32, 0);
        if (status == ERROR)
        {
            error_counter++; 
        }

        status = recv(sock_tcp_client6, (VOID *)rcvBuffer, 32, 0);
        if (status == ERROR)
        {
            error_counter++; 
        }

        loopcount++;
    } 

    /* Stop the Server thread. */
    spin = NX_FALSE;

    /* Close down our sockets. */
    soc_close(sock_tcp_client);
    soc_close(sock_tcp_client6);

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else if(loopcount != 5)
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


/* Define the Server thread. */

void    thread_server_entry(ULONG thread_input)
{

INT          status;                                 
NXD_ADDRESS  server_ip_address;
UINT         address_index;
NX_PACKET    *packet_ptr4, *packet_ptr3, *packet_ptr2, *packet_ptr;


    /* Allow Netx to initialize the driver. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 5);

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&bsd_server_ip);
    if(status)
        test_control_return(1);

    /* Enable ICMPv6 */
    status = nxd_icmp_enable(&bsd_server_ip);
    if(status)
        test_control_return(1);

    /* Set Client IPv6 interface address. */
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    server_ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    server_ip_address.nxd_ip_address.v6[1] = 0x0000f101;
    server_ip_address.nxd_ip_address.v6[2] = 0;
    server_ip_address.nxd_ip_address.v6[3] = 0x1234;

    status = nxd_ipv6_address_set(&bsd_server_ip, 0, NX_NULL, 10, &address_index);

    status |= nxd_ipv6_address_set(&bsd_server_ip, 0, &server_ip_address, 64, &address_index);
    if (status)
        test_control_return(1);

    /* Time for duplicate address check. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Set Server IPv6 interface address. */
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    server_ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    server_ip_address.nxd_ip_address.v6[1] = 0x0000f101;
    server_ip_address.nxd_ip_address.v6[2] = 0;
    server_ip_address.nxd_ip_address.v6[3] = 0x1234;

    status = nx_tcp_socket_create(&bsd_server_ip, &server_socket1, "Server IPv4 Socket", 
                         NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                         100, NX_NULL, NX_NULL);

    status += nx_tcp_socket_create(&bsd_server_ip, &server_socket2, "Server IPv6 Socket", 
                         NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                         100, NX_NULL, NX_NULL);

    if (status )
    {
        test_control_return(1);
    }

    status = nx_tcp_server_socket_listen(&bsd_server_ip, 76, &server_socket1, 5, NX_NULL);
    status += nx_tcp_server_socket_listen(&bsd_server_ip, 77, &server_socket2, 5, NX_NULL);

    if (status )
    {
        test_control_return(1);
    }

    status = nx_tcp_server_socket_accept(&server_socket1, 4 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
    {
    
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_tcp_server_socket_accept(&server_socket2, 4 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
    {
    
        printf("ERROR!\n");
        test_control_return(1);
    }

    while(spin)
    {

        status = nx_tcp_socket_receive(&server_socket1, &packet_ptr3, 4 * NX_IP_PERIODIC_RATE);

        /* Check if the Client terminated the connection. */
        if (spin!= NX_TRUE)
        {
            /* It did, so let's bail. */
            break;
        }

        /* Otherwise we expect a packet. */
        if (status != NX_SUCCESS)
        {
            error_counter++;
        }
        else
        {
            nx_packet_release(packet_ptr3);
        }

        status = nx_tcp_socket_receive(&server_socket2, &packet_ptr4, 4 * NX_IP_PERIODIC_RATE);

        /* Check if the Client terminated the connection. */
        if (spin!= NX_TRUE)
        {
            /* It did, so let's bail. */
            break;
        }

        /* Here we expect a packet. */
        if(status != NX_SUCCESS)
        {
            error_counter++;
        }
        else
        {
            nx_packet_release(packet_ptr4);
        }

        status = nx_packet_allocate(&bsd_pool, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        if (status)
        {

            /* No packets available. Abort! */

            printf("ERROR!\n");
            test_control_return(1);
        }
        status = nx_packet_data_append(packet_ptr, responses[0], strlen(responses[0]),
                                        &bsd_pool, NX_NO_WAIT);
        if (status)
        {
            test_control_return(1);
        }

        status = nx_packet_allocate(&bsd_pool, &packet_ptr2, NX_TCP_PACKET, NX_NO_WAIT);
        if (status)
        {
            /* No packets available. Abort! */

            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_packet_data_append(packet_ptr2, responses[1], strlen(responses[1]),
                                        &bsd_pool, NX_NO_WAIT);
        if (status)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_tcp_socket_send(&server_socket1, packet_ptr, NX_IP_PERIODIC_RATE);

        if (status )
        {
            error_counter++;
            nx_packet_release(packet_ptr2);
        }

        status = nx_tcp_socket_send(&server_socket2, packet_ptr2, NX_IP_PERIODIC_RATE);

        if (status )
        {
            nx_packet_release(packet_ptr2);
            error_counter++;
        }
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    nx_tcp_socket_delete(&server_socket1); 
    nx_tcp_socket_delete(&server_socket2); 

  /* All done */
  return;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void  netx_bsd_tcp_clients_shared_port_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP Client Socket Shared Port Test............N/A");

    test_control_return(3);

}
#endif /* defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6) */



    
