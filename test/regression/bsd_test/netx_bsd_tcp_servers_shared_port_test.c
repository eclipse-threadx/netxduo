/* This demoonstrates sharing a port between an IPv4 and IPv6 TCP server socket to send 
   and receive packets (e.g emulates a socket that can send/receive iPv4 and Ipv6 packets)
   using a simulated Ethernet driver.  */

#include   "tx_api.h"
#include   "nx_api.h"


extern  void  test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6) && defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_client;
static TX_THREAD               thread_server;
static NX_PACKET_POOL          bsd_pool;
static NX_IP                   bsd_server_ip;
static NX_IP                   bsd_client_ip;
static NX_TCP_SOCKET           client_socket1;
static NX_TCP_SOCKET           client_socket2;

static UINT                    error_counter = 0;

#define CLIENT_ADDRESS      IP_ADDRESS(1,2,3,5)
#define SERVER_ADDRESS      IP_ADDRESS(1,2,3,4)
#define SERVER_PORT         87


static char *requests[2] = {"Request1", "Request2"};
static char *responses[2] = {"Response1", "Response2"};
static UINT spin = NX_TRUE;

/* Define thread prototypes.  */

INT     HandleClient(INT  clientsock);
static  VOID    thread_client_entry(ULONG thread_input);
static  VOID    thread_server_entry(ULONG thread_input);
VOID    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_servers_shared_port_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a BSD packet pool.  */
    status =  nx_packet_pool_create(&bsd_pool, "NetX BSD Packet Pool", 1516, pointer, 16384);
    
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

    /* Now initialize BSD Server IP.  */
    status = bsd_initialize (&bsd_server_ip, &bsd_pool, pointer, 2048, 4);

    /* Check for BSD errors.  */
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

    return;
}



void    thread_server_entry(ULONG thread_input)
{

INT          hcstatus, sock, sock6, sock_tcp_server, sock_tcp_server6;
UINT         status;
struct       sockaddr_in6 echoServAddr6;               
struct       sockaddr_in echoServAddr;               
INT          Serverlen;
NXD_ADDRESS  ip_address;
UINT         address_index;
UINT         loopcount = 0;
INT          length;
struct       sockaddr_in localAddr;               
struct       sockaddr_in6 localAddr6;               


    printf("NetX Test:   Basic BSD TCP Server Socket Shared Port Test............");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE / 5);

    memset(&echoServAddr, 0, sizeof(echoServAddr));
    memset(&echoServAddr6, 0, sizeof(echoServAddr6));

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&bsd_server_ip);
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable ICMPv6 */
    status = nxd_icmp_enable(&bsd_server_ip);
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
    ip_address.nxd_ip_address.v6[3] = 0x1234;

    status = nxd_ipv6_address_set(&bsd_server_ip, 0, NX_NULL, 10, &address_index);

    status |= nxd_ipv6_address_set(&bsd_server_ip, 0, &ip_address, 64, &address_index);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for IPv6 stack to finish DAD process. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Create BSD TCP IPv6 Server Socket */ 
    sock_tcp_server6 = socket( AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    if (sock_tcp_server6 == -1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   

    echoServAddr6.sin6_addr._S6_un._S6_u32[0] = htonl(0x20010db8);
    echoServAddr6.sin6_addr._S6_un._S6_u32[1] = htonl(0xf101);
    echoServAddr6.sin6_addr._S6_un._S6_u32[2] = 0x0;
    echoServAddr6.sin6_addr._S6_un._S6_u32[3] = htonl(0x1234);
    echoServAddr6.sin6_port = htons(SERVER_PORT);
    echoServAddr6.sin6_family = AF_INET6;

    /* Create BSD TCP IPv4 Server Socket */ 
    sock_tcp_server = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock_tcp_server == -1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   

    echoServAddr.sin_family = AF_INET;
    echoServAddr.sin_port = htons(SERVER_PORT);
    echoServAddr.sin_addr.s_addr = htonl(SERVER_ADDRESS);

    /* Bind the IPv4 and IPv6 server sockets. */
    hcstatus = bind (sock_tcp_server, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr));
    hcstatus |= bind (sock_tcp_server6, (struct sockaddr *) &echoServAddr6, sizeof(echoServAddr6));
    if (hcstatus < 0)
    {
        test_control_return(1);
    }   

    /* Now listen for any client connections for these server sockets. */
    hcstatus = listen (sock_tcp_server, 5);
    if (hcstatus < 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    hcstatus = listen (sock_tcp_server6, 5);
    if (hcstatus < 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* All set to accept client connections */

    /* Loop to check for client connection requests.  */
    /* This assumes the IPv4 Client socket makes a connectin request before the IPv6 socket. */

    Serverlen = sizeof(echoServAddr);
    sock = accept(sock_tcp_server, (struct sockaddr *)&echoServAddr, &Serverlen);
    if ((sock == NX_SOC_ERROR) || (sock == NX_BSD_MAX_SOCKETS + NX_BSD_SOCKFD_START - 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    length = sizeof(localAddr);
    getsockname(sock_tcp_server, (struct sockaddr *)&localAddr, &length);
    if (localAddr.sin_port != htons(SERVER_PORT))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    Serverlen = sizeof(echoServAddr6);
    sock6 = accept(sock_tcp_server6, (struct sockaddr *)&echoServAddr6, &Serverlen);
    if ((sock6 == NX_SOC_ERROR) || (sock6 == NX_BSD_MAX_SOCKETS + NX_BSD_SOCKFD_START - 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    length = sizeof(localAddr6);
    getsockname(sock_tcp_server6, (struct sockaddr *)&localAddr6, &length);
    if (localAddr6.sin6_port != htons(SERVER_PORT))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Loop to send and receive IPv4 and IPv6 transmissions. */
    while(loopcount < 5)
    {

        hcstatus = HandleClient(sock);
        if (hcstatus == ERROR)
        {
            error_counter++;
        }

        hcstatus = HandleClient(sock6);
        if (hcstatus == ERROR)
        {
            error_counter++;
        }

        loopcount++;
    } 

    /* Stop the client thread. */
    spin = NX_FALSE;

    /* Close down our server sockets. */
    soc_close(sock6);
    soc_close(sock);

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


/* Define the Client thread. */

void    thread_client_entry(ULONG thread_input)
{

INT          status;                                 
NXD_ADDRESS  client_ip_address, server_ip_address;
UINT         address_index;
NX_PACKET    *packet_ptr4, *packet_ptr3, *packet_ptr2, *packet_ptr;


    /* Allow Netx to initialize the driver, also let the server get set up first. */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&bsd_client_ip);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable ICMPv6 */
    status = nxd_icmp_enable(&bsd_client_ip);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set Client IPv6 interface address. */
    client_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    client_ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    client_ip_address.nxd_ip_address.v6[1] = 0x0000f101;
    client_ip_address.nxd_ip_address.v6[2] = 0;
    client_ip_address.nxd_ip_address.v6[3] = 0x1235;

    status = nxd_ipv6_address_set(&bsd_client_ip, 0, NX_NULL, 10, &address_index);

    status |= nxd_ipv6_address_set(&bsd_client_ip, 0, &client_ip_address, 64, &address_index);
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Time for duplicate address check. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Set Server IPv6 interface address. */
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    server_ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    server_ip_address.nxd_ip_address.v6[1] = 0x0000f101;
    server_ip_address.nxd_ip_address.v6[2] = 0;
    server_ip_address.nxd_ip_address.v6[3] = 0x1234;

    status = nx_tcp_socket_create(&bsd_client_ip, &client_socket1, "Client IPv4 Socket", 
                         NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                         100, NX_NULL, NX_NULL);

    status += nx_tcp_socket_create(&bsd_client_ip, &client_socket2, "Client IPv4 Socket", 
                         NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                         100, NX_NULL, NX_NULL);

    if (status )
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_tcp_client_socket_bind(&client_socket1, NX_ANY_PORT, 100);
    status += nx_tcp_client_socket_bind(&client_socket2, NX_ANY_PORT, 100);

    if (status )
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_tcp_client_socket_connect(&client_socket1, SERVER_ADDRESS, SERVER_PORT, 200);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_tcp_client_socket_connect(&client_socket2, &server_ip_address, SERVER_PORT, 300);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    while(spin)
    {

        status = nx_packet_allocate(&bsd_pool, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        if (status )
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_packet_data_append(packet_ptr, requests[0], strlen(requests[0]),
                                        &bsd_pool, NX_NO_WAIT);

        if (status )
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_tcp_socket_send(&client_socket1, packet_ptr, 100);

        if (status )
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_packet_allocate(&bsd_pool, &packet_ptr2, NX_TCP_PACKET, NX_NO_WAIT);
        if (status )
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_packet_data_append(packet_ptr2, requests[1], strlen(requests[1]),
                                        &bsd_pool, NX_NO_WAIT);
        if (status )
        {
            printf("ERROR!\n");
            test_control_return(1);
        }


        status = nx_tcp_socket_send(&client_socket2, packet_ptr2, 100);

        if (status)
        {
            nx_packet_release(packet_ptr2);
            error_counter++;
        }

        status = nx_tcp_socket_receive(&client_socket1, &packet_ptr3, 200);
        if(status != NX_SUCCESS)
        {

            error_counter++;
        }
        else
        {
            nx_packet_release(packet_ptr3);
        }

        status = nx_tcp_socket_receive(&client_socket2, &packet_ptr4, 200);
        if(status != NX_SUCCESS)
        {

            error_counter++;
        }
        else
        {
            nx_packet_release(packet_ptr4);
        }
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    nx_tcp_socket_delete(&client_socket1); 
    nx_tcp_socket_delete(&client_socket2); 

    /* All done */
    return;
}


INT     HandleClient(INT  clientsock)
{

INT     status;
CHAR    rcvBuffer[32];


    status = recv(clientsock, (VOID *)rcvBuffer, 32, 0);
    if (status == ERROR )
    {
        return(ERROR);
    }

    /* a zero return from a recv() call indicates client is terminated! */
    if (status == 0)
    {

        return(ERROR); 
    }    

    /* And echo the same data to the client */
    status = send(clientsock, responses[clientsock % 2], strlen(responses[clientsock % 2]), 0);

    if (status == ERROR )
    {
        return(ERROR); 
    }

    return(NX_SUCCESS);            
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void  netx_bsd_tcp_servers_shared_port_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP Server Socket Shared Port Test............N/A");

    test_control_return(3);

}
#endif /* defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6) */




    
