/* This demoonstrates sharing a port between an IPv4 and IPv6 TCP server socket to send 
   and receive packets (e.g emulates a socket that can send/receive iPv4 and Ipv6 packets)
   using a simulated Ethernet driver.  */


#include   "tx_api.h"
#include   "nx_api.h"

extern  void  test_control_return(UINT status);
#if defined(FEATURE_NX_IPV6) && defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_client;
static TX_THREAD               thread_client6;
static TX_THREAD               thread_server;
static TX_THREAD               thread_server6;
static NX_PACKET_POOL          bsd_pool;
static NX_IP                   bsd_ip_server;
static NX_IP                   bsd_ip_client;
static NX_TCP_SOCKET           client_ipv6_socket;

static UINT                    error_counter = 0;

#define CLIENT_ADDRESS      IP_ADDRESS(1,2,3,5)
#define SERVER_ADDRESS      IP_ADDRESS(1,2,3,4)
#define SERVER_PORT         87

/* Define some global data. */
static UINT ipv4_complete = NX_FALSE;

/* Define thread prototypes.  */


static  VOID    thread_client_entry(ULONG thread_input);
static  VOID    thread_client6_entry(ULONG thread_input);
static  VOID    thread_server_entry(ULONG thread_input);
static  VOID    thread_server6_entry(ULONG thread_input);
VOID    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_servers_share_port_test_application_define(void *first_unused_memory)
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

    /* Create a thread for the IPv4 server.  */
    status= tx_thread_create(&thread_server, "BSD App IPv4 Server", thread_server_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status!= NX_SUCCESS)
    {
        error_counter++;
    }


    /* Create a thread for IPv6 server.  */
    status= tx_thread_create(&thread_server6, "BSD App IPv6 Server", thread_server6_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status!= NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create an IP instance for the BSD Server sockets.  */
    status = nx_ip_create(&bsd_ip_server, "NetX BSD Server", SERVER_ADDRESS, 0xFFFFFF00UL,  
                          &bsd_pool, _nx_ram_network_driver, pointer, DEMO_STACK_SIZE, 1);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&bsd_ip_server);

    /* Enable ARP and supply ARP cache memory for BSD  */
    status +=  nx_arp_enable(&bsd_ip_server, (void *) pointer, 1024);
    
    pointer = pointer + 1024; 

    /* Check ARP enable status.  */     
    if (status)
    {
        error_counter++;
    }

    /* Now initialize BSD IP.  */
    status = bsd_initialize (&bsd_ip_server, &bsd_pool, pointer, 2048, 4);

    /* Check for BSD errors.  */
    if (status)
    {
        error_counter++;
    }

    pointer = pointer + 2048; 

    /********************** Set up the Client  **************************/

    status = nx_ip_create(&bsd_ip_client, "NetX BSD Client", CLIENT_ADDRESS, 0xFFFFFF00UL,  
                          &bsd_pool, _nx_ram_network_driver, pointer, DEMO_STACK_SIZE, 1);


    pointer =  pointer + DEMO_STACK_SIZE;

    if (status!= NX_SUCCESS)
    {
        error_counter++;
    }


    /* Create a thread for IPv4 client.  */
    status= tx_thread_create(&thread_client, "BSD App IPpv4 Client", thread_client_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            16, 16, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status!= NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create a thread for IPv6 client.  */
    status= tx_thread_create(&thread_client6, "BSD App IPv6 Client", thread_client6_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            16, 16, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status!= NX_SUCCESS)
    {
        error_counter++;
    }     

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&bsd_ip_client);

    /* Enable ARP and supply ARP cache memory for BSD  */
    status +=  nx_arp_enable(&bsd_ip_client, (void *) pointer, 1024);
    
    pointer = pointer + 1024; 

    /* Check ARP enable status.  */     
    if (status)
    {
        error_counter++;
    }

    return;
}

/* Define the IPv4 server thread */
void    thread_server_entry(ULONG thread_input)
{

INT         status,  sock, sock_tcp_server;
ULONG       actual_status;
INT         Clientlen;
INT         i;
UINT        is_set = NX_FALSE;
struct      sockaddr_in serverAddr;                  
struct      sockaddr_in ClientAddr;
UINT        ipv4_server_complete = NX_FALSE;
INT         maxfd;
fd_set      master_list, read_ready;
CHAR        Server_Rcv_Buffer[100];


    if (error_counter) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE); /* Don't let the IPv4 connection finish before IPv6 connection is created. */

    status =  nx_ip_status_check(&bsd_ip_server, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE); 
    
    /* Check status...  */ 
    if (status != NX_SUCCESS) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create BSD TCP Socket */
    sock_tcp_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock_tcp_server == -1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set the server port and IP address */

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(IP_ADDRESS(1,2,3,4));
    serverAddr.sin_port = htons(SERVER_PORT);

    /* Bind this server socket */
    status = bind (sock_tcp_server, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

    if (status < 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    FD_ZERO(&master_list);
    FD_ZERO(&read_ready);
    FD_SET(sock_tcp_server,&master_list);
    maxfd = sock_tcp_server;

    /* Now listen for any client connections for this server socket */
    status = listen (sock_tcp_server, 5);
    if (status < 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* All set to accept client connections */
    /* Loop to create and establish server connections.  */
    do
    {

        read_ready = master_list;

        tx_thread_sleep(NX_IP_PERIODIC_RATE / 5);   /* Allow some time to other threads too */

        /* Let the underlying TCP stack determine the timeout. */
        status = select(maxfd + 1, &read_ready, 0, 0, 0);

        if ( (status == ERROR) || (status == 0) )
        {
            continue;
        }

        /* Detected a connection request. */
        is_set = FD_ISSET(sock_tcp_server,&read_ready);

        if(is_set)
        {
        
            Clientlen = sizeof(ClientAddr);

            sock = accept(sock_tcp_server,(struct sockaddr*)&ClientAddr, &Clientlen);

            /* Add this new connection to our master list */
            FD_SET(sock, &master_list);   

            if ( sock > maxfd)
            {
                maxfd = sock;
            }   

            continue; 
        }

        /* Check the set of 'ready' sockets, e.g connected to remote host and waiting for
           notice of packets received. */
        for (i = 0; i < (maxfd+1); i++)
        {

            if (((i+ NX_BSD_SOCKFD_START) != sock_tcp_server) && 
                 (FD_ISSET(i + NX_BSD_SOCKFD_START, &master_list)) && 
                 (FD_ISSET(i + NX_BSD_SOCKFD_START, &read_ready)))
            {

                while(1)
                {

                    status = recv(i + NX_BSD_SOCKFD_START, (VOID *)Server_Rcv_Buffer, 100, 0);
            
                    if (status == ERROR)
                    {
                        /* This is a blocking socket. If no data is received, but the connection is still good,
                           the EAGAIN error is set. If it was a non blocking socket, the EWOULDBLOCK socket 
                           error is set. */
                        if (errno == EAGAIN) 
                        {
                            continue;
                        }
                        else if (errno == ENOTCONN) 
                        {
                            /* If the socket connection is terminated, the socket error will be ENOTCONN. */
                            break;
                        }
                        else
                        {
                            /* Another error has occurred...probably an internal error of some kind
                               so best to terminate the connection. */
                            error_counter++; 
                            break;
                        }                    
                    }
                    else if (status == 0)
                    {

                        /* If the socket connection is terminated, the socket error will be ENOTCONN. */
                        break;
                    }

                    tx_thread_sleep(NX_IP_PERIODIC_RATE);
                    status = send(i + NX_BSD_SOCKFD_START, "Hello from IPv4\n", strlen("Hello from IPv4\n")+1, 0);
            
                    if (status == ERROR)
                    {
                        if (errno == ENOTCONN)
                        {

                            /* If the socket connection is terminated, the socket error will be ENOTCONN. */
                            break;
                        }
                        else
                        {
                        
                            error_counter++;
                            break;
                        }
                    }
                }
            
                /* Close this socket */   
                status = soc_close(i+ NX_BSD_SOCKFD_START);

                if (status == ERROR)
                {
                
                    error_counter++;
                }

                /* Indicate the IPv4 server socket is closed. */
                ipv4_server_complete = NX_TRUE;
                break;
            }    
        }   

        /* Loop back to check any next client connection */
    } while(!ipv4_server_complete);

    /* Indicate the IPv4 connection is done. */
    ipv4_complete = NX_TRUE;

    /* Close down our server sockets. */
    status = soc_close(sock_tcp_server);

    if (status == ERROR)
    {

        error_counter++;
    }

}

/* Define the IPv6 server thread */

void    thread_server6_entry(ULONG thread_input)
{
INT         status,  sock6, sock6_tcp_server;
ULONG       actual_status;
INT         Clientlen;
INT         i;
UINT        is_set = NX_FALSE;
NXD_ADDRESS ip_address;
struct      sockaddr_in6 serverAddr;                  
struct      sockaddr_in6 ClientAddr;
UINT        address_index;
UINT        ipv6_complete = NX_FALSE;
INT         maxfd;
fd_set      master_list, read_ready;
CHAR        Server_Rcv_Buffer[100];


    if (error_counter) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("NetX Test:   BSD TCP Server Socket Shared Port Test........");

    status =  nx_ip_status_check(&bsd_ip_server, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE); 
    
    /* Check status...  */ 
    if (status != NX_SUCCESS) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&bsd_ip_server);
    if((status != NX_SUCCESS) && (status != NX_ALREADY_ENABLED))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable ICMPv6 */
    status = nxd_icmp_enable(&bsd_ip_server);
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* This assumes we are using the primary network interface (index 0). */
    status = nxd_ipv6_address_set(&bsd_ip_server, 0, NX_NULL, 10, &address_index);

    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set ip interface address. */
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    ip_address.nxd_ip_address.v6[1] = 0x0000f101;
    ip_address.nxd_ip_address.v6[2] = 0;
    ip_address.nxd_ip_address.v6[3] = 0x101;
    
    /* Set the host global IP address. We are assuming a 64 
       bit prefix here but this can be any value (< 128). */
    status = nxd_ipv6_address_set(&bsd_ip_server, 0, &ip_address, 64, &address_index);

    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for IPv6 stack to finish DAD process. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Create BSD TCP Socket */
    sock6_tcp_server = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    if (sock6_tcp_server == -1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set the server port and IP address */
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin6_addr._S6_un._S6_u32[0] = htonl(0x20010db8);
    serverAddr.sin6_addr._S6_un._S6_u32[1] = htonl(0xf101);
    serverAddr.sin6_addr._S6_un._S6_u32[2] = 0x0;
    serverAddr.sin6_addr._S6_un._S6_u32[3] = htonl(0x0101);
    serverAddr.sin6_port = htons(SERVER_PORT);
    serverAddr.sin6_family = AF_INET6;

    /* Bind this server socket */
    status = bind (sock6_tcp_server, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

    if (status < 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   

    FD_ZERO(&master_list);
    FD_ZERO(&read_ready);
    FD_SET(sock6_tcp_server,&master_list);
    maxfd = sock6_tcp_server;

    /* Now listen for any client connections for this server socket */
    status = listen (sock6_tcp_server, 5);
    if (status < 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* All set to accept client connections */
    is_set = NX_FALSE;

    /* Loop to create and establish server connections.  */
    do
    {

        read_ready = master_list;

        tx_thread_sleep(NX_IP_PERIODIC_RATE / 5);   /* Allow some time to other threads too */

        /* Let the underlying TCP stack determine the timeout. */
        status = select(maxfd + 1, &read_ready, 0, 0, 0);

        if ( (status == ERROR) || (status == 0) )
        {

            continue;
        }

        /* Detected a connection request. */
        is_set = FD_ISSET(sock6_tcp_server,&read_ready);

        if(is_set)
        {
    
            Clientlen = sizeof(ClientAddr);
    
            sock6 = accept(sock6_tcp_server,(struct sockaddr*)&ClientAddr, &Clientlen);
    
            /* Add this new connection to our master list */
            FD_SET(sock6, &master_list);   
    
            if ( sock6 > maxfd)
            {
                maxfd = sock6;
            }   
    
            continue; 
        }

        /* Check the set of 'ready' sockets, e.g connected to remote host and waiting for
           notice of packets received. */
        for (i = 0; i < (maxfd+1); i++)
        {
    
            if (((i+ NX_BSD_SOCKFD_START) != sock6_tcp_server) && 
                 (FD_ISSET(i + NX_BSD_SOCKFD_START, &master_list)) && 
                 (FD_ISSET(i + NX_BSD_SOCKFD_START, &read_ready)))
            {
    
                while(1)
                {

                    memset(&Server_Rcv_Buffer[0], 0, 100); 
                    status = recv(i + NX_BSD_SOCKFD_START, (VOID *)Server_Rcv_Buffer, 100, 0);
            
                    if ((status == ERROR) || (status == 0))
                    {
                        /* This is a blocking socket. If no data is received, but the connection is still good,
                           the EAGAIN error is set. If it was a non blocking socket, the EWOULDBLOCK socket 
                           error is set. */
                        if (errno == EAGAIN) 
                        {
                            continue;
                        }
                        else if (errno == ENOTCONN) 
                        {
                            /* If the socket connection is terminated, the socket error will be ENOTCONN. */
                            break;
                        }
                        else if (status == 0)
                        {

                            break;
                        }

                        else 
                        {
                            /* Another error has occurred...probably an internal error of some kind
                               so best to terminate the connection. */
                            error_counter++;
                            break;
                        }                    
                    }
    
                    status = send(i + NX_BSD_SOCKFD_START, "Hello\n", strlen("Hello\n")+1, 0);
            
                    if (status == ERROR) 
                    {
                        if (errno == ENOTCONN)
                        {

                            /* If the socket connection is terminated, the socket error will be ENOTCONN. */
                            break;
                        }
                        else
                        {
                        
                            error_counter++;
                            break;
                        }
                    }

                    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    
                }
            
                /* Close this socket */   
    
                status = soc_close(i+ NX_BSD_SOCKFD_START);
                ipv6_complete = NX_TRUE;
    
                if (status == ERROR)
                {
                
                    error_counter++;
                }
                break;
            }    
            
        }   

         /* Loop back to check any next client connection */
    } while (!ipv6_complete);

    status = soc_close(sock6_tcp_server);

    if (status == ERROR)
    {

        error_counter++;
    }

    /* Close down our server socket. */
    while (!ipv4_complete)
    {
        tx_thread_sleep(20);
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

/* Define the IPv6 Client thread. */

void    thread_client6_entry(ULONG thread_input)
{

INT          status;                                 
NXD_ADDRESS  server_ip_address, ip_address;
NX_PACKET    *packet_rcv_ptr, *packet_ptr;
UINT         loopcount = 0;
char         *requests[2] = {"Request1", "Request2"};
UINT        address_index;

    /* Allow Netx to initialize the driver, also let the server get set up first. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&bsd_ip_client);
    if((status != NX_SUCCESS) && (status != NX_ALREADY_ENABLED))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable ICMPv6 */
    status = nxd_icmp_enable(&bsd_ip_client);

    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set ip interface address. */
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    ip_address.nxd_ip_address.v6[1] = 0x0000f101;
    ip_address.nxd_ip_address.v6[2] = 0;
    ip_address.nxd_ip_address.v6[3] = 0x1235;
    
    /* Set the host global IP address. We are assuming a 64 
       bit prefix here but this can be any value (< 128). */
    status = nxd_ipv6_address_set(&bsd_ip_client, 0, &ip_address, 64, &address_index);

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
    server_ip_address.nxd_ip_address.v6[3] = 0x101;

    status += nx_tcp_socket_create(&bsd_ip_client, &client_ipv6_socket, "Client IPv6 Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                                   100, NX_NULL, NX_NULL);

    if (status )
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_tcp_client_socket_bind(&client_ipv6_socket, NX_ANY_PORT, 100);

    if (status )
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_tcp_client_socket_connect(&client_ipv6_socket, &server_ip_address, SERVER_PORT, 10 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    while(loopcount < 5)
    {

        status = nx_packet_allocate(&bsd_pool, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        if (status )
        {
            error_counter++;
        }

        status = nx_packet_data_append(packet_ptr, requests[1], strlen(requests[1]),
                                        &bsd_pool, NX_NO_WAIT);
        if (status )
        {
            error_counter++;
        }

        status = nx_tcp_socket_send(&client_ipv6_socket, packet_ptr, NX_IP_PERIODIC_RATE);

        if (status)
        {
            nx_packet_release(packet_ptr);
            error_counter++;
        }

        status = nx_tcp_socket_receive(&client_ipv6_socket, &packet_rcv_ptr, 5 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
        {

            error_counter++;
        }
        else
        {
            nx_packet_release(packet_rcv_ptr);
        }

        loopcount++;
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 2);
    }

    nx_tcp_socket_disconnect(&client_ipv6_socket, 200);
    nx_tcp_socket_delete(&client_ipv6_socket); 

    /* All done */
    return;
}


/* Define the IPv4 Client thread. */
void    thread_client_entry(ULONG thread_input)
{

INT          status;                                 
UINT         loopcount = 0;
ULONG        actual_status;
INT          sock_tcp_client;
struct       sockaddr_in echoServAddr;               
UINT         ipv4_client_complete = NX_FALSE;
CHAR         Client_Rcv_Buffer[100];

    /* IPv4 waits for IPv6 DAD protocol */
    tx_thread_sleep(4 * NX_IP_PERIODIC_RATE);

    status =  nx_ip_status_check(&bsd_ip_server, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE); 
    
    /* Check status...  */ 
    if (status != NX_SUCCESS) 
    { 
        printf("ERROR!\n");
        test_control_return(1);
    } 


    memset(&echoServAddr, 0, sizeof(echoServAddr));
    echoServAddr.sin_family = AF_INET;
    echoServAddr.sin_addr.s_addr = htonl(IP_ADDRESS(1,2,3,4));
    echoServAddr.sin_port = htons(SERVER_PORT);

    /* Now make client connections with the server. */
    while (!ipv4_client_complete)
    {

        /* Create BSD TCP Socket */
        sock_tcp_client = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (sock_tcp_client == -1)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    
        /* Now connect this client to the server */
        status = connect(sock_tcp_client, (struct sockaddr *)&echoServAddr, sizeof(echoServAddr));
    
        /* Check for error.  */
        if (status != OK)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Now receive the echoed packet from the server */
        while(loopcount < 5)
        {
    
   
            status = send(sock_tcp_client, "Hello from Client4", (strlen("Hello from Client4")+1), 0);
    
            if (status == ERROR)
            {
                error_counter++;
            }

            memset(&Client_Rcv_Buffer[0], 0, 100);
            status = recv(sock_tcp_client, (VOID *)Client_Rcv_Buffer, 100, 0);
    
            if (status < 0)
            {
                if (errno == EAGAIN) 
                {
                    continue;
                }
                else if (errno == ENOTCONN)
                {

                    break;
                }
                else
                {
                    /* Another error has occurred.... */
                    error_counter++; 
                    break;
                }                    
            }

            loopcount++;

        }

        ipv4_client_complete = NX_TRUE;

        /* close this client socket */   
        status = soc_close(sock_tcp_client);

        if (status == ERROR)
        {
            error_counter++;
        }

   }

    /* All done */
    return;
}
#else  /*  FEATURE_NX_IPV6 */


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void  netx_bsd_tcp_servers_share_port_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   BSD TCP Server Socket Shared Port Test.....N/A\n");

    test_control_return(3);

}

#endif /* FEATURE_NX_IPV6 */

    
