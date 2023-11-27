/* This demoonstrates sharing a port between an IPv4 and IPv6 TCP client socket to send 
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
static TX_THREAD               thread_client6;
static TX_THREAD               thread_server;
static TX_THREAD               thread_server6;
static NX_PACKET_POOL          bsd_pool;
static NX_IP                   bsd_ip_server;
static NX_IP                   bsd_ip_client;

static UINT                    error_counter = 0;

#define CLIENT_ADDRESS      IP_ADDRESS(1,2,3,5) 
#define SERVER_ADDRESS      IP_ADDRESS(1,2,3,4)
#define SERVER_PORT         74
#define SERVER6_PORT        76
#define CLIENT_PORT         87

/* Define global data. */

static UINT         ipv4_client_complete = NX_FALSE;
static UINT         ipv6_client_complete = NX_FALSE;

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
void    netx_bsd_tcp_clients_share_port_test_application_define(void *first_unused_memory)
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

    /* Create an IP instance for the BSD .  */
    status = nx_ip_create(&bsd_ip_server, "NetX BSD IPv4 Server", SERVER_ADDRESS, 0xFFFFFF00UL,  
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


    /********************** Set up the Client  **************************/


    /* Create an IP instance for the BSD .  */
    status = nx_ip_create(&bsd_ip_client, "NetX BSD IPv4 Client", CLIENT_ADDRESS, 0xFFFFFF00UL,  
                          &bsd_pool, _nx_ram_network_driver, pointer, DEMO_STACK_SIZE, 1);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&bsd_ip_client);

    status =  nx_icmp_enable(&bsd_ip_client);
    /* Enable ARP and supply ARP cache memory for BSD  */
    status +=  nx_arp_enable(&bsd_ip_client, (void *) pointer, 1024);
    
    pointer = pointer + 1024; 

    /* Check ARP enable status.  */     
    if (status)
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


    /* Now initialize BSD IP.  */
    status = bsd_initialize (&bsd_ip_client, &bsd_pool, pointer, 2048, 4);

    /* Check for BSD errors.  */
    if (status)
    {
        error_counter++;
    }

    pointer = pointer + 2048; 

    return;
}

/* Define the IPv4 server thread */
void    thread_server_entry(ULONG thread_input)
{

INT          status;                                 
ULONG        actual_status;
NX_TCP_SOCKET server_ipv4_socket;
NX_PACKET    *packet_rcv_ptr, *packet_ptr;
char         *requests[2] = {"Request1", "Request2"};
UINT         ipv4_server_complete = NX_FALSE;

    /* Check status...  */ 
    if (error_counter) 
    { 
        printf("ERROR!\n");
        test_control_return(11);
    } 

    /* Wait for IPv6 get set up first. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    status =  nx_ip_status_check(&bsd_ip_server, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE); 
    
    /* Check status...  */ 
    if (status != NX_SUCCESS) 
    { 
        printf("ERROR!\n");
        test_control_return(12);
    } 

    status = nx_tcp_socket_create(&bsd_ip_server, &server_ipv4_socket, "Server IPv4 Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                                   100, NX_NULL, NX_NULL);

    if (status )
    {
        printf("ERROR!\n");
        test_control_return(13);
    }

    status = nx_tcp_server_socket_listen(&bsd_ip_server, SERVER_PORT, &server_ipv4_socket,  5, NX_NULL);

    if (status )
    {
        printf("ERROR!\n");
        test_control_return(14);
    }

    status = nx_tcp_server_socket_accept(&server_ipv4_socket, 1000);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(15);
    }

    while(!ipv4_server_complete)
    {

        status = nx_tcp_socket_receive(&server_ipv4_socket, &packet_rcv_ptr, 500);
        if(status != NX_SUCCESS)
        {
            if (status == NX_NOT_CONNECTED)
            {

                ipv4_server_complete = NX_TRUE;
                break;
            }

            test_control_return(16);
            error_counter++;
        }

        else
        {

            nx_packet_release(packet_rcv_ptr);
        }

        status = nx_packet_allocate(&bsd_pool, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        if (status )
        {

            test_control_return(17);
            error_counter++;
        }

        status = nx_packet_data_append(packet_ptr, requests[0], strlen(requests[0]),
                                        &bsd_pool, NX_NO_WAIT);
        if (status )
        {

            test_control_return(18);
            error_counter++;
        }

        status = nx_tcp_socket_send(&server_ipv4_socket, packet_ptr, 100);

        if (status)
        {
            nx_packet_release(packet_ptr);


            if (status == NX_NOT_CONNECTED)
            {
                ipv4_server_complete = NX_TRUE;
                break;
            }

            test_control_return(19);
            error_counter++;
        }

        tx_thread_sleep(NX_IP_PERIODIC_RATE / 2);
    }
    
    status = nx_tcp_socket_disconnect(&server_ipv4_socket, 200);

    if (status !=NX_SUCCESS)
    {
        test_control_return(20);
    }
    nx_tcp_socket_delete(&server_ipv4_socket); 

    if (status !=NX_SUCCESS)
    {
        test_control_return(21);
    }
    /* All done */
    return;

}

/* Define the IPv6 server thread */

void    thread_server6_entry(ULONG thread_input)
{

INT          status;                                 
ULONG        actual_status;
NX_TCP_SOCKET server_ipv6_socket;
NX_PACKET    *packet_rcv_ptr, *packet_ptr;
char         *requests[2] = {"Request6_1", "Request6_2"};
UINT         ipv6_server_complete = NX_FALSE;
UINT         address_index;
NXD_ADDRESS ip_address;


    /* Check status...  */ 
    if (error_counter) 
    { 
        printf("ERROR22!\n");
        test_control_return(22);
    } 

    printf("NetX Test:   BSD TCP Client Socket Shared Port Test........");
    status =  nx_ip_status_check(&bsd_ip_server, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE); 
    
    /* Check status...  */ 
    if (status != NX_SUCCESS) 
    { 
        printf("ERROR23!\n");
        test_control_return(23);
    } 

    status = nxd_ipv6_enable(&bsd_ip_server);

    if((status != NX_SUCCESS) && (status != NX_ALREADY_ENABLED))
    {
        printf("ERROR24!\n");
        test_control_return(24);
    }

    /* Enable ICMPv6 */
    status = nxd_icmp_enable(&bsd_ip_server);
    if(status)
    {
        printf("ERROR25!\n");
        test_control_return(25);
    }

    /* This assumes we are using the primary network interface (index 0). */
    status = nxd_ipv6_address_set(&bsd_ip_server, 0, NX_NULL, 10, &address_index);

    if (status)
    {
        printf("ERROR26!\n");
        test_control_return(26);
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
        printf("ERROR27!\n");
        test_control_return(27);
    }

    /* Wait for IPv6 stack to finish DAD process. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    status = nx_tcp_socket_create(&bsd_ip_server, &server_ipv6_socket, "Server IPv6 Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                                   100, NX_NULL, NX_NULL);

    if (status )
    {
        printf("ERROR28!\n");
        test_control_return(28);
    }

    status = nx_tcp_server_socket_listen(&bsd_ip_server, SERVER6_PORT, &server_ipv6_socket,  5, NX_NULL);

    if (status )
    {
        printf("ERROR29!\n");
        test_control_return(29);
    }

    status = nx_tcp_server_socket_accept(&server_ipv6_socket, TX_WAIT_FOREVER);
    if (status != NX_SUCCESS)
    {
        printf("ERROR30!\n");
        test_control_return(30);
    }

    while(!ipv6_server_complete)
    {

        status = nx_tcp_socket_receive(&server_ipv6_socket, &packet_rcv_ptr, 500);
        if(status != NX_SUCCESS)
        {
            if (status == NX_NOT_CONNECTED)
            {

                ipv6_server_complete = NX_TRUE;
                break;
            }


            printf("ERROR31!\n");
            test_control_return(31);
            error_counter++;
        }

        else
        {
            nx_packet_release(packet_rcv_ptr);
        }

        status = nx_packet_allocate(&bsd_pool, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        if (status )
        {

            printf("ERROR32\n");
            test_control_return(32);
            error_counter++;
        }

        status = nx_packet_data_append(packet_ptr, requests[1], strlen(requests[1]),
                                        &bsd_pool, NX_NO_WAIT);
        if (status )
        {

            printf("ERROR33!\n");
            test_control_return(33);
            error_counter++;
        }

        status = nx_tcp_socket_send(&server_ipv6_socket, packet_ptr, 100);

        if (status)
        {
            nx_packet_release(packet_ptr);


            if (status == NX_NOT_CONNECTED)
            {

                ipv6_server_complete = NX_TRUE;
                break;
            }

            printf("ERROR34!\n");
            test_control_return(34);
            error_counter++;
        }

        tx_thread_sleep(NX_IP_PERIODIC_RATE / 2);
    }

    nx_tcp_socket_disconnect(&server_ipv6_socket, 200);
    nx_tcp_socket_delete(&server_ipv6_socket); 

    /* Wait for IPv4 to close down before closing down our server socket. */
    while (!ipv6_client_complete)
    {
        tx_thread_sleep(20);
    }

    if(error_counter)
    {
        printf("ERROR35!\n");
        test_control_return(35);
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

INT         status;
ULONG       actual_status;
INT         sock6_tcp_client;
struct      sockaddr_in6 echoServAddr6, echoClientAddr6;               
UINT        address_index;
NXD_ADDRESS ip_address;
CHAR        Client_Rcv_Buffer[100];
UINT        loopcount = 0;

    tx_thread_sleep(NX_IP_PERIODIC_RATE / 2);

    status =  nx_ip_status_check(&bsd_ip_client, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE); 
    
    /* Check status...  */ 
    if (status != NX_SUCCESS) 
    { 
        printf("ERROR36!\n");
        test_control_return(36);
    } 

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&bsd_ip_client);
    if((status != NX_SUCCESS) && (status != NX_ALREADY_ENABLED))
    { 
        printf("ERROR37!\n");
        test_control_return(37);
    } 


    /* Enable ICMPv6 */
    status = nxd_icmp_enable(&bsd_ip_client);
    if(status)
    { 
        printf("ERROR38!\n");
        test_control_return(38);
    } 

    /* This assumes we are using the primary network interface (index 0). */
    status = nxd_ipv6_address_set(&bsd_ip_client, 0, NX_NULL, 10, &address_index);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR39!\n");
        test_control_return(39);
    }


    ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    ip_address.nxd_ip_address.v6[1] = 0xf101;
    ip_address.nxd_ip_address.v6[2] = 0;
    ip_address.nxd_ip_address.v6[3] = 0x1235;


     /* Set the host global IP address. We are assuming a 64
        bit prefix here but this can be any value (< 128). */
     status = nxd_ipv6_address_set(&bsd_ip_client, 0, &ip_address, 64, &address_index);

     if (status)
     {
         printf("ERROR40!\n");
         test_control_return(40);
     }


    /* Wait for IPv6 stack to finish DAD process. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);


    echoClientAddr6.sin6_addr._S6_un._S6_u32[0] = htonl(0x20010db8);
    echoClientAddr6.sin6_addr._S6_un._S6_u32[1] = htonl(0xf101);
    echoClientAddr6.sin6_addr._S6_un._S6_u32[2] = 0x0;
    echoClientAddr6.sin6_addr._S6_un._S6_u32[3] = htonl(0x1235);
    echoClientAddr6.sin6_port = htons(CLIENT_PORT);
    echoClientAddr6.sin6_family = AF_INET6;

    memset(&echoServAddr6, 0, sizeof(echoServAddr6));
    echoServAddr6.sin6_addr._S6_un._S6_u32[0] = htonl(0x20010db8);
    echoServAddr6.sin6_addr._S6_un._S6_u32[1] = htonl(0xf101);
    echoServAddr6.sin6_addr._S6_un._S6_u32[2] = 0x0;
    echoServAddr6.sin6_addr._S6_un._S6_u32[3] = htonl(0x0101);
    echoServAddr6.sin6_port = htons(SERVER6_PORT);
    echoServAddr6.sin6_family = AF_INET6;


    /* Now make client connections with the server. */
    while (!ipv6_client_complete)
    {

        /* Create BSD TCP Socket */
        sock6_tcp_client = socket( AF_INET6, SOCK_STREAM, IPPROTO_TCP);

        if (sock6_tcp_client == ERROR)
        {
            printf("ERROR41!\n");
            test_control_return(41);
        }
    
        status = bind (sock6_tcp_client, (struct sockaddr *) &echoClientAddr6, sizeof(echoClientAddr6));

        if (status == ERROR)
        {
            printf("ERROR42!\n");
            test_control_return(42);
        }

        /* Now connect this client to the server */
        status = connect(sock6_tcp_client, (struct sockaddr *)&echoServAddr6, sizeof(echoServAddr6));
    
        /* Check for error.  */
        if (status == ERROR)
        {
            printf("ERROR43!\n");
            test_control_return(43);
            return;
    
        }

        /* Now receive the echoed packet from the server */
        while(loopcount < 5)
        {
    
            send(sock6_tcp_client, "Hello", (strlen("Hello")+1), 0);
    
            memset(&Client_Rcv_Buffer[0], 0, 100);
            status = recv(sock6_tcp_client, (VOID *)Client_Rcv_Buffer, 100, 0);
    
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


                    printf("ERROR44!\n");
                    test_control_return(44);
                    error_counter++; 
                    break;
                }                    

            }
            else if (status == 0)
            {

                break;
            }

            tx_thread_sleep(80 * NX_IP_PERIODIC_RATE / 100);
            loopcount++;
        }

        ipv6_client_complete = NX_TRUE;

        break;
    }


    /* close this client socket */   
    status = soc_close(sock6_tcp_client);

    if (status != ERROR)
    {

        printf("ERROR46!\n");
        test_control_return(45);
        error_counter++;
    }
}


/* Define the IPv4 Client thread. */
void    thread_client_entry(ULONG thread_input)
{

INT          status;                                 
UINT         loopcount = 0;
ULONG        actual_status;
INT          sock_tcp_client;
struct       sockaddr_in echoServAddr;
struct       sockaddr_in echoClientAddr;               
CHAR         Client_Rcv_Buffer[100];

    /* IPv4 waits for IPv6 DAD protocol */
    tx_thread_sleep(550 * NX_IP_PERIODIC_RATE / 100);

    status =  nx_ip_status_check(&bsd_ip_client, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE); 
    
    /* Check status...  */ 
    if (status != NX_SUCCESS) 
    { 
        printf("ERROR46a!\n");
        test_control_return(46);
    } 

    echoClientAddr.sin_family = AF_INET;
    echoClientAddr.sin_port = htons(CLIENT_PORT);
    echoClientAddr.sin_addr.s_addr = htonl(CLIENT_ADDRESS);

    memset(&echoServAddr, 0, sizeof(echoServAddr));
    echoServAddr.sin_family = AF_INET;
    echoServAddr.sin_addr.s_addr = htonl(SERVER_ADDRESS);
    echoServAddr.sin_port = htons(SERVER_PORT);

    /* Now make client connections with the server. */
    while (!ipv4_client_complete)
    {

        /* Create BSD TCP Socket */
        sock_tcp_client = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (sock_tcp_client == -1)
        {
            printf("ERROR47!\n");
            test_control_return(47);
        }

        status = bind (sock_tcp_client, (struct sockaddr *) &echoClientAddr, sizeof(echoClientAddr));

        if (status < 0)
        {
            printf("ERROR%d!\n", errno);
            test_control_return(48);
        }

        /* Now connect this client to the server */
        status = connect(sock_tcp_client, (struct sockaddr *)&echoServAddr, sizeof(echoServAddr));
    
        /* Check for error.  */
        if (status != OK)
        {
            printf("ERROR49!\n");
            test_control_return(49);
        }

        /* Now receive the echoed packet from the server */
        while(loopcount < 5)
        {
    
            status = send(sock_tcp_client, "Hello from Client4", (strlen("Hello from Client4")+1), 0);
    
            if (status == ERROR)
            {

                printf("ERROR50!\n");
                test_control_return(50);
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

                    printf("ERROR51!\n");
                    test_control_return(51);
                    error_counter++; 
                    break;
                }                    

            }
            else if (status == 0)
            {

                break;
            }
            tx_thread_sleep(80 * NX_IP_PERIODIC_RATE / 100);
            loopcount++;
        }

        ipv4_client_complete = NX_TRUE;
   }

    /* close this client socket */   
    status = soc_close(sock_tcp_client);

    if (status == ERROR)
    {

        printf("ERROR53!\n");
        test_control_return(53);
        error_counter++;
    }

    /* All done */
    return;
}
#else  /*  FEATURE_NX_IPV6 */


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void  netx_bsd_tcp_clients_share_port_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   BSD TCP Client Socket Shared Port Test........N/A\n");

    test_control_return(3);

}

#endif /* FEATURE_NX_IPV6 */



    
