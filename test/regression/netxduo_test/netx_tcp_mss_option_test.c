/* This NetX test concentrates on the TCP Socket relisten operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ip.h"
                                     
extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;      
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket; 
static NX_TCP_SOCKET           server_socket; 
#define CLIENT_PORT            0x88
#define SERVER_PORT            0x89
                                                  

/* Define the counters used in the demo application...  */

static ULONG                   error_counter = 0;          
static UINT                    syn_counter = 0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    tcp_checksum_compute(NX_PACKET *packet_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_mss_option_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

                     
    error_counter =     0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;   

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    /* Check the status.  */
    if (status)
        error_counter++;
                         
    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check the status.  */
    if (status)
        error_counter++;     

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;
                                
    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}              


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;  

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP MSS Option Test.......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;
                             
    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, CLIENT_PORT, NX_NO_WAIT);

    /* Check for error.  */  
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);      
    }                                    
                             
    /* Set the callback function.  */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive;

    /* Send NOP KIND option in my_tcp_packet_receive. */
    /* Call connect to send a SYN  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 5 * NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          
                        
    /* Disconnect this socket.  */
    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)            
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          

    /* Set the callback function.  */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive;
                                                                      
    /* Send invalid option in my_tcp_packet_receive. */
    /* Call connect to send a SYN  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 5 * NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status == NX_SUCCESS)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       
                      
    /* Set the callback function.  */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive;
                                                                      
    /* Send invalid option in my_tcp_packet_receive. */
    /* Call connect to send a SYN  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 5 * NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status == NX_SUCCESS)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                      
#ifdef NX_ENABLE_TCP_MSS_CHECK
    /* Set the callback function.  */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive;
                                                                      
    /* Send mss smaller than minimum in my_tcp_packet_receive. */
    /* Call connect to send a SYN  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 5 * NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status == NX_SUCCESS)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
#endif /* NX_ENABLE_TCP_MSS_CHECK */

    /* Check status.  */
    if (error_counter)
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
    

static void    thread_1_entry(ULONG thread_input)
{

UINT            status;
ULONG           actual_status;


    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        error_counter++;
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                NX_NULL, NX_NULL);
                                
    /* Check for error.  */
    if (status)
        error_counter++;      

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, SERVER_PORT, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    while (1)
    {
                                            
        /* Accept a client socket connection.  */
        status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
            error_counter++;        
                   
        /* Check the mss value.  */
        if (server_socket.nx_tcp_socket_peer_mss != 536)
            error_counter++;    

        /* Disconnect this socket.  */
        status =  nx_tcp_socket_disconnect(&server_socket, 5 * NX_IP_PERIODIC_RATE);

        /* Determine if the status is valid.  */
        if (status)
            error_counter++;                 

        /* Unaccept the server socket.  */
        status =  nx_tcp_server_socket_unaccept(&server_socket);

        /* Check for error.  */
        if (status)
            error_counter++;

        /* Setup server socket for listening again.  */
        status =  nx_tcp_server_socket_relisten(&ip_1, SERVER_PORT, &server_socket);

        /* Check for error.  */
        if (status)
            error_counter++;
    }
}         
     
static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER  *tcp_header_ptr;   
ULONG           *option_word_1;
    
    /* Update the counter.  */
    syn_counter ++;

    /* Get the TCP header pointer.  */
    tcp_header_ptr =  (NX_TCP_HEADER *) packet_ptr -> nx_packet_prepend_ptr;  
    option_word_1 = (ULONG *)(tcp_header_ptr + 1);

    /* Swap the endianess.  */
    NX_CHANGE_ULONG_ENDIAN(*option_word_1);     

    /* Check the counter.  */
    if (syn_counter == 1)
    {                    
                                                                      
        /* Set the NOP KIND option.  */ 
        *option_word_1 = NX_TCP_NOP_KIND << 24;  
    }                              
          
    /* Check the counter.  */
    if (syn_counter == 2)
    {                    
                                                                      
        /* Set the invalid Option.  */ 
        *option_word_1 = 0x04000000;  
    }      
              
    /* Check the counter.  */
    if (syn_counter == 3)
    {                    
                                                                      
        /* Set the invalid Option.  */ 
        *option_word_1 = 0x04090000;  
    }      

#ifdef NX_ENABLE_TCP_MSS_CHECK
    /* Check the counter.  */
    if (syn_counter == 4)
    {                    
                                                                      
        /* Set the mss smaller than minimum.  */ 
        *option_word_1 = NX_TCP_MSS_OPTION | (NX_TCP_MSS_MINIMUM - 1);  
    }      
#endif /* NX_ENABLE_TCP_MSS_CHECK */

    /* Swap the endianess.  */
    NX_CHANGE_ULONG_ENDIAN(*option_word_1);       
 
    /* Calculate the TCP checksum.  */
    tcp_checksum_compute(packet_ptr);

    /* Clear the callback function.  */
    ip_1.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}
  
static void    tcp_checksum_compute(NX_PACKET *packet_ptr)
{
NX_TCP_HEADER  *tcp_header_ptr;   
ULONG          *source_ip, *dest_ip;
ULONG           checksum;

    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
    {

        /* Get IPv4 addresses. */
        source_ip = (ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 8);
        dest_ip = (ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 4);
    }
    else
    {

        /* Get IPv6 addresses. */
        source_ip = (ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 32);
        dest_ip = (ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 16);
    }

    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);

    /* Calculate the TCP checksum.  */
    tcp_header_ptr -> nx_tcp_header_word_4 = 0;

    /* Calculate the checksum.  */
    checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                       packet_ptr -> nx_packet_length,
                                       source_ip, dest_ip);
    checksum = ~checksum & NX_LOWER_16_MASK;
    tcp_header_ptr -> nx_tcp_header_word_4 = (checksum << NX_SHIFT_BY_16);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_mss_option_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP MSS Option Test.......................................N/A\n");

    test_control_return(3);      
}
#endif
