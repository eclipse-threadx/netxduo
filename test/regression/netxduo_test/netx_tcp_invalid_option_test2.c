/* This NetX test concentrates on the invalid TCP option when the ACK bit is not set.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
                                     
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#include   "nx_tcp.h"
#include   "nx_ip.h"

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
static UINT                    rst_counter = 0;
static UINT                    hacked_counter = 0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);      
static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);      
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_invalid_option_test2_application_define(void *first_unused_memory)
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
    printf("NetX Test:   TCP Invalid Option Test2..................................");

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
                             
    /* Set the callback function.  */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive;       
    advanced_packet_process_callback = my_packet_process;
                             

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, NX_ANY_PORT, NX_NO_WAIT);

    /* Check for error.  */  
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);      
    }                

    /* Call connect to establish connection.  */ 
    /* The received SYN+ACK is modified to clean ACK bit and invalid option length. */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 1 * NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status != NX_NOT_CONNECTED)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                       

    /* Cleanup TCP socket. */
    nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);
    nx_tcp_client_socket_unbind(&client_socket);

    tx_thread_sleep(NX_IP_PERIODIC_RATE * 2);
                             

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, NX_ANY_PORT, NX_NO_WAIT);

    /* Check for error.  */  
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);      
    }                
                             
    /* Set the callback function.  */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive;       
    advanced_packet_process_callback = my_packet_process;

    /* Call connect to establish connection.  */ 
    /* The received SYN+ACK is modified to FIN packet without ACK bit and invalid option length. */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 1 * NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status != NX_NOT_CONNECTED)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                       

    /* Cleanup TCP socket. */
    nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);
    nx_tcp_client_socket_unbind(&client_socket);

    tx_thread_sleep(NX_IP_PERIODIC_RATE * 2);
                             

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, NX_ANY_PORT, NX_NO_WAIT);

    /* Check for error.  */  
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);      
    }                
                             
    /* Set the callback function.  */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive;       
    advanced_packet_process_callback = my_packet_process;

    /* Call connect to establish connection.  */ 
    /* The received SYN+ACK is modified clear all bits and invalid option length. */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 1 * NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status != NX_NOT_CONNECTED)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                       

    /* Cleanup TCP socket. */
    nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);
    nx_tcp_client_socket_unbind(&client_socket);

    tx_thread_sleep(NX_IP_PERIODIC_RATE * 2);

    /* Check status.  */
    if ((error_counter) || (rst_counter != 3))
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
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

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
                                        
    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, 1 * NX_IP_PERIODIC_RATE);


    /* Clear TCP socket. */
    nx_tcp_server_socket_unaccept(&server_socket);

    /* Relisten for next round. */
    nx_tcp_server_socket_relisten(&ip_1, SERVER_PORT, &server_socket);
                                        
    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, 2 * NX_IP_PERIODIC_RATE);


    /* Clear TCP socket. */
    nx_tcp_server_socket_unaccept(&server_socket);

    /* Relisten for next round. */
    nx_tcp_server_socket_relisten(&ip_1, SERVER_PORT, &server_socket);
                                        
    /* Accept a client socket connection.  */
    nx_tcp_server_socket_accept(&server_socket, 2 * NX_IP_PERIODIC_RATE);
}         
     
static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER  *tcp_header_ptr;   
ULONG          *option_word;
ULONG           checksum;
ULONG          *source_ip, *dest_ip;
    
    /* Set the tcp header pointer.  */
    tcp_header_ptr = (NX_TCP_HEADER *) packet_ptr ->nx_packet_prepend_ptr;    

    /* Swap the endianess.  */ 
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check if it is an SYN+ACK packet.  */
    if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && 
       (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT))
    {

        /* Add the option.  */
        option_word = (ULONG *) (packet_ptr ->nx_packet_prepend_ptr + 20 );  

        /* Add the invalid MSS option.  */
        *option_word = 0x02030000 | 536;
        NX_CHANGE_ULONG_ENDIAN(*option_word);

        /* Update the option word pointer.  */
        option_word ++;                        
        *option_word = NX_TCP_OPTION_END;  
        NX_CHANGE_ULONG_ENDIAN(*option_word);    

        /* Clear ACK bit.  */
        tcp_header_ptr -> nx_tcp_header_word_3 &= ~NX_TCP_ACK_BIT;

        if (hacked_counter == 1)
        {

            /* Clear SYN bit and set FIN bit. */
            tcp_header_ptr -> nx_tcp_header_word_3 &= ~NX_TCP_SYN_BIT;
            tcp_header_ptr -> nx_tcp_header_word_3 |= NX_TCP_FIN_BIT;
        }
        else if (hacked_counter == 2)
        {

            /* Clear SYN bit. */
            tcp_header_ptr -> nx_tcp_header_word_3 &= ~NX_TCP_SYN_BIT;
        }
        hacked_counter++;

        /* Update the TCP header length.  */
        tcp_header_ptr -> nx_tcp_header_word_3 += 0x20000000;

        /* Update the packet length.  */
        packet_ptr -> nx_packet_length  += 8;
        packet_ptr -> nx_packet_append_ptr += 8;

        /* Swap the endianess.  */ 
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr ->nx_tcp_header_word_3);

        /* Clear the checksum field. */
        tcp_header_ptr -> nx_tcp_header_word_4 = 0;

        /* Calculate the checksum . */
#ifdef __PRODUCT_NETXDUO__
        dest_ip = &server_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4;
        source_ip = &server_socket.nx_tcp_socket_connect_interface -> nx_interface_ip_address;
        checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                           packet_ptr -> nx_packet_length,
                                           source_ip, dest_ip);
        checksum = ~checksum & NX_LOWER_16_MASK;
#else
        checksum =  _nx_tcp_checksum(packet_ptr, server_socket.nx_tcp_socket_connect_interface -> nx_interface_ip_address, server_socket.nx_tcp_socket_connect_ip);
#endif
        tcp_header_ptr -> nx_tcp_header_word_4 = (checksum << NX_SHIFT_BY_16);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
    }      
    else
    {

        /* Swap the endianess.  */ 
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr ->nx_tcp_header_word_3);
    }

    /* Clear the callback function.  */
    ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}        

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER   *tcp_header_ptr;

    /* Set the TCP header pointer.  */
    tcp_header_ptr = (NX_TCP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20); 

    /* Swap the endianess.  */ 
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check if it is a RST packet.  */
    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
    {

        /* It is a RST packet.  */
        rst_counter++;

        /* Clear the callback.  */ 
        advanced_packet_process_callback = NX_NULL;
    }
                                     
    /* Swap the endianess.  */ 
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;
}            

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_invalid_option_test2_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Invalid Option Test2..................................N/A\n");

    test_control_return(3);      
}
#endif
