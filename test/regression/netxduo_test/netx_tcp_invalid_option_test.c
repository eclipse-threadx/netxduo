/* This NetX test concentrates on the TCP Socket relisten operation.  */

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
static UINT                    fin_counter = 0;
static UINT                    rst_counter = 0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);      
static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);      
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static VOID    inject_invalid_option();


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_invalid_option_test_application_define(void *first_unused_memory)
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
    printf("NetX Test:   TCP Invalid Option Test...................................");

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

    /* Call connect to establish connection.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT, 1 * NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                       
               
    /* Check the client and server socket state.  */
    if ((client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) || (server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED))     
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Inject invalid option with invalid SEQ and ACK. */
    /* The receiver is expected to drop the packet. */
    inject_invalid_option();

    /* Check the client and server socket state.  */
    if ((client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) || (server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED))     
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               
                             
    /* Set the callback function.  */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive;       
    advanced_packet_process_callback = my_packet_process;
                                                           
    /* Call connect to send a SYN  */ 
    status = nx_tcp_socket_disconnect(&client_socket, 1 * NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status == NX_SUCCESS)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Check the client and server socket state.  */ 
#ifdef __PRODUCT_NETXDUO__
    if ((client_socket.nx_tcp_socket_state != NX_TCP_CLOSED) || (server_socket.nx_tcp_socket_state != NX_TCP_LISTEN_STATE))
#else
    if ((client_socket.nx_tcp_socket_state != NX_TCP_CLOSED) || (server_socket.nx_tcp_socket_state != NX_TCP_CLOSED))
#endif
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             

    /* Check status.  */
    if ((error_counter) || (fin_counter != 1) || (rst_counter != 1))
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
    status =  nx_tcp_server_socket_accept(&server_socket, 1 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;           
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

    /* Check if it is a FIN packet.  */
    if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_FIN_BIT) && 
       (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT))
    {

        /* Update the fin_counter.  */
        fin_counter++;

        /* Add the option.  */
        option_word = (ULONG *) (packet_ptr ->nx_packet_prepend_ptr + 20 );  

        /* Add the invalid MSS option.  */
        *option_word = 0x02030000 | 536;
        NX_CHANGE_ULONG_ENDIAN(*option_word);

        /* Update the option word pointer.  */
        option_word ++;                        
        *option_word = NX_TCP_OPTION_END;  
        NX_CHANGE_ULONG_ENDIAN(*option_word);    

        /* The ACK must be set or else the packet is dropped before parsing TCP option. */
#if 0
        /* Clean the ACK bit.  */
        tcp_header_ptr -> nx_tcp_header_word_3 = (tcp_header_ptr -> nx_tcp_header_word_3 & (~NX_TCP_ACK_BIT));
#endif

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
        dest_ip = &client_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4;
        source_ip = &client_socket.nx_tcp_socket_connect_interface -> nx_interface_ip_address;
        checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                           packet_ptr -> nx_packet_length,
                                           source_ip, dest_ip);
        checksum = ~checksum & NX_LOWER_16_MASK;
#else
        checksum =  _nx_tcp_checksum(packet_ptr, client_socket.nx_tcp_socket_connect_interface -> nx_interface_ip_address, client_socket.nx_tcp_socket_connect_ip);
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
    ip_1.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

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

static VOID    inject_invalid_option()
{
NX_PACKET *packet_ptr;
NX_TCP_HEADER *tcp_header_ptr;
ULONG *option_word;
ULONG checksum;
#ifdef __PRODUCT_NETXDUO__
ULONG *source_ip, *dest_ip;
#endif

    if (nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_IP_PERIODIC_RATE))
    {
        error_counter++;
        return;
    }

    /* Construct TCP header with invalid SEQ and ACK. */
    tcp_header_ptr =  (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    tcp_header_ptr -> nx_tcp_header_word_0 = (((ULONG)(client_socket.nx_tcp_socket_port)) << NX_SHIFT_BY_16) | (ULONG)client_socket.nx_tcp_socket_connect_port;
    tcp_header_ptr -> nx_tcp_sequence_number = 0;
    tcp_header_ptr -> nx_tcp_acknowledgment_number = 0;
    tcp_header_ptr -> nx_tcp_header_word_3 = NX_TCP_SYN_HEADER | NX_TCP_ACK_BIT | NX_TCP_PSH_BIT | 200;
    tcp_header_ptr -> nx_tcp_header_word_4 = 0;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

    /* Add invalid TCP option. */
    option_word = (ULONG *)(packet_ptr ->nx_packet_prepend_ptr + 20);  

    /* Add the invalid MSS option.  */
    *option_word = 0x02030000 | 536;
    NX_CHANGE_ULONG_ENDIAN(*option_word);

    /* Update the option word pointer.  */
    option_word ++;                        
    *option_word = NX_TCP_OPTION_END;  
    NX_CHANGE_ULONG_ENDIAN(*option_word);    

    /* Setup the packet payload pointers and length for a basic TCP packet.  */
    packet_ptr -> nx_packet_append_ptr =  packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER) + 8;

    /* Setup the packet length.  */
    packet_ptr -> nx_packet_length =  sizeof(NX_TCP_HEADER) + 8;


    /* Write ABCs into the packet payload!  */
    if (nx_packet_data_append(packet_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_IP_PERIODIC_RATE))
    {
        nx_packet_release(packet_ptr);
        error_counter++;
        return;
    }

        /* Calculate the checksum . */
#ifdef __PRODUCT_NETXDUO__
    packet_ptr -> nx_packet_address.nx_packet_interface_ptr = client_socket.nx_tcp_socket_connect_interface;
    dest_ip = &client_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4;
    source_ip = &client_socket.nx_tcp_socket_connect_interface -> nx_interface_ip_address;
    checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                       packet_ptr -> nx_packet_length,
                                       source_ip, dest_ip);
    checksum = ~checksum & NX_LOWER_16_MASK;
#else
    packet_ptr -> nx_packet_ip_interface = client_socket.nx_tcp_socket_connect_interface;
    packet_ptr -> nx_packet_next_hop_address = client_socket.nx_tcp_socket_next_hop_address;
    checksum =  _nx_tcp_checksum(packet_ptr, packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address, client_socket.nx_tcp_socket_connect_ip);
#endif
    /* Move the checksum into header.  */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
    tcp_header_ptr -> nx_tcp_header_word_4 =  (checksum << NX_SHIFT_BY_16);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

    /* Send the TCP packet. */
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
#ifdef __PRODUCT_NETXDUO__
    _nx_ip_packet_send(&ip_0, packet_ptr, client_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4,
                       client_socket.nx_tcp_socket_type_of_service, client_socket.nx_tcp_socket_time_to_live, NX_IP_TCP,
                       client_socket.nx_tcp_socket_fragment_enable,
                       client_socket.nx_tcp_socket_next_hop_address);
#else
    _nx_ip_packet_send(&ip_0, packet_ptr,  client_socket.nx_tcp_socket_connect_ip,
                       client_socket.nx_tcp_socket_type_of_service, client_socket.nx_tcp_socket_time_to_live, NX_IP_TCP,
                       client_socket.nx_tcp_socket_fragment_enable);
#endif

    tx_mutex_put(&(ip_0.nx_ip_protection));
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_invalid_option_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Invalid Option Test...................................N/A\n");

    test_control_return(3);      
}
#endif
