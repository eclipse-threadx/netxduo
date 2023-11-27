/* This NetX test concentrates on the IPv6 TCP Socket relisten operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
                                     
extern void    test_control_return(UINT status);
#ifdef FEATURE_NX_IPV6   

#include   "nx_ipv6.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket_0; 
static NX_TCP_SOCKET           client_socket_1;
static NX_TCP_SOCKET           server_socket_0; 
static NX_TCP_SOCKET           server_socket_1;      

/* The 2 ports will hashed to the same index. */
#define SERVER_PORT_0          0x00000100
#define SERVER_PORT_1          0x00008100
                                                  

/* Define the counters used in the demo application...  */

static ULONG                   error_counter = 0;          
static UINT                    syn_counter = 0;
static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
static NX_PACKET               *copy_packet;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);      
static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_socket_relisten_test2_application_define(void *first_unused_memory)
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

    if (status)
        error_counter++;
                         
    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_2.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_2.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_2.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[3] = 0x10000002;   

    /* Set interfaces' address */
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);

    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);     

    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;
    
    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check ICMP enable status.  */
    if(status)
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
UINT        client_port;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Socket Relisten Test 2................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket_0, "Client Socket 0", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Get a free port for the client's use.  */
    status =  nx_tcp_free_port_find(&ip_0, 1, &client_port);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket_0, client_port, NX_NO_WAIT);

    /* Check for error.  */  
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);      
    }                                    

    /* Should return some error message. */
    status =  nx_tcp_server_socket_relisten(&ip_0, 12, &client_socket_0);
    if (status != NX_ALREADY_BOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                       
                                                                
    /* Call connect to send a SYN  */ 
    status = nxd_tcp_client_socket_connect(&client_socket_0, &ipv6_address_2, SERVER_PORT_0, NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               
                      
    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket_1, "Client Socket 1", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Get a free port for the client's use.  */
    status =  nx_tcp_free_port_find(&ip_0, 1, &client_port);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket_1, client_port, NX_NO_WAIT);

    /* Check for error.  */  
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                       
                             
    /* Set the callback function.  */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive;
                                                           
    /* Call connect to send a SYN  */ 
    status = nxd_tcp_client_socket_connect(&client_socket_1, &ipv6_address_2, SERVER_PORT_1, NX_IP_PERIODIC_RATE);
                                                                                                    
    /* Check for error.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          
                  
    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&client_socket_1, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;     

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
    status =  nx_tcp_socket_create(&ip_1, &server_socket_0, "Server Socket 0", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                NX_NULL, NX_NULL);
                                
    /* Check for error.  */
    if (status)
        error_counter++;      

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, SERVER_PORT_0, &server_socket_0, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;
                            
    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_relisten(&ip_1, SERVER_PORT_0, &server_socket_0);

    /* Check for error.  */
    if (status != NX_NOT_CLOSED)
        error_counter++;          
                                        
    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket_0, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;  

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket_1, "Server Socket 1", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                NX_NULL, NX_NULL);
                                
    /* Check for error.  */
    if (status)
        error_counter++;      

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, SERVER_PORT_1, &server_socket_1, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket_1, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;    

    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&server_socket_1, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unaccept server socket.  */
    status =  nx_tcp_server_socket_unaccept(&server_socket_1);

    /* Check for error.  */
    if (status)
        error_counter++;      
                              
    /* Check the socket state.  */
    if (server_socket_1.nx_tcp_socket_state != NX_TCP_CLOSED) 
        error_counter++;
                          
    /* Check the TCP port table.  */
    if ((ip_1.nx_ip_tcp_port_table[1] != &server_socket_0) || (ip_1.nx_ip_tcp_port_table[1] -> nx_tcp_socket_bound_next != &server_socket_0))
        error_counter++;

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(&ip_1, copy_packet); 

    /* Relisten.  */   
    status =  nx_tcp_server_socket_relisten(&ip_1, SERVER_PORT_1, &server_socket_1);

    /* Check for error.  */
    if (status != NX_CONNECTION_PENDING)
        error_counter++;

    /* Check the socket state.  */
    if (server_socket_1.nx_tcp_socket_state != NX_TCP_LISTEN_STATE) 
        error_counter++;

    /* Check the mss value.  */
    if (server_socket_1.nx_tcp_socket_peer_mss != 1220)    
        error_counter++;

    /* Check the TCP port table.  */
    if ((ip_1.nx_ip_tcp_port_table[1] != &server_socket_0) || (ip_1.nx_ip_tcp_port_table[1] -> nx_tcp_socket_bound_next != &server_socket_1))
        error_counter++;
}         
     
static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
UINT            status;    
NX_TCP_HEADER  *tcp_header_ptr;
ULONG          *option_word_1;
ULONG           checksum;
ULONG           old_m;
ULONG           new_m;    
    
    /* Update the counter.  */
    syn_counter ++;

    /* Check the counter.  */
    if (syn_counter == 1)
    {
                      
        /* Update the packet prepend and length to include the IPv6 header.  */
        packet_ptr -> nx_packet_prepend_ptr -= 40;        
        packet_ptr -> nx_packet_length += 40;

        /* Store the packet.  */
        status = nx_packet_copy(packet_ptr, &copy_packet, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }
        else
        {           
                                 
            /* Update the packet IP header.  */
            copy_packet -> nx_packet_ip_header = copy_packet -> nx_packet_prepend_ptr;

            /* Update the packet prepend and length.  */
            copy_packet -> nx_packet_prepend_ptr += 40;        
            copy_packet -> nx_packet_length -= 40;

            /* Update the packet prepend and length to include the IPv6 header.  */
            packet_ptr -> nx_packet_prepend_ptr += 40;        
            packet_ptr -> nx_packet_length -= 40;
                                     
            /* Get the TCP header pointer.  */
            tcp_header_ptr =  (NX_TCP_HEADER *) copy_packet -> nx_packet_prepend_ptr;  
            option_word_1 = (ULONG *)(tcp_header_ptr + 1);

            /* Swap the endianess.  */
            NX_CHANGE_ULONG_ENDIAN(*option_word_1);        
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);    
                                                                                
            /* Get the old checksum (HC) in header. */
            checksum = tcp_header_ptr -> nx_tcp_header_word_4 >> 16; 
                              
            /* Get the old mss. */
            old_m = *option_word_1 & 0x0000FFFF;;                                       

            /* Set the new TTL as 1. */
            new_m = 0;       
                              
            /* Update the mss value as zero.  */ 
            *option_word_1 = NX_TCP_MSS_OPTION | new_m;  

            /* Update the checksum, get the new checksum(HC'),
            The new_m is ULONG value, so need get the lower value after invert. */
            checksum = ((~checksum) & 0xFFFF) + ((~old_m) & 0xFFFF) + new_m;

            /* Fold a 4-byte value into a two byte value */
            checksum = (checksum >> 16) + (checksum & 0xFFFF);

            /* Do it again in case previous operation generates an overflow */
            checksum = (checksum >> 16) + (checksum & 0xFFFF);          

            /* Now store the new checksum in the IP header.  */
            tcp_header_ptr -> nx_tcp_header_word_4 =  ((tcp_header_ptr -> nx_tcp_header_word_4 & 0x0000FFFF) | ((~checksum) << 16)); 
                                     
            /* Swap the endianess.  */
            NX_CHANGE_ULONG_ENDIAN(*option_word_1);       
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);    
        }                   
    }                              

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}                    
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_socket_relisten_test2_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Socket Relisten Test 2................................N/A\n");

    test_control_return(3);      
}
#endif
