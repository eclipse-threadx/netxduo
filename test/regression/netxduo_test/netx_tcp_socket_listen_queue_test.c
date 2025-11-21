/* This NetX test concentrates on the TCP Socket unaccept operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ip.h"
                                     
extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_IPV4)

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
static UINT                    v4_syn_counter = 0;        
static UINT                    v6_syn_counter = 0;  
static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
static NX_PACKET               *v4_syn_packet;     
static NX_PACKET               *v4_rst_packet;    
static NX_PACKET               *v6_syn_packet;   
static NX_PACKET               *v6_rst_packet;   
static NX_PACKET               *copy_packet[20];


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
void    netx_tcp_socket_listen_queue_test_application_define(void *first_unused_memory)
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

    /* Check ARP enable status.  */
    if(status)
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
UINT        client_port;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Socket Listen Queue Test..............................");

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
                                                           
    /* Call connect to send a SYN with IPv6 address.  */ 
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
                                                                       
    /* Call connect to send a SYN with IPv4 address.  */ 
    nx_tcp_client_socket_connect(&client_socket_1, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT_1, NX_NO_WAIT);                                  
                    
    /* Sleep 500 ticks, Server socket receive packet.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

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
UINT            i;         
NX_IPV6_HEADER  *ip_header_ptr;


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

    /* Sleep 0.5 second to receive the IPV4 SYN packet.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE/2);

    /* Copy the IP header.  */
    v4_syn_packet -> nx_packet_prepend_ptr -= 20;    
    v4_syn_packet -> nx_packet_length += 20;

    /* Copy the packet.  */
    status = nx_packet_copy(v4_syn_packet, &copy_packet[0], &pool_0, NX_NO_WAIT);   
             
    /* Check status .  */
    if (status)
    {
        error_counter ++;
    }
    else
    {

        /* Update the packet IP header.  */
        copy_packet[0] -> nx_packet_ip_header = copy_packet[0] -> nx_packet_prepend_ptr;

        /* Update the copy packet pointer.  */    
        copy_packet[0] -> nx_packet_prepend_ptr += 20;    
        copy_packet[0] -> nx_packet_length -= 20;

        tcp_checksum_compute(copy_packet[0]);

        /* Let server receive the packet.  */
        _nx_tcp_packet_receive(&ip_1, copy_packet[0]); 
    }
            
    /* Check the listen queue current count.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_next -> nx_tcp_listen_queue_current != 1)
        error_counter ++;
                         
    /* Copy the IP header.  */
    v4_rst_packet -> nx_packet_prepend_ptr -= 20;    
    v4_rst_packet -> nx_packet_length += 20;

    /* Copy the packet.  */
    status = nx_packet_copy(v4_rst_packet, &copy_packet[1], &pool_0, NX_NO_WAIT);   
                        
    /* Check status .  */
    if (status)
    {
        error_counter ++;
    }
    else
    {
                          
        /* Update the packet IP header.  */
        copy_packet[1] -> nx_packet_ip_header = copy_packet[1] -> nx_packet_prepend_ptr;
                                                                                      
        /* Update the copy packet pointer.  */    
        copy_packet[1] -> nx_packet_prepend_ptr += 20;    
        copy_packet[1] -> nx_packet_length -= 20;

        tcp_checksum_compute(copy_packet[1]);

        /* Let server receive the packet.  */
        _nx_tcp_packet_receive(&ip_1, copy_packet[1]); 
    }
              
    /* Check the listen queue current count.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_next -> nx_tcp_listen_queue_current != 0)
        error_counter ++;
                        
    /* Copy the IP header.  */
    v6_syn_packet -> nx_packet_prepend_ptr -= 40;    
    v6_syn_packet -> nx_packet_length += 40;

    /* Copy the packet.  */
    status = nx_packet_copy(v6_syn_packet, &copy_packet[2], &pool_0, NX_NO_WAIT); 

    /* Check status .  */
    if (status)
    {
        error_counter ++;
    }
    else
    {
                    
        /* Update the packet IP header.  */
        copy_packet[2] -> nx_packet_ip_header = copy_packet[2] -> nx_packet_prepend_ptr;
                                                                           
        /* Update the copy packet pointer.  */    
        copy_packet[2] -> nx_packet_prepend_ptr += 40;    
        copy_packet[2] -> nx_packet_length -= 40;

        tcp_checksum_compute(copy_packet[2]);

        /* Let server receive the packet.  */
        _nx_tcp_packet_receive(&ip_1, copy_packet[2]); 
    }
              
    /* Check the listen queue current count.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_next -> nx_tcp_listen_queue_current != 1)
        error_counter ++;
                       
    /* Copy the IP header.  */
    v6_rst_packet -> nx_packet_prepend_ptr -= 40;    
    v6_rst_packet -> nx_packet_length += 40;

    /* Copy the packet.  */
    status = nx_packet_copy(v6_rst_packet, &copy_packet[3], &pool_0, NX_NO_WAIT);   
                    
    /* Check status .  */
    if (status)
    {
        error_counter ++;
    }
    else
    {
                           
        /* Update the packet IP header.  */
        copy_packet[3] -> nx_packet_ip_header = copy_packet[3] -> nx_packet_prepend_ptr;
                                                          
        /* Update the copy packet pointer.  */    
        copy_packet[3] -> nx_packet_prepend_ptr += 40;    
        copy_packet[3] -> nx_packet_length -= 40;

        tcp_checksum_compute(copy_packet[3]);

        /* Let server receive the packet.  */
        _nx_tcp_packet_receive(&ip_1, copy_packet[3]);
    }  

    /* Check the listen queue current count.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_next -> nx_tcp_listen_queue_current != 0)
        error_counter ++;

    /* Loop to recieve the SYN packet with different source address.  */
    for (i = 4; i< 15; i++)
    {

        /* Copy the packet.  */
        status = nx_packet_copy(v6_syn_packet, &copy_packet[i], &pool_0, NX_NO_WAIT);   

        /* Check status .  */
        if (status)
        {
            error_counter ++;
        }
        else
        {

            /* Update the packet IP header.  */
            copy_packet[i] -> nx_packet_ip_header = copy_packet[i] -> nx_packet_prepend_ptr;   
                       
            /* Update the source IP address.  */
            if (i >= 6)
            {             

                /* Points to the base of IPv6 header. */
                ip_header_ptr = (NX_IPV6_HEADER*)copy_packet[i] -> nx_packet_prepend_ptr;

                /* Update the address.  */
                ip_header_ptr -> nx_ip_header_source_ip[3] += i;   
            }
                         
            /* Update the copy packet pointer.  */    
            copy_packet[i] -> nx_packet_prepend_ptr += 40;    
            copy_packet[i] -> nx_packet_length -= 40;

            tcp_checksum_compute(copy_packet[i]);

            /* Let server receive the packet.  */
            _nx_tcp_packet_receive(&ip_1, copy_packet[i]);
        }
    }

    /* Check the listen queue current count.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_next -> nx_tcp_listen_queue_current != 5)
        error_counter ++;

    /* Loop to recieve the RST packet with different source address.  */
    for (i = 14; i >= 4; i--)
    {

        /* Copy the packet.  */
        status = nx_packet_copy(v6_rst_packet, &copy_packet[i], &pool_0, NX_NO_WAIT);   

        /* Check status .  */
        if (status)
        {
            error_counter ++;
        }
        else
        {

            /* Update the packet IP header.  */
            copy_packet[i] -> nx_packet_ip_header = copy_packet[i] -> nx_packet_prepend_ptr;   
                       
            /* Update the source IP address.  */
            if (i >= 6)
            {             

                /* Points to the base of IPv6 header. */
                ip_header_ptr = (NX_IPV6_HEADER*)copy_packet[i] -> nx_packet_prepend_ptr;

                /* Update the address.  */
                ip_header_ptr -> nx_ip_header_source_ip[3] += i;   
            }
                         
            /* Update the copy packet pointer.  */    
            copy_packet[i] -> nx_packet_prepend_ptr += 40;    
            copy_packet[i] -> nx_packet_length -= 40;

            tcp_checksum_compute(copy_packet[i]);

            /* Let server receive the packet.  */
            _nx_tcp_packet_receive(&ip_1, copy_packet[i]);
        }
    }

    /* Check the listen queue current count.  */
    if (ip_1.nx_ip_tcp_active_listen_requests -> nx_tcp_listen_next -> nx_tcp_listen_queue_current != 0)
        error_counter ++;
}         
     
static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
UINT            status;     
NX_TCP_HEADER   *tcp_header_ptr;
ULONG           tcp_header_word_3;
    

    /* Check the packet version.   */
    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
    {        

        /* Get the TCP header.  */ 
        tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

        /* Get the word.  */
        tcp_header_word_3 = tcp_header_ptr -> nx_tcp_header_word_3;

        /* Swap the endianess.  */
        NX_CHANGE_ULONG_ENDIAN(tcp_header_word_3);

        /* Check if the packet is an SYN packet.  */
        if (tcp_header_word_3 & NX_TCP_SYN_BIT)
        {

            /* Update the counter.  */
            v4_syn_counter ++;

            /* Check the counter.  */
            if (v4_syn_counter == 1)
            {

                /* Update the packet prepend and length to include the IPv4 header.  */
                packet_ptr -> nx_packet_prepend_ptr -= 20;        
                packet_ptr -> nx_packet_length += 20;

                /* Store the packet.  */
                status = nx_packet_copy(packet_ptr, &v4_syn_packet, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

                /* Check for error.  */
                if (status)
                {
                    error_counter++;
                }
                else
                {           

                    /* Update the packet IP header.  */
                    v4_syn_packet -> nx_packet_ip_header = v4_syn_packet -> nx_packet_prepend_ptr;

                    /* Update the packet prepend and length.  */
                    v4_syn_packet -> nx_packet_prepend_ptr += 20;        
                    v4_syn_packet -> nx_packet_length -= 20;                                                             
                }                       

                /* Store the packet.  */
                status = nx_packet_copy(packet_ptr, &v4_rst_packet, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

                /* Check for error.  */
                if (status)
                {
                    error_counter++;
                }
                else
                {           

                    /* Update the packet IP header.  */
                    v4_rst_packet -> nx_packet_ip_header = v4_rst_packet -> nx_packet_prepend_ptr;

                    /* Update the packet prepend and length.  */
                    v4_rst_packet -> nx_packet_prepend_ptr += 20;        
                    v4_rst_packet -> nx_packet_length -= 20;                           

                    /* Get the TCP header.  */ 
                    tcp_header_ptr = (NX_TCP_HEADER *)v4_rst_packet -> nx_packet_prepend_ptr;

                    /* Swap the endianess.  */
                    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

                    /* Clear the SYN bit and set the RST bit.  */   
                    tcp_header_ptr -> nx_tcp_header_word_3 = (tcp_header_ptr -> nx_tcp_header_word_3 & (~NX_TCP_SYN_BIT)) | NX_TCP_RST_BIT;      

                    /* Swap the endianess.  */
                    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);   
                }

                /* Update the packet prepend and length to include the IPv4 header.  */
                packet_ptr -> nx_packet_prepend_ptr += 20;        
                packet_ptr -> nx_packet_length -= 20;
            } 
        }
    }
    else if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
    {

        /* Get the TCP header.  */ 
        tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

        /* Get the word.  */
        tcp_header_word_3 = tcp_header_ptr -> nx_tcp_header_word_3;

        /* Swap the endianess.  */
        NX_CHANGE_ULONG_ENDIAN(tcp_header_word_3);

        /* Check if the packet is an SYN packet.  */
        if (tcp_header_word_3 & NX_TCP_SYN_BIT)
        {

            /* Update the counter.  */
            v6_syn_counter ++;

            /* Check the counter.  */
            if (v6_syn_counter == 1)
            {

                /* Update the packet prepend and length to include the IPv6 header.  */
                packet_ptr -> nx_packet_prepend_ptr -= 40;        
                packet_ptr -> nx_packet_length += 40;

                /* Store the packet.  */
                status = nx_packet_copy(packet_ptr, &v6_syn_packet, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

                /* Check for error.  */
                if (status)
                {
                    error_counter++;
                }
                else
                {           

                    /* Update the packet IP header.  */
                    v6_syn_packet -> nx_packet_ip_header = v6_syn_packet -> nx_packet_prepend_ptr;

                    /* Update the packet prepend and length.  */
                    v6_syn_packet -> nx_packet_prepend_ptr += 40;        
                    v6_syn_packet -> nx_packet_length -= 40;                                                             
                }                      
                     
                /* Store the packet.  */
                status = nx_packet_copy(packet_ptr, &v6_rst_packet, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

                /* Check for error.  */
                if (status)
                {
                    error_counter++;
                }
                else
                {           

                    /* Update the packet IP header.  */
                    v6_rst_packet -> nx_packet_ip_header = v6_rst_packet -> nx_packet_prepend_ptr;

                    /* Update the packet prepend and length.  */
                    v6_rst_packet -> nx_packet_prepend_ptr += 40;        
                    v6_rst_packet -> nx_packet_length -= 40;              
      

                    /* Get the TCP header.  */ 
                    tcp_header_ptr = (NX_TCP_HEADER *)v6_rst_packet -> nx_packet_prepend_ptr;

                    /* Swap the endianess.  */
                    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

                    /* Clear the SYN bit and set the RST bit.  */   
                    tcp_header_ptr -> nx_tcp_header_word_3 = (tcp_header_ptr -> nx_tcp_header_word_3 & (~NX_TCP_SYN_BIT)) | NX_TCP_RST_BIT;      

                    /* Swap the endianess.  */
                    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);   
                }   

                /* Update the packet prepend and length to include the IPv6 header.  */
                packet_ptr -> nx_packet_prepend_ptr += 40;        
                packet_ptr -> nx_packet_length -= 40;
            } 
        }
    }

    tcp_checksum_compute(packet_ptr);

    /* Let server receive the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}                    


#if defined(__PRODUCT_NETXDUO__)
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
static void    tcp_checksum_compute(PACKET *packet_ptr)
{
NX_TCP_HEADER  *tcp_header_ptr;   
ULONG           source_ip, dest_ip;
ULONG           checksum;

    /* Get IPv4 addresses. */
    source_ip = *(ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 8);
    dest_ip = *(ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 4);
    
    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);

    /* Calculate the TCP checksum.  */
    tcp_header_ptr -> nx_tcp_header_word_4 = 0;

    /* Calculate the checksum.  */
    checksum = _nx_tcp_checksum(packet_ptr, source_ip, dest_ip);
    tcp_header_ptr -> nx_tcp_header_word_4 = (checksum << NX_SHIFT_BY_16);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
}
#endif /* __PRODUCT_NETXDUO__ */

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_socket_listen_queue_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Socket Listen Queue Test..............................N/A\n");

    test_control_return(3);      
}
#endif
