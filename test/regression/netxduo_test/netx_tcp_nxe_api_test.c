/* This NetX test concentrates on the basic TCP operation.  */

#include   "nx_tcp.h"
#include   "tx_api.h"
#include   "nx_api.h"    
#include   "nx_ip.h"
#include   "nx_packet.h"    
                                
extern void  test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048           

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
#ifdef __PRODUCT_NETXDUO__ 
static NX_PACKET_POOL          invalid_pool;
#endif /* __PRODUCT_NETXDUO__ */
static NX_IP                   ip_0;
static NX_IP                   ip_1;  
static NX_IP                   invalid_ip;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;  
static NX_TCP_SOCKET           invalid_socket;       

/* Define the counters used in the demo application...  */
static ULONG                   error_counter =     0;


/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);   
static void    tcp_receive_notify(NX_TCP_SOCKET *socket_ptr); 
#if defined(NX_ENABLE_TCP_QUEUE_DEPTH_UPDATE_NOTIFY) && defined(__PRODUCT_NETXDUO__)
static void    tcp_socket_queue_depth_notify(NX_TCP_SOCKET *socket_ptr);
#endif             
#ifdef __PRODUCT_NETXDUO__
static void    window_update_notify(NX_TCP_SOCKET *socket_ptr); 
#endif /* __PRODUCT_NETXDUO__ */
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

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

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++; 
}              


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *packet;    
NX_PACKET   *unknow_packet;
#ifdef __PRODUCT_NETXDUO__
NX_PACKET   invalid_packet;   
NX_PACKET   *invalid_packet_2;  
#endif /* __PRODUCT_NETXDUO__ */   
#ifdef FEATURE_NX_IPV6    
NXD_ADDRESS ip_address;
NXD_ADDRESS nxd_ip_address;
#endif
UINT        port;
UINT        free_port;
ULONG       mss, peer_mss, peer_ip_address, peer_port, bytes_available;
ULONG       tcp_packets_sent, tcp_bytes_sent, tcp_packets_received, tcp_bytes_received, tcp_invalid_packets, tcp_receive_packets_dropped, tcp_checksum_errors, tcp_connections, tcp_disconnections, tcp_connections_dropped, tcp_retransmit_packets;
ULONG       packets_sent, bytes_sent, packets_received, bytes_received, retransmit_packets, packets_queued, checksum_errors, socket_state, transmit_queue_depth, transmit_window, receive_window;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP NXE API Test..........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       
    
    /************************************************/   
    /* Tested the nxe_tcp_enable api                */
    /************************************************/ 
    
    /* Enable the TCP feature for invalid IP instance.  */
    status = nx_tcp_enable(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Enable the TCP feature for valid IP instance.  */
    status = nx_tcp_enable(&ip_0); 
                
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      
           
    /* Enable the TCP feature for valid IP instance.  */
    status = nx_tcp_enable(&ip_1); 
                
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Enable the TCP feature again.  */
    status = nx_tcp_enable(&ip_0); 
                
    /* Check for error.  */
    if (status != NX_ALREADY_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
          
    /************************************************/   
    /* Tested the nxe_tcp_socket_create api         */
    /************************************************/ 
    
    /* Create the TCP socket for invalid IP instance.  */            
    status =  nx_tcp_socket_create(NX_NULL, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Create the TCP socket for invalid IP instance.  */            
    status =  nx_tcp_socket_create(&invalid_ip, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
           
    /* Create the TCP socket for invalid socket.  */            
    status =  nx_tcp_socket_create(&ip_0, NX_NULL, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Set the invalid IP instance parameter.  */
    invalid_ip.nx_ip_id = NX_IP_ID;
          
    /* Create the TCP socket with invalid structure size.  */            
    status =  _nxe_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL, sizeof(NX_TCP_SOCKET) + 1);

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Create the TCP socket for IP instance with  socket.  */            
    status =  nx_tcp_socket_create(&invalid_ip, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Create the TCP socket with invalid type of service.  */            
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   0xFFFFFFFF, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Create the TCP socket with invalid type of fragment.  */            
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, 0xFFFFFFFF, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                  

    /* Create the TCP socket with invalid time of live.  */            
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_DONT_FRAGMENT, 0xFFFFFFFF, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Create the TCP socket with invalid window size.  */            
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 0,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                 

#ifdef __PRODUCT_NETXDUO__
                                   
    /* Create the TCP socket with invalid window size.  */            
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, (1 << 30),
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
          
    /* Create the TCP socket with valid parameters.  */            
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Create the TCP socket with valid parameters.  */            
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
        
    /* Create the same Client socket again.  */            
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
              
    /************************************************/   
    /* Tested the nxe_tcp_free_port_find api        */
    /************************************************/ 
    
    /* Find the free port with invalid IP instance.  */            
    status =  nx_tcp_free_port_find(NX_NULL, 80, &free_port);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                     
    /* Clear the invalid IP instance ID.  */
    invalid_ip.nx_ip_id = NX_NULL; 

    /* Find the free port with invalid IP instance ID.  */            
    status =  nx_tcp_free_port_find(&invalid_ip, 80, &free_port);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Find the free port with invalid free port pointer.  */            
    status =  nx_tcp_free_port_find(&ip_0, 80, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set the invalid IP instance ID.  */
    invalid_ip.nx_ip_id = NX_IP_ID; 
           
    /* Find the free port when disable the TCP feature.  */            
    status =  nx_tcp_free_port_find(&invalid_ip, 80, &free_port);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
             
    /* Find the free port with invalid port.  */            
    status =  nx_tcp_free_port_find(&ip_0, 0xFFFFFFFF, &free_port);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
             
    /************************************************/   
    /* Tested the nxe_tcp_info_get api              */
    /************************************************/ 

    /* Get the TCP information with invalid IP instance.  */
    status =  nx_tcp_info_get(NX_NULL, &tcp_packets_sent, &tcp_bytes_sent, &tcp_packets_received, &tcp_bytes_received,
                              &tcp_invalid_packets, &tcp_receive_packets_dropped, &tcp_checksum_errors, &tcp_connections, 
                              &tcp_disconnections, &tcp_connections_dropped, &tcp_retransmit_packets);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
       
    /* Clear the invalid IP instance ID.  */
    invalid_ip.nx_ip_id = NX_NULL; 
               
    /* Get the TCP information with invalid IP instance ID.  */
    status =  nx_tcp_info_get(&invalid_ip, &tcp_packets_sent, &tcp_bytes_sent, &tcp_packets_received, &tcp_bytes_received,
                              &tcp_invalid_packets, &tcp_receive_packets_dropped, &tcp_checksum_errors, &tcp_connections, 
                              &tcp_disconnections, &tcp_connections_dropped, &tcp_retransmit_packets);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
           
    /* Set the invalid IP instance ID.  */
    invalid_ip.nx_ip_id = NX_IP_ID; 
                             
    /* Get the TCP information when disable the TCP feature.  */
    status =  nx_tcp_info_get(&invalid_ip, &tcp_packets_sent, &tcp_bytes_sent, &tcp_packets_received, &tcp_bytes_received,
                              &tcp_invalid_packets, &tcp_receive_packets_dropped, &tcp_checksum_errors, &tcp_connections, 
                              &tcp_disconnections, &tcp_connections_dropped, &tcp_retransmit_packets);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
         
             
    /************************************************/   
    /* Tested the nxe_tcp_client_socket_bind api    */
    /************************************************/
              
    /* Bind the port with invalid socket.  */            
    status =  nx_tcp_client_socket_bind(NX_NULL, 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          
                       
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Bind the port with invalid socket ID.  */            
    status =  nx_tcp_client_socket_bind(&invalid_socket, 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                                         
    /* Bind the port when disable TCP feature.  */            
    status =  nx_tcp_client_socket_bind(&invalid_socket, 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
                                          
    /* Bind the port with invalid prot.  */            
    status =  nx_tcp_client_socket_bind(&client_socket, 0xFFFFFFFF, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    


    /************************************************/   
    /* Tested the nxe_tcp_client_socket_connect api */
    /************************************************/
             
    /* Connect the TCP with invalid socket.  */            
    status =  nx_tcp_client_socket_connect(NX_NULL, IP_ADDRESS(1, 2, 3, 5), 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          
                       
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
         
    /* Connect the TCP with invalid socket ID.  */            
    status =  nx_tcp_client_socket_connect(&invalid_socket, IP_ADDRESS(1, 2, 3, 5), 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                    
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;

    /* Connect the TCP when disable the TCP feature.  */            
    status =  nx_tcp_client_socket_connect(&invalid_socket, IP_ADDRESS(1, 2, 3, 5), 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Connect the TCP with invalid IP address.  */            
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(0, 0, 0, 0), 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
#ifdef __PRODUCT_NETXDUO__
    if (status != NX_IP_ADDRESS_ERROR)
#else
    if (status != NX_NOT_BOUND)
#endif
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
         
    /* Connect the TCP with invalid IP address.  */            
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(255, 255, 255, 255), 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Connect the TCP with invalid port.  */            
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 0xFFFFFFFF, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
         
#ifdef FEATURE_NX_IPV6            
    /*************************************************/   
    /* Tested the nxde_tcp_client_socket_connect api */
    /*************************************************/

    /* Set the IP address.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
             
    /* Connect the TCP with invalid socket.  */            
    status =  nxd_tcp_client_socket_connect(NX_NULL, &ip_address, 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          
                       
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
         
    /* Connect the TCP with invalid socket ID.  */            
    status =  nxd_tcp_client_socket_connect(&invalid_socket, &ip_address, 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                    
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;

    /* Connect the TCP when disable the TCP feature.  */            
    status =  nxd_tcp_client_socket_connect(&invalid_socket, &ip_address, 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Connect the TCP with invalid IP address.  */            
    status =  nxd_tcp_client_socket_connect(&client_socket, NX_NULL, 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                  

    /* Set the IP address as invalid version.  */
    ip_address.nxd_ip_version = 0x80;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
         
    /* Connect the TCP with invalid IP address.  */            
    status =  nxd_tcp_client_socket_connect(&client_socket, &ip_address, 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
           
    /* Set the IP address as invalid address.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(255, 255, 255, 255);
         
    /* Connect the TCP with invalid IP address.  */            
    status =  nxd_tcp_client_socket_connect(&client_socket, &ip_address, 80, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
           
    /* Set the IP address as invalid address.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(128, 0, 0, 1);
         
    /* Connect the TCP with valid IP address and invalid port.  */            
    status =  nxd_tcp_client_socket_connect(&client_socket, &ip_address, 0xFFFFFFFF, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                         
    /* Set the IP address as valid address.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(192, 0, 0, 1);

    /* Connect the TCP with invalid port.  */            
    status =  nxd_tcp_client_socket_connect(&client_socket, &ip_address, 0xFFFFFFFF, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
#endif

    /************************************************/   
    /* Tested the nxe_tcp_client_socket_port_get api*/
    /************************************************/
                           
    /* Get the Client socket port with invalid socket.  */            
    status =  nx_tcp_client_socket_port_get(NX_NULL, &port);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Get the Client socket port with invalid socket ID.  */            
    status =  nx_tcp_client_socket_port_get(&invalid_socket, &port);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Get the Client socket port with invalid port pointer.  */            
    status =  nx_tcp_client_socket_port_get(&client_socket, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
          
    /* Get the Client socket port when disable TCP feature.  */            
    status =  nx_tcp_client_socket_port_get(&invalid_socket, &port);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
            
    /************************************************/   
    /* Tested the nxe_tcp_client_socket_unbind api  */
    /************************************************/
                         
    /* Unbind the Client socket with invalid socket.  */            
    status =  nx_tcp_client_socket_unbind(NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
                        
    /* Unbind the Client socket with invalid socket ID.  */            
    status =  nx_tcp_client_socket_unbind(&invalid_socket);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
       
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                         
    /* Unbind the Client socket when disable the TCP feature.  */            
    status =  nx_tcp_client_socket_unbind(&invalid_socket);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
            
    /************************************************/   
    /* Tested the nxe_tcp_server_socket_accept api  */
    /************************************************/
                           
    /* Accept the Server socket with invalid socket.  */            
    status =  nx_tcp_server_socket_accept(NX_NULL, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                                
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Accept the Server socket with invalid socket ID.  */            
    status =  nx_tcp_server_socket_accept(&invalid_socket, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
              
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
             
    /* Accept the Server socket when disable TCP feature.  */            
    status =  nx_tcp_server_socket_accept(&invalid_socket, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
      
    /************************************************/   
    /* Tested the nxe_tcp_server_socket_listen api  */
    /************************************************/
                        
    /* Listen the Server socket with invalid IP instance.  */            
    status =  nx_tcp_server_socket_listen(NX_NULL, 8080, &server_socket, 5, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Clear the IP instance ID.  */
    invalid_ip.nx_ip_id   = NX_NULL;
                     
    /* Listen the Server socket with invalid IP instance ID.  */            
    status =  nx_tcp_server_socket_listen(&invalid_ip, 8080, &server_socket, 5, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Listen the Server socket with invalid socket.  */            
    status =  nx_tcp_server_socket_listen(&ip_1, 8080, NX_NULL, 5, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                           

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Listen the Server socket with invalid socket ID.  */            
    status =  nx_tcp_server_socket_listen(&ip_1, 8080, &invalid_socket, 5, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                                       
    /* Set the IP instance ID.  */
    invalid_ip.nx_ip_id = NX_IP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_ip.nx_ip_tcp_packet_receive = NX_NULL;

    /* Listen the Server socket when disable the TCP feature.  */            
    status =  nx_tcp_server_socket_listen(&invalid_ip, 8080, &server_socket, 5, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /* Listen the Server socket with invalid port.  */            
    status =  nx_tcp_server_socket_listen(&ip_1, 0, &server_socket, 5, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Listen the Server socket with invalid port.  */            
    status =  nx_tcp_server_socket_listen(&ip_1, 0xFFFFFFFF, &server_socket, 5, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /************************************************/   
    /* Tested the nxe_tcp_server_socket_relisten api*/
    /************************************************/
                        
    /* Relisten the Server socket with invalid IP instance.  */            
    status =  nx_tcp_server_socket_relisten(NX_NULL, 8080, &server_socket);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Clear the IP instance ID.  */
    invalid_ip.nx_ip_id   = NX_NULL;
                     
    /* Relisten the Server socket with invalid IP instance ID.  */            
    status =  nx_tcp_server_socket_relisten(&invalid_ip, 8080, &server_socket);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Relisten the Server socket with invalid socket.  */            
    status =  nx_tcp_server_socket_relisten(&ip_1, 8080, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                           

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Relisten the Server socket with invalid socket ID.  */            
    status =  nx_tcp_server_socket_relisten(&ip_1, 8080, &invalid_socket);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                                       
    /* Set the IP instance ID.  */
    invalid_ip.nx_ip_id = NX_IP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_ip.nx_ip_tcp_packet_receive = NX_NULL;

    /* Relisten the Server socket when disable the TCP feature.  */            
    status =  nx_tcp_server_socket_relisten(&invalid_ip, 8080, &server_socket);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /* Relisten the Server socket with invalid port.  */            
    status =  nx_tcp_server_socket_relisten(&ip_1, 0, &server_socket);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Relisten the Server socket with invalid port.  */            
    status =  nx_tcp_server_socket_relisten(&ip_1, 0xFFFFFFFF, &server_socket);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /************************************************/   
    /* Tested the nxe_tcp_server_socket_unaccept api*/
    /************************************************/
           
    /* Unaccept the Server socket with invalid socket.  */            
    status =  nx_tcp_server_socket_unaccept(NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
          
    /* Unaccept the Server socket with invalid socket ID.  */            
    status =  nx_tcp_server_socket_unaccept(&invalid_socket);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                       
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                
    /* Unaccept the Server socket when disable TCP feature.  */            
    status =  nx_tcp_server_socket_unaccept(&invalid_socket);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
               
    /************************************************/   
    /* Tested the nxe_tcp_server_socket_unlisten api*/
    /************************************************/
                        
    /* Unlisten the Server socket with invalid IP instance.  */            
    status =  nx_tcp_server_socket_unlisten(NX_NULL, 8080);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Clear the IP instance ID.  */
    invalid_ip.nx_ip_id   = NX_NULL;
                     
    /* Unlisten the Server socket with invalid IP instance ID.  */            
    status =  nx_tcp_server_socket_unlisten(&invalid_ip, 8080);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                  
                                       
    /* Set the IP instance ID.  */
    invalid_ip.nx_ip_id = NX_IP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_ip.nx_ip_tcp_packet_receive = NX_NULL;

    /* Unlisten the Server socket when disable the TCP feature.  */            
    status =  nx_tcp_server_socket_unlisten(&invalid_ip, 8080);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /* Unlisten the Server socket with invalid port.  */            
    status =  nx_tcp_server_socket_unlisten(&ip_1, 0);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Unlisten the Server socket with invalid port.  */            
    status =  nx_tcp_server_socket_unlisten(&ip_1, 0xFFFFFFFF);
                
    /* Check for error.  */
    if (status != NX_INVALID_PORT)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
               
    /************************************************/   
    /* Tested the nxe_tcp_socket_bytes_available api*/
    /************************************************/
           
    /* Get the Server socket available bytes with invalid socket.  */            
    status =  nx_tcp_socket_bytes_available(NX_NULL, &bytes_available);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
          
    /* Get the Server socket available bytes with invalid socket ID.  */          
    status =  nx_tcp_socket_bytes_available(&invalid_socket, &bytes_available);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
            
    /* Get the Server socket available bytes with invalid bytes available pointer.  */          
    status =  nx_tcp_socket_bytes_available(&server_socket, NX_NULL);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                  
    /* Get the Server socket available bytes when disable the TCP feature.  */          
    status =  nx_tcp_socket_bytes_available(&invalid_socket, &bytes_available);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /************************************************/   
    /* Tested the nxe_tcp_socket_disconnect api     */
    /************************************************/
                      
    /* Disconnect the TCP with invalid socket.  */            
    status =  nx_tcp_socket_disconnect(NX_NULL, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                         
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Disconnect the TCP with invalid socket ID.  */            
    status =  nx_tcp_socket_disconnect(&invalid_socket, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
              
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
         
    /* Disconnect the TCP when disable TCP feature.  */            
    status =  nx_tcp_socket_disconnect(&invalid_socket, 5 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
               
    /************************************************/   
    /* Tested the nxe_tcp_socket_info_get api       */
    /************************************************/ 

    /* Get the TCP socket information with invalid socket.  */
    status =  nx_tcp_socket_info_get(NX_NULL, &packets_sent, &bytes_sent, 
                                     &packets_received, &bytes_received, 
                                     &retransmit_packets, &packets_queued,
                                     &checksum_errors, &socket_state,
                                     &transmit_queue_depth, &transmit_window,
                                     &receive_window);
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                           
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Get the TCP socket information with invalid socket ID.  */
    status =  nx_tcp_socket_info_get(&invalid_socket, &packets_sent, &bytes_sent, 
                                     &packets_received, &bytes_received, 
                                     &retransmit_packets, &packets_queued,
                                     &checksum_errors, &socket_state,
                                     &transmit_queue_depth, &transmit_window,
                                     &receive_window);
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              
                    
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
              
    /* Get the TCP socket information when disable TCP feature.  */
    status =  nx_tcp_socket_info_get(&invalid_socket, &packets_sent, &bytes_sent, 
                                     &packets_received, &bytes_received, 
                                     &retransmit_packets, &packets_queued,
                                     &checksum_errors, &socket_state,
                                     &transmit_queue_depth, &transmit_window,
                                     &receive_window);
                     
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                
                                  
    /************************************************/   
    /* Tested the nxe_tcp_socket_mss_get api       */
    /************************************************/ 
                               
    /* Get the socket mss with invalid socket.  */
    status =  nx_tcp_socket_mss_get(NX_NULL, &mss);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;       

    /* Get the socket mss with invalid socket.  */
    status =  nx_tcp_socket_mss_get(&invalid_socket, &mss);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          

    /* Get the socket mss with invalid mss pointer.  */
    status =  nx_tcp_socket_mss_get(&client_socket, NX_NULL);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                  

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                 
    /* Get the socket mss when disable TCP feature.  */
    status =  nx_tcp_socket_mss_get(&invalid_socket, &mss);
                      
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
                                   
    /************************************************/   
    /* Tested the nxe_tcp_socket_mss_peer_get api   */
    /************************************************/ 
                               
    /* Get the peer socket mss with invalid socket.  */
    status =  nx_tcp_socket_mss_peer_get(NX_NULL, &peer_mss);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;       

    /* Get the peer socket mss with invalid socket.  */
    status =  nx_tcp_socket_mss_peer_get(&invalid_socket, &peer_mss);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          

    /* Get the peer socket mss with invalid mss pointer.  */
    status =  nx_tcp_socket_mss_peer_get(&client_socket, NX_NULL);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                  

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                 
    /* Get the peer socket mss when disable TCP feature.  */
    status =  nx_tcp_socket_mss_peer_get(&invalid_socket, &peer_mss);
                      
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                      
    /************************************************/   
    /* Tested the nxe_tcp_socket_mss_set api        */
    /************************************************/ 
                               
    /* Set the socket mss with invalid socket.  */
    status =  nx_tcp_socket_mss_set(NX_NULL, 512);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;       

    /* Set the socket mss with invalid socket.  */
    status =  nx_tcp_socket_mss_set(&invalid_socket, 512);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                      

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                 
    /* Set the socket mss when disable TCP feature.  */
    status =  nx_tcp_socket_mss_set(&invalid_socket, 512);
                      
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /************************************************/   
    /* Tested the nxe_tcp_socket_peer_info_get api  */
    /************************************************/ 

    /* Get peer socket information with invalid socket.  */
    status =  nx_tcp_socket_peer_info_get(NX_NULL, &peer_ip_address, &peer_port); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
            
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;  

    /* Get peer socket information with invalid socket ID.  */
    status =  nx_tcp_socket_peer_info_get(&invalid_socket, &peer_ip_address, &peer_port); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
             
    /* Get peer socket information with invalid peer IP address pointer.  */
    status =  nx_tcp_socket_peer_info_get(&client_socket, NX_NULL, &peer_port); 
                     
    /* Check for error.  */
#ifdef __PRODUCT_NETXDUO__
    if (status != NX_PTR_ERROR)
#else
    if (status != NX_NOT_CONNECTED)
#endif
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
              
    /* Get peer socket information with invalid peer port pointer.  */
    status =  nx_tcp_socket_peer_info_get(&client_socket, &peer_ip_address, NX_NULL); 
                     
    /* Check for error.  */
#ifdef __PRODUCT_NETXDUO__
    if (status != NX_PTR_ERROR)
#else
    if (status != NX_NOT_CONNECTED)
#endif
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                    
    /* Get peer socket information when disable TCP feature.  */
    status =  nx_tcp_socket_peer_info_get(&invalid_socket, &peer_ip_address, &peer_port); 
                     
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                

                         
#ifdef FEATURE_NX_IPV6     
    /************************************************/   
    /* Tested the nxde_tcp_socket_peer_info_get api */
    /************************************************/ 

    /* Get peer socket information with invalid socket.  */
    status =  nxd_tcp_socket_peer_info_get(NX_NULL, &nxd_ip_address, &peer_port); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
            
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;  

    /* Get peer socket information with invalid socket ID.  */
    status =  nxd_tcp_socket_peer_info_get(&invalid_socket, &nxd_ip_address, &peer_port); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
             
    /* Get peer socket information with invalid peer IP address pointer.  */
    status =  nxd_tcp_socket_peer_info_get(&client_socket, NX_NULL, &peer_port); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
              
    /* Get peer socket information with invalid peer port pointer.  */
    status =  nxd_tcp_socket_peer_info_get(&client_socket, &nxd_ip_address, NX_NULL); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                    
    /* Get peer socket information when disable TCP feature.  */
    status =  nxd_tcp_socket_peer_info_get(&invalid_socket, &nxd_ip_address, &peer_port); 
                     
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                
#endif


#if defined(NX_ENABLE_TCP_QUEUE_DEPTH_UPDATE_NOTIFY) && defined(__PRODUCT_NETXDUO__)
    /*******************************************************/   
    /* Tested the nxe_tcp_socket_queue_depth_notify_set api*/
    /*******************************************************/ 

    /* Set the queue depth notify function with invalid socket.  */
    status =  nx_tcp_socket_queue_depth_notify_set(NX_NULL, tcp_socket_queue_depth_notify); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
    
    /* Set the queue depth notify function with invalid socket ID.  */
    status =  nx_tcp_socket_queue_depth_notify_set(&invalid_socket, tcp_socket_queue_depth_notify); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Set the queue depth notify function with invalid callback pointer.  */
    status =  nx_tcp_socket_queue_depth_notify_set(&client_socket, NX_NULL); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
    
    /* Set the queue depth notify function when disable TCP feature.  */
    status =  nx_tcp_socket_queue_depth_notify_set(&invalid_socket, tcp_socket_queue_depth_notify); 
                     
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
#endif
    
    /************************************************/   
    /* Tested the nxe_tcp_socket_receive api        */
    /************************************************/ 

    /* Receive a TCP message with invalid socket.  */
    status =  nx_tcp_socket_receive(NX_NULL, &packet, 5 * NX_IP_PERIODIC_RATE);
                          
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
          
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
                   
    /* Receive a TCP message with invalid socket ID.  */
    status =  nx_tcp_socket_receive(&invalid_socket, &packet, 5 * NX_IP_PERIODIC_RATE);
                          
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             

    /* Receive a TCP message with invalid packet pointer.  */
    status =  nx_tcp_socket_receive(&server_socket, NX_NULL, 5 * NX_IP_PERIODIC_RATE);
                          
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
             
    /* Receive a TCP message with invalid packet pointer.  */
    status =  nx_tcp_socket_receive(&invalid_socket, &packet, 5 * NX_IP_PERIODIC_RATE);
                          
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
              
    /************************************************/   
    /* Tested the nxe_tcp_socket_receive_notify api */
    /************************************************/ 
                     
    /* Set the socket receive notify function with invalid socket.  */
    status =  nx_tcp_socket_receive_notify(NX_NULL, tcp_receive_notify); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;   

    /* Set the socket receive notify function with invalid socket.  */
    status =  nx_tcp_socket_receive_notify(&invalid_socket, tcp_receive_notify); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       

#ifdef __PRODUCT_NETXDUO__
    /* Clear socket receive notify function.  */
    status =  nx_tcp_socket_receive_notify(&server_socket, NX_NULL);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
            
    /* Set the socket receive notify function when disable TCP feature.  */
    status =  nx_tcp_socket_receive_notify(&invalid_socket, tcp_receive_notify); 
                     
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
#endif /* __PRODUCT_NETXDUO__ */
            
    /************************************************/   
    /* Tested the nxe_tcp_socket_send api           */
    /************************************************/ 

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {             
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the packet with invalid socket.  */
    status =  nx_tcp_socket_send(NX_NULL, packet, 5 * NX_IP_PERIODIC_RATE);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
           
    /* Send the packet with invalid socket.  */
    status =  nx_tcp_socket_send(&invalid_socket, packet, 5 * NX_IP_PERIODIC_RATE);
                      
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Send the packet with invalid packet.  */
    unknow_packet = NX_NULL;
    status =  nx_tcp_socket_send(&client_socket, unknow_packet, 5 * NX_IP_PERIODIC_RATE);
                      
    /* Check for error.  */
    if (status != NX_INVALID_PACKET)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

#ifdef __PRODUCT_NETXDUO__
    /* Send the packet with freed packet.  */
    packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
    status =  nx_tcp_socket_send(&client_socket, packet, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status != NX_INVALID_PACKET)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
    packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#endif

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                     
    /* Send the packet when disable TCP feature.  */
    status =  nx_tcp_socket_send(&invalid_socket, packet, 5 * NX_IP_PERIODIC_RATE);
                      
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef __PRODUCT_NETXDUO__
    /* Set the socket ID, tcp_packet_receive and connect IP address.  */   
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    invalid_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_NULL;     

    /* Send the packet with invalid connect IP address.  */
    status =  nx_tcp_socket_send(&invalid_socket, packet, 5 * NX_IP_PERIODIC_RATE);
                      
    /* Check for error.  */
    if (status != NX_NOT_CONNECTED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
           
    /* Set the socket ID, tcp_packet_receive and connect IP address.  */   
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    invalid_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4; 
                
    /* Send the invalid packet that prepend pointer is less than data start.  */         
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;
    invalid_packet_2 -> nx_packet_pool_owner = (NX_PACKET_POOL *) &invalid_pool;
    invalid_packet_2 -> nx_packet_pool_owner -> nx_packet_pool_id = NX_PACKET_POOL_ID;
    invalid_packet_2 -> nx_packet_data_start = (UCHAR *)0x20;
    invalid_packet_2 -> nx_packet_prepend_ptr = (UCHAR *)0x10;
    invalid_packet_2 -> nx_packet_append_ptr = (UCHAR *)0x30;
    invalid_packet_2 -> nx_packet_data_end = (UCHAR *)0x40;  
    invalid_packet_2 -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *) NX_PACKET_ALLOCATED;
    status =  nx_tcp_socket_send(&invalid_socket, invalid_packet_2, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status != NX_UNDERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
           
    /* Append packet with invalid packet that prepend pointer is less than data start.  */     
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;     
    invalid_packet_2 -> nx_packet_pool_owner = (NX_PACKET_POOL *) &invalid_pool;  
    invalid_packet_2 -> nx_packet_pool_owner -> nx_packet_pool_id = NX_PACKET_POOL_ID;
    invalid_packet_2 -> nx_packet_data_start = (UCHAR *)0x10;
    invalid_packet_2 -> nx_packet_prepend_ptr = (UCHAR *)0x40;
    invalid_packet_2 -> nx_packet_append_ptr = (UCHAR *)0x80;
    invalid_packet_2 -> nx_packet_data_end = (UCHAR *)0x60;           
    invalid_packet_2 -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *) NX_PACKET_ALLOCATED;
    status =  nx_tcp_socket_send(&invalid_socket, invalid_packet_2, 5 * NX_IP_PERIODIC_RATE); 
         
    /* Check for error.  */
    if (status != NX_OVERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Release the packet*/   
    status =  nx_packet_release(packet);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
#endif /* __PRODUCT_NETXDUO__ */
          
    /************************************************/   
    /* Tested the nxe_tcp_socket_state_wait api     */
    /************************************************/ 

    /* Wait for state with invalid socket.  */
    status =  nx_tcp_socket_state_wait(NX_NULL, NX_TCP_ESTABLISHED, 5 * NX_IP_PERIODIC_RATE);  

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                      
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Wait for state with invalid socket ID.  */
    status =  nx_tcp_socket_state_wait(&invalid_socket, NX_TCP_ESTABLISHED, 5 * NX_IP_PERIODIC_RATE);  

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                   
    /* Wait for state when disable TCP feature.  */
    status =  nx_tcp_socket_state_wait(&invalid_socket, NX_TCP_ESTABLISHED, 5 * NX_IP_PERIODIC_RATE);  

    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Wait for state with invalid desired state.  */
    status =  nx_tcp_socket_state_wait(&client_socket, 0, 5 * NX_IP_PERIODIC_RATE);  

    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for state with invalid desired state.  */
    status =  nx_tcp_socket_state_wait(&client_socket, NX_TCP_LAST_ACK + 1, 5 * NX_IP_PERIODIC_RATE);  

    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                     
    /***************************************************/   
    /* Tested the nxe_tcp_socket_transmit_configure api*/
    /***************************************************/ 

    /* Configure the socket further with invalid socket.  */
    status =  nx_tcp_socket_transmit_configure(NX_NULL, 10, 300, 10, 0);
                          
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
                  
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Configure the socket further with invalid socket ID.  */
    status =  nx_tcp_socket_transmit_configure(&invalid_socket, 10, 300, 10, 0);
                          
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      
                
    /* Configure the socket further with invalid max queue depth.  */
    status =  nx_tcp_socket_transmit_configure(&server_socket, 0, 300, 10, 0);
                          
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

#ifdef __PRODUCT_NETXDUO__ 
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
            
    /* Configure the socket further when disable TCP feature.  */
    status =  nx_tcp_socket_transmit_configure(&invalid_socket, 10, 300, 10, 0);
                          
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               
          
    /*********************************************************/   
    /* Tested the nxe_tcp_socket_window_update_notify_set api*/
    /*********************************************************/ 
                
    /* Set the queue depth notify function with invalid socket.  */
    status =  nx_tcp_socket_window_update_notify_set(NX_NULL, window_update_notify); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
                
    /* Set the queue depth notify function with invalid socket.  */
    status =  nx_tcp_socket_window_update_notify_set(&invalid_socket, window_update_notify); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
                 
    /* Set the queue depth notify function with invalid notify function.  */
    status =  nx_tcp_socket_window_update_notify_set(&client_socket, NX_NULL); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
            
    /* Set the queue depth notify function when disable TCP feature.  */
    status =  nx_tcp_socket_window_update_notify_set(&invalid_socket, window_update_notify); 
                     
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       
                                                                  
    /************************************************/   
    /* Tested the nxe_tcp_socket_delete api         */
    /************************************************/
                                    
    /* Delete the TCP socket with invalid socket.  */
    status =  nx_tcp_socket_delete(NX_NULL); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              

    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;
                                      
    /* Delete the TCP socket with invalid socket ID.  */
    status =  nx_tcp_socket_delete(&invalid_socket); 
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
          
    /* Set the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_TCP_ID;

    /* Disable the TCP feature for invalid IP instance.  */
    invalid_socket.nx_tcp_socket_ip_ptr = (NX_IP *)&invalid_ip;
    invalid_socket.nx_tcp_socket_ip_ptr -> nx_ip_tcp_packet_receive = NX_NULL;
                                  
    /* Delete the TCP socket when disable TCP feature.  */
    status =  nx_tcp_socket_delete(&invalid_socket); 
                     
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

#ifdef NX_ENABLE_LOW_WATERMARK
    /* Clear the socket ID.  */
    invalid_socket.nx_tcp_socket_id  = NX_NULL;

    /* Set receive queue to invalid socket. */
    status = nx_tcp_socket_receive_queue_max_set(&invalid_socket, 10);
                     
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
#endif /* NX_ENABLE_LOW_WATERMARK */
#endif /* __PRODUCT_NETXDUO__ */                                                                                                   
    
    printf("SUCCESS!\n");
    test_control_return(0);
}             
         
#if defined(NX_ENABLE_TCP_QUEUE_DEPTH_UPDATE_NOTIFY) && defined(__PRODUCT_NETXDUO__)
static void  tcp_socket_queue_depth_notify(NX_TCP_SOCKET *socket_ptr)
{
}
#endif
#ifdef __PRODUCT_NETXDUO__ 
static void  window_update_notify(NX_TCP_SOCKET *socket_ptr)
{
}               
#endif /* __PRODUCT_NETXDUO__ */
static void  tcp_receive_notify(NX_TCP_SOCKET *socket_ptr)
{             
} 
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP NXE API Test..........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
