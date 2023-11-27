/* This NetX test case test _nx_tcp_packet_receive function with non standard operation .  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_tcp.h"
#include    "nx_ip.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;   
static UINT                    packet_count = 0;        
                                             
static NX_PACKET               *my_packet1;
static NX_PACKET               *my_packet2;  
static NX_PACKET               *copy_packet_1;  
static NX_PACKET               *copy_packet_2;
static NX_PACKET               *copy_packet_3;

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_packet_receive_function_test_application_define(void *first_unused_memory)
#endif
{
    CHAR       *pointer;
    UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = _nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += _nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1,2,3,5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer = pointer + 2048;
                                     
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;       

    /* Check ARP enable status.  */
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
    UINT       status;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Packet Receive Function Test..........................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
        NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 600,
        NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Attempt to connect the socket.  */
    tx_thread_relinquish();

    /* Determine if the timeout error occurred.  */
    if((status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Call connect.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1,2,3,5), 12, 5 * NX_IP_PERIODIC_RATE);
                   
    /* Check for error.  */
    if((status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet1, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check for error.  */
    if((status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                  

    memcpy(my_packet1 -> nx_packet_prepend_ptr,"ABCDEFGHIJKLMNOPQRSTUVWXYZ12", 28);
    my_packet1 -> nx_packet_length = 28;
    my_packet1 -> nx_packet_append_ptr = my_packet1 -> nx_packet_prepend_ptr + 28;

    /* Send the packet.  */
    status = nx_tcp_socket_send(&client_socket, my_packet1, 2 * NX_IP_PERIODIC_RATE);
                
    /* Check for error.  */
    if((status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   
                      
    /* Point to new receive function */
    ip_1.nx_ip_tcp_packet_receive = packet_receive;
               
    /* Allocate a new packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet2, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check for error.  */
    if((status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                  

    memcpy(my_packet2 -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ12", 28);
    my_packet2 -> nx_packet_length = 28;
    my_packet2 -> nx_packet_append_ptr = my_packet2 -> nx_packet_prepend_ptr + 28;

    /* Send the packet.  */
    status = nx_tcp_socket_send(&client_socket, my_packet2, 2 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
    {   
        printf("ERROR!\n");
        test_control_return(1);
    }                        
}

static void    thread_1_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;  
NX_PACKET  *packet_ptr;      
#ifndef NX_DISABLE_RX_SIZE_CHECKING
NX_PACKET  *invalid_packet;
#endif

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
        NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 650,
        NX_NULL, thread_1_disconnect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, thread_1_connect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    if(status)
        error_counter++;

    /* Receive a TCP message from the socket.  */
    status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }
    else
    {

        /* Release the packet.  */
        nx_packet_release(packet_ptr);
    }                   
                       
#ifndef NX_DISABLE_RX_SIZE_CHECKING
    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &invalid_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check for error.  */
    if((status != NX_SUCCESS))
    {                           
        error_counter++;
    }                  

    /* Set the packet length with invalid value.  */
    memcpy(invalid_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ12", 28);
    invalid_packet -> nx_packet_length = sizeof(NX_TCP_HEADER) - 1;
    invalid_packet -> nx_packet_append_ptr = invalid_packet -> nx_packet_prepend_ptr + invalid_packet -> nx_packet_length;
            
    /* Directly call _nx_tcp_packet_receive invalid packet.  */
    _nx_tcp_packet_receive(&ip_1, invalid_packet);
    
    /* Receive a TCP message from the socket.  */
    status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status == NX_SUCCESS)
    {
        error_counter++;
    }   
#endif
                                                    
    /* Obtain the IP internal mutex before processing the IP event.  */
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);  

    /* Directly call _nx_tcp_packet_receive valid packet.  */
    _nx_tcp_packet_receive(&ip_1, copy_packet_1);      

    /* Directly call _nx_tcp_packet_receive valid packet.  */
    _nx_tcp_packet_receive(&ip_1, copy_packet_2);

    /* Directly call _nx_tcp_packet_receive to receive packet with incorrect checksum.  */
    _nx_tcp_packet_receive(&ip_1, copy_packet_3);      
                                               
    /* Release the IP internal mutex.  */
    tx_mutex_put(&(ip_1.nx_ip_protection));         

    /* Receive a TCP message from the socket.  */
    status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }    
    else
    {

        /* Release the packet.  */
        nx_packet_release(packet_ptr);
    }          

    /* Determine if the test was successful.  */
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

static void    thread_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void    thread_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if(socket != &server_socket)
        error_counter++;
}
                                                                                                           
static void    packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{         
    UINT    status;        

    /* Only store the packet one time.  */
    if (packet_count == 0)
    {

        /* Update the packet prepend and length to include the IP header.  */
        packet_ptr -> nx_packet_prepend_ptr -= 20;        
        packet_ptr -> nx_packet_length += 20;

        /* Store the packet.  */
        status = nx_packet_copy(packet_ptr, &copy_packet_1, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }
        else
        {           

            /* Update the packet prepend and length.  */
            copy_packet_1 -> nx_packet_prepend_ptr += 20;        
            copy_packet_1 -> nx_packet_length -= 20;
        }
        
        /* Store the packet.  */
        status = nx_packet_copy(packet_ptr, &copy_packet_2, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }
        else
        {                 

            /* Update the packet prepend and length.  */
            copy_packet_2 -> nx_packet_prepend_ptr += 20;        
            copy_packet_2 -> nx_packet_length -= 20;
        }
        
        /* Store the packet.  */
        status = nx_packet_copy(packet_ptr, &copy_packet_3, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }
        else
        {                 

            /* Update the packet prepend and length.  */
            copy_packet_3 -> nx_packet_prepend_ptr += 20;        
            copy_packet_3 -> nx_packet_length -= 20;

            /* Clear the checksum field. */
            *(copy_packet_3 -> nx_packet_prepend_ptr + 16) = 0;
            *(copy_packet_3 -> nx_packet_prepend_ptr + 17) = 0;
        }

        /* Update the packet count.  */
        packet_count ++;   
    }          

    /* Release the packet.  */
    nx_packet_release(packet_ptr);

    /* Stop the process.  */
    return;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_packet_receive_function_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Packet Receive Function Test..........................N/A\n"); 

    test_control_return(3);  
}      
#endif