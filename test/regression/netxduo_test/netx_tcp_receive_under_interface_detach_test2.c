/* This NetX test concentrates on the TCP Socket connect reset operation under interface deatch(tested receive queue count).  */

#include   "tx_api.h"
#include   "nx_api.h"
                          
extern void  test_control_return(UINT status);
                                     
#if defined __PRODUCT_NETXDUO__ && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0; 
static TX_THREAD               ntest_1;      
static TX_THREAD               ntest_2;   

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;       
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;     
static NX_TCP_SOCKET           server_socket;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   ntest_2_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);  
static void    ntest_1_entry(ULONG thread_input);    
static void    ntest_2_entry(ULONG thread_input);   
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_receive_under_interface_detach_test2_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;         

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;  
                                               
    /* Create the main thread.  */
    tx_thread_create(&ntest_2, "thread 2", ntest_2_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
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
                                          
    /* Create an IP instance.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;    
                             
    /* Set the second interface.  */
    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_256);
    status += nx_ip_interface_attach(&ip_1, "Second Interface", IP_ADDRESS(2, 2, 3, 5), 0xFFFFFF00UL, _nx_ram_network_driver_256);
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
                                  
    /* Check ARP enable status.  */
    if (status)
        error_counter++;        

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
                                  
    /* Check ARP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);                  
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}
           

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Receive Under Interface Detach Test2..................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;        
                          
    /* Bind the client_socket port to 12.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_NO_WAIT);

    /* Check for error.  */
    if (status)
        error_counter++;          

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(2, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Resume the thread 2.  */
    tx_thread_resume(&ntest_2);

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)    
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the packet out! This packe should not be sent.  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)
    {
        error_counter++;
    }
             
    /* Let other threads run again.  */
    tx_thread_relinquish();

    /* Check the error counter.  */
    if ((error_counter) || (ntest_2_counter != 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {

        /* Output successful.  */
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}                       
         
/* Define the test threads.  */

static void    ntest_1_entry(ULONG thread_input)
{                                                                                                       
              
UINT        status;

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                   NX_NULL, NX_NULL);
                                
    /* Check for error.  */
    if (status)
        error_counter++;            

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 2 * NX_IP_PERIODIC_RATE); 

    /* Check for error.  */
    if (status)
        error_counter++;                                           
}    
       

/* Define the test threads.  */

static void    ntest_2_entry(ULONG thread_input)
{                                                                                                       
              
UINT        status;
                             
    /* Update the ntest_2_counter.  */
    ntest_2_counter++;

    /* Check the TCP socket receive queue count.  */  
    if (server_socket.nx_tcp_socket_receive_queue_count != 1)       
        error_counter++;
                                       
    /* Detach the second interface for IP instance 2.  */
    status = nx_ip_interface_detach(&ip_1, 1);

    /* Check the status.  */
    if (status)
        error_counter++;
      
    /* Check the TCP socket receive queue count.  */      
    if (server_socket.nx_tcp_socket_receive_queue_count != 1)       
        error_counter++;
}    
#else       
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_receive_under_interface_detach_test2_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   TCP Receive Under Interface Detach Test2..................N/A\n");
    test_control_return(3);
}
#endif