/* This NetX test concentrates on the basic TCP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
                       
extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048       

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           client_socket;            


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_error_operation_check_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

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

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for IP instances 0.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;      
}
                   

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NXD_ADDRESS server_ip;


    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Error Operation Check Test............................");

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
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the server IP address.  */
    server_ip.nxd_ip_version = NX_IP_VERSION_V4;
    server_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);    
    
    /* Call connect before port bound.  */ 
    status = nxd_tcp_client_socket_connect(&client_socket, &server_ip, 12, 5 * NX_IP_PERIODIC_RATE);
                         
    /* Check for error.  */
    if (status != NX_NOT_BOUND)    
    {
        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)           
    {
        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Set the unreachable IPv4 address.  */  
    server_ip.nxd_ip_version = NX_IP_VERSION_V4;
    server_ip.nxd_ip_address.v4 = IP_ADDRESS(2, 2, 3, 5);
                                            
    /* Call connect with error address.  */ 
    status = nxd_tcp_client_socket_connect(&client_socket, &server_ip, 12, 5 * NX_IP_PERIODIC_RATE);
                         
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)    
    {
        printf("ERROR!\n");
        test_control_return(1);
    }        

#ifdef FEATURE_NX_IPV6
    /* Set the unreachable IPv6 address.  */  
    server_ip.nxd_ip_version = NX_IP_VERSION_V6; 
    server_ip.nxd_ip_address.v6[0] = 0x20010000;
    server_ip.nxd_ip_address.v6[1] = 0x00000000;
    server_ip.nxd_ip_address.v6[2] = 0x00000000;
    server_ip.nxd_ip_address.v6[3] = 0x10000002;  
                                              
    /* Call connect with error address.  */ 
    status = nxd_tcp_client_socket_connect(&client_socket, &server_ip, 12, 5 * NX_IP_PERIODIC_RATE);
                         
    /* Check for error.  */
    if (status != NX_NO_INTERFACE_ADDRESS)    
    {
        printf("ERROR!\n");
        test_control_return(1);
    }     
#endif

#ifndef NX_DISABLE_ERROR_CHECKING
    /* Set the error address version.  */  
    server_ip.nxd_ip_version = 0x05;
    server_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
             
    /* Call connect with error address.  */ 
    status = nxd_tcp_client_socket_connect(&client_socket, &server_ip, 12, 5 * NX_IP_PERIODIC_RATE);
                         
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)    
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   
#endif /* NX_DISABLE_ERROR_CHECKING */
         
    /* Set the server address.  */  
    server_ip.nxd_ip_version = NX_IP_VERSION_V4;
    server_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    /* Set the small interface mtu.  */ 
    status = nx_ip_interface_mtu_set(&ip_0, 0, 20);
                                                     
    /* Check for error.  */
    if (status)    
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Call connect with small interface mtu.  */ 
    status = nxd_tcp_client_socket_connect(&client_socket, &server_ip, 12, 5 * NX_IP_PERIODIC_RATE);
                         
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)    
    {
        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}          
#else   
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_error_operation_check_test_application_define(void *first_unused_memory)
#endif
{                                                              

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Error Operation Check Test............................N/A\n");   
        
    test_control_return(3);     
}
#endif    
