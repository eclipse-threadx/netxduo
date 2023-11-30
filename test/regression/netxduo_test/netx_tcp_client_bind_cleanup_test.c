/* This NetX test concentrates on the TCP Client Bind Cleanup operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0; 
static TX_THREAD               ntest_1;   
static TX_THREAD               ntest_2;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           client_socket_0;    
static NX_TCP_SOCKET           client_socket_1;         
static NX_TCP_SOCKET           client_socket_2;     


/* Define the counters used in the test application...  */

static ULONG                   error_counter;


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
void    netx_tcp_client_bind_cleanup_test_application_define(void *first_unused_memory)
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
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
                                           
    /* Create the main thread.  */
    tx_thread_create(&ntest_2, "thread 2", ntest_2_entry, 0,  
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

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}
           

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Client Bind Cleanup Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket 0.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket_0, "Client Socket 0", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;       

    /* Create a socket 1.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket_1, "Client Socket 1", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;      

    /* Create a socket 2.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket_2, "Client Socket 2", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;    

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_0.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;
                                 
    /* Check the TCP socket bind suspended count.  */
    if (client_socket_1.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_2.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;  
                          
    /* Bind the client_socket_0 port to 12.  */
    status =  nx_tcp_client_socket_bind(&client_socket_0, 12, NX_NO_WAIT);

    /* Check for error.  */
    if (status)
        error_counter++;       

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_0.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_1.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;           

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_2.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;     

    /* Bind the client_socket_1 port to same port.  */
    status =  nx_tcp_client_socket_bind(&client_socket_1, 12, 2 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status != NX_PORT_UNAVAILABLE)
        error_counter++;
                        
    /* Check the TCP socket bind suspended count.  */
    if (client_socket_0.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_1.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_2.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;      
                               
    /* Unbind the socket 0.  */
    status =  nx_tcp_client_socket_unbind(&client_socket_0);

    /* Check for error.  */
    if (status)
        error_counter++;
                                  
    /* Unbind the socket 1.  */
    status =  nx_tcp_client_socket_unbind(&client_socket_1);

    /* Check for error.  */
    if (status != NX_NOT_BOUND)
        error_counter++;     

    /* Unbind the socket 2.  */
    status =  nx_tcp_client_socket_unbind(&client_socket_2);

    /* Check for error.  */
    if (status != NX_NOT_BOUND)
        error_counter++;

    /* Delete the socket 0.  */
    status =  nx_tcp_socket_delete(&client_socket_0);
               
    /* Check for error.  */
    if (status)
        error_counter++;   

    /* Delete the socket 1.  */
    status =  nx_tcp_socket_delete(&client_socket_1);
               
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket 2.  */
    status =  nx_tcp_socket_delete(&client_socket_2);
               
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Check the error counter.  */
    if (error_counter)
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
                              
                          
    /* Check the TCP socket bind suspended count.  */
    if (client_socket_0.nx_tcp_socket_bind_suspended_count != 1)       
        error_counter++;
                                 
    /* Check the TCP socket bind suspended count.  */
    if (client_socket_1.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;    

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_2.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;

    /* Bind the client_socket_3 port to same port.  */
    status =  nx_tcp_client_socket_bind(&client_socket_2, 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status != NX_PORT_UNAVAILABLE)
        error_counter++; 
      
    /* Check the TCP socket bind suspended count.  */
    if (client_socket_0.nx_tcp_socket_bind_suspended_count != 1)       
        error_counter++;
                                 
    /* Check the TCP socket bind suspended count.  */
    if (client_socket_1.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;   

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_2.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;
}     

/* Define the test threads.  */

static void    ntest_2_entry(ULONG thread_input)
{                                                                                                       
                          
    /* Check the TCP socket bind suspended count.  */
    if (client_socket_0.nx_tcp_socket_bind_suspended_count != 2)       
        error_counter++;
                                 
    /* Check the TCP socket bind suspended count.  */
    if (client_socket_1.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;    

    /* Check the TCP socket bind suspended count.  */
    if (client_socket_2.nx_tcp_socket_bind_suspended_count != 0)       
        error_counter++;   
}
      
