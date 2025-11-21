/* This NetX test concentrates on the TCP Socket Unbind operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static TX_THREAD               thread_2;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           client_socket_0;  
static NX_TCP_SOCKET           client_socket_1;    
static NX_TCP_SOCKET           client_socket_2;
static NX_TCP_SOCKET           client_socket_3;

/* Define the counters used in the demo application...  */   

static ULONG                   error_counter =     0;

/* The 2 ports will hashed to the same index. */
#define CLIENT_PORT_1           0x00000100
#define CLIENT_PORT_2           0x00008100


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_2_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_tcp_socket_unbind_test_application_define(void *first_unused_memory)
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

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;  

    tx_thread_create(&thread_2, "thread 2", thread_2_entry, 0,  
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

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}
           


static void thread_0_entry(ULONG thread_input)
{

UINT        status;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Socket Unbind Cleanup Test 1..........................");

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

    /* Bind the socket 0.  */
    status = nx_tcp_client_socket_bind(&client_socket_0, CLIENT_PORT_1, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;  
                          
    /* Bind the socket 1.  */
    status = nx_tcp_client_socket_bind(&client_socket_1, CLIENT_PORT_2, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;     

    /* Let socket 2 bind to CLIENT_PORT_1. */
    tx_thread_relinquish();

    /* Unbind the socket 0.  */
    status =  nx_tcp_client_socket_unbind(&client_socket_0);

    /* Check for error.  */
    if (status)
        error_counter++;
                        
    /* Unbind the socket 1.  */
    status =  nx_tcp_client_socket_unbind(&client_socket_1);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket 0.  */
    status =  nx_tcp_socket_delete(&client_socket_0);

    /* Check for error.  */
    if (status)
        error_counter++;   

    /* Delete the socket 0.  */
    status =  nx_tcp_socket_delete(&client_socket_1);

    /* Check for error.  */
    if (status)
        error_counter++;   


    /* Let thread 1 finish jobs */
    tx_thread_relinquish();
                   
    /* Check status.  */
    if ((error_counter))
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


static void thread_1_entry(ULONG thread_input)
{
UINT status;

    /* Create a socket 2.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket_2, "Client Socket 2", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;    


    /* Bind the socket 2 to the port socket 0 has bound to */
    status = nx_tcp_client_socket_bind(&client_socket_2, CLIENT_PORT_1, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;  

    /* Unbind the socket 2.  */
    status = nx_tcp_client_socket_unbind(&client_socket_2);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket 1.  */
    status = nx_tcp_socket_delete(&client_socket_2);

    /* Check for error.  */
    if (status)
        error_counter++;


}

static void thread_2_entry(ULONG thread_input)
{
UINT status;

    /* Create a socket 3.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket_3, "Client Socket 3", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;    

    /* Bind the socket 3 to the port socket 0 has bound to */
    status = nx_tcp_client_socket_bind(&client_socket_3, CLIENT_PORT_1, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;  

    /* Unbind the socket 3.  */
    status = nx_tcp_client_socket_unbind(&client_socket_3);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket 3.  */
    status = nx_tcp_socket_delete(&client_socket_3);

    /* Check for error.  */
    if (status)
        error_counter++;

}
