/* This NetX test concentrates on the UDP free port find operation.  */


#include   "tx_api.h"
#include   "nx_api.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           my_socket[NX_MAX_PORT - NX_SEARCH_PORT_START + 1];
#ifdef __PRODUCT_NETXDUO__
static NX_UDP_SOCKET           my_socket_1;
#endif /* __PRODUCT_NETXDUO__ */

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* The 2 ports will hashed to the same index. */
#define CLIENT_PORT_1           0x00000100
#define CLIENT_PORT_2           0x00008100

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

extern void  test_control_return(UINT status);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_udp_free_port_find_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
UINT        free_port;
UINT        i;


    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Free Port Find Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status != NX_SUCCESS)
        error_counter++;

    status = nx_udp_socket_bind(&socket_0, CLIENT_PORT_1, 2 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;

    /* CLIENT_PORT_1 has been bound. */
    status =  nx_udp_free_port_find(&ip_0, CLIENT_PORT_1, &free_port);
    if((status != NX_SUCCESS) && (free_port != CLIENT_PORT_1 + 1))
        error_counter++;

    /* CLIENT_PORT_2 and CLIENT_PORT_1 are mapped to the same index. */
    status =  nx_udp_free_port_find(&ip_0, CLIENT_PORT_2, &free_port);
    if ((status != NX_SUCCESS) || (free_port != CLIENT_PORT_2))
        error_counter++;

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_0);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Test port wrap around. */
    status = nx_udp_socket_bind(&socket_0, NX_MAX_PORT, 2 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;

    status =  nx_udp_free_port_find(&ip_0, NX_MAX_PORT, &free_port);
    if ((status != NX_SUCCESS) || (free_port != NX_SEARCH_PORT_START))
        error_counter++;

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_0);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_0);
    if (status)
        error_counter++;

    for(i = 0; i <= (NX_MAX_PORT - NX_SEARCH_PORT_START); i++)
    {
        status = nx_udp_socket_create(&ip_0, &my_socket[i], "Socket Array",
                                      NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_udp_socket_bind(&my_socket[i], i + NX_SEARCH_PORT_START, NX_IP_PERIODIC_RATE);
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    status = nx_udp_free_port_find(&ip_0, NX_SEARCH_PORT_START, &free_port);
    if(status != NX_NO_FREE_PORTS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef __PRODUCT_NETXDUO__
    /* Verify the port number ahead of NX_SEARCH_PORT_START.  */
    status = nx_udp_socket_create(&ip_0, &my_socket_1, "Socket 1",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_bind(&my_socket_1, (NX_SEARCH_PORT_START - 1), NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_free_port_find(&ip_0, (NX_SEARCH_PORT_START - 1), &free_port);
    if(status != NX_NO_FREE_PORTS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* __PRODUCT_NETXDUO__ */

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
    

