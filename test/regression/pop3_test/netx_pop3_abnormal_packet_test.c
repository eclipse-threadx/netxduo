/* 
   This tests POP3 client process abnormal packet.  
 */

#include  "tx_api.h"
#include  "nx_api.h"
#include  "nx_ram_network_driver_test_1500.h"
#include  "nxd_pop3_client.h"
extern   void  test_control_return(UINT);
#if !defined(NX_DISABLE_IPV4)

#define DEMO_STACK_SIZE             2048

static   UINT  error_counter = 0;

extern   void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

/* Set up Client thread entry point. */
static void    client_thread_entry(ULONG info);


/* Set up the POP3 Client and POP3 server socket.  */

static TX_THREAD           client_thread;
static NX_POP3_CLIENT      pop3_client;
static NX_PACKET_POOL      client_packet_pool;
static NX_IP               client_ip;

/* Use the maximum size payload to insure no packets are dropped. */
#define PAYLOAD_SIZE 1514

static char abnormal_packet[] = {0x0A};

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_pop3_abnormal_packet_test_application_define(void *first_unused_memory)
#endif
{

UINT     status;
UCHAR   *free_memory_pointer;

    
    /* Setup the working pointer.  */
    free_memory_pointer =  (UCHAR *) first_unused_memory;

    /* Initialize NetX.  */
    nx_system_initialize();

    /* Create a client thread.  */
    tx_thread_create(&client_thread, "Client", client_thread_entry, 0,  
                     free_memory_pointer, DEMO_STACK_SIZE, 1, 1, 
                     TX_NO_TIME_SLICE, TX_AUTO_START);

    free_memory_pointer =  free_memory_pointer + DEMO_STACK_SIZE;

    /* The demo client username and password is the authentication 
       data used when the server attempts to authentication the client. */

    /* Create Client packet pool. */
    status =  nx_packet_pool_create(&client_packet_pool, "POP3 Client Packet Pool", 
                                    PAYLOAD_SIZE, free_memory_pointer, (PAYLOAD_SIZE * 10));
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer = free_memory_pointer + (PAYLOAD_SIZE * 10);    

    /* Create IP instance for demo Client */
    status = nx_ip_create(&client_ip, "POP3 Client IP Instance", IP_ADDRESS(1,2,3,5), 0xFFFFFF00UL, 
                          &client_packet_pool, _nx_ram_network_driver_1024, free_memory_pointer, 
                          2048, 1);

    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer =  free_memory_pointer + 2048;

    /* Enable ARP and supply ARP cache memory. */
    nx_arp_enable(&client_ip, (void *) free_memory_pointer, 1024);

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer = free_memory_pointer + 1024;
    
    /* Enable TCP and ICMP for Client IP. */
    nx_tcp_enable(&client_ip);
    nx_icmp_enable(&client_ip);

    return;
}

/* Define the application thread entry function. */

void    client_thread_entry(ULONG info)
{

UINT status;
UCHAR *buffer_ptr;
UINT buffer_length;
CHAR test_buffer[11] = {0};
CHAR *argument;

    NX_PARAMETER_NOT_USED(info);

    /* Print out test information banner.  */
    printf("NetX Test:   POP3 Abnormal Packet Test................................."); 

    buffer_ptr = abnormal_packet;
    buffer_length = sizeof(abnormal_packet);
    test_buffer[0] = 0x0D;
    argument = test_buffer + 1;
    _nx_pop3_parse_response(buffer_ptr, 1, buffer_length, argument, 10, NX_FALSE, NX_FALSE);

    if (test_buffer[0] != 0x0D)
    {
        error_counter++;
    }

    if(error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    };

}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_pop3_abnormal_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   POP3 Abnormal Packet Test.................................N/A\n"); 

    test_control_return(3);  
}      
#endif
