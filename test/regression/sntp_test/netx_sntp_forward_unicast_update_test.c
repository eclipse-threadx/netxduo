/* 
   netx_sntp_forward_unicast_update_test.c
 
   This demonstrates the time update notify feature in NetX SNTP Client.  The Client
   connects to the SNTP server in unicast mode (simulated server) and sends a unicast
   request.  If a valid reply is received, the time update notify callback should be called 
   for a successful completion.  

 */


#include <stdio.h>
#include "nx_api.h"
#include "nxd_sntp_client.h"
        
extern void    test_control_return(UINT result);

#if !defined(NX_DISABLE_IPV4)

/* Define SNTP packet size. */
#define NX_SNTP_CLIENT_PACKET_SIZE                 (NX_UDP_PACKET + 100)

/* Define SNTP packet pool size. */
#define NX_SNTP_CLIENT_PACKET_POOL_SIZE            (4 * (NX_SNTP_CLIENT_PACKET_SIZE + sizeof(NX_PACKET)))

/* Set up generic network driver for demo program. */
void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Application defined services of the NetX SNTP Client. */

UINT leap_second_handler(NX_SNTP_CLIENT *client_ptr, UINT leap_indicator);
VOID client_time_update_notify(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time);
static void inject_sntp_server_reply(char *pkt_data, UINT size);

static UINT time_updates_received = 0;
static UINT error_counter = 0;


/* Set up client thread and network resources. */

static NX_PACKET_POOL      client_packet_pool;
static NX_IP               client_ip;
static TX_THREAD           demo_client_thread;
static NX_SNTP_CLIENT      demo_client;

/* NTP server reply. */
static char broadcast_data_1[90] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x57, 0x00, 0x0c, 
    0x29, 0x1e, 0xaa, 0x4f, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x4c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 
    0xbc, 0xa3, 0xc0, 0xa8, 0x7e, 0x82, 0xc0, 0xa8, 
    0x7e, 0x2a, 0x00, 0x7b, 0x00, 0x7b, 0x00, 0x38,
    0x7f, 0xa0, 0x1c, 0x02, 0x00, 0xec, 0x00, 0x00, 
    0x07, 0xdd, 0x00, 0x00, 0x06, 0x6e, 
    0x89, 0xbd, 0x04, 0x0a, 
    0xd6, 0x4b, 0xd7, 0xeb, 
    0xb3, 0x25, 0xe0, 0x52, 
    0xd2, 0xc9, 0x6b, 0x90, 
    0xa1, 0x32, 0xdb, 0x1e, 
    0xd6, 0x4b, 0xd8, 0x5b, 
    0x20, 0x27, 0x62, 0xa4, 
    0xd6, 0x4b, 0xd8, 0x5b, 
    0x20, 0x2c, 0x4b, 0x46 
    };


static UINT pkt1_size = 90;



#define CLIENT_IP_ADDRESS       IP_ADDRESS(192,168,126,42)
#define SERVER_IP_ADDRESS       IP_ADDRESS(192,168,126,130)


/* Set up client thread entry point. */
void    demo_client_thread_entry(ULONG info);

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_sntp_forward_unicast_update_test_application_define(void *first_unused_memory)
#endif
{
        
UINT     status;
UCHAR    *free_memory_pointer;


    free_memory_pointer = (UCHAR *)first_unused_memory;

    /* Create client packet pool. */
    status =  nx_packet_pool_create(&client_packet_pool, "SNTP Client Packet Pool",
                                    NX_SNTP_CLIENT_PACKET_SIZE, free_memory_pointer, 
                                    NX_SNTP_CLIENT_PACKET_POOL_SIZE);

    /* Check for errors. */
    if (status != NX_SUCCESS)
    {

        error_counter++;
    }

    /* Initialize the NetX system. */
    nx_system_initialize();

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer =  free_memory_pointer + NX_SNTP_CLIENT_PACKET_POOL_SIZE;

    /* Create Client IP instances */
    status = nx_ip_create(&client_ip, "SNTP IP Instance", CLIENT_IP_ADDRESS, 
                          0xFFFFFF00UL, &client_packet_pool, _nx_ram_network_driver, //_nx_ram_network_driver, 
                          free_memory_pointer, 2048, 1);
    
    /* Check for error. */
    if (status != NX_SUCCESS)
    {

        error_counter++;
    }

    free_memory_pointer =  free_memory_pointer + 2048;

    /* Enable ARP and supply ARP cache memory. */
    status =  nx_arp_enable(&client_ip, (void **) free_memory_pointer, 2048);

    /* Check for error. */
    if (status != NX_SUCCESS)
    {

        error_counter++;
    }

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer = free_memory_pointer + 2048;
    
    /* Enable UDP for client. */
    status =  nx_udp_enable(&client_ip);
    status |= nx_icmp_enable(&client_ip);

    /* Check for error. */
    if (status != NX_SUCCESS)
    {

        error_counter++;
    }
    /* Create the client thread */
    status = tx_thread_create(&demo_client_thread, "SNTP Client Thread", demo_client_thread_entry, 
                              (ULONG)(&demo_client), free_memory_pointer, 2048, 
                              4, 4, TX_NO_TIME_SLICE, TX_DONT_START);

    /* Check for errors */
    if (status != TX_SUCCESS)
    {

        error_counter++;
    }

    /* Update pointer to unallocated (free) memory. */
    free_memory_pointer = free_memory_pointer + 2048;

    /* Create the SNTP Client to run in broadcast mode.. */
    status =  nx_sntp_client_create(&demo_client, &client_ip, 0, &client_packet_pool,  
                                    leap_second_handler, 
                                    NULL,/* no kiss of death handler */
                                    NULL /* no random_number_generator callback */);

    /* Check for error. */
    if (status != NX_SUCCESS)
    {

        error_counter++;
    }

    tx_thread_resume(&demo_client_thread);

    return;
}


/* Define the client thread.  */
void    demo_client_thread_entry(ULONG info)
{

UINT   status;


    printf("NetX Test:   NETX SNTP Client Time Update Notify Test..................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Give other threads (IP instance) a chance to initialize. */
    tx_thread_sleep(20); 

     status = nx_sntp_client_set_time_update_notify(&demo_client, client_time_update_notify);

     if (status)
     {
         printf("ERROR!\n");
         test_control_return(1);
     }

    /* Set up client time updates. */

    /* Initialize the Client for unicast mode to poll the SNTP server once an hour. */
    /* Use the IPv4 service to set up the Client and set the IPv4 SNTP server. */
    status = nx_sntp_client_initialize_unicast(&demo_client, SERVER_IP_ADDRESS);


    /* Check for error. */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_sntp_client_run_unicast(&demo_client);

    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive the server response. */
    inject_sntp_server_reply(broadcast_data_1, pkt1_size);

    tx_thread_sleep(100);

    /* To return resources to NetX and ThreadX stop the SNTP client and delete the client instance. */
    status = nx_sntp_client_delete(&demo_client);

    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    if (error_counter || (time_updates_received != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    printf("SUCCESS!\n");
    test_control_return(0);
}

/* This application defined handler for handling an impending leap second is not
   required by the SNTP Client. The default handler below only logs the event for
   every time stamp received with the leap indicator set.  */

UINT leap_second_handler(NX_SNTP_CLIENT *client_ptr, UINT leap_indicator)
{

    /* Handle the leap second handler... */

    return NX_SUCCESS;
}

void inject_sntp_server_reply(char *pkt_data, UINT size)
{

UINT                    status;
NX_PACKET              *my_packet;

    /* Allocate the packet and let the client IP stack receive it.  */
    status =  nx_packet_allocate(client_ip.nx_ip_default_packet_pool, &my_packet, 0,  500);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }

    /* Load the data simulating the server reply */
    my_packet -> nx_packet_length = size - 14;
    memcpy(my_packet -> nx_packet_prepend_ptr + 16, pkt_data + 14, my_packet -> nx_packet_length);
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    my_packet -> nx_packet_prepend_ptr += 16;
    my_packet -> nx_packet_append_ptr += 16;

    /* Send to the Client stack*/
    _nx_ip_packet_deferred_receive(&client_ip, my_packet);

}

VOID  client_time_update_notify(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time)
{

    time_updates_received++;
    return;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_sntp_forward_unicast_update_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NETX SNTP Client Time Update Notify Test..................N/A\n"); 

    test_control_return(3);  
}      
#endif