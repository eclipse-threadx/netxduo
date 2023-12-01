#include "nx_api.h"
#include "nx_ip.h"
#include "nxd_sntp_client.h"
                 
extern void test_control_return(UINT status);
#if !defined(NX_DISABLE_IPV4)
/* Define SNTP packet size. */
#define NX_SNTP_CLIENT_PACKET_SIZE                 (NX_UDP_PACKET + 100)

/* Define SNTP packet pool size. */
#define NX_SNTP_CLIENT_PACKET_POOL_SIZE            (4 * (NX_SNTP_CLIENT_PACKET_SIZE + sizeof(NX_PACKET)))

/* NTP server reply. */
static char pkt_data[90] = {
 
    /* Ethernet header */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x57, 0x00, 0x0c, 
    0x29, 0x1e, 0xaa, 0x4f, 0x08, 0x00, 
    
    /* IP layer */
    0x45, 0x00, 0x00, 0x4c, 
    0x00, 0x00, 0x40, 0x00, 
    0x40, 0x11, 0xbc, 0xa3, 
    0xc0, 0xa8, 0x7e, 0x82, 
    0xc0, 0xa8, 0x7e, 0x2a, 
    
    /* UDP header */
    0x00, 0x7b, 0x00, 0x7b, 0x00, 0x38, 0x28, 0x3f, 

    /* SNTP data  */
    0x1c,                   // flags was 28 which= server mode 4 and version 3
    0x2,                    // stratum 
    0x3,                    // poll interval
    0xf9,                   // clock precision 
    0x0, 0x0,0x4,0x23,      // root delay
    0x0, 0x0,0x8,0xf3,      // root dispersion
    0x82,0x95,0x11,0x8,     // ref ID
 
  /* for March 30, 2017, 16:14:23.665 */
    0xdc,0x87,0xab,0xc1, 0x16,0xe4,0xbc,0x59,  // ref timestamp
    
    0xdc,0x87,0xad,0x5f, 0xa7,0x00,0x68,0x0,   // origin timestamp
    
    0xdc,0x87,0xad,0x5f, 0xa7,0xc9,0xfd,0x90,  // receive timestamp
    
    0xdc,0x87,0xad,0x5f, 0xa7,0xcc,0x42,0x36 
};  

static UINT pkt_size = 90;


extern void _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);

/* Set up client thread and network resources. */

static NX_PACKET_POOL      client_packet_pool;
static NX_IP               client_ip;
static TX_THREAD           sntp_client_thread;
static NX_SNTP_CLIENT      sntp_client;


#define CLIENT_IP_ADDRESS       IP_ADDRESS(192,168,126,42)
#define SERVER_IP_ADDRESS       IP_ADDRESS(192,168,126,130)
#define SERVER_IP_ADDRESS_2     SERVER_IP_ADDRESS

/* Set up the SNTP network and address index; */
static UINT     iface_index;

static UINT     error_counter;

/* Set up client thread entry point. */
static void sntp_client_thread_entry(ULONG info);

static void inject_sntp_server_reply();

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_sntp_client_unicast_display_date_test_application_define(void *first_unused_memory)
#endif
{

UINT     status;
UCHAR    *free_memory_pointer;

    error_counter = 0;

    free_memory_pointer = (UCHAR *)first_unused_memory;

    /* Create client packet pool. */
    status =  nx_packet_pool_create(&client_packet_pool, "SNTP Client Packet Pool",
                                    NX_SNTP_CLIENT_PACKET_SIZE, free_memory_pointer, 
                                    NX_SNTP_CLIENT_PACKET_POOL_SIZE);
    free_memory_pointer =  free_memory_pointer + NX_SNTP_CLIENT_PACKET_POOL_SIZE;

    /* Check for errors. */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Initialize the NetX system. */
    nx_system_initialize();


    /* Create Client IP instances */
    status = nx_ip_create(&client_ip, "SNTP IP Instance", CLIENT_IP_ADDRESS, 
                          0xFFFFFF00UL, &client_packet_pool, _nx_ram_network_driver_1500, 
                          free_memory_pointer, 2048, 1);
    free_memory_pointer =  free_memory_pointer + 2048;
    
    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Enable ARP and supply ARP cache memory. */
    status =  nx_arp_enable(&client_ip, (void **) free_memory_pointer, 2048);
    free_memory_pointer = free_memory_pointer + 2048;

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    
    /* Enable UDP for client. */
    status =  nx_udp_enable(&client_ip);

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    status = nx_icmp_enable(&client_ip);

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Create the client thread */
    status = tx_thread_create(&sntp_client_thread, "SNTP Client Thread", sntp_client_thread_entry, 
                              (ULONG)(&sntp_client), free_memory_pointer, 2048, 
                              4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    free_memory_pointer = free_memory_pointer + 2048;

    /* Check for errors */
    if (status != TX_SUCCESS)
        error_counter++;

    /* set the SNTP network interface to the primary interface. */
    iface_index = 0;

    /* Create the SNTP Client to run in broadcast mode.. */
    status =  nx_sntp_client_create(&sntp_client, &client_ip, iface_index, &client_packet_pool,  
                                    NX_NULL, 
                                    NX_NULL, 
                                    NX_NULL /* no random_number_generator callback */);

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    tx_thread_resume(&sntp_client_thread);

    return;
}

/* Define size of buffer to display client's local time. */
#define BUFSIZE 50

/* If 1000 ticks per second, the precision should be 1ms. */
#if (NX_IP_PERIODIC_RATE == 1000)
#define EXPECTED_DATE0  "Mar 30, 2017 16:14:23.655 UTC "
#define EXPECTED_DATE1  "Mar 30, 2017 16:14:23.656 UTC "
#define EXPECTED_DATE2  "Mar 30, 2017 16:14:23.657 UTC "
#define EXPECTED_DATE3  "Mar 30, 2017 16:14:23.658 UTC "
#define EXPECTED_DATE4  "Mar 30, 2017 16:14:23.659 UTC "
#define EXPECTED_DATE5  "Mar 30, 2017 16:14:23.660 UTC "
#define EXPECTED_DATE6  "Mar 30, 2017 16:14:23.661 UTC "
#else
#define EXPECTED_DATE0  "Mar 30, 2017 16:14:23.655 UTC "
#define EXPECTED_DATE1  "Mar 30, 2017 16:14:23.665 UTC "
#define EXPECTED_DATE2  "Mar 30, 2017 16:14:23.675 UTC "
#define EXPECTED_DATE3  "Mar 30, 2017 16:14:23.685 UTC "
#define EXPECTED_DATE4  "Mar 30, 2017 16:14:23.695 UTC "
#define EXPECTED_DATE5  "Mar 30, 2017 16:14:23.705 UTC "
#define EXPECTED_DATE6  "Mar 30, 2017 16:14:23.715 UTC "
#endif

/* Define the client thread.  */
void    sntp_client_thread_entry(ULONG info)
{

UINT   status;
UINT   server_status;
CHAR   buffer[BUFSIZE];
ULONG  base_seconds;
ULONG  base_fraction; 
ULONG  seconds, milliseconds;
UINT   loops;
UINT   display_done = NX_FALSE;


    printf("NetX Test:   NETX SNTP Client Unicast Display Date Test................");

    /* Give other threads (IP instance) a chance to initialize. */
    tx_thread_sleep(1 * NX_IP_PERIODIC_RATE); 

    /* Use the IPv4 service to initialize the Client and set the IPv4 SNTP server. */
    status = nx_sntp_client_initialize_unicast(&sntp_client, SERVER_IP_ADDRESS);

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Set the base time which is quite old but should suffice. */
    base_seconds =  0xd2c96b90;  /* Jan 24, 2012 UTC */
    base_fraction = 0xa132db1e;


    /* Apply to the SNTP Client local time.  */
    status = nx_sntp_client_set_local_time(&sntp_client, base_seconds, base_fraction);

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    status = nx_sntp_client_run_unicast(&sntp_client);

    if (status != NX_SUCCESS)
        error_counter++;

    inject_sntp_server_reply();
    loops = 0;
    do 
    {

        /* First verify we have a valid SNTP service running. */
        status = nx_sntp_client_receiving_updates(&sntp_client, &server_status);
    
        if ((status == NX_SUCCESS) && (server_status == NX_TRUE))
        {

            /* Server status is good. Now get the Client local time. */

            /* Display the local time in years, months, date format.  */
            status = nx_sntp_client_get_local_time(&sntp_client, &seconds, &milliseconds, &buffer[0]);

            if (status == NX_SUCCESS)
            {
                  
                status = nx_sntp_client_utility_display_date_time(&sntp_client, &buffer[0], BUFSIZE);
                
                if (status != NX_SUCCESS)
                {
                    error_counter++;
                }
                else
                {
                   if (!memcmp(&buffer[0], EXPECTED_DATE0, strlen(EXPECTED_DATE0)) ||
                       !memcmp(&buffer[0], EXPECTED_DATE1, strlen(EXPECTED_DATE0)) ||
                       !memcmp(&buffer[0], EXPECTED_DATE2, strlen(EXPECTED_DATE0)) ||
                       !memcmp(&buffer[0], EXPECTED_DATE3, strlen(EXPECTED_DATE0)) ||
                       !memcmp(&buffer[0], EXPECTED_DATE4, strlen(EXPECTED_DATE0)) ||
                       !memcmp(&buffer[0], EXPECTED_DATE5, strlen(EXPECTED_DATE0)) ||
                       !memcmp(&buffer[0], EXPECTED_DATE6, strlen(EXPECTED_DATE0))) 
                    {

                        display_done = NX_TRUE;
                        break;
                    }
                    else
                    {
printf("date: %s.\n", buffer);
                        error_counter++;
                    }                   
                }    
            }    

        }
        else
        {
        
            /* Wait a short bit to check again. */
            tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);  
        }
        
        loops++;
        
    } while((loops < 4) && (display_done == NX_FALSE));
    
    /* We can stop the SNTP service if for example we think the SNTP service has stopped. */
    status = nx_sntp_client_stop(&sntp_client);

    if (status != NX_SUCCESS)
        error_counter++;

    status = nx_sntp_client_delete(&sntp_client);

    if (status != NX_SUCCESS)
        error_counter++;

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

    return;
}


void inject_sntp_server_reply()
{

UINT                    status;
NX_PACKET              *my_packet;

    /* Now, this packet is a received one, allocate the packet and let the IP stack receives it.  */
    /* Allocate a packet.  */
    status =  nx_packet_allocate(client_ip.nx_ip_default_packet_pool, &my_packet, 0,  5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }
    
    my_packet -> nx_packet_length = pkt_size - 14;
    memcpy(my_packet -> nx_packet_prepend_ptr + 16, pkt_data + 14, my_packet -> nx_packet_length);
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    my_packet -> nx_packet_prepend_ptr += 16;
    my_packet -> nx_packet_append_ptr += 16;
    
    _nx_ip_packet_deferred_receive(&client_ip, my_packet);

}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_sntp_client_unicast_display_date_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NETX SNTP Client Unicast Display Date Test................N/A\n");

    test_control_return(3);  
}      
#endif
