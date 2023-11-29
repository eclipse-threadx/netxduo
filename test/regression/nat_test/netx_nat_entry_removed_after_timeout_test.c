
/* This NetX test concentrates on the NAT TCP operation and
   the NX_NAT_NON_TCP_SESSION_TIMEOUT and NX_NAT_TCP_SESSION_TIMEOUT
   expirations. This test verifies the entries are removed when
   the table checks for expired entries.
 
   Note that NX_NAT_ENABLE_REPLACEMENT is not necessary for this test. 
 
*/

#include   "tx_api.h"
#include   "nx_api.h"    
#include   "nx_nat.h"                         

extern void    test_control_return(UINT status);

#if defined NX_NAT_ENABLE && defined __PRODUCT_NETXDUO__ && (NX_MAX_PHYSICAL_INTERFACES >= 2) 


#define     DEMO_STACK_SIZE         2048

static UINT error_counter = 0;
                                                 
/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                    thread_client;  

/* Set up the NAT components. */

/* Create a NAT instance, packet pool and translation table. */
                                                 
NX_PACKET_POOL                      nat_packet_pool;   
NX_NAT_DEVICE                       nat_server;  
NX_IP                               nat_ip;      
NX_IP                               local_ip;
NX_IP                               external_ip;   
NX_TCP_SOCKET                       tcp_socket;
NX_UDP_SOCKET                       udp_socket;
                                                                  

/* Configure the NAT network parameters. */

/* Set NetX IP packet pool packet size. This should be less than the Maximum Transmit Unit (MTU) of
   the driver (allow enough room for the Ethernet header plus padding bytes for frame alignment).  */
#define NX_NAT_PACKET_SIZE                          1536

/* Set the size of the NAT IP packet pool.  */
#define NX_NAT_PACKET_POOL_SIZE                     (NX_NAT_PACKET_SIZE * 10)

/* Set NetX IP helper thread stack size. */   
#define NX_NAT_IP_THREAD_STACK_SIZE                 2048

/* Set the server IP thread priority */
#define NX_NAT_IP_THREAD_PRIORITY                   2

/* Set ARP cache size of a NAT ip instance. */
#define NX_NAT_ARP_CACHE_SIZE                       1024 

/* Set NAT entries memory size. Should be 5 entries. */
#define NX_NAT_ENTRY_CACHE_SIZE                     148 

/* Define NAT IP addresses, local host private IP addresses and external host IP address. */
#define NX_NAT_LOCAL_IPADR              (IP_ADDRESS(192, 168, 2, 1))  
#define NX_NAT_LOCAL_HOST1              (IP_ADDRESS(192, 168, 2, 3))
#define NX_NAT_LOCAL_HOST2              (IP_ADDRESS(192, 168, 2, 10)) 
#define NX_NAT_LOCAL_GATEWAY            (IP_ADDRESS(192, 168, 2, 1))    
#define NX_NAT_LOCAL_NETMASK            (IP_ADDRESS(255, 255, 255, 0))
#define NX_NAT_EXTERNAL_IPADR           (IP_ADDRESS(192, 168, 0, 10))   
#define NX_NAT_EXTERNAL_HOST            (IP_ADDRESS(192, 168, 0, 100))   
#define NX_NAT_EXTERNAL_GATEWAY         (IP_ADDRESS(192, 168, 0, 1))    
#define NX_NAT_EXTERNAL_NETMASK         (IP_ADDRESS(255, 255, 255, 0)) 

#define CONNECT_PEER_PORT               0x89
#define CONNECT_LOCAL_PORT              0x69

/* Set up counters */
static UINT    found_entries = 0;
static UINT    removed_entries = 0;
static UINT    time_lapse = 0;

/* This is based on the NAT Non TCP Session default timeout of 120 ticks 
   and TCP Session timeout of 300 ticks for regression testing. */
#define TIME_SLICE 25

/* Set up generic network driver for demo program. */             
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);    

/* Define thread prototypes.  */
static void    thread_client_entry(ULONG thread_input); 
                                                                        

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nat_entry_removed_after_timeout_test_application_define(void *first_unused_memory)
#endif
{

UINT     status;
UCHAR    *pointer; 
UINT     error_counter = 0;
    
    /* Initialize the NetX system. */
    nx_system_initialize();
    
    /* Setup the pointer to unallocated memory.  */
    pointer =  (UCHAR *) first_unused_memory;
                          
    /* Create the first client thread.  */
    tx_thread_create(&thread_client, "client thread", thread_client_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE; 
    
    /* Create NAT packet pool. */   
    status =  nx_packet_pool_create(&nat_packet_pool, "NAT Packet Pool", 
                                    NX_NAT_PACKET_SIZE, pointer, 
                                    NX_NAT_PACKET_POOL_SIZE);

    /* Update pointer to unallocated (free) memory. */
    pointer = pointer + NX_NAT_PACKET_POOL_SIZE;    

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }                            
    /* Create IP instances for NAT server (global network) */
    status = nx_ip_create(&nat_ip, "NAT IP Instance", NX_NAT_EXTERNAL_IPADR, NX_NAT_EXTERNAL_NETMASK, 
                          &nat_packet_pool, _nx_ram_network_driver_1500, pointer, 
                          NX_NAT_IP_THREAD_STACK_SIZE, NX_NAT_IP_THREAD_PRIORITY);

    /* Update pointer to unallocated (free) memory. */
    pointer =  pointer + NX_NAT_IP_THREAD_STACK_SIZE;

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }
                 
    /* Set the private interface(private network).  */
    status += nx_ip_interface_attach(&nat_ip, "Private Interface", NX_NAT_LOCAL_IPADR, NX_NAT_LOCAL_NETMASK, _nx_ram_network_driver_1500);
             
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }      
    
    /* Create IP instances for Local network IP instance */
    status = nx_ip_create(&local_ip, "Local IP Instance", NX_NAT_LOCAL_HOST1, NX_NAT_LOCAL_NETMASK, 
                          &nat_packet_pool, _nx_ram_network_driver_1500, pointer, 
                          NX_NAT_IP_THREAD_STACK_SIZE, NX_NAT_IP_THREAD_PRIORITY);

    /* Update pointer to unallocated (free) memory. */
    pointer =  pointer + NX_NAT_IP_THREAD_STACK_SIZE;

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }
                  
    /* Set the global network gateway for NAT IP instance.  */
    status = nx_ip_gateway_address_set(&nat_ip, NX_NAT_EXTERNAL_GATEWAY);
                       
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }                    
    
    /* Set the global network gateway for Local IP instance.  */
    status = nx_ip_gateway_address_set(&local_ip, NX_NAT_LOCAL_GATEWAY);
                       
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }                               

    
    /* Enable ARP and supply ARP cache memory for NAT IP isntance. */
    status =  nx_arp_enable(&nat_ip, (void **) pointer, NX_NAT_ARP_CACHE_SIZE);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }          
    
    /* Update pointer to unallocated (free) memory. */
    pointer = pointer + NX_NAT_ARP_CACHE_SIZE;
                                              
    /* Enable ARP and supply ARP cache memory for Local IP isntance. */
    status =  nx_arp_enable(&local_ip, (void **) pointer, NX_NAT_ARP_CACHE_SIZE);
                         
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }        
    
    /* Update pointer to unallocated (free) memory. */
    pointer = pointer + NX_NAT_ARP_CACHE_SIZE;
                                     
    /* Enable TCP traffic.  */
    status = nx_tcp_enable(&local_ip);
    status += nx_icmp_enable(&local_ip);
                                           
    /* Check status.  */
    if (status)
    {
        error_counter++;
    } 

    /* Create a NetX NAT server and cache with a global interface index.  */
    status =  nx_nat_create(&nat_server, &nat_ip, 0, pointer, NX_NAT_ENTRY_CACHE_SIZE);
                                        
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }      

    /* Update pointer to unallocated (free) memory. */
    pointer = pointer + NX_NAT_ENTRY_CACHE_SIZE;                
}                    

/* Define the test threads.  */

static void    thread_client_entry(ULONG thread_input)
{

UINT        status;
UINT        i;
UINT        peer_port;
UINT        local_port;
UINT        found;
NX_PACKET   *my_packet;
UINT        time_to_search;
NX_NAT_TRANSLATION_ENTRY search_entry;
NX_NAT_TRANSLATION_ENTRY *entry_ptr;


    /* Print out test information banner.  */
    printf("NetX Test:   NAT Remove Expired_Entries Test.............................\n");                                                       
             
    /* Check error status on set up. */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Enable the NAT service.  */
    nx_nat_enable(&nat_server);   
   
    /* Create a TCP local socket.  */
    status = nx_tcp_socket_create(&local_ip, &tcp_socket, "TCP Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200, NX_NULL, NX_NULL);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }      

     /* Create a UDP local socket.  */
    status = nx_udp_socket_create(&local_ip, &udp_socket, "UDP Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    peer_port = CONNECT_PEER_PORT;
    local_port = CONNECT_LOCAL_PORT;

    /* Iterate enough time for all three entries to expire. */
    for (i = 0; i < 8; i++)
    {
        
        /* Check if we have found 3 expired entries in the NAT table. */
        if (found_entries == 3) 
        {
            break;
        }

        /* Fill up NAT table for 4 different entries. */                                            

        if ((i == 1) || (i == 0)) 
        {

            /* Bind the UDP socket to a new local port.  */
            status =  nx_udp_socket_bind(&udp_socket, local_port, TX_WAIT_FOREVER);

            /* Check status.  */
            if (status)
            {

                error_counter++;
                break;
            }        

            /* Allocate a packet.  */
            status =  nx_packet_allocate(&nat_packet_pool, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

            /* Check status.  */
            if (status)
            {

                error_counter++;
                break;
            }   

            /* Write ABCs into the packet payload!  */
            memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

            /* Adjust the write pointer.  */
            my_packet -> nx_packet_length =  28;
            my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

            /* Send the UDP packet to a different peer port.  */
            status =  nx_udp_socket_send(&udp_socket, my_packet, NX_NAT_EXTERNAL_HOST, peer_port);

            /* Check status.  */
            if (status)
            {

                error_counter++;
                break;
            }   
                                              
            status =  nx_udp_socket_unbind(&udp_socket);

            /* Check status.  */
            if (status)
            {

                error_counter++;
                break;
            } 
            
            tx_thread_sleep(2*TIME_SLICE);

        }
        else if (i == 2) 
        {

            /* Bind the socket to the next highest local port from the last entry in the table.  */
            status =  nx_tcp_client_socket_bind(&tcp_socket, local_port, NX_WAIT_FOREVER);
        
            /* Check status.  */
            if (status)
            {
                error_counter++;
                break;
            }   
        
            /* Attempt to connect the socket to the external host on a destination port higher than the last entry in the table.  */
            status =  nx_tcp_client_socket_connect(&tcp_socket, NX_NAT_EXTERNAL_HOST, peer_port, TIME_SLICE);

            /* Unbind the socket.  */
            status =  nx_tcp_client_socket_unbind(&tcp_socket);

            /* Check for error.  */
            if (status)
            {          
                /* If an error, abort test. */
                error_counter++;
                break;
            }

            tx_thread_sleep(TIME_SLICE);  

        }
        else
        {

            /* Just wait for another entry to expire. */
            tx_thread_sleep(2*TIME_SLICE);  

        }

        /* Check if we have an entry timeout */
        time_lapse = tx_time_get();       
        time_to_search = NX_TRUE;
        
        /* Check if the TCP entry has expired. */
        if (time_lapse >= ((2*TIME_SLICE)*2 + NX_NAT_TCP_SESSION_TIMEOUT))
        {
            /* The TCP entry should have expired. */
            search_entry.protocol = NX_PROTOCOL_TCP;
            search_entry.local_port = CONNECT_LOCAL_PORT+2;
            search_entry.peer_port = CONNECT_PEER_PORT+2;
        }
        /* Check if the second UDP entry has expired. Ignore if it has already
           expired and been removed.*/
        else if ((time_lapse >= (2*TIME_SLICE + NX_NAT_NON_TCP_SESSION_TIMEOUT) &&
                  found_entries == 1)) 
        {

            /* Second UDP entry should be expired. */
            search_entry.protocol = NX_PROTOCOL_UDP;
            search_entry.local_port = CONNECT_LOCAL_PORT+1;
            search_entry.peer_port = CONNECT_PEER_PORT+1;
        }

        /* Check if the first UDP entry has expired. Ignore if it 
           has already expired and been removed. */
        else if  ((time_lapse > NX_NAT_NON_TCP_SESSION_TIMEOUT) &&
                  (found_entries == 0))
        {

            /* First TCP entry should be expired. */
            search_entry.protocol = NX_PROTOCOL_UDP;
            search_entry.local_port = CONNECT_LOCAL_PORT;
            search_entry.peer_port = CONNECT_PEER_PORT;
        }
        else
        {
          
           /* No entries expired in this loop iteration.   */
           time_to_search = NX_FALSE;
        }
        
        /* Do we expect an entry expiration*/
        if (time_to_search)
        {

            /* Yes, search for this entry in the table. */

            /* Fill in the rest of the record with addresses. */
            search_entry.local_ip_address = NX_NAT_LOCAL_HOST1;
            search_entry.peer_ip_address = NX_NAT_EXTERNAL_HOST;

            /* Get the start of the NAT list of dynamic entries. */
            entry_ptr = nat_server.nx_nat_dynamic_active_entry_head;

            found = NX_FALSE;
            
            /* Search the whole table until a match is found. */
            while (entry_ptr) 
            {                        

                /* Do sender and entry protocols match? */
                if ((search_entry.protocol == entry_ptr -> protocol) &&
                    (search_entry.peer_ip_address == entry_ptr -> peer_ip_address) &&
                    (search_entry.peer_port == entry_ptr -> peer_port) &&
                    (search_entry.local_ip_address == entry_ptr -> local_ip_address) &&
                    (search_entry.local_port == entry_ptr -> local_port))
                {
                                                   
                    /* We have a matching entry.  */
                    found_entries++; 
                    found = NX_TRUE;
                    break;
                }
                                 
                 entry_ptr = entry_ptr -> next_entry_ptr;
            }

            /* If not found, the test failed. */
            if (!found) 
            {
                error_counter++;
                break;
            }
            
            /* Send a ping so we force NAT to check the table for expired entries. */
            nx_icmp_ping(&local_ip, NX_NAT_EXTERNAL_HOST + i, "ABC", 3, &my_packet, 1);
            
            /* Get the start of the NAT list of dynamic entries. */
            entry_ptr = nat_server.nx_nat_dynamic_active_entry_head;

            found = NX_FALSE;
            
            /* Search the table again to verify the entry is removed. */
            while (entry_ptr) 
            {                        

                /* Do search and entry protocols match? */
                if ((search_entry.protocol == entry_ptr -> protocol) &&
                    (search_entry.peer_ip_address == entry_ptr -> peer_ip_address) &&
                    (search_entry.peer_port == entry_ptr -> peer_port) &&
                    (search_entry.local_ip_address == entry_ptr -> local_ip_address) &&
                    (search_entry.local_port == entry_ptr -> local_port))
                {
                                                   
                    /* We have a matching entry.  */
                    found = NX_TRUE;
                    break;
                }
                                 
                 entry_ptr = entry_ptr -> next_entry_ptr;
            }

            /* If found, the test failed, the entry was not removed. */
            if (found) 
            {
                error_counter++;
                break;
            }
            else
            {
                removed_entries++;
            }
        }   

        if (i < 3) 
        {
        
            /* Increment the connection port only if we are still adding entries. */
            local_port ++;
            peer_port ++;
        }
    } 
    
    /* All three of the original UDP and TCP entries should have been found removed. */
    while (found_entries < 3) 
    {
       error_counter++;
    }  

    /* Final check on error status. */
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

#else                  

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nat_entry_removed_after_timeout_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   NAT Remove Expired_Entries Test...........................N/A\n");                                                       
    test_control_return(3);
}
#endif
