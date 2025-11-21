
/* This NetX test concentrates on the NAT TCP operation and
   NX_NAT_ENABLE_REPLACMENT feature. This test creates five
   test cases where the NAT table is manually filled in with a variety of
   non TCP and TCP entries.  The non TCP response timeouts use the standard NAT timeout
   defined by NX_NAT_NON_TCP_SESSION_TIMEOUT. The TCP timeouts use the extended timeout
   NX_NAT_TCP_SESSION_TIMEOUT.  None of the entries should timeout. 
 
   Once the table is filled, the TCP client attempts to make a connection on a
   new port to an external host (we don't create the TCP server).
   The outbound SYN packet will require an entry for this outbound packet.
 
   The success case is if NAT removes the oldest non TCP entry and inerts the new
   TCP entry at the head of the list.
 
   Each test case varies with respect to where the oldest entry is to verify
   that the removal of the link leaves the remaining entries properly linked
   and the NAT available list parameters updated.
 
*/

#include   "tx_api.h"
#include   "nx_api.h"    
#include   "nx_nat.h"     
                    
extern void    test_control_return(UINT status);

#if defined NX_NAT_ENABLE && defined __PRODUCT_NETXDUO__ && (NX_MAX_PHYSICAL_INTERFACES >= 2) && defined NX_NAT_ENABLE_REPLACMENT

#define     DEMO_STACK_SIZE         2048
                                                
/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD    thread_client;  
static UINT         error_counter = 0;

/* Set up the NAT components. */

/* Create a NAT instance, packet pool and translation table. */
                                                 
NX_PACKET_POOL                      nat_packet_pool;   
NX_NAT_DEVICE                       nat_server;  
NX_IP                               nat_ip;      
NX_IP                               local_ip;
NX_IP                               external_ip;   
NX_TCP_SOCKET                       local_socket;
NX_TCP_SOCKET                       external_socket;
                                                                  

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

/* Set NAT table size large enough for 5 entries. */
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

static void *dynamic_cache_ptr;
static UINT  dynamic_entries;


/* Set up generic network driver for demo program. */             
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);    

static UINT add_nat_entry(UINT protocol, ULONG local_ip_address , ULONG peer_ip_address , UINT local_port, UINT peer_port, ULONG response_timeout, UINT timestamp);

/* Define thread prototypes.  */

static void    thread_client_entry(ULONG thread_input); 
                                                                        

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nat_tcp_remove_oldest_udp_entry_test_application_define(void *first_unused_memory)
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
             
    dynamic_cache_ptr = (void **) pointer;
                            
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
UINT        temp1, temp2, oldest_local_port;
UINT        i, j;
ULONG       timeout = NX_NAT_NON_TCP_SESSION_TIMEOUT;
UINT        peer_port;
UINT        local_port;
ULONG       local_ip_address;
ULONG       peer_ip_address;
UINT        protocol;
UINT        timestamp;
UINT        found;
NX_NAT_TRANSLATION_ENTRY search_entry;
NX_NAT_TRANSLATION_ENTRY *entry_ptr;


    /* Print out test information banner.  */
    printf("NetX Test:   NAT TCP Remove Oldest UDP Entry Test........................");                                                       
             
    /* Check error status on set up. */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Enable the NAT service.  */
    nx_nat_enable(&nat_server);   
   
    /* Create a TCP local socket.  */
    status = nx_tcp_socket_create(&local_ip, &local_socket, "Local Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200, NX_NULL, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }   
       
    temp1 = tx_time_get();
    for (j = 0; j < 4; j++)
    {
      
        /* Fill up NAT table for 4 different test cases. */                                            

        /* Starting parameters for entries we will add directly: */
        timeout = NX_NAT_NON_TCP_SESSION_TIMEOUT;
        protocol= NX_PROTOCOL_TCP;
        peer_port = CONNECT_PEER_PORT;
        local_port = CONNECT_LOCAL_PORT;
        peer_ip_address = NX_NAT_EXTERNAL_IPADR;
        local_ip_address = NX_NAT_LOCAL_HOST1;
        
        /* Add 5 entries to the table for each test case. */
        for (i = 0; i < 5; i++)
        { 
              
              switch  (j)
              {
                  
                case 0:
                /* Oldest UDP entry the next entry after the dynamic list head. */
                {
                    if ((i != 2) && (i != 4)) 
                    {
                        /* Add a few long timeouts. */
                        timeout = NX_NAT_NON_TCP_SESSION_TIMEOUT; 
                        protocol = NX_PROTOCOL_UDP;
                        timestamp = 10 - i; 
                    }
                    else
                    {
                        timeout =  NX_NAT_TCP_SESSION_TIMEOUT;
                        protocol = NX_PROTOCOL_TCP;
                        timestamp = i;
                    }

                    /* Oldest_entry = 3; */
                    if  (i == 3) 
                    {
                      oldest_local_port = local_port;
                    }
                    
                    break;
              }
              case 1: 
               /* Oldest UDP entry is the tail of the dynamic list */
              {
                    if ((i != 2) && (i != 4)) 
                    {
                        /* Add a few long timeouts. */
                        timeout = NX_NAT_NON_TCP_SESSION_TIMEOUT; 
                        protocol = NX_PROTOCOL_UDP;
                        timestamp = i; 
                    }
                    else
                    {
                        timeout = NX_NAT_TCP_SESSION_TIMEOUT;
                        protocol = NX_PROTOCOL_TCP;
                        timestamp = 10 - i;
                    }
                    
                    /* Oldest_entry = 0; */
                    if (i == 0) 
                    {
                      oldest_local_port = local_port;
                    }
                    /* Now add in the elapsed time. */
                    timestamp +=  temp2 - temp1;
                    
                    break;
              }
              case 2:
                /* Oldest UDP entry is the head of the dynamic list */
              {
                    if ((i != 2) && (i != 4)) 
                    {
                        /* Add a few long timeouts. */
                        timeout = NX_NAT_TCP_SESSION_TIMEOUT;
                        protocol = NX_PROTOCOL_TCP;
                        timestamp = i;                   
                    }
                    else
                    {
                        timeout = NX_NAT_NON_TCP_SESSION_TIMEOUT; 
                        protocol = NX_PROTOCOL_UDP;
                        timestamp = 10 - i;
                    }
                    
                    /* Oldest_entry = 4; */
                    if (i == 4) 
                    {
                      oldest_local_port = local_port;
                    }
                    /* Now add in the elapsed time. */
                    timestamp +=  temp2 - temp1;
                    
                    break;
              }                
              case 3:
               /* Oldest UDP entry is in the middle of the list */
              {   
                              
                  if ((i != 2) && (i != 3)) 
                  {
                      /* Add a few long timeouts. */
                      timeout = NX_NAT_TCP_SESSION_TIMEOUT;
                      protocol = NX_PROTOCOL_TCP;
                      timestamp = i;                   
                  }
                  else
                  {
                      timeout = NX_NAT_NON_TCP_SESSION_TIMEOUT; 
                      protocol = NX_PROTOCOL_UDP;

                      /* Throw in an ICMP entry. */
                      if (i == 2)
                      {
                          protocol = NX_PROTOCOL_ICMP;
                      }
                      
                      timestamp = 10 - i;
                  }

                  /* Oldest_entry = 3; */
                  if (i == 3) 
                  {
                      oldest_local_port = local_port;
                  }
                    
                  /* Now add in the elapsed time. */
                  timestamp +=  temp2 - temp1;
                  break;
              }    
              default:
              {  
                  break;
              }
            }
            
            status = add_nat_entry(protocol, local_ip_address , peer_ip_address , local_port, peer_port, timeout, timestamp);
            if (status)
            {
                error_counter++;
            }

            local_port ++;
            peer_port ++;
        } 
        
        /* Make sure our timestamps are less than the current time! */
        tx_thread_sleep(50);
        
        /* Assign separate ports for another TCP Connection */
        local_port += 100;
        peer_port += 100;
                         
        /* Bind the socket to a local port.  */
        status =  nx_tcp_client_socket_bind(&local_socket, local_port, NX_WAIT_FOREVER);
        
        /* Check status.  */
        if (status)
        {
            error_counter++;
        }   
        
        /* Attempt to connect the socket to the external host on a destination port higher than the last entry in the table.  */
        status =  nx_tcp_client_socket_connect(&local_socket, NX_NAT_EXTERNAL_HOST, peer_port, 20);

        /* Create the translation record to find in the NAT table. This should
           correspond to the TCP connection attemp (SYN packet outbound). */
        memset(&search_entry, 0, sizeof(NX_NAT_TRANSLATION_ENTRY));
        search_entry.protocol = NX_PROTOCOL_TCP;
        search_entry.local_ip_address = NX_NAT_LOCAL_HOST1;
        search_entry.peer_ip_address = NX_NAT_EXTERNAL_HOST;
        search_entry.local_port = local_port;
        search_entry.peer_port = peer_port;

         /* Get the start of the NAT list of dynamic entries. */
        entry_ptr = nat_server.nx_nat_dynamic_active_entry_head;

        found = NX_FALSE;
        
        /* Search the whole table until a match is found. */
        while (entry_ptr) 
        {                        

            /* Check if the oldest UDP entry has been removed. */
            if ((entry_ptr -> local_port == oldest_local_port)  && (entry_ptr -> protocol == NX_PROTOCOL_UDP))
            {
                error_counter++;
            }

            /* Do sender and entry protocols match? */
            if ((search_entry.protocol == entry_ptr -> protocol) &&
                (search_entry.peer_ip_address == entry_ptr -> peer_ip_address) &&
                (search_entry.peer_port == entry_ptr -> peer_port) &&
                (search_entry.local_ip_address == entry_ptr -> local_ip_address) &&
                (search_entry.local_port == entry_ptr -> local_port))
            {
                                               
                /* We have a matching entry.  */
                found = NX_TRUE;
            }
                             
             entry_ptr = entry_ptr -> next_entry_ptr;
        }

        /* If not found, the test failed. */
        if (!found) 
        {
            error_counter++;
        }
        
        /* Unbind the socket.  */
        status =  nx_tcp_client_socket_unbind(&local_socket);

        /* Check for error.  */
        if (status)
        {
          
            /* If an error, abort test. */
            error_counter++;
            break;
        }
        
        /* Check the active and available list parameters */
        if ((nat_server.nx_nat_dynamic_available_entry_head != NX_NULL) ||
            (nat_server.nx_nat_dynamic_available_entries != 0) ||
            (nat_server.nx_nat_dynamic_active_entries != 5))
        {
            error_counter++;        
        }

        /* Clear the NAT table and table counters. */
        
        /* Clear the entry cache.  */
        memset((void *) dynamic_cache_ptr, 0, NX_NAT_ENTRY_CACHE_SIZE);

        /* Pickup starting address of the available entry list.  */
        entry_ptr = (NX_NAT_TRANSLATION_ENTRY *) dynamic_cache_ptr;

        /* Determine how many NAT daynamic entries will fit in this cache area.  */
        dynamic_entries = NX_NAT_ENTRY_CACHE_SIZE / sizeof(NX_NAT_TRANSLATION_ENTRY);         
                   
        /* Initialize the pointers of available NAT entries.  */
        for (i = 0; i < (dynamic_entries - 1); i++)
        {
            /* Setup each entry to point to the next entry.  */
            entry_ptr -> next_entry_ptr = entry_ptr + 1;
            entry_ptr ++;
        }

        /* Setup the head pointers of the available and dynamic (active) lists in the NAT Device.  */    
        nat_server.nx_nat_dynamic_available_entry_head = (NX_NAT_TRANSLATION_ENTRY *) dynamic_cache_ptr; 
        nat_server.nx_nat_dynamic_active_entry_head = NX_NULL;
        nat_server.nx_nat_dynamic_available_entries = dynamic_entries;
        nat_server.nx_nat_dynamic_active_entries = 0;
        nat_server.nx_nat_static_active_entries = 0; 
        
        temp2 = tx_time_get();
        
    } /* Try the next test case */    
    
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


static UINT external_port = 20000;

static UINT add_nat_entry(UINT protocol, ULONG local_ip_address , ULONG peer_ip_address , UINT local_port, UINT peer_port, ULONG response_timeout, UINT timestamp)
{

NX_NAT_TRANSLATION_ENTRY *insert_entry_ptr;


    external_port++;

    /* Get one available entry.  */
    insert_entry_ptr = (nat_server.nx_nat_dynamic_available_entry_head);

    /* Update the entry head.  */
    nat_server.nx_nat_dynamic_available_entry_head = insert_entry_ptr -> next_entry_ptr;

    /* Initialize the allocated memory to NULL. */
    memset(insert_entry_ptr, 0, sizeof(NX_NAT_TRANSLATION_ENTRY));

    /* Assign the entry attributes. */ 
    insert_entry_ptr -> protocol = protocol;
    insert_entry_ptr -> local_ip_address = local_ip_address;
    insert_entry_ptr -> peer_ip_address = peer_ip_address;
    insert_entry_ptr -> local_port = local_port;
    insert_entry_ptr -> external_port = external_port;
    insert_entry_ptr -> peer_port = peer_port;
    insert_entry_ptr -> response_timeout = response_timeout; 

    /* Set the entry timestamp.  */
    insert_entry_ptr -> response_timestamp = timestamp;                                                          

    /* Set entry type to dynamically created. */
    insert_entry_ptr -> translation_type = NX_NAT_DYNAMIC_ENTRY;

    /* Update the table counters. */
    nat_server.nx_nat_dynamic_active_entries ++;
    nat_server.nx_nat_dynamic_available_entries --;
    
    /* Add this entry onto the table entry list.  */
    insert_entry_ptr -> next_entry_ptr = nat_server.nx_nat_dynamic_active_entry_head;
    nat_server.nx_nat_dynamic_active_entry_head = insert_entry_ptr;                                                                  

    return NX_SUCCESS;
}

#else                  

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nat_tcp_remove_oldest_udp_entry_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   NAT TCP Remove Oldest UDP Entry Test......................N/A\n");                                                       
    test_control_return(3);
}
#endif
