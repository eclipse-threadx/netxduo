/* DHCPREQUEST generated during REBINDING state: 'server identifier' MUST NOT be filled in, 'requested IP address' option MUST NOT 
 * be filled in, 'ciaddr' MUST be filled in with client's IP address.
 * rfc 2131, page 32, 4.3.2 DHCPREQUEST message
 *
 */
#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_udp.h"
#include   "nx_ipv4.h"
#include   "nx_ip.h"
#include   "nxd_dhcp_client.h"
#include   "nxd_dhcp_server.h"
#include   "nx_ram_network_driver_test_1500.h"   
#include   "netx_dhcp_clone_function.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8

#define     NX_DHCP_SERVER_IP_ADDRESS_0 IP_ADDRESS(10,0,0,1)   
#define     START_IP_ADDRESS_LIST_0     IP_ADDRESS(10,0,0,10)
#define     END_IP_ADDRESS_LIST_0       IP_ADDRESS(10,0,0,19)

#define     NX_DHCP_SUBNET_MASK_0       IP_ADDRESS(255,255,255,0)
#define     NX_DHCP_DEFAULT_GATEWAY_0   IP_ADDRESS(10,0,0,1)
#define     NX_DHCP_DNS_SERVER_0        IP_ADDRESS(10,0,0,1)


/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;
static NX_DHCP                 dhcp_client;

static TX_THREAD               server_thread;
static NX_PACKET_POOL          server_pool;
static NX_IP                   server_ip;
static NX_DHCP_SERVER          dhcp_server;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static CHAR                    *pointer;

static UINT                    dhcp_request_flag;
static UINT                    dhcp_renew_flag;

static ULONG                   ip_src_addr, ip_dest_addr;
/* Define thread prototypes.  */

static void    server_thread_entry(ULONG thread_input);
static void    client_thread_entry(ULONG thread_input);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_04_03_02_03_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the client thread.  */
    tx_thread_create(&client_thread, "thread client", client_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the server thread.  */
    tx_thread_create(&server_thread, "thread server", server_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;
    
    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;
    
    /* Create an IP instance for the DHCP Server.  */
    status = nx_ip_create(&server_ip, "DHCP Server", NX_DHCP_SERVER_IP_ADDRESS_0, 0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for DHCP Client IP.  */
    status =  nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;
    
    /* Enable ARP and supply ARP cache memory for DHCP Server IP.  */
    status =  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&client_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
    
    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&server_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&client_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&server_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    return;
}

/* Define the test threads.  */

void    server_thread_entry(ULONG thread_input)
{

UINT        status;
UINT        iface_index;
UINT        addresses_added;

    printf("NetX Test:   DHCP 04_03_02_03 Test.....................................");

    /* Create the DHCP Server.  */
    status =  nx_dhcp_server_create(&dhcp_server, &server_ip, pointer, DEMO_STACK_SIZE, 
                                   "DHCP Server", &server_pool);
    
    pointer = pointer + DEMO_STACK_SIZE;
    
    /* Check for errors creating the DHCP Server. */
    if (status)
        error_counter++;

    /* Load the assignable DHCP IP addresses for the first interface.  */
    iface_index = 0;

    status = nx_dhcp_create_server_ip_address_list(&dhcp_server, iface_index, START_IP_ADDRESS_LIST_0, 
                                                   END_IP_ADDRESS_LIST_0, &addresses_added);

    /* Check for errors creating the list. */
    if (status)
        error_counter++;

    /* Verify all the addresses were added to the list. */
    if (addresses_added != 10)
        error_counter++;

    status = nx_dhcp_set_interface_network_parameters(&dhcp_server, iface_index, NX_DHCP_SUBNET_MASK_0, 
                                                      NX_DHCP_DEFAULT_GATEWAY_0, NX_DHCP_DNS_SERVER_0);

    /* Check for errors setting network parameters. */
    if (status)
        error_counter++;

    server_ip.nx_ip_udp_packet_receive = my_udp_packet_receive;

    /* Start DHCP Server task.  */
    status = nx_dhcp_server_start(&dhcp_server);

    /* Check for errors starting up the DHCP server.  */
    if (status)
        error_counter++;
   
    /* Sleep 20s. */
    tx_thread_sleep(20 * NX_IP_PERIODIC_RATE);

    if((error_counter) || (dhcp_request_flag == 0))
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

/* Define the test threads.  */

void    client_thread_entry(ULONG thread_input)
{

UINT        status;

    dhcp_request_flag = 0;
    dhcp_renew_flag = 0;

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    if (status)
        error_counter++;

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    advanced_packet_process_callback   = my_packet_process;

    /* Start the DHCP Client.  */
    status =  nx_dhcp_start(&dhcp_client);
    if (status)
        error_counter++;

    /* Wait for DHCP to assign the IP address.  */
    do
    {
        /* Check for address resolution.  */
        status =  nx_ip_status_check(&client_ip, NX_IP_ADDRESS_RESOLVED, (ULONG *) &status, NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status)
        {
            /* wait a bit. */
            tx_thread_sleep(NX_IP_PERIODIC_RATE);
        }

    } while (status != NX_SUCCESS);

    /* Sleep 20s */
    tx_thread_sleep(20 * NX_IP_PERIODIC_RATE);

    /* Stopping the DHCP client. */
    nx_dhcp_stop(&dhcp_client);

    /* All done. Return resources to NetX and ThreadX. */    
    nx_dhcp_delete(&dhcp_client);

    return;
}


static UINT my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UINT            status;
ULONG           message_type;
ULONG           src_dst_port;
ULONG           ciaddr;
ULONG           requested_ip_addr;
ULONG           server_identifier;
NX_UDP_HEADER   *udp_header_ptr;
#ifdef __PRODUCT_NETXDUO__
NX_IPV4_HEADER *ip_header;
#else
NX_IP_HEADER   *ip_header;
#endif

    udp_header_ptr = (NX_UDP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    src_dst_port = udp_header_ptr -> nx_udp_header_word_0; 
    NX_CHANGE_ULONG_ENDIAN(src_dst_port);

    /* client port 68(0x44), server port 67(0x43). packet sent to server from client*/
    if(src_dst_port == 0x00440043)
    {
        if(dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state == NX_DHCP_STATE_INIT)
        {
            /* Get the dhcp message type. */
            status = dhcp_get_option_value((packet_ptr -> nx_packet_prepend_ptr + 20 + 8), NX_DHCP_SERVER_OPTION_DHCP_TYPE, 
                                                &message_type, (packet_ptr -> nx_packet_length - 20 - 8));
            if(status)
                error_counter++;

            /* Check if the message is a DHCPREQUEST. */
            if(message_type == NX_DHCP_TYPE_DHCPDISCOVER)
            {
#ifdef __PRODUCT_NETXDUO__
                ip_header = (NX_IPV4_HEADER*)packet_ptr -> nx_packet_prepend_ptr;
#else
                ip_header = (NX_IP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
#endif
                /* Get the  sourceand destination ip address. */
                ip_dest_addr = ip_header -> nx_ip_header_destination_ip;
                ip_src_addr = ip_header -> nx_ip_header_source_ip;
            }

        }
        /* Rebinding state. */
        else if((dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state == NX_DHCP_STATE_RENEWING))
        {
            /* Get the dhcp message type. */
            status = dhcp_get_option_value((packet_ptr -> nx_packet_prepend_ptr + 20 + 8), NX_DHCP_SERVER_OPTION_DHCP_TYPE, 
                                                &message_type, (packet_ptr -> nx_packet_length - 20 - 8));
            if(status)
                error_counter++;

            /* Check if the message is a DHCPREQUEST. */
            if(message_type == NX_DHCP_TYPE_DHCPREQUEST)
            {
                dhcp_renew_flag = 1;                
            }

        }
        /* rebing state. */
        else if((dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state == NX_DHCP_STATE_REBINDING))
        {
            /* Get the dhcp message type. */
            status = dhcp_get_option_value((packet_ptr -> nx_packet_prepend_ptr + 20 + 8), NX_DHCP_SERVER_OPTION_DHCP_TYPE, 
                                                &message_type, (packet_ptr -> nx_packet_length - 20 - 8));
            if(status)
                error_counter++;

            /* Check if the message is a DHCPREQUEST. */
            if(message_type == NX_DHCP_TYPE_DHCPREQUEST)
            {

                dhcp_request_flag++;

                /* Get the server id. */
                status = dhcp_get_option_value((packet_ptr -> nx_packet_prepend_ptr + 20 + 8), NX_DHCP_OPTION_DHCP_SERVER, 
                                                    &server_identifier, (packet_ptr -> nx_packet_length - 20 - 8));

                /* According to RFC, at this point, the 'server identifier' option MUST NOT be filled. */
                if((status != NX_OPTION_ERROR) || 
                   ((status == NX_SUCCESS) && (server_identifier != 0)))
                    error_counter++;

                
                /* Get the requested ip address. */
                status = dhcp_get_option_value((packet_ptr -> nx_packet_prepend_ptr + 20 + 8), NX_DHCP_OPTION_DHCP_IP_REQ, 
                                                    &requested_ip_addr, (packet_ptr -> nx_packet_length - 20 - 8));

                /* According to RFC, at this point, the 'requested ip address' option MUST NOT be filled. */
                if((status != NX_OPTION_ERROR) || 
                   ((status == NX_SUCCESS) && (requested_ip_addr != 0)))
                    error_counter++;

                /* Get ciaddr field value. */
                ciaddr = dhcp_get_data((packet_ptr -> nx_packet_prepend_ptr + 20 + 8 + NX_BOOTP_OFFSET_CLIENT_IP), 4);

                /* According to RFC, at this point , the ciaddr MUST be the client's ip address. */
                if(ciaddr != client_ip.nx_ip_address)
                    error_counter++;

                /* restore the callback to NULL. */
                advanced_packet_process_callback = NX_NULL;
            }
        }
    }
    /* server to client. */
    else if(src_dst_port == 0x00430044)
    {
        /* Make sure this is a ACK respond to the REQUEST sent at renewing state. */
        if(dhcp_renew_flag == 1)
        {
            /* drop the DHCPACK to let client go to rebing state. */

            /* Get the dhcp message type. */
            status = dhcp_get_option_value((packet_ptr -> nx_packet_prepend_ptr + 20 + 8), NX_DHCP_SERVER_OPTION_DHCP_TYPE, 
                                                &message_type, (packet_ptr -> nx_packet_length - 20 - 8));
            if(status)
                error_counter++;

            /* Check if the message is a DHCPREQUEST. */
            if(message_type == NX_DHCP_TYPE_DHCPACK)
            {
                *operation_ptr = NX_RAMDRIVER_OP_DROP;
            }

        }
    }
   
    return NX_TRUE;

}

void    my_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

UINT            status;
ULONG           message_type;
NX_UDP_HEADER   *udp_header_ptr;
ULONG           *requested_lease_time;
ULONG           checksum;
#if !defined(__PRODUCT_NETXDUO__)
ULONG           temp;
ULONG           length;
UCHAR           *word_ptr;
ULONG           packet_length;
ULONG           adjusted_packet_length;
NX_PACKET       *current_packet;
UCHAR           *pad_ptr;
#endif

    udp_header_ptr = (NX_UDP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr);

    /* Get the dhcp message type. */
    status = dhcp_get_option_value((packet_ptr -> nx_packet_prepend_ptr + 8), NX_DHCP_SERVER_OPTION_DHCP_TYPE, 
                                       &message_type, (packet_ptr -> nx_packet_length - 8));
    if(status)
        error_counter++;

    /* Check if the message is a DHCPOFFER. */
    if(message_type == NX_DHCP_TYPE_DHCPDISCOVER)
    {
        /* change the requested lease time. Because NETX DHCP Client doesn't have an API to set requested lease time.*/
        /* change the lease time to 5s, so that we can get the RENEWING state early. */
        requested_lease_time = (ULONG *)(packet_ptr -> nx_packet_prepend_ptr + 253);
        *requested_lease_time = 0x05000000;
 
#ifdef __PRODUCT_NETXDUO__ 
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
               
        /* compute the checksum. */

        /* Yes, we need to compute the UDP checksum.  */
        checksum = _nx_ip_checksum_compute(packet_ptr,
                        NX_PROTOCOL_UDP,
                        packet_ptr -> nx_packet_length,
                        &ip_src_addr,
                        &ip_dest_addr);
        checksum = ~checksum & NX_LOWER_16_MASK;

        /* If the computed checksum is zero, it is transmitted as all ones. */
        /* RFC 768, page 2. */
        if(checksum == 0)
            checksum = 0xFFFF;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 | checksum;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

#else

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        /* First calculate the checksum of the pseudo UDP header that includes the source IP
           address, destination IP address, protocol word, and the UDP length.  */
        temp =  ip_src_addr;
        checksum =  (temp >> NX_SHIFT_BY_16);
        checksum += (temp & NX_LOWER_16_MASK);
        checksum += (ip_dest_addr >> NX_SHIFT_BY_16);
        checksum += (ip_dest_addr & NX_LOWER_16_MASK);
        checksum += (NX_IP_UDP >> NX_SHIFT_BY_16);
        checksum += packet_ptr -> nx_packet_length;

        /* Setup the length of the packet checksum.  */
        length =  packet_ptr -> nx_packet_length;

        /* Initialize the current packet to the input packet pointer.  */
        current_packet =  packet_ptr;

        /* Loop to calculate the packet's checksum.  */
        while (length)
        {
            /* Calculate the current packet length.  */
            packet_length =  current_packet -> nx_packet_append_ptr - current_packet -> nx_packet_prepend_ptr;
        
            /* Make the adjusted packet length evenly divisible by sizeof(ULONG).  */
            adjusted_packet_length =  ((packet_length + (sizeof(ULONG) - 1))/sizeof(ULONG))*sizeof(ULONG);
            
            /* Determine if we need to add padding bytes.  */
            if (packet_length < adjusted_packet_length)
            {

                /* Calculate how many bytes we need to zero at the end of the packet.  */
                temp =  adjusted_packet_length - packet_length;
                
                /* Setup temporary pointer to the current packet's append pointer.  */
                pad_ptr =  current_packet -> nx_packet_append_ptr;
            
                /* Loop to pad current packet with 0s so we don't have to worry about a partial last word.  */
                while(temp)
                {
            
                    /* Check for the end of the packet.  */
                    if (pad_ptr >= current_packet -> nx_packet_data_end)
                        break;
                   
                    /* Write a 0. */
                    *pad_ptr++ =  0;
                    
                    /* Decrease the pad count.  */
                    temp--;
                }       
            }


            /* Setup the pointer to the start of the packet.  */
            word_ptr =  (UCHAR *) current_packet -> nx_packet_prepend_ptr;

            /* Now loop through the current packet to compute the checksum on this packet.  */
            while (adjusted_packet_length)
            {

                /* Pickup a whole ULONG.  */
                temp =  *((ULONG *) word_ptr);

                /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
                   swap the endian of the long word in the message.  */
                NX_CHANGE_ULONG_ENDIAN(temp);

                /* Add upper 16-bits into checksum.  */
                checksum =  checksum + (temp >> NX_SHIFT_BY_16);

                /* Add lower 16-bits into checksum.  */
                checksum =  checksum + (temp & NX_LOWER_16_MASK);

                /* Move the word pointer and decrease the length.  */
                word_ptr =  word_ptr + sizeof(ULONG);
                adjusted_packet_length = adjusted_packet_length - sizeof(ULONG);
            }

            /* Adjust the checksum length.  */
            length =  length - packet_length;

            /* Determine if we are at the end of the current packet.  */
            if ((length) && (word_ptr >= (UCHAR *) current_packet -> nx_packet_append_ptr) &&
                (current_packet -> nx_packet_next))
            {

                /* We have crossed the packet boundary.  Move to the next packet
                   structure.  */
                current_packet =  current_packet -> nx_packet_next;

                /* Setup the new word pointer.  */
                word_ptr =  (UCHAR *) current_packet -> nx_packet_prepend_ptr;
            }
        }

        /* Add in the carry bits into the checksum.  */
        checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);
    
        /* Do it again in case previous operation generates an overflow.  */
        checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);    

        /* Place the packet in the second word of the UDP header.  */
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        udp_header_ptr -> nx_udp_header_word_1 =  udp_header_ptr -> nx_udp_header_word_1 | 
                                                    (~checksum & NX_LOWER_16_MASK);
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
#endif
        /* Restore the udp packet receiving function. */
        server_ip.nx_ip_udp_packet_receive = _nx_udp_packet_receive;
    }

    /* Let server receives the packet.  */
    _nx_udp_packet_receive(ip_ptr, packet_ptr); 
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_04_03_02_03_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NetX DHCP 04_03_02_03 Test................................N/A\n"); 

    test_control_return(3);  
}      
#endif