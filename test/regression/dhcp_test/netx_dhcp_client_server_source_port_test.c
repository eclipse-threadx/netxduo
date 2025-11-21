/* This NetX test concentrates on the DHCP operation to verify the DHCP server source port 
   is excluded from DHCP Client validation checks.  Further the NetX /NetX Duo packet processing
   should forward packets for the UDP socket bound to 68 without requiring the source port
   be 67.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_dhcp_client.h"
          

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8      

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;
static NX_DHCP                 dhcp_client;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   packet_counter;
static CHAR                    *pointer;

/* Define thread prototypes.  */             
static void    client_thread_entry(ULONG thread_input);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);  
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);    
extern USHORT  _nx_ip_checksum_compute(NX_PACKET *, ULONG, UINT, ULONG *, ULONG *);
extern void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);

/* DCHP Unicast Interaction Message.  */
                                          

/* Frame (342 bytes) DHCP Offer. The server source port is modified from 67 to 83 in the OFFER
   and REPLY packets for testing purposed. */
static const unsigned char pkt2[342] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x50, /* .."3DV.P */
0x56, 0x39, 0xf6, 0x3d, 0x08, 0x00, 0x45, 0x10, /* V9.=..E. */
0x01, 0x48, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, /* .H...... */
0x25, 0x79, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, /* %y...... */
0x00, 0x1c, 0x00, 0x53, 0x00, 0x44, 0x01, 0x34, /* ...C.D.4 */
0xdb, 0x11, 0x02, 0x01, 0x06, 0x00, 0x22, 0x33, /* .!...."3 */
0x44, 0x6e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, /* Dn...... */
0x00, 0x00, 0x0a, 0x00, 0x00, 0x1c, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x56, 0x00, 0x00, 0x00, 0x00, /* "3DV.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, /* ......c. */
0x53, 0x63, 0x35, 0x01, 0x02, 0x36, 0x04, 0x0a, /* Sc5..6.. */
0x00, 0x00, 0x01, 0x33, 0x04, 0x00, 0x00, 0x01, /* ...3.... */
0x2c, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, /* ,....... */
0x04, 0x0a, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};


/* Frame (342 bytes) DHCP ACK */
static const unsigned char pkt4[342] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x50, /* .."3DV.P */
0x56, 0x39, 0xf6, 0x3d, 0x08, 0x00, 0x45, 0x10, /* V9.=..E. */
0x01, 0x48, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, /* .H...... */
0x25, 0x79, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, /* %y...... */
0x00, 0x1c, 0x00, 0x53, 0x00, 0x44, 0x01, 0x34, /* ...C.D.4 */
0xd8, 0x10, 0x02, 0x01, 0x06, 0x00, 0x22, 0x33, /* . ...."3 */
0x44, 0x6e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, /* Dn...... */
0x00, 0x00, 0x0a, 0x00, 0x00, 0x1c, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x56, 0x00, 0x00, 0x00, 0x00, /* "3DV.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, /* ......c. */
0x53, 0x63, 0x35, 0x01, 0x05, 0x36, 0x04, 0x0a, /* Sc5..6.. */
0x00, 0x00, 0x01, 0x33, 0x04, 0x00, 0x00, 0x01, /* ...3.... */
0x2c, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, /* ,....... */
0x04, 0x0a, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

ULONG  dhcp_get_data_local(UCHAR *data, UINT size)
{

ULONG   value = 0;

   
    /* Process the data retrieval request.  */
    while (size-- > 0)
    {

        /* Build return value.  */
        value = (value << 8) | *data++;
    }

    /* Return value.  */
    return(value);
}

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_server_source_port_test_application_define(void *first_unused_memory)
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
                                                
    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;
    
    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;           

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&client_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    return;
}                

/* Define the test threads.  */

void    client_thread_entry(ULONG thread_input)
{

UINT        status;
ULONG       client_ip_address;
ULONG       client_ip_network_mask;

                           
    printf("NetX Test:   DHCP Client Server Source Port Test.......................");
                    
    /* Check the error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    if (status)            
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */
                           
    /* Clear the broadcast flag.  */
    status = nx_dhcp_clear_broadcast_flag(&dhcp_client, NX_TRUE);   
    if (status)             
    {
        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = my_packet_process;

    /* Start the DHCP Client.  */
    status =  nx_dhcp_start(&dhcp_client);
    if (status)             
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                           
    /* Check for address resolution.  */
    status =  nx_ip_status_check(&client_ip, NX_IP_ADDRESS_RESOLVED, (ULONG *) &status, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)             
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get the IP address.  */
    status = nx_ip_address_get(&client_ip, &client_ip_address, &client_ip_network_mask);      
                                   
    /* Check status.  */
    if (status)             
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the IP address.  */
    if ((client_ip_address != IP_ADDRESS(10, 0, 0, 28)) ||
        (client_ip_network_mask != IP_ADDRESS(255, 255, 255, 0)))        
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Stopping the DHCP client. */
    status = nx_dhcp_stop(&dhcp_client);
                                        
    /* Check status.  */
    if (status)             
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* All done. Return resources to NetX and ThreadX. */    
    status = nx_dhcp_delete(&dhcp_client);
                                           
    /* Check status.  */
    if (status)             
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Check the error.  */  
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

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
UINT            status; 
ULONG           dhcp_xid;    
NX_PACKET       *my_packet;

    /* Is this a DHCP packet e.g. not an ARP packet? */
    if (packet_ptr -> nx_packet_length < 328)
    {
        /* Maybe an ARP packet. let the RAM driver deal with it */
        return NX_TRUE;
    }

    /* Update the packet counter.  */
    packet_counter ++;     

    /* Check the packet counter.  */   
    if (packet_counter == 1)
    {
                       
        /* Receive the DHCP Discover message.  */ 

        /* Send DHCP Offer message.  */
        status =  nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &my_packet, 0,  NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            return NX_TRUE;
        }

        /* Write the DHCP Offer message.  */
        my_packet -> nx_packet_length = sizeof(pkt2) - 14;
        memcpy(my_packet -> nx_packet_prepend_ptr + 16, pkt2 + 14, my_packet -> nx_packet_length);
        my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

        my_packet -> nx_packet_prepend_ptr += 16;
        my_packet -> nx_packet_append_ptr += 16;
    }
    else if (packet_counter == 2)
    {      

        /* Receive the DHCP Request message,  */

        /* Send DHCP ACK message.  */
        status =  nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &my_packet, 0,  NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            return NX_TRUE;
        }

        /* Write the DHCP ACK message.  */
        my_packet -> nx_packet_length = sizeof(pkt4) - 14;
        memcpy(my_packet -> nx_packet_prepend_ptr + 16, pkt4 + 14, my_packet -> nx_packet_length);
        my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

        my_packet -> nx_packet_prepend_ptr += 16;
        my_packet -> nx_packet_append_ptr += 16;
    }

    /* Get the XID of DHCP message from DHCP Server.  */    
    dhcp_xid = dhcp_get_data_local(my_packet -> nx_packet_prepend_ptr + 20 + 8 + NX_BOOTP_OFFSET_XID, 4);

    /* Replace the XID.  */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_xid = dhcp_xid;

    /* Receive the packet.  */
    _nx_ip_packet_deferred_receive(ip_ptr, my_packet);

    return NX_TRUE;
}


#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_server_source_port_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Client Server Source Port Test.......................N/A\n");

    test_control_return(3);  
}      
#endif