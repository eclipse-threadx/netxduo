/* This NetX test concentrates on the RARP dynamic entry operation.  */

#include   "tx_api.h"
#include   "nx_api.h"   
#include   "nx_rarp.h"        
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_RARP_INFO) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static UINT                    response_type;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);       
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_rarp_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static VOID    ip_address_change_notify(NX_IP *ip_ptr, VOID *additional_info); 
static VOID    fake_rarp_response_packet(NX_PACKET **my_packet, UINT type); 
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);      
void           _nx_ram_network_driver_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT interface_instance_id);
                                                                         
#define NX_ETHERNET_RARP    0x8035
#define NX_ETHERNET_SIZE    14

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rarp_basic_processing_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", 0, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Attach the 2nd interface IP address so it dosn't need RARP service. */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 111), 0xFF000000, _nx_ram_network_driver_256);
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }      

#if (NX_MAX_PHYSICAL_INTERFACES > 2) && defined(__PRODUCT_NETXDUO__) 
    /* Attach the 3rd interface IP address so it dosn't need RARP service. */
    status = nx_ip_interface_attach(&ip_0, "3rd interface", 0, 0xFFFFFF00, _nx_ram_network_driver_256);
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }      
#endif
}
                          

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       actual_status;
ULONG       ip_address, network_mask;
ULONG       rarp_requests_sent, rarp_responses_received, rarp_invalid_messages;


    /* Print out some test information banners.  */
    printf("NetX Test:   RARP Basic Processing Test................................");
            
    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

#if (NX_MAX_PHYSICAL_INTERFACES > 2) && defined(__PRODUCT_NETXDUO__) 
    /* Disable address mapping. */
    nx_ip_interface_address_mapping_configure(&ip_0, 2, NX_FALSE);
#endif

   /* Enable RARP for IP Instance 0.  */
    status  =  nx_rarp_enable(&ip_0);
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                              
            
    /* Enable the rarp feature again.  */
    status = nx_rarp_enable(&ip_0);  
           
    /* Check status...  */
    if (status != NX_ALREADY_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register IP address change callback. */
    status = nx_ip_address_change_notify(&ip_0, ip_address_change_notify, NX_NULL);

    /* Check for error */
    if (status)
    {
                     
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = my_rarp_packet_process;

    /* Set the response type as 0 .  */
    response_type = 0;

    /* Waiting NetX sending the RARP request to get the address.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);     
                              
    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_ADDRESS_RESOLVED, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

   /* Enable RARP for IP Instance 0.  */
    status  =  nx_rarp_enable(&ip_0);
    if (status)              
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
                           
    /* Set the response type as 0 .  */
    response_type = 1;

    /* Waiting NetX sending the RARP request to get the address.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);  

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_ADDRESS_RESOLVED, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get the IP instance address.  */          
    status = nx_ip_interface_address_get(&ip_0, 0, &ip_address, &network_mask);
          
    /* Check status...  */
    if((status != NX_SUCCESS) || (ip_address != IP_ADDRESS(1,2,3,4)) || (network_mask != 0xFFFFFF00UL))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get information about RARP.  */
    status =  nx_rarp_info_get(&ip_0, NX_NULL, NX_NULL, NX_NULL);       

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status =  nx_rarp_info_get(&ip_0, &rarp_requests_sent, &rarp_responses_received, &rarp_invalid_messages);       
    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
#ifndef NX_DISABLE_ARP_INFO
    if((rarp_requests_sent != 2) || (rarp_responses_received != 1) || (rarp_invalid_messages != 3))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif                            
                     
#ifdef __PRODUCT_NETXDUO__
    /* Tested the nx_rarp_enable feature after IP address resloved.  */       
         
    /* Enable the rarp feature again.  */
    status = nx_rarp_enable(&ip_0);  
           
    /* Check status...  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the rarp feature.  */
    status =  nx_rarp_disable(&ip_0);  

    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

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

static UINT    my_rarp_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{       
UINT        status;
NX_PACKET   *fake_packet_1;  
NX_PACKET   *fake_packet_2; 
NX_PACKET   *fake_packet_3;
                         
    /* Drop the packet. */
    *operation_ptr = NX_RAMDRIVER_OP_DROP;

    /* Check the response type.  */
    if (response_type == 0)
    {                    

        /* Disable the rarp feature.  */
        status =  nx_rarp_disable(&ip_0);  

        /* Check status.  */
        if (status)
            error_counter++;

        /* Fake the response packet.  */
        fake_rarp_response_packet(&fake_packet_1, NX_RARP_OPTION_RESPONSE);

        /* Call the driver to receive this packet.  */
        _nx_ram_network_driver_receive(&ip_0, fake_packet_1, 0);
    }
    else if (response_type == 1)
    {          

        /* Fake a request packet.  */
        fake_rarp_response_packet(&fake_packet_1, NX_RARP_OPTION_REQUEST);

        /* Call the driver to receive this packet.  */
        _nx_ram_network_driver_receive(&ip_0, fake_packet_1, 0);   
                                                                  
        /* Fake a invalid packet.  */
        fake_rarp_response_packet(&fake_packet_2, 0);

        /* Call the driver to receive this packet.  */
        _nx_ram_network_driver_receive(&ip_0, fake_packet_2, 0);   

        /* Fake the response packet.  */
        fake_rarp_response_packet(&fake_packet_3, NX_RARP_OPTION_RESPONSE);

        /* Call the driver to receive this packet.  */
        _nx_ram_network_driver_receive(&ip_0, fake_packet_3, 0);             
    }
      
    return NX_TRUE;
}     
static VOID fake_rarp_response_packet(NX_PACKET **packet_ptr, UINT type) 
{             
UINT        status;       
NX_PACKET   *my_packet;
ULONG       *ethernet_frame_ptr;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Create a fake RARP response packet to assign address(1.2.3.4)!  */
    my_packet -> nx_packet_prepend_ptr[0] =   0x00;     /* Ethernet header  */
    my_packet -> nx_packet_prepend_ptr[1] =   0x01;     
    my_packet -> nx_packet_prepend_ptr[2] =   0x80;     /* IP address  */
    my_packet -> nx_packet_prepend_ptr[3] =   0x00; 
    my_packet -> nx_packet_prepend_ptr[4] =   0x06;     /* Hardware address size */
    my_packet -> nx_packet_prepend_ptr[5] =   0x04;     /* IP address size  */

    /* Check the type.  */
    if (type == NX_RARP_OPTION_REQUEST)
    {                
        my_packet -> nx_packet_prepend_ptr[6] =   0x00;     /* RARP request  */
        my_packet -> nx_packet_prepend_ptr[7] =   0x03;
    }
    else if (type == NX_RARP_OPTION_RESPONSE)
    {                           
        my_packet -> nx_packet_prepend_ptr[6] =   0x00;     /* RARP response  */
        my_packet -> nx_packet_prepend_ptr[7] =   0x04;
    }
    else
    {       
        my_packet -> nx_packet_prepend_ptr[6] =   0x00;     /* Invalid RARP type  */
        my_packet -> nx_packet_prepend_ptr[7] =   0x00;
    }
    my_packet -> nx_packet_prepend_ptr[8] =   0x11;     /* Sender Ethernet hardware address  */
    my_packet -> nx_packet_prepend_ptr[9] =   0x22;
    my_packet -> nx_packet_prepend_ptr[10] =  0x33;
    my_packet -> nx_packet_prepend_ptr[11] =  0x44;
    my_packet -> nx_packet_prepend_ptr[12] =  0x55;
    my_packet -> nx_packet_prepend_ptr[13] =  0x67;
    my_packet -> nx_packet_prepend_ptr[14] =  0x01;     /* Sender IP address  */
    my_packet -> nx_packet_prepend_ptr[15] =  0x02;
    my_packet -> nx_packet_prepend_ptr[16] =  0x03;
    my_packet -> nx_packet_prepend_ptr[17] =  0x87;
    my_packet -> nx_packet_prepend_ptr[18] =  0x11;     /* Target hardware address  */
    my_packet -> nx_packet_prepend_ptr[19] =  0x22;
    my_packet -> nx_packet_prepend_ptr[20] =  0x33;
    my_packet -> nx_packet_prepend_ptr[21] =  0x44;
    my_packet -> nx_packet_prepend_ptr[22] =  0x55;
    my_packet -> nx_packet_prepend_ptr[23] =  0x66;
    my_packet -> nx_packet_prepend_ptr[24] =  0x01;     /* Target IP address  */
    my_packet -> nx_packet_prepend_ptr[25] =  0x02;
    my_packet -> nx_packet_prepend_ptr[26] =  0x03;
    my_packet -> nx_packet_prepend_ptr[27] =  0x04;
               
    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28; 
                          
    /* Fake a receive RARP packet.  */
    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[TEST_INTERFACE];     

    /* Adjust the prepend pointer.  */
    my_packet -> nx_packet_prepend_ptr =  my_packet -> nx_packet_prepend_ptr - NX_ETHERNET_SIZE;

    /* Adjust the packet length.  */
    my_packet -> nx_packet_length =  my_packet -> nx_packet_length + NX_ETHERNET_SIZE;

    /* Setup the ethernet frame pointer to build the ethernet frame.  Backup another 2
    bytes to get 32-bit word alignment.  */
    ethernet_frame_ptr =  (ULONG *) (my_packet -> nx_packet_prepend_ptr - 2);

    /* Build the ethernet frame.  */
    *ethernet_frame_ptr     =  0x00000011;
    *(ethernet_frame_ptr+1) = 0x22334456;
    *(ethernet_frame_ptr+2) =  (0x00000011 << 16) | (0x22334457 >> 16);
    *(ethernet_frame_ptr+3) =  ((0x22334457 & 0xFFFF) << 16);  
    *(ethernet_frame_ptr+3) |= NX_ETHERNET_RARP;        

    /* Endian swapping if NX_LITTLE_ENDIAN is defined.  */
    NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));
    NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr+1));
    NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr+2));
    NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr+3));

    /* Set the packet pointer.  */
    *packet_ptr = my_packet;
}
static VOID ip_address_change_notify(NX_IP *ip_ptr, VOID *additional_info)
{       
}  
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_rarp_basic_processing_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   RARP Basic Processing Test................................N/A\n");

    test_control_return(3);

}
#endif
