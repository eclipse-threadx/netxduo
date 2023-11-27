/* This NetX test concentrates on the code coverage for RARP functions,
 *_nx_rarp_packet_receive
*/

#include "nx_api.h"
#include "tx_thread.h"
#include "nx_rarp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static CHAR                    *pointer;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req); 
static UINT    rarp_packet_allocate(NX_IP *ip_ptr, NX_PACKET **packet_ptr, UINT arp_type,
                                    UCHAR *source_ip, UCHAR *source_physical, 
                                    UCHAR *target_ip, UCHAR *target_physical);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rarp_branch_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
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

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;
UCHAR       source_mac[6];
UCHAR       source_ip[4];
UCHAR       destination_mac[6];
UCHAR       destination_ip[6];

    /* Print out some test information banners.  */
    printf("NetX Test:   RARP Branch Test..........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Test _nx_rarp_packet_receive.  */
    /* Hit condition of if (*(message_ptr + 6))  */
    source_mac[0] = 0x11;
    source_mac[1] = 0x22;
    source_mac[2] = 0x33;
    source_mac[3] = 0x44;
    source_mac[4] = 0x55;
    source_mac[5] = 0x67;
    source_ip[0] = 0x01;
    source_ip[1] = 0x02;
    source_ip[2] = 0x03;
    source_ip[3] = 0x87;

    destination_mac[0] = 0x11;
    destination_mac[1] = 0x22;
    destination_mac[2] = 0x33;
    destination_mac[3] = 0x44;
    destination_mac[4] = 0x55;
    destination_mac[5] = 0x66; 
    destination_ip[0] = 0x01;
    destination_ip[1] = 0x02;
    destination_ip[2] = 0x03;
    destination_ip[3] = 0x04;

    /* Allocate ARP packet, */
    status = rarp_packet_allocate(&ip_0, &my_packet, NX_RARP_OPTION_RESPONSE, source_ip, source_mac, destination_ip, destination_mac);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];

    /* Call function.  */
    _nx_rarp_packet_receive(&ip_0, my_packet); 

    /* Set the MAC and IP address.  */
    source_mac[0] = 0x11;
    source_mac[1] = 0x22;
    source_mac[2] = 0x33;
    source_mac[3] = 0x44;
    source_mac[4] = 0x55;
    source_mac[5] = 0x67;
    source_ip[0] = 0x01;
    source_ip[1] = 0x02;
    source_ip[2] = 0x03;
    source_ip[3] = 0x87;

    destination_mac[0] = 0x11;
    destination_mac[1] = 0x22;
    destination_mac[2] = 0x33;
    destination_mac[3] = 0x44;
    destination_mac[4] = 0x55;
    destination_mac[5] = 0x66; 
    destination_ip[0] = 0x00;
    destination_ip[1] = 0x00;
    destination_ip[2] = 0x00;
    destination_ip[3] = 0x00;

    /* Allocate ARP packet, */
    status = rarp_packet_allocate(&ip_0, &my_packet, NX_RARP_OPTION_RESPONSE, source_ip, source_mac, destination_ip, destination_mac);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0]; 

    /* Call function.  */
    _nx_rarp_packet_receive(&ip_0, my_packet);


    /* Hit condition of if (previous_ip_address != *(message_ptr + 6))  */
    source_mac[0] = 0x11;
    source_mac[1] = 0x22;
    source_mac[2] = 0x33;
    source_mac[3] = 0x44;
    source_mac[4] = 0x55;
    source_mac[5] = 0x67;
    source_ip[0] = 0x01;
    source_ip[1] = 0x02;
    source_ip[2] = 0x03;
    source_ip[3] = 0x87;

    destination_mac[0] = 0x11;
    destination_mac[1] = 0x22;
    destination_mac[2] = 0x33;
    destination_mac[3] = 0x44;
    destination_mac[4] = 0x55;
    destination_mac[5] = 0x66; 
    destination_ip[0] = 0x01;
    destination_ip[1] = 0x02;
    destination_ip[2] = 0x03;
    destination_ip[3] = 0x04;

    /* Allocate ARP packet, */
    status = rarp_packet_allocate(&ip_0, &my_packet, NX_RARP_OPTION_RESPONSE, source_ip, source_mac, destination_ip, destination_mac);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];

    /* Call function.  */
    _nx_rarp_packet_receive(&ip_0, my_packet); 

    /* Set the MAC and IP address.  */
    source_mac[0] = 0x11;
    source_mac[1] = 0x22;
    source_mac[2] = 0x33;
    source_mac[3] = 0x44;
    source_mac[4] = 0x55;
    source_mac[5] = 0x67;
    source_ip[0] = 0x01;
    source_ip[1] = 0x02;
    source_ip[2] = 0x03;
    source_ip[3] = 0x87;

    destination_mac[0] = 0x11;
    destination_mac[1] = 0x22;
    destination_mac[2] = 0x33;
    destination_mac[3] = 0x44;
    destination_mac[4] = 0x55;
    destination_mac[5] = 0x66; 
    destination_ip[0] = 0x01;
    destination_ip[1] = 0x02;
    destination_ip[2] = 0x03;
    destination_ip[3] = 0x05;

    /* Allocate ARP packet, */
    status = rarp_packet_allocate(&ip_0, &my_packet, NX_RARP_OPTION_RESPONSE, source_ip, source_mac, destination_ip, destination_mac);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0]; 

    /* Call function.  */
    _nx_rarp_packet_receive(&ip_0, my_packet);

    /* Allocate ARP packet, */
    status = rarp_packet_allocate(&ip_0, &my_packet, NX_RARP_OPTION_RESPONSE, source_ip, source_mac, destination_ip, destination_mac);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];
    my_packet -> nx_packet_length -=  1;

    /* Call function.  */
    _nx_rarp_packet_receive(&ip_0, my_packet);

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


UINT  rarp_packet_allocate(NX_IP *ip_ptr, NX_PACKET **packet_ptr, UINT arp_type,  
                           UCHAR *source_ip, UCHAR *source_physical, 
                           UCHAR *target_ip, UCHAR *target_physical)
{

NX_PACKET       *my_packet;


    /* Allocate a packet to build the ARP message in.  */
    if (nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &my_packet, NX_PHYSICAL_HEADER, NX_NO_WAIT))
    {

        /* Error getting packet, so just get out!  */
        return (NX_FALSE);
    }                                   
    
    /* Create a fake RARP response packet to assign address(1.2.3.4)!  */
    my_packet -> nx_packet_prepend_ptr[0] =   0x00;     /* Ethernet header  */
    my_packet -> nx_packet_prepend_ptr[1] =   0x01;     
    my_packet -> nx_packet_prepend_ptr[2] =   0x80;     /* IP address  */
    my_packet -> nx_packet_prepend_ptr[3] =   0x00; 
    my_packet -> nx_packet_prepend_ptr[4] =   0x06;     /* Hardware address size */
    my_packet -> nx_packet_prepend_ptr[5] =   0x04;     /* IP address size  */

    /* Check the type.  */
    if (arp_type == NX_RARP_OPTION_REQUEST)
    {                
        my_packet -> nx_packet_prepend_ptr[6] =   0x00;     /* RARP request  */
        my_packet -> nx_packet_prepend_ptr[7] =   0x03;
    }
    else if (arp_type == NX_RARP_OPTION_RESPONSE)
    {                           
        my_packet -> nx_packet_prepend_ptr[6] =   0x00;     /* RARP response  */
        my_packet -> nx_packet_prepend_ptr[7] =   0x04;
    }
    else
    {       
        my_packet -> nx_packet_prepend_ptr[6] =   0x00;     /* Invalid RARP type  */
        my_packet -> nx_packet_prepend_ptr[7] =   0x00;
    }

    my_packet -> nx_packet_prepend_ptr[8] =   source_physical[0];     /* Sender Ethernet hardware address  */
    my_packet -> nx_packet_prepend_ptr[9] =   source_physical[1];;
    my_packet -> nx_packet_prepend_ptr[10] =  source_physical[2];;
    my_packet -> nx_packet_prepend_ptr[11] =  source_physical[3];;
    my_packet -> nx_packet_prepend_ptr[12] =  source_physical[4];;
    my_packet -> nx_packet_prepend_ptr[13] =  source_physical[5];;
    my_packet -> nx_packet_prepend_ptr[14] =  source_ip[0];     /* Sender IP address  */
    my_packet -> nx_packet_prepend_ptr[15] =  source_ip[1];
    my_packet -> nx_packet_prepend_ptr[16] =  source_ip[2];
    my_packet -> nx_packet_prepend_ptr[17] =  source_ip[3];
    my_packet -> nx_packet_prepend_ptr[18] =  target_physical[0];     /* Target hardware address  */
    my_packet -> nx_packet_prepend_ptr[19] =  target_physical[1];
    my_packet -> nx_packet_prepend_ptr[20] =  target_physical[2];
    my_packet -> nx_packet_prepend_ptr[21] =  target_physical[3];
    my_packet -> nx_packet_prepend_ptr[22] =  target_physical[4];
    my_packet -> nx_packet_prepend_ptr[23] =  target_physical[5];
    my_packet -> nx_packet_prepend_ptr[24] =  target_ip[0];     /* Target IP address  */
    my_packet -> nx_packet_prepend_ptr[25] =  target_ip[1];
    my_packet -> nx_packet_prepend_ptr[26] =  target_ip[2];
    my_packet -> nx_packet_prepend_ptr[27] =  target_ip[3];
               
    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28; 

    /* Return packet.  */
    *packet_ptr = my_packet;

    return (NX_TRUE);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rarp_branch_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RARP Branch Test..........................................N/A\n"); 

    test_control_return(3);  
}      
#endif

