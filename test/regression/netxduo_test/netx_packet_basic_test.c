/* This NetX test concentrates on the basic packet operations.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_packet.h"

#define     DEMO_STACK_SIZE         2048

#define     TEST_SIZE               (NX_UDP_PACKET+28)

#ifndef NX_PACKET_ALIGNMENT
#define NX_PACKET_ALIGNMENT         sizeof(ULONG)
#endif /* NX_PACKET_ALIGNMENT */

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_PACKET_POOL          pool_2;               
#ifdef NX_DISABLE_ERROR_CHECKING     
static NX_PACKET_POOL          pool_3;
#endif
static NX_PACKET_POOL          pool_4;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                    *pool_0_ptr;
static CHAR                    *pool_1_ptr;
static CHAR                    *pool_2_ptr;              
#ifdef NX_DISABLE_ERROR_CHECKING     
static CHAR                    *pool_3_ptr;  
#endif
static CHAR                    *pool_4_ptr;  
static ULONG                    pool_0_size;


static UCHAR                   buffer[2048];

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void  test_control_return(UINT status);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_packet_basic_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    pool_0_ptr =  NX_NULL;
    pool_1_ptr =  NX_NULL;
    pool_2_ptr =  NX_NULL;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();


    /* Create first packet pool.  */
    pointer = (CHAR *)(((ALIGN_TYPE)pointer + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1));
    pool_0_ptr =  pointer;
    pool_0_size = (((TEST_SIZE + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1)) + ((sizeof(NX_PACKET) + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1))) * 3;
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pool_0_ptr, pool_0_size);

    pointer = pointer + pool_0_size;
    if (status)
        error_counter++;

    /* Create second packet pool.  */
    pointer = (CHAR *)(((ALIGN_TYPE)pointer + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1));
    status =  nx_packet_pool_create(&pool_1, "NetX Second Packet Pool", 200, pointer, 1000);
    pool_1_ptr =  pointer;
    pointer = pointer + 1000;

    if (status)
        error_counter++;

    /* Create third packet pool.  */
    pointer = (CHAR *)(((ALIGN_TYPE)pointer + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1));
    status =  nx_packet_pool_create(&pool_2, "NetX Third Packet Pool", 256, pointer, 8192);
    pool_2_ptr =  pointer;
    pointer = pointer + 8192;

    if (status)
        error_counter++; 
                                              
#ifdef NX_DISABLE_ERROR_CHECKING      
    /* Create fourth packet pool, small pool size.  */
    status =  nx_packet_pool_create(&pool_3, "NetX Fourth Packet Pool", 256, pointer, 200);  
    pool_3_ptr =  pointer;
    pointer = pointer + 200;

    if (status)
        error_counter++;
#endif

    /* Create fourth packet pool, small pool size.  */
    pointer = (CHAR *)(((ALIGN_TYPE)pointer + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1));
    status =  nx_packet_pool_create(&pool_4, "NetX Fifth Packet Pool", 252, pointer, 8192);  
    pool_4_ptr =  pointer;
    pointer = pointer + 8192;

    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet1;
NX_PACKET   *my_packet2;
NX_PACKET   *my_packet3;
NX_PACKET   *my_packet4;
#if !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__)
NX_PACKET   *packet_ptr;
#endif /* !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__) */
ULONG       size;
UCHAR       local_buffer[300];
ULONG       total_packets, free_packets, empty_pool_requests, empty_pool_suspensions, invalid_packet_releases;
    
    /* Print out test information banner.  */
    printf("NetX Test:   Packet Basic Processing Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                            

    /* Delete all the packet pools.  */
    status =   nx_packet_pool_delete(&pool_0);
    status +=  nx_packet_pool_delete(&pool_1);
    status +=  nx_packet_pool_delete(&pool_2);               
#ifdef NX_DISABLE_ERROR_CHECKING     
    status +=  nx_packet_pool_delete(&pool_3);
#endif
    status +=  nx_packet_pool_delete(&pool_4);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create the pools again.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pool_0_ptr, pool_0_size);
    status +=  nx_packet_pool_create(&pool_1, "NetX Second Packet Pool", TEST_SIZE, pool_1_ptr, 1000);
    status +=  nx_packet_pool_create(&pool_2, "NetX Third Packet Pool", 256, pool_2_ptr, 8192);     
#ifdef NX_DISABLE_ERROR_CHECKING      
    status +=  nx_packet_pool_create(&pool_3, "NetX Fourth Packet Pool", 256, pool_3_ptr, 200); 
#endif
    status +=  nx_packet_pool_create(&pool_4, "NetX Fifth Packet Pool", 252, pool_4_ptr, 8192);  

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate packets.  */
    status =   nx_packet_allocate(&pool_4, &my_packet1, NX_UDP_PACKET, 10);
    status +=  nx_packet_allocate(&pool_4, &my_packet2, NX_UDP_PACKET, 10);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check alignment. */
    if(((ALIGN_TYPE)my_packet1 & (NX_PACKET_ALIGNMENT - 1)) ||
       ((ALIGN_TYPE)my_packet2 & (NX_PACKET_ALIGNMENT - 1)) ||
       ((ALIGN_TYPE)(my_packet1 -> nx_packet_data_start) & (NX_PACKET_ALIGNMENT - 1)) ||
       ((ALIGN_TYPE)(my_packet2 -> nx_packet_data_start) & (NX_PACKET_ALIGNMENT - 1)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_release(my_packet1);
    status += nx_packet_release(my_packet2);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Allocate packets.  */
    status =   nx_packet_allocate(&pool_0, &my_packet1, NX_UDP_PACKET, 10);
    status +=  nx_packet_allocate(&pool_0, &my_packet2, NX_UDP_PACKET, 10);
    status +=  nx_packet_allocate(&pool_0, &my_packet3, NX_UDP_PACKET, 10);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Attempt to allocate another packet to get the error return.  */
    status =  nx_packet_allocate(&pool_0, &my_packet4, NX_UDP_PACKET, NX_NO_WAIT);

    /* Check status.  */
    if (status != NX_NO_PACKET)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release all the packets but the first.  */
    status =   nx_packet_release(my_packet2);
    status +=  nx_packet_release(my_packet3);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Place the alphabet in the packet.  */
    status =  nx_packet_data_append(my_packet1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_NO_WAIT);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Copy the packet to another pool.  */
    status =  nx_packet_copy(my_packet1, &my_packet2, &pool_1, NX_NO_WAIT);

    /* Check status.  */
    if ((status != NX_SUCCESS) || (my_packet2 -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Retrieve the payload from new packet.  */
    local_buffer[0] =  0;
    status =  nx_packet_data_retrieve(my_packet2, local_buffer, &size);

    /* Check status.  */
    if ((status) || (my_packet2 -> nx_packet_length != 28) || (size != 28) || (local_buffer[0] != 'A'))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet copy.  */
    status =  nx_packet_release(my_packet2);

#if !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__)
    /* Make sure the packet is chained. */
    while(my_packet1 -> nx_packet_next == (NX_PACKET *)NX_NULL)
    {

        /* Append numbers to first message. This will introduce packet chaining.  */
        status +=  nx_packet_data_append(my_packet1, "0102030405060708091011121314151617181920", 40, &pool_0, NX_NO_WAIT);
    }

    /* Trim data in the last packet. */
    my_packet1 -> nx_packet_length -= (ULONG)((ALIGN_TYPE)my_packet1 -> nx_packet_last -> nx_packet_append_ptr - (ALIGN_TYPE)my_packet1 -> nx_packet_last -> nx_packet_append_ptr);
    my_packet1 -> nx_packet_last = my_packet1;
    packet_ptr = my_packet1 -> nx_packet_next;

    /* Append numbers to first message. This will reuse the packet chaining.  */
    status +=  nx_packet_data_append(my_packet1, "abc", 3, &pool_0, NX_NO_WAIT);

    /* Check status.  */
    if ((status != NX_SUCCESS) || (my_packet1 -> nx_packet_next != packet_ptr))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Copy the packet to a packet in both pools.  This requires chaining and non-chaining.  */
    status =  nx_packet_copy(my_packet1, &my_packet2, &pool_1, NX_NO_WAIT);
    status +=  nx_packet_copy(my_packet2, &my_packet3, &pool_2, NX_NO_WAIT);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (my_packet2 -> nx_packet_length != my_packet1 -> nx_packet_length) || 
        (my_packet3 -> nx_packet_length != my_packet2 -> nx_packet_length))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Retrieve the payload from the first new packet.  */
    local_buffer[0] =  0;
    status =  nx_packet_data_retrieve(my_packet2, local_buffer, &size);

    /* Check status.  */
    if ((status) || 
        (my_packet1 -> nx_packet_length != my_packet2 -> nx_packet_length) || 
        (size != my_packet2 -> nx_packet_length) || 
        (local_buffer[0] != 'A') || (local_buffer[28] != '0'))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Retrieve the payload from the second new packet.  */
    local_buffer[0] =  0;
    status =  nx_packet_data_retrieve(my_packet3, local_buffer, &size);

    /* Check status.  */
    if ((status) || (my_packet3 -> nx_packet_length != my_packet2 -> nx_packet_length) || 
        (size != my_packet2 -> nx_packet_length) || 
        (local_buffer[0] != 'A') || (local_buffer[28] != '0'))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_PACKET_CHAIN && __PRODUCT_NETXDUO__ */

    /* Transmit release all packets.  */
    status =   nx_packet_transmit_release(my_packet1);
    
#if !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__)
    status +=  nx_packet_transmit_release(my_packet2);
    status +=  nx_packet_transmit_release(my_packet3);
#endif /* NX_DISABLE_PACKET_CHAIN && __PRODUCT_NETXDUO__ */

    /* Get nothing from the first pool.  */
    status +=  nx_packet_pool_info_get(&pool_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);

    /* Get information about the first pool.  */
    status +=  nx_packet_pool_info_get(&pool_0, &total_packets, &free_packets, &empty_pool_requests, &empty_pool_suspensions, &invalid_packet_releases);

#ifndef NX_DISABLE_PACKET_INFO

    if(empty_pool_requests != 1)
        status++;
#endif

    /* Check status.  */
    if ((status) || (total_packets != 3) || (free_packets != 3) || (empty_pool_suspensions) || (invalid_packet_releases))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           
           
    /* Delete all the packet pools.  */
    status =   nx_packet_pool_delete(&pool_0);
    status +=  nx_packet_pool_delete(&pool_1);
    status +=  nx_packet_pool_delete(&pool_2);               
#ifdef NX_DISABLE_ERROR_CHECKING     
    status +=  nx_packet_pool_delete(&pool_3);
#endif
             
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Tested the abnormal operation. */

    /* Create the pools again.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pool_0_ptr, pool_0_size);
    status +=  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", TEST_SIZE, pool_1_ptr, 1000);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate the packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet1, 0, NX_NO_WAIT);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef __PRODUCT_NETXDUO__
    /* Append data that is larger than whole pool. */
    status = nx_packet_data_append(my_packet1, buffer, sizeof(buffer), &pool_0, NX_NO_WAIT);

    /* Check the status.  */
    if((!status) ||(pool_0.nx_packet_pool_invalid_releases))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* __PRODUCT_NETXDUO__ */
                          
    /* Copy the packet with length 0.  */
    status = nx_packet_copy(my_packet1, &my_packet2, &pool_0, NX_NO_WAIT);
           
    /* Check the status.  */
    if(!status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                     
#if !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__)
    /* Append data that is two packet size. */
    status = nx_packet_data_append(my_packet1, buffer, TEST_SIZE * 2, &pool_0, NX_NO_WAIT);

    /* Check the status.  */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                           
    /* Copy the packet when the pool size not enough.  */
    status = nx_packet_copy(my_packet1, &my_packet2, &pool_0, NX_NO_WAIT);
           
    /* Check the status.  */
    if(!status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Modify the first packet prepend and append.  */
    my_packet1 -> nx_packet_prepend_ptr = my_packet1 -> nx_packet_append_ptr;
    my_packet1 -> nx_packet_length = TEST_SIZE;    

    /* Copy the packet .  */
    status = nx_packet_copy(my_packet1, &my_packet2, &pool_1, NX_NO_WAIT);
           
    /* Check the status.  */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
#endif

    /* Release the packet.  */
    nx_packet_release(my_packet1);
                                 
    /* Allocate the packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet1, 0, NX_NO_WAIT);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Construct the packet data.  */ 
    memcpy(my_packet1 -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet1 -> nx_packet_append_ptr =  my_packet1 -> nx_packet_prepend_ptr + 28;  

    /* Set the invalid length.  */
    my_packet1 -> nx_packet_length =  30;         

    /* Copy the packet when the pool size not enough.  */
    status = nx_packet_copy(my_packet1, &my_packet2, &pool_0, NX_NO_WAIT);
           
    /* Check the status.  */
    if(!status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Retrieve the packet data.  */
    status = nx_packet_data_retrieve(my_packet1, buffer, &size);
               
    /* Check the status.  */
    if(!status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
            
    /* Extract the packet with zero offset.  */
    status = nx_packet_data_extract_offset(my_packet1, 30, buffer, sizeof(buffer), &size);
               
    /* Check the status.  */
    if(!status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           
             
    /* Set the invalid packet length.  */ 
    my_packet1 -> nx_packet_length =  0; 
    
    /* Extract the packet with zero offset.  */
    status = nx_packet_data_extract_offset(my_packet1, 0, buffer, sizeof(buffer), &size);
               
    /* Check the status.  */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            
      
    /* Set the valid packet length.  */ 
    my_packet1 -> nx_packet_length =  28; 
    
    /* Extract the packet with small buffer.  */
    status = nx_packet_data_extract_offset(my_packet1, 0, buffer, 26, &size);
               
    /* Check the status.  */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Release the packet.  */
    nx_packet_release(my_packet1);

#ifndef NX_DISABLE_PACKET_CHAIN
                                                  
    /* Allocate the packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet1, 0, NX_NO_WAIT);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Append data that is two packet size. */
    status = nx_packet_data_append(my_packet1, buffer, TEST_SIZE * 2, &pool_0, NX_NO_WAIT);

    /* Check the status.  */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Extract the packet.  */
    status = nx_packet_data_extract_offset(my_packet1, TEST_SIZE, buffer, sizeof(buffer), &size);
               
    /* Check the status.  */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                   
    /* Extract the packet with small buffer.  */
    status = nx_packet_data_extract_offset(my_packet1, 0, buffer, TEST_SIZE, &size);
               
    /* Check the status.  */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the invalid length.  */
    my_packet1 -> nx_packet_length = TEST_SIZE * 3;
    
    /* Extract the packet with invalid length.  */
    status = nx_packet_data_extract_offset(my_packet1, TEST_SIZE * 2, buffer, sizeof(buffer), &size);
               
    /* Check the status.  */
    if(!status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Reset the packet length.  */ 
    my_packet1 -> nx_packet_length = TEST_SIZE * 2;

    /* Try to release this packet.  */
    status = nx_packet_release(my_packet1);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif


#ifndef NX_DISABLE_ERROR_CHECKING
    /* Allocate the packet with large packet type.  */
    status = nx_packet_allocate(&pool_0, &my_packet1, (pool_0.nx_packet_pool_payload_size + 4), NX_NO_WAIT);

    /* Check for error.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Allocate the packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet1, 0, NX_NO_WAIT);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Modifed the pool owner.  */
    my_packet1 -> nx_packet_pool_owner = NX_NULL;

    /* Try to release this packet.  */
    status = nx_packet_release(my_packet1);

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Modifed the pool owner ID.  */
    my_packet1 -> nx_packet_pool_owner = &pool_0;
    my_packet1 -> nx_packet_pool_owner -> nx_packet_pool_id = 0;

    /* Try to release this packet.  */
    status = nx_packet_release(my_packet1);

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Recover the pool ID.  */
    my_packet1 -> nx_packet_pool_owner -> nx_packet_pool_id = NX_PACKET_POOL_ID;

    /* Try to release this packet.  */
    status = nx_packet_release(my_packet1);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    printf("SUCCESS!\n");
    test_control_return(0);
}

