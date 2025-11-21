/* This NetX test concentrates on the basic packet operations.  */

#include   "nx_packet.h"    
#include   "tx_api.h"
#include   "nx_api.h"
#include   "tx_thread.h"
extern void     test_control_return(UINT status);
                                   
#if !defined(NX_DISABLE_ERROR_CHECKING) && !defined(NX_PACKET_HEADER_PAD)

#define     DEMO_STACK_SIZE         2048

#ifndef NX_PACKET_ALIGNMENT
#define NX_PACKET_ALIGNMENT 4
#endif /* NX_PACKET_ALIGNMENT */

#define     TEST_SIZE               (((NX_UDP_PACKET+28)+NX_PACKET_ALIGNMENT - 1)/NX_PACKET_ALIGNMENT*NX_PACKET_ALIGNMENT)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;  
static NX_PACKET_POOL          pool_1;  
static NX_PACKET_POOL          invalid_pool;


/* Define the counters used in the test application...  */

static ULONG                   error_counter; 
static CHAR                    *pointer;


/* Define thread prototypes.  */

static void     ntest_0_entry(ULONG thread_input);   

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_packet_nxe_api_test_application_define(void *first_unused_memory)
#endif
{
UINT    status;
ULONG   header_size = (sizeof(NX_PACKET) + NX_PACKET_ALIGNMENT - 1)/NX_PACKET_ALIGNMENT*NX_PACKET_ALIGNMENT;
                         
    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory; 

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();            
       
    /* Create packet pool with valid parameters in NULL thread.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pointer,(TEST_SIZE + header_size) * 3);
         
    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }

    /* Create packet pool with corruptted memory.  */
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", TEST_SIZE, pointer - 1,(TEST_SIZE + header_size) * 3);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {
        error_counter++;
    }

    /* Create packet pool with corruptted memory.  */
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", TEST_SIZE, pointer + 1,(TEST_SIZE + header_size) * 3);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {
        error_counter++;
    }

    /* Create the same packet pool with valid parameters in NULL thread.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pointer,(TEST_SIZE + header_size) * 3);

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {
        error_counter++;
    }

    /* Update the pointer.  */
    pointer = pointer + (TEST_SIZE + header_size) * 3;

    if (NX_PACKET_ALIGNMENT != sizeof(ULONG))
    {

        /* Print out test information banner.  */
        printf("NetX Test:   Packet NXE API Test.......................................N/A\n"); 

        test_control_return(3);  
    }
}             


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT        status;  
ULONG       total_packets, free_packets, empty_pool_requests, empty_pool_suspensions, invalid_packet_releases;
ULONG       packet_length;
ULONG       buffer[200];
ULONG       bytes_copied;
NX_PACKET   *my_packet_1; 
NX_PACKET   *my_packet_2; 
NX_PACKET   invalid_packet; 
NX_PACKET   *invalid_packet_2;
ULONG       header_size = (sizeof(NX_PACKET) + NX_PACKET_ALIGNMENT - 1)/NX_PACKET_ALIGNMENT*NX_PACKET_ALIGNMENT;
    
    /* Print out test information banner.  */
    printf("NetX Test:   Packet NXE API Test.......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
               
    /************************************************/   
    /* Tested the nxe_packet_pool_create api        */
    /************************************************/

#ifndef NX_DISABLE_ERROR_CHECKING
    /* Create packet pool with invalid pool size.  */
    status =  _nxe_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pointer, (TEST_SIZE + header_size) * 3, 0);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
#endif /* NX_DISABLE_ERROR_CHECKING */

    /* Create packet pool with null pool.  */
    status =  nx_packet_pool_create(NX_NULL, "NetX Main Packet Pool", TEST_SIZE, pointer, (TEST_SIZE + header_size) * 3);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Create packet pool with null pointer.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, NX_NULL, (TEST_SIZE + header_size) * 3);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Create packet pool with invalid payload size.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 0, pointer, (TEST_SIZE + header_size) * 3);
         
    /* Check for error.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
        
    /* Create packet pool with invalid pool size.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pointer, 0);
         
    /* Check for error.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Create the same packet pool with valid parameters.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pointer,(TEST_SIZE + header_size) * 3);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /************************************************/   
    /* Tested the nxe_packet_pool_delete api        */
    /************************************************/   
             
    /* Delete packet pool with null pool.  */
    status =  nx_packet_pool_delete(NX_NULL);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
           
    /* Delete packet pool with invalid pool.  */
    status =  nx_packet_pool_delete(&invalid_pool);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
           
    /************************************************/   
    /* Tested the nxe_packet_pool_info_get api      */
    /************************************************/   
             
    /* Get the packet pool info with null pool.  */              
    status =  nx_packet_pool_info_get(NX_NULL, &total_packets, &free_packets, &empty_pool_requests, &empty_pool_suspensions, &invalid_packet_releases);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                  
    /* Get the packet pool info with invalid pool.  */              
    status =  nx_packet_pool_info_get(&invalid_pool, &total_packets, &free_packets, &empty_pool_requests, &empty_pool_suspensions, &invalid_packet_releases);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

#ifdef NX_ENABLE_LOW_WATERMARK
    /************************************************/   
    /* Tested the nxe_packet_pool_low_watermark api */
    /************************************************/   
             
    /* Delete packet pool with null pool.  */
    status =  nx_packet_pool_low_watermark_set(NX_NULL, 5);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
           
    /* Delete packet pool with invalid pool.  */
    status =  nx_packet_pool_low_watermark_set(&invalid_pool, 5);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_ENABLE_LOW_WATERMARK  */

    /************************************************/   
    /* Tested the nxe_packet_allocate api        */
    /************************************************/

    /* Allocate packet with null pool.  */
    status =  nx_packet_allocate(NX_NULL, &my_packet_1, NX_UDP_PACKET, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
               
    /* Allocate packet with invalid pool.  */
    status =  nx_packet_allocate(&invalid_pool, &my_packet_1, NX_UDP_PACKET, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                      
    /* Allocate packet with null packet.  */
    status =  nx_packet_allocate(&pool_0, NX_NULL, NX_UDP_PACKET, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Allocate packet with Four byte unaligned packet type.  */
    status =  nx_packet_allocate(&pool_0, &my_packet_1, 5, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Allocate packet with big packet type.  */
    status =  nx_packet_allocate(&pool_0, &my_packet_1, TEST_SIZE + 4, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
            
    /* Allocate packet with valid parameter.  */
    status =  nx_packet_allocate(&pool_0, &my_packet_1, NX_UDP_PACKET, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                   
    /************************************************/   
    /* Tested the nxe_packet_data_append api        */
    /************************************************/

    /* Append the packet data with null packet.  */
    status =  nx_packet_data_append(NX_NULL, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
           
    /* Append the packet data with null data.  */
    status =  nx_packet_data_append(my_packet_1, NX_NULL, 28, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
           
    /* Append the packet data with null data size.  */
    status =  nx_packet_data_append(my_packet_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 0, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Append the packet data with null pool.  */
    status =  nx_packet_data_append(my_packet_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, NX_NULL, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Append the packet data with invalid pool.  */
    status =  nx_packet_data_append(my_packet_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &invalid_pool, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                 

    /* Append the packet with invalid packet that prepend pointer is less than data start.  */      
    invalid_packet.nx_packet_data_start = (UCHAR *)0x20;
    invalid_packet.nx_packet_prepend_ptr = (UCHAR *)0x10;
    invalid_packet.nx_packet_append_ptr = (UCHAR *)0x30;
    invalid_packet.nx_packet_data_end = (UCHAR *)0x40;  
    status =  nx_packet_data_append(&invalid_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_UNDERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
           
    /* Append packet with invalid packet that prepend pointer is less than data start.  */      
    invalid_packet.nx_packet_data_start = (UCHAR *)0x10;
    invalid_packet.nx_packet_prepend_ptr = (UCHAR *)0x20;
    invalid_packet.nx_packet_append_ptr = (UCHAR *)0x40;
    invalid_packet.nx_packet_data_end = (UCHAR *)0x20;                     
    status =  nx_packet_data_append(&invalid_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_OVERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
              
    /* Append the packet data with valid parameters.  */
    status =  nx_packet_data_append(my_packet_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /************************************************/   
    /* Tested the nxe_packet_copy api               */
    /************************************************/

    /* Copy packet with null original packet.  */
    status =  nx_packet_copy(NX_NULL, &my_packet_2, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
        
    /* Copy packet with null new packet.  */
    status =  nx_packet_copy(my_packet_1, NX_NULL, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Copy packet with null pool.  */
    status =  nx_packet_copy(my_packet_1, &my_packet_2, NX_NULL, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
          
    /* Copy packet with invalid pool.  */
    status =  nx_packet_copy(my_packet_1, &my_packet_2, &invalid_pool, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Copy packet with invalid original packet that prepend pointer is less than data start.  */      
    invalid_packet.nx_packet_data_start = (UCHAR *)0x20;
    invalid_packet.nx_packet_prepend_ptr = (UCHAR *)0x10;
    invalid_packet.nx_packet_append_ptr = (UCHAR *)0x30;
    invalid_packet.nx_packet_data_end = (UCHAR *)0x40;  
    status =  nx_packet_copy(&invalid_packet, &my_packet_2, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_UNDERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
           
    /* Copy packet with invalid original packet that prepend pointer is less than data start.  */      
    invalid_packet.nx_packet_data_start = (UCHAR *)0x10;
    invalid_packet.nx_packet_prepend_ptr = (UCHAR *)0x20;
    invalid_packet.nx_packet_append_ptr = (UCHAR *)0x40;
    invalid_packet.nx_packet_data_end = (UCHAR *)0x20;  
    status =  nx_packet_copy(&invalid_packet, &my_packet_2, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status != NX_OVERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Copy packet with valid parameters.  */      
    status =  nx_packet_copy(my_packet_1, &my_packet_2, &pool_0, NX_IP_PERIODIC_RATE);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          

    /************************************************/   
    /* Tested the nxe_packet_length_get api         */
    /************************************************/

    /* Get packet length with null packet.  */
    status =  nx_packet_length_get(NX_NULL, &packet_length);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              

    /* Get packet length with null length pointer.  */
    status =  nx_packet_length_get(my_packet_1, NX_NULL);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              

    /* Get packet length with invalid packet pool owner.  */
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;
    invalid_packet_2 -> nx_packet_pool_owner = NX_NULL;
    status =  nx_packet_length_get(invalid_packet_2, NX_NULL);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              

    /* Get packet length with invalid packet pool ID.  */
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;
    invalid_packet_2 -> nx_packet_pool_owner = (NX_PACKET_POOL *) &invalid_pool;
    invalid_packet_2 -> nx_packet_pool_owner -> nx_packet_pool_id = 0;
    status =  nx_packet_length_get(invalid_packet_2, NX_NULL);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              
         
    /* Get packet length with valid parameters.  */
    status =  nx_packet_length_get(my_packet_1, &packet_length);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                   

    /************************************************/   
    /* Tested the nxe_packet_data_extract_offset api*/
    /************************************************/

    /* Extract the packet data with null packet.  */
    status =  nx_packet_data_extract_offset(NX_NULL, 0, buffer, 200, &bytes_copied);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              
              
    /* Extract the packet data with invalid buffer.  */
    status =  nx_packet_data_extract_offset(my_packet_1, 0, NX_NULL, 200, &bytes_copied);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              
      
    /* Extract the packet data with null bytes copied parameter.  */
    status =  nx_packet_data_extract_offset(my_packet_1, 0, buffer, 200, NX_NULL);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
           
    /* Extract the packet data with valid parameter.  */
    status =  nx_packet_data_extract_offset(my_packet_1, 0, buffer, 200, &bytes_copied);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
             
    /************************************************/   
    /* Tested the nxe_packet_data_retrieve api      */
    /************************************************/

    /* Retrieve the packet data with null packet.  */
    status =  nx_packet_data_retrieve(NX_NULL, buffer, &bytes_copied);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              
              
    /* Extract the packet data with invalid buffer.  */
    status =  nx_packet_data_retrieve(my_packet_1, NX_NULL, &bytes_copied);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              
      
    /* Extract the packet data with valid parameter.  */
    status =  nx_packet_data_retrieve(my_packet_1, buffer, NX_NULL);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
          
    /* Extract the packet data with valid parameter.  */
    status =  nx_packet_data_retrieve(my_packet_1, buffer, &bytes_copied);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          
             
    /************************************************/   
    /* Tested the nxe_packet_release api            */
    /************************************************/

    /* Release the packet with invalid packet.  */
    invalid_packet_2 = NX_NULL;
    status =  nx_packet_release(invalid_packet_2);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
         
    /* Release the packet with invalid original packet that prepend pointer is less than data start.  */  
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;
    invalid_packet_2 -> nx_packet_pool_owner = (NX_PACKET_POOL *) &invalid_pool;
    invalid_packet_2 -> nx_packet_pool_owner -> nx_packet_pool_id = NX_PACKET_POOL_ID;
    invalid_packet_2 -> nx_packet_data_start = (UCHAR *)0x20;
    invalid_packet_2 -> nx_packet_prepend_ptr = (UCHAR *)0x10;
    invalid_packet_2 -> nx_packet_append_ptr = (UCHAR *)0x30;
    invalid_packet_2 -> nx_packet_data_end = (UCHAR *)0x40;  
    status =  nx_packet_release(invalid_packet_2);
         
    /* Check for error.  */
    if (status != NX_UNDERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
           
    /* Release the packet with invalid original packet that prepend pointer is less than data start.  */ 
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;     
    invalid_packet_2 -> nx_packet_pool_owner = (NX_PACKET_POOL *) &invalid_pool;  
    invalid_packet_2 -> nx_packet_pool_owner -> nx_packet_pool_id = NX_PACKET_POOL_ID;
    invalid_packet_2 -> nx_packet_data_start = (UCHAR *)0x10;
    invalid_packet_2 -> nx_packet_prepend_ptr = (UCHAR *)0x20;
    invalid_packet_2 -> nx_packet_append_ptr = (UCHAR *)0x40;
    invalid_packet_2 -> nx_packet_data_end = (UCHAR *)0x20;                       
    status =  nx_packet_release(invalid_packet_2);
         
    /* Check for error.  */
    if (status != NX_OVERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Release the packet data with valid packet.  */
    status =  nx_packet_release(my_packet_1);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
        
    /************************************************/   
    /* Tested the nxe_packet_transmit_release api   */
    /************************************************/

    /* Release the packet with invalid packet.  */
    invalid_packet_2 = NX_NULL;
    status =  nx_packet_transmit_release(invalid_packet_2);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Release the packet with no packet pool owner.  */
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;
    invalid_packet_2 -> nx_packet_pool_owner = NX_NULL;
    status =  nx_packet_transmit_release(invalid_packet_2);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Release the packet with invalid packet owner.  */
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;
    invalid_packet_2 -> nx_packet_pool_owner = (NX_PACKET_POOL *) &invalid_pool;
    invalid_packet_2 -> nx_packet_pool_owner -> nx_packet_pool_id = 0;
    status =  nx_packet_transmit_release(invalid_packet_2);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Release the packet with invalid packet nx_packet_tcp_queue_next.  */
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;
    invalid_packet_2 -> nx_packet_append_ptr = invalid_packet_2 -> nx_packet_data_end;
    invalid_packet_2 -> nx_packet_pool_owner = (NX_PACKET_POOL *) &pool_0;
#ifdef __PRODUCT_NETXDUO__
    invalid_packet_2 -> nx_packet_union_next.nx_packet_tcp_queue_next = ((NX_PACKET *)NX_PACKET_FREE);
#else
    invalid_packet_2 -> nx_packet_tcp_queue_next = ((NX_PACKET *)NX_PACKET_FREE);
#endif
    status =  nx_packet_transmit_release(invalid_packet_2);
         
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
         
    /* Release the packet with invalid original packet that prepend pointer is less than data start.  */  
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;
    invalid_packet_2 -> nx_packet_pool_owner = (NX_PACKET_POOL *) &invalid_pool;
    invalid_packet_2 -> nx_packet_pool_owner -> nx_packet_pool_id = NX_PACKET_POOL_ID;
    invalid_packet_2 -> nx_packet_data_start = (UCHAR *)0x20;
    invalid_packet_2 -> nx_packet_prepend_ptr = (UCHAR *)0x10;
    invalid_packet_2 -> nx_packet_append_ptr = (UCHAR *)0x30;
    invalid_packet_2 -> nx_packet_data_end = (UCHAR *)0x40;  
    status =  nx_packet_transmit_release(invalid_packet_2);
         
    /* Check for error.  */
    if (status != NX_UNDERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
           
    /* Release the packet with invalid original packet that prepend pointer is less than data start.  */ 
    invalid_packet_2 = (NX_PACKET *) &invalid_packet;     
    invalid_packet_2 -> nx_packet_pool_owner = (NX_PACKET_POOL *) &invalid_pool;  
    invalid_packet_2 -> nx_packet_pool_owner -> nx_packet_pool_id = NX_PACKET_POOL_ID;
    invalid_packet_2 -> nx_packet_data_start = (UCHAR *)0x10;
    invalid_packet_2 -> nx_packet_prepend_ptr = (UCHAR *)0x20;
    invalid_packet_2 -> nx_packet_append_ptr = (UCHAR *)0x40;
    invalid_packet_2 -> nx_packet_data_end = (UCHAR *)0x20;                       
    status =  nx_packet_transmit_release(invalid_packet_2);
         
    /* Check for error.  */
    if (status != NX_OVERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Release the packet data with valid packet.  */
    status =  nx_packet_transmit_release(my_packet_2);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                        
                                     
    /* Delete packet pool with valid pool.  */
    status =  nx_packet_pool_delete(&pool_0);
         
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    printf("SUCCESS!\n");
    test_control_return(0);
}      

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_packet_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Packet NXE API Test.......................................N/A\n"); 

    test_control_return(3);  
}      
#endif

