/* This NetX test concentrates on the IP Address Change Notify operation.  */

#include   "tx_api.h"
#include   "nx_api.h" 

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0; 

/* Define the counters used in the test application...  */

static ULONG                   error_counter;   
static ULONG                   ip_0_address_change_counter; 

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);  
static void    ip_0_address_change_notify(NX_IP *ip_ptr, VOID *additional_info); 


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_address_change_notify_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    /* Initialize the value.  */
    error_counter = 0;
    ip_0_address_change_counter = 0;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;

    /* Print out test information banner.  */
    printf("NetX Test:   IP Address Change Notify Test.............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             

    /* Register IP address change callback. */
    status = nx_ip_address_change_notify(&ip_0, ip_0_address_change_notify, NX_NULL);

    /* Check for error */
    if (status)
    {
                     
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the address change counter.  */
    if (ip_0_address_change_counter != 0)  
    {
                     
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test nx_ip_address_set function.  */

    /* Set the same address and network mask again.  */
    status = nx_ip_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00);
    
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
         
    /* Check the address change counter.  */
    if (ip_0_address_change_counter != 0)  
    {
                     
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the different address and same network mask again.  */
    status = nx_ip_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00);
    
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
         
    /* Check the address change counter.  */
    if (ip_0_address_change_counter != 1)  
    {
                     
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the same address and different network mask again.  */
    status = nx_ip_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0xFFFF0000);
    
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                  
    /* Check the address change counter.  */
    if (ip_0_address_change_counter != 2)  
    {
                     
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test nx_ip_interface_address_set function.  */

    /* Set the different address and same network mask again.  */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 2, 3, 6), 0xFFFF0000);
    
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
         
    /* Check the address change counter.  */
    if (ip_0_address_change_counter != 3)  
    {
                     
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the same address and different network mask again.  */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 2, 3, 6), 0xFF000000);
    
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the address change counter.  */
    if (ip_0_address_change_counter != 4)  
    {
                     
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);

}         
static VOID ip_0_address_change_notify(NX_IP *ip_ptr, VOID *additional_info)
{    

    /* Update the address change counter.  */
    ip_0_address_change_counter++;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_address_change_notify_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Address Change Notify Test.............................N/A\n"); 

    test_control_return(3);  
}      
#endif      