/* This test case validates nxd_ipv6_address_delete. */

#include    "tx_api.h"
#include    "nx_api.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6)
#include    "nx_ipv6.h"
                                  
#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;     

                                          
/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_util_api_test_application_define(void *first_unused_memory)
#endif
{
    CHAR       *pointer;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();           
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT       status;
ULONG      ipv6_address_1[4];   
ULONG      ipv6_address_2[4];

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Util API Test........................................");         
                     
    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x10000000;
    ipv6_address_1[3] = 0x00000011;    

    /* Set address 2. */
    ipv6_address_2[0] = 0x20010000;
    ipv6_address_2[1] = 0x00000000;
    ipv6_address_2[2] = 0x20000000;
    ipv6_address_2[3] = 0x00000022;
                      
    /* Check the address by prefixe length.  */
    status = CHECK_IP_ADDRESSES_BY_PREFIX(ipv6_address_1, ipv6_address_2, 48);
    
    /* Check the status.  */
    if (status != 1)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Check the address by prefixe length.  */
    status = CHECK_IP_ADDRESSES_BY_PREFIX(ipv6_address_1, ipv6_address_2, 64);
    
    /* Check the status.  */
    if (status != 1)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }  
           
    /* Check the address by prefixe length.  */
    status = CHECK_IP_ADDRESSES_BY_PREFIX(ipv6_address_1, ipv6_address_2, 96);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }  
                 
    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000011;    

    /* Set address 2. */
    ipv6_address_2[0] = 0x20010000;
    ipv6_address_2[1] = 0x00000000;
    ipv6_address_2[2] = 0x00000000;
    ipv6_address_2[3] = 0x00000022;

    /* Check the address by prefixe length.  */
    status = CHECK_IP_ADDRESSES_BY_PREFIX(ipv6_address_1, ipv6_address_2, 127);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000011;    

    /* Set address 2. */
    ipv6_address_2[0] = 0x20010000;
    ipv6_address_2[1] = 0x00000000;
    ipv6_address_2[2] = 0x00000000;
    ipv6_address_2[3] = 0x00000022;

    /* Check the address by prefixe length.  */
    status = CHECK_IP_ADDRESSES_BY_PREFIX(ipv6_address_1, ipv6_address_2, 16);
    
    /* Check the status.  */
    if (status != 1)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000003; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000003; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000003; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x20010000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000003; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 1)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000003; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000003; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000003; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000003; 

    /* Check the address by prefixe length.  */
    status = CHECK_UNSPECIFIED_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000; 
                                                
    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000002; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 1)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000002; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000002; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000002; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000002; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000002; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000002; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000002; 

    /* Check if the address is router multicast address.  */
    status = CHECK_ALL_ROUTER_MCAST_ADDRESS(ipv6_address_1);
    
    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00010000;

    /* Set address 2. */
    ipv6_address_2[0] = 0x20010000;
    ipv6_address_2[1] = 0x00000000;
    ipv6_address_2[2] = 0x00000000;
    ipv6_address_2[3] = 0x00000022;

    /* Check if the address is node multicast address.  */
    status = CHECK_IPV6_SOLICITED_NODE_MCAST_ADDRESS(ipv6_address_1, ipv6_address_2);

    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00010003;

    /* Set address 2. */
    ipv6_address_2[0] = 0x20010000;
    ipv6_address_2[1] = 0x00000000;
    ipv6_address_2[2] = 0x00000000;
    ipv6_address_2[3] = 0x00000022;

    /* Check if the address is node multicast address.  */
    status = CHECK_IPV6_SOLICITED_NODE_MCAST_ADDRESS(ipv6_address_1, ipv6_address_2);

    /* Check the status.  */
    if (status == 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00010003;

    /* Set address 2. */
    ipv6_address_2[0] = 0x20010000;
    ipv6_address_2[1] = 0x00000000;
    ipv6_address_2[2] = 0x00000000;
    ipv6_address_2[3] = 0x00000022;

    /* Check if the address is node multicast address.  */
    status = CHECK_IPV6_SOLICITED_NODE_MCAST_ADDRESS(ipv6_address_1, ipv6_address_2);

    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00010003;

    /* Set address 2. */
    ipv6_address_2[0] = 0x20010000;
    ipv6_address_2[1] = 0x00000000;
    ipv6_address_2[2] = 0x00000000;
    ipv6_address_2[3] = 0x00000022;

    /* Check if the address is node multicast address.  */
    status = CHECK_IPV6_SOLICITED_NODE_MCAST_ADDRESS(ipv6_address_1, ipv6_address_2);

    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x20010004;

    /* Set address 2. */
    ipv6_address_2[0] = 0x20010000;
    ipv6_address_2[1] = 0x00000000;
    ipv6_address_2[2] = 0x00000000;
    ipv6_address_2[3] = 0x00000022;

    /* Check if the address is node multicast address.  */
    status = CHECK_IPV6_SOLICITED_NODE_MCAST_ADDRESS(ipv6_address_1, ipv6_address_2);

    /* Check the status.  */
    if (status != 0)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
               
    /* Set address 1. */
    ipv6_address_1[0] = 0xFF030000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000004;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
               
    /* Set address 1. */
    ipv6_address_1[0] = 0xFF010000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000004;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)     
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
      
    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00010003;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != (IPV6_ADDRESS_MULTICAST | IPV6_ALL_NODE_MCAST))
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00010003;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00010003;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF050000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00010003;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /* Set address 1. */
    ipv6_address_1[0] = 0xFF000001;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF000001;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF000001;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
      
    /* Set address 1. */
    ipv6_address_1[0] = 0xFF000001;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00010003;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF000001;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Set address 1. */
    ipv6_address_1[0] = 0xFF000001;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00010003;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF000001;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00010003;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF000001;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000002;
    ipv6_address_1[3] = 0x00010003;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0x00000000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000000;
    ipv6_address_1[3] = 0x00000003;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != (IPV6_ADDRESS_UNICAST | IPV6_ADDRESS_GLOBAL))
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000001;
    ipv6_address_1[2] = 0x00000001;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000001;
    ipv6_address_1[3] = 0x00000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != IPV6_ADDRESS_MULTICAST)
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }
 
    /* Set address 1. */
    ipv6_address_1[0] = 0xFF020000;
    ipv6_address_1[1] = 0x00000000;
    ipv6_address_1[2] = 0x00000001;
    ipv6_address_1[3] = 0xFF000000;

    /* Check the address type.  */
    status = IPv6_Address_Type(ipv6_address_1);

    /* Check the status.  */
    if (status != (IPV6_ADDRESS_MULTICAST | IPV6_SOLICITED_NODE_MCAST))
    {                 
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Change the IPv6 address with NULL pointer.  */
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(NX_NULL);

    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);     
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_util_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Util API Test........................................N/A\n");

    test_control_return(3);

}
#endif
