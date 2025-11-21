/* This NetX test concentrates on inet_ntoa function.  */
#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"

#define     DEMO_STACK_SIZE         4096

static TX_THREAD  ntest_0;
static void       ntest_0_entry(ULONG thread_input);
extern void       test_control_return(UINT status);
extern void       _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define the ThreadX and NetX object control blocks...  */
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

static ULONG      error_counter;

/* Define the ThreadX and NetX object control blocks...  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_ntoa_test_application_define(void *first_unused_memory)
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
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 1024);
    pointer =  pointer + 1024;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, DEMO_STACK_SIZE, 1);
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status)
        error_counter++;

    status = bsd_initialize(&ip_0, &pool_0, pointer, DEMO_STACK_SIZE, 2);
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status)
        error_counter++;
}

static void ntest_0_entry(ULONG thread_input)
{

struct in_addr in_val;
INT    status;
ULONG  addr;
CHAR  *addr_str;
CHAR  *ret;

    printf("NetX Test:   Basic BSD ntoa Test...........................");

    addr_str = "11.10.10.10";
    addr = htonl(0x0b0a0a0a);
    status = inet_aton(addr_str, &in_val);
    if ((status !=  1) || (in_val.s_addr != addr))
        error_counter++;

    ret = inet_ntoa(in_val);

    if (ret == NX_NULL)
        error_counter++;
    else if (strcmp(ret, addr_str))
        error_counter++;

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
extern void       test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_ntoa_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD ntoa Test...........................N/A\n"); 

    test_control_return(3);  
}      
#endif
