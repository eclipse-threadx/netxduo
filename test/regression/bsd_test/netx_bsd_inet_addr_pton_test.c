/* This NetX test concentrates on the basic BSD utility function, inet_addr and inet_pton which
   both call inet_aton for converting addresses into a in_addr numeric format.  */

#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"


#define     DEMO_STACK_SIZE         4096

static TX_THREAD  ntest_0;
static void       ntest_0_entry(ULONG thread_input);
extern void       test_control_return(UINT status);

static ULONG      error_counter;


/* Define the ThreadX and NetX object control blocks...  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_inet_addr_pton_test_application_define(void *first_unused_memory)      
#endif
{
CHAR    *pointer;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


}

static void ntest_0_entry(ULONG thread_input)
{

struct  in_addr in_val;
UCHAR   ipv4_addr_num1[4] = {0x1, 0x2, 0x3, 0x4};

CHAR    *ipv4_addr_str1 = "1.2.3.4";
CHAR    *ipv4_addr_str2 = "1.2.3.g";
UCHAR   ipv4_addr[4]; 
UINT    status;


    printf("NetX Test:   Basic BSD inet_addr inet_pton Test............");

    in_val.s_addr = inet_addr("10.10.10.10");

    if((in_val.s_addr ==  0xFFFFFFFF) || (in_val.s_addr != 0x0a0a0a0a))
        error_counter++;

    in_val.s_addr = inet_addr("10.10.2570"); /* 2570 == 0x0a0a */
    if((in_val.s_addr ==  0xFFFFFFFF) || (in_val.s_addr != 0x0a0a0a0a))
        error_counter++;
    
    in_val.s_addr = inet_addr("10.657930"); /* 657930 == 0x0a0a0a */
    if((in_val.s_addr ==  0xFFFFFFFF) || (in_val.s_addr != 0x0a0a0a0a))
        error_counter++;

    /* octal */
    in_val.s_addr = inet_addr("012.012.012.012");
    if((in_val.s_addr ==  0xFFFFFFFF) || (in_val.s_addr != 0x0a0a0a0a))
        error_counter++;

    /* hex */
    in_val.s_addr = inet_addr("0xa.0xa.0xa.0xa");
    if((in_val.s_addr ==  0xFFFFFFFF) || (in_val.s_addr != 0x0a0a0a0a))
        error_counter++;

    /* decimal, octal and hex */
    in_val.s_addr = inet_addr("10.012.0xa.10");
    if((in_val.s_addr ==  0xFFFFFFFF) || (in_val.s_addr != 0x0a0a0a0a))
        error_counter++;

        /* Invalid IP address. */
    in_val.s_addr = inet_addr("10.10.10,10.10");
    if(in_val.s_addr != 0xFFFFFFFF)
        error_counter++;

    /* Invalid IP address char */
    in_val.s_addr = inet_addr("10.10.1h");
    if(in_val.s_addr != 0xFFFFFFFF)
        error_counter++;

    /* Invalid first character. */
    in_val.s_addr = inet_addr("a0.10.1h");
    if(in_val.s_addr != 0xFFFFFFFF)
        error_counter++;

    status = inet_pton(AF_INET,  ipv4_addr_str1, ipv4_addr);
    if((status != 1) && (memcmp(ipv4_addr, ipv4_addr_num1, 4) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET,  ipv4_addr_str2, ipv4_addr);
    if(status != 0)
        error_counter++;

    if(error_counter)
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

extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_inet_addr_pton_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   Basic BSD inet_addr inet_pton Test............N/A\n");
    test_control_return(3);
}

#endif
