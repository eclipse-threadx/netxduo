/* This NetX test concentrates on the basic BSD UDP non-blocking operation.  */
#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
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
void    netx_bsd_aton_test_application_define(void *first_unused_memory)
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

struct in_addr in_val;
int    status;

    printf("NetX Test:   Basic BSD aton Test...........................");

    status = inet_aton("11.10.10.10", &in_val);
    if((status !=  1) || (in_val.s_addr != htonl(0x0b0a0a0a)))
        error_counter++;

    status = inet_aton("11.10.2570", &in_val); /* 2570 == 0x0a0a */
    if((status !=  1) || (in_val.s_addr != htonl(0x0b0a0a0a)))
        error_counter++;
    
    status = inet_aton("11.657930", &in_val); /* 657930 == 0x0a0a0a */
    if((status !=  1) || (in_val.s_addr != htonl(0x0b0a0a0a)))
        error_counter++;

    /* octal */
    status = inet_aton("013.012.012.012", &in_val);
    if((status !=  1) || (in_val.s_addr != htonl(0x0b0a0a0a)))
        error_counter++;

    /* hex */
    status = inet_aton("0xb.0xa.0xa.0xa", &in_val);
    if((status !=  1) || (in_val.s_addr != htonl(0x0b0a0a0a)))
        error_counter++;

    /* decimal, octal and hex */
    status = inet_aton("11.012.0xa.10", &in_val);
    if((status !=  1) || (in_val.s_addr != htonl(0x0b0a0a0a)))
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
extern void       test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_aton_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD aton Test...........................N/A\n"); 

    test_control_return(3);  
}      
#endif
