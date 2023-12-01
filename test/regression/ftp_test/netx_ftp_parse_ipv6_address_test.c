
#include    "tx_api.h"
#include    "fx_api.h" 
#include    "nx_api.h"
#include    "nxd_ftp_server.h"

extern void     test_control_return(UINT);

#if defined(FEATURE_NX_IPV6)

#define     DEMO_STACK_SIZE         4096

/* Define the counters used in the demo application...  */
static ULONG                   error_counter = 0;

static TX_THREAD test_thread;
static void      thread_test_entry(ULONG thread_input);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_parse_ipv6_address_test_application_define(void *first_unused_memory)
#endif
{

UCHAR   *pointer;

    /* Setup the working pointer.  */
    pointer =  (UCHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&test_thread, "FTP test thread", thread_test_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;
}

/* Define the helper FTP server thread.  */
void    thread_test_entry(ULONG thread_input)
{
UINT i;
UINT status;
UCHAR *buffer_ptr;
UCHAR valid_buffer[100];


    /* Print out test information banner.  */
    printf("NetX Test:   FTP Parse IPv6 Address Test...............................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    memset(valid_buffer, 0xFF, sizeof(valid_buffer));

    /* Invalid colons 1.  */
    buffer_ptr = "1:2:3:4:5:6:7:8:9:10";
    status = _nx_ftp_utility_parse_IPv6_address(buffer_ptr, 21, (NXD_ADDRESS *)(&valid_buffer));
    if (status != NX_FTP_INVALID_ADDRESS)
        error_counter++;

    /* Invalid conlons 2.  */
    buffer_ptr = "1:2:3:4:5:6::8:9:10";
    status = _nx_ftp_utility_parse_IPv6_address(buffer_ptr, 20, (NXD_ADDRESS *)(&valid_buffer));
    if (status != NX_FTP_INVALID_ADDRESS)
        error_counter++;

    /* Invalid conlons 3.  */
    buffer_ptr = "1:2:3::4:5:6:7:8";
    status = _nx_ftp_utility_parse_IPv6_address(buffer_ptr, 17, (NXD_ADDRESS *)(&valid_buffer));
    if (status != NX_FTP_INVALID_ADDRESS)
        error_counter++;

    /* Check write overflow. */
    for (i = sizeof(NXD_ADDRESS); i < sizeof(valid_buffer); i++)
    {
        if (valid_buffer[i] != 0xFF)
        {
            error_counter++;
            break;
        }
    }

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

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_parse_ipv6_address_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   FTP Parse IPv6 Address Test...............................N/A\n"); 

    test_control_return(3);  
}      
#endif