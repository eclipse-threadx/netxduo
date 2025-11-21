/* This NetX test concentrates on the basic BSD UDP non-blocking operation.  */
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
void    netx_bsd_pton_test_application_define(void *first_unused_memory)
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

UINT      status;


CHAR *ipv6_addr_str1 = "fe80::74ac:2217:530:5d7f";
ULONG ipv6_addr_num1[] = {htonl(0xfe800000), htonl(0), htonl(0x74ac2217), htonl(0x05305d7f)};

CHAR *ipv6_addr_str2 = "fe80::74ac:0:530:5d7f";
ULONG ipv6_addr_num2[] = {htonl(0xfe800000), htonl(0), htonl(0x74ac0000), htonl(0x05305d7f)};

CHAR *ipv6_addr_str3 = "::ffff:1.2.3.4";
ULONG ipv6_addr_num3[] = {htonl(0), htonl(0), htonl(0xffff), htonl(0x01020304)};

CHAR *ipv6_addr_str4 = "::1.2.3.4";
ULONG ipv6_addr_num4[] = {htonl(0), htonl(0), htonl(0), htonl(0x01020304)};

CHAR *ipv6_addr_str5 = "fe80::74gc:0:p30:5d7f";

CHAR *ipv6_addr_str6 = "2001:0000:0000:0003:0000:0000:0000:0053";
CHAR *ipv6_addr_str6_1 = "2001:0:0:3::0053";
ULONG ipv6_addr_num6[] = {htonl(0x20010000), htonl(3), htonl(0), htonl(0x53)};

CHAR *ipv4_addr_str1 = "1.2.3.4";
ULONG ipv4_addr_num1[] = {htonl(0x01020304)};

CHAR *ipv4_addr_str2 = "1.2.3.g";

CHAR *ipv4_addr_str3 = "11.10.2570"; /* 2570 == 0x0a0a */
ULONG ipv4_addr_num3[] = {htonl(0x0b0a0a0a)};

UCHAR ipv6_addr[16]; /* 16*8 == 128 */
UCHAR ipv4_addr[4]; /* 4*8 == 32 */


    printf("NetX Test:   Basic BSD pton Test...........................");

    status = inet_pton(AF_INET6, ipv6_addr_str1, ipv6_addr);
    if((status != 1) || (memcmp(ipv6_addr, ipv6_addr_num1, 16) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET6, ipv6_addr_str2, ipv6_addr);
    if((status != 1) || (memcmp(ipv6_addr, ipv6_addr_num2, 16) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET6, ipv6_addr_str3, ipv6_addr);
    if((status != 1) || (memcmp(ipv6_addr, ipv6_addr_num3, 16) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET6, ipv6_addr_str4, ipv6_addr);
    if((status != 1) || (memcmp(ipv6_addr, ipv6_addr_num4, 16) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET6, ipv6_addr_str5, ipv6_addr);
    if(status != 0)
        error_counter++;

    status = inet_pton(AF_INET6, ipv6_addr_str6, ipv6_addr);
    if((status != 1) || (memcmp(ipv6_addr, ipv6_addr_num6, 16) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET6, ipv6_addr_str6_1, ipv6_addr);
    if((status != 1) || (memcmp(ipv6_addr, ipv6_addr_num6, 16) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET,  ipv4_addr_str1, ipv4_addr);
    if((status != 1) || (memcmp(ipv4_addr, ipv4_addr_num1, 4) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET,  ipv4_addr_str2, ipv4_addr);
    if(status != 0)
        error_counter++;

    status = inet_pton(AF_INET,  ipv4_addr_str3, ipv4_addr);
    if((status != 1) || (memcmp(ipv4_addr, ipv4_addr_num3, 4) != 0 ))
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
void    netx_bsd_pton_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Basic BSD pton Test...........................N/A\n");
    test_control_return(3);
}

#endif
