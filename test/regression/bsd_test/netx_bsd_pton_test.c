/***************************************************************************/
/* Copyright (c) 2024 Microsoft Corporation                                */
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

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

/* inet_pton() applies strict POSIX parsing: only the four part a.b.c.d form is
   accepted, every part is decimal, in the range 0 to 255, written without a
   leading zero, and no other character may appear anywhere in the string.
   Each of these must be rejected, even though inet_aton() accepts some of them. */
CHAR *ipv4_bad_str[] = {
                        "0xb.0xa.0xa.0xa",  /* hexadecimal notation             */
                        "0Xb.0xa.0xa.0xa",  /* hexadecimal notation, upper case */
                        "013.012.012.012",  /* octal notation                   */
                        "127.0.0.010",      /* octal notation, last part        */
                        "010.1.1.1",        /* leading zero, first part         */
                        "00.0.0.0",         /* leading zero on a zero part      */
                        "0.00.0.0",         /* leading zero on a zero part      */
                        "1.2.3.04",         /* leading zero, last part          */
                        "1.2.3.0004",       /* leading zeros, last part         */
                        "11.657930",        /* a.b form                         */
                        "184549386",        /* a form                           */
                        "1.2.3.4 ",         /* trailing space                   */
                        "1.2.3.4\t",        /* trailing tab                     */
                        "1.2.3.4\n",        /* trailing newline                 */
                        " 1.2.3.4",         /* leading space                    */
                        "1.2.3.4.",         /* trailing separator               */
                        "1.2.3.",           /* trailing separator, a.b.c form   */
                        ".1.2.3",           /* leading separator                */
                        "1.2.3.4.5",        /* five parts                       */
                        "1.2.3.256",        /* part out of range                */
                        "256.1.1.1",        /* part out of range                */
                        "4294967296.1.2.3", /* part overflowing 32 bits         */
                        "1.2.3.4x",         /* trailing garbage                 */
                        "1.2.3.-4",         /* signed part                      */
                        "1..2.3",           /* empty part                       */
                        "",                 /* empty string                     */
                        "."                 /* separator only                   */
                       };
/* An IPv4-mapped or an IPv4-compatible IPv6 address ends in a dotted-decimal
   tail, and that tail is handed to the same strict parser.  ipv6_addr_str3 and
   ipv6_addr_str4 above cover the two forms; these cover the boundary values, a
   tail behind a prefix, and everything the strict parser has to turn down. */
CHAR *ipv6_mapped_str1 = "::ffff:0.0.0.0";
ULONG ipv6_mapped_num1[] = {htonl(0), htonl(0), htonl(0xffff), htonl(0)};

CHAR *ipv6_mapped_str2 = "::ffff:255.255.255.255";
ULONG ipv6_mapped_num2[] = {htonl(0), htonl(0), htonl(0xffff), htonl(0xffffffff)};

CHAR *ipv6_mapped_str3 = "2001:db8::ffff:1.2.3.4";
ULONG ipv6_mapped_num3[] = {htonl(0x20010db8), htonl(0), htonl(0xffff), htonl(0x01020304)};

CHAR *ipv6_mapped_bad_str[] = {
                        "::ffff:010.1.1.1",         /* leading zero, first part      */
                        "::ffff:1.2.3.04",          /* leading zero, last part       */
                        "::ffff:00.0.0.0",          /* leading zero on a zero part   */
                        "::ffff:013.012.012.012",   /* octal notation                */
                        "::ffff:0xb.0xa.0xa.0xa",   /* hexadecimal notation          */
                        "::ffff:1.2.3.256",         /* part out of range             */
                        "::ffff:256.1.1.1",         /* part out of range, first part */
                        "::ffff:11.657930",         /* a.b form                      */
                        "::ffff:1.2.3",             /* three parts                   */
                        "::ffff:1.2.3.4.5",         /* five parts                    */
                        "::ffff:1.2.3.",            /* trailing separator            */
                        "::ffff:1..2.3",            /* empty part                    */
                        "::ffff:1.2.3.-4",          /* signed part                   */
                        "::ffff:1.2.3.4x",          /* trailing garbage              */
                        "::ffff:1.2.3.4 ",          /* trailing space                */
                        "::ffff:1.2.3.4\t",         /* trailing tab                  */
                        "::1.2.3.256",              /* compatible form, out of range */
                        "::1.2.3",                  /* compatible form, three parts  */
                        "2001:db8::ffff:1.2.3.400"  /* out of range behind a prefix  */
                       };
UINT  i;

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
    if(status != 0)
        error_counter++;

    /* Walk the presentations inet_pton() has to reject. */
    for(i = 0; i < (sizeof(ipv4_bad_str) / sizeof(ipv4_bad_str[0])); i++)
    {

        status = inet_pton(AF_INET, ipv4_bad_str[i], ipv4_addr);
        if(status != 0)
            error_counter++;
    }

    /* The boundary values must still be accepted. */
    status = inet_pton(AF_INET, "0.0.0.0", ipv4_addr);
    if((status != 1) || (*(ULONG *)ipv4_addr != htonl(0x00000000)))
        error_counter++;

    status = inet_pton(AF_INET, "255.255.255.255", ipv4_addr);
    if((status != 1) || (*(ULONG *)ipv4_addr != htonl(0xffffffff)))
        error_counter++;

    status = inet_pton(AF_INET, "11.10.10.10", ipv4_addr);
    if((status != 1) || (*(ULONG *)ipv4_addr != htonl(0x0b0a0a0a)))
        error_counter++;

    /* The dotted-decimal tail of an IPv4-mapped or IPv4-compatible address:
       boundary values and a tail behind a prefix are accepted. */
    status = inet_pton(AF_INET6, ipv6_mapped_str1, ipv6_addr);
    if((status != 1) || (memcmp(ipv6_addr, ipv6_mapped_num1, 16) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET6, ipv6_mapped_str2, ipv6_addr);
    if((status != 1) || (memcmp(ipv6_addr, ipv6_mapped_num2, 16) != 0 ))
        error_counter++;

    status = inet_pton(AF_INET6, ipv6_mapped_str3, ipv6_addr);
    if((status != 1) || (memcmp(ipv6_addr, ipv6_mapped_num3, 16) != 0 ))
        error_counter++;

    /* A tail the strict parser turns down invalidates the whole address, even
       though inet_aton() accepts some of these forms. */
    for(i = 0; i < (sizeof(ipv6_mapped_bad_str) / sizeof(ipv6_mapped_bad_str[0])); i++)
    {

        status = inet_pton(AF_INET6, ipv6_mapped_bad_str[i], ipv6_addr);
        if(status != 0)
            error_counter++;
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
