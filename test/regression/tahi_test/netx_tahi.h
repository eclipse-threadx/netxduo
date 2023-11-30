#ifndef _NETX_TAHI_H_
#define _NETX_TAHI_H_


#include "tx_api.h"
#include "nx_api.h"
#ifdef __PRODUCT_NETXDUO__
#include "nxd_dhcpv6_client.h"
#endif
#endif

#define TITLE           1   /* This entry contains the name of the test. */
#define INJECT          2   /* This entry contains packet that needs to be injected into the system.*/
#define CHECK           3   /* This entry contains packet that needs to be matched. */
#define WAIT            4   /* This entry is to place a wait. */
#define DUMP            5   /* This entry flushes the incoming packet queue. */
#define CLEANUP         6   /* This is a marker, indicating the beginning sequeuence of cleanup procedure. */

#define N_CHECK         7   /* This entry contains packet that do not want to be received.  */

#ifdef NX_IPSEC_ENABLE
#define D_CHECK         8   /* This entry contains packet that needs to be matched after decryption. */
#define ASSEMBLE        9   /* This entry contains packet that needs to be assembled. */
#define AD_CHECK        10  /* This entry contains packet that needs to be assembled and be matched after decryption. */
#define TD_CHECK        11  /* This entry contains packet that needs to be matched after decryption which is tunneled. */
#endif

#define DHCPV6_CONFIRM          12 
#define DHCPV6_RELEASE          13
#define DHCPV6_REBOOT           14
#define DHCPV6_INFO_REQUEST   15
#define DHCPV6_DNS              16

#define CLEAN_HOP_LIMIT 20 /* This is a marker, indicating the hop limit should be initial to 0xff.  */
#define NS_UNSPEC       21 /* This is a marker, indicating the NS is being check.  */
#define CHECK_V6REQUEST 22 /* This is a marker, indicating the ping6_request has been send.  */
#define REBOOT          23 /* This is a marker, indicating the reboot process.  */


#define NS          31  /* NS packet.  */
#define NA          32  /* NA packet.  */
#define RS          33  /* RS packet.  */
#define ER          34  /* ECHO REPLY packet.  */
#define RELEASE     35  /* DHCPV6 RELEASE packet.  */
#define DECLINE     36  /* DHCPV6 DECLINE packet.  */
#define REQUEST     37  /* DHCPV6 DECLINE packet.  */
#define ANY         38  /* ANY packet.  */



/* Define the protocol value for pmtu.p2 or icmp.p2 ping6 process.  */
#define PMTU        0
#define ICMP        1

typedef struct TAHI_TEST_SEQ_struct
{
    /* The command.  Only INJECT and CHECK carries valid pkt_data and pkt_size. */
    int   command;

    /* Only INJECT and CHECK carries valid pkt_data and pkt_size. */
    /* For TITLE, pkt_data carries a const string, which is used as the name of the test case. */
    char *pkt_data;
    int   pkt_size;

    /* Used for CHECK and WAIT. */
    /* WAIT command: wait this amount of time. */
    /* CHECK command: during the timeout period, check any incoming packets against the pkt_data in this entry. */
    int   timeout;

    /*Used in D_CHECK to lookup the sa */
    /*  Next layer protocol*/
    UCHAR protocol;

    /* Used when the next layer protocol is UDP*/
    ULONG src_port;
    ULONG dst_port;

    /*Used when the next layer protocol is ICMP or ICMPv6*/
    UINT  option;
} TAHI_TEST_SEQ;

typedef struct TAHI_TEST_SUITE_struct
{
    TAHI_TEST_SEQ *test_case;
    int            test_case_size;
} TAHI_TEST_SUITE;


void netx_tahi_run_test_case(NX_IP *ip_0, TAHI_TEST_SEQ *test_case, int test_case_size);
#ifdef __PRODUCT_NETXDUO__
void netx_tahi_set_dhcpv6(NX_DHCPV6 *dhcpv6_client_ptr);
#endif
void netx_tahi_set_dhcpv6_reboot(void (*dhcpv6_reboot)());
void netx_tahi_set_dhcpv6_info_request(void (*dhcpv6_info_request)());
void netx_tahi_set_dhcpv6_dns(void (*dhcpv6_dns)());
