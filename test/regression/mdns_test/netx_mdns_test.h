#ifndef _NETX_MDNS_TEST_H_
#define _NETX_MDNS_TEST_H_


#include "tx_api.h"
#include "nx_api.h"

#ifdef __PRODUCT_NETXDUO__
#include "nxd_mdns.h"

#ifndef NX_MDNS_RR_SET_UNIQUE
#define NX_MDNS_RR_SET_UNIQUE               0
#endif

/* Define the test command.  */
/* basic command.  */
#define TITLE                               1   /* This entry contains the name of the test. */
#define INJECT                              2   /* This entry contains packet that needs to be injected into the system.*/
#define CHECK                               3   /* This entry contains packet that needs to be matched. */
#define WAIT                                4   /* This entry is to place a wait. */
#define DUMP                                5   /* This entry flushes the incoming packet queue. */
#define CLEANUP                             6   /* This is a marker, indicating the beginning sequeuence of cleanup procedure. */
#define N_CHECK                             7  /* This entry contains packet that do not want to be received.  */

#ifdef NX_IPSEC_ENABLE
#define D_CHECK                             8   /* This entry contains packet that needs to be matched after decryption. */
#define ASSEMBLE                            9   /* This entry contains packet that needs to be assembled. */
#define AD_CHECK                            10   /* This entry contains packet that needs to be assembled and be matched after decryption. */
#define TD_CHECK                            11  /* This entry contains packet that needs to be matched after decryption which is tunneled. */
#endif

#define NS                                  12  /* NS packet.  */
#define NA                                  13  /* NA packet.  */
#define RS                                  14  /* RS packet.  */
#define ER                                  15  /* ECHO REPLY packet.  */
#define CLEAN_HOP_LIMIT                     16 /* This is a marker, indicating the hop limit should be initial to 0xff.  */
#define NS_UNSPEC                           17 /* This is a marker, indicating the NS is being check.  */
#define CHECK_V6REQUEST                     18 /* This is a marker, indicating the ping6_request has been send.  */
#define REBOOT                              19 /* This is a marker, indicating the reboot process.  */

/*mDNS command.  */
#define MDNS_CHECK_DATA_V4                  0x50    /* This entry contains packet that needs to be matched by IPv4 UDP data. */
#define MDNS_CHECK_DATA_V6                  0x51    /* This entry contains packet that needs to be matched by IPv6 UDP data. */
#define MDNS_CHECK_RR_COUNT_REMOTE          0x52    /* This entry checks remote resource record count. */
#define MDNS_CHECK_RR_COUNT_LOCAL           0x53    /* This entry checks local resource record count. */
#define MDNS_CHECK_RR_DATA                  0x54    /* This entry checks local resource record data. */
#define MDNS_CHECK_ANY_V4                   0x55    /* This entry contains packet that needs to be matched by IPv4 mDNS data. */
#define MDNS_CHECK_ANY_V6                   0x56    /* This entry contains packet that needs to be matched by IPv6 mDNS data. */
#define MDNS_CHECK_PROBING_CALLBACK_INVOKED 0x57    /* This entry checks the value of probing callback invoked. */
#define MDNS_CHECK_SERVICE_CALLBACK_INVOKED 0x58    /* This entry checks the value of callback invoked. */
#define MDNS_REJECT_DATA_V4                 0x59    /* This entry contains packet that is not expected matched by IPv4 UDP data. */
#define MDNS_REJECT_DATA_V6                 0x5A    /* This entry contains packet that is not expected matched by IPv6 UDP data. */
#define MDNS_REJECT_ANY_V4                  0x5B    /* This entry contains packet that is not expected matched by IPv4 mDNS data. */
#define MDNS_REJECT_ANY_V6                  0x5C    /* This entry contains packet that is not expected matched by IPv6 mDNS data. */
#define MDNS_SET_IPV4_ADDRESS               0x5D    /* This entry sets the ipv4 address. */
#define MDNS_SET_SERVICE_CALLBACK           0x5E    /* This entry sets the service callback function. */
#define MDNS_SET_SERVICE_CALLBACK_STATE     0x5F    /* This entry sets the callback state. */
#define MDNS_SET_PROBING_CALLBACK_STATE     0x60    /* This entry sets the probing state. */
#define MDNS_TIMER_RESET                    0x61    /* This entry resets the timer. */
#define MDNS_TIMER_CHECK                    0x62    /* This entry checks the timer. */
#define MDNS_TIMER_MAX_CHECK                0x63    /* This entry checks the max timer. */
#define MDNS_QUERY                          0x64    /* This entry adds query to mDNS. */ 
#define MDNS_QUERY_ONESHOT                  0x65    /* This entry adds one-shot query to mDNS. */
#define MDNS_QUERY_DELETE                   0x66    /* This entry deletes query to mDNS. */
#define MDNS_QUERY_HOST_ADDRESS             0x67    /* This entry adds query to mDNS. */
#define MDNS_SERVICE_ADD                    0x68    /* This entry adds a service to mDNS. */
#define MDNS_SERVICE_DELETE                 0x69    /* This entry deletes all services to mDNS. */
#define MDNS_INTERFACE_DISABLE              0x6A    /* This entry disable interface. */
#define MDNS_INTERFACE_ENABLE               0x6B    /* This entry enable interface. */
#define MDNS_LLA_ADD                        0x6C    /* This entry adds link local address. */
#define MDNS_LLA_DELETE                     0x6D    /* This entry deletes link local address. */
#define MDNS_RECREATE                       0x6F    /* This entry deletes and creates mdns instance. */
#define MDNS_WAIT_TICK                      0x70    /* This entry sleep specified ticks. */


#define MDNS_FLAG_QUERY                     0x0000  /* Define flag for standard query. */
#define MDNS_FLAG_RESPONSE                  0x8400  /* Define flag for standard query response, No error. */


typedef struct MDNS_TEST_SEQ_struct
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
} MDNS_TEST_SEQ;

typedef struct MDNS_TEST_SUITE_struct
{
    MDNS_TEST_SEQ *test_case;
    int           *test_case_size;
} MDNS_TEST_SUITE;

typedef struct MDNS_RR_DATA_STRUCT
{
    char       *mdns_rr_data_name;
    char       *mdns_rr_data_type;
    char       *mdns_rr_data_domain_name;
}MDNS_RR_DATA;

typedef struct MDNS_SERVICE_STRUCT
{
    char       *name;
    char       *type;
    char       *sub_type;
    UCHAR      *txt;
    ULONG       ttl;
    USHORT      priority;
    USHORT      weights;
    USHORT      port;
    UCHAR       set;
    UINT        if_index;
}MDNS_SERVICE;

typedef struct MDNS_QUERY_INFO_STRUCT
{
    char       *name;
    char       *type;
    char       *sub_type;
}MDNS_QUERY_INFO;

void netx_mdns_run_test_case(NX_IP *ip_ptr, NX_MDNS *mdns_ptr, MDNS_TEST_SEQ *test_case, int test_case_size);
void netx_mdns_probing_notify(struct NX_MDNS_STRUCT *mdns_ptr, UCHAR *name, UINT state);

#endif /* __PRODUCT_NETXDUO__  */
#endif
