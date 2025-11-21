#ifndef _NX_RAM_NETWORK_DRIVER_TEST_1500_H_
#define _NX_RAM_NETWORK_DRIVER_TEST_1500_H_
#include "tx_api.h"
#include "tx_timer.h"
#define NX_RAMDRIVER_OP_BYPASS      0
#define NX_RAMDRIVER_OP_DROP        1
#define NX_RAMDRIVER_OP_DELAY       2
#define NX_RAMDRIVER_OP_DUPLICATE   3

#define NX_RAMDRIVER_TIMER_UNUSED   0
#define NX_RAMDRIVER_TIMER_USED     1
#define NX_RAMDRIVER_TIMER_DIRTY    2

#define NX_MAX_TIMER                5

VOID _nx_ram_network_driver_timer_clean(VOID);


#ifdef NX_PCAP_ENABLE

/* Define return values.  */
#define NX_PCAP_FILE_OK             1
#define NX_PCAP_FILE_ERROR          0

/* Define the pcap header struct.  */
typedef struct NX_PCAP_HEADER_FILE_STRUCT
{
UINT    magic_number;               /* magic number */
USHORT  version_major;              /* major version number */
USHORT  version_minor;              /* minor version number */
INT     this_zone;                  /* GMT to local correction */
UINT    sig_figs;                   /* accuracy of timestamps */
UINT    snapshot_length;            /* max length of captured packets, in octets */
UINT    link_type;                  /* data link type */
} NX_PCAP_FILE_HEADER; 

typedef struct NX_PCAP_PACKET_HEADER_STRUCT
{
UINT    time_stamp_second;          /* timestamp seconds */
UINT    time_stamp_microseconds;    /* timestamp microseconds */
UINT    capture_length;             /* number of octets of packet saved in file */
UINT    actual_length;              /* actual length of packet */
} NX_PCAP_PACKET_HEADER;

/* Define time value.  */
typedef struct timeval NX_TIME_VALUE;

#endif /* NX_PCAP_ENABLE  */

#endif /* _NX_RAM_NETWORK_DRIVER_TEST_1500_H_ */
