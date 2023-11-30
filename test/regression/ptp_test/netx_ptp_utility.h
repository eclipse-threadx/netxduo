#ifndef TEST_UTILITY_H
#define TEST_UTILITY_H

#include "nxd_ptp_client.h"

void test_control_return(UINT status);

#ifdef DEBUG
#define DBGPRINTF(...)  printf(##__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

#define ASSERT_DEBUG(c) printf("\n[%s:%d]Assert fail: %s\n", __FILE__, __LINE__, (c));
#define ASSERT_TRUE(p) {if (!(p)) {ASSERT_DEBUG(#p);test_control_return(1);}}
#define ASSERT_SUCCESS(v) ASSERT_TRUE((v) == 0)

/* Define the UDP ports */
#define PTP_EVENT_UDP_PORT          319
#define PTP_GENERAL_UDP_PORT        320

/* Define the IPv4 multicast address "224.0.1.129" */
#define PTP_IPV4_MULTICAST_ADDR     IP_ADDRESS(224,0,1,129)

/* Define the IPv6 multicast address "ff0e::181" */
#define PTP_IPV6_MULTICAST_ADDR_SET(x)  {           \
        (x) -> nxd_ip_version = NX_IP_VERSION_V6;   \
        (x) -> nxd_ip_address.v6[0] = 0xff0e0000UL; \
        (x) -> nxd_ip_address.v6[1] = 0;            \
        (x) -> nxd_ip_address.v6[2] = 0;            \
        (x) -> nxd_ip_address.v6[3] = 0x181; }

typedef struct
{

    /* Timestamp from master.  */
    NX_PTP_TIME sync;
    NX_PTP_TIME follow_up;
    NX_PTP_TIME delay_response;

    /* Timestamp from client.  */
    NX_PTP_TIME sync_received;
    NX_PTP_TIME delay_request;
} TEST_TIMESTAMP;

typedef struct
{
    UCHAR clock_id[NX_PTP_CLOCK_PORT_IDENTITY_SIZE];
    UCHAR sequence_id[2];
} DELAY_REQUEST_CONTEXT;


VOID create_socket(NX_IP *ip_ptr, NX_UDP_SOCKET *socket_ptr, UINT port);
VOID send_announce(NX_UDP_SOCKET *socket_ptr, NX_PACKET_POOL *pool_ptr, USHORT utc_offset);
VOID send_sync(NX_UDP_SOCKET *socket_ptr, NX_PACKET_POOL *pool_ptr, NX_PTP_TIME *ts);
VOID send_follow_up(NX_UDP_SOCKET *socket_ptr, NX_PACKET_POOL *pool_ptr, NX_PTP_TIME *ts);
VOID send_delay_response(NX_UDP_SOCKET *socket_ptr, NX_PACKET_POOL *pool_ptr,
                         DELAY_REQUEST_CONTEXT *context, NX_PTP_TIME *ts);
UINT receive_delay_request(NX_UDP_SOCKET *socket_ptr, DELAY_REQUEST_CONTEXT *context,
                           UINT wait_option);
VOID set_two_steps(UCHAR two_steps);
VOID set_clock_id(UCHAR *clock_id);
VOID set_ip_version(UCHAR ip_version);
VOID calibrate_timestamp(TEST_TIMESTAMP *test_ts, NX_PTP_TIME *ts);
VOID _netx_ptp_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
UINT _netx_ptp_clock_callback(NX_PTP_CLIENT *client_ptr, UINT operation,
                              NX_PTP_TIME *time_ptr, NX_PACKET *packet_ptr,
                              VOID *callback_data);

#endif /* TEST_UTILITY_H */