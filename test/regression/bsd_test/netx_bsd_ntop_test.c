/* This NetX test concentrates on the basic BSD UDP non-blocking operation.  */
#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"

#define     DEMO_STACK_SIZE         4096

static TX_THREAD  ntest_0;
static void       ntest_0_entry(ULONG thread_input);
extern void       test_control_return(UINT status);

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];

#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            10

static ULONG                   packet_pool_area[(256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 8 / 4];

extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

static ULONG      error_counter;

/* Define the ThreadX and NetX object control blocks...  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_ntop_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, packet_pool_area, sizeof(packet_pool_area));

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 4096, 1);
    pointer =  pointer + 4096;

    /* Enable BSD */
    status = bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;


}

static void ntest_0_entry(ULONG thread_input)
{

/* Network byte ordered IPv6 adddress. */

/* fe80::74ac:2217:530:5d7f */
ULONG ipv6_addr1[] = {htonl(0xfe800000), htonl(0), htonl(0x74ac2217), htonl(0x5305d7f)};
/* fe80::74ac:0:530:5d7f */
ULONG ipv6_addr2[] = {htonl(0xfe800000), htonl(0), htonl(0x74ac0000), htonl(0x5305d7f)};
/* ::ffff:1.2.3.4 */
ULONG ipv6_addr3[] = {htonl(0), htonl(0), htonl(0xffff), htonl(0x01020304)};
/* ::1.2.3.4 */
ULONG ipv6_addr4[] = {htonl(0), htonl(0), htonl(0), htonl(0x01020304)};
/* fe80:1232:af65:f3d2:2d28:af23:201:403*/
ULONG ipv6_addr5[] = {htonl(0xfe801232), htonl(0xaf65f3d2), htonl(0x2d28af23), htonl(0x2010403)};


/* Max Length = 46.   "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255" */
CHAR      dst[46];
const CHAR      *rt_ptr;


    printf("NetX Test:   Basic BSD ntop Test...........................");

    rt_ptr = inet_ntop(AF_INET6, ((VOID *)(&ipv6_addr1[0])), dst, 46);
    if((rt_ptr == NX_NULL) || (strcmp(dst, "fe80::74ac:2217:530:5d7f") != 0))
        error_counter++;

    rt_ptr = inet_ntop(AF_INET6, (VOID *)(&ipv6_addr2[0]), dst, 46);
    if((rt_ptr == NX_NULL) || (strcmp(dst, "fe80::74ac:0:530:5d7f") != 0))
        error_counter++;

    rt_ptr = inet_ntop(AF_INET6, (VOID *)(&ipv6_addr3[0]), dst, 46);
    if((rt_ptr == NX_NULL) || (strcmp(dst, "::ffff:1.2.3.4") != 0))
        error_counter++;

    rt_ptr = inet_ntop(AF_INET6, (VOID *)(&ipv6_addr4[0]), dst, 46);
    if((rt_ptr == NX_NULL) || (strcmp(dst, "::1.2.3.4") != 0))
        error_counter++;

    rt_ptr = inet_ntop(AF_INET6, (VOID *)(&ipv6_addr5[0]), dst, 46);
    if((rt_ptr == NX_NULL) || (strcmp(dst, "fe80:1232:af65:f3d2:2d28:af23:201:403") != 0))
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
void    netx_bsd_ntop_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Basic BSD ntop Test...........................N/A\n");
    test_control_return(3);
}

#endif
