/* This NetX test concentrates on the BSD RAW Packet blocking operation for PPPoE traffic.  */
/* This test case covers the following scenarios: 
   Be able to create socket_1 of PPPOE_SESS for receiving SESS traffice, 
   socket_2 for receiving PPPOE_DISC traffic
   socket_3 for sending either PPPOE_DISC or PPPOE_SESS traffic. 
*/


#include   "tx_api.h"
#include   "nx_api.h"
#if defined (__PRODUCT_NETXDUO__) && defined (NX_BSD_RAW_PPPOE_SUPPORT) && !defined(NX_DISABLE_IPV4)
#ifdef NX_BSD_ENABLE
#include   "nxd_bsd.h"
#include   "nx_icmpv6.h"
#define     DEMO_STACK_SIZE         8192


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            20
/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static TX_SEMAPHORE            ntest1_sem;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);

static char *requests[4] = {"Request1",  "Request2",  "Request3",  "Request4"};
static char response[4][32] = {"              Response1", "              Response2", "              Response3", "              Response4"};

static char rcvBuffer[50];


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_raw_pppoe_test_application_define(void *first_unused_memory)
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

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, (256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 2);
    pointer = pointer + (256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 2;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2,2,3,4), 0xFFFFFF00UL, _nx_ram_network_driver_512);

    if (status)
        error_counter++;



    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable raw processing for both IP instances.  */
    status += nx_ip_raw_packet_enable(&ip_0);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check RAW enable and BSD init status.  */
    if (status)
        error_counter++;

    tx_semaphore_create(&ntest1_sem, "ntest0 semaphore", 0);
}


static char mac_ip0_if0[6];
static char mac_ip0_if1[6];


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
struct sockaddr_ll sock_addr_if0;
struct sockaddr_ll sock_addr_if1;
int recv_bytes;
int i, n;
int fromAddr_len;
struct sockaddr_ll fromAddr;
int sock_sess0;
int sock_sess1;
int sock_disc0;
int sock_disc1;
int ioctl_arg;
USHORT type;



    printf("NetX Test:   Basic BSD PPPoE SESS Blocking Test............");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    mac_ip0_if0[0] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_msw >> 8) & 0xFF;
    mac_ip0_if0[1] = ip_0.nx_ip_interface[0].nx_interface_physical_address_msw & 0xFF;
    mac_ip0_if0[2] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 24) & 0xff;
    mac_ip0_if0[3] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 16) & 0xff;
    mac_ip0_if0[4] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 8) & 0xff;
    mac_ip0_if0[5] = ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw  & 0xff;

    mac_ip0_if1[0] = (ip_0.nx_ip_interface[1].nx_interface_physical_address_msw >> 8) & 0xFF;
    mac_ip0_if1[1] = ip_0.nx_ip_interface[1].nx_interface_physical_address_msw & 0xFF;
    mac_ip0_if1[2] = (ip_0.nx_ip_interface[1].nx_interface_physical_address_lsw >> 24) & 0xff;
    mac_ip0_if1[3] = (ip_0.nx_ip_interface[1].nx_interface_physical_address_lsw >> 16) & 0xff;
    mac_ip0_if1[4] = (ip_0.nx_ip_interface[1].nx_interface_physical_address_lsw >> 8) & 0xff;
    mac_ip0_if1[5] = ip_0.nx_ip_interface[1].nx_interface_physical_address_lsw  & 0xff;


    /* Creaet sock_sess0 and sock_sess1 for PPPOE_SESS */
    sock_sess0 = socket(AF_PACKET, SOCK_RAW, ETHERTYPE_PPPOE_SESS);
    sock_sess1 = socket(AF_PACKET, SOCK_RAW, ETHERTYPE_PPPOE_SESS);
    /* Creaet sock_disc0 and sock_disc1 for PPPOE_SESS */
    sock_disc0 = socket(AF_PACKET, SOCK_RAW, ETHERTYPE_PPPOE_DISC);
    sock_disc1 = socket(AF_PACKET, SOCK_RAW, ETHERTYPE_PPPOE_DISC);        
    
    /* Validate the sockets. */
    if((sock_sess0 == 0) || (sock_sess1 == 0) || (sock_disc0 == 0) || (sock_disc1 == 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* First test that the receiver is able to block on receiving a DISC or a SESS message. */
    sock_addr_if0.sll_family = AF_PACKET;
    sock_addr_if0.sll_protocol = ETHERTYPE_PPPOE_SESS;
    sock_addr_if0.sll_ifindex = 0;

    tx_semaphore_put(&ntest1_sem);
    /* Expect ntest_1 to send one DISC to if0, one DISC to if1, one SESS to if0, one SESS to if1 */
    /* ntest_0 only receives data on recv_sess0 and recv_disc0 */

    fromAddr_len = sizeof(fromAddr);
    recv_bytes = recvfrom(sock_sess0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes != (strlen("Request1") + 1 + 14))
        error_counter++;
    type = (rcvBuffer[12] << 8) | rcvBuffer[13];
    if(type != ETHERTYPE_PPPOE_SESS)
        error_counter++;
    
    if(strcmp(&rcvBuffer[14], "Request1"))
        error_counter++;
    
    if(fromAddr_len != sizeof(struct sockaddr_ll))
        error_counter++;

    if((fromAddr.sll_family != AF_PACKET) || (fromAddr.sll_ifindex != 1))
        error_counter++;



    recv_bytes = recvfrom(sock_sess0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes != (strlen("Request2") + 1 + 14))
        error_counter++;
    type = (rcvBuffer[12] << 8) | rcvBuffer[13];
    if(type != ETHERTYPE_PPPOE_SESS)
        error_counter++;
    
    if(strcmp(&rcvBuffer[14], "Request2"))
        error_counter++;
    
    if(fromAddr_len != sizeof(struct sockaddr_ll))
        error_counter++;

    if((fromAddr.sll_family != AF_PACKET) || (fromAddr.sll_ifindex != 0))
        error_counter++;

    recv_bytes = recvfrom(sock_disc0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes != (strlen("Request3") + 1 + 14))
        error_counter++;
    type = (rcvBuffer[12] << 8) | rcvBuffer[13];
    if(type != ETHERTYPE_PPPOE_DISC)
        error_counter++;
    
    if(strcmp(&rcvBuffer[14], "Request3"))
        error_counter++;
    
    if(fromAddr_len != sizeof(struct sockaddr_ll))
        error_counter++;

    if((fromAddr.sll_family != AF_PACKET) || (fromAddr.sll_ifindex != 1))
        error_counter++;

    recv_bytes = recvfrom(sock_disc0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes != (strlen("Request4") + 1 + 14))
        error_counter++;
    type = (rcvBuffer[12] << 8) | rcvBuffer[13];
    if(type != ETHERTYPE_PPPOE_DISC)
        error_counter++;
    
    if(strcmp(&rcvBuffer[14], "Request4"))
        error_counter++;
    
    if(fromAddr_len != sizeof(struct sockaddr_ll))
        error_counter++;

    if((fromAddr.sll_family != AF_PACKET) || (fromAddr.sll_ifindex != 0))
        error_counter++;

    /* ntest_0 sends out SESS messages through sock_sess0 (if0) and sock_sess1 (if1).  Verify that
       ntest_0 is able to receive both messages on sock_sess0. */
    sock_addr_if0.sll_family = AF_PACKET;
    sock_addr_if0.sll_ifindex = 0;

    /* Set up response[0] to be SESS packet, send through interface 0 */
    for(i = 0; i < 6; i++)
    {
        response[0][i] = mac_ip0_if1[i];
        response[0][i + 6] = mac_ip0_if0[i];
    }
    response[0][12] = (ETHERTYPE_PPPOE_SESS >> 8);
    response[0][13] = ETHERTYPE_PPPOE_SESS & 0xFF;
            
    n = sendto(sock_sess0, response[0], sizeof(response[0]), 0, (struct sockaddr*)&sock_addr_if0, sizeof(sock_addr_if0));
    if(n != sizeof(response[0]))
        error_counter++;

    /* Set up response[1] to be SESS packet, send through interface 1 */
    for(i = 0; i < 6; i++)
    {
        response[1][i] = mac_ip0_if0[i];
        response[1][i + 6] = mac_ip0_if1[i];
    }
    response[1][12] = (ETHERTYPE_PPPOE_SESS >> 8);
    response[1][13] = ETHERTYPE_PPPOE_SESS & 0xFF;

    sock_addr_if1.sll_family = AF_PACKET;
    sock_addr_if1.sll_protocol = ETHERTYPE_PPPOE_SESS;
    sock_addr_if1.sll_ifindex = 1;

    n = sendto(sock_sess0, response[1], sizeof(response[1]), 0, (struct sockaddr*)&sock_addr_if1, sizeof(sock_addr_if1));
    if(n != sizeof(response[1]))
        error_counter++;

    recv_bytes = recvfrom(sock_sess0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes != sizeof(response[0]))
        error_counter++;
    type = (rcvBuffer[12] << 8) | rcvBuffer[13];
    if(type != ETHERTYPE_PPPOE_SESS)
        error_counter++;
    
    if(strcmp(&rcvBuffer[14], "Response1"))
        error_counter++;
    
    if(fromAddr_len != sizeof(struct sockaddr_ll))
        error_counter++;

    if((fromAddr.sll_family != AF_PACKET) || (fromAddr.sll_ifindex != 1))
        error_counter++;

    recv_bytes = recvfrom(sock_sess0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes != sizeof(response[1]))
        error_counter++;
    type = (rcvBuffer[12] << 8) | rcvBuffer[13];
    if(type != ETHERTYPE_PPPOE_SESS)
        error_counter++;
    
    if(strcmp(&rcvBuffer[14], "Response2"))
        error_counter++;
    
    if(fromAddr_len != sizeof(struct sockaddr_ll))
        error_counter++;

    if((fromAddr.sll_family != AF_PACKET) || (fromAddr.sll_ifindex != 0))
        error_counter++;

    /* Set up response[2] to be DISC packet, send through interface 0 */
    for(i = 0; i < 6; i++)
    {
        response[2][i] = mac_ip0_if1[i];
        response[2][i + 6] = mac_ip0_if0[i];
    }
    response[2][12] = (ETHERTYPE_PPPOE_DISC >> 8);
    response[2][13] = ETHERTYPE_PPPOE_DISC & 0xFF;

    sock_addr_if0.sll_protocol = ETHERTYPE_PPPOE_DISC;

    n = sendto(sock_sess0, response[2], sizeof(response[2]), 0, (struct sockaddr*)&sock_addr_if0, sizeof(sock_addr_if0));
    if(n != sizeof(response[0]))
        error_counter++;

    sock_addr_if0.sll_family = AF_PACKET;
    sock_addr_if0.sll_ifindex = 1;

    /* Set up response[3] to be DISC packet, send through interface 1 */
    for(i = 0; i < 6; i++)
    {
        response[3][i] = mac_ip0_if0[i];
        response[3][i + 6] = mac_ip0_if1[i];
    }
    response[3][12] = (ETHERTYPE_PPPOE_DISC >> 8);
    response[3][13] = ETHERTYPE_PPPOE_DISC & 0xFF;

    sock_addr_if1.sll_protocol = ETHERTYPE_PPPOE_DISC;

    n = sendto(sock_sess0, response[3], sizeof(response[3]), 0, (struct sockaddr*)&sock_addr_if1, sizeof(sock_addr_if1));
    if(n != sizeof(response[3]))
        error_counter++;

    recv_bytes = recvfrom(sock_disc0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes != sizeof(response[2]))
        error_counter++;
    type = (rcvBuffer[12] << 8) | rcvBuffer[13];
    if(type != ETHERTYPE_PPPOE_DISC)
        error_counter++;
    
    if(strcmp(&rcvBuffer[14], "Response3"))
        error_counter++;
    
    if(fromAddr_len != sizeof(struct sockaddr_ll))
        error_counter++;

    if((fromAddr.sll_family != AF_PACKET) || (fromAddr.sll_ifindex != 1))
        error_counter++;

    recv_bytes = recvfrom(sock_disc0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes != sizeof(response[3]))
        error_counter++;
    type = (rcvBuffer[12] << 8) | rcvBuffer[13];
    if(type != ETHERTYPE_PPPOE_DISC)
        error_counter++;
    
    if(strcmp(&rcvBuffer[14], "Response4"))
        error_counter++;
    
    if(fromAddr_len != sizeof(struct sockaddr_ll))
        error_counter++;

    if((fromAddr.sll_family != AF_PACKET) || (fromAddr.sll_ifindex != 0))
        error_counter++;
       

    /* Set all sockets to be non-blocking */
    ioctl_arg = NX_TRUE;
    if(ioctl(sock_sess0, FIONBIO, &ioctl_arg))
        error_counter++;

    if(ioctl(sock_sess1, FIONBIO, &ioctl_arg))
        error_counter++;

    if(ioctl(sock_disc0, FIONBIO, &ioctl_arg))
        error_counter++;

    if(ioctl(sock_disc1, FIONBIO, &ioctl_arg))
        error_counter++;

    /* Now try to receive from all these sockets and none of them should have any data available for read. */
    recv_bytes = recvfrom(sock_sess0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes > 0)
        error_counter++;
    recv_bytes = recvfrom(sock_sess1, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes > 0)
        error_counter++;
    recv_bytes = recvfrom(sock_disc0, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes > 0)
        error_counter++;
    recv_bytes = recvfrom(sock_disc1, rcvBuffer, sizeof(rcvBuffer), 0, (struct sockaddr*)&fromAddr, &fromAddr_len);
    if(recv_bytes > 0)
        error_counter++;

    soc_close(sock_sess0);
    soc_close(sock_sess1);
    soc_close(sock_disc0);
    soc_close(sock_disc1);

    validate_bsd_structure();
    tx_thread_sleep(2);
    if(error_counter)
        printf("ERROR!\n");
    else
        printf("SUCCESS!\n");

    if(error_counter)
        test_control_return(1);    

    test_control_return(0);    
}
    

extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];
extern TX_BLOCK_POOL nx_bsd_socket_block_pool;
static void validate_bsd_structure(void)
{
int i;
    /* Make sure every BSD socket should be free by now. */
    
    for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
    {
#ifdef __PRODUCT_NETX__
        if(nx_bsd_socket_array[i].nx_bsd_socket_in_use)
#else        
        if(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE)
#endif            
        {
            error_counter++;
        }

        if(nx_bsd_socket_array[i].nx_bsd_socket_tcp_socket ||
           nx_bsd_socket_array[i].nx_bsd_socket_udp_socket)
        {
            error_counter++;
        }
    }
    
    /* Make sure all the NX SOCKET control blocks are released. */
    if(nx_bsd_socket_block_pool.tx_block_pool_available != 
       nx_bsd_socket_block_pool.tx_block_pool_total)
    {    
        error_counter++;
    }

    /* Make sure all the sockets are released */
    if(ip_0.nx_ip_tcp_created_sockets_ptr ||
       ip_0.nx_ip_udp_created_sockets_ptr)
    {
        error_counter++;
        return;
    }

}
static void    ntest_1_packet_send(int msg_id, int if_id, int type)
{
UINT status;
int  i;
NX_PACKET *packet_ptr;
NX_IP_DRIVER driver_request;


    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_NO_WAIT);
    if(status)
    {
        error_counter++;
        return;
    }

    /* Construct the first message as SESS type, sent through interface 0 */
    for(i = 0; i < 6; i++)
    {
        if(if_id == 0)
        {
            packet_ptr -> nx_packet_prepend_ptr[i] = mac_ip0_if1[i];
            packet_ptr -> nx_packet_prepend_ptr[i + 6] = mac_ip0_if0[i];
        }
        else
        {
            packet_ptr -> nx_packet_prepend_ptr[i] = mac_ip0_if0[i];
            packet_ptr -> nx_packet_prepend_ptr[i + 6] = mac_ip0_if1[i];
        }
    }
    packet_ptr -> nx_packet_prepend_ptr[12] = type >> 8;
    packet_ptr -> nx_packet_prepend_ptr[13] = type & 0xFF;
    memcpy(&packet_ptr -> nx_packet_prepend_ptr[14], requests[msg_id], (strlen(requests[msg_id]) + 1));
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + strlen(requests[msg_id]) + 14 + 1;
    packet_ptr -> nx_packet_length = strlen(requests[msg_id]) + 14 + 1;
    

    driver_request.nx_ip_driver_ptr = &ip_0;
    driver_request.nx_ip_driver_command = NX_LINK_PACKET_PPPOE_SESS_SEND;
    driver_request.nx_ip_driver_packet = packet_ptr;
    driver_request.nx_ip_driver_interface = &(ip_0.nx_ip_interface[if_id]);

    (driver_request.nx_ip_driver_interface -> nx_interface_link_driver_entry)(&driver_request);

    return;
}


static void    ntest_1_entry(ULONG thread_input)
{


    tx_semaphore_get(&ntest1_sem, NX_IP_PERIODIC_RATE);

    tx_thread_sleep(5);

    ntest_1_packet_send(0, 0, NX_LINK_PACKET_PPPOE_SESS_SEND);
    ntest_1_packet_send(1, 1, NX_LINK_PACKET_PPPOE_SESS_SEND);
    ntest_1_packet_send(2, 0, NX_LINK_PACKET_PPPOE_DISC_SEND);
    ntest_1_packet_send(3, 1, NX_LINK_PACKET_PPPOE_DISC_SEND);


}


#endif /* NX_BSD_ENABLE */

#else /* __PRODUCT_NETXDUO__ */

extern void    test_control_return(UINT status);
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_raw_pppoe_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Basic BSD Raw PPPOE Test......................N/A\n");
    test_control_return(3);
}
#endif /* __PRODUCT_NETXDUO__ */

