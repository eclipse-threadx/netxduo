#include    "tx_api.h"
#include    "nx_api.h"
#include    "netx_tahi.h"
#if defined(FEATURE_NX_IPV6) && defined(NX_TAHI_ENABLE)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"
#include    "nx_icmpv6.h"
#include    "nx_udp.h"
#include    "nxd_dhcpv6_client.h"
#ifdef NX_IPSEC_ENABLE
#include    "nx_ipsec.h"
#endif



#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0
#define     MAX_PACKET_SIZE    1600

/* Define the ThreadX and NetX object control blocks...  */

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

static ULONG                    original_xid;
static UCHAR                    original_cid[18];

/* Define thread prototypes.  */
extern void         test_control_return(UINT status);
extern UINT         (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT         packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT         in_cleanup_process;
static TX_MUTEX     pkt_capture_mutex;
static TX_SEMAPHORE pkt_count_sem;
static int          pkt_capture_flag = 0;
static UCHAR        packet_data[MAX_PACKET_SIZE];
#ifdef NX_IPSEC_ENABLE
static NX_PACKET    *assemble_pkt;
static UCHAR        assemble_pkt_data[MAX_PACKET_SIZE];
static UINT         fragment_cnt = 0;
#endif


static NX_PACKET *incoming_pkts = NX_NULL;
static NX_PACKET *incoming_pkts_tail = NX_NULL;

static NX_DHCPV6 *tahi_dhcpv6_client_ptr;
static void (*tahi_dhcpv6_reboot)();
static void (*tahi_dhcpv6_info_request)();
static void (*tahi_dhcpv6_dns)();

static void perform_check(char *pkt_data, int pkt_size, int timeout)
{
UINT       status;
NX_PACKET *current_pkt;
ULONG      start_time, current_time, time_remaining;
ULONG      bytes_copied;
    
    /* Compute the amount of time to wait for. */
    start_time = current_time = tx_time_get();

    /* timeout value is expressed in terms of seconds.  Convert it to ticks. */
    time_remaining = timeout  - (current_time - start_time);
    
    
    while(time_remaining > 0)
    {
        /* Wait for a packet. */
        status = tx_semaphore_get(&pkt_count_sem, time_remaining);

        if(status == NX_SUCCESS)
        {
            tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
            current_pkt = incoming_pkts;
            if(incoming_pkts)
            {
                incoming_pkts = incoming_pkts -> nx_packet_queue_next;
            }
            else
            {
                incoming_pkts_tail = NX_NULL;
            }
            tx_mutex_put(&pkt_capture_mutex);

            if(current_pkt)
            {

                /* A packet has been queued.  Examine the content of the packet. */
                status = nx_packet_data_retrieve(current_pkt, packet_data, &bytes_copied);

                if((status != NX_SUCCESS) || 
                   ((UINT)(pkt_size - 14) != bytes_copied) ||
                   (memcmp(pkt_data + 14, packet_data, bytes_copied) != 0))
                {
                    /* Not a match. */
                    
                    /* Compute new timeout value. */
                    current_time = tx_time_get();
                    time_remaining = timeout - (current_time - start_time);
                    if(time_remaining > 0x80000000)
                    {
                        /* Underflow */
                        time_remaining = 0;
                        error_counter = 1;
                    }
                    nx_packet_release(current_pkt);
                    continue;  
                }
                else
                {
                    /* Packet is a match.  Get out of this CHECK state. */
                    time_remaining = 0;
                    nx_packet_release(current_pkt);
                    continue;
                }
            }
        }  
        else
        {
            /* Timeout */                
            error_counter = 1;
            time_remaining = 0;
        }
    }
}

static void perform_null_check(int pkt_data, int pkt_size, int timeout)
{
UINT            status;
NX_PACKET       *current_pkt;
ULONG           start_time, current_time, time_remaining;
NX_UDP_HEADER   *udp_header_ptr;
ULONG           dst_port;



    /* Compute the amount of time to wait for. */
    start_time = current_time = tx_time_get();

    /* timeout value is expressed in terms of seconds.  Convert it to ticks. */
    time_remaining = timeout  - (current_time - start_time);

    while(time_remaining > 0)
    {
        /* Wait for a packet. */
        status = tx_semaphore_get(&pkt_count_sem, time_remaining);

        /* Did not receive any packet.  */
        if (status != NX_SUCCESS)
            break;    

        /* Compute the amount of time to wait for. */
        current_time = tx_time_get();

        /* Compute remaining ticks. */
        time_remaining = timeout - (current_time - start_time);
        if(time_remaining > 0x80000000)
        {
            /* Underflow */
            time_remaining = 0;
        }

        /* Receive a packet.  */
        tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
        current_pkt = incoming_pkts;
        if(incoming_pkts)
        {
            incoming_pkts = incoming_pkts -> nx_packet_queue_next;
        }
        else
        {
            incoming_pkts_tail = NX_NULL;
        }
        tx_mutex_put(&pkt_capture_mutex);

        if (!current_pkt)
            continue;

        /* Check this is a IPV6 packet.  */
/*
        if (*(current_pkt -> nx_packet_prepend_ptr - 2) != 0x86 ||
            *(current_pkt -> nx_packet_prepend_ptr - 1) != 0xdd)
            continue;*/


        /* Check next header ia a ICMPv6 header.  */
        if (*(current_pkt -> nx_packet_prepend_ptr + 6) != 0x3a)
            continue;

        /* Get destination UDP port */
        udp_header_ptr = (NX_UDP_HEADER*)(current_pkt-> nx_packet_prepend_ptr + 40);
        dst_port = udp_header_ptr -> nx_udp_header_word_0; 
        NX_CHANGE_ULONG_ENDIAN(dst_port);


        switch(pkt_data)
        {
        case NA:
            if (*(current_pkt -> nx_packet_prepend_ptr + 40) == 0x88)
            {
                error_counter = 1;
                time_remaining = 0;
                nx_packet_release(current_pkt);                       
            }
            break;

        case NS:
            if (*(current_pkt -> nx_packet_prepend_ptr + 40) == 0x87)
            {
                if (pkt_size == NS_UNSPEC)
                {
                    CHECK_UNSPECIFIED_ADDRESS((ULONG *)(current_pkt -> nx_packet_prepend_ptr + 8));
                    break;
                }
                error_counter = 1;
                time_remaining = 0;
                nx_packet_release(current_pkt);                       
            }
            break;

        case RS:
            if (*(current_pkt -> nx_packet_prepend_ptr + 40) == 0x85)
            {
                error_counter = 1;
                time_remaining = 0;
                nx_packet_release(current_pkt);                       
            }
            break;

        case ER:
            if (*(current_pkt -> nx_packet_prepend_ptr + 40) == 0x81)
            {
                error_counter = 1;
                time_remaining = 0;
                nx_packet_release(current_pkt);                       
            }
            break;
        case RELEASE:
            if ((((dst_port & 0x0000FFFF) == 0x00000222) || ((dst_port & 0x0000FFFF) == 0x00000223)) &&
                (*(current_pkt -> nx_packet_prepend_ptr + 48) == 0x08))
            {
                error_counter = 1;
                time_remaining = 0;
                nx_packet_release(current_pkt);                       
            }
            break;
        case DECLINE:
            if ((((dst_port & 0x0000FFFF) == 0x00000222) || ((dst_port & 0x0000FFFF) == 0x00000223)) &&
                (*(current_pkt -> nx_packet_prepend_ptr + 48) == 0x09))
            {
                error_counter = 1;
                time_remaining = 0;
                nx_packet_release(current_pkt);                       
            }
            break;
        case REQUEST:
            if ((((dst_port & 0x0000FFFF) == 0x00000222) || ((dst_port & 0x0000FFFF) == 0x00000223)) &&
                (*(current_pkt -> nx_packet_prepend_ptr + 48) == 0x03))
            {
                error_counter = 1;
                time_remaining = 0;
                nx_packet_release(current_pkt);                       
            }
            break;

        case ANY:
            if(((dst_port & 0x0000FFFF) == 0x00000222) || ((dst_port & 0x0000FFFF) == 0x00000223))
            {
                error_counter = 1;
                time_remaining = 0;
                nx_packet_release(current_pkt);                       
            }
            break;



        default:
            break;
        }
    }
}

#ifdef NX_IPSEC_ENABLE
static void perform_decrypt_check(NX_IP *ip_ptr, char *pkt_data, int pkt_size, int timeout, int is_tunneled,
                                  UCHAR protocol, ULONG src_port, ULONG dst_port, UINT option)
{
    UINT                status;
    NX_PACKET           *current_pkt;
    ULONG               start_time, current_time, time_remaining;
    NX_IPSEC_SA         *egress_sa_ptr;
    UCHAR               *iv_ptr_cur, *iv_ptr_data;
    UCHAR               *input_payload_ptr_cur, *input_payload_ptr_data;
    UINT                input_payload_size;
    NX_IPV6_HEADER      *ipv6_header;
    NXD_ADDRESS         src_addr, dest_addr;
    ULONG               data_offset;
    UINT                icv_size, iv_size;  /* in bytes */
    NX_IPSEC_SA         *cur_sa_ptr;
    NX_IPSEC_ESP_HEADER *esp_header_ptr;

    /* Compute the amount of time to wait for. */
    start_time = current_time = tx_time_get();

    /* timeout value is expressed in terms of seconds.  Convert it to ticks. */
    time_remaining = timeout  - (current_time - start_time);


    while(time_remaining > 0)
    {
        /* Wait for a packet. */
        status = tx_semaphore_get(&pkt_count_sem, time_remaining);

        if(status == NX_SUCCESS)
        {
            tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
            current_pkt = incoming_pkts;
            if(incoming_pkts)
            {
                incoming_pkts = incoming_pkts -> nx_packet_queue_next;
            }
            else
            {
                incoming_pkts_tail = NX_NULL;
            }
            tx_mutex_put(&pkt_capture_mutex);

            if(current_pkt)
            {

                /* A packet has been queued.  Examine the header of the packet. 
                   Include IPv6 header and ESP header in transport mode. */
                if(((UINT)(pkt_size - 14) != current_pkt -> nx_packet_length) ||
                    (memcmp(pkt_data + 14, current_pkt -> nx_packet_prepend_ptr, 40) != 0))
                {
                    /* Not a match. */

                    /* Compute new timeout value. */
                    current_time = tx_time_get();
                    time_remaining = timeout - (current_time - start_time);
                    if(time_remaining > 0x80000000)
                    {
                        /* Underflow */
                        time_remaining = 0;
                        error_counter = 1;
                    }
                    nx_packet_release(current_pkt);
                    continue;  
                }
                else
                {

                    /* Get SA. */
                    ipv6_header = (NX_IPV6_HEADER*)(current_pkt -> nx_packet_prepend_ptr);

                    src_addr.nxd_ip_version = NX_IP_VERSION_V6;
                    dest_addr.nxd_ip_version = NX_IP_VERSION_V6;

                    NX_IPV6_ADDRESS_CHANGE_ENDIAN(ipv6_header -> nx_ip_header_destination_ip);
                    NX_IPV6_ADDRESS_CHANGE_ENDIAN(ipv6_header -> nx_ip_header_source_ip);

                    COPY_IPV6_ADDRESS(ipv6_header -> nx_ip_header_source_ip, 
                        src_addr.nxd_ip_address.v6);


                    COPY_IPV6_ADDRESS(ipv6_header -> nx_ip_header_destination_ip, 
                        dest_addr.nxd_ip_address.v6);

                    /* Get SA. */
                    if (is_tunneled == NX_TRUE)
                    {
                        cur_sa_ptr =  ip_ptr -> nx_ip_ipsec_egress_sa_ptr;
                        status = NX_IPSEC_TRAFFIC_BYPASS;

                        esp_header_ptr = (NX_IPSEC_ESP_HEADER*)(current_pkt -> nx_packet_prepend_ptr + 40);

                        if (cur_sa_ptr != NX_NULL)
                        {
                            do 
                            {

                                /* Determine if the SA has been found based on traffic selection. */
                                if (CHECK_IPV6_ADDRESSES_SAME(dest_addr.nxd_ip_address.v6,
                                    cur_sa_ptr -> nx_ipsec_tunnel_exit_address.nxd_ip_address.v6) &&
                                    esp_header_ptr -> nx_ipsec_esp_spi == cur_sa_ptr -> nx_ipsec_sa_spi)
                                {

                                    status = NX_IPSEC_TRAFFIC_PROTECT;
                                    egress_sa_ptr = cur_sa_ptr;
                                    break;
                                }
                                else
                                {

                                    /* Move to the next entry in the SA list.  */
                                    cur_sa_ptr =  cur_sa_ptr -> nx_ipsec_sa_created_next;
                                }
                            } while (cur_sa_ptr != ip_ptr -> nx_ip_ipsec_egress_sa_ptr);
                        }
                    }
                    else
                    {
                            status = _nx_ipsec_sa_egress_lookup(ip_ptr, &src_addr, &dest_addr, 
                                protocol, src_port, dst_port, 
                                &data_offset, &egress_sa_ptr, option);
                    }

                    if (status != NX_IPSEC_TRAFFIC_PROTECT)
                    {
                        nx_packet_release(current_pkt);
                        continue;
                    }

                    /* Packet is a match.  Decrypt packets. */
                    icv_size = egress_sa_ptr -> nx_ipsec_sa_integrity_method -> nx_crypto_ICV_size_in_bits >> 3;
                    iv_size = egress_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_IV_size_in_bits >> 3;
                    iv_ptr_data = (UCHAR *)pkt_data + 14 + 40 + sizeof(NX_IPSEC_ESP_HEADER);
                    iv_ptr_cur = current_pkt -> nx_packet_prepend_ptr + 40 + sizeof(NX_IPSEC_ESP_HEADER);
                    input_payload_size = pkt_size - 14 - 40 - sizeof(NX_IPSEC_ESP_HEADER) - icv_size - iv_size;
                    input_payload_ptr_data = iv_ptr_data + iv_size;
                    input_payload_ptr_cur = iv_ptr_cur + iv_size;

                    status = _nx_ipsec_cryption_process(egress_sa_ptr, egress_sa_ptr -> nx_ipsec_sa_encryption_method, NX_CRYPTO_DECRYPT, 
                        (CHAR) egress_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_algorithm,
                        egress_sa_ptr -> nx_ipsec_sa_encrypt_key_string,
                        egress_sa_ptr -> nx_ipsec_sa_encrypt_key_len_in_bits,
                        iv_ptr_data, (egress_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_IV_size_in_bits >> 3),
                        egress_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_block_size_in_bytes,
                        input_payload_ptr_data, input_payload_size,
                        input_payload_ptr_data, input_payload_size, current_pkt);

                    if (status != NX_SUCCESS)
                    {
                        nx_packet_release(current_pkt);
                        continue;
                    }

                    status = _nx_ipsec_cryption_process(egress_sa_ptr, egress_sa_ptr -> nx_ipsec_sa_encryption_method, NX_CRYPTO_DECRYPT, 
                        (CHAR) egress_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_algorithm,
                        egress_sa_ptr -> nx_ipsec_sa_encrypt_key_string,
                        egress_sa_ptr -> nx_ipsec_sa_encrypt_key_len_in_bits,
                        iv_ptr_cur, iv_size,
                        egress_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_block_size_in_bytes,
                        input_payload_ptr_cur, input_payload_size,
                        input_payload_ptr_cur, input_payload_size, current_pkt);

                    if (status != NX_SUCCESS)
                    {
                        nx_packet_release(current_pkt);
                        continue;
                    }

                    if (memcmp(input_payload_ptr_cur, input_payload_ptr_data, input_payload_size) == 0)
                    {
                        time_remaining = 0;
                    }

                    nx_packet_release(current_pkt);
                    continue;
                }
            }
        }  
        else
        {
            /* Timeout */
            if(pkt_data != NX_NULL)
            {
                /* We expect a packet. */


                error_counter = 1;
            }
            time_remaining = 0;
        }
    }
}




static void perform_assemble(NX_IP *ip_ptr, char *pkt_data, int pkt_size, int timeout, int is_last)
{
    UINT       status;
    NX_PACKET *current_pkt;
    ULONG      start_time, current_time, time_remaining;

    /* Compute the amount of time to wait for. */
    start_time = current_time = tx_time_get();

    /* timeout value is expressed in terms of seconds.  Convert it to ticks. */
    time_remaining = timeout  - (current_time - start_time);


    while(time_remaining > 0)
    {
        /* Wait for a packet. */
        status = tx_semaphore_get(&pkt_count_sem, time_remaining);

        if(status == NX_SUCCESS)
        {
            tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
            current_pkt = incoming_pkts;
            if(incoming_pkts)
            {
                incoming_pkts = incoming_pkts -> nx_packet_queue_next;
            }
            else
            {
                incoming_pkts_tail = NX_NULL;
            }
            tx_mutex_put(&pkt_capture_mutex);

            if(current_pkt)
            {

                /* A packet has been queued.  Examine the header of the packet.
                   Include IPv6 header and Fragmentation header in transport mode. */
                if(((UINT)(pkt_size - 14) != current_pkt -> nx_packet_length) ||
                    (memcmp(pkt_data + 14, current_pkt -> nx_packet_prepend_ptr, 40) != 0))
                {
                    /* Not a match. */

                    /* Compute new timeout value. */
                    current_time = tx_time_get();
                    time_remaining = timeout - (current_time - start_time);
                    if(time_remaining > 0x80000000)
                    {
                        /* Underflow */
                        time_remaining = 0;
                        error_counter = 1;
                    }
                    nx_packet_release(current_pkt);
                    continue;  
                }
                else
                {
                    /* Packet is a match. Assemble packet. */

                    if (fragment_cnt == 0)
                    {
                        /* Allocate a packet.  */
                        status =  nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &assemble_pkt, 0,  NX_WAIT_FOREVER);

                        /* Check status.  */
                        if (status != NX_SUCCESS)
                        {
                            nx_packet_release(current_pkt);
                            continue;
                        }

                        memcpy(assemble_pkt_data, pkt_data, 54);

                        /* Copy IPv6 header. */
                        memcpy(assemble_pkt -> nx_packet_append_ptr, current_pkt -> nx_packet_prepend_ptr, 40);
                        assemble_pkt -> nx_packet_append_ptr += 40;

                        /* Initial packet length to IPv6 header length. */
                        assemble_pkt -> nx_packet_length = 40;
                    }

                    memcpy(assemble_pkt_data + (assemble_pkt -> nx_packet_length + 14), pkt_data + 62, pkt_size - 62);
 
                    /* Append packet data. */
                    memcpy(assemble_pkt -> nx_packet_append_ptr, current_pkt -> nx_packet_prepend_ptr + 48, current_pkt -> nx_packet_length - 48);
                    assemble_pkt -> nx_packet_append_ptr += current_pkt -> nx_packet_length - 48;

                    /* Increase packet length by data. */
                    assemble_pkt -> nx_packet_length += current_pkt -> nx_packet_length - 48;

                    fragment_cnt++;

                    /* Put assembled packet to incoming packet chain. */
                    if (is_last == NX_TRUE)
                    {
                        tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);

                        if(incoming_pkts == NX_NULL)
                        {
                            incoming_pkts = assemble_pkt;
                        }
                        else
                        {
                            incoming_pkts_tail -> nx_packet_queue_next = assemble_pkt;
                        }
                        incoming_pkts_tail = assemble_pkt;

                        assemble_pkt -> nx_packet_queue_next = NX_NULL;

                        tx_mutex_put(&pkt_capture_mutex);

                        tx_semaphore_put(&pkt_count_sem);

                        fragment_cnt = 0;

                    }

                    time_remaining = 0;
                    nx_packet_release(current_pkt);
                    continue;
                }
            }
        }  
        else
        {
            /* Timeout */
            if(pkt_data != NX_NULL)
            {
                /* We expect a packet. */


                error_counter = 1;
            }
            time_remaining = 0;
        }
    }
}
#endif

static void inject_packet(NX_IP *ip_ptr, char *pkt_data, int pkt_size)
{

UINT                    status;
NX_PACKET              *my_packet;

    /* Now, this packet is a received one, allocate the packet and let the IP stack receives it.  */
    /* Allocate a packet.  */
    status =  nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &my_packet, 0,  NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }
    
    my_packet -> nx_packet_length = pkt_size - 14;
    memcpy(my_packet -> nx_packet_prepend_ptr + 16, pkt_data + 14, my_packet -> nx_packet_length);
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    my_packet -> nx_packet_prepend_ptr += 16;
    my_packet -> nx_packet_append_ptr += 16;
    
    _nx_ip_packet_deferred_receive(ip_ptr, my_packet);

}

static void dump_packets(void)
{

    NX_PACKET *tmp_pkt;

    tmp_pkt = incoming_pkts;
    
    while(tmp_pkt)
    {
        tx_semaphore_get(&pkt_count_sem, 0);
        incoming_pkts = tmp_pkt -> nx_packet_queue_next;
        nx_packet_release(tmp_pkt);
        tmp_pkt = incoming_pkts;
    }
    incoming_pkts = NX_NULL;

}

/* Make sure the packet initial is right.  */
static void clean_hop_limit(NX_IP *ip_ptr)
{

    /* Add by wangyang for the simulation TAHI test in VS.  */
    ip_ptr -> nx_ipv6_hop_limit = 0xff;
}

/* Do ping6 process.  */
static void perform_check_v6request(NX_IP *ip_ptr, UCHAR flag, UINT length, char *pkt_data, int pkt_size, int timeout)
{

    /* Define the variable for ping6 process.  */
    NXD_ADDRESS   ping6add1;
    CHAR          ping6data1[1452]= "12";
    NX_PACKET     *my_packet;
    int           i;

    /* flag = 0 means pmtu.p2 ping6 test.  */
    /* flag = 1 means icmp.p2 ping6 test.  */
    if (flag == 0)
    {
        ping6add1.nxd_ip_version = NX_IP_VERSION_V6;
        ping6add1.nxd_ip_address.v6[0] = 0xFF1E0000;
        ping6add1.nxd_ip_address.v6[1] = 0x00000000;
        ping6add1.nxd_ip_address.v6[2] = 0x00000000;
        ping6add1.nxd_ip_address.v6[3] = 0x00010002;

        for(i = 0; i < 1452; i++)
            ping6data1[i] = '0';
    }
    else
    {
        ping6add1.nxd_ip_version = NX_IP_VERSION_V6;
        ping6add1.nxd_ip_address.v6[0] = 0xfe800000;
        ping6add1.nxd_ip_address.v6[1] = 0x00000000;
        ping6add1.nxd_ip_address.v6[2] = 0x020000ff;
        ping6add1.nxd_ip_address.v6[3] = 0xfe000100;
    }

    /* used for icmp.p2 test and do ping6 process.  */
    nxd_icmp_ping(ip_ptr, &ping6add1, ping6data1, length, &my_packet, 0);

    /* Invoke the check function to check the ping6 request packet.  */
    perform_check(pkt_data, pkt_size, timeout);
}

/* Reboot process.  */
static void perform_reboot(NX_IP *ip_ptr)
{

static NXD_ADDRESS    ipv6_address_1;

    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x021122ff;
    ipv6_address_1.nxd_ip_address.v6[3] = 0xfe334456;

    nx_ip_fragment_disable(ip_ptr);

    if(ip_ptr -> nx_ipv6_address[0].nxd_ipv6_address[0])
        nxd_ipv6_address_delete(ip_ptr, 0);
    if(ip_ptr -> nx_ipv6_address[1].nxd_ipv6_address[0])
        nxd_ipv6_address_delete(ip_ptr, 1);

    ip_ptr -> nx_ipv6_packet_receive = NULL;

    /* nx_ipv6_hop_limit make sure the after reboot process the limit is back to the 0xff.  */
    ip_ptr -> nx_ipv6_hop_limit = 0xff;

    /* nx_ip_packet_id affects the fragment identifier.  */
    ip_ptr -> nx_ip_packet_id = NX_INIT_PACKET_ID;

    /* nx_ip_icmp_sequence affects the ping6 request sequence.  */
    ip_ptr -> nx_ip_icmp_sequence = 0;
  
    /* Enable IPv6 */
    nxd_ipv6_enable(ip_ptr);

    /* Enable ICMPv6 */
    nxd_icmp_enable(ip_ptr);

    nx_ip_fragment_enable(ip_ptr);

    nxd_ipv6_address_set(ip_ptr, 0, &ipv6_address_1,64, NX_NULL);
}

static void dhcpv6_confirm()
{
    nx_dhcpv6_request_confirm(tahi_dhcpv6_client_ptr);
}

static void dhcpv6_release()
{
    nx_dhcpv6_request_release(tahi_dhcpv6_client_ptr);
}

void netx_tahi_set_dhcpv6(NX_DHCPV6 *dhcpv6_client_ptr)
{
    tahi_dhcpv6_client_ptr = dhcpv6_client_ptr;
}

void netx_tahi_set_dhcpv6_dns(void (*dhcpv6_dns)())
{
    tahi_dhcpv6_dns = dhcpv6_dns;
}

void netx_tahi_set_dhcpv6_reboot(void (*dhcpv6_reboot)())
{
    tahi_dhcpv6_reboot = dhcpv6_reboot;
}

void netx_tahi_set_dhcpv6_info_request(void (*dhcpv6_info_request)())
{
    tahi_dhcpv6_info_request = dhcpv6_info_request;
}

extern ULONG test_control_successful_tests;
extern ULONG test_control_failed_tests;
static int steps;
void netx_tahi_run_test_case(NX_IP *ip_ptr, TAHI_TEST_SEQ *test_case, int test_case_size)
{

    int i;

    /* Init the semaphore and mutex. */
    tx_mutex_create(&pkt_capture_mutex, "TAHI PKT CAPTURE", 0);
    tx_semaphore_create(&pkt_count_sem, "TAHI_PKT COUNT SEM", 0);

    /* Set the flag to queue up packets. */
    tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
    pkt_capture_flag = 1;
    tx_mutex_put(&pkt_capture_mutex);

    packet_process_callback = packet_process;

    in_cleanup_process = 0;
    error_counter = 0;
    for(steps = 0; steps < test_case_size; steps++)
    {

        /* If error has occured, skip all the test steps and start the cleanup process. */
        if(error_counter && !in_cleanup_process)
        {
            if(test_case[steps].command != CLEANUP)
                continue;
        }

        switch(test_case[steps].command)
        {
        case CLEANUP:
            /* This is a marker.  Nothing needs to be done here. */
            in_cleanup_process = 1;
            continue;

        case TITLE:
            printf("NetX Test:   TAHI %s TEST", test_case[steps].pkt_data);

            /* Align the output.  */
            for (i = test_case[steps].pkt_size; i <= 47; i++)
                printf(".");
            break;
        case INJECT:
            inject_packet(ip_ptr, test_case[steps].pkt_data, test_case[steps].pkt_size);
            break;
        case WAIT:
            tx_thread_sleep(test_case[steps].timeout * NX_IP_PERIODIC_RATE);
            break;
        case CHECK:
            perform_check(test_case[steps].pkt_data, test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE + 2);
            break;
        case N_CHECK:
            perform_null_check((int)test_case[steps].pkt_data, test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE);
            break;
        case DUMP:
            dump_packets();
            break;
        case CLEAN_HOP_LIMIT:
            clean_hop_limit(ip_ptr);
            break;
        case CHECK_V6REQUEST:
            perform_check_v6request(ip_ptr,test_case[steps].protocol, test_case[steps].option, test_case[steps].pkt_data, test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE + 2);
            break;
        case REBOOT:
            perform_reboot(ip_ptr);
            break;
        case DHCPV6_REBOOT:
            perform_reboot(ip_ptr);
            tahi_dhcpv6_reboot();
            break;
        case DHCPV6_INFO_REQUEST:
            tahi_dhcpv6_info_request();
            break;
        case DHCPV6_DNS:
            tahi_dhcpv6_dns();
            break;
        case DHCPV6_CONFIRM:
            dhcpv6_confirm();
            break;
        case DHCPV6_RELEASE:
            dhcpv6_release();
            break;
#ifdef NX_IPSEC_ENABLE
        case D_CHECK:
            perform_decrypt_check(ip_ptr, test_case[steps].pkt_data, test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE + 2, NX_FALSE,
                                  test_case[steps].protocol, test_case[steps].src_port, test_case[steps].dst_port, test_case[steps].option);
            break;
        case ASSEMBLE:
            perform_assemble(ip_ptr, test_case[steps].pkt_data, test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE + 2, NX_FALSE);
            break;
        case AD_CHECK:
            perform_assemble(ip_ptr, test_case[steps].pkt_data, test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE + 2, NX_TRUE);
            perform_decrypt_check(ip_ptr, (CHAR *)assemble_pkt_data, assemble_pkt -> nx_packet_length + 14, test_case[steps].timeout* NX_IP_PERIODIC_RATE + 2, NX_FALSE,
                                  (UCHAR)test_case[steps].protocol, test_case[steps].src_port, test_case[steps].dst_port, test_case[steps].option);
            break;
        case TD_CHECK:
            perform_decrypt_check(ip_ptr, test_case[steps].pkt_data, test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE + 2, NX_TRUE,
                                  test_case[steps].protocol, test_case[steps].src_port, test_case[steps].dst_port, test_case[steps].option);
            break;
#endif
        default:
            break;
        }
    }
    /* Set the flag to queue up packets. */
    tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
    pkt_capture_flag = 0;
    tx_mutex_put(&pkt_capture_mutex);
    dump_packets();
    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_failed_tests++;
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_successful_tests++;
    }

    tx_mutex_delete(&pkt_capture_mutex);
    tx_semaphore_delete(&pkt_count_sem);
}

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

    tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
    if(pkt_capture_flag == 0)
    {
        nx_packet_release(packet_ptr);
        tx_mutex_put(&pkt_capture_mutex);
        return NX_NULL;
    }

    if(incoming_pkts == NX_NULL)
    {
        incoming_pkts = packet_ptr;
    }
    else
    {
        incoming_pkts_tail -> nx_packet_queue_next = packet_ptr;
    }
    incoming_pkts_tail = packet_ptr;
    
    packet_ptr -> nx_packet_queue_next = NX_NULL;
    
    tx_mutex_put(&pkt_capture_mutex);

    tx_semaphore_put(&pkt_count_sem);
    
    return NX_NULL;
}

UINT tahi_dhcpv6_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_UDP_HEADER   *udp_header_ptr;
ULONG           src_dst_port;
ULONG           message_type;
NX_IPV6_HEADER  *ip_header;
ULONG           checksum;
ULONG           *ip_src_addr, *ip_dest_addr;
UCHAR           cid[18] = {0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
                           0xac, 0x7d, 0x87, 0x3a, 0x00, 0x11, 0x22, 0x33,
                           0x44, 0x56};


    udp_header_ptr = (NX_UDP_HEADER*)(packet_ptr -> nx_packet_prepend_ptr + 40);
    src_dst_port = udp_header_ptr -> nx_udp_header_word_0; 
    NX_CHANGE_ULONG_ENDIAN(src_dst_port);


    /* From port 546(client) to 547(server). Check if this is a DHCPv6 packet sent from client to server*/
    if(src_dst_port == 0x02220223)
    {
        packet_ptr -> nx_packet_prepend_ptr += 40;
        packet_ptr -> nx_packet_length -= 40;

        /* Get IP address for checksum computing. */
        ip_header = (NX_IPV6_HEADER *)(packet_ptr -> nx_packet_ip_header);
        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_source_ip);
        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_destination_ip);
        ip_src_addr  = &(ip_header -> nx_ip_header_source_ip[0]);
        ip_dest_addr = &(ip_header -> nx_ip_header_destination_ip[0]);

        /* Get message type. */
        _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 8, 1, &message_type);

        if(message_type == NX_DHCPV6_MESSAGE_TYPE_SOLICIT)
        {
            /* Record original xid, modify the xid to be the same with Tahi test packet. */
            _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 9, 3, &original_xid);
            *(ULONG *)(packet_ptr -> nx_packet_prepend_ptr + 8) = 0x12f03e01;
        }
        else if(message_type == NX_DHCPV6_MESSAGE_TYPE_REQUEST)
        {
            /* Record original xid, modify the xid to be the same with Tahi test packet. */
            _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 9, 3, &original_xid);
            *(ULONG *)(packet_ptr -> nx_packet_prepend_ptr + 8) = 0x900e0803;
        }
        else if((message_type == NX_DHCPV6_MESSAGE_TYPE_CONFIRM) || 
                (message_type == NX_DHCPV6_MESSAGE_TYPE_RENEW)   ||
                (message_type == NX_DHCPV6_MESSAGE_TYPE_REBIND)  ||
                (message_type == NX_DHCPV6_MESSAGE_TYPE_RELEASE) ||
                (message_type == NX_DHCPV6_MESSAGE_TYPE_DECLINE))
        {
            /* Record original xid, modify the xid to be the same with Tahi test packet. */
            _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 9, 3, &original_xid);
            *(ULONG *)(packet_ptr -> nx_packet_prepend_ptr + 8) = 0x66915200 + message_type;
        }
        else if(message_type == NX_DHCPV6_MESSAGE_TYPE_INFORM_REQUEST)
        {
            /* Record original xid, modify the xid to be the same with Tahi test packet. */
            _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 9, 3, &original_xid);
            *(ULONG *)(packet_ptr -> nx_packet_prepend_ptr + 8) = 0x12f03e0b;
        }

        /* Record original cid, modify the cid to be the same with Tahi test packet. */
        memcpy(original_cid, (packet_ptr -> nx_packet_prepend_ptr + 12), 18);
        memcpy(packet_ptr -> nx_packet_prepend_ptr + 12, cid, 18);


        /* Compute the checksum. */
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        /* Yes, we need to compute the UDP checksum.  */
        checksum = _nx_ip_checksum_compute(packet_ptr,
                NX_PROTOCOL_UDP,
                packet_ptr -> nx_packet_length,
                ip_src_addr,
                ip_dest_addr);
        checksum = ~checksum & NX_LOWER_16_MASK;

        /* If the computed checksum is zero, it is transmitted as all ones. */
        /* RFC 768, page 2. */
        if(checksum == 0)
            checksum = 0xFFFF;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 | checksum;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        packet_ptr -> nx_packet_prepend_ptr -= 40;
        packet_ptr -> nx_packet_length += 40;

        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_source_ip);
        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_destination_ip);
    }
    /* dst port 53, dns */ 
    else if((src_dst_port & 0x0000FFFF) == 0x00000035)
    {
        packet_ptr -> nx_packet_prepend_ptr += 40;
        packet_ptr -> nx_packet_length -= 40;

        /* Get IP address for checksum computing. */
        ip_header = (NX_IPV6_HEADER *)(packet_ptr -> nx_packet_ip_header);
        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_source_ip);
        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_destination_ip);
        ip_src_addr  = &(ip_header -> nx_ip_header_source_ip[0]);
        ip_dest_addr = &(ip_header -> nx_ip_header_destination_ip[0]);


        /* Modify the transmit ID to be the same with the packet captured by wireshark. */
        *(USHORT *)(packet_ptr -> nx_packet_prepend_ptr + 8) = 0xf907;

        /* Compute the checksum. */
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        /* Yes, we need to compute the UDP checksum.  */
        checksum = _nx_ip_checksum_compute(packet_ptr,
                NX_PROTOCOL_UDP,
                packet_ptr -> nx_packet_length,
                ip_src_addr,
                ip_dest_addr);
        checksum = ~checksum & NX_LOWER_16_MASK;

        /* If the computed checksum is zero, it is transmitted as all ones. */
        /* RFC 768, page 2. */
        if(checksum == 0)
            checksum = 0xFFFF;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 | checksum;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        packet_ptr -> nx_packet_prepend_ptr -= 40;
        packet_ptr -> nx_packet_length += 40;

        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_source_ip);
        NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header -> nx_ip_header_destination_ip);

    }

    return NX_TRUE;

}

void    tahi_dhcpv6_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

ULONG                   *ip_src_addr, *ip_dest_addr;
ULONG                   dst_port;
NX_UDP_HEADER           *udp_header_ptr;
ULONG                   checksum;
NX_IPV6_HEADER          *ip_header;
ULONG                   message_type;

    udp_header_ptr = (NX_UDP_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);
    dst_port = udp_header_ptr -> nx_udp_header_word_0; 
    NX_CHANGE_ULONG_ENDIAN(dst_port);

    /* Check if this is a DHCPv6 packet sent to client. */
    if((dst_port & 0x0000FFFF) == 0x00000222)
    {

        /* Get IP address for checksum computing. */
        ip_header = (NX_IPV6_HEADER *)(packet_ptr -> nx_packet_ip_header);
        ip_src_addr  = &(ip_header -> nx_ip_header_source_ip[0]);
        ip_dest_addr= &(ip_header -> nx_ip_header_destination_ip[0]);


        /* Modify the xid and cid. */
        _nx_dhcpv6_utility_get_data(packet_ptr -> nx_packet_prepend_ptr + 8, 1, &message_type);
        NX_CHANGE_ULONG_ENDIAN(original_xid);
        *(ULONG *)(packet_ptr -> nx_packet_prepend_ptr + 8) = original_xid + message_type;
        memcpy(packet_ptr -> nx_packet_prepend_ptr + 12, original_cid, 18);


        /* Compute the checksum. */
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        /* Yes, we need to compute the UDP checksum.  */
        checksum = _nx_ip_checksum_compute(packet_ptr,
                NX_PROTOCOL_UDP,
                packet_ptr -> nx_packet_length,
                ip_src_addr,
                ip_dest_addr);
        checksum = ~checksum & NX_LOWER_16_MASK;

        /* If the computed checksum is zero, it is transmitted as all ones. */
        /* RFC 768, page 2. */
        if(checksum == 0)
            checksum = 0xFFFF;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000;

        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 | checksum;

        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    }

    _nx_udp_packet_receive(ip_ptr, packet_ptr); 

}
#endif
