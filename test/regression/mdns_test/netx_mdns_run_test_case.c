#include    "tx_api.h"
#include    "nx_api.h"

#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_IPV4
#include    "netx_mdns_test.h"
#include    "nx_tcp.h"
#include    "nx_ip.h"

#ifdef FEATURE_NX_IPV6
#include    "nx_ipv6.h"
#include    "nx_icmpv6.h"
#endif /* FEATURE_NX_IPV6  */

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0
#define     MAX_PACKET_SIZE    1600

/* Define the ThreadX and NetX object control blocks...  */

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */
extern void         test_control_return(UINT status);
extern UINT         (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT         packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT         in_cleanup_process;
static TX_MUTEX     pkt_capture_mutex;
static TX_SEMAPHORE pkt_count_sem;
static int          pkt_capture_flag = 0;
static NX_PACKET    *assemble_pkt;
static UCHAR        assemble_pkt_data[MAX_PACKET_SIZE];
static UINT         fragment_cnt = 0;
static UINT         service_callback_invoked;
static UINT         service_callback_state; 
static UINT         probing_callback_invoked;
static UINT         probing_callback_state;
static UCHAR        mdns_stack[DEMO_STACK_SIZE];


static NX_PACKET *incoming_pkts = NX_NULL;
static NX_PACKET *incoming_pkts_tail = NX_NULL;

static VOID service_change_notify(NX_MDNS *mdns_ptr, NX_MDNS_SERVICE *service_ptr, UINT state)
{

    /* Check state. */
    if(service_callback_state == state)
        service_callback_invoked++;
}

static void perform_check(char *pkt_data, int pkt_size, int timeout)
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

                /* A packet has been queued.  Examine the content of the packet. */
                if(((pkt_size - 14) != current_pkt -> nx_packet_length) ||
                   (memcmp(pkt_data + 14, current_pkt -> nx_packet_prepend_ptr, current_pkt -> nx_packet_length) != 0))
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

static void decode_mdns_data(ULONG *current_len, CHAR **org_data)
{
CHAR   *character = *org_data;
CHAR    compressed = NX_FALSE;
UINT    labelSize;
    
    /* As long as we haven't found a zero terminating label */
    while(*character != '\0')
    {

        labelSize =  *character++;

        /* Is this a compression pointer or a count.  */
        if(labelSize <= NX_MDNS_LABEL_MAX)
        {
            
            *(assemble_pkt_data + *current_len) = *(character - 1);
            *current_len = *current_len + 1;

            /* Simple count, check for space and copy the label.  */
            while(labelSize > 0)
            {

                *(assemble_pkt_data + *current_len) =  *character++;
                *current_len = *current_len + 1;
                labelSize--;
            }
        }
        else if((labelSize & NX_MDNS_COMPRESS_MASK) == NX_MDNS_COMPRESS_VALUE)
        {

            /* This is a pointer, just adjust the source.  */
            if(compressed == NX_FALSE)
                *org_data = character + 1;
            compressed = NX_TRUE;
            character =  assemble_pkt_data + ((labelSize & NX_MDNS_LABEL_MAX) << 8) + *character;
        }
        else
        {

            /* Not defined, just fail */
            return;
        }
    }
    
    /* Null terminate name.  */
    *(assemble_pkt_data + *current_len) =  '\0';
    *current_len = *current_len + 1;
    
    if(compressed == NX_FALSE)
        *org_data = character + 1;
}

static void perform_check_mdns_data(char *pkt_data, int pkt_size, int timeout, int cmd)
{
UINT       status;
NX_PACKET *current_pkt;
ULONG      start_time, current_time, time_remaining;
ULONG      offset, assemble_len;
USHORT     question_cnt;
USHORT     answer_cnt;
USHORT     tmp;
USHORT     type;
USHORT     data_len;
UCHAR     *data_len_ptr;
UCHAR      expect_pkt;

    /* Calculate offset. */
    if((cmd == MDNS_CHECK_DATA_V4) || (cmd == MDNS_REJECT_DATA_V4))
        offset = 28;
    else
        offset = 48;

    /* Whether this packet is expected. */    
    if((cmd == MDNS_REJECT_DATA_V4) || (cmd == MDNS_REJECT_DATA_V6))
        expect_pkt = NX_FALSE;
    else
        expect_pkt = NX_TRUE;

    /* Copy DNS header. */
    memcpy(assemble_pkt_data, pkt_data + 14 + offset, 12);
    assemble_len = 12;
    pkt_data += (26 + offset);

    /* Get counts of question and answer. */
    question_cnt = *((USHORT*)(assemble_pkt_data + 4));
    NX_CHANGE_USHORT_ENDIAN(question_cnt);
    answer_cnt = *((USHORT*)(assemble_pkt_data + 6));
    NX_CHANGE_USHORT_ENDIAN(answer_cnt);
    tmp = *((USHORT*)(assemble_pkt_data + 8));
    NX_CHANGE_USHORT_ENDIAN(tmp);
    answer_cnt += tmp;
    tmp = *((USHORT*)(assemble_pkt_data + 10));
    NX_CHANGE_USHORT_ENDIAN(tmp);
    answer_cnt += tmp;

    /* Decode questions. */
    while(question_cnt)
    {
        decode_mdns_data(&assemble_len, &pkt_data);

        /* Copy fixed data. */
        memcpy(assemble_pkt_data + assemble_len, pkt_data, 4);
        assemble_len += 4;
        pkt_data += 4;

        question_cnt--;
    }

    /* Decode answers. */
    while(answer_cnt)
    {
        decode_mdns_data(&assemble_len, &pkt_data);

        /* Get type. */
        type = *pkt_data;
        type = (type << 8) + *(pkt_data + 1);

        /* Copy fixed data. */
        memcpy(assemble_pkt_data + assemble_len, pkt_data, 10);
        assemble_len += 10;
        pkt_data += 10;

        /* Get data length pointer. */
        data_len_ptr = assemble_pkt_data + assemble_len - 2;

        if((type == NX_MDNS_RR_TYPE_PTR) ||
           (type == NX_MDNS_RR_TYPE_SRV))
        {
        
            /* Need decode. */
            if(type == NX_MDNS_RR_TYPE_SRV)
            {

                /* The first 6 bytes of SRV are fixed. */
                memcpy(assemble_pkt_data + assemble_len, pkt_data, 6);
                assemble_len += 6;
                pkt_data += 6;
            }

            decode_mdns_data(&assemble_len, &pkt_data);

            /* Calculate decoded data length. */
            data_len = (USHORT)(assemble_pkt_data + assemble_len - data_len_ptr) - 2;
            *((USHORT*)data_len_ptr) = data_len;
            NX_CHANGE_USHORT_ENDIAN(*((USHORT*)data_len_ptr));
        }
        else
        {

            /* Nothing to decode. */
            data_len = (*data_len_ptr << 8) | *(data_len_ptr + 1);
            memcpy(assemble_pkt_data + assemble_len, pkt_data, data_len);
            assemble_len += data_len;
            pkt_data += data_len;
        }

        answer_cnt--;
    }
    
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
                if((assemble_len != current_pkt -> nx_packet_length - offset) ||
                   (memcmp(assemble_pkt_data, current_pkt -> nx_packet_prepend_ptr + offset, assemble_len) != 0))
                {
                    /* Not a match. */
                    
                    /* Compute new timeout value. */
                    current_time = tx_time_get();
                    time_remaining = timeout - (current_time - start_time);
                    if((time_remaining > 0x80000000) && (expect_pkt == NX_TRUE))
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

                    if(expect_pkt == NX_FALSE)                
                        error_counter = 1;
                    continue;
                }
            }
        }  
        else
        {
            /* Timeout */  
            if(expect_pkt == NX_TRUE)                
                error_counter = 1;
            time_remaining = 0;
        }
    }
}

static void perform_check_mdns_any(int pkt_size, int timeout, int cmd)
{
UINT       status;
NX_PACKET *current_pkt;
ULONG      start_time, current_time, time_remaining;
ULONG      offset;
USHORT     target_flags = pkt_size;
USHORT     pkt_flags;
USHORT     src_port, dst_port;
UCHAR      expect_pkt;

    /* Calculate offset. */
    if((cmd == MDNS_CHECK_ANY_V4) || (cmd == MDNS_REJECT_ANY_V4))
        offset = 20;
    else
        offset = 40;

    /* Whether this packet is expected. */    
    if((cmd == MDNS_REJECT_ANY_V4) || (cmd == MDNS_REJECT_ANY_V6))
        expect_pkt = NX_FALSE;
    else
        expect_pkt = NX_TRUE;
        
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

                /* Get UDP port. */
                src_port = *((USHORT*)(current_pkt -> nx_packet_prepend_ptr + offset));
                dst_port = *((USHORT*)(current_pkt -> nx_packet_prepend_ptr + offset + 2));

                /* Change endian. */
                NX_CHANGE_USHORT_ENDIAN(src_port);
                NX_CHANGE_USHORT_ENDIAN(dst_port);

                /* Get flags in packet. */
                pkt_flags = *((USHORT*)(current_pkt -> nx_packet_prepend_ptr + offset + 10));

                /* Change endian. */
                NX_CHANGE_USHORT_ENDIAN(pkt_flags);

                /* A packet has been queued.  Examine the content of the packet. */
                if((src_port != 5353) ||
                   (dst_port != 5353) ||
                   (pkt_flags != target_flags))
                {
                    /* Not a match. */
                    
                    /* Compute new timeout value. */
                    current_time = tx_time_get();
                    time_remaining = timeout - (current_time - start_time);
                    if((time_remaining > 0x80000000) && (expect_pkt == NX_TRUE))
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

                    if(expect_pkt == NX_FALSE)                
                        error_counter = 1;
                    continue;
                }
            }
        }  
        else
        {
            /* Timeout */       
            if(expect_pkt == NX_TRUE)                
                error_counter = 1;
            time_remaining = 0;
        }
    }
}

static void perform_mdns_rr_check(NX_MDNS *mdns_ptr, int pkt_size, int cmd)
{

ULONG *head;
NX_MDNS_RR *p;
UCHAR *record_buffer;
UINT buffer_size;
UINT rr_count;

    tx_mutex_get(&mdns_ptr -> nx_mdns_mutex, TX_WAIT_FOREVER);

    /* Get buffer. */
    if(cmd == MDNS_CHECK_RR_COUNT_REMOTE)
    {
        record_buffer = mdns_ptr -> nx_mdns_peer_service_cache;
        buffer_size = mdns_ptr -> nx_mdns_peer_service_cache_size;
    }
    else
    {
        record_buffer = mdns_ptr -> nx_mdns_local_service_cache;
        buffer_size = mdns_ptr -> nx_mdns_local_service_cache_size;
    }

    rr_count = 0;

    /* Get head. */
    head = (ULONG*)record_buffer;
    head = (ULONG*)(*head);

    /* Loop to find record. */
    for(p = (NX_MDNS_RR*)((ULONG*)record_buffer + 1); (ULONG*)p < head; p++)
    {

        /* Check whether the resource record is valid. */
        if ((p -> nx_mdns_rr_state == NX_MDNS_RR_STATE_VALID) ||
            (p -> nx_mdns_rr_state == NX_MDNS_RR_STATE_DELETE))
            rr_count++;
    }

    if(pkt_size != rr_count)
        error_counter = 1;

    tx_mutex_put(&mdns_ptr -> nx_mdns_mutex);
}


#ifndef NX_MDNS_DISABLE_CLIENT
static void perform_mdns_rr_data_check(NX_MDNS *mdns_ptr, char *pkt_data, int pkt_size)
{
MDNS_RR_DATA *rr_data_ptr = (MDNS_RR_DATA*)pkt_data;
UCHAR *buffer = assemble_pkt_data;
UINT index = 0;
NX_MDNS_SERVICE service;

    /* Loop to check RR data. */
    while(pkt_size > 0)
    {

        /* Get service by type and domain. */
        if(nx_mdns_service_lookup(mdns_ptr, NX_NULL, rr_data_ptr -> mdns_rr_data_type, NX_NULL, index, &service))
            error_counter++;
        else
        {
            index++;

            /* Check name fileds. */
            if(strcmp(service.service_name, rr_data_ptr -> mdns_rr_data_name))
               error_counter++;
        }

        pkt_size--;
        rr_data_ptr++;
    }
}
#endif /* NX_MDNS_DISABLE_CLIENT  */


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
    
    /* Mark the packet as IPv6 */
    my_packet -> nx_packet_ip_version = NX_IP_VERSION_V6;
    
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    my_packet -> nx_packet_prepend_ptr += 16;
    my_packet -> nx_packet_append_ptr += 16;
    
    _nx_ip_packet_deferred_receive(ip_ptr, my_packet);

}

static void dump_packets(void)
{

    NX_PACKET *tmp_pkt;
    
    tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
    tmp_pkt = incoming_pkts;
    
    while(tmp_pkt)
    {
        tx_semaphore_get(&pkt_count_sem, 0);
        incoming_pkts = tmp_pkt -> nx_packet_queue_next;
        nx_packet_release(tmp_pkt);
        tmp_pkt = incoming_pkts;
    }
        incoming_pkts = NX_NULL;
    
    tx_mutex_put(&pkt_capture_mutex);
}

void netx_mdns_probing_notify(struct NX_MDNS_STRUCT *mdns_ptr, UCHAR *name, UINT state)
{


    /* Check state. */
    if(probing_callback_state == state)
        probing_callback_invoked++;
}

extern ULONG test_control_successful_tests;
extern ULONG test_control_failed_tests;
void netx_mdns_run_test_case(NX_IP *ip_ptr, NX_MDNS *mdns_ptr, MDNS_TEST_SEQ *test_case, int test_case_size)
{

int steps;
int i;
MDNS_SERVICE *mdns_service;
MDNS_QUERY_INFO *query;
ULONG current_time;
ULONG v4_address;

    /* Init the semaphore and mutex. */
    tx_mutex_create(&pkt_capture_mutex, "TAHI PKT CAPTURE", 0);
    tx_semaphore_create(&pkt_count_sem, "TAHI_PKT COUNT SEM", 0);


    packet_process_callback = packet_process;

    in_cleanup_process = 0;
    error_counter = 0;
    service_callback_state = 0;
    service_callback_invoked = 0;
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
            printf("NetX Test:   MDNS %s TEST", test_case[steps].pkt_data);

            /* Align the output.  */
            for (i = test_case[steps].pkt_size; i <= 47; i++)
                printf(".");

            /* Set the flag to queue up packets. */
            tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
            pkt_capture_flag = 1;
            tx_mutex_put(&pkt_capture_mutex);
            break;
        case INJECT:
            inject_packet(ip_ptr, test_case[steps].pkt_data, test_case[steps].pkt_size);
            break;
        case WAIT:
            tx_thread_sleep(test_case[steps].timeout * NX_IP_PERIODIC_RATE);
            break;
        case MDNS_WAIT_TICK:
            tx_thread_sleep(test_case[steps].timeout * NX_IP_PERIODIC_RATE / 100);
            break;
        case CHECK:
            perform_check(test_case[steps].pkt_data, test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE + NX_MDNS_TIMER_COUNT_RANGE);
            break;
        case MDNS_SET_IPV4_ADDRESS:
            nx_ip_address_set(ip_ptr, test_case[steps].pkt_size, 0xFF000000);
            break;
#if defined FEATURE_NX_IPV6 && defined NX_ENABLE_IPV6_MULTICAST
        case MDNS_LLA_ADD:
            nx_ip_interface_physical_address_set(ip_ptr, 0, test_case[steps].pkt_size, test_case[steps].timeout, NX_TRUE);
            nxd_ipv6_address_set(ip_ptr, 0, NX_NULL, 10, NX_NULL);
            break;
        case MDNS_LLA_DELETE:
            nxd_ipv6_address_delete(ip_ptr, 0);
            break;
#endif /* FEATURE_NX_IPV6 && NX_ENABLE_IPV6_MULTICAST */
        case MDNS_CHECK_DATA_V4:
        case MDNS_CHECK_DATA_V6:
        case MDNS_REJECT_DATA_V4:
        case MDNS_REJECT_DATA_V6:
            perform_check_mdns_data(test_case[steps].pkt_data, test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE + NX_MDNS_TIMER_COUNT_RANGE, test_case[steps].command);
            break;
        case MDNS_CHECK_ANY_V4:
        case MDNS_CHECK_ANY_V6:
        case MDNS_REJECT_ANY_V4:
        case MDNS_REJECT_ANY_V6:
            perform_check_mdns_any(test_case[steps].pkt_size, test_case[steps].timeout* NX_IP_PERIODIC_RATE + NX_MDNS_TIMER_COUNT_RANGE, test_case[steps].command);
            break;
#ifndef NX_MDNS_DISABLE_CLIENT
        case MDNS_QUERY:
            query = (MDNS_QUERY_INFO *)test_case[steps].pkt_data;
            nx_mdns_service_continuous_query(mdns_ptr, query -> name, query -> type, query -> sub_type);
            break;
        case MDNS_QUERY_HOST_ADDRESS:
            nx_mdns_host_address_get(mdns_ptr, test_case[steps].pkt_data, &v4_address, NX_NULL, test_case[steps].timeout* NX_IP_PERIODIC_RATE);
            break;
        case MDNS_QUERY_DELETE:
            nx_mdns_service_query_stop(mdns_ptr, query -> name, query -> type, query -> sub_type);
            break;
        case MDNS_SET_SERVICE_CALLBACK_STATE:
            service_callback_state = test_case[steps].pkt_size;
            service_callback_invoked = test_case[steps].timeout;
            break;
        case MDNS_SET_SERVICE_CALLBACK:
            service_callback_state = test_case[steps].pkt_size;
            service_callback_invoked = test_case[steps].timeout;
            nx_mdns_service_notify_set(mdns_ptr, (ULONG)test_case[steps].pkt_data, service_change_notify);
            break;
        case MDNS_CHECK_SERVICE_CALLBACK_INVOKED:
            if(service_callback_invoked != test_case[steps].timeout)
                error_counter++;
            break;
        case MDNS_CHECK_RR_DATA:
            perform_mdns_rr_data_check(mdns_ptr, test_case[steps].pkt_data, test_case[steps].pkt_size);
            break;
#endif /* NX_MDNS_DISABLE_CLIENT  */
#ifndef NX_MDNS_DISABLE_SERVER
        case MDNS_SERVICE_DELETE:
            mdns_service = (MDNS_SERVICE*)test_case[steps].pkt_data;
            nx_mdns_service_delete(mdns_ptr, mdns_service -> name, mdns_service -> type, mdns_service -> sub_type);
            break;
        case MDNS_SERVICE_ADD:
            mdns_service = (MDNS_SERVICE*)test_case[steps].pkt_data;
            nx_mdns_service_add(mdns_ptr, mdns_service -> name, mdns_service -> type, mdns_service -> sub_type, mdns_service -> txt, 
                                mdns_service -> ttl, mdns_service -> priority, mdns_service -> weights, mdns_service -> port,
                                mdns_service -> set, mdns_service -> if_index);
            break;
#endif /* NX_MDNS_DISABLE_SERVER  */
        case MDNS_SET_PROBING_CALLBACK_STATE:
            probing_callback_state = test_case[steps].pkt_size;
            probing_callback_invoked = test_case[steps].timeout;
            break;
        case MDNS_CHECK_PROBING_CALLBACK_INVOKED:
            if(probing_callback_invoked != test_case[steps].timeout)
                error_counter++;
            break;
        case MDNS_TIMER_RESET:
            tx_time_set(0);
            break;
        case MDNS_TIMER_CHECK:
            current_time = tx_time_get();
            if((current_time < (ULONG)((test_case[steps].timeout - test_case[steps].pkt_size) * NX_IP_PERIODIC_RATE / 100)) || 
               (current_time > (ULONG)((test_case[steps].timeout + test_case[steps].pkt_size) * NX_IP_PERIODIC_RATE / 100)))
                error_counter++;
            break;
        case MDNS_TIMER_MAX_CHECK:
            current_time = tx_time_get();
            if(current_time > (ULONG)(test_case[steps].timeout * NX_IP_PERIODIC_RATE / 100))
                error_counter++;
            break;
        case MDNS_INTERFACE_DISABLE:
            nx_mdns_disable(mdns_ptr, 0);
            break;
        case MDNS_INTERFACE_ENABLE:
            nx_mdns_enable(mdns_ptr, 0);
            break;
        case MDNS_RECREATE:
        {
        NX_PACKET_POOL *pool_ptr = mdns_ptr -> nx_mdns_packet_pool_ptr;
        UCHAR *local_buffer = mdns_ptr -> nx_mdns_local_service_cache;
        UCHAR *remote_buffer = mdns_ptr -> nx_mdns_peer_service_cache;
        UINT local_buffer_size = mdns_ptr -> nx_mdns_local_service_cache_size;
        UINT remote_buffer_size = mdns_ptr -> nx_mdns_peer_service_cache_size;
            
            nx_mdns_delete(mdns_ptr);
            nx_mdns_create(mdns_ptr, ip_ptr, pool_ptr, 2, mdns_stack, DEMO_STACK_SIZE, 
                           test_case[steps].pkt_data, local_buffer, local_buffer_size, remote_buffer, remote_buffer_size, netx_mdns_probing_notify);
            nx_mdns_enable(mdns_ptr, 0);

        }break;
        case MDNS_CHECK_RR_COUNT_REMOTE:
        case MDNS_CHECK_RR_COUNT_LOCAL:
            perform_mdns_rr_check(mdns_ptr, test_case[steps].pkt_size, test_case[steps].command);
            break;
        case DUMP:
            dump_packets();
            break;
        default:
            break;
        }
    }
    /* Set the flag to queue up packets. */
    tx_mutex_get(&pkt_capture_mutex, TX_WAIT_FOREVER);
    pkt_capture_flag = 0;
    packet_process_callback = NX_NULL;
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
#endif
