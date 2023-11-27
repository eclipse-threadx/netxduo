#include   "tx_api.h"
#include   "nx_api.h"
#include   <time.h>

extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_IPV4
#include   "nxd_mdns.h"
#define     DEMO_STACK_SIZE    2048
#define     BUFFER_SIZE        10240

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1[5];
static TX_THREAD               ntest_2[5];

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static TX_SEMAPHORE            sema_0;
static UCHAR                   buffer[BUFFER_SIZE];
static ULONG                   current_buffer_size;
static UCHAR                   mdns_stack[DEMO_STACK_SIZE];
static ULONG                   buffer_org_head;
static ULONG                   buffer_org_tail;
static ULONG                   free_buffer_size;
static UINT                    cache_state;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_2_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);
static void    check_empty_buffer(UCHAR *buffer_ptr, UINT buffer_size);
static void    empty_buffer_init(UCHAR *buffer_ptr, UINT buffer_size);
static VOID    cache_full_notify(NX_MDNS *mdns_ptr, UINT state, UINT cache_tye);

extern UINT    _nx_mdns_cache_add_resource_record(NX_MDNS *mdns_ptr, UINT cache_type, NX_MDNS_RR *record_ptr, NX_MDNS_RR **insert_ptr, UCHAR *is_present, UINT interface_index);
extern UINT    _nx_mdns_cache_delete_resource_record(NX_MDNS *mdns_ptr, UINT cache_type, NX_MDNS_RR *record_ptr);
extern UINT    _nx_mdns_cache_add_string(NX_MDNS *mdns_ptr, UINT cache_type, VOID *string_ptr, UINT string_len, VOID **insert_ptr, UCHAR find_string, UCHAR add_name);
extern UINT    _nx_mdns_cache_delete_string(NX_MDNS *mdns_ptr, UINT cache_type, VOID *string_ptr, UINT string_len);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_internal_function_test(void *first_unused_memory)
#endif
{

UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;
    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, 
                          _nx_ram_network_driver, pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);

    /* Check UDP enable status.  */
    if(status)
        error_counter++;

    status = nx_igmp_enable(&ip_0);

    /* Check status. */
    if(status)
        error_counter++;

    /* Create semaphore. */
    status = tx_semaphore_create(&sema_0, "SEMA 0", 0);

    /* Check status. */
    if(status)
        error_counter++;

    /* Create the test thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, (ULONG)(pointer + DEMO_STACK_SIZE),  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;
}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
CHAR      *pointer = (CHAR*)thread_input;
UINT       i;
NX_MDNS_RR *last_inserted;
NX_MDNS_RR *inserted[3];
ULONG      head;
NX_MDNS_RR rr[3];
UCHAR     *last_inserted_string;
CHAR       test_string[32];
UCHAR     *inserted_strings[4];
CHAR      *test_strings[] = {"First", "Second", "Third", "M"};
ULONG      tail;
NX_MDNS_RR peer_rr;
UINT       rr_count;
UCHAR     *insert_ptr[30];
CHAR      *cache_string[] = {
        "Hello0",
        "World0",
        "Hello world0",
        "Hello world00",
        "Hello world000",
        "Hello world0000",
        "Hello world00000",
        "Hello world000000",
        "Hello world0000000",
        "Hello world00000000",
        "Hello world000000000",
        "Hello world0000000000",
        "Hello world00000000000",
        "Hello world000000000000",
        "Hello world0000000000000",
        "Hello world00000000000000",
        "Hello world000000000000000",
        "Hello world0000000000000000",
        "Hello world00000000000000000",
        "Hello world00000000000000000000000000000000000000000000000000000000000000000111111111111111111111122222222222222"};


    printf("NetX Test:   MDNS Internal Function Test...............................");
    
    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set pointer. */
    pointer = (CHAR*)thread_input;    
            

    /**********************************************************/
    /*          Test Local and Peer cache notify              */
    /**********************************************************/

    /* Create a MDNS instance.  */
    memset(buffer, 0xFF, BUFFER_SIZE);
    current_buffer_size = 512;
    status = _nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
                             buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    pointer += DEMO_STACK_SIZE;

    /* Cache notify test.  */
    status = _nx_mdns_cache_notify_set(&mdns_0, cache_full_notify);
    
    /* Check status. */
    if(status)
        error_counter++;

#ifndef NX_MDNS_DISABLE_SERVER
    /* Test the local buffer full notify.  */
    /* Loop to add string to local buffer until full. */
    i = 0;
    while(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, 
                                    cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE) == NX_SUCCESS)
    {
        i++;
    }
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;

    /* Deleted the strings. */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, insert_ptr[0], 0);

    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;

    /* Delete the string.  */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, insert_ptr[2], 0);
    
    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;

    /* Delete the string.  */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, insert_ptr[4], 0);

    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);    
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;

    /* Delete the string.  */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, insert_ptr[6], 0);

    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);    
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;
    
    /* Delete the string.  */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, insert_ptr[8], 0);

    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);    
    
    /* Check the cache state.  */
    if (cache_state != 2)
        error_counter++;
#endif /* NX_MDNS_DISABLE_SERVER  */

#ifndef NX_MDNS_DISABLE_CLIENT
    /* Test the peer buffer full notify.  */
    /* Loop to add string to local buffer until full. */
    i = 0;
    while(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, 
                                    cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE) == NX_SUCCESS)
    {
        i++;
    }
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;

    /* Deleted the strings. */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, insert_ptr[0], 0);

    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;

    /* Delete the string.  */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, insert_ptr[2], 0);
    
    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;

    /* Delete the string.  */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, insert_ptr[4], 0);

    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);    
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;

    /* Delete the string.  */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, insert_ptr[6], 0);

    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);    
    
    /* Check the cache state.  */
    if (cache_state != 1)
        error_counter++;
    
    /* Delete the string.  */
    _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, insert_ptr[8], 0);

    /* Add the string.  */
    _nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, cache_string[i], strlen(cache_string[i]), (VOID **)&insert_ptr[i], NX_FALSE, NX_TRUE);    
    
    /* Check the cache state.  */
    if (cache_state != 2)
        error_counter++;
#endif /* NX_MDNS_DISABLE_CLIENT  */

    /* Delet the MDNS instance.  */
    _nx_mdns_delete(&mdns_0);

#ifndef NX_MDNS_DISABLE_SERVER
    /**********************************************************/
    /*                    Cache String Test                   */
    /**********************************************************/

    /* Basic string test. */
    /* Initialize the buffer. */
    current_buffer_size = 512;
    memset(buffer, 0xFF, BUFFER_SIZE);
    status = _nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    pointer += DEMO_STACK_SIZE;

    /* Check status. */
    if(status)
        error_counter++;

    empty_buffer_init(buffer, current_buffer_size);

    /* Create 5 threads to test string functions. */
    for(i = 0; i < 5; i++)
    {
        tx_thread_create(&ntest_2[i], "thread 2", ntest_2_entry, i + 1,  
                         pointer, DEMO_STACK_SIZE, 
                         3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

        pointer = pointer + DEMO_STACK_SIZE;
    }

    /* Wait until all threads finish. */
    for(i = 0; i < 5; i++)
    {
        if(tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE))
        {
            error_counter++;
            break;
        }
    }

    check_empty_buffer(buffer, current_buffer_size);
    _nx_mdns_delete(&mdns_0); 
#endif /* NX_MDNS_DISABLE_SERVER  */


#ifndef NX_MDNS_DISABLE_CLIENT
    /**********************************************************/
    /*                  Function Test                         */
    /**********************************************************/
    
    /* Initialize random. */
    srand((UINT)time(0));

    /* Basic RR test. */    
    /* Create a MDNS instance.  */
    current_buffer_size = 512;
    memset(buffer, 0xFF, BUFFER_SIZE);
    status = _nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
                             buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    pointer += DEMO_STACK_SIZE;

    /* Check status. */
    if(status)
        error_counter++;

    empty_buffer_init(buffer + current_buffer_size, current_buffer_size);

    /* Create 5 threads to test string functions. */
    for(i = 0; i < 5; i++)
    {
        tx_thread_create(&ntest_1[i], "thread 1", ntest_1_entry, i + 1,  
                         pointer, DEMO_STACK_SIZE, 
                         3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

        pointer = pointer + DEMO_STACK_SIZE;
    }

    /* Wait until all threads finish. */
    for(i = 0; i < 5; i++)
    {
        if(tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE))
        {
            error_counter++;
            break;
        }
    }

    check_empty_buffer(buffer + current_buffer_size, current_buffer_size);
    _nx_mdns_delete(&mdns_0);
#endif /* NX_MDNS_DISABLE_CLIENT  */

    
#ifndef NX_MDNS_DISABLE_SERVER
    /**********************************************************/
    /*                  Local Cache RR Test                   */
    /**********************************************************/

    /* RR full test. */
    /* Initialize the buffer. */
    current_buffer_size = BUFFER_SIZE >> 1;
    memset(buffer, 0xFF, BUFFER_SIZE);
    status = _nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
                             buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    pointer += DEMO_STACK_SIZE;

    /* Check status. */
    if(status)
        error_counter++;

    empty_buffer_init(buffer, current_buffer_size);

    /* Loop to add resource record to local buffer until full. */
    i = 0;
    memset(&rr[0], 0, sizeof(NX_MDNS_RR));
    do
    {
        rr[0].nx_mdns_rr_name = (UCHAR *)"test";
        rr[0].nx_mdns_rr_type = NX_MDNS_RR_TYPE_A;
        rr[0].nx_mdns_rr_class = (USHORT)i;
        rr[0].nx_mdns_rr_ttl = i;
        rr[0].nx_mdns_rr_rdata_length = (USHORT)i;
        rr[0].nx_mdns_rr_timer_count = 0;
        rr[0].nx_mdns_rr_retransmit_count = (UCHAR)(i + 1);
        rr[0].nx_mdns_rr_state = NX_MDNS_RR_STATE_VALID;
        i++;
    }while(_nx_mdns_cache_add_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, 
                                              &rr[0], &last_inserted, NX_NULL, 0) == NX_SUCCESS);

    i--;

    /* HEAD and TAIL take 4 bytes each. */
    if(i != (free_buffer_size / sizeof(NX_MDNS_RR)))
        error_counter++;
    
    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != i)
        error_counter++;
    if(mdns_0.nx_mdns_local_string_count != 0)
        error_counter++;
    if(mdns_0.nx_mdns_local_string_bytes != 0)
        error_counter++;
    
    /* Delete all inserted resource records. */
    while(i > 0)
    {

        /* Add it again. */
        i--;
        rr[0].nx_mdns_rr_name = (UCHAR *)"test";
        rr[0].nx_mdns_rr_type = NX_MDNS_RR_TYPE_A;
        rr[0].nx_mdns_rr_class = (USHORT)i;
        rr[0].nx_mdns_rr_ttl = i;
        rr[0].nx_mdns_rr_rdata_length = (USHORT)i;
        rr[0].nx_mdns_rr_timer_count = 0;
        rr[0].nx_mdns_rr_retransmit_count = (UCHAR)(i + 1);
        rr[0].nx_mdns_rr_state = NX_MDNS_RR_STATE_VALID;

        if(_nx_mdns_cache_add_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL,
                                              &rr[0], &last_inserted, NX_NULL, 0))
        {

            /* No error is expected. */
            error_counter++;
            break;
        }

        /* Check mdns information. */
        if(mdns_0.nx_mdns_local_rr_count != i + 1)
            error_counter++;

        if(_nx_mdns_cache_delete_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, last_inserted))
        {

            /* No error is expected. */
            error_counter++;
            break;
        }      

        /* Check mdns information. */
        if(mdns_0.nx_mdns_local_rr_count != i)
            error_counter++;
    }

    check_empty_buffer(buffer, current_buffer_size);
    _nx_mdns_delete(&mdns_0);


    /* RR middle usage test. */
    /* Initialize the buffer. */
    current_buffer_size = BUFFER_SIZE >> 1;
    memset(buffer, 0xFF, BUFFER_SIZE);
    status = _nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
                             buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    pointer += DEMO_STACK_SIZE;

    /* Check status. */
    if(status)
        error_counter++;

    empty_buffer_init(buffer, current_buffer_size);

    /* Initialize RRs. */
    memset(&rr, 0, sizeof(rr));
    for(i = 0; i < 3; i++)
    {
        rr[i].nx_mdns_rr_name = (UCHAR *)"test";
        rr[i].nx_mdns_rr_type = NX_MDNS_RR_TYPE_A;
        rr[i].nx_mdns_rr_class = (USHORT)i;
        rr[i].nx_mdns_rr_ttl = i;
        rr[i].nx_mdns_rr_rdata_length = (USHORT)i;
        rr[i].nx_mdns_rr_timer_count = 0;
        rr[i].nx_mdns_rr_retransmit_count = (UCHAR)(i + 1);
        rr[i].nx_mdns_rr_state = NX_MDNS_RR_STATE_VALID;
    }

    /* Add two RRs. */
    if(_nx_mdns_cache_add_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, &rr[0], &inserted[0], NX_NULL, 0))
        error_counter++;

    if(_nx_mdns_cache_add_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, &rr[1], &inserted[1], NX_NULL, 0))
        error_counter++;

    /* Store HEAD. */
    head = *((ULONG*)buffer);

    /* Delete the first resource record. */
    if(_nx_mdns_cache_delete_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, inserted[0]))
            error_counter++;

    /* Add the third RR. */
    if(_nx_mdns_cache_add_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, &rr[2], &inserted[2], NX_NULL, 0))
        error_counter++;

    /* Check HEAD. */
    if(head != *((ULONG*)buffer))
        error_counter++;

    /* Delete all RRs. */
    if(_nx_mdns_cache_delete_resource_record(&mdns_0,NX_MDNS_CACHE_TYPE_LOCAL, inserted[1]))
        error_counter++;
    if(_nx_mdns_cache_delete_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, inserted[2]))
        error_counter++;

    check_empty_buffer(buffer, current_buffer_size);
    _nx_mdns_delete(&mdns_0);
#endif /* NX_MDNS_DISABLE_SERVER  */

    
#ifndef NX_MDNS_DISABLE_CLIENT
    /**********************************************************/
    /*                  Peer Cache RR Test                    */
    /**********************************************************/    
    
    /* Create a MDNS instance.  */
    memset(buffer, 0xFF, BUFFER_SIZE);
    current_buffer_size = 512;
    status = _nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
                             buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    pointer += DEMO_STACK_SIZE;
    
    /* Enable the MDNS function.  */
    _nx_mdns_enable(&mdns_0, 0);

    /* Loop to add resource record to peer buffer. */
    memset(&peer_rr, 0, sizeof(NX_MDNS_RR));
    for (i = 0; i < 100; i++)
    {
        if(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, "test", strlen("test"), (VOID **)&(peer_rr.nx_mdns_rr_name), NX_FALSE, NX_TRUE))
            error_counter++;
        peer_rr.nx_mdns_rr_type = NX_MDNS_RR_TYPE_A;
        peer_rr.nx_mdns_rr_class = (USHORT)i;
        peer_rr.nx_mdns_rr_ttl = i;
        peer_rr.nx_mdns_rr_rdata_length = (USHORT)i;
        peer_rr.nx_mdns_rr_timer_count = 0;
        peer_rr.nx_mdns_rr_retransmit_count = (UCHAR)(i + 1);
        peer_rr.nx_mdns_rr_state = NX_MDNS_RR_STATE_VALID;
        if (_nx_mdns_cache_add_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, 
                                              &peer_rr, &last_inserted, NX_NULL, 0))
            error_counter++;
        
        rr_count = (current_buffer_size - mdns_0.nx_mdns_peer_string_bytes - 2 * sizeof(ULONG)) / sizeof(NX_MDNS_RR);
        if (i > (rr_count - 1))
        {

            /* Check mdns information. */
            if(mdns_0.nx_mdns_peer_rr_count != rr_count)
                error_counter++;
        }
        else
        {

            /* Check mdns information. */
            if(mdns_0.nx_mdns_peer_rr_count != i + 1)
                error_counter++;
        }
    }

    if(_nx_mdns_cache_delete_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, last_inserted))
    {

        /* No error is expected. */
        error_counter++;
    }

    /* Check mdns information. */
    if(mdns_0.nx_mdns_peer_rr_count != (rr_count - 1))
        error_counter++;

    /* Disable the MDNS function.  */
    _nx_mdns_disable(&mdns_0, 0);

    /* Delet the MDNS instance.  */
    _nx_mdns_delete(&mdns_0);
#endif /* NX_MDNS_DISABLE_CLIENT  */


#ifndef NX_MDNS_DISABLE_SERVER  
    /* String full test. */
    /* Initialize the buffer. */
    current_buffer_size = BUFFER_SIZE >> 1;
    memset(buffer, 0xFF, BUFFER_SIZE);
    status = _nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    pointer += DEMO_STACK_SIZE;

    /* Check status. */
    if(status)
        error_counter++; 

    empty_buffer_init(buffer, current_buffer_size);
    /* Loop to add string to local buffer until full. */
    i = 0;
    sprintf(test_string, "%.15d", i);
    while(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, 
                                    test_string, 15, (VOID **)&last_inserted_string, NX_FALSE, NX_TRUE) == NX_SUCCESS)
    {
        i++;
        sprintf(test_string, "%.15d", i);
    }

    /* HEAD and TAIL take 4 bytes each. Each string take 5 extra bytes. */
    if(i != (free_buffer_size / 20))
        error_counter++;

    /* HEAD and TAIL take 4 bytes each. Each string take 5 extra bytes. */
    if(i != (free_buffer_size / 20))
        error_counter++;

    if(mdns_0.nx_mdns_local_rr_count != 0)
        error_counter++;
    if(mdns_0.nx_mdns_local_string_count != i)
        error_counter++;
    if(mdns_0.nx_mdns_local_string_bytes != i * 20)
        error_counter++;    
    /* Delete all inserted strings. */
    while(i > 0)
    {

        /* Add it again. */
        sprintf(test_string, "%.15d", i - 1); 

        if(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL,
                                     test_string, 15, (VOID **)&last_inserted_string, NX_FALSE, NX_TRUE))
        {

            /* No error is expected. */
            error_counter++;
            break;
        }

        /* Check mdns information. */
        if(mdns_0.nx_mdns_local_string_count != i)
            error_counter++;
        if(mdns_0.nx_mdns_local_string_bytes != i * 20)
            error_counter++;

        /* Delete the string twice. */
        if(_nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, last_inserted_string, 0))
        {

            /* No error is expected. */
            error_counter++;
            break;
        }
        if(_nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, last_inserted_string, 0))
        {

            /* No error is expected. */
            error_counter++;
            break;
        }

        /* Check mdns information. */
        if(mdns_0.nx_mdns_local_string_count != (i - 1))
            error_counter++;
        if(mdns_0.nx_mdns_local_string_bytes != (i - 1) * 20)
            error_counter++;

        i--;
    }

    check_empty_buffer(buffer, current_buffer_size);  

    _nx_mdns_delete(&mdns_0);

#endif /* NX_MDNS_DISABLE_SERVER  */

#ifndef NX_MDNS_DISABLE_CLIENT

    /* String full test. */
    /* Initialize the buffer. */
    current_buffer_size = BUFFER_SIZE >> 1;
    memset(buffer, 0xFF, BUFFER_SIZE);
    status = _nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    pointer += DEMO_STACK_SIZE;

    /* Check status. */
    if(status)
        error_counter++; 

    empty_buffer_init(buffer + current_buffer_size, current_buffer_size);

    /* Loop to add string to peer buffer until full. */
    i = 0;
    sprintf(test_string, "%.15d", i);
    while(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, 
                                    test_string, 15, (VOID **)&last_inserted_string, NX_FALSE, NX_TRUE) == NX_SUCCESS)
    {
        i++;
        sprintf(test_string, "%.15d", i);
    }

    /* HEAD and TAIL take 4 bytes each. Each string take 5 extra bytes. */
    if(i != (free_buffer_size / 20))
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_peer_rr_count != 0)
        error_counter++;
    if(mdns_0.nx_mdns_peer_string_count != i)
        error_counter++;
    if(mdns_0.nx_mdns_peer_string_bytes != i * 20)
        error_counter++;

    /* Delete all inserted strings. */
    while(i > 0)
    {

        /* Add it again. */
        sprintf(test_string, "%.15d", i - 1); 

        if(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER,
                                     test_string, 15, (VOID **)&last_inserted_string, NX_FALSE, NX_TRUE))
        {

            /* No error is expected. */
            error_counter++;
            break;
        }

        /* Check mdns information. */
        if(mdns_0.nx_mdns_peer_string_count != i)
            error_counter++;
        if(mdns_0.nx_mdns_peer_string_bytes != i * 20)
            error_counter++;

        /* Delete the string twice. */
        if(_nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, last_inserted_string, 0))
        {

            /* No error is expected. */
            error_counter++;
            break;
        }
        if(_nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, last_inserted_string, 0))
        {

            /* No error is expected. */
            error_counter++;
            break;
        }
        /* Check mdns information. */
        if(mdns_0.nx_mdns_peer_string_count != (i - 1))
            error_counter++;
        if(mdns_0.nx_mdns_peer_string_bytes != (i - 1) * 20)
            error_counter++;

        i--;
    }

    check_empty_buffer(buffer + current_buffer_size, current_buffer_size); 

    _nx_mdns_delete(&mdns_0);
#endif /* NX_MDNS_DISABLE_CLIENT  */


#ifndef NX_MDNS_DISABLE_SERVER
    /* String middle usage. */
    /* Initialize the buffer. */
    current_buffer_size = 512;
    memset(buffer, 0xFF, BUFFER_SIZE);
    status = _nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);

    pointer += DEMO_STACK_SIZE;

    /* Check status. */
    if(status)
        error_counter++;

    empty_buffer_init(buffer, current_buffer_size);

    /* Insert 3 strings. */
    for(i = 0; i < 3; i++)
    {
        if(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL,
                                     test_strings[i], strlen(test_strings[i]), (VOID **)&inserted_strings[i], NX_FALSE, NX_TRUE))
        {

            /* No error is expected. */
            error_counter++;
            break;
        }
    }

    /* Store TAIL. */
    tail = *((ULONG*)buffer + (current_buffer_size >> 2) - 1);
    
    /* Delete the string in middle. */
    if(_nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, inserted_strings[1], 0))
        error_counter++;

    /* Insert a string that is less than deleted one. */
    if(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL,
                                 test_strings[i], strlen(test_strings[i]), (VOID **)&inserted_strings[i], NX_FALSE, NX_TRUE))
        error_counter++;

    /* Check TAIL. */
    if(tail != *((ULONG*)buffer + (current_buffer_size >> 2) - 1))
        error_counter++;

    /* Deleted all strings. */
    for(i = 0; i < 4; i++)
        _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, inserted_strings[i], 0);

    check_empty_buffer(buffer, current_buffer_size);
    _nx_mdns_delete(&mdns_0);
#endif /* NX_MDNS_DISABLE_SERVER  */


    /* Determine if the test was successful.  */
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


static void    ntest_1_entry(ULONG thread_input)
{
CHAR *test_strings[] = {
    "1",
    "a",
    "b",
    "c",
    "MDNS",
    "Hello world0",
    "Hello world1",
    "Hello world1 Hello",
    "Hello hello Hello",
    "Hello Hello Hello Hello",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
};
UINT string_count= sizeof(test_strings) / sizeof(CHAR*);
INT loop_count = 1000;
UINT add_count;
NX_MDNS_RR rr[5];
NX_MDNS_RR *inserted_rr[5];
UCHAR *inserted_strings[5];
UINT index;



    /* Loop 1000 times to add and delete strings */
    while(loop_count > 0)
    {
        if ((loop_count == 0x00000232) &&
            (thread_input == 1))
            thread_input = thread_input;

        if ((loop_count == 0x00000235) &&
            (thread_input == 5))
            thread_input = thread_input;

        /* Initialize variables. */
        add_count = 0;
        memset(rr, 0, sizeof(rr));
        memset(inserted_strings, 0, sizeof(inserted_strings));
        memset(inserted_rr, 0, sizeof(inserted_strings));

        /* Insert records. */
        while(add_count < thread_input)
        {
            
            tx_mutex_get(&mdns_0.nx_mdns_mutex, TX_WAIT_FOREVER);
            if(add_count & 1)
            {

                /* Insert same RR when add_count is odd. */
                memcpy(&rr[add_count], &rr[add_count - 1], sizeof(NX_MDNS_RR));
                if(rr[add_count].nx_mdns_rr_name)
                {
                    if(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL,
                                                 test_strings[index], strlen(test_strings[index]), (VOID **)&rr[add_count].nx_mdns_rr_name, NX_FALSE, NX_TRUE) == NX_SUCCESS)
                    {
                        inserted_strings[add_count] = rr[add_count].nx_mdns_rr_name;

                        /* Insert rr. */
                        if(_nx_mdns_cache_add_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL,
                                                              &rr[add_count], &inserted_rr[add_count], NX_NULL, 0))
                            _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, inserted_strings[add_count], 0);

                    }
                }
            }
            else 
            {
                index = rand() % string_count;
                if(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL,
                                             test_strings[index], strlen(test_strings[index]), (VOID **)&rr[add_count].nx_mdns_rr_name, NX_FALSE, NX_TRUE) == NX_SUCCESS)
                {

                    /* Set random values. */
                    inserted_strings[add_count] = rr[add_count].nx_mdns_rr_name;
                    rr[add_count].nx_mdns_rr_type = NX_MDNS_RR_TYPE_A;
                    rr[add_count].nx_mdns_rr_class = (USHORT)thread_input;
                    rr[add_count].nx_mdns_rr_ttl = add_count + 100;
                    rr[add_count].nx_mdns_rr_rdata_length = rand() % 0xFFFF;
                    rr[add_count].nx_mdns_rr_timer_count = 0;
                    rr[add_count].nx_mdns_rr_retransmit_count = (UCHAR)(rand() % 0xFFFF);
                    rr[add_count].nx_mdns_rr_state = NX_MDNS_RR_STATE_VALID;

                    /* Insert rr. */
                    if(_nx_mdns_cache_add_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL,
                                                           &rr[add_count], &inserted_rr[add_count], NX_NULL, 0))
                        _nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, inserted_strings[add_count], 0);
                                                       
                }
            }

            add_count++;
            loop_count--;
            tx_mutex_put(&mdns_0.nx_mdns_mutex);
            tx_thread_relinquish();

        }

        /* Delete all inserted strings and records. */
        while(add_count--)
        {

            /* No error is expected. */
            tx_mutex_get(&mdns_0.nx_mdns_mutex, TX_WAIT_FOREVER);
            if ((inserted_rr[add_count]) && (inserted_rr[add_count] -> nx_mdns_rr_name))
            {
                _nx_mdns_cache_delete_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, inserted_rr[add_count]);
            }
            tx_mutex_put(&mdns_0.nx_mdns_mutex);
            tx_thread_relinquish();
        }
    }
    tx_semaphore_put(&sema_0);

}


static void    ntest_2_entry(ULONG thread_input)
{
CHAR *test_strings[] = {
    "1",
    "a",
    "b",
    "c",
    "MDNS",
    "Hello world0",
    "Hello world1",
    "Hello world1 Hello",
    "Hello hello Hello",
    "Hello Hello Hello Hello",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
};
UINT string_count= sizeof(test_strings) / sizeof(CHAR*);
INT loop_count = 1000;
UINT add_count;
UCHAR *inserted_strings[5];
UINT index;

    /* Loop 1000 times to add and delete strings */
    while(loop_count > 0)
    {

        /* Initialize variables. */
        add_count = 0;
        memset(inserted_strings, 0, sizeof(inserted_strings));

        /* Insert strings. */
        while(add_count < thread_input)
        {
            index = rand() % string_count;
            tx_mutex_get(&mdns_0.nx_mdns_mutex, TX_WAIT_FOREVER);
            if(_nx_mdns_cache_add_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL,
                                         test_strings[index], strlen(test_strings[index]), (VOID **)&inserted_strings[add_count], NX_FALSE, NX_TRUE))
            {

                /* Only the last string exceed the buffer. */
                if(index != (string_count - 1))
                {
                    tx_mutex_put(&mdns_0.nx_mdns_mutex);
                    error_counter++;
                    tx_semaphore_put(&sema_0);
                    return;
                }
            }
            else
            {
                add_count++;
                loop_count--;
            }
            tx_mutex_put(&mdns_0.nx_mdns_mutex);
            tx_thread_relinquish();
        }

        /* Delete all inserted strings. */
        while(add_count--)
        {

            /* No error is expected. */
            tx_mutex_get(&mdns_0.nx_mdns_mutex, TX_WAIT_FOREVER);
            if(_nx_mdns_cache_delete_string(&mdns_0, NX_MDNS_CACHE_TYPE_LOCAL, inserted_strings[add_count], 0))
            {
                tx_mutex_put(&mdns_0.nx_mdns_mutex);
                error_counter++;
                tx_semaphore_put(&sema_0);
                return;
            }
            tx_mutex_put(&mdns_0.nx_mdns_mutex);
            tx_thread_relinquish();
        }
    }

    tx_semaphore_put(&sema_0);
}


VOID  cache_full_notify(NX_MDNS *mdns_ptr, UINT state, UINT cache_type)
{
    
    switch(state)
    {
        case NX_MDNS_CACHE_STATE_FULL:
        {              

            cache_state = 1; 
            break;
        }
        case NX_MDNS_CACHE_STATE_FRAGMENTED:
        {
            cache_state = 2; 
            break;
        }
        default:
        {
            cache_state = 0; 
            break;
        }
    }
}

static void    check_empty_buffer(UCHAR *buffer_ptr, UINT buffer_size)
{

ULONG     *tail, *head;
UINT       i;

    /* Check the head of buffer. */
    head = (ULONG*)buffer_ptr;
    if(*head != buffer_org_head)
        error_counter++;

    /* Check the tail of buffer. */
    /* Since all strings are deleted, tail should pointer to the end of buffer. */
    tail = (ULONG*)buffer_ptr + (buffer_size >> 2) - 1;
    if(*tail != buffer_org_tail)
        error_counter++;

    /* Check buffer overflow. */
    for(i = (buffer_size << 1); i < buffer_size; i++)
    {
        if(buffer_ptr[i] != 0xFF)
        {
            error_counter++;
            break;
        }
    }
}

static void    empty_buffer_init(UCHAR *buffer_ptr, UINT buffer_size)
{
ULONG     *tail, *head;

    head = (ULONG*)buffer_ptr;
    buffer_org_head = *head;

    tail = (ULONG*)buffer_ptr + (buffer_size >> 2) - 1;
    buffer_org_tail = *tail;

    free_buffer_size = buffer_org_tail - buffer_org_head;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_internal_function_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Internal Function Test...............................N/A\n");
    test_control_return(3);
}
#endif
