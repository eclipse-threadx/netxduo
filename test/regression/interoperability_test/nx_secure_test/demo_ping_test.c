#include "tls_test_frame.h"

/* Declare the test entries of two test instances. */
INT demo_func_entry_0(TLS_TEST_INSTANCE* instance_ptr);
INT demo_func_entry_1(TLS_TEST_INSTANCE* instance_ptr);

/* Declare global semaphore pointers. */
TLS_TEST_SEMAPHORE* semaphore_server_prepared;
TLS_TEST_SEMAPHORE* semaphore_client_terminated;

INT main( INT argc, CHAR* argv[])
{
INT status;
TLS_TEST_INSTANCE* ins0;
TLS_TEST_INSTANCE* ins1;
TLS_TEST_DIRECTOR* director;
INT exit_status[2], i;

    /* Create two test instances. */
    status = tls_test_instance_create(&ins0,              /* test instance ptr */
                                      "icmp_server",      /* instance name */
                                      demo_func_entry_0,  /* test entry */
                                      0,                  /* delay(seconds) */
                                      40000,                 /* timeout(seconds) */
                                      1024,               /* shared buffer size */
                                      NULL);              /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_create(&ins1, 
                                      "icmp_client",
                                      demo_func_entry_1,
                                      1,
                                      40000,
                                      1024,
                                      NULL);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Create two semaphore and set the initial value as 0. */
    status = tls_test_semaphore_create(&semaphore_server_prepared, 0/* initial value */);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);
    status = tls_test_semaphore_create(&semaphore_client_terminated, 0);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Create the test director. */
    status = tls_test_director_create(&director, NULL/* description (reserved) */);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Register test instances to the test director. */
    status = tls_test_director_register_test_instance(director, ins0);
    status += tls_test_director_register_test_instance(director, ins1);
    return_value_if_fail(TLS_TEST_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Launch test. */
    status = tls_test_director_test_start(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Error checking. */
    tls_test_instance_show_exit_status(ins0);
    tls_test_instance_show_exit_status(ins1);

    /* Record exit codes. */
    status = tls_test_instance_get_exit_status(ins0, &(exit_status[0]));
    status += tls_test_instance_get_exit_status(ins1, &(exit_status[1]));
    return_value_if_fail(TLS_TEST_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Destroy the director and the registered instances. */
    status = tls_test_director_clean_all(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Destroy semaphores. */
    tls_test_semaphore_destroy(semaphore_server_prepared);
    tls_test_semaphore_destroy(semaphore_client_terminated);

    return exit_status[0] | exit_status[1];
}

/* Call external program as test entry */
INT demo_func_entry_1(TLS_TEST_INSTANCE* instance_ptr)
{
INT exit_status;
INT status;
/* Define an array of strings as the arguments of external program. */
/* Note: the last element of the array must be NULL. */
CHAR* external_cmd[] = { "ping", TLS_TEST_IP_ADDRESS_STRING, "-c", "4", (CHAR*)NULL};

    /* Wait for server prepared. */
    tls_test_semaphore_wait(semaphore_server_prepared);

    /* Call external program to ping the icmp server. */
    /* The exit code of external program will be stored in the contorl block of current instance . */
    tls_test_launch_external_test_process(&exit_status, external_cmd);

    /* Post another semaphore after the icmp test. */
    tls_test_semaphore_post(semaphore_client_terminated);

    /* Check for the exit status of external program. */
    return_value_if_fail(0 == exit_status, TLS_TEST_INSTANCE_EXTERNAL_PROGRAM_FAILED);
    return TLS_TEST_SUCCESS;
}

static TLS_TEST_INSTANCE* demo_instance;

/* Create a threax device as an icmp echo server. */
INT demo_func_entry_0(TLS_TEST_INSTANCE* instance_ptr)
{  
VOID* shm;
INT status;

    /* Store the address of current instance control block in static variable for we don't have the method passing parameters to ThreadX kernel. */
    demo_instance = instance_ptr;

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
}

/* Define the ThreadX and NetX object control blocks...  */
NX_PACKET_POOL    pool_0;
NX_IP             ip_0;  
UCHAR tls_packet_buffer[4000];

/* Define the IP thread's stack area.  */
ULONG             ip_thread_stack[3 * 1024 / sizeof(ULONG)];

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)
ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

/* Define the ARP cache area.  */
ULONG             arp_space_area[512 / sizeof(ULONG)];

/* Define the demo thread.  */
ULONG             demo_thread_stack[6 * 1024 / sizeof(ULONG)];
TX_THREAD         demo_thread;

/* Pcap network driver.  */
VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* Declare a thread entry. */
VOID demo_thread_entry(ULONG thread_input);

/* Define what the initial system looks like.  */
void    tx_application_define(void *first_unused_memory)
{
ULONG gateway_ipv4_address;
UINT  status;

    /* Initialize the NetX system.  */
    nx_system_initialize();
    
    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", TLS_TEST_IP_ADDRESS_NUMBER, 0xFFFFFF00UL, &pool_0, _nx_pcap_network_driver, (UCHAR*)ip_thread_stack, sizeof(ip_thread_stack), 1);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *)arp_space_area, sizeof(arp_space_area));
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    status =  nx_ip_fragment_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Post the semaphore to enable icmp test. */
    tls_test_semaphore_post(semaphore_server_prepared);

    /* Create an new thread waiting for the termination of icmp test. */
    tx_thread_create(&demo_thread, "demo thread", demo_thread_entry, 0, demo_thread_stack, sizeof(demo_thread_stack), 16, 16, 4, TX_AUTO_START);
}

/* The function entry of the thread created by tx_thread_create. */
VOID demo_thread_entry(ULONG thread_input)
{
    INT status;

    /* Wait fot the termination of icmp test. */
    /* Wait until success to avoid system call being interrupted by SIGUSR1. */
    tls_test_semaphore_wait(semaphore_client_terminated);

    exit(0);
}
