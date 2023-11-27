/* This is the test control routine the NetX TCP/IP stack.  All tests are dispatched from this routine.  */

#include "tx_api.h"
#include "nx_api.h"
#include <stdio.h>
#include <stdlib.h>
#include "nx_ram_network_driver_test_1500.h"

/*
#define NETXTEST_TIMEOUT_DISABLE
*/

#define TEST_STACK_SIZE         4096

/* 1 minute. */
#define TEST_TIMEOUT_LOW        (60 * NX_IP_PERIODIC_RATE)
/* 15 minutes. */
#define TEST_TIMEOUT_MID        (900 * NX_IP_PERIODIC_RATE)
/* 120 minutes. */
#define TEST_TIMEOUT_HIGH       (7200 * NX_IP_PERIODIC_RATE)

/* Define the test control ThreadX objects...  */

TX_THREAD       test_control_thread;
#ifndef NETXTEST_TIMEOUT_DISABLE
TX_SEMAPHORE    test_control_sema;
#endif

/* Define the test control global variables.   */

ULONG           test_control_return_status;
ULONG           test_control_successful_tests;
ULONG           test_control_failed_tests;
ULONG           test_control_warning_tests;
ULONG           test_control_na_tests;

/* Remember the start of free memory.  */

UCHAR           *test_free_memory_ptr;

extern volatile UINT   _tx_thread_preempt_disable;

/* Define test entry pointer type.  */

typedef  struct TEST_ENTRY_STRUCT
{
    VOID        (*test_entry)(void *);
    UINT        timeout;
} TEST_ENTRY;


/* Define the prototypes for the test entry points.  */
void    netx_mqtt_api_test_application_define(void*);
void    netx_mqtt_client_connect_application_define(void*);
void    netx_mqtt_client_connect_packet_send_failure_application_define(void*);
void    netx_mqtt_client_connect_v6_application_define(void*);
void    netx_mqtt_client_connect_non_block_application_define(void*);
void    netx_mqtt_client_connect_non_block_2_application_define(void*);
void    netx_mqtt_client_connect_auth_application_define(void*);
void    netx_mqtt_client_connect_auth_empty_application_define(void*);
void    netx_mqtt_client_null_password_application_define(void *);
void    netx_mqtt_client_subscribe_application_define(void*);
void    netx_mqtt_client_unsubscribe_application_define(void*);
void    netx_mqtt_client_publish_QoS0_application_define(void *);
void    netx_mqtt_client_publish_QoS1_application_define(void *);
void    netx_mqtt_client_publish_QoS2_application_define(void *);
void    netx_mqtt_client_receive_QoS0_application_define(void *);
void    netx_mqtt_client_receive_QoS1_application_define(void *);
void    netx_mqtt_client_receive_QoS2_application_define(void *);
void    netx_mqtt_client_connect_will_message_application_define(void *);
void    netx_mqtt_client_connect_auth_will_application_define(void *);
void    netx_mqtt_client_connect_will_topic_only_application_define(void *);
void    netx_mqtt_not_connected_application_define(void *);
void    netx_mqtt_client_keepalive_application_define(void*);
void    netx_mqtt_client_keepalive_timeout_application_define(void*);
void    netx_mqtt_client_multiple_receive_application_define(void*);
void    netx_mqtt_remaining_length_test(void *);
void    netx_mqtt_client_publish_non_zero_packet_id_application_define(void*);
void    netx_mqtt_client_subscribe_non_zero_packet_id_application_define(void*);
void    netx_mqtt_client_packet_leak_application_define(void *);
void    netx_mqtt_client_receive_span_application_define(void *first_unused_memory);
void    netx_mqtt_client_publish_packet_chain_application_define(void *);
void    netx_mqtt_client_subscribe_packet_chain_application_define(void *);
void    netx_mqtt_client_connack_error_application_define(void *);
void    netx_mqtt_client_branch_application_define(void *);
void    netx_mqtt_websocket_non_block_test_application_define(void *);
void    netx_mqtt_websocket_block_test_application_define(void *);
#ifdef CTEST
void    test_application_define(void *);
#endif


/* Define the array of test entry points.  */

TEST_ENTRY  test_control_tests[] = 
{
#ifdef CTEST
    {test_application_define, TEST_TIMEOUT_LOW},
#else /* CTEST */
    {netx_mqtt_remaining_length_test, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_receive_QoS0_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_receive_QoS1_application_define, TEST_TIMEOUT_LOW},
    /*{netx_mqtt_client_receive_QoS2_application_define, TEST_TIMEOUT_LOW},*/
    {netx_mqtt_client_publish_QoS0_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_publish_QoS1_application_define, TEST_TIMEOUT_LOW},
    /* {netx_mqtt_client_publish_QoS2_application_define, TEST_TIMEOUT_LOW}, */
    {netx_mqtt_client_subscribe_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_unsubscribe_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connect_auth_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connect_auth_empty_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connect_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connect_v6_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connect_non_block_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connect_non_block_2_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_null_password_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_api_test_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connect_will_message_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connect_will_topic_only_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connect_auth_will_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_not_connected_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_keepalive_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_keepalive_timeout_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_multiple_receive_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_publish_non_zero_packet_id_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_subscribe_non_zero_packet_id_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_packet_leak_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_receive_span_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_publish_packet_chain_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_subscribe_packet_chain_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_connack_error_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_client_branch_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_websocket_non_block_test_application_define, TEST_TIMEOUT_LOW},
    {netx_mqtt_websocket_block_test_application_define, TEST_TIMEOUT_LOW},
#endif /* CTEST */

    {TX_NULL, TEST_TIMEOUT_LOW},
};

/* Define thread prototypes.  */

void  test_control_thread_entry(ULONG thread_input);
void  test_control_return(UINT status);
void  test_control_cleanup(void);
void  _nx_ram_network_driver_reset(void);

/* Define necessary external references.  */

#ifdef __ghs
extern TX_MUTEX                 __ghLockMutex;
#endif

extern TX_TIMER                 *_tx_timer_created_ptr;
extern ULONG                    _tx_timer_created_count;
#ifndef TX_TIMER_PROCESS_IN_ISR
extern TX_THREAD                _tx_timer_thread;
#endif
extern TX_THREAD                *_tx_thread_created_ptr;
extern ULONG                    _tx_thread_created_count;
extern TX_SEMAPHORE             *_tx_semaphore_created_ptr;
extern ULONG                    _tx_semaphore_created_count;
extern TX_QUEUE                 *_tx_queue_created_ptr;
extern ULONG                    _tx_queue_created_count;
extern TX_MUTEX                 *_tx_mutex_created_ptr;
extern ULONG                    _tx_mutex_created_count;
extern TX_EVENT_FLAGS_GROUP     *_tx_event_flags_created_ptr;
extern ULONG                    _tx_event_flags_created_count;
extern TX_BYTE_POOL             *_tx_byte_pool_created_ptr;
extern ULONG                    _tx_byte_pool_created_count;
extern TX_BLOCK_POOL            *_tx_block_pool_created_ptr;
extern ULONG                    _tx_block_pool_created_count;

extern NX_PACKET_POOL *         _nx_packet_pool_created_ptr;
extern ULONG                    _nx_packet_pool_created_count;
extern NX_IP *                  _nx_ip_created_ptr;
extern ULONG                    _nx_ip_created_count; 

/* Define main entry point.  */

int main()
{
    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();


    return 0;
}

//#define TEST_FREE_MEMORY_POOL_SIZE (100 * 1024)
//static ULONG test_free_memory_pool[TEST_FREE_MEMORY_POOL_SIZE / sizeof(ULONG)];
/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{
    UCHAR    *pointer;

    /* Setup a pointer to the first unused memory.  */
    pointer = (UCHAR *)   first_unused_memory; 

    /* Create the test control thread.  */
    tx_thread_create(&test_control_thread, "test control thread", test_control_thread_entry, 0,  
        pointer, TEST_STACK_SIZE, 
        0, 0, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + TEST_STACK_SIZE;
    
#ifndef NETXTEST_TIMEOUT_DISABLE
    /* Create the test control semaphore.  */
    tx_semaphore_create(&test_control_sema, "Test control semaphore", 0);
#endif

    /* Remember the free memory pointer.  */
    //test_free_memory_ptr = (UCHAR*)test_free_memory_pool;
    test_free_memory_ptr = pointer;
}

/* Define the test control thread.  This thread is responsible for dispatching all of the 
tests in the ThreadX test suite.  */

void  test_control_thread_entry(ULONG thread_input)
{
    UINT    i;

    /* Loop to process all tests...  */
    i = 0;
    while (test_control_tests[i].test_entry != TX_NULL)
    {

        /* Dispatch the test.  */
        (test_control_tests[i++].test_entry)(test_free_memory_ptr);

        if (test_control_return_status != 3)
        {

#ifdef NETXTEST_TIMEOUT_DISABLE
            /* Suspend control test to allow test to run.  */
            tx_thread_suspend(&test_control_thread);
#else
            if(tx_semaphore_get(&test_control_sema, test_control_tests[i - 1].timeout))
            {

                /* Test case timeouts. */
                printf("ERROR!\n");
                test_control_failed_tests++;

            }
#endif
        }
        else
            test_control_return_status = 0;    

        /* Test finished, cleanup in preparation for the next test.  */
        test_control_cleanup();
        fflush(stdout);
    }

    /* Finished with all tests, print results and return!  */
    printf("**** Testing Complete ****\n");
    printf("**** Test Summary:  Tests Passed:  %lu   Tests Warning:  %lu   Tests Failed:  %lu\n", test_control_successful_tests, test_control_warning_tests, test_control_failed_tests);
#if 0
    fclose(stream);
#endif
#ifdef BATCH_TEST
    exit(test_control_failed_tests);
#endif


}

void  test_control_return(UINT status)
{
    UINT    old_posture = TX_INT_ENABLE;

    /* Save the status in a global.  */
    test_control_return_status = status;

    /* Ensure interrupts are enabled.  */
    old_posture = tx_interrupt_control(TX_INT_ENABLE);

    /* Determine if it was successful or not.  */
    if((status == 1) || (_tx_thread_preempt_disable) || (old_posture == TX_INT_DISABLE))       
        test_control_failed_tests++;
    else if(status == 2)
        test_control_warning_tests++;
    else if(status == 0)
        test_control_successful_tests++;
    else if(status == 3)
        test_control_na_tests++;

#ifdef NETXTEST_TIMEOUT_DISABLE
    /* Resume the control thread to fully exit the test.  */
    tx_thread_resume(&test_control_thread);
#else
    if(test_control_return_status != 3)
        tx_semaphore_put(&test_control_sema);
#endif
}

void  test_control_cleanup(void)
{
    TX_MUTEX        *mutex_ptr;
    TX_THREAD       *thread_ptr;

    /* Clean timer used by RAM driver. */
    _nx_ram_network_driver_timer_clean();

    /* Delete all IP instances.   */
    while (_nx_ip_created_ptr)
    {

        /* Delete all UDP sockets.  */
        while (_nx_ip_created_ptr -> nx_ip_udp_created_sockets_ptr)
        {

            /* Make sure the UDP socket is unbound.  */
            nx_udp_socket_unbind(_nx_ip_created_ptr -> nx_ip_udp_created_sockets_ptr);

            /* Delete the UDP socket.  */
            nx_udp_socket_delete(_nx_ip_created_ptr -> nx_ip_udp_created_sockets_ptr);
        }

        /* Delete all TCP sockets.  */
        while (_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr)
        {

            /* Disconnect.  */
            nx_tcp_socket_disconnect(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr, NX_NO_WAIT);

            /* Make sure the TCP client socket is unbound.  */
            nx_tcp_client_socket_unbind(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr);

            /* Make sure the TCP server socket is unaccepted.  */
            nx_tcp_server_socket_unaccept(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr);

            /* Delete the TCP socket.  */
            nx_tcp_socket_delete(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr);
        }

        /* Clear all listen requests.  */
        while (_nx_ip_created_ptr -> nx_ip_tcp_active_listen_requests)
        {

            /* Make sure the TCP server socket is unlistened.  */
            nx_tcp_server_socket_unlisten(_nx_ip_created_ptr, (_nx_ip_created_ptr -> nx_ip_tcp_active_listen_requests) -> nx_tcp_listen_port);
        }

        /* Delete the IP instance.  */
        nx_ip_delete(_nx_ip_created_ptr);
    }

    /* Delete all the packet pools.  */
    while (_nx_packet_pool_created_ptr)
    {
        nx_packet_pool_delete(_nx_packet_pool_created_ptr);
    }

    /* Reset the RAM driver.  */
    _nx_ram_network_driver_reset();

    /* Delete all queues.  */
    while(_tx_queue_created_ptr)
    {

        /* Delete queue.  */
        tx_queue_delete(_tx_queue_created_ptr);
    }

    /* Delete all semaphores.  */
    while(_tx_semaphore_created_ptr)
    {
#ifndef NETXTEST_TIMEOUT_DISABLE
        if(_tx_semaphore_created_ptr != &test_control_sema)
        {

            /* Delete semaphore.  */
            tx_semaphore_delete(_tx_semaphore_created_ptr);
        }
        else if(_tx_semaphore_created_count == 1)
            break;
        else
        {
            /* Delete semaphore.  */
            tx_semaphore_delete(_tx_semaphore_created_ptr -> tx_semaphore_created_next);
        }
#else
        /* Delete semaphore.  */
        tx_semaphore_delete(_tx_semaphore_created_ptr);
#endif
    }

    /* Delete all event flag groups.  */
    while(_tx_event_flags_created_ptr)
    {

        /* Delete event flag group.  */
        tx_event_flags_delete(_tx_event_flags_created_ptr);
    }

    /* Delete all byte pools.  */
    while(_tx_byte_pool_created_ptr)
    {

        /* Delete byte pool.  */
        tx_byte_pool_delete(_tx_byte_pool_created_ptr);
    }

    /* Delete all block pools.  */
    while(_tx_block_pool_created_ptr)
    {

        /* Delete block pool.  */
        tx_block_pool_delete(_tx_block_pool_created_ptr);
    }

    /* Delete all timers.  */
    while(_tx_timer_created_ptr)
    {

        /* Deactivate timer.  */
        tx_timer_deactivate(_tx_timer_created_ptr);

        /* Delete timer.  */
        tx_timer_delete(_tx_timer_created_ptr);
    }

    /* Delete all mutexes (except for system mutex).  */
    while(_tx_mutex_created_ptr)
    {

        /* Setup working mutex pointer.  */
        mutex_ptr = _tx_mutex_created_ptr;

#ifdef __ghs

        /* Determine if the mutex is the GHS system mutex.  If so, don't delete!  */
        if(mutex_ptr == &__ghLockMutex)
        {

            /* Move to next mutex.  */
            mutex_ptr = mutex_ptr -> tx_mutex_created_next;
        }

        /* Determine if there are no more mutexes to delete.  */
        if(_tx_mutex_created_count == 1)
            break;
#endif

        /* Delete mutex.  */
        tx_mutex_delete(mutex_ptr);
    }

    /* Delete all threads, except for timer thread, and test control thread.  */
    while (_tx_thread_created_ptr)
    {

        /* Setup working pointer.  */
        thread_ptr = _tx_thread_created_ptr;

#ifdef TX_TIMER_PROCESS_IN_ISR

        /* Determine if there are more threads to delete.  */
        if(_tx_thread_created_count == 1)
            break;

        /* Determine if this thread is the test control thread.  */
        if(thread_ptr == &test_control_thread)
        {

            /* Move to the next thread pointer.  */
            thread_ptr = thread_ptr -> tx_thread_created_next;
        }
#else

        /* Determine if there are more threads to delete.  */
        if(_tx_thread_created_count == 2)
            break;

        /* Move to the thread not protected.  */
        while ((thread_ptr == &_tx_timer_thread) || (thread_ptr == &test_control_thread))
        {

            /* Yes, move to the next thread.  */
            thread_ptr = thread_ptr -> tx_thread_created_next;
        }
#endif

        /* First terminate the thread to ensure it is ready for deletion.  */
        tx_thread_terminate(thread_ptr);

        /* Delete the thread.  */
        tx_thread_delete(thread_ptr);
    }

    /* At this point, only the test control thread and the system timer thread and/or mutex should still be
    in the system.  */


}

void SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number)
{
    *error_counter = (*error_counter) + 1;

    printf("Error: File %s:%d\n", filename, line_number);



}
