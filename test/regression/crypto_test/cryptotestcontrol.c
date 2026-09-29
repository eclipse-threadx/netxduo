/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation 
 * Copyright (c) 2026 Eclipse ThreadX contributors
 * 
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 * 
 * SPDX-License-Identifier: MIT
 **************************************************************************/

// Portions of this file were generated with AI assistance.

/* This is the test control routine the NetX TCP/IP stack.  All tests are dispatched from this routine.  */
#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "tx_api.h"
#include "nx_api.h"
#else
#include "nx_crypto_port.h"
#endif
#include <stdio.h>
#include "nx_crypto.h"

#if defined(__linux__) && defined(USE_FORK)
#undef __suseconds_t_defined
#undef _STRUCT_TIMEVAL
#undef _SYS_SELECT_H
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/poll.h>

void fork_child();
#endif

/*
#define NETXTEST_TIMEOUT_DISABLE
*/

#ifdef NX_CRYPTO_STANDALONE_ENABLE
#define tx_kernel_enter()  test_application_define(0);
#endif
 FILE *stream;

#define TEST_STACK_SIZE         4096

#ifdef NX_CRYPTO_STANDALONE_ENABLE
#define NX_IP_PERIODIC_RATE  100
#endif

/* 1 minute. */
#define TEST_TIMEOUT_LOW        (60 * NX_IP_PERIODIC_RATE)
/* 15 minutes. */
#define TEST_TIMEOUT_MID        (900 * NX_IP_PERIODIC_RATE)
/* 120 minutes. */
#define TEST_TIMEOUT_HIGH       (7200 * NX_IP_PERIODIC_RATE)

/* Define the test control ThreadX objects...  */
#ifndef NX_CRYPTO_STANDALONE_ENABLE
TX_THREAD       test_control_thread;
#ifndef NETXTEST_TIMEOUT_DISABLE
TX_SEMAPHORE    test_control_sema;
#endif
#endif

/* Define the test control global variables.   */

ULONG           test_control_return_status;
ULONG           test_control_successful_tests;
ULONG           test_control_failed_tests;
ULONG           test_control_warning_tests;
ULONG           test_control_na_tests;

/* Remember the start of free memory.  */

UCHAR           *test_free_memory_ptr;
#ifndef NX_CRYPTO_STANDALONE_ENABLE
extern volatile UINT   _tx_thread_preempt_disable;
#endif
/* Define test entry pointer type.  */

typedef  struct TEST_ENTRY_STRUCT
{
    VOID        (*test_entry)(void *);
    UINT        timeout;
} TEST_ENTRY;


/* Define the prototypes for the test entry points.  */
void nx_secure_3des_test_application_define(void *first_unused_memory);
void nx_secure_3des_error_checking_test_application_define(void *first_unused_memory);
void nx_secure_des_test_application_define(void *first_unused_memory);
void nx_secure_des_error_checking_test_application_define(void *first_unused_memory);
void nx_secure_drbg_test_application_define(void *first_unused_memory);
void nx_secure_ec_test_application_define(void *first_unused_memory);
void nx_secure_ec_additional_test_application_define(void *first_unused_memory);
void nx_secure_ecdh_test_application_define(void *first_unused_memory);
void nx_secure_ecdh_error_checking_test_application_define(void *first_unused_memory);
void nx_secure_ecdh_self_test_application_define(void *first_unused_memory);
void nx_secure_ecdsa_test_application_define(void *first_unused_memory);
void nx_secure_ecdsa_error_checking_test_application_define(void *first_unused_memory);
void nx_secure_ecjpake_self_test_application_define(void *first_unused_memory);
void nx_secure_aes_additional_test_application_define(void *first_unused_memory);
void nx_secure_sha_additional_test_application_define(void *first_unused_memory);
void nx_secure_sha256_test_application_define(void *);
void nx_secure_sha256_rfc_test_application_define(void *);
void nx_secure_sha384_test_application_define(void *);
void nx_secure_sha512_test_application_define(void *);
void nx_secure_hmac_md5_test_application_define(void *first_unused_memory);
void nx_secure_hmac_md5_error_checking_test_application_define(void *first_unused_memory);
void nx_secure_hmac_sha1_test_application_define(void *first_unused_memory);
void nx_secure_hmac_sha256_test_application_define(void *);
void nx_secure_hmac_sha384_test_application_define(void *);
void nx_secure_hmac_sha512_test_application_define(void *);
void nx_secure_huge_number_test_application_define(void *first_unused_memory);
void nx_secure_md5_test_application_define(void *first_unused_memory);
void nx_secure_rsa_test_application_define(void *);
void nx_secure_rsa_error_checking_test_application_define(void *);
void nx_secure_aes_test_application_define(void *first_unused_memory);
void nx_secure_aes_ccm_test_application_define(void *first_unused_memory);
void nx_secure_phash_prf_test_application_define(void *);
void nx_secure_pkcs1_v1_5_test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory);

#define INCLUDE_TWO_WAY_TEST 1

#ifdef NX_SECURE_TLS_CLIENT_DISABLED
#undef INCLUDE_TWO_WAY_TEST
#define INCLUDE_TWO_WAY_TEST 0
#endif

#ifdef NX_SECURE_TLS_SERVER_DISABLED
#undef INCLUDE_TWO_WAY_TEST
#define INCLUDE_TWO_WAY_TEST 0
#endif

/* Define the array of test entry points.  */

TEST_ENTRY  test_control_tests[] =
{

#ifdef CTEST
    {test_application_define, TEST_TIMEOUT_HIGH},
#else /* CTEST */
    /* Crypto test. */
    {nx_secure_des_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_des_error_checking_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_drbg_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_ec_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_ec_additional_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_ecdh_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_ecdh_error_checking_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_ecdh_self_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_ecdsa_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_ecdsa_error_checking_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_ecjpake_self_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_3des_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_3des_error_checking_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha256_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha256_rfc_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha384_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha512_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha_additional_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_md5_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_md5_error_checking_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_sha1_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_sha256_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_sha384_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_sha512_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_huge_number_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_md5_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_rsa_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_rsa_error_checking_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_aes_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_aes_additional_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_aes_ccm_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_phash_prf_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_pkcs1_v1_5_test_application_define, TEST_TIMEOUT_LOW},
#endif /* CTEST */
    {NX_CRYPTO_NULL, TEST_TIMEOUT_LOW},
};

/* Define thread prototypes.  */

void  test_control_thread_entry(ULONG thread_input);
void  test_control_return(UINT status);
void  test_control_cleanup(void);
void  _nx_ram_network_driver_reset(void);

/* Define necessary external references.  */
#ifndef NX_CRYPTO_STANDALONE_ENABLE
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
#endif

/* Define main entry point.  */
int main()
{

#ifdef NX_CRYPTO_SELF_TEST
    nx_crypto_initialize();

    _nx_crypto_method_self_test(0);
#endif

#if 0
    /* Reassign "stdout" to "freopen.out": */
    stream = freopen( "test_result.txt", "w", stdout );
#endif

#if defined(__linux__) && defined(USE_FORK)
    fork_child();
#else

    /* Enter the ThreadX kernel or use the test_application_define mapped to tx_kernel_enter when NX_CRYPTO_STANDALONE_ENABLE  */
    tx_kernel_enter();

#endif

#if defined(NX_CRYPTO_STANDALONE_ENABLE) && defined(BATCH_TEST)

    /* Without the kernel there is no control thread, so tx_kernel_enter above
       ran the test on this stack and returned here.  The summary and the exit
       status are reported from this point, because the control thread that
       normally reports them was never created and a verdict that reaches no
       exit status is a test that cannot fail.  */
    printf("**** Testing Complete ****\n");
    printf("**** Test Summary:  Tests Passed:  %lu   Tests Warning:  %lu   Tests Failed:  %lu\n", test_control_successful_tests, test_control_warning_tests, test_control_failed_tests);
    fflush(stdout);

    /* Report the verdict through the exit status: a failure outranks an N/A,
       and an N/A outranks a pass.  A test whose subject matter is compiled
       out of this configuration then reaches ctest as a skip rather than as a
       pass.  Under CTEST the binary holds one test, so each count is 0 or 1.  */
    if (test_control_failed_tests)
        exit((INT)test_control_failed_tests);
    else if (test_control_na_tests)
        exit(3);
    else
        exit(0);
#endif

    return 0;
}

#if defined(__linux__) && defined(USE_FORK)
static pid_t child_pid = -1;
static UINT test_index = 0;
static int result_fd[2];

void kill_child(int sig)
{
CHAR data[4]={0, 1, 0, 0};

    printf("killed by SIGALRM!\n");
    fflush(stdout);
    write(result_fd[1], data, sizeof(data));
    exit(1);
}

void fork_child()
{
INT status;
CHAR data[4];
struct pollfd fds;

    while (test_control_tests[test_index].test_entry != NX_CRYPTO_NULL)
    {

        /* Create pipe for communicating. */
        pipe(result_fd);
        fds.fd = result_fd[0];
        fds.events=POLLIN | POLLOUT | POLLERR;

        /* Fork test process. */
        child_pid = fork();
        if (child_pid > 0)
        {
            wait(&status);
            poll(&fds, 1, 0);
            if (fds.revents & POLLIN)
            {
                read(result_fd[0], data, sizeof(data));
                test_control_successful_tests += (ULONG)data[0];
                test_control_failed_tests += (ULONG)data[1];
                test_control_warning_tests += (ULONG)data[2];
                test_control_na_tests += (ULONG)data[3];
            }
            else
            {

                /* The child process crashes. */
                printf("ERROR!\n");
                test_control_failed_tests++;
            }

            fflush(stdout);

            test_index++;
        }
        else
        {

            /* Setup SIGALRM callback function. */
            signal(SIGALRM, (void (*)(int))kill_child);

            /* Initialize the results. */
            test_control_successful_tests = 0;
            test_control_failed_tests = 0;
            test_control_warning_tests = 0;
            test_control_na_tests = 0;

            /* Setup timeout alarm. */
            alarm(test_control_tests[test_index].timeout / NX_IP_PERIODIC_RATE);

            /* Enter the ThreadX kernel.  */
            tx_kernel_enter();
            return;
        }
    }

    /* Finished with all tests, print results and return!  */
    printf("**** Testing Complete ****\n");
    printf("**** Test Summary:  Tests Passed:  %lu   Tests Warning:  %lu   Tests Failed:  %lu\n", test_control_successful_tests, test_control_warning_tests, test_control_failed_tests);
#ifdef BATCH_TEST
    exit(test_control_failed_tests);
#endif
}

/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{

    /* Dispatch the test.  */
    (test_control_tests[test_index].test_entry)(first_unused_memory);
}

void  test_control_return(UINT status)
{
UINT    old_posture = TX_INT_ENABLE;
INT     exit_code = status;
CHAR    data[4];

    fflush(stdout);

    /* Initialize result through pipe. */
    data[0] = (CHAR)test_control_successful_tests;
    data[1] = (CHAR)test_control_failed_tests;
    data[2] = (CHAR)test_control_warning_tests;
    data[3] = (CHAR)test_control_na_tests;

    /* Save the status in a global.  */
    test_control_return_status = status;

    /* Ensure interrupts are enabled.  */
    old_posture = tx_interrupt_control(TX_INT_ENABLE);

    /* Determine if it was successful or not.  */
    if((status == 1) || (_tx_thread_preempt_disable) || (old_posture == TX_INT_DISABLE))
    {
        data[1]++;
        exit_code = 1;
    }
    else if(status == 2)
    {
        data[2]++;
        exit_code = 2;
    }
    else if(status == 0)
    {
        data[0]++;
        exit_code = 0;
    }
    else if(status == 3)
    {
        data[3]++;
        exit_code = 3;
    }

    /* Send result through pipe. */
    write(result_fd[1], data, sizeof(data));
    exit(exit_code);
}

#else
/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{
    UCHAR    *pointer;

    /* Setup a pointer to the first unused memory.  */
    pointer = (UCHAR *)   first_unused_memory;
    
#ifndef NX_CRYPTO_STANDALONE_ENABLE
    /* Create the test control thread.  */
    tx_thread_create(&test_control_thread, "test control thread", test_control_thread_entry, 0,
        pointer, TEST_STACK_SIZE,
        0, 0, TX_NO_TIME_SLICE, TX_AUTO_START);
#else
    test_control_thread_entry(0);
#endif

    pointer = pointer + TEST_STACK_SIZE;

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#ifndef NETXTEST_TIMEOUT_DISABLE
    /* Create the test control semaphore.  */
    tx_semaphore_create(&test_control_sema, "Test control semaphore", 0);
#endif
#endif

    /* Remember the free memory pointer.  */
    test_free_memory_ptr = pointer;
}

/* Define the test control thread.  This thread is responsible for dispatching all of the
tests in the ThreadX test suite.  */

void  test_control_thread_entry(ULONG thread_input)
{
    UINT    i;

    /* Loop to process all tests...  */
    i = 0;
    while (test_control_tests[i].test_entry != NX_CRYPTO_NULL)
    {

        /* Dispatch the test.  */
        (test_control_tests[i++].test_entry)(test_free_memory_ptr);

        if (test_control_return_status != 3)
        {
#ifndef NX_CRYPTO_STANDALONE_ENABLE
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
    /* Report the verdict through the exit status: a failure outranks an N/A,
       and an N/A outranks a pass.  A test whose subject matter is compiled
       out of this configuration then reaches ctest as a skip rather than as a
       pass.  Under CTEST the binary holds one test, so each count is 0 or 1.  */
    if (test_control_failed_tests)
        exit((INT)test_control_failed_tests);
    else if (test_control_na_tests)
        exit(3);
    else
        exit(0);
#endif

}

void  test_control_return(UINT status)
{
#ifndef NX_CRYPTO_STANDALONE_ENABLE
    UINT    old_posture = TX_INT_ENABLE;
#endif

    /* Save the status in a global.  */
    test_control_return_status = status;
#ifndef NX_CRYPTO_STANDALONE_ENABLE
    /* Ensure interrupts are enabled.  */
    old_posture = tx_interrupt_control(TX_INT_ENABLE);
#endif

    /* Determine if it was successful or not.  */
#ifndef NX_CRYPTO_STANDALONE_ENABLE
    if((status == 1) || (_tx_thread_preempt_disable) || (old_posture == TX_INT_DISABLE))
#else
    if(status == 1) 
#endif
        test_control_failed_tests++;
    else if(status == 2)
        test_control_warning_tests++;
    else if(status == 0)
        test_control_successful_tests++;
    else if(status == 3)
        test_control_na_tests++;
#ifndef NX_CRYPTO_STANDALONE_ENABLE
#ifdef NETXTEST_TIMEOUT_DISABLE
    /* Resume the control thread to fully exit the test.  */
    tx_thread_resume(&test_control_thread);
#else
    if(test_control_return_status != 3)
        tx_semaphore_put(&test_control_sema);
#endif
#endif
}

/* Report a kernel object the cleanup walk cannot remove.  Only the kind, the
   address and the status are printed: a delete is refused when the control
   block no longer holds its identifier, which is what a reused frame looks
   like, so the object's name field is a pointer that no longer resolves.  */

static UINT  test_control_cleanup_report(CHAR *object_kind, VOID *object_ptr, UINT status)
{

    printf("ERROR! test_control_cleanup cannot delete %s at %p, status %u\n",
           object_kind, object_ptr, status);
    test_control_failed_tests++;
    return(1);
}

void  test_control_cleanup(void)
{
#ifndef NX_CRYPTO_STANDALONE_ENABLE
    TX_MUTEX        *mutex_ptr;
    TX_THREAD       *thread_ptr;
    VOID            *object_ptr;
    UINT            status;
    UINT            cleanup_error;

    /* A refused delete leaves the object at the head of its list, so every walk
       below stops on the first object it cannot remove rather than spinning on
       it for the whole test timeout.  */
    cleanup_error = 0;
    status = TX_SUCCESS;

    /* Delete all queues.  */
    while((_tx_queue_created_ptr) && (cleanup_error == 0))
    {

        /* Delete queue.  */
        object_ptr = (VOID *)_tx_queue_created_ptr;
        status = tx_queue_delete(_tx_queue_created_ptr);
        if (status != TX_SUCCESS)
            cleanup_error = test_control_cleanup_report("queue", object_ptr, status);
    }

    /* Delete all semaphores.  */
    while((_tx_semaphore_created_ptr) && (cleanup_error == 0))
    {
#ifndef NETXTEST_TIMEOUT_DISABLE
        if(_tx_semaphore_created_ptr != &test_control_sema)
        {

            /* Delete semaphore.  */
            object_ptr = (VOID *)_tx_semaphore_created_ptr;
            status = tx_semaphore_delete(_tx_semaphore_created_ptr);
        }
        else if(_tx_semaphore_created_count == 1)
            break;
        else
        {
            /* Delete semaphore.  */
            object_ptr = (VOID *)_tx_semaphore_created_ptr -> tx_semaphore_created_next;
            status = tx_semaphore_delete(_tx_semaphore_created_ptr -> tx_semaphore_created_next);
        }
#else
        /* Delete semaphore.  */
        object_ptr = (VOID *)_tx_semaphore_created_ptr;
        status = tx_semaphore_delete(_tx_semaphore_created_ptr);
#endif
        if (status != TX_SUCCESS)
            cleanup_error = test_control_cleanup_report("semaphore", object_ptr, status);
    }

    /* Delete all event flag groups.  */
    while((_tx_event_flags_created_ptr) && (cleanup_error == 0))
    {

        /* Delete event flag group.  */
        object_ptr = (VOID *)_tx_event_flags_created_ptr;
        status = tx_event_flags_delete(_tx_event_flags_created_ptr);
        if (status != TX_SUCCESS)
            cleanup_error = test_control_cleanup_report("event flag group", object_ptr, status);
    }

    /* Delete all byte pools.  */
    while((_tx_byte_pool_created_ptr) && (cleanup_error == 0))
    {

        /* Delete byte pool.  */
        object_ptr = (VOID *)_tx_byte_pool_created_ptr;
        status = tx_byte_pool_delete(_tx_byte_pool_created_ptr);
        if (status != TX_SUCCESS)
            cleanup_error = test_control_cleanup_report("byte pool", object_ptr, status);
    }

    /* Delete all block pools.  */
    while((_tx_block_pool_created_ptr) && (cleanup_error == 0))
    {

        /* Delete block pool.  */
        object_ptr = (VOID *)_tx_block_pool_created_ptr;
        status = tx_block_pool_delete(_tx_block_pool_created_ptr);
        if (status != TX_SUCCESS)
            cleanup_error = test_control_cleanup_report("block pool", object_ptr, status);
    }

    /* Delete all timers.  */
    while((_tx_timer_created_ptr) && (cleanup_error == 0))
    {

        /* Deactivate timer.  */
        tx_timer_deactivate(_tx_timer_created_ptr);

        /* Delete timer.  */
        object_ptr = (VOID *)_tx_timer_created_ptr;
        status = tx_timer_delete(_tx_timer_created_ptr);
        if (status != TX_SUCCESS)
            cleanup_error = test_control_cleanup_report("timer", object_ptr, status);
    }

    /* Delete all mutexes (except for system mutex).  */
    while((_tx_mutex_created_ptr) && (cleanup_error == 0))
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
        status = tx_mutex_delete(mutex_ptr);
        if (status != TX_SUCCESS)
            cleanup_error = test_control_cleanup_report("mutex", (VOID *)mutex_ptr, status);
    }

    /* Delete all threads, except for timer thread, and test control thread.  */
    while ((_tx_thread_created_ptr) && (cleanup_error == 0))
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
        status = tx_thread_delete(thread_ptr);
        if (status != TX_SUCCESS)
            cleanup_error = test_control_cleanup_report("thread", (VOID *)thread_ptr, status);
    }
#endif

    /* At this point, only the test control thread and the system timer thread and/or mutex should still be
    in the system.  */

#ifdef NX_PCAP_ENABLE
    /* Close the pcap file.  */
    close_pcap_file();
#endif
}
#endif
