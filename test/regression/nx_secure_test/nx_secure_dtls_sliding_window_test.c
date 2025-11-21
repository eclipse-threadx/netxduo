/* This test concentrates on DTLS connections.  */

#include   "nx_api.h"
#include   "nx_secure_dtls_api.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"
#include   "tls_test_utility.h"

extern VOID    test_control_return(UINT status);

#if defined(NX_SECURE_ENABLE_DTLS)

#define THREAD_STACK_SIZE           1024

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD                thread_0;
static UINT                     error_counter;

static NX_SECURE_DTLS_SESSION   dtls_session;
static ULONG remote_number[2];

#define SLIDING_WINDOW_SET (0xFFFFFFFFul)
#define SEQUENCE_NUM_MAX   (0xFFFFFFFFul)

static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];

/* Define thread prototypes.  */
static VOID    ntest_0_entry(ULONG thread_input);

#define ERROR_COUNTER() __ERROR_COUNTER(__FILE__, __LINE__)

static VOID    __ERROR_COUNTER(UCHAR *file, UINT line)
{
    printf("\nError on line %d in %s\n", line, file);
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_sliding_window_test_application_define(void *first_unused_memory)
#endif
{
UINT     status;
CHAR    *pointer;

    error_counter = 0;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&thread_0, "thread 0", ntest_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Initialize the NetX system.  */
    nx_system_initialize();

    nx_secure_tls_initialize();
    nx_secure_dtls_initialize();
}



static void ntest_0_entry(ULONG thread_input)
{
UINT status;
UINT i;
ULONG current_seq;


    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Sliding Window Test...........................");

    /* Sequence number[1] == lower half, Sequence number[0] == upper half (network byte order) */

    /* Clear out window for initial checks. */
    dtls_session.nx_secure_dtls_sliding_window = 0;

    /* Initial handshake - incoming and "last seen" are both 0. The sliding window check
    SHOULD FAIL because we don't check until we have sequence number 1 or higher incoming. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;
    remote_number[0] = 0;
    remote_number[1] = 0;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;
    remote_number[0] = 0;
    remote_number[1] = 1;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check valid incoming sequence number in window. Window is still 0 so this is OK. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 3;
    remote_number[0] = 0;
    remote_number[1] = 2;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check incoming sequence number that has fallen off the window. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 47;
    remote_number[0] = 0;
    remote_number[1] = 3; /* Window size == 32. This falls off the "left" of the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Now check sequence numbers with upper half bits set. */

    /* Check equal numbers - should fail! */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;
    remote_number[0] = 1;
    remote_number[1] = 0;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;
    remote_number[0] = 1;
    remote_number[1] = 1;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check valid incoming sequence number in window. Window is still 0 so this is OK. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 3;
    remote_number[0] = 0;
    remote_number[1] = SEQUENCE_NUM_MAX - 4; /* Delta from expected is 3+4 == 7 which is in the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check incoming sequence number that has fallen off the window but crosses boundary. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 3;
    remote_number[0] = 0;
    remote_number[1] = SEQUENCE_NUM_MAX - 42; /* Delta from expected is 3+42 == 45 which is outside the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check incoming sequence number that is in the window. Window is 0 so number is valid! */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 1;
    remote_number[0] = 1;
    remote_number[1] = 3; /* Window size == 32. This number is in the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);    

    /* Check incoming sequence number that has fallen off the window. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 47;
    remote_number[0] = 1;
    remote_number[1] = 3; /* Window size == 32. This falls off the "left" of the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);    

    /************************************************************************************/
    /* Now check the window by setting bits - 0xFFFFFFFF is all packets seen - all 
       incoming sequence numbers less than the expected should fail. */
    dtls_session.nx_secure_dtls_sliding_window = SLIDING_WINDOW_SET;

    /* Initial handshake - incoming and "last seen" are both 0. The sliding window check
       SHOULD FAIL because we don't check until we have sequence number 1 or higher incoming. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;
    remote_number[0] = 0;
    remote_number[1] = 0;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number. No failure because it's to the "right" of the window. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;
    remote_number[0] = 0;
    remote_number[1] = 1;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check valid incoming sequence number in window. Given bit is set, so failure expected. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 3;
    remote_number[0] = 0;
    remote_number[1] = 2;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check incoming sequence number that has fallen off the window. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 47;
    remote_number[0] = 0;
    remote_number[1] = 2; /* Window size == 32. This falls off the "left" of the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Now check sequence numbers with upper half bits set. */

    /* Check equal numbers - should fail! */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;
    remote_number[0] = 1;
    remote_number[1] = 0;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;
    remote_number[0] = 1;
    remote_number[1] = 1;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check valid incoming sequence number in window. Window is set so expect failure! */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 3;
    remote_number[0] = 0;
    remote_number[1] = SEQUENCE_NUM_MAX - 4; /* Delta from expected is 3+4 == 7 which is in the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check incoming sequence number that has fallen off the window but crosses boundary. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 3;
    remote_number[0] = 0;
    remote_number[1] = SEQUENCE_NUM_MAX - 42; /* Delta from expected is 3+42 == 45 which is outside the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check incoming sequence number that is in the window. Window is set so expect failure! */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 5;
    remote_number[0] = 1;
    remote_number[1] = 3; /* Window size == 32. This number is in the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);    

    /* Check incoming sequence number that has fallen off the window. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 47;
    remote_number[0] = 1;
    remote_number[1] = 3; /* Window size == 32. This falls off the "left" of the window. */
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);    


    /************************************************************************************/
    /* Now check the window update by setting and checking sequence numbers. Clear the 
       window to start. */
    dtls_session.nx_secure_dtls_sliding_window = 0;

    /* Set the sequence number. */
    remote_number[0] = 0;
    remote_number[1] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 0;
    status = _nx_secure_dtls_session_sliding_window_update(&dtls_session, remote_number);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Check valid incoming sequence number. This was already seen so fail! */
    remote_number[0] = 0;
    remote_number[1] = 1;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number. This should be OK! */
    remote_number[0] = 0;
    remote_number[1] = 2;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* *****Update with new number.***** */
    remote_number[0] = 0;
    remote_number[1] = 2;
    status = _nx_secure_dtls_session_sliding_window_update(&dtls_session, remote_number);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Check valid incoming sequence number. This was already seen so fail! */
    remote_number[0] = 0;
    remote_number[1] = 1;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number. This has now been seen so should fail! */
    remote_number[0] = 0;
    remote_number[1] = 2;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Update with new number. */
    remote_number[0] = 0;
    remote_number[1] = 3;
    status = _nx_secure_dtls_session_sliding_window_update(&dtls_session, remote_number);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Check valid incoming sequence number. This was already seen so fail! */
    remote_number[0] = 0;
    remote_number[1] = 1;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number. This was already seen so fail! */
    remote_number[0] = 0;
    remote_number[1] = 2;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number. Same as expected so fail! */
    remote_number[0] = 0;
    remote_number[1] = 3;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number. Valid so pass! */
    remote_number[0] = 0;
    remote_number[1] = 4;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /******************************************************************************************/
    /* Check boundary conditions. */
    dtls_session.nx_secure_dtls_sliding_window = 0;

    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = SEQUENCE_NUM_MAX - 8;
    remote_number[0] = 0;
    remote_number[1] = SEQUENCE_NUM_MAX - 8;
    status = _nx_secure_dtls_session_sliding_window_update(&dtls_session, remote_number);
    EXPECT_EQ(NX_SECURE_TLS_OUT_OF_ORDER_MESSAGE, status);

    /* Check valid incoming sequence number. Should pass. */
    remote_number[0] = 0;
    remote_number[1] = SEQUENCE_NUM_MAX - 4;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check valid incoming sequence number. Should pass */
    remote_number[0] = 0;
    remote_number[1] = SEQUENCE_NUM_MAX - 15;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check valid incoming sequence number. Outside window so fail! */
    remote_number[0] = 0;
    remote_number[1] = SEQUENCE_NUM_MAX - 57;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check valid incoming sequence number across boundary. Should pass */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = SEQUENCE_NUM_MAX - 8;
    remote_number[0] = 1;
    remote_number[1] = 5;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check incoming sequence number with >1 top half delta. Should fail */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 3;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = SEQUENCE_NUM_MAX - 8;
    remote_number[0] = 1;
    remote_number[1] = 5;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /* Check incoming sequence number with >1 top half delta (the other way). Should be OK because it's much larger. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = SEQUENCE_NUM_MAX - 8;
    remote_number[0] = 3;
    remote_number[1] = 5;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /*******************************************************************************************/
    /* Update sliding window. */
    dtls_session.nx_secure_dtls_sliding_window = 0;    
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 1;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 3;
    remote_number[0] = 1;
    remote_number[1] = 3;
    status = _nx_secure_dtls_session_sliding_window_update(&dtls_session, remote_number);
    EXPECT_EQ(NX_SECURE_TLS_OUT_OF_ORDER_MESSAGE, status);

    /* Check valid incoming sequence number. This was not seen but crosses boundary. Should pass. */
    remote_number[0] = 0;
    remote_number[1] = SEQUENCE_NUM_MAX - 4;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_TRUE, status);

    /* Check valid incoming sequence number. Same as expected so fail! */
    remote_number[0] = 1;
    remote_number[1] = 3;
    status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
    EXPECT_EQ(NX_FALSE, status);

    /*****************************************************************************************/
    /* Loop through to check window. */

    /* Mark the first one as seen */
    dtls_session.nx_secure_dtls_sliding_window = 1;    

    for(i = 1; i < 64; ++i)
    {
        /* First update window. */
        dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
        dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = i;
        remote_number[0] = 0;
        remote_number[1] = i + 1;
        status = _nx_secure_dtls_session_sliding_window_update(&dtls_session, remote_number);
        EXPECT_EQ(NX_SUCCESS, status);

        /* Check incoming sequence number. One behind expected - all have been seen so fail! */
        remote_number[0] = 0;
        remote_number[1] = i;
        status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
        EXPECT_EQ(NX_FALSE, status);

        /* Equal to last seen - fail! */
        remote_number[0] = 0;
        remote_number[1] = i + 1;
        status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
        EXPECT_EQ(NX_FALSE, status);

        /* One ahead - pass! */
        remote_number[0] = 0;
        remote_number[1] = i + 2;
        status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
        EXPECT_EQ(NX_TRUE, status);

        /* Several ahead - pass! */
        remote_number[0] = 0;
        remote_number[1] = i + 6;
        status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
        EXPECT_EQ(NX_TRUE, status);

    }


    /*****************************************************************************************/
    /* Loop through to check window across boundary */

    /* Mark the first one as seen */
    dtls_session.nx_secure_dtls_sliding_window = 1;    

    for(i = 1; i < 64; ++i)
    {
        current_seq = SEQUENCE_NUM_MAX - (i + 32);
        /* First update window. */
        dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
        dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = current_seq;
        remote_number[0] = 0;
        remote_number[1] = current_seq + 1;
        status = _nx_secure_dtls_session_sliding_window_update(&dtls_session, remote_number);
        EXPECT_EQ(NX_SUCCESS, status);

        /* Check incoming sequence number. One behind expected - all have been seen so fail! */
        remote_number[0] = 0;
        remote_number[1] = current_seq;
        status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
        EXPECT_EQ(NX_FALSE, status);

        /* Equal to last seen - fail! */
        remote_number[0] = 0;
        remote_number[1] = current_seq + 1;
        status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
        EXPECT_EQ(NX_FALSE, status);

        /* One ahead - pass! */
        remote_number[0] = 0;
        remote_number[1] = current_seq + 2;
        status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
        EXPECT_EQ(NX_TRUE, status);

        /* Several ahead - pass! */
        remote_number[0] = 0;
        remote_number[1] = current_seq + 6;
        status = _nx_secure_dtls_session_sliding_window_check(&dtls_session, remote_number);
        EXPECT_EQ(NX_TRUE, status);

    }

    /**********************************************************************************/
    /* Check error conditions in window update. */
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[0] = 0;
    dtls_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_sequence_number[1] = 1;
    remote_number[0] = 0;
    remote_number[1] = 1;
    status = _nx_secure_dtls_session_sliding_window_update(&dtls_session, remote_number);
    EXPECT_EQ(NX_SECURE_TLS_OUT_OF_ORDER_MESSAGE, status);

    if (error_counter)
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
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_sliding_window_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Sliding Window Test...........................N/A\n");
    test_control_return(3);
}
#endif
