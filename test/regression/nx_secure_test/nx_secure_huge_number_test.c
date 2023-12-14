/* Test for aes ctr encrypting the plain text which is not multiples of 16. */

#include <stdio.h>
#include "nx_crypto_huge_number.h"
#include "tls_test_utility.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_huge_number_test_application_define(void *first_unused_memory)
#endif
{
#ifndef NX_CRYPTO_STANDALONE_ENABLE
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
                     first_unused_memory, 4096,
                     16, 16, 4, TX_AUTO_START);
#else
    thread_0_entry(0);
#endif
}

static VOID thread_0_entry(ULONG thread_input)
{
UINT status;
NX_CRYPTO_HUGE_NUMBER a, b, c;
HN_UBASE a_buf[10240], b_buf[10240], c_buf[10240], tmp[10240];

    /* Print out test information banner.  */
    printf("NetX Secure Test:   HUGE NUMBER TEST...................................");

    /* Test for 1 + (-1) */
    a.nx_crypto_huge_number_data = a_buf;
    b.nx_crypto_huge_number_data = b_buf;
    c.nx_crypto_huge_number_data = c_buf;

    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &a, 1); /* a = 1 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &b, 2); /* b = 2 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &c, 1); /* c = 1 */
    _nx_crypto_huge_number_subtract( &c, &b); /* c = -1 */
    _nx_crypto_huge_number_add( &a, &c); /* a = 0 */

    /* Compare two numbers with different sign. */
    status = _nx_crypto_huge_number_compare( &a, &c);
    EXPECT_EQ( status, NX_CRYPTO_HUGE_NUMBER_GREATER);
    status = _nx_crypto_huge_number_compare( &c, &a);
    EXPECT_EQ( status, NX_CRYPTO_HUGE_NUMBER_LESS);

    /* Compare two negative numbers. */
    _nx_crypto_huge_number_subtract( &a, &b); /* a = -2 */
    status = _nx_crypto_huge_number_compare( &c, &a);
    EXPECT_EQ( status, NX_CRYPTO_HUGE_NUMBER_GREATER);

    /* Test for _nx_crypto_huge_number_adjust_size. */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &a, 0); /* a = 0 */
    a.nx_crypto_huge_number_size = 2;
    a.nx_crypto_huge_number_data[1] = 0;
    _nx_crypto_huge_number_adjust_size( &a);

    /* Test for _nx_crypto_huge_number_add_unsigned. */
    /* Drop the carry. */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &a, 0xffffffff); /* a = 1 */
    a.nx_crypto_huge_number_size = 1;
    a.nx_crypto_huge_buffer_size = 4;
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &b, 1); /* b = 2 */
    b.nx_crypto_huge_number_size = 1;
    b.nx_crypto_huge_buffer_size = 4;
    _nx_crypto_huge_number_add_unsigned( &a, &b);

    /* Test for _nx_crypto_huge_number_multiply. */
    /* Created a negative huge number whose first HN_UBASE is zero. */
    a.nx_crypto_huge_number_size = 2;
    a.nx_crypto_huge_buffer_size = 1024;
    a.nx_crypto_huge_number_data[0] = 0;
    a.nx_crypto_huge_number_data[1] = 1;
    a.nx_crypto_huge_number_is_negative = NX_CRYPTO_TRUE;
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &b, 1); /* b = 1 */
    _nx_crypto_huge_number_multiply( &a, &b, &c);

    /* Not enough space for _nx_crypto_huge_number_extract. */
    status = _nx_crypto_huge_number_extract( &a, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL);
    EXPECT_EQ( status, NX_CRYPTO_NOT_SUCCESSFUL);

    /* Tests for huge number setup. */
    UCHAR bytes[4] = {1, 1, 1, 0};
    a.nx_crypto_huge_buffer_size = 2;
    status = _nx_crypto_huge_number_setup( &a, bytes, 4);
    EXPECT_EQ( status, NX_CRYPTO_SIZE_ERROR);
    status = _nx_crypto_huge_number_setup( &a, NULL, 0);
    EXPECT_EQ( status, NX_CRYPTO_SIZE_ERROR);
    a.nx_crypto_huge_buffer_size = 4;
    bytes[0] = 0;
    bytes[1] = 0;
    bytes[2] = 0;
    status = _nx_crypto_huge_number_setup( &a, bytes, 4);
    EXPECT_EQ( status, NX_CRYPTO_SUCCESS);

    /* Setup huge numbers with different types of byte stream. */
    UCHAR byte_stream[4] = { 1, 1, 1, 1};
    _nx_crypto_huge_number_setup( &a, byte_stream, 1);
    _nx_crypto_huge_number_setup( &a, byte_stream, 2);
    _nx_crypto_huge_number_setup( &a, byte_stream, 3);

    /* Tests for _nx_crypto_huge_number_inverse_modulus. */
    /* Assign a and m as two even numbers */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &b, 4); /* b = 4 */
    status = _nx_crypto_huge_number_inverse_modulus( &b, &b, &c, tmp);
    EXPECT_EQ( status, NX_CRYPTO_NOT_SUCCESSFUL);

    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &a, 3); /* a = 3 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &b, 4); /* b = 4 */
    status = _nx_crypto_huge_number_inverse_modulus( &b, &a, &c, tmp);

    /* Tests for _nx_crypto_huge_number_modulus. */
    a.nx_crypto_huge_number_size = 2;
    a.nx_crypto_huge_number_data[1] = 0;
    _nx_crypto_huge_number_modulus( &b, &a);

    /* Test of 0xFFFFFFFFFFFFFFFF00000000 mod 0xFFFFFFFFFFFFFFFEFFFFFFFF for _nx_crypto_huge_number_modulus. */
    a.nx_crypto_huge_number_size = 3;
    a.nx_crypto_huge_number_data[0] = 0xFFFFFFFF;
    a.nx_crypto_huge_number_data[1] = 0xFFFFFFFE;
    a.nx_crypto_huge_number_data[2] = 0xFFFFFFFF;
    b.nx_crypto_huge_number_size = 3;
    b.nx_crypto_huge_number_data[0] = 0x00000000;
    b.nx_crypto_huge_number_data[1] = 0xFFFFFFFF;
    b.nx_crypto_huge_number_data[2] = 0xFFFFFFFF;
    _nx_crypto_huge_number_modulus( &b, &a);

    /* Call _nx_crypto_huge_number_modulus with negative numbers. */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &a, 0); /* a = 0 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &c, 2); /* c = 2 */
    _nx_crypto_huge_number_subtract( &a, &c); /* a = -2 */

    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &b, 0); /* b = 0 */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &c, 3); /* c = 3 */
    _nx_crypto_huge_number_subtract( &b, &c); /* b = -3 */
    _nx_crypto_huge_number_modulus( &b, &a);

    /* Tests for _nx_crypto_huge_number_inverse_modulus. */

    /* The size of p is large than a. */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &a, 5);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &b, 4);
    b.nx_crypto_huge_number_size = 2;
    _nx_crypto_huge_number_inverse_modulus_prime( &a, &b, &c, tmp);

    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &a, 2);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &b, 3);
    _nx_crypto_huge_number_inverse_modulus( &a, &b, &c, tmp);

    a.nx_crypto_huge_number_size = 2;
    a.nx_crypto_huge_number_data[0] = 0xffffffff;
    a.nx_crypto_huge_number_data[1] = 0xffffffff;
    _nx_crypto_huge_number_add_digit_unsigned(&a, 1);

    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT( &a, -1);
    _nx_crypto_huge_number_add_digit_unsigned(&a, 1);

    /* multiply zero. */
    _nx_crypto_huge_number_multiply_digit(&a, 0, &a);

    /* _nx_crypto_huge_number_rbg. */
    _nx_crypto_huge_number_rbg(63, (UCHAR *)tmp);
    _nx_crypto_huge_number_rbg(56, (UCHAR *)tmp);
    _nx_crypto_huge_number_rbg(32, (UCHAR *)tmp);
    _nx_crypto_huge_number_rbg(33, (UCHAR *)tmp);
    _nx_crypto_huge_number_rbg(41, (UCHAR *)tmp);
    _nx_crypto_huge_number_rbg(49, (UCHAR *)tmp);

    printf("SUCCESS!\n");
    test_control_return(0);
}
