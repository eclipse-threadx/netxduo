#include <stdio.h>
#include "nx_crypto_ec.h"
#include "tls_test_utility.h"
#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif

#define MAXIMUM_KEY_BITS 256

extern NX_CRYPTO_CONST NX_CRYPTO_EC _nx_crypto_ec_secp192r1;
static UCHAR scratch_buffer[1024];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_ec_additional_test_application_define(void *first_unused_memory)
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
UINT status, huge_number_size;
NX_CRYPTO_EC_POINT point, point1;
UCHAR *scratch_ptr, buffer[256];
NX_CRYPTO_HUGE_NUMBER value;
NX_CRYPTO_EC test_ec;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   EC Additional Test.................................");

    scratch_ptr = scratch_buffer;
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&(point.nx_crypto_ec_point_x), scratch_ptr, 64);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&(point.nx_crypto_ec_point_y), scratch_ptr, 64);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&(point1.nx_crypto_ec_point_x), scratch_ptr, 64);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&(point1.nx_crypto_ec_point_y), scratch_ptr, 64);

    point.nx_crypto_ec_point_type = NX_CRYPTO_EC_POINT_AFFINE;
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point.nx_crypto_ec_point_x), 0);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point.nx_crypto_ec_point_y), 1);

    status = _nx_crypto_ec_point_is_infinite(&point);
    EXPECT_EQ(NX_CRYPTO_FALSE, status);

    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point.nx_crypto_ec_point_y), 0);
    status = _nx_crypto_ec_point_is_infinite(&point);
    EXPECT_EQ(NX_CRYPTO_TRUE, status);

    _nx_crypto_ec_point_set_infinite(&point);

    /* Compressed format is not supported. */
    buffer[0] = 0;
    status = _nx_crypto_ec_point_setup(&point, buffer, 1);
    EXPECT_EQ(NX_CRYPTO_FORMAT_NOT_SUPPORTED, status);

    /* ec_point_x _nx_crypto_huge_number_extract_fixed_size failed. */
    point.nx_crypto_ec_point_x.nx_crypto_huge_number_data[63] = 0xff;
    point.nx_crypto_ec_point_x.nx_crypto_huge_number_size = 64;
    _nx_crypto_ec_point_extract_uncompressed((NX_CRYPTO_EC *)&_nx_crypto_ec_secp192r1, &point, buffer, 50, &huge_number_size);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point.nx_crypto_ec_point_x), 0);

    /* ec_point_y _nx_crypto_huge_number_extract_fixed_size failed. */
    point.nx_crypto_ec_point_y.nx_crypto_huge_number_data[62] = 0xff;
    point.nx_crypto_ec_point_y.nx_crypto_huge_number_data[63] = 0;
    point.nx_crypto_ec_point_y.nx_crypto_huge_number_size = 64;
    _nx_crypto_ec_point_extract_uncompressed((NX_CRYPTO_EC *)&_nx_crypto_ec_secp192r1, &point, buffer, 50, &huge_number_size);

    /* byte_stream_size < 1 + (clen << 1) */
    _nx_crypto_ec_point_extract_uncompressed((NX_CRYPTO_EC *)&_nx_crypto_ec_secp192r1, &point, buffer, 0, &huge_number_size);

    /* ec_point is infinite. */
    point.nx_crypto_ec_point_type = NX_CRYPTO_EC_POINT_AFFINE;
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point.nx_crypto_ec_point_x), 0);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point.nx_crypto_ec_point_y), 0);
    _nx_crypto_ec_point_fp_projective_to_affine((NX_CRYPTO_EC *)&_nx_crypto_ec_secp192r1, &point, (VOID *)buffer);

#ifdef NX_CRYPTO_SELF_TEST
    /* The value and curve -> nx_crypto_ec_field.fp are equal. */
    test_ec = _nx_crypto_ec_secp192r1;
    test_ec.nx_crypto_ec_field.fp.nx_crypto_huge_number_data = (VOID *)buffer;
    NX_CRYPTO_MEMCPY(buffer, _nx_crypto_ec_secp192r1.nx_crypto_ec_field.fp.nx_crypto_huge_number_data, _nx_crypto_ec_secp192r1.nx_crypto_ec_field.fp.nx_crypto_huge_number_size);
    _nx_crypto_ec_secp192r1_reduce(&test_ec, &test_ec.nx_crypto_ec_field.fp, (VOID *)buffer);
    _nx_crypto_ec_secp224r1_reduce(&test_ec, &test_ec.nx_crypto_ec_field.fp, (VOID *)buffer);
    _nx_crypto_ec_secp256r1_reduce(&test_ec, &test_ec.nx_crypto_ec_field.fp, (VOID *)buffer);
    _nx_crypto_ec_secp384r1_reduce(&test_ec, &test_ec.nx_crypto_ec_field.fp, (VOID *)buffer);
    _nx_crypto_ec_secp521r1_reduce(&test_ec, &test_ec.nx_crypto_ec_field.fp, (VOID *)buffer);

    /* Invoke _nx_crypto_ec_subtract_digit_reduce. */
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&value, scratch_ptr, 64);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&value, 0);
    _nx_crypto_ec_subtract_digit_reduce(&test_ec, &value, 2, NX_CRYPTO_NULL);

    value.nx_crypto_huge_number_size = 2;
    value.nx_crypto_huge_number_data[1] = 1;
    value.nx_crypto_huge_number_data[0] = 0;
    _nx_crypto_ec_subtract_digit_reduce(&test_ec, &value, 2, NX_CRYPTO_NULL);

    value.nx_crypto_huge_number_size = 2;
    value.nx_crypto_huge_number_data[1] = 1;
    value.nx_crypto_huge_number_data[0] = 3;
    _nx_crypto_ec_subtract_digit_reduce(&test_ec, &value, 2, NX_CRYPTO_NULL);

    /* _nx_crypto_ec_fp_affine_add, left == right. */
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(test_ec.nx_crypto_ec_field.fp), 23);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point.nx_crypto_ec_point_x), 23);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point.nx_crypto_ec_point_y), 23);
    _nx_crypto_ec_fp_affine_add(&test_ec, &point, &point, (HN_UBASE *)scratch_ptr);

    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point1.nx_crypto_ec_point_x), 23);
    NX_CRYPTO_HUGE_NUMBER_SET_DIGIT(&(point1.nx_crypto_ec_point_y), 24);
    _nx_crypto_ec_fp_affine_add(&test_ec, &point, &point1, (HN_UBASE *)scratch_ptr);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
