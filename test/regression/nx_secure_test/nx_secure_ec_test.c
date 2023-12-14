
#include <stdio.h>
#include "nx_crypto_ec.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif
#include "tls_test_utility.h"

#define MAXIMUM_KEY_BITS 256

#include "nx_secure_ec_test_data.c"

/* Scratch buffer for huge number. */
HN_UBASE scratch_buffer[10000];

/* Output. */
static UCHAR output_data[256];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_ec_test_application_define(void *first_unused_memory)
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
UINT i;
NX_CRYPTO_EC_POINT point;
NX_CRYPTO_HUGE_NUMBER m;
NX_CRYPTO_EC_POINT output;
HN_UBASE *scratch;
UINT out_len;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   EC Test............................................");

    for (i = 0; i < sizeof(ec_data) / sizeof(EC_DATA); i++)
    {
        scratch = scratch_buffer;

        memset(output_data, 0xFF, sizeof(output_data));

        /* Initialize and setup point data. */
        NX_CRYPTO_EC_POINT_INITIALIZE(&point, NX_CRYPTO_EC_POINT_AFFINE, scratch, ec_data[i].point_len * 2);
        _nx_crypto_ec_point_setup(&point, ec_data[i].point_data, ec_data[i].point_len);
        //NX_CRYPTO_EC_POINT_SETUP(&point, ec_data[i].point_data + 1, (ec_data[i].point_len - 1) / 2, ec_data[i].point_data + 1 + (ec_data[i].point_len - 1) / 2, (ec_data[i].point_len - 1) / 2, NULL, 0);

        /* Initialize and setup mul data. */
        NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&m, scratch, ec_data[i].m_len);
        _nx_crypto_huge_number_setup(&m, ec_data[i].m, ec_data[i].m_len);

        /* Test EC Multiple function. */
        NX_CRYPTO_EC_POINT_INITIALIZE(&output, NX_CRYPTO_EC_POINT_AFFINE, scratch, ec_data[i].point_len * 2);
        _nx_crypto_ec_fp_projective_multiple((NX_CRYPTO_EC*)ec_data[i].curve, &point, &m, &output, scratch);
   
        _nx_crypto_ec_point_extract_uncompressed((NX_CRYPTO_EC*)ec_data[i].curve, &output, output_data, sizeof(output_data), &out_len);

        EXPECT_EQ(0, memcmp(output_data, ec_data[i].mul_data, ec_data[i].mul_len));
    }

#ifdef NX_CRYPTO_ENABLE_CURVE25519_448
    for (i = 0; i < sizeof(ec_data_x25519_448) / sizeof(EC_DATA); i++)
    {
        scratch = scratch_buffer;

        memset(output_data, 0xFF, sizeof(output_data));

        /* Initialize and setup point data. */
        NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&m, scratch, ec_data_x25519_448[i].m_len);
        NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&point.nx_crypto_ec_point_x, scratch, ec_data_x25519_448[i].point_len);
        NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&output.nx_crypto_ec_point_x, scratch, ec_data_x25519_448[i].mul_len);

        NX_CRYPTO_MEMCPY(m.nx_crypto_huge_number_data, ec_data_x25519_448[i].m, ec_data_x25519_448[i].m_len);
        m.nx_crypto_huge_number_size = ec_data_x25519_448[i].m_len >> HN_SIZE_SHIFT;

        NX_CRYPTO_MEMCPY(point.nx_crypto_ec_point_x.nx_crypto_huge_number_data, ec_data_x25519_448[i].point_data, ec_data_x25519_448[i].point_len);
        point.nx_crypto_ec_point_x.nx_crypto_huge_number_size = ec_data_x25519_448[i].point_len >> HN_SIZE_SHIFT;

        /* Test EC Multiple function. */
        ec_data_x25519_448[i].curve -> nx_crypto_ec_multiple((NX_CRYPTO_EC *)ec_data_x25519_448[i].curve, &point, &m, &output, scratch);

        _nx_crypto_ec_extract_fixed_size_le(&output.nx_crypto_ec_point_x, output_data, ec_data_x25519_448[i].mul_len);

        EXPECT_EQ(0, memcmp(output_data, ec_data_x25519_448[i].mul_data, ec_data_x25519_448[i].mul_len));

    }


#endif /* NX_CRYPTO_ENABLE_CURVE25519_448 */


    printf("SUCCESS!\n");
    test_control_return(0);
}
