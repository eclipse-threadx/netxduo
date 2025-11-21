/* Test for aes ctr encrypting the plain text which is not multiples of 16. */

#include <stdio.h>
#include "nx_crypto.h"
#include "tls_test_utility.h"
#include "nx_crypto_sha1.h"
#include "nx_crypto_sha2.h"
#include "nx_crypto_sha5.h"
#include "nx_crypto_method_self_test.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

extern NX_CRYPTO_METHOD crypto_method_sha1;

static UINT test_nx_crypto_init_failed(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    return 233;
}

static UINT test_nx_crypto_operation_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 233;
}

static UINT test_nx_crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 0;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_sha_additional_test_application_define(void *first_unused_memory)
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
UINT i, status, backup;
UCHAR output[256], metadata[sizeof(NX_CRYPTO_SHA512)], data[32];
NX_CRYPTO_METHOD test_method;
NX_CRYPTO_SHA1 *sha_ptr, sha1_ctx;
UCHAR buffer1[16], buffer2[16];

    /* Print out test information banner.  */
    printf("NetX Secure Test:   SHA ADDITIONAL TEST................................");

#ifdef NX_CRYPTO_SELF_TEST
    _nx_crypto_self_test_memmove(buffer1, buffer2, 16);
    _nx_crypto_self_test_memmove(buffer2, buffer1, 16);
    _nx_crypto_self_test_memmove(buffer1, buffer1, 16);
#endif /* NX_CRYPTO_SELF_TEST */

    /* Tests for invalid pointers. */
    status = _nx_crypto_method_sha1_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                NX_CRYPTO_NULL,
                                                (NX_CRYPTO_METHOD *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);

    status = _nx_crypto_method_sha1_operation(NX_CRYPTO_HASH_UPDATE,
                                                NX_CRYPTO_NULL,
                                                (NX_CRYPTO_METHOD *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);

    status = _nx_crypto_method_sha1_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                (NX_CRYPTO_METHOD *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                output,
                                                sizeof(output),
                                                metadata,
                                                sizeof(metadata),
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Tests for invalid pointers. */
    status = _nx_crypto_method_sha256_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                NX_CRYPTO_NULL,
                                                (NX_CRYPTO_METHOD *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    test_method.nx_crypto_algorithm = NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256;
    status = _nx_crypto_method_sha256_operation(NX_CRYPTO_HASH_UPDATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);

    status = _nx_crypto_method_sha256_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                output,
                                                sizeof(output),
                                                metadata,
                                                sizeof(metadata),
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    /* Tests for invalid pointers. */
    status = _nx_crypto_method_sha512_operation(0xFFFFFFFF,
                                                NX_CRYPTO_NULL,
                                                (NX_CRYPTO_METHOD *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                output,
                                                sizeof(output),
                                                metadata,
                                                sizeof(metadata),
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);

    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_AUTHENTICATE,
                                                NX_CRYPTO_NULL,
                                                (NX_CRYPTO_METHOD *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                output,
                                                sizeof(output),
                                                metadata,
                                                sizeof(metadata),
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_VERIFY,
                                                NX_CRYPTO_NULL,
                                                (NX_CRYPTO_METHOD *)NX_CRYPTO_NULL,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                output,
                                                sizeof(output),
                                                metadata,
                                                sizeof(metadata),
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    test_method.nx_crypto_algorithm = 0xFFFF;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_AUTHENTICATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                output,
                                                sizeof(output),
                                                metadata,
                                                sizeof(metadata),
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);

    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                output,
                                                sizeof(output),
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);

    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_UPDATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                output,
                                                sizeof(output),
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);

    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                0,
                                                (UCHAR *)NX_CRYPTO_NULL,
                                                output,
                                                sizeof(output),
                                                metadata,
                                                sizeof(metadata),
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL);

    /* Tests for sha update. */
    UCHAR buffer[0x80];
    NX_SHA256 nx_sha2;
    nx_sha2.nx_sha256_bit_count[0] = 0xffffffff; /* f * 8 */
    status = _nx_crypto_sha256_update(&nx_sha2, buffer, 1);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    NX_SHA512 nx_sha5;
    nx_sha5.nx_sha512_bit_count[0] = 0xffffffffffffffff; /* f * 16 */
    status = _nx_crypto_sha512_update(&nx_sha5, buffer, 1);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    /* NULL method pointer. */
    status = _nx_crypto_sha1_initialize(NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_sha1_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

#ifndef NX_IPSEC_ENABLE
    /* NULL metadata pointer. */
    status = _nx_crypto_method_sha1_init(&test_method, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);
#endif /* NX_IPSEC_ENABLE */

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_sha1_init(&test_method, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_sha1_init(&test_method, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    _nx_crypto_method_sha1_cleanup(NX_CRYPTO_NULL);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_sha1_operation(0, NX_CRYPTO_NULL,
                                              &test_method, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              NX_CRYPTO_NULL, 0, /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_sha1_operation(0, NX_CRYPTO_NULL,
                                              &test_method, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              (VOID *)0x03, 0, /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_sha1_operation(0, NX_CRYPTO_NULL,
                                              &test_method, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              (VOID *)0x04, 0, /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Initialize the method by crypto_operation ptr. */
    status = _nx_crypto_method_sha1_operation(NX_CRYPTO_HASH_INITIALIZE, NX_CRYPTO_NULL,
                                              &test_method, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              metadata, sizeof(metadata), /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* context pointer is NULL. */
    status = _nx_crypto_sha1_update(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* roll-over of the bit count into the MSW. */
    sha_ptr = (NX_CRYPTO_SHA1 *)&metadata;
    sha_ptr -> nx_sha1_bit_count[0] = -1;
    _nx_crypto_sha1_update(sha_ptr, data, 1);

    /* Not enough ouput size. */
    status = _nx_crypto_method_sha1_operation(0, NX_CRYPTO_NULL,
                                              &test_method, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              metadata, sizeof(metadata), /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* Not enough ouput size. */
    status = _nx_crypto_method_sha1_operation(NX_CRYPTO_HASH_CALCULATE, NX_CRYPTO_NULL,
                                              &test_method, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              metadata, sizeof(metadata), /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* Update 0 bytes data. */
    status = _nx_crypto_method_sha1_operation(NX_CRYPTO_HASH_UPDATE, NX_CRYPTO_NULL,
                                              &test_method, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              metadata, sizeof(metadata), /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Invoke sha1_digest_calculate directly. */
    status = _nx_crypto_method_sha1_operation(NX_CRYPTO_HASH_CALCULATE, NX_CRYPTO_NULL,
                                              &test_method, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              output, sizeof(output), /* output */
                                              metadata, sizeof(metadata), /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);

    /* NULL context pointer. */
    status = _nx_crypto_sha256_initialize(NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL context pointer. */
    status = _nx_crypto_sha256_update(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_sha256_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_sha256_init(&test_method, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_sha256_init(&test_method, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_sha256_init(&test_method, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    status = _nx_crypto_method_sha256_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_sha256_operation(0, NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                (VOID *)0x03, 0, /* crypto metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_sha256_operation(0, NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                (VOID *)0x04, 0, /* crypto metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_sha256_operation(0, NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                (VOID *)0x04, sizeof(NX_CRYPTO_SHA256), /* crypto metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid crypto method id. */
    test_method.nx_crypto_algorithm = 0;
    status = _nx_crypto_method_sha256_operation(0, NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                (VOID *)0x04, sizeof(NX_CRYPTO_SHA256), /* crypto metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL /* packet_ptr and callback */);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Output size is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA256;
    status = _nx_crypto_method_sha256_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    test_method.nx_crypto_algorithm = NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256;
    status = _nx_crypto_method_sha256_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA224;
    status = _nx_crypto_method_sha256_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* Output size is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA256;
    status = _nx_crypto_method_sha256_operation(0,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    test_method.nx_crypto_algorithm = NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256;
    status = _nx_crypto_method_sha256_operation(0,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA224;
    status = _nx_crypto_method_sha256_operation(0,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_sha512_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);

    /* NULL context pointer. */
    status = _nx_crypto_method_sha512_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    /* Initialize the hash method by crypto_operation. */
    status = _nx_crypto_method_sha256_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Update 0 bytes data. */
    status = _nx_crypto_method_sha256_operation(NX_CRYPTO_HASH_UPDATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Invoke sha224. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA224;
    status = _nx_crypto_method_sha256_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                buffer1, sizeof(buffer1), /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                output, sizeof(output), /* output */
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL context pointer. */
    status = _nx_crypto_sha512_initialize(NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL context pointer. */
    status = _nx_crypto_sha512_update(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_sha512_init(&test_method, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_sha512_init(&test_method, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_sha512_init(&test_method, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_sha512_operation(0,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                (VOID *)0x03, 0,
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_sha512_operation(0,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, 0,
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid crypto operation. */
    status = _nx_crypto_method_sha512_operation(0,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Invalid algoritm id. */
    test_method.nx_crypto_algorithm = 0;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Initialize sha512 by crypto_method_operation. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Update data by crypto_method_operation. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_UPDATE,
                                                NX_CRYPTO_NULL,
                                                &test_method,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL, 0,
                                                NX_CRYPTO_NULL,
                                                NX_CRYPTO_NULL, 0,
                                                metadata, sizeof(metadata),
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NX_CRYPTO_VERIFY SHA512 output length is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_VERIFY,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NX_CRYPTO_VERIFY SHA384 output length is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA384;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_VERIFY,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NX_CRYPTO_VERIFY SHA512224 output length is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512_224;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_VERIFY,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NX_CRYPTO_VERIFY SHA512256 output length is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512_256;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_VERIFY,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NX_CRYPTO_HASH_CALCULATE SHA512 output_length is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NX_CRYPTO_HASH_CALCULATE SHA384 output_length is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA384;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NX_CRYPTO_HASH_CALCULATE SHA512224 output_length is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512_224;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NX_CRYPTO_HASH_CALCULATE SHA512256 output_length is not enough. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512_256;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                NX_CRYPTO_NULL, 0, /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                NX_CRYPTO_NULL, 0, /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* Invoke sha384. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA384;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                buffer1, sizeof(buffer1), /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                output, sizeof(output), /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Invoke sha512224. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512_224;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                buffer1, sizeof(buffer1), /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                output, sizeof(output), /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Invoke sha512256. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA512_256;
    status = _nx_crypto_method_sha512_operation(NX_CRYPTO_HASH_CALCULATE,
                                                NX_CRYPTO_NULL,
                                                &test_method, /* method */
                                                NX_CRYPTO_NULL, 0, /* key */
                                                buffer1, sizeof(buffer1), /* input */
                                                NX_CRYPTO_NULL, /* iv */
                                                output, sizeof(output), /* output */
                                                metadata, sizeof(metadata), /* metadata */
                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

/* For NX_CRYPTO_STATE_CHECK. */
#ifdef NX_CRYPTO_SELF_TEST
    backup = _nx_crypto_library_state;
    _nx_crypto_library_state = 0;

    status = _nx_crypto_method_sha1_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_sha1_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_sha1_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_sha256_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_sha256_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_sha256_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_sha512_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_sha512_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_sha512_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    _nx_crypto_library_state = backup;

    /* Tests for _nx_crypto_method_self_test_sha. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_sha(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid nx_crypto_algorithm. */
    test_method.nx_crypto_algorithm = 0;
    status = _nx_crypto_method_self_test_sha(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(1, status);

    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_HASH_SHA1;
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_sha(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_sha(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_sha(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_sha(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_sha1;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_sha(&test_method, &sha1_ctx, sizeof(sha1_ctx));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
