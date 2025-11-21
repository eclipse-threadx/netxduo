/* Test for aes ctr encrypting the plain text which is not multiples of 16. */

#include <stdio.h>
#include "nx_crypto_aes.h"
#include "nx_crypto_ccm.h"
#include "nx_crypto_ctr.h"
#include "nx_crypto_cbc.h"
#include "tls_test_utility.h"
#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h" 
#endif
#include "nx_crypto_xcbc_mac.h"
#include "nx_crypto_method_self_test.h"

#define MAXIMUM_KEY_BITS 256

#include "nx_secure_aes_additional_test_data.c"

/* Define software AES method. */
static NX_CRYPTO_METHOD test_crypto_method_aes =
{
    0,                                        /* AES crypto algorithm filled at runtime */
    0,                                        /* Key size in bits                       */
    NX_CRYPTO_AES_IV_LEN_IN_BITS,             /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3,    /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES initialization routine.            */
    NX_CRYPTO_NULL,                           /* AES cleanup routine, not used.         */
    _nx_crypto_method_aes_operation           /* AES operation                          */

};

extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;

/* AES context. */
static NX_AES aes_ctx;

/* Input to hold plain plus nonce. */
static ULONG key[(MAXIMUM_KEY_BITS >> 5) + 1];

/* IV. */
static ULONG iv[4];

/* Output. */
static ULONG encrypt_output[MAXIMUM_KEY_BITS >> 5];
static ULONG decrypt_output[MAXIMUM_KEY_BITS >> 5];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

static UINT test_crypto_function(VOID *a, UCHAR *b, UCHAR *c, UINT d)
{
    return 0;
}

static UINT test_key_set_function(VOID *a, UCHAR *b, UINT c)
{
    return 0;
}

static UINT test_nx_crypto_init_failed(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    return 233;
}

static UINT count = 0;
static UINT test_nx_crypto_init_failed_second(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    count++;
    if (count == 2)
        return 233;
    return 0;
}

static UINT test_nx_crypto_init_succeed(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    return 0;
}

static UINT test_nx_crypto_operation_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 233;
}

static UINT test_nx_crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 0;
}

static UINT test_nx_crypto_cleanup_failed(VOID *crypto_metadata)
{
    return 233;
}

static UINT test_nx_crypto_operation_NX_CRYPTO_DECRYPT_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_DECRYPT)
    {
        return 233;
    }

    return _nx_crypto_method_aes_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, packet_ptr, nx_crypto_hw_process_callback);
}

static UINT test_nx_crypto_operation_NX_CRYPTO_DECRYPT_error(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_DECRYPT)
    {
        return 0;
    }

    return _nx_crypto_method_aes_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, packet_ptr, nx_crypto_hw_process_callback);
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_aes_additional_test_application_define(void *first_unused_memory)
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
UCHAR test_plain[17] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
UCHAR metadata[2048], input[1024], output[1024];
NX_CRYPTO_METHOD test_method;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   AES ADDITIONAL TEST................................");

    for (i = 0; i < sizeof(aes_data) / sizeof(AES_DATA); i++)
    {

        /* Encryption. */
        memset(encrypt_output, 0xFF, sizeof(encrypt_output));
        memset(decrypt_output, 0xFF, sizeof(decrypt_output));

        /* Conjunction of key and nonce for CTR mode. */
        /* It does not affect CBC mode. */
        memcpy(key, aes_data[i].key, aes_data[i].key_len);
        memcpy(key + (aes_data[i].key_len >> 2), aes_data[i].iv, 4);

        if (aes_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CBC)
        {
            memcpy(iv, aes_data[i].iv, sizeof(iv));
        }
        else
        {
            memcpy(iv, aes_data[i].iv + 4, 8);
        }

        /* Set crypto algorithm. */
        test_crypto_method_aes.nx_crypto_algorithm = aes_data[i].algorithm;

        test_crypto_method_aes.nx_crypto_init(&test_crypto_method_aes,
                                              (UCHAR *)key,
                                              (aes_data[i].key_len << 3),
                                              NX_CRYPTO_NULL,
                                              &aes_ctx,
                                              sizeof(aes_ctx));

        status = test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                            NX_CRYPTO_NULL,
                                                            &test_crypto_method_aes,
                                                            (UCHAR *)key,
                                                            (aes_data[i].key_len << 3),
                                                            aes_data[i].plain,
                                                            aes_data[i].plain_len,
                                                            (UCHAR *)iv,
                                                            (UCHAR *)encrypt_output,
                                                            sizeof(encrypt_output),
                                                            &aes_ctx,
                                                            sizeof(aes_ctx),
                                                            NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        if ( ( aes_data[i].plain_len % test_crypto_method_aes.nx_crypto_block_size_in_bytes) && ( aes_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CBC))
        {
            EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);
        }

        /* Decryption. */
        status = test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                                            NX_CRYPTO_NULL,
                                                            &test_crypto_method_aes,
                                                            (UCHAR *)key,
                                                            (aes_data[i].key_len << 3),
                                                            (UCHAR *)encrypt_output,
                                                            aes_data[i].plain_len,
                                                            (UCHAR *)iv,
                                                            (UCHAR *)decrypt_output,
                                                            sizeof(decrypt_output),
                                                            &aes_ctx,
                                                            sizeof(aes_ctx),
                                                            NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        if ( ( aes_data[i].plain_len % test_crypto_method_aes.nx_crypto_block_size_in_bytes) && ( aes_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CBC))
        {
            EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);
        }
        else
        {
            EXPECT_EQ( 0, memcmp( aes_data[i].plain, decrypt_output, aes_data[i].plain_len));
        }

    }

    /* Specify an illegal algorithm type. */
    i = 0;
    test_crypto_method_aes.nx_crypto_algorithm = 0xFFFF;
    status = test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                        NX_CRYPTO_NULL,
                                                        &test_crypto_method_aes,
                                                        (UCHAR *)key,
                                                        (aes_data[i].key_len << 3),
                                                        aes_data[i].plain,
                                                        aes_data[i].plain_len,
                                                        (UCHAR *)iv,
                                                        (UCHAR *)encrypt_output,
                                                        sizeof(encrypt_output),
                                                        &aes_ctx,
                                                        sizeof(aes_ctx),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ( status, NX_CRYPTO_INVALID_ALGORITHM);

    /* Specify an illegal operation type in cbc mode. */
    test_crypto_method_aes.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CBC;
    status = test_crypto_method_aes.nx_crypto_operation(0xFFFF,
                                                        NX_CRYPTO_NULL,
                                                        &test_crypto_method_aes,
                                                        (UCHAR *)key,
                                                        (aes_data[i].key_len << 3),
                                                        aes_data[i].plain,
                                                        test_crypto_method_aes.nx_crypto_block_size_in_bytes,
                                                        (UCHAR *)iv,
                                                        (UCHAR *)encrypt_output,
                                                        sizeof(encrypt_output),
                                                        &aes_ctx,
                                                        sizeof(aes_ctx),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ( status, NX_CRYPTO_INVALID_ALGORITHM);

    /* Invalid block_size. */
    status = _nx_crypto_cbc_encrypt_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 17);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);
    status = _nx_crypto_cbc_encrypt(NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, 17);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);

    iv[0] = 0;

    /* Invalid block_size. */
    status = _nx_crypto_ccm_encrypt_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, 0, (UCHAR *)iv, 0, 1);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);
    status = _nx_crypto_ccm_encrypt_update(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, 1);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);
    status = _nx_crypto_ccm_encrypt_calculate(NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 1);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);
    status = _nx_crypto_ccm_decrypt_calculate(NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 1);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);

    /* Invalid iv_len. */
    status = _nx_crypto_ctr_encrypt_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 7, NX_CRYPTO_NULL, 4);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);
    status = _nx_crypto_ctr_encrypt_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 8, NX_CRYPTO_NULL, 3);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);

    /* Invalid block_size. */
    status = _nx_crypto_ctr_encrypt(NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, 1);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);

    /* Unrecognized operations. */
    test_crypto_method_aes.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CCM_8;
    status = test_crypto_method_aes.nx_crypto_operation(0xFFFF,
                                                        NX_CRYPTO_NULL,
                                                        &test_crypto_method_aes,
                                                        (UCHAR *)key,
                                                        (aes_data[i].key_len << 3),
                                                        aes_data[i].plain,
                                                        test_crypto_method_aes.nx_crypto_block_size_in_bytes,
                                                        (UCHAR *)iv,
                                                        (UCHAR *)encrypt_output,
                                                        sizeof(encrypt_output),
                                                        &aes_ctx,
                                                        sizeof(aes_ctx),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ( status, NX_CRYPTO_INVALID_ALGORITHM);

#if 0
    /* Authenication failed. */
    status = _nx_crypto_ccm_authentication_check(metadata,
                                                 (UINT (*)(VOID *, UCHAR *, UCHAR *, UINT))_nx_crypto_aes_encrypt,
                                                 NX_CRYPTO_NULL,
                                                 input, 16,
                                                 input, output, 16,
                                                 (UCHAR *)iv, 16, NX_CRYPTO_CCM_BLOCK_SIZE);
    EXPECT_EQ( status, NX_CRYPTO_AUTHENTICATION_FAILED);

    /* 0 byte additional data. */
    status = _nx_crypto_ccm_authentication_check(metadata,
                                                 (UINT (*)(VOID *, UCHAR *, UCHAR *, UINT))_nx_crypto_aes_encrypt,
                                                 NX_CRYPTO_NULL,
                                                 input, 0,
                                                 input, output, 16,
                                                 (UCHAR *)iv, 16, NX_CRYPTO_CCM_BLOCK_SIZE);
    EXPECT_EQ( status, NX_CRYPTO_AUTHENTICATION_FAILED);

    /* 0 byte plaintext to be encrypted. */
    status = _nx_crypto_ccm_encrypt(metadata,
                                    (UINT (*)(VOID *, UCHAR *, UCHAR *, UINT))_nx_crypto_aes_encrypt,
                                    NX_CRYPTO_NULL,
                                    input, 0,
                                    input, output, 0,
                                    (UCHAR *)iv, 0, NX_CRYPTO_CCM_BLOCK_SIZE
                                    );
    EXPECT_EQ( status, NX_CRYPTO_SUCCESS);

    /* the length of plaintext is not multiples of block size. */
    status = _nx_crypto_ccm_encrypt(metadata,
                                    (UINT (*)(VOID *, UCHAR *, UCHAR *, UINT))_nx_crypto_aes_encrypt,
                                    NX_CRYPTO_NULL,
                                    input, 0,
                                    input, output, 27,
                                    (UCHAR *)iv, 0, NX_CRYPTO_CCM_BLOCK_SIZE
                                    );
    EXPECT_EQ( status, NX_CRYPTO_SUCCESS);
#endif

    /* NULL crypto method pointer. */
    status = test_crypto_method_aes.nx_crypto_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 128, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL key pointer. */
    status = test_crypto_method_aes.nx_crypto_init(&test_crypto_method_aes, NX_CRYPTO_NULL, 128, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = test_crypto_method_aes.nx_crypto_init(&test_crypto_method_aes, (UCHAR *)key, 128, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata is not 4-byte aligned. */
    status = test_crypto_method_aes.nx_crypto_init(&test_crypto_method_aes, (UCHAR *)key, 128, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid metadata size. */
    status = test_crypto_method_aes.nx_crypto_init(&test_crypto_method_aes, (UCHAR *)key, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ( status, NX_CRYPTO_PTR_ERROR);

    /* Invalid key size. */
    status = test_crypto_method_aes.nx_crypto_init(&test_crypto_method_aes, (UCHAR *)key, 0, NX_CRYPTO_NULL, (VOID *)0x04, 6400);
    EXPECT_EQ( status, NX_CRYPTO_UNSUPPORTED_KEY_SIZE);

    /* Just cover it. */
    status = _nx_crypto_method_aes_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    /* NULL method pointer. */
    status = _nx_crypto_method_aes_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_aes_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata is not 4-byte aligned. */
    status = _nx_crypto_method_aes_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, (VOID *)0x03, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid metadata size. */
    status = _nx_crypto_method_aes_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL method pointer. */
    status = _nx_crypto_method_aes_cbc_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_aes_cbc_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata is not 4-byte aligned. */
    status = _nx_crypto_method_aes_cbc_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, (VOID *)0x03, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid metadata size. */
    status = _nx_crypto_method_aes_cbc_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL method pointer. */
    status = _nx_crypto_method_aes_ccm_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_aes_ccm_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata is not 4-byte aligned. */
    status = _nx_crypto_method_aes_ccm_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, (VOID *)0x03, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid metadata size. */
    status = _nx_crypto_method_aes_ccm_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL method pointer. */
    status = _nx_crypto_method_aes_ctr_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL key pointer. */
    status = _nx_crypto_method_aes_ctr_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_aes_ctr_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, (UCHAR *)key, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata is not 4-byte aligned. */
    status = _nx_crypto_method_aes_ctr_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, (UCHAR *)key, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, (VOID *)0x03, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid metadata size. */
    status = _nx_crypto_method_aes_ctr_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, (UCHAR *)key, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid algorithm. */
    test_crypto_method_aes.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CCM_8 - 1;
    status = _nx_crypto_method_aes_ccm_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, (UCHAR *)key, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, &aes_ctx, sizeof(NX_CRYPTO_AES), NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_INVALID_ALGORITHM);

    test_crypto_method_aes.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CCM + 1;
    status = _nx_crypto_method_aes_ccm_operation(0, NX_CRYPTO_NULL, &test_crypto_method_aes, (UCHAR *)key, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, &aes_ctx, sizeof(NX_CRYPTO_AES), NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_INVALID_ALGORITHM);

    /* NULL method pointer. */
    status = _nx_crypto_method_aes_xcbc_operation(0, NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, /* method */
                                                  NX_CRYPTO_NULL, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  NX_CRYPTO_NULL, 0, /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL key pointer. */
    status = _nx_crypto_method_aes_xcbc_operation(0, NX_CRYPTO_NULL,
                                                  &test_crypto_method_aes, /* method */
                                                  NX_CRYPTO_NULL, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL, /* iv */
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  NX_CRYPTO_NULL, 0, /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_aes_xcbc_operation(0, NX_CRYPTO_NULL, 
                                                  &test_crypto_method_aes,
                                                  (UCHAR *)key, 0,
                                                  NX_CRYPTO_NULL, 0,
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0,
                                                  NX_CRYPTO_NULL, 0, /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata is not 4-byte aligned. */
    status = _nx_crypto_method_aes_xcbc_operation(0, NX_CRYPTO_NULL,
                                                  &test_crypto_method_aes,
                                                  (UCHAR *)key, 0,
                                                  NX_CRYPTO_NULL, 0,
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0,
                                                  (VOID *)0x03, 0, /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid metadata size. */
    status = _nx_crypto_method_aes_xcbc_operation(0, NX_CRYPTO_NULL,
                                                 &test_crypto_method_aes,
                                                 (UCHAR *)key, 0,
                                                 NX_CRYPTO_NULL, 0,
                                                 NX_CRYPTO_NULL,
                                                 NX_CRYPTO_NULL, 0,
                                                 (VOID *)0x04, 0,
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid metadata size. */
    status = _nx_crypto_method_aes_ctr_operation(0, NX_CRYPTO_NULL,
                                                 &test_crypto_method_aes,
                                                 (UCHAR *)key, 0,
                                                 NX_CRYPTO_NULL, 0,
                                                 NX_CRYPTO_NULL,
                                                 NX_CRYPTO_NULL, 0,
                                                 (VOID *)0x04, 0,
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

/* For NX_CRYPTO_STATE_CHECK. */
#ifdef NX_CRYPTO_SELF_TEST
    backup = _nx_crypto_library_state;
    _nx_crypto_library_state = 0;

    status = _nx_crypto_method_aes_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_aes_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_aes_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_aes_cbc_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_aes_ccm_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_aes_ctr_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_aes_xcbc_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    _nx_crypto_library_state = backup;
#endif /* NX_CRYPTO_SELF_TEST */

    /* Invoke xcbc-mac operation. */
    test_crypto_method_aes.nx_crypto_algorithm = NX_CRYPTO_AUTHENTICATION_AES_XCBC_MAC_96;
    status = _nx_crypto_method_aes_operation(0, NX_CRYPTO_NULL,
                                             &test_crypto_method_aes,
                                             key_cbc_128_1, sizeof(key_cbc_128_1), /* key */
                                             test_plain, sizeof(test_plain), /* input */
                                             iv_cbc_128_0,
                                             output, sizeof(output),
                                             metadata, sizeof(metadata),
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Invalid block size. */
    status = _nx_crypto_xcbc_mac(NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* input_length_in_byte == block_size. */
    status = _nx_crypto_xcbc_mac(metadata, test_crypto_function, test_key_set_function, NX_CRYPTO_NULL, 0, input, output, NX_CRYPTO_XCBC_MAC_BLOCK_SIZE, NX_CRYPTO_NULL, 0, NX_CRYPTO_XCBC_MAC_BLOCK_SIZE);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#ifdef NX_CRYPTO_SELF_TEST
    /* Tests for _nx_crypto_method_self_test_aes. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_aes(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_algorithm == NX_CRYPTO_ENCRYPTION_AES_CBC nx_crypto_key_size_in_bits != 256 */
    test_method.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CBC; 
    test_method.nx_crypto_key_size_in_bits = 0;
    status = _nx_crypto_method_self_test_aes(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(1, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    test_method.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CTR; 
    test_method.nx_crypto_key_size_in_bits = 256;
    status = _nx_crypto_method_self_test_aes(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_algorithm == NX_CRYPTO_ENCRYPTION_AES_CTR nx_crypto_key_size_in_bits != 256 */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    test_method.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CTR; 
    test_method.nx_crypto_key_size_in_bits = 0;
    status = _nx_crypto_method_self_test_aes(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(1, status);

    /* Invalid algorithm id. */
    test_method.nx_crypto_algorithm = 0;
    status = _nx_crypto_method_self_test_aes(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(1, status);

    /* nx_crypto_operation is NULL */
    test_method.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CTR; 
    test_method.nx_crypto_key_size_in_bits = 256;
    test_method.nx_crypto_init = test_nx_crypto_init_succeed;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_aes(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);
    
    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_aes(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_aes(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed. */
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_aes(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup failed. */
    test_method = crypto_method_aes_cbc_256;
    test_method.nx_crypto_cleanup = test_nx_crypto_cleanup_failed;
    status = _nx_crypto_method_self_test_aes(&test_method, &aes_ctx, sizeof(aes_ctx));
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    EXPECT_EQ(233, status);

    /* nx_crypto_init failed at the second times. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed_second;
    status = _nx_crypto_method_self_test_aes(&test_method, &aes_ctx, sizeof(aes_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_DECRYPT failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_NX_CRYPTO_DECRYPT_failed;
    status = _nx_crypto_method_self_test_aes(&test_method, &aes_ctx, sizeof(aes_ctx));
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP(output, plain_decrypt, xx) != 0. */
    test_method.nx_crypto_operation = test_nx_crypto_operation_NX_CRYPTO_DECRYPT_error;
    status = _nx_crypto_method_self_test_aes(&test_method, &aes_ctx, sizeof(aes_ctx));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_aes_cbc_256;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_aes(&test_method, &aes_ctx, sizeof(aes_ctx));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
