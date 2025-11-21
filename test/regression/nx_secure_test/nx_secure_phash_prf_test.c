#include <stdio.h>

#include "tls_test_utility.h"
#include "nx_crypto_tls_prf_1.h"
#include "nx_crypto_tls_prf_sha256.h"
#include "nx_crypto_tls_prf_sha384.h"
#include "nx_crypto_tls_prf_sha512.h"
#include "nx_crypto_null.h"
#include "nx_crypto_method_self_test.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_phash_prf_test_application_define(void *first_unused_memory)
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

/*  Cryptographic routines. */

extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha384;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha512;

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

static UINT test_crypto_operation(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method,
                                UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                UCHAR *input, ULONG input_length_in_byte,
                                UCHAR *iv_ptr,
                                UCHAR *output, ULONG output_length_in_byte,
                                VOID *crypto_metadata, ULONG crypto_metadata_size,
                                VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 0;
};

static UINT test_crypto_cleanup(VOID *crypto_metadata)
{
    return 0;
};

static VOID thread_0_entry(ULONG thread_input)
{
UINT status, backup;
NX_CRYPTO_TLS_PRF_1 prf_1;
NX_CRYPTO_PHASH phash;
NX_CRYPTO_METHOD test_method;
UCHAR secret_sha1[] = { 0x86, 0xec, 0x88 };
UCHAR label_sha1[] = { 0xc8, 0x37, 0xaf, 0x7d };
UCHAR seed_sha1[] = { 0x36, 0x54, 0xf1, 0x6f };
UCHAR output[32];


    /* Print out test information banner.  */
    printf("NetX Secure Test:   P_Hash and PRF Test................................");

    /* Test the size of secret is odd.  */
    status = crypto_method_tls_prf_1.nx_crypto_init(&crypto_method_tls_prf_1,
                                                    secret_sha1,
                                                    sizeof(secret_sha1),
                                                    NX_CRYPTO_NULL,
                                                    (VOID *)&prf_1,
                                                    sizeof(prf_1));

    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    /* PHASH parameter error: output is null.  */
    status = crypto_method_tls_prf_1.nx_crypto_operation(NX_CRYPTO_PRF,
                                                         NX_CRYPTO_NULL,
                                                         &crypto_method_tls_prf_1,
                                                         label_sha1,
                                                         sizeof(label_sha1),
                                                         seed_sha1,
                                                         sizeof(seed_sha1),
                                                         NX_CRYPTO_NULL,
                                                         NX_CRYPTO_NULL,
                                                         NX_CRYPTO_NULL,
                                                         (VOID *)&prf_1,
                                                         sizeof(prf_1),
                                                         NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(status, NX_CRYPTO_INVALID_PARAMETER);

    status = _nx_crypto_method_prf_1_operation(0,      /* Encrypt, Decrypt, Authenticate */
                                               NX_CRYPTO_NULL, /* Crypto handler */
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    status = _nx_crypto_method_prf_sha_256_operation(0,      /* Encrypt, Decrypt, Authenticate */
                                               NX_CRYPTO_NULL, /* Crypto handler */
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    status = _nx_crypto_method_prf_sha384_operation(0,      /* Encrypt, Decrypt, Authenticate */
                                               NX_CRYPTO_NULL, /* Crypto handler */
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    status = _nx_crypto_method_prf_sha512_operation(0,      /* Encrypt, Decrypt, Authenticate */
                                               NX_CRYPTO_NULL, /* Crypto handler */
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* _nx_crypto_phash errors */
    /* hash_method is null. */
    phash.nx_crypto_hmac_method = NX_CRYPTO_NULL;
    status = _nx_crypto_phash(&phash, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_INVALID_PARAMETER);

    /* hash_method -> nx_crypto_init is null. */
    phash.nx_crypto_hmac_method = &test_method;
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    status = _nx_crypto_phash(&phash, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_INVALID_PARAMETER);

    /* hash_method -> nx_crypto_operation is null. */
    NX_CRYPTO_MEMSET(&test_method, 0xff, sizeof(test_method));
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_phash(&phash, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_INVALID_PARAMETER);

    /* hash_method -> nx_crypto_cleanup is null. */
    NX_CRYPTO_MEMSET(&test_method, 0xff, sizeof(test_method));
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_phash(&phash, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_INVALID_PARAMETER);

    /* output is null. */
    NX_CRYPTO_MEMSET(&test_method, 0xff, sizeof(test_method));
    status = _nx_crypto_phash(&phash, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_INVALID_PARAMETER);

    /* hash_size > hmac_output_size. */
    phash.nx_crypto_hmac_method = &crypto_method_hmac_sha1;
    phash.nx_crypto_hmac_output_size = 0;
    status = _nx_crypto_phash(&phash, output, 4);
    EXPECT_EQ(status, NX_CRYPTO_INVALID_PARAMETER);

    status = _nx_crypto_method_prf_1_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    status = _nx_crypto_method_prf_sha_256_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    status = _nx_crypto_method_prf_sha384_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    status = _nx_crypto_method_prf_sha512_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    /* Tests for crypto_method_public_null. */
    status = _nx_crypto_method_null_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    status = _nx_crypto_method_null_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    status = _nx_crypto_method_null_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_SUCCESS);

    /* NULL method pointer. */
    status = _nx_crypto_method_prf_1_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL key pointer. */
    status = _nx_crypto_method_prf_1_init(&crypto_method_tls_prf_sha256, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_prf_1_init(&crypto_method_tls_prf_sha256, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_prf_1_init(&crypto_method_tls_prf_sha256, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_prf_1_init(&crypto_method_tls_prf_sha256, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL method pointer. */
    status = _nx_crypto_method_prf_sha_256_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL key pointer. */
    status = _nx_crypto_method_prf_sha_256_init(&crypto_method_tls_prf_sha256, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_prf_sha_256_init(&crypto_method_tls_prf_sha256, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_prf_sha_256_init(&crypto_method_tls_prf_sha256, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_prf_sha_256_init(&crypto_method_tls_prf_sha256, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL method pointer. */
    status = _nx_crypto_method_prf_sha384_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL key pointer. */
    status = _nx_crypto_method_prf_sha384_init(&crypto_method_tls_prf_sha384, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_prf_sha384_init(&crypto_method_tls_prf_sha384, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_prf_sha384_init(&crypto_method_tls_prf_sha384, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_prf_sha384_init(&crypto_method_tls_prf_sha384, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL method pointer. */
    status = _nx_crypto_method_prf_sha512_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL key pointer. */
    status = _nx_crypto_method_prf_sha512_init(&crypto_method_tls_prf_sha512, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_prf_sha512_init(&crypto_method_tls_prf_sha512, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_prf_sha512_init(&crypto_method_tls_prf_sha512, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_prf_sha512_init(&crypto_method_tls_prf_sha512, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL key pointer. */
    status = _nx_crypto_method_prf_1_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               NX_CRYPTO_NULL, 0,                    /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_prf_1_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_prf_1_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x03, 0,               /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_prf_1_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x04, 0,               /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid crypto operation. */
    status = _nx_crypto_method_prf_1_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x04, sizeof(NX_CRYPTO_TLS_PRF_1),/* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_NOT_SUCCESSFUL);

    /* NULL key pointer. */
    status = _nx_crypto_method_prf_sha_256_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               NX_CRYPTO_NULL, 0,                    /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_prf_sha_256_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_prf_sha_256_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x03, 0,               /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_prf_sha_256_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x04, 0,               /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid crypto operation. */
    status = _nx_crypto_method_prf_sha_256_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x04, sizeof(NX_CRYPTO_TLS_PRF_SHA256),/* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_NOT_SUCCESSFUL);

    /* NULL key pointer. */
    status = _nx_crypto_method_prf_sha384_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               NX_CRYPTO_NULL, 0,                    /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_prf_sha384_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_prf_sha384_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x03, 0,               /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_prf_sha384_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x04, 0,               /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid crypto operation. */
    status = _nx_crypto_method_prf_sha384_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x04, sizeof(NX_CRYPTO_TLS_PRF_SHA384),/* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_NOT_SUCCESSFUL);

    /* NULL key pointer. */
    status = _nx_crypto_method_prf_sha512_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               NX_CRYPTO_NULL, 0,                    /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_prf_sha512_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_prf_sha512_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x03, 0,               /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_prf_sha512_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x04, 0,               /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid crypto operation. */
    status = _nx_crypto_method_prf_sha512_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_tls_prf_sha512, /* crypto_method */
                                               (VOID *)0x04, 0,               /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               (VOID *)0x04, sizeof(NX_CRYPTO_TLS_PRF_SHA512),/* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(status, NX_CRYPTO_NOT_SUCCESSFUL);

    /* hash_method -> nx_crypto_init is NULL. */
    NX_CRYPTO_MEMSET(&phash, 0, sizeof(phash));
    phash.nx_crypto_hmac_method = &test_method;
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_crypto_operation;
    test_method.nx_crypto_ICV_size_in_bits = 128;
    test_method.nx_crypto_cleanup = test_crypto_cleanup;
    phash.nx_crypto_hmac_output = output;
    phash.nx_crypto_hmac_output_size = 16;
    phash.nx_crypto_phash_temp_A = output;
    phash.nx_crypto_phash_seed = output;
    phash.nx_crypto_phash_seed_length = 16;
    _nx_crypto_phash(&phash, output, 16);

/* For NX_CRYPTO_STATE_CHECK. */
#ifdef NX_CRYPTO_SELF_TEST
    backup = _nx_crypto_library_state;
    _nx_crypto_library_state = 0;

    status = _nx_crypto_method_prf_1_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_1_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_1_operation(0, NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL, /* crypto_method */
                                               NX_CRYPTO_NULL, 0,                    /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_sha_256_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_sha_256_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_sha_256_operation(0, NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL, /* crypto_method */
                                               NX_CRYPTO_NULL, 0,                    /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_sha384_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_sha384_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_sha384_operation(0, NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL, /* crypto_method */
                                               NX_CRYPTO_NULL, 0,                    /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_sha512_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_sha512_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_prf_sha512_operation(0, NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL, /* crypto_method */
                                               NX_CRYPTO_NULL, 0,                    /* key */
                                               NX_CRYPTO_NULL, 0,                    /* input */
                                               NX_CRYPTO_NULL,                       /* iv */
                                               NX_CRYPTO_NULL, 0,                    /* output */
                                               NX_CRYPTO_NULL, 0,                    /* crypto metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);             /* packet_ptr callback */
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    _nx_crypto_library_state = backup;

    /* Tests for _nx_crypto_method_self_test_prf. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_prf(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid nx_crypto_algorithm. */
    test_method.nx_crypto_algorithm = 0;
    status = _nx_crypto_method_self_test_prf(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(1, status);

    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_PRF_HMAC_SHA1;
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_prf(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_prf(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_prf(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_prf(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_tls_prf_1;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_prf(&test_method, &prf_1, sizeof(prf_1));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
