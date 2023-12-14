#include <stdio.h>

#include "tls_test_utility.h"
#include "nx_crypto_rsa.h"
#include "nx_crypto_method_self_test.h"
#include "nx_crypto_pkcs1_v1.5.h"
#include "nx_crypto_hmac_sha2.h"
#include "nx_secure_rsa_key_pairs.c"

extern NX_CRYPTO_METHOD crypto_method_pkcs1;

static UINT test_crypto_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                       UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                       VOID **handler,
                       VOID *crypto_metadata,
                       ULONG crypto_metadata_size)
{
    return 0;
}

static UINT test_crypto_init_failed(struct NX_CRYPTO_METHOD_STRUCT *method,
                       UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                       VOID **handler,
                       VOID *crypto_metadata,
                       ULONG crypto_metadata_size)
{
    return 233;
}

static UINT test_crypto_cleanup(VOID *handler)
{
    return 0;
}

static UINT test_crypto_operation(UINT op,       /* Encrypt, Decrypt, Authenticate */
                           VOID *handler, /* Crypto handler */
                           struct NX_CRYPTO_METHOD_STRUCT *method,
                           UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                           UCHAR *input, ULONG input_length_in_byte,
                           UCHAR *iv_ptr,
                           UCHAR *output, ULONG output_length_in_byte,
                           VOID *crypto_metadata, ULONG crypto_metadata_size,
                           VOID *packet_ptr,
                           VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 0;
}

static UINT test_crypto_operation_failed(UINT op,       /* Encrypt, Decrypt, Authenticate */
                           VOID *handler, /* Crypto handler */
                           struct NX_CRYPTO_METHOD_STRUCT *method,
                           UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                           UCHAR *input, ULONG input_length_in_byte,
                           UCHAR *iv_ptr,
                           UCHAR *output, ULONG output_length_in_byte,
                           VOID *crypto_metadata, ULONG crypto_metadata_size,
                           VOID *packet_ptr,
                           VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 233;
}

static UINT test_crypto_operation_authenticate_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_AUTHENTICATE)
        return 233;

    return 0;
}

static UINT test_nx_crypto_operation_NX_CRYPTO_VERIFY_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_VERIFY)
        return 233;

    return _nx_crypto_method_pkcs1_v1_5_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_pkcs1_v1_5_test_application_define(void *first_unused_memory)
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
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_pkcs1;
extern NX_CRYPTO_METHOD crypto_method_sha1;

static NX_CRYPTO_RSA rsa_metadata;
static UCHAR hash_metadata[1500];
static UCHAR message_buffer[512*2];

static UCHAR msg[] = {
0x0a, 0x8a, 0x62, 0x3d, 0x34, 0xa5, 0x82, 0xce, 0xee, 0x74, 0x62, 0x88, 0xf2, 0x15, 0xb9, 0x19, 
0xc6, 0x47, 0x57, 0xda, 0xed, 0xd0, 0x00, 0x54, 0x5e, 0x1d, 0x7a, 0x04, 0x35, 0x29, 0xe5, 0x5b, 
0xa9, 0xa0, 0x4b, 0x09, 0x3e, 0x43, 0x78, 0x7b, 0x3b, 0x8e, 0x0c, 0xa2, 0x5f, 0x98, 0xce, 0xf7, 
0xd0, 0x3c, 0x43, 0xbc, 0x54, 0x76, 0x80, 0x84, 0xc3, 0x0f, 0x3c, 0xf5, 0xbd, 0x7d, 0x29, 0xcd, 
0x98, 0x05, 0x85, 0x23, 0x9c, 0x22, 0xeb, 0xf0, 0x73, 0x2a, 0x70, 0xcd, 0xdb, 0x2f, 0xeb, 0xfe, 
0x9e, 0x23, 0x94, 0xb0, 0xc4, 0x40, 0xd1, 0x7f, 0x07, 0xa7, 0x4c, 0x3b, 0x87, 0x48, 0x49, 0xec, 
0xbf, 0x01, 0x37, 0x13, 0xb8, 0x0a, 0x84, 0x33, 0x7c, 0x90, 0xb6, 0x90, 0xce, 0xa0, 0xb8, 0x37, 
0x18, 0x47, 0x71, 0x3e, 0xa5, 0xf8, 0x9b, 0x4d, 0x10, 0x2d, 0xd3, 0x5e, 0xfd, 0x51, 0xec, 0xc0
};

static UCHAR s[] = {
0x7e, 0x7b, 0xd7, 0xed, 0xd4, 0xa1, 0x37, 0xa4, 0x2b, 0x0b, 0xc8, 0x08, 0x7d, 0xd4, 0x1d, 0x4a, 
0x56, 0x5c, 0x00, 0xa1, 0xb0, 0xaa, 0xa4, 0x2b, 0x73, 0xbc, 0x98, 0x1b, 0x20, 0x6b, 0xb1, 0x8d, 
0x59, 0x83, 0x18, 0xeb, 0xea, 0x17, 0xb6, 0xde, 0xb1, 0x4e, 0x9f, 0xbc, 0xcb, 0x69, 0x0d, 0xe7, 
0x30, 0xfe, 0x68, 0x10, 0x11, 0xa2, 0x08, 0xdf, 0xab, 0x46, 0xc0, 0x9d, 0x78, 0x2e, 0x61, 0x5f, 
0xf5, 0x93, 0x74, 0xc0, 0xec, 0x3e, 0x5d, 0x74, 0xfb, 0x2a, 0xd6, 0x52, 0x89, 0x31, 0x1e, 0xef, 
0x94, 0x65, 0x86, 0xe8, 0xa7, 0x8f, 0x64, 0x59, 0xe0, 0xdb, 0x71, 0x01, 0x48, 0xd1, 0x39, 0x76, 
0x75, 0x9a, 0x86, 0x4d, 0x30, 0xeb, 0x4f, 0x28, 0x21, 0xdc, 0x65, 0x22, 0x62, 0x1d, 0x43, 0x0e, 
0x64, 0x96, 0xd4, 0xf4, 0xa4, 0x5b, 0xbc, 0x26, 0xa1, 0x14, 0x66, 0xfb, 0x97, 0x5b, 0xc3, 0x3e, 
0x55, 0x03, 0x52, 0x81, 0xc9, 0x4a, 0xcf, 0xd2, 0xee, 0x6a, 0xf0, 0x86, 0x51, 0x1c, 0x0e, 0xfc, 
0xc2, 0x5d, 0x81, 0x6c, 0x20, 0x48, 0x29, 0xb5, 0x33, 0x7c, 0x57, 0xbb, 0x7c, 0x11, 0xa1, 0x77, 
0xa4, 0xe0, 0x72, 0x1e, 0x9a, 0xc5, 0x37, 0x68, 0xa5, 0x33, 0x63, 0xbb, 0xf7, 0xec, 0xa7, 0x51, 
0x42, 0x0b, 0x95, 0x96, 0x14, 0x9d, 0xe2, 0x40, 0x00, 0xda, 0x7d, 0xa3, 0x58, 0xb9, 0x5f, 0x79, 
0x22, 0xa5, 0x80, 0xbc, 0x75, 0x7d, 0xeb, 0xf7, 0x20, 0x49, 0xff, 0x7f, 0x89, 0xdc, 0x9d, 0x83, 
0x40, 0x59, 0x97, 0x60, 0x32, 0x52, 0xa7, 0xc5, 0x2e, 0x2f, 0x61, 0xb8, 0xa4, 0xe5, 0x5f, 0x5e, 
0xd1, 0x1d, 0xf8, 0xf2, 0xf9, 0xf7, 0xd6, 0xb9, 0x61, 0x81, 0x04, 0x7b, 0xeb, 0x94, 0x5a, 0xb0, 
0x9e, 0x78, 0x58, 0xe5, 0x5e, 0x32, 0x90, 0x35, 0xb5, 0x06, 0xb4, 0x3f, 0xee, 0xad, 0x0f, 0x7e
};

static UCHAR output[512];
static UCHAR metadata[10240];

static VOID thread_0_entry(ULONG thread_input)
{
UINT status, backup;
UCHAR buffer[64];
NX_CRYPTO_METHOD test_method;
NX_CRYPTO_PKCS1_OPTIONS pkcs1_options;
NX_CRYPTO_PKCS1 pkcs1;
UCHAR *modulus;
UINT   modulus_len;
UCHAR *pub_e;
UINT   pub_e_len;
UCHAR *pri_e;
UINT   pri_e_len;
UCHAR *plain_text;
UINT   input_length;
UCHAR *cipher_text;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   PKCS1#v1.5 test....................................");

    pkcs1_options.public_cipher_method = &crypto_method_rsa;
    pkcs1_options.public_cipher_metadata = (VOID *)&rsa_metadata;
    pkcs1_options.public_cipher_metadata_size = sizeof(rsa_metadata);
    pkcs1_options.hash_method = &crypto_method_sha1;
    pkcs1_options.hash_metadata = (VOID *)&hash_metadata;
    pkcs1_options.hash_metadata_size = sizeof(hash_metadata);

    modulus = m_2048_0;
    modulus_len = sizeof(m_2048_0);
    pub_e = pub_e_2048_0;
    pub_e_len = sizeof(pub_e_2048_0);
    pri_e = pri_e_2048_0;
    pri_e_len = sizeof(pri_e_2048_0);
    plain_text = msg;
    input_length = sizeof(msg);
    cipher_text = s;

    status = crypto_method_pkcs1.nx_crypto_operation(NX_CRYPTO_SET_ADDITIONAL_DATA,
                                                     NX_CRYPTO_NULL,
                                                     &crypto_method_pkcs1,
                                                     modulus,
                                                     modulus_len << 3,
                                                     (UCHAR *)&pkcs1_options,
                                                     sizeof(pkcs1_options),
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL,
                                                     0,
                                                     &pkcs1,
                                                     sizeof(pkcs1),
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    status = crypto_method_pkcs1.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                     NX_CRYPTO_NULL,
                                                     &crypto_method_pkcs1,
                                                     pri_e,
                                                     pri_e_len << 3,
                                                     plain_text,
                                                     input_length,
                                                     NX_CRYPTO_NULL,
                                                     output,
                                                     modulus_len,
                                                     &pkcs1,
                                                     sizeof(pkcs1),
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, cipher_text, modulus_len));

    status = crypto_method_pkcs1.nx_crypto_operation(NX_CRYPTO_VERIFY,
                                                     NX_CRYPTO_NULL,
                                                     &crypto_method_pkcs1,
                                                     pub_e,
                                                     pub_e_len << 3,
                                                     plain_text,
                                                     input_length,
                                                     NX_CRYPTO_NULL,
                                                     cipher_text,
                                                     modulus_len,
                                                     &pkcs1,
                                                     sizeof(pkcs1),
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_pkcs1_v1_5_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_pkcs1_v1_5_init(&crypto_method_pkcs1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_pkcs1_v1_5_init(&crypto_method_pkcs1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_pkcs1_v1_5_init(&crypto_method_pkcs1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, &pkcs1, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_pkcs1_v1_5_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_pkcs1_v1_5_operation(0, NX_CRYPTO_NULL,
                                                    NX_CRYPTO_NULL, /* method */
                                                    NX_CRYPTO_NULL, 0, /* key */
                                                    NX_CRYPTO_NULL, 0, /* input */
                                                    NX_CRYPTO_NULL, /* iv */
                                                    NX_CRYPTO_NULL, 0, /* outptu */
                                                    NX_CRYPTO_NULL, 0, /* crypto metadata */
                                                    NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_pkcs1_v1_5_operation(0, NX_CRYPTO_NULL,
                                                    &crypto_method_pkcs1, /* method */
                                                    NX_CRYPTO_NULL, 0, /* key */
                                                    NX_CRYPTO_NULL, 0, /* input */
                                                    NX_CRYPTO_NULL, /* iv */
                                                    NX_CRYPTO_NULL, 0, /* outptu */
                                                    NX_CRYPTO_NULL, 0, /* crypto metadata */
                                                    NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_pkcs1_v1_5_operation(0, NX_CRYPTO_NULL,
                                                    &crypto_method_pkcs1, /* method */
                                                    NX_CRYPTO_NULL, 0, /* key */
                                                    NX_CRYPTO_NULL, 0, /* input */
                                                    NX_CRYPTO_NULL, /* iv */
                                                    NX_CRYPTO_NULL, 0, /* outptu */
                                                    (VOID *)0x03, 0, /* crypto metadata */
                                                    NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_pkcs1_v1_5_operation(0, NX_CRYPTO_NULL,
                                                    &crypto_method_pkcs1, /* method */
                                                    NX_CRYPTO_NULL, 0, /* key */
                                                    NX_CRYPTO_NULL, 0, /* input */
                                                    NX_CRYPTO_NULL, /* iv */
                                                    NX_CRYPTO_NULL, 0, /* outptu */
                                                    &pkcs1, 0, /* crypto metadata */
                                                    NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* options -> public_cipher_metadata < options -> public_cipher_method -> nx_crypto_metadtata_area_size. */
    pkcs1_options.public_cipher_method = &crypto_method_rsa;
    pkcs1_options.public_cipher_metadata_size = 0;
    status = _nx_crypto_method_pkcs1_v1_5_operation(NX_CRYPTO_SET_ADDITIONAL_DATA, NX_CRYPTO_NULL,
                                                    &crypto_method_pkcs1, /* method */
                                                    NX_CRYPTO_NULL, 0, /* key */
                                                    (UCHAR *)&pkcs1_options, sizeof(pkcs1_options), /* input */
                                                    NX_CRYPTO_NULL, /* iv */
                                                    NX_CRYPTO_NULL, 0, /* outptu */
                                                    &pkcs1, sizeof(pkcs1), /* crypto metadata */
                                                    NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* options -> hash_metadata_size < options -> hash_method -> nx_crypto_metadata_area_size. */
    pkcs1_options.public_cipher_method = &crypto_method_rsa;
    pkcs1_options.public_cipher_metadata = (VOID *)&rsa_metadata;
    pkcs1_options.public_cipher_metadata_size = sizeof(rsa_metadata);
    pkcs1_options.hash_method = &crypto_method_sha1;
    pkcs1_options.hash_metadata_size = 0;
    status = _nx_crypto_method_pkcs1_v1_5_operation(NX_CRYPTO_SET_ADDITIONAL_DATA, NX_CRYPTO_NULL,
                                                    &crypto_method_pkcs1, /* method */
                                                    NX_CRYPTO_NULL, 0, /* key */
                                                    (UCHAR *)&pkcs1_options, sizeof(pkcs1_options), /* input */
                                                    NX_CRYPTO_NULL, /* iv */
                                                    NX_CRYPTO_NULL, 0, /* outptu */
                                                    &pkcs1, sizeof(pkcs1), /* crypto metadata */
                                                    NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Invalid op parameter. */
    status = _nx_crypto_method_pkcs1_v1_5_operation(0xff, NX_CRYPTO_NULL,
                                                    &crypto_method_pkcs1, /* method */
                                                    NX_CRYPTO_NULL, 0, /* key */
                                                    (UCHAR *)&pkcs1_options, sizeof(pkcs1_options), /* input */
                                                    NX_CRYPTO_NULL, /* iv */
                                                    NX_CRYPTO_NULL, 0, /* outptu */
                                                    &pkcs1, sizeof(pkcs1), /* crypto metadata */
                                                    NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Invalid algorithm id. */
    test_method.nx_crypto_algorithm = 0xff;
    status = _nx_crypto_pkcs1_v1_5_encode(NX_CRYPTO_NULL, 0, &test_method, NX_CRYPTO_NULL, 0, buffer, sizeof(buffer));
    EXPECT_EQ(NX_CRYPTO_AUTHENTICATION_FAILED, status);

    /* sizeof(ctx -> scratch_buffer) < 2*(ctx -> modulus_size) */
    pkcs1.modulus_size = sizeof(pkcs1.scratch_buffer);
    pkcs1.hash_method = &crypto_method_hmac_sha256;
    pkcs1.public_cipher_method = &crypto_method_rsa;
    status = _nx_crypto_pkcs1_v1_5_verify(NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, (UCHAR *)&pkcs1);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* ctx -> public_cipher_method -> nx_crypto_init failed. */
    pkcs1.modulus_size = 0;
    pkcs1.public_cipher_method = &test_method;
    test_method.nx_crypto_init = test_crypto_init_failed;
    test_method.nx_crypto_operation = test_crypto_operation_failed;
    status = _nx_crypto_pkcs1_v1_5_verify(NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, (UCHAR *)&pkcs1);
    EXPECT_EQ(233, status);

    /* ctx -> public_cipher_method -> nx_crypto_operation failed. */
    pkcs1.modulus_size = 0;
    pkcs1.public_cipher_method = &test_method;
    test_method.nx_crypto_init = test_crypto_init;
    test_method.nx_crypto_operation = test_crypto_operation_failed;
    status = _nx_crypto_pkcs1_v1_5_verify(NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, (UCHAR *)&pkcs1);
    EXPECT_EQ(233, status);

    /* ctx -> public_cipher_method -> nx_crypto_cleanup is NULL. */
    test_method.nx_crypto_operation = test_crypto_operation;
    test_method. nx_crypto_cleanup = NX_CRYPTO_NULL;
    _nx_crypto_pkcs1_v1_5_verify(NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, (UCHAR *)&pkcs1);

    /* output_size < ctx -> modulus_size. */
    pkcs1.modulus_size = 32;
    status = _nx_crypto_pkcs1_v1_5_sign(NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, (UCHAR *)&pkcs1, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* ctx -> public_cipher_method -> nx_crypto_init failed. */
    pkcs1.modulus_size = 0;
    pkcs1.public_cipher_method = &test_method;
    pkcs1.hash_method = &crypto_method_sha1;
    test_method.nx_crypto_init = test_crypto_init_failed;
    test_method.nx_crypto_operation = test_crypto_operation_failed;
    pkcs1_options.hash_method = &crypto_method_sha1;
    pkcs1_options.hash_metadata = (VOID *)&hash_metadata;
    pkcs1_options.hash_metadata_size = sizeof(hash_metadata);
    status = _nx_crypto_pkcs1_v1_5_sign(buffer, sizeof(buffer), buffer, sizeof(buffer), (UCHAR *)&pkcs1, buffer, 0);
    EXPECT_EQ(233, status);

    /* ctx -> public_cipher_method -> nx_crypto_cleanup is NULL. */
    pkcs1.public_cipher_method = &test_method;
    test_method.nx_crypto_init = test_crypto_init;
    test_method.nx_crypto_operation = test_crypto_operation;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    _nx_crypto_pkcs1_v1_5_sign(buffer, sizeof(buffer), buffer, sizeof(buffer), (UCHAR *)&pkcs1, buffer, 0);

/* For NX_CRYPTO_STATE_CHECK. */
#ifdef NX_CRYPTO_SELF_TEST
    backup = _nx_crypto_library_state;
    _nx_crypto_library_state = 0;

    status = _nx_crypto_method_pkcs1_v1_5_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_pkcs1_v1_5_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_pkcs1_v1_5_operation(0, NX_CRYPTO_NULL,
                                                    NX_CRYPTO_NULL, /* method */
                                                    NX_CRYPTO_NULL, 0, /* key */
                                                    NX_CRYPTO_NULL, 0, /* input */
                                                    NX_CRYPTO_NULL, /* iv */
                                                    NX_CRYPTO_NULL, 0, /* outptu */
                                                    NX_CRYPTO_NULL, 0, /* crypto metadata */
                                                    NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    _nx_crypto_library_state = backup;
#endif /* NX_CRYPTO_SELF_TEST */

    /* NULL hash method. */
    pkcs1.hash_method = NX_CRYPTO_NULL;
    status = _nx_crypto_pkcs1_v1_5_sign(NX_CRYPTO_NULL, 0, /* input */
                                        NX_CRYPTO_NULL, 0, /* private key */
                                        (UCHAR *)&pkcs1, /* metadata */
                                        NX_CRYPTO_NULL, 0 /* output */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL public cipher method. */
    pkcs1.hash_method = &crypto_method_sha1;
    pkcs1.public_cipher_method = NX_CRYPTO_NULL;
    status = _nx_crypto_pkcs1_v1_5_sign(NX_CRYPTO_NULL, 0, /* input */
                                        NX_CRYPTO_NULL, 0, /* private key */
                                        (UCHAR *)&pkcs1, /* metadata */
                                        NX_CRYPTO_NULL, 0 /* output */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* publid_cipher_method -> nx_crypto_init is NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    pkcs1.public_cipher_method = &test_method;
    status = _nx_crypto_pkcs1_v1_5_sign(NX_CRYPTO_NULL, 0, /* input */
                                        NX_CRYPTO_NULL, 0, /* private key */
                                        (UCHAR *)&pkcs1, /* metadata */
                                        NX_CRYPTO_NULL, 0 /* output */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* publid_cipher_method -> nx_crypto_operation is NULL. */
    test_method.nx_crypto_init = (VOID *)0xff;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_pkcs1_v1_5_sign(NX_CRYPTO_NULL, 0, /* input */
                                        NX_CRYPTO_NULL, 0, /* private key */
                                        (UCHAR *)&pkcs1, /* metadata */
                                        NX_CRYPTO_NULL, 0 /* output */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL hash method. */
    pkcs1.hash_method = NX_CRYPTO_NULL;
    status = _nx_crypto_pkcs1_v1_5_verify(NX_CRYPTO_NULL, 0, /* message */
                                          NX_CRYPTO_NULL, 0, /* signature */
                                          NX_CRYPTO_NULL, 0, /* public key */
                                          (UCHAR *)&pkcs1 /* metadata */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL public cipher method. */
    pkcs1.hash_method = &crypto_method_sha1;
    pkcs1.public_cipher_method = NX_CRYPTO_NULL;
    status = _nx_crypto_pkcs1_v1_5_verify(NX_CRYPTO_NULL, 0, /* message */
                                        NX_CRYPTO_NULL, 0, /* signature */
                                        NX_CRYPTO_NULL, 0, /* public key */
                                        (UCHAR *)&pkcs1 /* metadata */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* publid_cipher_method -> nx_crypto_init is NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    pkcs1.public_cipher_method = &test_method;
    status = _nx_crypto_pkcs1_v1_5_verify(NX_CRYPTO_NULL, 0, /* message */
                                        NX_CRYPTO_NULL, 0, /* signature */
                                        NX_CRYPTO_NULL, 0, /* public key */
                                        (UCHAR *)&pkcs1 /* metadata */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* publid_cipher_method -> nx_crypto_operation is NULL. */
    test_method.nx_crypto_init = (VOID *)0xff;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_pkcs1_v1_5_verify(NX_CRYPTO_NULL, 0, /* message */
                                        NX_CRYPTO_NULL, 0, /* signature */
                                        NX_CRYPTO_NULL, 0, /* public key */
                                        (UCHAR *)&pkcs1 /* metadata */);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

#ifdef NX_CRYPTO_SELF_TEST
    /* Tests for pkcs1 self test. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_pkcs1(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_pkcs1(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_crypto_init_failed;
    status = _nx_crypto_method_self_test_pkcs1(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_SET_ADDITIONAL_DATA failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_crypto_operation_failed;
    status = _nx_crypto_method_self_test_pkcs1(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_AUTHENTICATE failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_crypto_operation_authenticate_failed;
    status = _nx_crypto_method_self_test_pkcs1(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* Output validation failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_crypto_operation;
    status = _nx_crypto_method_self_test_pkcs1(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_operation NX_CRYPTO_VERIFY failed. */
    test_method = crypto_method_pkcs1;
    test_method.nx_crypto_operation = test_nx_crypto_operation_NX_CRYPTO_VERIFY_failed;
    status = _nx_crypto_method_self_test_pkcs1(&test_method, metadata, sizeof(metadata));
    EXPECT_EQ(233, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_pkcs1;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_pkcs1(&test_method, metadata, sizeof(metadata));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}

