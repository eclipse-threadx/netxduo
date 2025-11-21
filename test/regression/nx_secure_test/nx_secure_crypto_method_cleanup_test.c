
#include <stdio.h>

#include "nx_crypto_rsa.h"
#include "nx_crypto_des.h"
#include "nx_crypto_3des.h"
#include "nx_crypto_aes.h"
#include "nx_crypto_sha2.h"
#include "nx_crypto_hmac_sha1.h"
#include "nx_crypto_hmac_sha5.h"
#include "nx_crypto_hmac_md5.h"
#include "nx_crypto_drbg.h"
#ifndef CERT_BUILD
#include "nx_crypto_ecdh.h"
#include "nx_crypto_ecdsa.h"
#include "nx_crypto_ecjpake.h"
#endif

#include "tls_test_utility.h"

extern VOID    test_control_return(UINT status);

#if defined(NX_SECURE_KEY_CLEAR)

/* Metadata buffer. */
static UCHAR metadata[10240];
static UCHAR scratch_buffer[4000];

static TX_THREAD thread_0;

static VOID thread_0_entry(ULONG thread_input);

/* Random data, just for cleanup test.  */
static UCHAR key_test[] = {
0xAB, 0x1D, 0x89, 0x17, 0x09, 0x9E, 0x72, 0x16, 0x8D, 0x27, 0x2D, 0x07, 0xD0, 0xCD, 0x27, 0x3A, 
0x6B, 0xE0, 0xB0, 0xFE, 0x31, 0xEA, 0x49, 0x6D, 0xD9, 0x3C, 0x2D, 0x70, 0xF9, 0xE9, 0x2C, 0x7C, 
0x65, 0x19, 0xF1, 0x2C, 0x3A, 0x50, 0x23, 0x52, 0x4F, 0xDB, 0x77, 0xFB, 0x6A, 0xE2, 0xDA, 0xFD, 
0x79, 0xEA, 0xA8, 0x3E, 0xCF, 0x54, 0x93, 0x56, 0x4A, 0x27, 0x01, 0x9D, 0xEB, 0x05, 0x0C, 0x24, 
0xED, 0x82, 0xD7, 0xD1, 0xDD, 0xC6, 0x87, 0x2F, 0xCE, 0xF4, 0xBD, 0xD8, 0xBB, 0xA7, 0xB1, 0x19, 
0xEB, 0xB6, 0xE4, 0x86, 0x53, 0x28, 0xD3, 0xC9, 0xB8, 0xEB, 0x02, 0xFB, 0x6A, 0x41, 0xF3, 0xCF, 
0xDE, 0x65, 0xF9, 0x7B, 0xC1, 0x87, 0xB2, 0x5B, 0x2F, 0x24, 0x75, 0x11, 0x4C, 0x70, 0xD1, 0x36, 
0x86, 0xB1, 0xB8, 0x40, 0x96, 0x25, 0x7B, 0xD7, 0x5B, 0x28, 0xBD, 0x83, 0x97, 0x7D, 0x35, 0xD7, 
0xAB, 0x1D, 0x89, 0x17, 0x09, 0x9E, 0x72, 0x16, 0x8D, 0x27, 0x2D, 0x07, 0xD0, 0xCD, 0x27, 0x3A, 
0x6B, 0xE0, 0xB0, 0xFE, 0x31, 0xEA, 0x49, 0x6D, 0xD9, 0x3C, 0x2D, 0x70, 0xF9, 0xE9, 0x2C, 0x7C, 
0x65, 0x19, 0xF1, 0x2C, 0x3A, 0x50, 0x23, 0x52, 0x4F, 0xDB, 0x77, 0xFB, 0x6A, 0xE2, 0xDA, 0xFD, 
0x79, 0xEA, 0xA8, 0x3E, 0xCF, 0x54, 0x93, 0x56, 0x4A, 0x27, 0x01, 0x9D, 0xEB, 0x05, 0x0C, 0x24, 
0xED, 0x82, 0xD7, 0xD1, 0xDD, 0xC6, 0x87, 0x2F, 0xCE, 0xF4, 0xBD, 0xD8, 0xBB, 0xA7, 0xB1, 0x19, 
0xEB, 0xB6, 0xE4, 0x86, 0x53, 0x28, 0xD3, 0xC9, 0xB8, 0xEB, 0x02, 0xFB, 0x6A, 0x41, 0xF3, 0xCF, 
0xDE, 0x65, 0xF9, 0x7B, 0xC1, 0x87, 0xB2, 0x5B, 0x2F, 0x24, 0x75, 0x11, 0x4C, 0x70, 0xD1, 0x36, 
0x86, 0xB1, 0xB8, 0x40, 0x96, 0x25, 0x7B, 0xD7, 0x5B, 0x28, 0xBD, 0x83, 0x97, 0x7D, 0x35, 0xD7, 
};

static UCHAR iv_test[] = {
0x54, 0x44, 0x3D, 0x48, 0xBD, 0x11, 0xEC, 0x39, 0x32, 0xD6, 0x02, 0x15, 0x01, 0x3C, 0xA6, 0x7E, 
0xDC, 0xB5, 0x50, 0x34, 0x3E, 0x3C, 0x94, 0x60, 0xA6, 0x44, 0x3E, 0x54, 0x8E, 0x9D, 0xC7, 0xAC, 
0x92, 0xD5, 0x4D, 0xB1, 0x6C, 0x1E, 0x1E, 0xE6, 0xE0, 0x30, 0xC2, 0x4B, 0x6B, 0xFD, 0xBF, 0xBE, 
0x68, 0x15, 0xA9, 0x39, 0x15, 0x3D, 0x1F, 0x39, 0xB5, 0x56, 0xB4, 0x33, 0x22, 0x93, 0xDF, 0xC0, 
0x59, 0x9A, 0x02, 0x2E, 0x89, 0xF8, 0x3B, 0xD3, 0xCC, 0x43, 0x6F, 0x8B, 0xD4, 0x72, 0x70, 0xD7, 
0x54, 0x44, 0x54, 0xAB, 0xFB, 0x67, 0xBC, 0x60, 0xFE, 0x6C, 0x3D, 0x37, 0x1B, 0x00, 0xFC, 0xD1, 
0x73, 0x1B, 0x39, 0xD3, 0xBE, 0x25, 0x4C, 0xBC, 0x21, 0x01, 0x6A, 0x44, 0x12, 0xCA, 0xBB, 0x5B, 
0x2A, 0xE7, 0x16, 0x69, 0x4B, 0x41, 0x31, 0x3D, 0xDA, 0x35, 0x4D, 0x89, 0xE8, 0x61, 0xA7, 0xF1, 
};

static UCHAR input_test[] = {
0x6E, 0x10, 0x33, 0x33, 0xC6, 0x09, 0x9F, 0x3C, 0x7A, 0x70, 0x26, 0x4C, 0x39, 0xD1, 0x86, 0x19, 
0x53, 0x42, 0xBB, 0x36, 0x6C, 0xEA, 0x71, 0x30, 0xD8, 0xF3, 0x63, 0x28, 0x87, 0x1F, 0x51, 0x78, 
0x03, 0xDA, 0x2C, 0x23, 0x28, 0x60, 0x94, 0x25, 0xEB, 0xE0, 0x3A, 0x05, 0xA8, 0x01, 0x89, 0x0B, 
0xD0, 0xCE, 0x48, 0x1A, 0xF4, 0x99, 0x61, 0x24, 0x10, 0x52, 0x19, 0x1D, 0xA5, 0x2C, 0x93, 0x5C, 
0x3F, 0xC2, 0xB7, 0x2F, 0x8D, 0xD6, 0xF4, 0x15, 0xCF, 0xFE, 0xD4, 0x20, 0x8F, 0xA7, 0xF5, 0x5F, 
0x4F, 0x36, 0xAE, 0x5F, 0xBA, 0xE1, 0xBC, 0x58, 0xE0, 0x08, 0x3A, 0x0F, 0x7E, 0xE0, 0xFC, 0x20, 
0x2B, 0x0A, 0x0C, 0x5D, 0x1F, 0xC6, 0x8C, 0x44, 0x85, 0xA9, 0x6B, 0x19, 0xD6, 0xC0, 0x82, 0x75, 
0x3A, 0x0B, 0x1F, 0x71, 0xEB, 0x80, 0x4D, 0x5B, 0x74, 0x9B, 0xD7, 0x61, 0xA8, 0x1B, 0x52, 0x24, 
0x6E, 0x10, 0x33, 0x33, 0xC6, 0x09, 0x9F, 0x3C, 0x7A, 0x70, 0x26, 0x4C, 0x39, 0xD1, 0x86, 0x19, 
0x53, 0x42, 0xBB, 0x36, 0x6C, 0xEA, 0x71, 0x30, 0xD8, 0xF3, 0x63, 0x28, 0x87, 0x1F, 0x51, 0x78, 
0x03, 0xDA, 0x2C, 0x23, 0x28, 0x60, 0x94, 0x25, 0xEB, 0xE0, 0x3A, 0x05, 0xA8, 0x01, 0x89, 0x0B, 
0xD0, 0xCE, 0x48, 0x1A, 0xF4, 0x99, 0x61, 0x24, 0x10, 0x52, 0x19, 0x1D, 0xA5, 0x2C, 0x93, 0x5C, 
0x3F, 0xC2, 0xB7, 0x2F, 0x8D, 0xD6, 0xF4, 0x15, 0xCF, 0xFE, 0xD4, 0x20, 0x8F, 0xA7, 0xF5, 0x5F, 
0x4F, 0x36, 0xAE, 0x5F, 0xBA, 0xE1, 0xBC, 0x58, 0xE0, 0x08, 0x3A, 0x0F, 0x7E, 0xE0, 0xFC, 0x20, 
0x2B, 0x0A, 0x0C, 0x5D, 0x1F, 0xC6, 0x8C, 0x44, 0x85, 0xA9, 0x6B, 0x19, 0xD6, 0xC0, 0x82, 0x75, 
0x3A, 0x0B, 0x1F, 0x71, 0xEB, 0x80, 0x4D, 0x5B, 0x74, 0x9B, 0xD7, 0x61, 0xA8, 0x1B, 0x52, 0x24, 
};

static UCHAR output_test[] = {
0x9B, 0xFF, 0xC5, 0xD6, 0xD4, 0x9E, 0x77, 0x7D, 0x27, 0x4C, 0x4F, 0x26, 0xFE, 0x01, 0x9D, 0xEE, 
0x38, 0xCC, 0x1E, 0x33, 0x8E, 0xA4, 0xB1, 0xD4, 0x83, 0xBA, 0x92, 0x2E, 0x80, 0x38, 0xF7, 0x24, 
0x45, 0xB5, 0x31, 0x7F, 0x93, 0xFD, 0x00, 0x51, 0x0C, 0x60, 0x87, 0x3C, 0x5B, 0xEC, 0xD3, 0xE0, 
0xD6, 0xE6, 0xF1, 0xED, 0x64, 0xB0, 0xD7, 0x90, 0x43, 0xBA, 0x9F, 0x42, 0x91, 0xA5, 0xB2, 0x92, 
0x82, 0x8A, 0xF0, 0xC1, 0x5F, 0xE6, 0xF8, 0xD2, 0x67, 0xFC, 0x76, 0x11, 0x4C, 0xF2, 0xD7, 0xB8, 
0x9A, 0xBE, 0x4E, 0x2C, 0xCF, 0xD6, 0xD4, 0x9A, 0x80, 0xD3, 0x11, 0x53, 0xBA, 0x0D, 0xEB, 0xB2, 
0xDF, 0xA1, 0xAB, 0xE7, 0x5A, 0xA2, 0xF4, 0xC4, 0xD2, 0x62, 0x32, 0xF2, 0x70, 0x59, 0x2A, 0xE7, 
0x08, 0x39, 0xBA, 0x2A, 0xF4, 0xD0, 0xB3, 0x2B, 0x44, 0xE9, 0x6F, 0x21, 0x05, 0x8E, 0x0C, 0xB1, 
0x9B, 0xFF, 0xC5, 0xD6, 0xD4, 0x9E, 0x77, 0x7D, 0x27, 0x4C, 0x4F, 0x26, 0xFE, 0x01, 0x9D, 0xEE, 
0x38, 0xCC, 0x1E, 0x33, 0x8E, 0xA4, 0xB1, 0xD4, 0x83, 0xBA, 0x92, 0x2E, 0x80, 0x38, 0xF7, 0x24, 
0x45, 0xB5, 0x31, 0x7F, 0x93, 0xFD, 0x00, 0x51, 0x0C, 0x60, 0x87, 0x3C, 0x5B, 0xEC, 0xD3, 0xE0, 
0xD6, 0xE6, 0xF1, 0xED, 0x64, 0xB0, 0xD7, 0x90, 0x43, 0xBA, 0x9F, 0x42, 0x91, 0xA5, 0xB2, 0x92, 
0x82, 0x8A, 0xF0, 0xC1, 0x5F, 0xE6, 0xF8, 0xD2, 0x67, 0xFC, 0x76, 0x11, 0x4C, 0xF2, 0xD7, 0xB8, 
0x9A, 0xBE, 0x4E, 0x2C, 0xCF, 0xD6, 0xD4, 0x9A, 0x80, 0xD3, 0x11, 0x53, 0xBA, 0x0D, 0xEB, 0xB2, 
0xDF, 0xA1, 0xAB, 0xE7, 0x5A, 0xA2, 0xF4, 0xC4, 0xD2, 0x62, 0x32, 0xF2, 0x70, 0x59, 0x2A, 0xE7, 
0x08, 0x39, 0xBA, 0x2A, 0xF4, 0xD0, 0xB3, 0x2B, 0x44, 0xE9, 0x6F, 0x21, 0x05, 0x8E, 0x0C, 0xB1, 
};

static ULONG error_counter = 0;

static NX_CRYPTO_METHOD crypto_method_des_cbc = 
{
    NX_CRYPTO_ENCRYPTION_DES_CBC,             /* DES crypto algorithm filled at runtime */
    NX_CRYPTO_DES_KEY_LEN_IN_BITS,            /* Key size in bits                       */
    NX_CRYPTO_DES_IV_LEN_IN_BITS,             /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS,         /* Block size in bytes                    */
    sizeof(NX_CRYPTO_DES),                    /* Metadata size in bytes                 */
    _nx_crypto_method_des_init,               /* DES initialization routine             */
    _nx_crypto_method_des_cleanup,            /* DES cleanup routine                    */
    _nx_crypto_method_des_operation           /* DES operation                          */

};
static NX_CRYPTO_METHOD crypto_method_aes_ctr_128 = 
{
    NX_CRYPTO_ENCRYPTION_AES_CTR,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_128_KEY_LEN_IN_BITS,        /* Key size in bits                       */
    64,                                       /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used             */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),  /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES-CTR initialization routine         */
    _nx_crypto_method_aes_cleanup,            /* AES-CTR cleanup routine                */
    _nx_crypto_method_aes_ctr_operation       /* AES-CTR operation                      */
};
static NX_CRYPTO_METHOD crypto_method_aes_ctr_192 = 
{
    NX_CRYPTO_ENCRYPTION_AES_CTR,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_192_KEY_LEN_IN_BITS,        /* Key size in bits                       */
    64,                                       /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used             */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),  /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES-CTR initialization routine         */
    _nx_crypto_method_aes_cleanup,            /* AES-CTR cleanup routine                */
    _nx_crypto_method_aes_ctr_operation       /* AES-CTR operation                      */
};
static NX_CRYPTO_METHOD crypto_method_aes_ctr_256 = 
{
    NX_CRYPTO_ENCRYPTION_AES_CTR,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_256_KEY_LEN_IN_BITS,        /* Key size in bits                       */
    64,                                       /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used             */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),  /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES-CTR initialization routine         */
    _nx_crypto_method_aes_cleanup,            /* AES-CTR cleanup routine                */
    _nx_crypto_method_aes_ctr_operation       /* AES-CTR operation                      */
};

#if defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) && defined(NX_SECURE_ENABLE_DTLS) && !defined(CERT_BUILD)
static NX_CRYPTO_METHOD crypto_method_ecjpake =
{
    NX_CRYPTO_KEY_EXCHANGE_ECJPAKE,                   /* ECJPAKE algorithm                     */
    0,                                                /* Key size in bits                      */
    0,                                                /* IV size in bits, not used             */
    0,                                                /* Transmitted ICV size in bits          */
    0,                                                /* Block size in bytes, not used         */
    sizeof(NX_CRYPTO_ECJPAKE),                        /* Metadata size in bytes                */
    _nx_crypto_method_ecjpake_init,                   /* Initialization routine                */
    _nx_crypto_method_ecjpake_cleanup,                /* Cleanup routine                       */
    _nx_crypto_method_ecjpake_operation               /* ECJPAKE operation                     */
};
static NX_CRYPTO_METHOD crypto_method_ec_secp256 =
{
    NX_CRYPTO_EC_SECP256R1,                   /* EC placeholder                         */
    256,                                      /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    0,                                        /* Metadata size in bytes                 */
    NX_NULL,                                  /* Initialization routine.                */
    NX_NULL,                                  /* Cleanup routine, not used.             */
    _nx_crypto_method_ec_secp256r1_operation, /* Operation                              */
};
static NX_CRYPTO_METHOD crypto_method_ec_secp521 =
{
    NX_CRYPTO_EC_SECP521R1,                   /* EC placeholder                         */
    521,                                      /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    0,                                        /* Metadata size in bytes                 */
    NX_NULL,                                  /* Initialization routine.                */
    NX_NULL,                                  /* Cleanup routine, not used.             */
    _nx_crypto_method_ec_secp521r1_operation, /* Operation                              */
};
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_METHOD crypto_method_ecdh;
#endif

extern NX_CRYPTO_METHOD crypto_method_drbg;
extern NX_CRYPTO_METHOD crypto_method_3des;
extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_192;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_sha384;
extern NX_CRYPTO_METHOD crypto_method_sha512;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha1;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha384;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha512;
extern NX_CRYPTO_METHOD crypto_method_hmac_md5;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha384;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha512;

typedef struct TEST_CLEANUP_STRUCT
{
    NX_CRYPTO_METHOD  *test_method;
    UINT               test_op[3];
    UINT               test_op_size;
    UINT               test_input_length;
}TEST_CLEANUP;

static TEST_CLEANUP test_cleanup_data[] = {
    {&crypto_method_rsa, {NX_CRYPTO_ENCRYPT, NX_NULL, NX_NULL,}, 1, sizeof(input_test),},
    {&crypto_method_des_cbc, {NX_CRYPTO_ENCRYPT, NX_CRYPTO_DECRYPT, NX_NULL,}, 2, sizeof(input_test),},
    {&crypto_method_3des, {NX_CRYPTO_ENCRYPT, NX_CRYPTO_DECRYPT, NX_NULL,}, 2, sizeof(input_test),},
    {&crypto_method_aes_cbc_128, {NX_CRYPTO_ENCRYPT, NX_CRYPTO_DECRYPT, NX_NULL,}, 2, sizeof(input_test),},
    {&crypto_method_aes_cbc_192, {NX_CRYPTO_ENCRYPT, NX_CRYPTO_DECRYPT, NX_NULL,}, 2, sizeof(input_test),},
    {&crypto_method_aes_cbc_256, {NX_CRYPTO_ENCRYPT, NX_CRYPTO_DECRYPT, NX_NULL,}, 2, sizeof(input_test),},
    {&crypto_method_aes_ctr_128, {NX_CRYPTO_ENCRYPT, NX_NULL, NX_NULL,}, 1, sizeof(input_test),},
    {&crypto_method_aes_ctr_192, {NX_CRYPTO_ENCRYPT, NX_NULL, NX_NULL,}, 1, sizeof(input_test),},
    {&crypto_method_aes_ctr_256, {NX_CRYPTO_ENCRYPT, NX_NULL, NX_NULL,}, 1, sizeof(input_test),},
    {&crypto_method_sha1, {NX_CRYPTO_HASH_INITIALIZE, NX_CRYPTO_HASH_UPDATE, NX_CRYPTO_HASH_CALCULATE,}, 3, sizeof(input_test),},
    {&crypto_method_sha256, {NX_CRYPTO_HASH_INITIALIZE, NX_CRYPTO_HASH_UPDATE, NX_CRYPTO_HASH_CALCULATE,}, 3, sizeof(input_test),},
    {&crypto_method_sha384, {NX_CRYPTO_HASH_INITIALIZE, NX_CRYPTO_HASH_UPDATE, NX_CRYPTO_HASH_CALCULATE,}, 3, sizeof(input_test),},
    {&crypto_method_sha512, {NX_CRYPTO_HASH_INITIALIZE, NX_CRYPTO_HASH_UPDATE, NX_CRYPTO_HASH_CALCULATE,}, 3, sizeof(input_test),},
    {&crypto_method_hmac_sha1, {NX_CRYPTO_AUTHENTICATE, NX_NULL, NX_NULL,}, 1, sizeof(input_test),},
    {&crypto_method_hmac_sha256, {NX_CRYPTO_AUTHENTICATE, NX_NULL, NX_NULL,}, 1, sizeof(input_test),},
    {&crypto_method_hmac_sha384, {NX_CRYPTO_AUTHENTICATE, NX_NULL, NX_NULL,}, 1, sizeof(input_test),},
    {&crypto_method_hmac_sha512, {NX_CRYPTO_AUTHENTICATE, NX_NULL, NX_NULL,}, 1, sizeof(input_test),},
    {&crypto_method_hmac_md5, {NX_CRYPTO_AUTHENTICATE, NX_NULL, NX_NULL,}, 1, sizeof(input_test),},
    {&crypto_method_tls_prf_1, {NX_CRYPTO_PRF, NX_NULL, NX_NULL,}, 1, 80},
    {&crypto_method_tls_prf_sha256, {NX_CRYPTO_PRF, NX_NULL, NX_NULL,}, 1, 80},
    {&crypto_method_tls_prf_sha384, {NX_CRYPTO_PRF, NX_NULL, NX_NULL,}, 1, 80},
    {&crypto_method_tls_prf_sha512, {NX_CRYPTO_PRF, NX_NULL, NX_NULL,}, 1, 80},
};

static UINT test_cleanup_size = sizeof(test_cleanup_data) / sizeof(TEST_CLEANUP);

#if defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) && defined(NX_SECURE_ENABLE_DTLS) && !defined(CERT_BUILD)
UINT crypto_method_cleanup_ecdh_test(NX_CRYPTO_METHOD *crypto_method);
UINT crypto_method_cleanup_ecdsa_test(NX_CRYPTO_METHOD *crypto_method);
UINT crypto_method_cleanup_ecjpake_test(NX_CRYPTO_METHOD *crypto_method);
#endif
UINT crypto_method_cleanup_drbg_test(NX_CRYPTO_METHOD *crypto_method);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_crypto_method_cleanup_test_application_define(void *first_unused_memory)
#endif
{
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
                     first_unused_memory, 4096,
                     16, 16, 4, TX_AUTO_START);
}

static VOID thread_0_entry(ULONG thread_input)
{
UINT i, j, k, status;
VOID *handler;
UINT key_size;
NX_CRYPTO_METHOD *crypto_method;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   Crypto Method Cleanup Test.........................");

    status = crypto_method_cleanup_drbg_test(&crypto_method_drbg);

    if (status)
    {
        error_counter++;
    }

#if defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) && defined(NX_SECURE_ENABLE_DTLS) && !defined(CERT_BUILD)
    status = crypto_method_cleanup_ecdh_test(&crypto_method_ecdh);

    if (status)
    {
        error_counter++;
    }

    status = crypto_method_cleanup_ecjpake_test(&crypto_method_ecjpake);

    if (status)
    {
        error_counter++;
    }

    status = crypto_method_cleanup_ecdsa_test(&crypto_method_ecdsa);

    if (status)
    {
        error_counter++;
    }
#endif

    for (i = 0; i < test_cleanup_size; i++)
    {
        crypto_method = test_cleanup_data[i].test_method;

        if (crypto_method -> nx_crypto_algorithm == NX_CRYPTO_KEY_EXCHANGE_RSA)
        {
            key_size = sizeof(key_test) << 3;
        }
        else
        {
            key_size = crypto_method -> nx_crypto_key_size_in_bits;
        }

        if (crypto_method -> nx_crypto_init)
        {
            status = crypto_method -> nx_crypto_init(crypto_method, key_test, key_size, &handler,
                                                     metadata, crypto_method -> nx_crypto_metadata_area_size);

            if (status)
            {
                error_counter++;
                continue;
            }
        }

        for (j = 0; j < test_cleanup_data[i].test_op_size; j++)
        {

            status = crypto_method -> nx_crypto_operation(test_cleanup_data[i].test_op[j],
                                                          &handler,
                                                          crypto_method,
                                                          key_test,
                                                          key_size,
                                                          input_test,
                                                          test_cleanup_data[i].test_input_length,
                                                          iv_test,
                                                          output_test,
                                                          sizeof(output_test),
                                                          metadata,
                                                          crypto_method -> nx_crypto_metadata_area_size,
                                                          NX_NULL, NX_NULL);

            if (status)
            {
                error_counter++;
                break;
            }
        }

        if (!crypto_method -> nx_crypto_cleanup)
        {
            error_counter++;
            continue;
        }

        status = crypto_method -> nx_crypto_cleanup((VOID *)metadata);

        if (status)
        {
            error_counter++;
            break;
        }

        for (k = 0; k < sizeof(metadata); k++)
        {
            if (metadata[k] != 0)
            {
                error_counter++;
                break;
           }
        }
    }

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
#if defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE) && defined(NX_SECURE_ENABLE_DTLS) && !defined(CERT_BUILD)
static UCHAR *ecdh_a = metadata;
static UCHAR *ecdh_b = metadata + sizeof(NX_CRYPTO_ECDH);
static UCHAR pubkey_a[256] = {0};
static UCHAR pubkey_b[256] = {0};
static UCHAR shared_secret_a[128] = {0};
static UCHAR shared_secret_b[128] = {0};

UINT crypto_method_cleanup_ecdh_test(NX_CRYPTO_METHOD *crypto_method)
{
UINT k;
UINT status;
VOID *handler_a, *handler_b;
UINT pubk_len;

    pubk_len = 1 + ((crypto_method_ec_secp521.nx_crypto_key_size_in_bits + 7) >> 2);

    if (crypto_method -> nx_crypto_init)
    {
        status = crypto_method -> nx_crypto_init(crypto_method, NX_NULL, NX_NULL, &handler_a,
                                                 ecdh_a, crypto_method -> nx_crypto_metadata_area_size);

        if (status)
        {
            return(NX_NOT_SUCCESSFUL);
        }
    }

    if (crypto_method -> nx_crypto_init)
    {
        status = crypto_method -> nx_crypto_init(crypto_method, NX_NULL, NX_NULL, &handler_b,
                                                 ecdh_b, crypto_method -> nx_crypto_metadata_area_size);

        if (status)
        {
            return(NX_NOT_SUCCESSFUL);
        }
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_EC_CURVE_SET, 
                                                  &handler_a,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)(&crypto_method_ec_secp521),
                                                  sizeof(NX_CRYPTO_METHOD *),
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  ecdh_a,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_EC_CURVE_SET, 
                                                  &handler_b,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)(&crypto_method_ec_secp521),
                                                  sizeof(NX_CRYPTO_METHOD *),
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  ecdh_b,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_DH_SETUP, 
                                                  &handler_a,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  pubkey_a,
                                                  sizeof(pubkey_a),
                                                  ecdh_a,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_DH_SETUP, 
                                                  &handler_b,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  pubkey_b,
                                                  sizeof(pubkey_b),
                                                  ecdh_b,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, 
                                                  &handler_a,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  pubkey_b,
                                                  pubk_len,
                                                  NX_NULL,
                                                  shared_secret_a,
                                                  sizeof(shared_secret_a),
                                                  ecdh_a,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, 
                                                  &handler_b,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  pubkey_a,
                                                  pubk_len,
                                                  NX_NULL,
                                                  shared_secret_b,
                                                  sizeof(shared_secret_b),
                                                  ecdh_b,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (!crypto_method -> nx_crypto_cleanup)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_cleanup((VOID *)ecdh_a);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_cleanup((VOID *)ecdh_b);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    for (k = 0; k < sizeof(metadata); k++)
    {
        if (metadata[k] != 0)
        {
            return(NX_NOT_SUCCESSFUL);
       }
    }

    return (NX_CRYPTO_SUCCESS);
}

UINT crypto_method_cleanup_ecdsa_test(NX_CRYPTO_METHOD *crypto_method)
{
UINT k;
UINT status;
VOID *handler;
NX_CRYPTO_HUGE_NUMBER private_key;
NX_CRYPTO_EC_POINT    public_key;
UINT                  buffer_size;
UINT                  curve_size;
HN_UBASE             *scratch;
NX_CRYPTO_EC         *curve;

    if (crypto_method -> nx_crypto_init)
    {
        status = crypto_method -> nx_crypto_init(crypto_method, NX_NULL, NX_NULL, &handler,
                                                 metadata, crypto_method -> nx_crypto_metadata_area_size);

        if (status)
        {
            return(NX_NOT_SUCCESSFUL);
        }
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_EC_CURVE_SET, 
                                                  &handler,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)(&crypto_method_ec_secp521),
                                                  sizeof(NX_CRYPTO_METHOD *),
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  metadata,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method_ec_secp521.nx_crypto_operation(NX_CRYPTO_EC_CURVE_GET,
                                                          NX_NULL,
                                                          &crypto_method_ec_secp521,
                                                          NX_NULL, 0,
                                                          NX_NULL, 0,
                                                          NX_NULL,
                                                          (UCHAR *)&curve,
                                                          sizeof(NX_CRYPTO_METHOD *),
                                                          metadata,
                                                          crypto_method -> nx_crypto_metadata_area_size,
                                                          NX_NULL, NX_NULL);
    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    buffer_size = curve -> nx_crypto_ec_n.nx_crypto_huge_buffer_size;
    curve_size = curve -> nx_crypto_ec_bits >> 3;
    if (curve -> nx_crypto_ec_bits & 7)
    {
        curve_size++;
    }

    scratch = (HN_UBASE*)scratch_buffer;
    NX_CRYPTO_EC_POINT_INITIALIZE(&public_key, NX_CRYPTO_EC_POINT_AFFINE, scratch, buffer_size);
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&private_key, scratch, buffer_size + 8);

    /* Generate the key pair. */
    _nx_crypto_ec_key_pair_generation_extra(curve, &curve -> nx_crypto_ec_g, &private_key,
                                            &public_key, scratch);

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_AUTHENTICATE, 
                                                  &handler,
                                                  crypto_method,
                                                  (UCHAR *)&private_key,
                                                  sizeof(NX_CRYPTO_HUGE_NUMBER *),
                                                  input_test,
                                                  sizeof(input_test),
                                                  NX_NULL,
                                                  output_test,
                                                  sizeof(output_test),
                                                  metadata,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_VERIFY, 
                                                  &handler,
                                                  crypto_method,
                                                  (UCHAR *)&public_key,
                                                  sizeof(NX_CRYPTO_HUGE_NUMBER *),
                                                  input_test,
                                                  sizeof(input_test),
                                                  NX_NULL,
                                                  output_test,
                                                  sizeof(output_test),
                                                  metadata,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (!crypto_method -> nx_crypto_cleanup)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_cleanup((VOID *)metadata);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    for (k = 0; k < sizeof(metadata); k++)
    {
        if (metadata[k] != 0)
        {
            return(NX_NOT_SUCCESSFUL);
       }
    }

    return (NX_CRYPTO_SUCCESS);
}

static UCHAR *ecjpake_ctx_client = metadata;
static UCHAR *ecjpake_ctx_server = metadata + sizeof(NX_CRYPTO_ECJPAKE);
static UCHAR client_hello[NX_CRYPTO_ECJPAKE_HELLO_LENGTH];
static UCHAR server_hello[NX_CRYPTO_ECJPAKE_HELLO_LENGTH];
static UCHAR client_ke[NX_CRYPTO_ECJPAKE_KEY_EXCHANGE_LENGTH];
static UCHAR server_ke[NX_CRYPTO_ECJPAKE_KEY_EXCHANGE_LENGTH];
static UCHAR client_pms[32];
static UCHAR server_pms[32];

UINT crypto_method_cleanup_ecjpake_test(NX_CRYPTO_METHOD *crypto_method)
{
UINT k;
UINT status;
VOID *handler_client, *handler_server;
NX_CRYPTO_EXTENDED_OUTPUT output[2];

    if (crypto_method -> nx_crypto_init)
    {
        status = crypto_method -> nx_crypto_init(crypto_method, key_test, (32 << 3), &handler_client,
                                                 ecjpake_ctx_client, crypto_method -> nx_crypto_metadata_area_size);

        if (status)
        {
            return(NX_NOT_SUCCESSFUL);
        }
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_HASH_METHOD_SET, 
                                                  &handler_client,
                                                  crypto_method,
                                                  NX_NULL,
                                                  (USHORT)(crypto_method_sha256.nx_crypto_metadata_area_size << 3),
                                                  (UCHAR *)(&crypto_method_sha256),
                                                  sizeof(NX_CRYPTO_METHOD),
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  ecjpake_ctx_client,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_CURVE_SET, 
                                                  &handler_client,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)(&crypto_method_ec_secp256),
                                                  sizeof(NX_CRYPTO_METHOD *),
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  ecjpake_ctx_client,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (crypto_method -> nx_crypto_init)
    {
        status = crypto_method -> nx_crypto_init(crypto_method, key_test, (32 << 3), &handler_server,
                                                 ecjpake_ctx_server, crypto_method -> nx_crypto_metadata_area_size);

        if (status)
        {
            return(NX_NOT_SUCCESSFUL);
        }
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_HASH_METHOD_SET, 
                                                  &handler_server,
                                                  crypto_method,
                                                  NX_NULL,
                                                  (USHORT)(crypto_method_sha256.nx_crypto_metadata_area_size << 3),
                                                  (UCHAR *)(&crypto_method_sha256),
                                                  sizeof(NX_CRYPTO_METHOD),
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  ecjpake_ctx_server,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_CURVE_SET, 
                                                  &handler_server,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)(&crypto_method_ec_secp256),
                                                  sizeof(NX_CRYPTO_METHOD *),
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  ecjpake_ctx_server,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    output[0].nx_crypto_extended_output_data = client_hello;
    output[0].nx_crypto_extended_output_length_in_byte = sizeof(client_hello);
    output[0].nx_crypto_extended_output_actual_size = 0;

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_CLIENT_HELLO_GENERATE, 
                                                  &handler_client,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)&output[0],
                                                  sizeof(output[0]),
                                                  ecjpake_ctx_client,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    output[1].nx_crypto_extended_output_data = server_hello;
    output[1].nx_crypto_extended_output_length_in_byte = sizeof(server_hello);
    output[1].nx_crypto_extended_output_actual_size = 0;

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_SERVER_HELLO_GENERATE, 
                                                  &handler_server,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)&output[1],
                                                  sizeof(output[1]),
                                                  ecjpake_ctx_server,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_SERVER_HELLO_PROCESS, 
                                                  &handler_client,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  server_hello,
                                                  output[1].nx_crypto_extended_output_actual_size,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  ecjpake_ctx_client,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_CLIENT_HELLO_PROCESS, 
                                                  &handler_client,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  client_hello,
                                                  output[0].nx_crypto_extended_output_actual_size,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  ecjpake_ctx_server,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    output[0].nx_crypto_extended_output_data = client_ke;
    output[0].nx_crypto_extended_output_length_in_byte = sizeof(client_ke);
    output[0].nx_crypto_extended_output_actual_size = 0;

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_CLIENT_KEY_EXCHANGE_GENERATE, 
                                                  &handler_client,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)&output[0],
                                                  sizeof(output[0]),
                                                  ecjpake_ctx_client,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    output[1].nx_crypto_extended_output_data = server_ke;
    output[1].nx_crypto_extended_output_length_in_byte = sizeof(server_ke);
    output[1].nx_crypto_extended_output_actual_size = 0;

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_SERVER_KEY_EXCHANGE_GENERATE, 
                                                  &handler_server,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)&output[1],
                                                  sizeof(output[1]),
                                                  ecjpake_ctx_server,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_SERVER_KEY_EXCHANGE_PROCESS, 
                                                  &handler_client,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  server_ke,
                                                  output[1].nx_crypto_extended_output_actual_size,
                                                  NX_NULL,
                                                  client_pms,
                                                  sizeof(client_pms),
                                                  ecjpake_ctx_client,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_ECJPAKE_CLIENT_KEY_EXCHANGE_PROCESS, 
                                                  &handler_server,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  client_ke,
                                                  output[0].nx_crypto_extended_output_actual_size,
                                                  NX_NULL,
                                                  server_pms,
                                                  sizeof(server_pms),
                                                  ecjpake_ctx_server,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (!crypto_method -> nx_crypto_cleanup)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_cleanup((VOID *)ecjpake_ctx_client);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_cleanup((VOID *)ecjpake_ctx_server);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    for (k = 0; k < sizeof(metadata); k++)
    {
        if (metadata[k] != 0)
        {
            return(NX_NOT_SUCCESSFUL);
       }
    }

    return (NX_CRYPTO_SUCCESS);
}
#endif

static UCHAR *entropy_input = input_test;
static UINT entropy_input_len = 32;
static UINT drbg_test_get_entropy_pr(UCHAR *entropy, UINT *entropy_len, UINT entropy_max_len);
UINT crypto_method_cleanup_drbg_test(NX_CRYPTO_METHOD *crypto_method)
{
NX_CRYPTO_DRBG_OPTIONS drbg_opt;
UINT status;
VOID *handler;
UINT k;
UCHAR *personalization_string = input_test + 32;
UINT personalization_string_len = 32;
UCHAR *nonce = input_test + 64;
UINT nonce_len = 32;
UCHAR *additional_input_reseed = input_test + 96;
UINT additional_input_reseed_len = 32;
UCHAR *additional_input = input_test + 128;
UINT additional_input_len = 32;


    drbg_opt.crypto_method = &crypto_method_aes_cbc_128;
    drbg_opt.crypto_metadata = metadata + sizeof(NX_CRYPTO_DRBG);
    drbg_opt.entropy_input = drbg_test_get_entropy_pr;
    drbg_opt.use_df = 1;
    drbg_opt.prediction_resistance = 1;
    drbg_opt.security_strength = 32;

    if (crypto_method -> nx_crypto_init)
    {
        status = crypto_method -> nx_crypto_init(crypto_method, nonce, NX_NULL, &handler,
                                                 metadata, crypto_method -> nx_crypto_metadata_area_size);

        if (status)
        {
            return(NX_NOT_SUCCESSFUL);
        }
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_DRBG_OPTIONS_SET, 
                                                  &handler,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  (UCHAR *)&drbg_opt,
                                                  sizeof(drbg_opt),
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  metadata,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_DRBG_INSTANTIATE, 
                                                  &handler,
                                                  crypto_method,
                                                  nonce,
                                                  nonce_len << 3,
                                                  personalization_string,
                                                  personalization_string_len,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  metadata,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_DRBG_RESEED, 
                                                  &handler,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  additional_input_reseed,
                                                  additional_input_reseed_len,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  metadata,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_operation(NX_CRYPTO_DRBG_GENERATE, 
                                                  &handler,
                                                  crypto_method,
                                                  NX_NULL,
                                                  NX_NULL,
                                                  additional_input,
                                                  additional_input_len,
                                                  NX_NULL,
                                                  output_test,
                                                  sizeof(output_test),
                                                  metadata,
                                                  crypto_method -> nx_crypto_metadata_area_size,
                                                  NX_NULL, NX_NULL);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    if (!crypto_method -> nx_crypto_cleanup)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    status = crypto_method -> nx_crypto_cleanup((VOID *)metadata);

    if (status)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    for (k = 0; k < sizeof(metadata); k++)
    {
        if (metadata[k] != 0)
        {
            return(NX_NOT_SUCCESSFUL);
       }
    }

    return (NX_CRYPTO_SUCCESS);
}
static UINT drbg_test_get_entropy_pr(UCHAR *entropy, UINT *entropy_len, UINT entropy_max_len)
{
    if (entropy_input_len < *entropy_len)
    {
        return(TX_SIZE_ERROR);
    }
    
    if (entropy_input_len > entropy_max_len)
    {
        return(TX_SIZE_ERROR);
    }

    memcpy(entropy, entropy_input, entropy_input_len);
    *entropy_len = entropy_input_len;

    return(NX_CRYPTO_SUCCESS);
}


#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_crypto_method_cleanup_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   Crypto Method Cleanup Test.........................N/A\n");
    test_control_return(3);
}
#endif
