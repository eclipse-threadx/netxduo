#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"
#include "ecc_certs.c"
#include   "nx_crypto_ecdh.h"



extern void    test_control_return(UINT status);

static NX_SECURE_TLS_SESSION session;
static NX_CRYPTO_METHOD fake_crypto_method;
static NX_CRYPTO_METHOD fake_public_auth_method;
static NX_CRYPTO_METHOD fake_x509_ecdsa_method;
static NX_CRYPTO_METHOD fake_x509_sha256_method;


static void NX_Secure_TLS_ecc_generate_keys_test();

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_ecc_generate_keys_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ECC Generate Keys Test.........................");
#if defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && !defined(NX_SECURE_DISABLE_X509)
    NX_Secure_TLS_ecc_generate_keys_test();

    printf("SUCCESS!\n");
#else
    
    printf("N/A\n");
#endif
    test_control_return(0);

}

#if defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && !defined(NX_SECURE_DISABLE_X509)

extern const                    USHORT nx_crypto_ecc_supported_groups[];
extern const                    UINT nx_crypto_ecc_supported_groups_size;

extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha1;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_sha384;
extern NX_CRYPTO_METHOD crypto_method_sha512;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;
#endif


/* Lookup table for X.509 digital certificates - they need a public-key algorithm and a hash routine for verification. */
static NX_SECURE_X509_CRYPTO _nx_crypto_x509_cipher_lookup_table_ecc_test[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_RSA_MD5,        &crypto_method_rsa,       &crypto_method_md5},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_1,      &crypto_method_rsa,       &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_rsa,       &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_1,    &crypto_method_ecdsa,     &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256,  &fake_x509_ecdsa_method,  &fake_x509_sha256_method}
};

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
#define TLS_1_3 session.nx_secure_tls_1_3
#else
#define TLS_1_3 0
#endif

static UINT _nx_crypto_method_ecdh_operation_test(UINT op,
    VOID* handle,
    struct NX_CRYPTO_METHOD_STRUCT* method,
    UCHAR* key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
    UCHAR* input, ULONG input_length_in_byte,
    UCHAR* iv_ptr,
    UCHAR* output, ULONG output_length_in_byte,
    VOID* crypto_metadata, ULONG crypto_metadata_size,
    VOID* packet_ptr,
    VOID(*nx_crypto_hw_process_callback)(VOID*, UINT))
{
    UINT status;
    NX_CRYPTO_EXTENDED_OUTPUT
        * extended_output;

    status = _nx_crypto_method_ecdh_operation(op, handle, method, key, key_size_in_bits, input, input_length_in_byte,
        iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size,
        packet_ptr, nx_crypto_hw_process_callback);

    if (op == NX_CRYPTO_DH_SETUP)
    {
        extended_output = (NX_CRYPTO_EXTENDED_OUTPUT*)output;

        /* Simulate an unsupported point format. */
        extended_output->nx_crypto_extended_output_data[0] = 0;
    }

    return(status);
}

/* Define what the initial system looks like.  */
/* Declare the ECDHE crypto method */
static NX_CRYPTO_METHOD crypto_method_ecdhe_test =
{
    NX_CRYPTO_KEY_EXCHANGE_ECDHE,                /* ECDHE crypto algorithm                 */
    0,                                           /* Key size in bits                       */
    0,                                           /* IV size in bits                        */
    0,                                           /* ICV size in bits, not used             */
    0,                                           /* Block size in bytes                    */
    sizeof(NX_CRYPTO_ECDH),                      /* Metadata size in bytes                 */
    _nx_crypto_method_ecdh_init,                 /* ECDH initialization routine            */
    _nx_crypto_method_ecdh_cleanup,              /* ECDH cleanup routine                   */
    _nx_crypto_method_ecdh_operation_test,       /* ECDH operation                         */
};
//extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc[];
static NX_SECURE_TLS_CIPHERSUITE_INFO fake_tls_session_ciphersuite;
//static NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;


/* Lookup table used to map ciphersuites to cryptographic routines. */
static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc_test[] =
{
    /* Ciphersuite,                           public cipher,             public_auth,                 session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &fake_crypto_method, &fake_crypto_method, &fake_crypto_method,     16,      16,        &fake_crypto_method,     32,        &fake_crypto_method},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &fake_crypto_method, &fake_crypto_method, &fake_crypto_method,     16,      16,        &fake_crypto_method,     32,        &fake_crypto_method},
};


static const UINT _nx_crypto_ciphersuite_lookup_table_ecc_test_size = sizeof(_nx_crypto_ciphersuite_lookup_table_ecc_test) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO);

/* Define the object we can pass into TLS. */
const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc_test =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table_ecc_test,
    sizeof(_nx_crypto_ciphersuite_lookup_table_ecc_test) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _nx_crypto_x509_cipher_lookup_table_ecc_test,
    sizeof(_nx_crypto_x509_cipher_lookup_table_ecc_test) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    &crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256,
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};

static UINT temp_named_curve;

static USHORT fake_groups[3] = {0, 1, 2};

static NX_SECURE_TLS_ECDHE_HANDSHAKE_DATA ecc_data;

#define METADATA_SIZE 1000
static ULONG crypto_metadata[METADATA_SIZE / sizeof(ULONG)];

static int init_count = 0;
static int iterations = 0;
static int call_count = 0;

static UINT fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                      UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                      VOID **handler,
                      VOID *crypto_metadata,
                      ULONG crypto_metadata_size)
{
    call_count = 0;
    if (init_count++ == 0)
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
}

static UINT fake_cleanup(VOID *crypto_metadata)
{
    return(NX_CRYPTO_NOT_SUCCESSFUL);
}

static int fake_x509_sha256_cleanup_count = 0;
static UINT fake_x509_sha256_cleanup(VOID *crypto_metadata)
{
    if(fake_x509_sha256_cleanup_count++ == 0)
        return(NX_CRYPTO_NOT_SUCCESSFUL);

    switch(fake_x509_sha256_cleanup_count)
    {
    case 2: /* Line 684 */
        ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ALGORITHM_RSA | (NX_SECURE_TLS_HASH_ALGORITHM_MD5 << 8);
        break;
    case 3: /* Line 688 */
        ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ALGORITHM_RSA | (NX_SECURE_TLS_HASH_ALGORITHM_SHA1 << 8);
        break;
    case 4: /* Line 692 */
        ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ALGORITHM_RSA | (NX_SECURE_TLS_HASH_ALGORITHM_SHA224 << 8);
        break;
    case 5: /* Line 696 */
        ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ALGORITHM_RSA | (NX_SECURE_TLS_HASH_ALGORITHM_SHA256 << 8);
        break;
    case 6: /* Line 700 */
        ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ALGORITHM_RSA | (NX_SECURE_TLS_HASH_ALGORITHM_SHA384 << 8);
        break;
    case 7: /* Line 704 */
        ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ALGORITHM_RSA | (NX_SECURE_TLS_HASH_ALGORITHM_SHA512 << 8);
        break;
    case 8: /* Line 709 */
        ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ALGORITHM_RSA | (NX_SECURE_TLS_HASH_ALGORITHM_NONE << 8);
        break;
    case 9: /* Line ??? */
        ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ALGORITHM_ANONYMOUS | (NX_SECURE_TLS_HASH_ALGORITHM_NONE << 8);
        break;
    default:
        ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ALGORITHM_RSA | (NX_SECURE_TLS_HASH_ALGORITHM_SHA512 << 8);
        break;
    }
    
    return(NX_CRYPTO_SUCCESS);
       
}


static UINT fake_operation(UINT op,       /* Encrypt, Decrypt, Authenticate */
                           VOID *handler, /* Crypto handler */
                           struct NX_CRYPTO_METHOD_STRUCT *method,
                           UCHAR *key,
                           NX_CRYPTO_KEY_SIZE key_size_in_bits,
                           UCHAR *input,
                           ULONG input_length_in_byte,
                           UCHAR *iv_ptr,
                           UCHAR *output,
                           ULONG output_length_in_byte,
                           VOID *crypto_metadata,
                           ULONG crypto_metadata_size,
                           VOID *packet_ptr,
                           VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if(call_count == iterations)
    {
        call_count = 0;
        iterations ++;
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }
    else
        call_count++;
    return(NX_CRYPTO_SUCCESS);
}


static int ecdsa_init_count = 0;
static int ecdsa_iterations = 0;
static int ecdsa_call_count = 0;

static UINT ecdsa_fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                            UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                            VOID **handler,
                            VOID *crypto_metadata,
                            ULONG crypto_metadata_size)
{
    ecdsa_call_count = 0;
    if (ecdsa_init_count++ == 0)
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
}



static UINT ecdsa_fake_operation(UINT op,       /* Encrypt, Decrypt, Authenticate */
                                 VOID *handler, /* Crypto handler */
                                 struct NX_CRYPTO_METHOD_STRUCT *method,
                                 UCHAR *key,
                                 NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                 UCHAR *input,
                                 ULONG input_length_in_byte,
                                 UCHAR *iv_ptr,
                                 UCHAR *output,
                                 ULONG output_length_in_byte,
                                 VOID *crypto_metadata,
                                 ULONG crypto_metadata_size,
                                 VOID *packet_ptr,
                                 VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if(ecdsa_call_count == ecdsa_iterations)
    {
        ecdsa_call_count = 0;
        ecdsa_iterations ++;
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }
    else
        ecdsa_call_count++;
    return(NX_CRYPTO_SUCCESS);
}


static int x509_sha256_init_count = 0;
static int x509_sha256_iterations = 0;
static int x509_sha256_call_count = 0;

static UINT x509_sha256_fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                                  UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                  VOID **handler,
                                  VOID *crypto_metadata,
                                  ULONG crypto_metadata_size)
{
    x509_sha256_call_count = 0;
    if (x509_sha256_init_count++ == 0)
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
}



static UINT x509_sha256_fake_operation(UINT op,       /* Encrypt, Decrypt, Authenticate */
                                       VOID *handler, /* Crypto handler */
                                       struct NX_CRYPTO_METHOD_STRUCT *method,
                                       UCHAR *key,
                                       NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                       UCHAR *input,
                                       ULONG input_length_in_byte,
                                       UCHAR *iv_ptr,
                                       UCHAR *output,
                                       ULONG output_length_in_byte,
                                       VOID *crypto_metadata,
                                       ULONG crypto_metadata_size,
                                       VOID *packet_ptr,
                                       VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if(x509_sha256_call_count == x509_sha256_iterations)
    {
        x509_sha256_call_count = 0;
        x509_sha256_iterations ++;
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }
    else
        x509_sha256_call_count++;
    return(NX_CRYPTO_SUCCESS);
}

static int public_auth_init_count = 0;
static int public_auth_iterations = 0;
static int public_auth_call_count = 0;

static UINT public_auth_fake_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                                  UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                  VOID **handler,
                                  VOID *crypto_metadata,
                                  ULONG crypto_metadata_size)
{
    public_auth_call_count = 0;
    if (public_auth_init_count++ == 0)
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    return(NX_CRYPTO_SUCCESS);
}



static UINT public_auth_fake_operation(UINT op,       /* Encrypt, Decrypt, Authenticate */
                                       VOID *handler, /* Crypto handler */
                                       struct NX_CRYPTO_METHOD_STRUCT *method,
                                       UCHAR *key,
                                       NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                       UCHAR *input,
                                       ULONG input_length_in_byte,
                                       UCHAR *iv_ptr,
                                       UCHAR *output,
                                       ULONG output_length_in_byte,
                                       VOID *crypto_metadata,
                                       ULONG crypto_metadata_size,
                                       VOID *packet_ptr,
                                       VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if(public_auth_call_count == public_auth_iterations)
    {
        public_auth_call_count = 0;
        public_auth_iterations ++;
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }
    else
        public_auth_call_count++;
    return(NX_CRYPTO_SUCCESS);
}

/* Declare a placeholder for EC SECP256R1. */
static NX_CRYPTO_METHOD crypto_method_fake_ec_secp256 =
{
    NX_CRYPTO_EC_SECP256R1<<1,                /* EC placeholder                         */
    256,                                      /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    0,                                        /* Metadata size in bytes                 */
    NX_CRYPTO_NULL,                           /* Initialization routine.                */
    NX_CRYPTO_NULL,                           /* Cleanup routine, not used.             */
    _nx_crypto_method_ec_secp256r1_operation, /* Operation                              */
};

/* Declare a placeholder for EC SECP384R1. */
static NX_CRYPTO_METHOD crypto_method_fake_ec_secp384 =
{
    NX_CRYPTO_EC_SECP384R1<<1,                /* EC placeholder                         */
    384,                                      /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    0,                                        /* Metadata size in bytes                 */
    NX_CRYPTO_NULL,                           /* Initialization routine.                */
    NX_CRYPTO_NULL,                           /* Cleanup routine, not used.             */
    _nx_crypto_method_ec_secp384r1_operation, /* Operation                              */
};

/* Declare a placeholder for EC SECP521R1. */
static NX_CRYPTO_METHOD crypto_method_fake_ec_secp521 =
{
    NX_CRYPTO_EC_SECP521R1<<1,                /* EC placeholder                         */
    521,                                      /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    0,                                        /* Metadata size in bytes                 */
    NX_CRYPTO_NULL,                           /* Initialization routine.                */
    NX_CRYPTO_NULL,                           /* Cleanup routine, not used.             */
    _nx_crypto_method_ec_secp521r1_operation, /* Operation                              */
};


static const NX_CRYPTO_METHOD *fake_ecc_curves[3] =
{
    &crypto_method_fake_ec_secp256,
    &crypto_method_fake_ec_secp384,
    &crypto_method_fake_ec_secp521,

};

static UCHAR public_key[50];
static NX_SECURE_X509_CERT      local_certificate;
TEST(NX_Secure_TLS, ecc_generate_keys_test)
{
UINT status;
UINT public_key_size = 2;



    nx_system_initialize();



    /* Set a fake tls_session_ciphersuite. */
    session.nx_secure_tls_session_ciphersuite = &fake_tls_session_ciphersuite;
    fake_tls_session_ciphersuite.nx_secure_tls_public_cipher = NX_NULL;

    /* Cover line 146 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, NX_NULL, NX_NULL, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);    

    /* Cover line 146 */
    fake_tls_session_ciphersuite.nx_secure_tls_public_cipher = &fake_crypto_method;
    fake_crypto_method.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, NX_NULL, NX_NULL, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);    

    fake_crypto_method.nx_crypto_operation = &fake_operation;

    /* Cover line 158 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, NX_NULL, NX_NULL, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYTPO_MISSING_ECC_CURVE, status);

    /* set up the curves */
    session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 3;
    session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups = fake_groups;
    session.nx_secure_tls_ecc.nx_secure_tls_ecc_curves = &fake_ecc_curves[0];

    /* Cover line 166 and 189 */
    fake_crypto_method.nx_crypto_init = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, NX_NULL, NX_NULL, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 176 */
    fake_crypto_method.nx_crypto_init = fake_init;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, NX_NULL, NX_NULL, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    

    /* Cover line 237 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    

    /* Cover line 267 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    

    /* Cover line 267/274 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
  //  EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    

    /* Cover line 279 */
    fake_crypto_method.nx_crypto_cleanup = fake_cleanup;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);    

    /* Cover line 274, 284 */
    fake_crypto_method.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 0, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SUCCESS, status);
    
    /* Cover line 298, 305 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status); 

    /* Add a local certificate */
    nx_secure_tls_initialize();
    memset(&local_certificate, 0, sizeof(local_certificate));
    status =  nx_secure_tls_session_create(&session,
                                           &nx_crypto_tls_ciphers_ecc_test,
                                           crypto_metadata,
                                           sizeof(crypto_metadata));
    session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 3;
    session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups = fake_groups;
    session.nx_secure_tls_ecc.nx_secure_tls_ecc_curves = &fake_ecc_curves[0];

    /* Cover line 320 */
    session.nx_secure_tls_session_ciphersuite = &fake_tls_session_ciphersuite;
    status = nx_secure_x509_certificate_initialize(&local_certificate,
                                                   ECTestServer2_der, ECTestServer2_der_len,
                                                   NX_NULL, 0, ECTestServer2_key_der,
                                                   ECTestServer2_key_der_len,
                                                   NX_SECURE_X509_KEY_TYPE_EC_DER);
    _nx_secure_tls_local_certificate_add(&session, &local_certificate);
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, 0, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);

    /* Set up a valid nx_secure_tls_ecdhe_signature_algorithm so we can pass line 318 */
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;
    /* Intercept the hash method. */
    nx_crypto_tls_ciphers_ecc_test.nx_secure_tls_x509_cipher_table->nx_secure_x509_public_cipher_method = &fake_crypto_method;
    nx_crypto_tls_ciphers_ecc_test.nx_secure_tls_x509_cipher_table->nx_secure_x509_hash_method = &fake_crypto_method;
    
    status = nx_secure_tls_ecc_initialize(&session, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          fake_ecc_curves);

    /* Cover line 349  and line 388*/
    fake_x509_sha256_method.nx_crypto_init = NX_NULL;
    fake_x509_sha256_method.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

    /* Cover line 360 */
    fake_x509_sha256_method.nx_crypto_init = x509_sha256_fake_init;
    fake_x509_sha256_method.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 383 */
    fake_x509_sha256_method.nx_crypto_init = NX_NULL;
    fake_x509_sha256_method.nx_crypto_operation = x509_sha256_fake_operation;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 408 */
    fake_x509_sha256_method.nx_crypto_init = x509_sha256_fake_init;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 428 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 448 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 468 */
    fake_x509_sha256_method.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 477 */
    fake_x509_sha256_method.nx_crypto_cleanup = fake_x509_sha256_cleanup;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover line 471 */
    fake_tls_session_ciphersuite.nx_secure_tls_public_auth = &fake_public_auth_method;
    fake_public_auth_method.nx_crypto_init = public_auth_fake_init;
    fake_public_auth_method.nx_crypto_cleanup = fake_cleanup;
    fake_public_auth_method.nx_crypto_operation = public_auth_fake_operation;


    fake_x509_sha256_method.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);

    /* Cover Line 653, 787 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);

    /* Cover Line 787, 821 */
    fake_public_auth_method.nx_crypto_init = NX_NULL;
    fake_public_auth_method.nx_crypto_operation = NX_NULL;
    fake_public_auth_method.nx_crypto_algorithm = NX_CRYPTO_DIGITAL_SIGNATURE_ECDSA;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

    /* Cover Line 816 */
    fake_public_auth_method.nx_crypto_init = public_auth_fake_init;
    fake_public_auth_method.nx_crypto_operation = public_auth_fake_operation;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover Line 833 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover Line 853 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover Line 862 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover Line 856 */
    fake_public_auth_method.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Cover Line 795 */
    fake_public_auth_method.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Cover Line 653 */
    fake_public_auth_method.nx_crypto_algorithm = NX_CRYPTO_KEY_EXCHANGE_RSA;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);

    /* Cover Line 653 */
    fake_public_auth_method.nx_crypto_algorithm = NX_CRYPTO_DIGITAL_SIGNATURE_RSA;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);

    /* Cover Line 653 */
    fake_public_auth_method.nx_crypto_algorithm = 0;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);


    /* Cover Line 795 */
    temp_named_curve = local_certificate.nx_secure_x509_private_key.ec_private_key.nx_secure_ec_named_curve;
    local_certificate.nx_secure_x509_private_key.ec_private_key.nx_secure_ec_named_curve = 0;
    fake_public_auth_method.nx_crypto_algorithm = NX_CRYPTO_DIGITAL_SIGNATURE_ECDSA;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYTPO_MISSING_ECC_CURVE, status);
    local_certificate.nx_secure_x509_private_key.ec_private_key.nx_secure_ec_named_curve = temp_named_curve;

    /* Install special handler for testing line 653-786 */
    fake_x509_sha256_method.nx_crypto_cleanup = fake_x509_sha256_cleanup;
    
    fake_public_auth_method.nx_crypto_init = NX_NULL;
    fake_public_auth_method.nx_crypto_operation = NX_NULL;
    fake_public_auth_method.nx_crypto_cleanup = NX_NULL;
    public_auth_call_count = 0;
    public_auth_init_count = 0;
    public_auth_iterations = 0;
    /* Cover Line 653, 684 */
    fake_public_auth_method.nx_crypto_algorithm = NX_CRYPTO_DIGITAL_SIGNATURE_RSA;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SUCCESS, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 688 */
    fake_public_auth_method.nx_crypto_init = public_auth_fake_init;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 692 */
    fake_public_auth_method.nx_crypto_operation = public_auth_fake_operation;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 696 */
    fake_public_auth_method.nx_crypto_cleanup = fake_cleanup;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 700 */
    fake_public_auth_method.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SUCCESS, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 704 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SUCCESS, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 709 */
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 787 */
    fake_public_auth_method.nx_crypto_algorithm = 0;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;
    fake_public_auth_method.nx_crypto_algorithm = NX_CRYPTO_DIGITAL_SIGNATURE_RSA;

    /* Cover Line 719 */
    local_certificate.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = 19;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 719 */
    local_certificate.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = 515;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 719 */
    local_certificate.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = (515 + 19);
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 787 */
    local_certificate.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = (515 + 19);
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
    ecc_data.nx_secure_tls_ecdhe_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA256;

    /* Cover Line 653 */
    fake_public_auth_method.nx_crypto_algorithm = 0;
    status = _nx_secure_tls_ecc_generate_keys(session.nx_secure_tls_session_ciphersuite, session.nx_secure_tls_protocol_version,
                                              TLS_1_3, session.nx_secure_tls_crypto_table,
                                              &session.nx_secure_tls_handshake_hash, &session.nx_secure_tls_ecc, &session.nx_secure_tls_key_material,
                                              &session.nx_secure_tls_credentials, NX_CRYPTO_EC_SECP256R1, 1, public_key, &public_key_size, &ecc_data,
                                              session.nx_secure_public_cipher_metadata_area,
                                              session.nx_secure_public_cipher_metadata_size,
                                              session.nx_secure_public_auth_metadata_area,
                                              session.nx_secure_public_auth_metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_SIGNATURE_ALGORITHM, status);

}

#endif
