#include "nx_secure_tls_api.h"
#include "nx_crypto.h"

// Utility function to print buffer
void print_buffer(const UCHAR* buf, ULONG size)
{
UINT i;
    printf("Buffer of size: %ld. Data:\n", size);
    if(buf)
    {
        for(i = 0; i < size; ++i)
        {
            printf("%02x ", (UINT)buf[i]);
            if((i+1) % 8 == 0)
            {
                printf("\n");
            }
        }
    }
    else
    {
        printf("NULL buffer passed as number\n");
    }
    printf("\n");
}

/* Define cryptographic methods for use with TLS. */

/* Declare the NONE method:  encrypt / hash method not config */
static NX_CRYPTO_METHOD crypto_method_none =
{
    NX_CRYPTO_NONE,                           /* Name of the crypto algorithm          */
    0,                                        /* Key size in bits, not used            */
    0,                                        /* IV size in bits, not used             */
    0,                                        /* ICV size in bits, not used            */
    0,                                        /* Block size in bytes                   */
    0,                                        /* Metadata size in bytes                */
    NX_NULL,                                  /* Initialization routine, not used      */
    NX_NULL,                                  /* Cleanup routine, not used             */
    NX_NULL                                   /* NULL operation                        */
};


/* Declare the NULL encrypt */
static NX_CRYPTO_METHOD crypto_method_null =
{
    NX_CRYPTO_ENCRYPTION_NULL,                /* Name of the crypto algorithm          */
    0,                                        /* Key size in bits, not used            */
    0,                                        /* IV size in bits, not used             */
    0,                                        /* ICV size in bits, not used            */
    4,                                        /* Block size in bytes                   */
    0,                                        /* Metadata size in bytes                */
    NX_NULL,                                  /* Initialization routine, not used      */
    NX_NULL,                                  /* Cleanup routine, not used             */
    NX_NULL                                   /* NULL operation                        */
};

/* Declare the AES-CBC 128 encrytion method. */
static NX_CRYPTO_METHOD crypto_method_aes_cbc_128 =
{
    NX_CRYPTO_ENCRYPTION_AES_CBC,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_128_KEY_LEN_IN_BITS,        /* Key size in bits                       */
    NX_CRYPTO_AES_IV_LEN_IN_BITS,             /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),  /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES-CBC initialization routine.        */
    NX_NULL,                                  /* AES-CBC cleanup routine, not used.     */
    _nx_crypto_method_aes_operation           /* AES-CBC operation                      */
};

/* Declare the AES-CBC 256 encryption method */
static NX_CRYPTO_METHOD crypto_method_aes_cbc_256 =
{
    NX_CRYPTO_ENCRYPTION_AES_CBC,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_256_KEY_LEN_IN_BITS,        /* Key size in bits                       */
    NX_CRYPTO_AES_IV_LEN_IN_BITS,             /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),  /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES-CBC initialization routine.        */
    NX_NULL,                                  /* AES-CBC cleanup routine, not used.     */
    _nx_crypto_method_aes_operation           /* AES-CBC operation                      */
};

/* Declare the HMAC SHA1 authentication method */
static NX_CRYPTO_METHOD crypto_method_hmac_sha1 =
{
    TLS_HASH_SHA_1,                               /* HMAC SHA1 algorithm                   */
    NX_CRYPTO_HMAC_SHA1_KEY_LEN_IN_BITS,          /* Key size in bits                      */
    0,                                            /* IV size in bits, not used             */
    NX_CRYPTO_AUTHENTICATION_ICV_TRUNC_BITS,      /* Transmitted ICV size in bits          */
    0,                                            /* Block size in bytes, not used         */
    sizeof(NX_SHA1_HMAC),                         /* Metadata size in bytes                */
    NX_NULL,                                      /* Initialization routine, not used      */
    NX_NULL,                                      /* Cleanup routine, not used             */
    _nx_crypto_method_hmac_sha1_operation         /* HMAC SHA1 operation                   */
};

/* Declare the HMAC SHA256 authentication method */
static NX_CRYPTO_METHOD crypto_method_hmac_sha256 =
{
    TLS_HASH_SHA_256,                             /* HMAC SHA256 algorithm                 */
    NX_CRYPTO_HMAC_SHA256_KEY_LEN_IN_BITS,        /* Key size in bits                      */
    0,                                            /* IV size in bits, not used             */
    NX_CRYPTO_AUTHENTICATION_ICV_TRUNC_BITS,      /* Transmitted ICV size in bits          */
    0,                                            /* Block size in bytes, not used         */
    sizeof(NX_SHA256_HMAC),                       /* Metadata size in bytes                */
    NX_NULL,                                      /* Initialization routine, not used      */
    NX_NULL,                                      /* Cleanup routine, not used             */
    _nx_crypto_method_hmac_sha256_operation       /* HMAC SHA256 operation                 */
};

/* Declare the HMAC MD5 authentication method */
static NX_CRYPTO_METHOD crypto_method_hmac_md5 =
{
    TLS_HASH_MD5,                                  /* HMAC MD5 algorithm                    */
    NX_CRYPTO_HMAC_MD5_KEY_LEN_IN_BITS,            /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    NX_CRYPTO_AUTHENTICATION_ICV_TRUNC_BITS,       /* Transmitted ICV size in bits          */
    0,                                             /* Block size in bytes, not used         */
    sizeof(NX_MD5_HMAC),                           /* Metadata size in bytes                */
    NX_NULL,                                       /* Initialization routine, not used      */
    NX_NULL,                                       /* Cleanup routine, not used             */
    _nx_crypto_method_hmac_md5_operation           /* HMAC MD5 operation                    */
};

/* Declare the RSA public cipher method. */
static NX_CRYPTO_METHOD crypto_method_rsa =
{
    TLS_CIPHER_RSA,                           /* RSA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_RSA),                    /* Metadata size in bytes                 */
    _nx_crypto_method_rsa_init,               /* RSA initialization routine.            */
    NX_NULL,                                  /* RSA cleanup routine, not used.         */
    _nx_crypto_method_rsa_operation           /* RSA operation                          */

};

/* Declare the public NULL cipher (not to be confused with the NULL methods above). This
 * is used as a placeholder in ciphersuites that do not use a cipher method for a
 * particular operation (e.g. some PSK ciphersuites don't use a public-key algorithm
 * like RSA).
 */
static NX_CRYPTO_METHOD crypto_method_public_null =
{
    TLS_CIPHER_NULL,                          /* Name of the crypto algorithm          */
    0,                                        /* Key size in bits, not used            */
    0,                                        /* IV size in bits, not used             */
    0,                                        /* ICV size in bits, not used            */
    1,                                        /* Block size in bytes                   */
    0,                                        /* Metadata size in bytes                */
    _nx_crypto_method_null_init,              /* Initialization routine, not used      */
    NX_NULL,                                  /* Cleanup routine, not used             */
    _nx_crypto_method_null_operation          /* NULL operation                        */
};



/* Declare the MD5 hash method */
static NX_CRYPTO_METHOD crypto_method_md5 =
{
    TLS_HASH_MD5,                                  /* MD5 algorithm                         */
    0,                                             /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    0,                                             /* Transmitted ICV size in bits          */
    16,                                            /* Block size in bytes                   */
    sizeof(NX_MD5),                                /* Metadata size in bytes                */
    NX_NULL,                                       /* Initialization routine, not used      */
    NX_NULL,                                       /* Cleanup routine, not used             */
    _nx_crypto_method_md5_operation                /* MD5 operation                         */
};

/* Declare the SHA1 hash method */
static NX_CRYPTO_METHOD crypto_method_sha1 =
{
    TLS_HASH_SHA_1,                                /* SHA1 algorithm                        */
    0,                                             /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    0,                                             /* Transmitted ICV size in bits          */
    20,                                            /* Block size in bytes                   */
    sizeof(NX_SHA1),                               /* Metadata size in bytes                */
    NX_NULL,                                       /* Initialization routine, not used      */
    NX_NULL,                                       /* Cleanup routine, not used             */
    _nx_crypto_method_sha1_operation               /* SHA1 operation                        */
};

/* Declare the SHA256 hash method */
static NX_CRYPTO_METHOD crypto_method_sha256 =
{
    TLS_HASH_SHA_256,                              /* SHA256 algorithm                      */
    0,                                             /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    0,                                             /* Transmitted ICV size in bits          */
    32,                                            /* Block size in bytes                   */
    sizeof(NX_SHA256),                             /* Metadata size in bytes                */
    NX_NULL,                                       /* Initialization routine, not used      */
    NX_NULL,                                       /* Cleanup routine, not used             */
    _nx_crypto_method_sha256_operation             /* SHA256 operation                      */
};


/* Declare the supported encryption methods.
   This table is used in constructing the NX_CRYPTO method list. */
static NX_CRYPTO_METHOD    *encryption_method_table[] =
{
    &crypto_method_aes_cbc_128,
    &crypto_method_aes_cbc_256,
    &crypto_method_null
};

/* Declare the supported authentication methods.
   This table is used in constructing the NX_CRYPTO method list. */
static NX_CRYPTO_METHOD    *authentication_method_table[] =
{
    &crypto_method_hmac_sha1,
    &crypto_method_hmac_sha256,
    &crypto_method_hmac_md5,
    &crypto_method_none
};

/* Declare the supported public cipher methods.
   This table is used in constructing the NX_CRYPTO method list. */
static NX_CRYPTO_METHOD    *public_cipher_method_table[] =
{
    &crypto_method_rsa,
    &crypto_method_public_null,
    &crypto_method_null
};

/* Declare the supported hash methods.
   This table is used in constructing the NX_CRYPTO method list. */
static NX_CRYPTO_METHOD    *hash_method_table[] =
{
    &crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_sha256
};

static NX_SECURE_METHODS    tls_methods =
{
    encryption_method_table,
    3,
    authentication_method_table,
    4,
    public_cipher_method_table,
    2,
    hash_method_table,
    3
};

/* Define scratch space for cryptographic methods. */
static CHAR crypto_metadata[2*sizeof(NX_AES)];
static CHAR authentication_metadata[2 * sizeof(NX_SHA256_HMAC)];
static CHAR public_cipher_metadata[2 * sizeof(NX_CRYPTO_RSA)];
static CHAR handshake_hash_metadata[2 * (sizeof(NX_MD5) + sizeof(NX_SHA1) + sizeof(NX_SHA256))];

static CHAR crypto_metadata2[2*sizeof(NX_AES)];
static CHAR authentication_metadata2[2 * sizeof(NX_SHA256_HMAC)];
static CHAR public_cipher_metadata2[2 * sizeof(NX_CRYPTO_RSA)];
static CHAR handshake_hash_metadata2[2 * (sizeof(NX_MD5) + sizeof(NX_SHA1) + sizeof(NX_SHA256))];

static UINT init_number = 0;

void nx_secure_tls_test_init_utility(NX_SECURE_TLS_SESSION *tls_session)
{
UINT status;

    /* Create a TLS session for our socket.  */
    if(init_number == 0)
    {
    status =  nx_secure_tls_session_create(tls_session,
                                           &tls_methods,
                                           crypto_metadata,
                                           sizeof(crypto_metadata),
                                           authentication_metadata,
                                           sizeof(authentication_metadata),
                                           public_cipher_metadata,
                                           sizeof(public_cipher_metadata),
                                           handshake_hash_metadata,
                                           sizeof(handshake_hash_metadata));
      init_number++;
    }
    else
    {
    status =  nx_secure_tls_session_create(tls_session,
                                           &tls_methods,
                                           crypto_metadata2,
                                           sizeof(crypto_metadata2),
                                           authentication_metadata2,
                                           sizeof(authentication_metadata2),
                                           public_cipher_metadata2,
                                           sizeof(public_cipher_metadata2),
                                           handshake_hash_metadata2,
                                           sizeof(handshake_hash_metadata2));
 
    }
    
    if(status != NX_SUCCESS)
    {
        printf("Failure in TLS initialization. \n");
    }
}

