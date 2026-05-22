/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 * Copyright (c) 2025-present Eclipse ThreadX Contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Crypto Component                                                 */
/**                                                                       */
/**   RSA public-key encryption algorithm                                 */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#include "nx_crypto_rsa.h"
#include "nx_crypto_huge_number.h"

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_crypto_rsa_operation                            PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*     This function performs an RSA encryption/decryption operation -    */
/*     for RSA the operation is the same but with different values        */
/*     for the exponent.                                                  */
/*                                                                        */
/*     The output is always the same length as the modulus.               */
/*                                                                        */
/*     If NULL is passed for the scratch buffer pointer, an internal      */
/*     scratch buffer is used.                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    exponent                              RSA exponent                  */
/*    exponent_length                       Length of exponent in bytes   */
/*    modulus                               RSA modulus                   */
/*    modulus_length                        Length of modulus in bytes    */
/*    p                                     RSA prime p                   */
/*    p_length                              Length of p in bytes          */
/*    q                                     RSA prime q                   */
/*    q_length                              Length of q in bytes          */
/*    input                                 Input data                    */
/*    input_length                          Length of input in bytes      */
/*    output                                Output buffer                 */
/*    scratch_buf_ptr                       Pointer to scratch buffer     */
/*    scratch_buf_length                    Length of scratch buffer      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_crypto_huge_number_setup          Setup huge number             */
/*    _nx_crypto_huge_number_crt_power_modulus                            */
/*                                          Raise a huge number for CRT   */
/*    _nx_crypto_huge_number_mont_power_modulus                           */
/*                                          Raise a huge number for       */
/*                                            montgomery reduction        */
/*    _nx_crypto_huge_number_extract        Extract huge number           */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_crypto_method_rsa_operation       Handle RSA operation          */
/*                                                                        */
/**************************************************************************/
NX_CRYPTO_KEEP UINT  _nx_crypto_rsa_operation(const UCHAR *exponent, UINT exponent_length, const UCHAR *modulus, UINT modulus_length,
                                              const UCHAR *p, UINT p_length, UCHAR *q, UINT q_length,
                                              const UCHAR *input, UINT input_length, UCHAR *output,
                                              USHORT *scratch_buf_ptr, UINT scratch_buf_length)
{
HN_UBASE             *scratch;
UINT                  mod_length;
NX_CRYPTO_HUGE_NUMBER modulus_hn, exponent_hn, input_hn, output_hn, p_hn, q_hn;

    NX_CRYPTO_PARAMETER_NOT_USED(scratch_buf_length);

    /* The RSA operation is reversible so both encryption and decryption can be done with the same operation. */
    /* Local pointer for pointer arithmetic. */
    scratch = (HN_UBASE *)scratch_buf_ptr;

    /* Set up each of the buffers - point into the scratch buffer at increments of the DH buffer size. */
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&modulus_hn, scratch, modulus_length);

    /* Input buffer(and scratch). */
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&input_hn, scratch, modulus_length);

    /* Exponent  buffer (and scratch). */
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&exponent_hn, scratch, modulus_length);

    /* Output buffer (and scratch). */
    NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&output_hn, scratch, modulus_length << 1);

    /* Copy the exponent from the caller's buffer. */
    _nx_crypto_huge_number_setup(&exponent_hn, exponent, exponent_length);

    /* Copy the input from the caller's buffer. */
    _nx_crypto_huge_number_setup(&input_hn, input, input_length);

    /* Copy the modulus from the caller's buffer. */
    _nx_crypto_huge_number_setup(&modulus_hn, modulus, modulus_length);

    if (p && q)
    {

        NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&p_hn, scratch, modulus_length >> 1);

        NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&q_hn, scratch, modulus_length >> 1);

        /* Copy the prime p and q from the caller's buffer. */
        _nx_crypto_huge_number_setup(&p_hn, p, p_length);
        _nx_crypto_huge_number_setup(&q_hn, q, q_length);

        /* Finally, generate shared secret from the remote public key, our generated private key, and the modulus, modulus.
           The actual calculation is "shared_secret = (public_key**private_key) % modulus"
           where the "**" denotes exponentiation. */
        _nx_crypto_huge_number_crt_power_modulus(&input_hn, &exponent_hn, &p_hn, &q_hn,
                                                 &modulus_hn, &output_hn,
                                                 scratch);
    }
    else
    {

        /* Finally, generate shared secret from the remote public key, our generated private key, and the modulus, modulus.
           The actual calculation is "shared_secret = (public_key**private_key) % modulus"
           where the "**" denotes exponentiation. */
        _nx_crypto_huge_number_mont_power_modulus(&input_hn, &exponent_hn, &modulus_hn,
                                                  &output_hn, scratch);
    }

    /* Copy the shared secret into the return buffer. */
    _nx_crypto_huge_number_extract(&output_hn, output, modulus_length, &mod_length);

    return(NX_CRYPTO_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_crypto_method_rsa_init                           PORTABLE C     */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function initializes the modulus for RSA context.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    method                                Pointer to RSA crypto method  */
/*    key                                   Pointer to modulus            */
/*    key_size_in_bits                      Length of modulus in bits     */
/*    handle                                Handle of method              */
/*    crypto_metadata                       Pointer to RSA context        */
/*    crypto_metadata_size                  Size of RSA context           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
NX_CRYPTO_KEEP UINT  _nx_crypto_method_rsa_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                                                UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                                VOID **handle,
                                                VOID *crypto_metadata,
                                                ULONG crypto_metadata_size)
{
NX_CRYPTO_RSA *ctx;

    NX_CRYPTO_PARAMETER_NOT_USED(handle);

    NX_CRYPTO_STATE_CHECK

    if ((method == NX_CRYPTO_NULL) || (key == NX_CRYPTO_NULL) || (crypto_metadata == NX_CRYPTO_NULL))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    /* Verify the metadata address is 4-byte aligned. */
    if((((ULONG)crypto_metadata) & 0x3) != 0)
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    if(crypto_metadata_size < sizeof(NX_CRYPTO_RSA))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    ctx = (NX_CRYPTO_RSA *)crypto_metadata;

    ctx -> nx_crypto_rsa_modulus = key;
    ctx -> nx_crypto_rsa_modulus_length = key_size_in_bits >> 3;
    ctx -> nx_crypto_rsa_prime_p = NX_CRYPTO_NULL;
    ctx -> nx_crypto_rsa_prime_p_length = 0;
    ctx -> nx_crypto_rsa_prime_q = NX_CRYPTO_NULL;
    ctx -> nx_crypto_rsa_prime_q_length = 0;

    /* Call _nx_crypto_crypto_rsa_set_prime() to set p and q for private key.
     * Chinese Remainder Theorem will be used when p and q are set. */

    return(NX_CRYPTO_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_crypto_method_rsa_cleanup                       PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function cleans up the crypto metadata.                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    crypto_metadata                       Crypto metadata               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    NX_CRYPTO_MEMSET                      Set the memory                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
NX_CRYPTO_KEEP UINT  _nx_crypto_method_rsa_cleanup(VOID *crypto_metadata)
{

    NX_CRYPTO_STATE_CHECK

#ifdef NX_SECURE_KEY_CLEAR
    if (!crypto_metadata)
        return (NX_CRYPTO_SUCCESS);

    /* Clean up the crypto metadata.  */
    NX_CRYPTO_MEMSET(crypto_metadata, 0, sizeof(NX_CRYPTO_RSA));
#else
    NX_CRYPTO_PARAMETER_NOT_USED(crypto_metadata);
#endif/* NX_SECURE_KEY_CLEAR  */

    return(NX_CRYPTO_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_crypto_method_rsa_operation                      PORTABLE C     */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function is the RSA operation function for crypto method.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    op                                    Operation                     */
/*    handle                                Handle to method              */
/*    method                                Pointer to RSA crypto method  */
/*    key                                   Exponent of RSA operation     */
/*    key_size_in_bits                      Size of exponent in bits      */
/*    input                                 Input stream                  */
/*    input_length_in_byte                  Length of input in byte       */
/*    iv_ptr                                Initial Vector (not used)     */
/*    output                                Output stream                 */
/*    output_length_in_byte                 Length of output in byte      */
/*    crypto_metadata                       Pointer to RSA context        */
/*    crypto_metadata_size                  Size of RSA context           */
/*    packet_ptr                            Pointer to packet (not used)  */
/*    nx_crypto_hw_process_callback         Pointer to callback function  */
/*                                            (not used)                  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_crypto_rsa_operation              Perform RSA operation         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
NX_CRYPTO_KEEP UINT  _nx_crypto_method_rsa_operation(UINT op,      /* Encrypt, Decrypt, Authenticate */
                                                     VOID *handle, /* Crypto handler */
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
NX_CRYPTO_RSA *ctx;
UINT           return_value = NX_CRYPTO_SUCCESS;


    NX_CRYPTO_PARAMETER_NOT_USED(handle);
    NX_CRYPTO_PARAMETER_NOT_USED(iv_ptr);
    NX_CRYPTO_PARAMETER_NOT_USED(packet_ptr);
    NX_CRYPTO_PARAMETER_NOT_USED(nx_crypto_hw_process_callback);

    NX_CRYPTO_STATE_CHECK

    /* Verify the metadata address is 4-byte aligned. */
    if((method == NX_CRYPTO_NULL) || (crypto_metadata == NX_CRYPTO_NULL) || ((((ULONG)crypto_metadata) & 0x3) != 0))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    if(crypto_metadata_size < sizeof(NX_CRYPTO_RSA))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    ctx = (NX_CRYPTO_RSA *)crypto_metadata;


    if (op == NX_CRYPTO_SET_PRIME_P)
    {
        ctx -> nx_crypto_rsa_prime_p = input;
        ctx -> nx_crypto_rsa_prime_p_length = input_length_in_byte;
    }
    else if (op == NX_CRYPTO_SET_PRIME_Q)
    {
        ctx -> nx_crypto_rsa_prime_q = input;
        ctx -> nx_crypto_rsa_prime_q_length = input_length_in_byte;
    }
    else
    {

        if (key == NX_CRYPTO_NULL)
        {
            return(NX_CRYPTO_PTR_ERROR);
        }

        if(output_length_in_byte < (key_size_in_bits >> 3))
            return(NX_CRYPTO_INVALID_BUFFER_SIZE);

        if (input_length_in_byte > (ctx -> nx_crypto_rsa_modulus_length))
        {
            return(NX_CRYPTO_PTR_ERROR);
        }

        return_value = _nx_crypto_rsa_operation(key,
                                                key_size_in_bits >> 3,
                                                ctx -> nx_crypto_rsa_modulus,
                                                ctx -> nx_crypto_rsa_modulus_length,
                                                ctx -> nx_crypto_rsa_prime_p,
                                                ctx -> nx_crypto_rsa_prime_p_length,
                                                ctx -> nx_crypto_rsa_prime_q,
                                                ctx -> nx_crypto_rsa_prime_q_length,
                                                input, input_length_in_byte,
                                                output,
                                                ctx -> nx_crypto_rsa_scratch_buffer,
                                                NX_CRYPTO_RSA_SCRATCH_BUFFER_SIZE);
    }

    return(return_value);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_crypto_rsa_pss_mgf1                             PORTABLE C      */
/*                                                           6.4.3        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Mask Generation Function 1 (MGF1) as defined in RFC 8017 §B.2.1.  */
/*    Generates a pseudo-random octet string of length mask_length from  */
/*    a seed, using the supplied hash function.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    hash_method         Hash function (e.g. SHA-256/384/512)           */
/*    hash_metadata       Scratch memory for hash operations             */
/*    hash_metadata_size  Size of hash_metadata in bytes                 */
/*    seed                MGF seed (typically the PSS H value)           */
/*    seed_length         Length of seed in bytes                        */
/*    mask                Output buffer for generated mask               */
/*    mask_length         Desired mask length in bytes                   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status              NX_CRYPTO_SUCCESS or error code                */
/*                                                                        */
/**************************************************************************/
static UINT _nx_crypto_rsa_pss_mgf1(const NX_CRYPTO_METHOD *hash_method,
                                     VOID *hash_metadata, ULONG hash_metadata_size,
                                     const UCHAR *seed, UINT seed_length,
                                     UCHAR *mask, UINT mask_length)
{
UINT   counter;
UINT   offset;
UINT   copy_len;
UINT   hash_len;
UINT   status;
UCHAR  counter_bytes[4];
UCHAR  hash_buf[64]; /* large enough for SHA-512 */
VOID  *handler = NX_CRYPTO_NULL;

    hash_len = (UINT)(hash_method -> nx_crypto_ICV_size_in_bits >> 3);

    /* Sanity check: hash_buf must be large enough to hold one hash output. */
    if (hash_len == 0u || hash_len > sizeof(hash_buf))
    {
        return(NX_CRYPTO_INVALID_BUFFER_SIZE);
    }

    offset   = 0;

    for (counter = 0; offset < mask_length; counter++)
    {
        counter_bytes[0] = (UCHAR)((counter >> 24) & 0xFFu);
        counter_bytes[1] = (UCHAR)((counter >> 16) & 0xFFu);
        counter_bytes[2] = (UCHAR)((counter >>  8) & 0xFFu);
        counter_bytes[3] = (UCHAR)( counter        & 0xFFu);

        if (hash_method -> nx_crypto_init)
        {
            status = hash_method -> nx_crypto_init((NX_CRYPTO_METHOD *)hash_method,
                                                    NX_CRYPTO_NULL, 0,
                                                    &handler,
                                                    hash_metadata, hash_metadata_size);
            if (status != NX_CRYPTO_SUCCESS)
            {
                return(status);
            }
        }

        status = hash_method -> nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                     handler, (NX_CRYPTO_METHOD *)hash_method,
                                                     NX_CRYPTO_NULL, 0,
                                                     NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0,
                                                     hash_metadata, hash_metadata_size,
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        if (status != NX_CRYPTO_SUCCESS)
        {
            return(status);
        }

        status = hash_method -> nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                     handler, (NX_CRYPTO_METHOD *)hash_method,
                                                     NX_CRYPTO_NULL, 0,
                                                     (UCHAR *)seed, (ULONG)seed_length,
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0,
                                                     hash_metadata, hash_metadata_size,
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        if (status != NX_CRYPTO_SUCCESS)
        {
            return(status);
        }

        status = hash_method -> nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                     handler, (NX_CRYPTO_METHOD *)hash_method,
                                                     NX_CRYPTO_NULL, 0,
                                                     counter_bytes, 4,
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0,
                                                     hash_metadata, hash_metadata_size,
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        if (status != NX_CRYPTO_SUCCESS)
        {
            return(status);
        }

        status = hash_method -> nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                     handler, (NX_CRYPTO_METHOD *)hash_method,
                                                     NX_CRYPTO_NULL, 0,
                                                     NX_CRYPTO_NULL, 0,
                                                     NX_CRYPTO_NULL,
                                                     hash_buf, (ULONG)sizeof(hash_buf),
                                                     hash_metadata, hash_metadata_size,
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        if (status != NX_CRYPTO_SUCCESS)
        {
            return(status);
        }

        copy_len = mask_length - offset;
        if (copy_len > hash_len)
        {
            copy_len = hash_len;
        }
        NX_CRYPTO_MEMCPY(&mask[offset], hash_buf, copy_len); /* Use case of memcpy is verified. */
        offset += copy_len;
    }

    return(NX_CRYPTO_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_crypto_rsa_pss_verify                           PORTABLE C      */
/*                                                           6.4.3        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Verifies an RSA-PSS signature encoding (RFC 8017 §9.1.2).          */
/*    Used by TLS 1.3 CertificateVerify processing.                      */
/*    Assumes salt length == hash length (required by RFC 8446 §4.2.3). */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    message_hash        Pre-computed mHash over the signed content     */
/*    hash_length         hLen = byte length of mHash                    */
/*    em                  Encoded message from RSA public-key operation  */
/*    em_bits             emBits = modulus_bits - 1                      */
/*    hash_method         Same hash used to build the PSS encoding       */
/*    hash_metadata       Scratch memory for hash operations             */
/*    hash_metadata_size  Size of hash_metadata in bytes                 */
/*    scratch             Work buffer; must be >= ceil(emBits/8) bytes   */
/*    scratch_length      Size of scratch in bytes                       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_CRYPTO_SUCCESS                Signature is valid                */
/*    NX_CRYPTO_NOT_SUCCESSFUL         Signature is invalid              */
/*    NX_CRYPTO_INVALID_BUFFER_SIZE    Buffers too small                 */
/*                                                                        */
/**************************************************************************/
UINT _nx_crypto_rsa_pss_verify(const UCHAR *message_hash, UINT hash_length,
                                const UCHAR *em, UINT em_bits,
                                const NX_CRYPTO_METHOD *hash_method,
                                VOID *hash_metadata, ULONG hash_metadata_size,
                                UCHAR *scratch, UINT scratch_length)
{
UINT         em_len;
UINT         db_len;
UINT         s_len;
UINT         i;
UINT         status;
UCHAR        zero_bits;
UCHAR       *db;
UCHAR       *h_prime;
const UCHAR *h;
const UCHAR *masked_db;
VOID        *handler = NX_CRYPTO_NULL;
static const UCHAR _pss_zero8[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    /* emLen = ceil(emBits / 8). */
    em_len = (em_bits + 7u) >> 3;

    /* TLS 1.3 mandates salt length == hash length (RFC 8446 §4.2.3). */
    s_len = hash_length;

    if (em_len < (hash_length + s_len + 2u))
    {
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }

    db_len = em_len - hash_length - 1u;

    /* scratch layout: db[db_len] | h_prime[hash_length]. */
    if (scratch_length < (db_len + hash_length))
    {
        return(NX_CRYPTO_INVALID_BUFFER_SIZE);
    }

    db      = scratch;
    h_prime = scratch + db_len;

    /* Step 4 – last byte must be 0xBC. */
    if (em[em_len - 1u] != 0xBCu)
    {
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }

    /* maskedDB = em[0..db_len-1],  H = em[db_len..em_len-2]. */
    masked_db = em;
    h         = em + db_len;

    /* Step 6 – top (8*emLen - emBits) bits of em[0] must be zero. */
    zero_bits = (UCHAR)(8u * em_len - em_bits);
    if (zero_bits && (em[0] & (UCHAR)(0xFFu << (8u - zero_bits))))
    {
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }

    /* Step 7 – dbMask = MGF1(H, db_len). */
    status = _nx_crypto_rsa_pss_mgf1(hash_method, hash_metadata, hash_metadata_size,
                                      h, hash_length, db, db_len);
    if (status != NX_CRYPTO_SUCCESS)
    {
        return(status);
    }

    /* Step 8 – DB = maskedDB XOR dbMask. */
    for (i = 0u; i < db_len; i++)
    {
        db[i] ^= masked_db[i];
    }

    /* Step 9 – zero the top bits of DB[0]. */
    if (zero_bits)
    {
        db[0] &= (UCHAR)(0xFFu >> zero_bits);
    }

    /* Steps 10-11 – PS (all zeros) then 0x01 separator. */
    for (i = 0u; i < db_len - s_len - 1u; i++)
    {
        if (db[i] != 0x00u)
        {
            return(NX_CRYPTO_NOT_SUCCESSFUL);
        }
    }
    if (db[db_len - s_len - 1u] != 0x01u)
    {
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }

    /* Steps 13-14 – H' = Hash(0x00^8 || mHash || salt). */
    if (hash_method -> nx_crypto_init)
    {
        status = hash_method -> nx_crypto_init((NX_CRYPTO_METHOD *)hash_method,
                                                NX_CRYPTO_NULL, 0,
                                                &handler,
                                                hash_metadata, hash_metadata_size);
        if (status != NX_CRYPTO_SUCCESS)
        {
            return(status);
        }
    }

    status = hash_method -> nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                 handler, (NX_CRYPTO_METHOD *)hash_method,
                                                 NX_CRYPTO_NULL, 0,
                                                 NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL,
                                                 NX_CRYPTO_NULL, 0,
                                                 hash_metadata, hash_metadata_size,
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    if (status != NX_CRYPTO_SUCCESS)
    {
        return(status);
    }

    /* Hash 8 zero bytes. */
    status = hash_method -> nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                 handler, (NX_CRYPTO_METHOD *)hash_method,
                                                 NX_CRYPTO_NULL, 0,
                                                 (UCHAR *)_pss_zero8, 8,
                                                 NX_CRYPTO_NULL,
                                                 NX_CRYPTO_NULL, 0,
                                                 hash_metadata, hash_metadata_size,
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    if (status != NX_CRYPTO_SUCCESS)
    {
        return(status);
    }

    /* Hash mHash. */
    status = hash_method -> nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                 handler, (NX_CRYPTO_METHOD *)hash_method,
                                                 NX_CRYPTO_NULL, 0,
                                                 (UCHAR *)message_hash, (ULONG)hash_length,
                                                 NX_CRYPTO_NULL,
                                                 NX_CRYPTO_NULL, 0,
                                                 hash_metadata, hash_metadata_size,
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    if (status != NX_CRYPTO_SUCCESS)
    {
        return(status);
    }

    /* Hash salt = DB[db_len - s_len .. db_len - 1]. */
    status = hash_method -> nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                 handler, (NX_CRYPTO_METHOD *)hash_method,
                                                 NX_CRYPTO_NULL, 0,
                                                 &db[db_len - s_len], (ULONG)s_len,
                                                 NX_CRYPTO_NULL,
                                                 NX_CRYPTO_NULL, 0,
                                                 hash_metadata, hash_metadata_size,
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    if (status != NX_CRYPTO_SUCCESS)
    {
        return(status);
    }

    status = hash_method -> nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                 handler, (NX_CRYPTO_METHOD *)hash_method,
                                                 NX_CRYPTO_NULL, 0,
                                                 NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL,
                                                 h_prime, (ULONG)hash_length,
                                                 hash_metadata, hash_metadata_size,
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    if (status != NX_CRYPTO_SUCCESS)
    {
        return(status);
    }

    /* Step 15 – compare H == H'. */
    if (NX_CRYPTO_MEMCMP(h, h_prime, hash_length) != 0)
    {
        return(NX_CRYPTO_NOT_SUCCESSFUL);
    }

    return(NX_CRYPTO_SUCCESS);
}

